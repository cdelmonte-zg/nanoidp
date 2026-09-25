"""
Configuration management for NanoIDP.
Loads settings and users from YAML files.
Uses Pydantic for validation and schema enforcement.
"""

import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple, TypeVar

import yaml

# Re-exported for compatibility: the models were defined here until #86, and
# every consumer (routes, services, MCP, tests) imports them from this module.
from .config_documents import (
    HooksSection,
    SettingsDocument,
    declared_validation_mode,
    document_defaults,
    load_settings_document,
    load_users_document,
    reject_unloadable,
)
from .config_store import ConfigFileStore, FileSnapshot, Fingerprint
from .config_writer import (
    LockNamespaceUnavailable,
    LockUnavailableError,
    compare_and_replace,
    revision_of_bytes,
)
from .hooks import SOURCE_SETTINGS, HookError, HookRegistry, bootstrap_registry
from .models import (  # noqa: F401
    SECURITY_PROFILES,
    OAuthClient,
    Settings,
    User,
    _coerce_additional_audiences,
    _coerce_client_str_list,
)
from .serialization import (
    IMPLICIT_CONFIG_VERSION,
    apply_settings_document,
    apply_users_document,
    check_config_version,
)
from .serialization import expand_env_vars as _expand_env_vars
from .token_subject import shared_name_warning

logger = logging.getLogger(__name__)


# The activation step of a load (#359): given the candidate Settings, build
# what the configuration needs before anything is committed (raising rejects
# the configuration) and return the function that publishes it once nothing
# can fail any more. Supplied by the process composition, because config
# must not import services.
Activation = Callable[[Settings, Path], Callable[[], None]]

# Called with the manager after every successful load, inside the load, once
# the new configuration is assigned (#235: the runtime identity store drops
# the runtime objects a reload has just declared). Supplied by the process
# composition, like the activation step. A post-commit callback: it must not
# raise, since the configuration is already in effect when it runs, and a
# raise would report a load that did happen as failed. A fallible backend
# (#354) has to revisit this.
AfterLoad = Callable[["ConfigManager"], None]


class ConfigurationRejected(ValueError):
    """A load refused the configuration; the running one stays in effect.

    ``kind`` is ``"invalid"`` when the files do not validate and
    ``"activation"`` when they do but a service the configuration needs
    (the signing service) cannot be built from them. A ValueError, so
    callers that already handled a failed load keep doing so.
    """

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


class DeclaredConfigurationUnloadable(RuntimeError):
    """The configuration files changed and do not load, so nothing can be
    checked against them (#354, step 4a): a mutation that depends on the
    declaration, such as creating a runtime user or client under a name that
    must not be declared, is refused. The configuration loaded before stays
    in force for everything else.

    ``temporary`` when what failed is outside the bytes (an I/O error, an
    activation, a plugin), which coming back may resolve; otherwise the
    files do not parse or validate, and only fixing them ends it."""

    def __init__(self, message: str, temporary: bool) -> None:
        super().__init__(message)
        self.temporary = temporary


class ReloadAfterSaveError(RuntimeError):
    """save() wrote both files successfully, but the runtime could not
    adopt them afterward (#229 review round on phase 2, blocking).

    Distinct from ConflictError (nothing was written) and HookError
    (written, only the mirror push failed): this means the write itself
    landed on disk, but reload_local() - the same _load_config path
    every reload() and startup use - raised while re-parsing it back in.
    Typically a Pydantic ValidationError for a value that reached
    settings.yaml without going through Settings' own field validators
    (e.g. an in-memory attribute set directly, bypassing
    validate_assignment, which Settings does not currently declare). The
    written file is authoritative; the in-memory ConfigManager still
    reflects whatever it had before this save() call, exactly as any
    other failed _load_config leaves it untouched (#204).
    """

    def __init__(self, message: str, kind: str = "reload_after_save") -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


# The two files of the declared configuration, in the order they are observed.
_FILES = ("settings.yaml", "users.yaml")

_T = TypeVar("_T")


# How long a pair of files whose load failed for a reason outside them waits
# before it is tried again: an external resource briefly missing must not be
# tried at request rate. Its own constant, of the order of #420's.
_TRANSIENT_RETRY_SECONDS = 5.0

# The clock of those waits, a seam of the tests.
_now = time.monotonic

# How long the other requests wait for the one check in flight before they
# are told to come back (#354, step 4a, sixth review).
_FOLLOWER_WAIT_SECONDS = 0.5

# How much older than the read a file's times must be for its stat to be
# trusted: a write in place within the timestamp's tick (1 to 4 ms on ext4,
# coarser on some filesystems, 2 s on FAT) leaves the stat unchanged. What
# git calls racily clean. The wall clock, since the file's times are.
_RACY_MARGIN_NS = 2 * 10**9
_wall_ns = time.time_ns


def _racy(fingerprints: Tuple[Optional[Fingerprint], ...], read_at_ns: int) -> bool:
    """By the modification time, as git: it is what a write of the content
    sets. The change time stays in the fingerprint, for what it detects."""
    return any(
        fingerprint is not None and fingerprint[2] >= read_at_ns - _RACY_MARGIN_NS for fingerprint in fingerprints
    )


# What a pair of files is, for freshness (#354, step 4a, fifth review): for
# each, whether it is there and the revision of its bytes. A missing file and
# an empty one have the same revision and do not load the same, so the
# revision alone is not the file's identity here; it stays the public
# revision of the write preconditions (#229).
_Identity = Tuple[Tuple[bool, str], Tuple[bool, str]]


def _identity_of(observed: Dict[str, FileSnapshot]) -> _Identity:
    settings, users = observed["settings.yaml"], observed["users.yaml"]
    return ((settings.exists, settings.revision), (users.exists, users.revision))


@dataclass(frozen=True)
class ConfigSnapshot:
    """The declared configuration as one load left it (#406).

    A load is transactional on the way in: nothing changes until both files
    have been read and validated. This is the way out. The fields below were
    published one assignment at a time, so a request reading two of them
    across a load got a pair that no load ever produced; they are published
    as this one value instead, and `ConfigManager` reads through to it.

    The carrier is immutable, not the objects it references. A load builds
    new ones rather than changing these, which is what makes publication
    atomic; but the surfaces that edit the configuration in memory before
    saving it (the MCP write tools: `handlers_users.py`, `handlers_clients.py`)
    do change those objects in place, and this step says nothing about them.
    Where the boundary for such an edit lies is #406's second step.

    What is NOT here: the signing service, published before the settings on
    purpose (#359), so that a request can pair older settings with the newer
    service and never the reverse; the hook registry, replaced before both;
    and runtime identities, which are read live by design (#235).
    """

    settings: Settings
    users: Dict[str, User]
    strict_config: bool
    config_version: int
    # The values the file declared for the fields a --profile forces, kept
    # apart so that a write serializes the operator's file and not the run's
    # hardening.
    declared: Dict[str, Any]
    # The revisions of the bytes this configuration was loaded from (#229
    # phase 5) - what a caller passes back to save() as expected_*_revision.
    users_revision: Optional[str]
    settings_revision: Optional[str]
    observed_at: float


def _persistable(loaded: ConfigSnapshot) -> Settings:
    """The declared settings of one loaded configuration: what a writer
    serializes, with the fields a --profile forced carrying the value the
    file declared."""
    if not loaded.declared:
        return loaded.settings
    return loaded.settings.model_copy(update=loaded.declared)


@dataclass(frozen=True)
class _Pending:
    # None when the files could not be read at all.
    revisions: Optional[_Identity]
    fingerprints: Optional[Tuple[Optional[Fingerprint], ...]]
    retry_after: float


def _causes(failure: BaseException) -> Iterator[BaseException]:
    """The failure and what it was raised from or while, once each."""
    seen = set()
    stack = [failure]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        stack.extend(link for link in (current.__cause__, current.__context__) if link is not None)


def _decided_by_the_bytes(failure: BaseException) -> bool:
    """Whether the bytes alone refused the load: files that do not parse or
    validate. Not an I/O error on the way, which a load reports under the
    same kind, nor an activation or a plugin, which depend on what is outside
    the two files."""
    return (
        isinstance(failure, ConfigurationRejected)
        and failure.kind == "invalid"
        and not any(isinstance(cause, OSError) for cause in _causes(failure))
    )


def _lock_behind(failure: BaseException) -> Optional[LockUnavailableError]:
    """The lock a failed load could not take, if that is what failed,
    however deep a load wrapped it: the configuration directory's is a
    ConfigurationRejected of the lock's kind, the keys directory's (taken by
    the activation) a ValueError inside one. Temporary, not files that do not
    load (#354, step 4a, review). A directory with no lock namespace at all
    is no lock held by a peer: that one is left to be what it says."""
    seen = set()
    current: Optional[BaseException] = failure
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, LockUnavailableError) and not isinstance(current, LockNamespaceUnavailable):
            return current
        current = current.__cause__
    return None


class ConfigManager:
    """Manages configuration loading and access."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        profile_override: Optional[str] = None,
        strict_config: Optional[bool] = None,
        activate: Optional[Activation] = None,
        after_load: Optional[AfterLoad] = None,
    ) -> None:
        self.config_dir = Path(config_dir or self._find_config_dir())
        self._activate = activate
        self._after_load = after_load
        # One load at a time (#359): two concurrent loads would each prepare
        # a signing service (and generate keys into the same fresh keys_dir
        # over each other), and could publish one load's service next to the
        # other load's settings. Reentrant, so a hook that reloads from
        # inside a load cannot deadlock the process.
        self._load_lock = threading.RLock()
        # Every observation of the configuration directory goes through one
        # store (#246): it owns the filesystem access and the directory
        # lock, so a read is one consistent look rather than several
        # independent ones that can compose into a state never on disk.
        self._store = ConfigFileStore(self.config_dir)
        # The fingerprints of the files the loaded configuration was read
        # from, and of a pair of files a check could not load (#354, step
        # 4a): what refresh_if_changed compares a stat with.
        # With it, whether they are too recent to be trusted: one observation,
        # published as one, so that nobody reads the fingerprints of one look
        # with the racy flag of another.
        self._loaded_state: Tuple[Tuple[Optional[Fingerprint], ...], bool] = ((None, None), True)
        # The identity, fingerprints and racy flag of the files refused.
        self._refused: Optional[Tuple[_Identity, Tuple[Optional[Fingerprint], ...], bool]] = None
        # How many checks established what the files are (the same bytes,
        # newer ones loaded, or bytes refused): a request that waited for the
        # check in flight takes the result of one made after it arrived.
        self._established = 0
        # How many loads were committed: whether a reload that raised had
        # committed first, whichever files it loaded.
        self._commits = 0
        # A pair of files whose load failed for a reason outside them, and
        # when it may be tried again.
        self._pending: Optional[_Pending] = None
        # What the last load read, set as soon as it has read: what a load
        # that then failed is to be remembered by.
        self._last_observed: Optional[Tuple[_Identity, Tuple[Optional[Fingerprint], ...], int]] = None
        # The identity of the files the loaded configuration came from.
        self._loaded_identity: Optional[_Identity] = None
        # One automatic freshness check at a time (#354, step 4a): the others
        # wait for it briefly (_FOLLOWER_WAIT_SECONDS) and take what it
        # established, but never queue behind one that waits for the
        # directory lock's timeout.
        self._freshness_lock = threading.Lock()
        # A transient CLI/programmatic `--profile` (#172). Kept here, not on
        # Settings, because it must survive every reload() - which rebuilds
        # Settings from YAML - and must never be written back to the file.
        if profile_override is not None and profile_override not in SECURITY_PROFILES:
            raise ValueError(
                f"Invalid profile override {profile_override!r}; "
                f"expected one of {', '.join(SECURITY_PROFILES)}"
            )
        self.profile_override: Optional[str] = profile_override
        # The transient CLI --strict-config (#175 piece 4), same contract as
        # profile_override: True wins over settings.yaml's config_validation
        # for the life of the process and is never written back. None means
        # "whatever the file declares".
        self.strict_config_override: Optional[bool] = strict_config
        # Effective strictness, re-derived from the file on every load.
        # ONE observation for the whole pre-load phase (#246): the
        # strictness the bootstrap registry runs under and the bootstrap
        # file it reads come from the same look at the directory, so a
        # write landing between them cannot pair one file's strictness with
        # the other's content.
        pre_load = self._observe_pre_load()
        # The configuration is one value from here on (#406): before the
        # first load it is the defaults, with the strictness the pre-load
        # observation established, which the bootstrap registry below reads.
        self._snapshot = ConfigSnapshot(
            settings=Settings(),
            users={},
            strict_config=self._effective_strict(self._declared_mode_of(pre_load["settings.yaml"])),
            # Effective config schema version of the loaded files (#175):
            # the declared value, or 1 when a file carries no
            # config_version key.
            config_version=IMPLICIT_CONFIG_VERSION,
            declared={},
            users_revision=None,
            settings_revision=None,
            observed_at=0.0,
        )
        # Hooks and plugins (#185): the bootstrap surface (bootstrap.yaml in
        # the config dir, NANOIDP_BOOTSTRAP_HOOK / _PLUGIN) is read before
        # the first load because settings.yaml may be what a hook renders;
        # settings.yaml's own hooks: / plugins: are merged in after each load.
        # bootstrap.yaml is read before settings.yaml (it may be what renders
        # it), so the strictness it follows comes from a raw peek at
        # settings.yaml's config_validation above: one contract per directory.
        self.hooks: HookRegistry = bootstrap_registry(
            self.config_dir,
            strict_config=self.strict_config,
            observed=pre_load["bootstrap.yaml"],
        )
        # Last settings.yaml hooks:/plugins: declaration applied to the
        # registry; an unchanged declaration is not re-applied on the next
        # load, so a post-write refresh does not drop and re-instantiate
        # plugins (review before 2.7.0rc4).
        self._hooks_snapshot: Optional[tuple] = None
        self._load_config()

    def _find_config_dir(self) -> str:
        """Find the config directory."""
        # Check environment variable
        if env_dir := os.getenv("NANOIDP_CONFIG_DIR", os.getenv("MOCK_IDP_CONFIG_DIR")):
            return env_dir

        # Check common locations
        candidates = [
            Path("./config"),
            Path("../config"),
            Path(__file__).parent.parent.parent.parent / "config",
        ]

        for candidate in candidates:
            if candidate.exists() and (candidate / "settings.yaml").exists():
                return str(candidate)

        # Default to ./config
        return "./config"

    def _effective_strict(self, declared_mode: str) -> bool:
        """--strict-config wins over the file, as --profile does (#172)."""
        if self.strict_config_override is not None:
            return self.strict_config_override
        return declared_mode == "strict"

    def _observe_pre_load(self) -> Dict[str, "FileSnapshot"]:
        """The one look the pre-load phase takes at the directory (#246).

        ``settings.yaml`` for the strictness the bootstrap registry runs
        under, ``bootstrap.yaml`` for what that registry is built from. Two
        files of one phase, so one acquisition.
        """
        try:
            return self._store.read_snapshot(("settings.yaml", "bootstrap.yaml"))
        except LockUnavailableError as exc:
            # Classified rather than a bare RuntimeError out of __init__,
            # where startup has no handler for it. It still fails, which is
            # right: the directory could not be observed at all.
            raise ConfigurationRejected(str(exc), kind=exc.kind) from exc

    def _declared_mode_of(self, settings: "FileSnapshot") -> str:
        """``config_validation`` as declared by settings.yaml, read raw.

        Needed before the document loader runs (it decides how that loader
        reports) and before bootstrap.yaml is read. A file that cannot be
        parsed at all returns the default here and fails with its real error
        a moment later, in _stage_directory, where the message belongs.

        Reads from the pre-load observation rather than taking one of its
        own, so this and bootstrap.yaml come from one look at the directory
        (#246). That observation is deliberately NOT the load's: it decides
        the strictness the bootstrap registry is built with, and that
        registry must exist before ``on_before_load`` runs, which may be
        what renders settings.yaml in the first place. The accepted
        consequence, stated rather than hidden: a write landing between the
        two phases means the bootstrap registry's strictness came from a
        settings.yaml the load never saw. Each phase observes consistently;
        they are two moments because the phases themselves are.
        """
        if not settings.exists:
            return "warn"
        try:
            data = yaml.safe_load(settings.data) or {}
        except Exception:  # noqa: BLE001 - reported by _stage_directory
            return "warn"
        return declared_validation_mode(data) if isinstance(data, dict) else "warn"

    def _load_config(self, run_before_load: bool = True) -> None:
        """Load all configuration files as ONE directory transaction.

        The transactional boundary is the whole configuration directory
        (#204 review): settings.yaml AND users.yaml are parsed and validated
        into candidates first, and only when both are valid does anything
        touch the runtime. A failed load (strict unknown key in either file,
        wrong types, version mismatch, strict plugin failure) leaves
        settings, users, strict_config, config_version, the
        profile hardening and the hook registry exactly as they were.
        """
        with self._load_lock:
            self._load_config_locked(run_before_load)

    def _load_config_locked(self, run_before_load: bool) -> None:
        # on_before_load: bootstrap hooks run once (first load only), the
        # settings.yaml-declared ones on every load. The registry enforces
        # the once-only rule; under hooks.strict a failure raises HookError
        # here, before anything is read.
        if run_before_load:
            self.hooks.run_before_load(self.config_dir)
        try:
            staged = self._stage_directory()
        except LockUnavailableError as exc:
            # The directory could not be observed at all: a peer holding the
            # lock past the timeout, or a filesystem that cannot do advisory
            # locking (#246 review). Classified like every other refused
            # load, so /api/config/reload and the MCP reload tool answer in
            # their documented shape instead of a 500.
            raise ConfigurationRejected(str(exc), kind=exc.kind) from exc
        except (OSError, ValueError, yaml.YAMLError) as exc:
            # OSError: a file that exists but cannot be read (permissions).
            raise ConfigurationRejected(str(exc), kind="invalid") from exc
        publish: Optional[Callable[[], None]] = None
        if self._activate is not None:
            try:
                publish = self._activate(staged["settings"], self.config_dir)
            except Exception as exc:
                raise ConfigurationRejected(
                    f"{self.config_dir / 'settings.yaml'}: {exc}", kind="activation"
                ) from exc
        self._commit_directory(staged, publish)
        if self._after_load is not None:
            self._after_load(self)
        logger.info(f"Loaded configuration from {self.config_dir}")
        logger.info(f"Loaded {len(self.users)} users")

    # Settings fields the stricter-dev profile forces at runtime (#47, #68).
    # Listed once so _apply_profile() and persistable_settings() cannot drift:
    # adding a derived field here is all it takes for it to be both applied
    # on every reload and kept out of the operator's file.
    _STRICTER_DEV_HARDENING: Dict[str, Any] = {
        "rate_limit_enabled": True,
        "password_hashing": True,
        # PKCE required and 'plain' rejected in stricter-dev (#47)
        "require_pkce": True,
        # Block debug mode in stricter-dev
        "debug": False,
    }

    def _apply_profile(self, settings: Settings) -> Dict[str, Any]:
        """Make the effective security profile real on a candidate Settings.

        Pure with respect to the manager: mutates only the candidate and
        RETURNS the declared-value snapshot; the caller commits both. See
        _STRICTER_DEV_HARDENING and persistable_settings().
        """
        declared: Dict[str, Any] = {}
        if self.profile_override is not None:
            declared["security_profile"] = settings.security_profile
            settings.security_profile = self.profile_override
        if settings.security_profile == "stricter-dev":
            for field, forced in self._STRICTER_DEV_HARDENING.items():
                declared[field] = getattr(settings, field)
                setattr(settings, field, forced)
        return declared

    @property
    def snapshot(self) -> ConfigSnapshot:
        """The declared configuration as one value (#406). A caller that
        answers from the configuration takes it once and reads it, rather
        than reading the manager again at each use: what it holds cannot be
        half of one load and half of the next."""
        return self._snapshot

    @property
    def settings(self) -> Settings:
        return self._snapshot.settings

    @property
    def users(self) -> Dict[str, User]:
        return self._snapshot.users

    @property
    def strict_config(self) -> bool:
        return self._snapshot.strict_config

    @property
    def config_version(self) -> int:
        return self._snapshot.config_version

    @property
    def users_revision(self) -> Optional[str]:
        return self._snapshot.users_revision

    @property
    def settings_revision(self) -> Optional[str]:
        return self._snapshot.settings_revision

    @property
    def observed_at(self) -> float:
        return self._snapshot.observed_at

    def persistable_settings(self) -> Settings:
        """The declared configuration state, as opposed to the effective one.

        Identical to self.settings except for the fields _apply_profile()
        forced, which carry the value the file declared. This is what the
        writer serializes: a transient --profile, or the hardening a profile
        implies, must never be written into the operator's file, where it
        would survive the next start without the flag.
        """
        # One observation (#406): composing the two from separate reads
        # wrote a file pairing one load's values with another's declarations.
        return _persistable(self.snapshot)

    def _stage_directory(self) -> Dict[str, Any]:
        """Parse and validate the whole directory into candidates, committing
        nothing. Any exception here leaves the manager untouched.

        The two files are acquired as ONE observation of the directory
        (#246): a write landing between two separate reads used to be
        observed as a settings/users pair that never existed on disk. Only
        the acquisition is inside the lock - parsing, environment expansion,
        the document models and the profile hardening all run on the bytes
        afterwards, because the atomic unit is the filesystem snapshot, not
        the reload.
        """
        staged: Dict[str, Any] = {}
        # Taken before the files are read, so it is never later than what
        # was read: whatever happened to the directory after this moment,
        # this configuration cannot speak about (#405).
        staged["observed_at"] = time.time()
        staged["read_at_ns"] = _wall_ns()
        observed = self._store.read_snapshot(_FILES)
        settings_observed = observed["settings.yaml"]
        users_observed = observed["users.yaml"]
        staged["fingerprints"] = (settings_observed.fingerprint, users_observed.fingerprint)
        staged["identity"] = _identity_of(observed)
        self._last_observed = (staged["identity"], staged["fingerprints"], staged["read_at_ns"])
        settings_file = self.config_dir / "settings.yaml"
        if not settings_observed.exists:
            logger.warning(f"Settings file not found: {settings_file}, using defaults")
            staged["settings_missing"] = True
            staged["strict"] = self._effective_strict("warn")
            staged["version"] = IMPLICIT_CONFIG_VERSION
            staged["settings"] = self._default_settings()
            staged["hooks_section"] = None
            staged["plugins"] = {}
            # Same revision current_revision() gives a missing file: the
            # hash of empty bytes (#229 phase 5).
            staged["settings_revision"] = revision_of_bytes(b"")
        else:
            # The revision describes exactly the bytes being parsed (#229
            # phase 5): a save precondition built on it therefore catches
            # every on-disk change since, which hashing a second read could
            # not promise. Since #246 the bytes and their revision are one
            # observation, carried by the snapshot rather than recomputed.
            raw = settings_observed.data
            staged["settings_revision"] = settings_observed.revision
            data = yaml.safe_load(raw) or {}
            # Candidate strictness: an edited config_validation takes effect
            # on the load that reads it, an explicit --strict-config keeps
            # winning, and a load that FAILS never changes the running mode
            # (#204 review).
            staged["settings_missing"] = False
            staged["strict"] = self._effective_strict(declared_validation_mode(data))
            # Refuse files written for a newer contract before reading any
            # key (#175): a silently half-understood file is worse than a
            # clear stop.
            staged["version"] = check_config_version(data, settings_file)
            data = _expand_env_vars(data)
            # YAML -> document model -> domain model (#175 piece 2).
            document = load_settings_document(data, settings_file, strict=staged["strict"])
            staged["settings"] = document.to_settings()
            staged["hooks_section"] = document.hooks
            staged["plugins"] = document.plugins
        # The profile hardening is part of the candidate, not a later step.
        staged["declared"] = self._apply_profile(staged["settings"])

        users_file = self.config_dir / "users.yaml"
        if not users_observed.exists:
            logger.warning(f"Users file not found: {users_file}, using defaults")
            staged["users"] = self._default_users()
            staged["users_revision"] = users_observed.revision
        else:
            uraw = users_observed.data
            staged["users_revision"] = users_observed.revision
            udata = yaml.safe_load(uraw) or {}
            # config_version is checked BEFORE placeholder expansion: it must
            # be a literal integer, never ${VAR} (#175 review).
            users_version = check_config_version(udata, users_file)
            # One contract for the whole directory (#175 review).
            if users_version != staged["version"]:
                raise ValueError(
                    f"{users_file}: config_version {users_version} does not match "
                    f"settings.yaml's config_version {staged['version']}; the "
                    f"configuration directory follows one contract version"
                )
            udata = _expand_env_vars(udata)
            staged["users"] = load_users_document(
                udata, users_file, strict=staged["strict"]
            ).to_users()
        return staged

    def _commit_directory(
        self, staged: Dict[str, Any], publish: Optional[Callable[[], None]] = None
    ) -> None:
        """Promote a fully validated staging to the runtime.

        The hook registry goes first because it is the only step that can
        still fail (strict plugin load), and replace_source() rolls itself
        back on failure (#200 review). Then the activation's publish (the
        signing service, #359), and only then the settings: readers take the
        settings before the signing service, so a request can pair older
        settings with the newer service but never the reverse. Nothing after
        the publish can fail; everything after it is plain assignment.
        """
        if staged["settings_missing"]:
            # A vanished settings.yaml takes its hooks, plugins and policy
            # with it (#185 review); bootstrap entries stay.
            self.hooks.drop_source(SOURCE_SETTINGS)
            self._hooks_snapshot = None
        else:
            self._configure_hooks_from(staged["hooks_section"], staged["plugins"])
        if publish is not None:
            publish()
        # A user and a client of the same name load, and are said (#445)
        client_ids = {client.client_id for client in staged["settings"].clients}
        for name in sorted(client_ids & set(staged["users"])):
            logger.warning(shared_name_warning(name))
        # One assignment (#406): a reader takes the whole configuration or
        # the whole previous one, never a pair of the two. The revisions in
        # it are those of the bytes this runtime was loaded from (#229
        # phase 5) - what a caller passes back to save() as
        # expected_*_revision to mean "refuse my save if the file moved
        # since the state I based my change on". Deliberately NOT the
        # file's revision at ask time: on a runtime that is stale against
        # the directory (another process wrote), a fresh disk hash would
        # satisfy the precondition exactly when the lost update is real.
        # Every successful write path refreshes these via reload_local().
        self._snapshot = ConfigSnapshot(
            settings=staged["settings"],
            users=staged["users"],
            strict_config=staged["strict"],
            config_version=staged["version"],
            declared=staged["declared"],
            users_revision=staged["users_revision"],
            settings_revision=staged["settings_revision"],
            observed_at=staged["observed_at"],
        )
        self._loaded_state = (staged["fingerprints"], _racy(staged["fingerprints"], staged["read_at_ns"]))
        self._loaded_identity = staged["identity"]
        self._commits += 1

    def _configure_hooks_from(self, hooks: HooksSection, plugins: Dict[str, Dict[str, Any]]) -> None:
        """Replace the settings.yaml-sourced hooks/plugins with the file's
        current declaration (#185); bootstrap entries are untouched. Skipped
        when the declaration is identical to the one already applied."""
        # Plugins as an ORDERED tuple, not a dict: dict equality ignores
        # order, and the v1 contract runs plugins in declaration order, so a
        # file that only reorders them must be re-applied (#200 review).
        snapshot = (
            hooks.model_dump(),
            frozenset(hooks.model_fields_set),
            tuple((name, dict(cfg)) for name, cfg in plugins.items()),
        )
        if snapshot == self._hooks_snapshot:
            return
        # The HooksSection itself, not model_dump(): only the policy values
        # the file declares explicitly override the bootstrap baseline.
        # replace_source rolls the registry back if registration raises, and
        # the snapshot is recorded only on success so a retry re-applies.
        self.hooks.replace_source(hooks, plugins, SOURCE_SETTINGS)
        self._hooks_snapshot = snapshot

    def notify_saved(self, path: Path, kind: str) -> None:
        """The single on_config_saved call site for every write path (#185):
        ConfigManager's own saves and YamlWriter's. Called AFTER the atomic
        write; under hooks.strict the hook's failure is raised as
        HookError.

        This method itself never reloads - that is each *caller's* job,
        and not every caller does it the same way (#229 review: this
        needs to say which). save() notifies both of its files,
        collecting either failure, then refreshes the runtime once and
        raises (both files are already written as one coordinated save
        by the time either hook runs, and reloading after each file
        individually would let the users.yaml reload discard the
        in-memory settings.yaml change save() just persisted) - this is
        save()'s write -> notify -> reload_local -> raise contract, and
        it is the only production path: save() is ConfigManager's one
        real caller of a save operation. YamlWriter._atomic_write runs
        the same contract right after its own single write. _save_users
        and _save_settings, called directly rather than through save(),
        do NOT reload themselves - they write and notify only, with no
        production caller left (#229 review: save() writes both files
        via compare_and_replace_many, not via these two methods); the
        hook-contract tests in test_hooks.py that call them directly
        exercise notify_saved's hook dispatch and HookError propagation
        in isolation, not save()'s full contract."""
        self.hooks.run_config_saved(path, kind)

    def _default_settings(self) -> Settings:
        """The Settings a directory without settings.yaml gets."""
        settings = SettingsDocument(
            authority_prefixes={
                "roles": "ROLE_",
                "groups": "GROUP_",
                "identity_class": "IDENTITY_",
                "entitlements": "ENT_",
            },
            allowed_identity_classes=["INTERNAL", "EXTERNAL", "PARTNER", "SERVICE"],
        ).to_settings()
        # The demo client the old fallback always shipped (#204 review: the
        # transactional refactor must not change what a directory without
        # settings.yaml gets).
        settings.clients = [
            OAuthClient(
                client_id="demo-client",
                client_secret="demo-secret",
                description="Default demo client",
            )
        ]
        return settings

    def _default_users(self) -> Dict[str, User]:
        """The users a directory without users.yaml gets."""
        return {
            "admin": User(
                username="admin",
                password="admin",
                email="admin@example.org",
                identity_class="INTERNAL",
                roles=["USER", "ADMIN"],
                tenant="default",
            ),
        }

    def get_user(self, username: str) -> Optional[User]:
        """The declared user with that name. Logins and grants resolve users
        through services.identities, which also sees runtime users (#235)."""
        return self.users.get(username)

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        import bcrypt
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def get_client(self, client_id: str) -> Optional[OAuthClient]:
        """The declared client with that id. Client checks resolve clients
        through services.identities, which also sees runtime clients (#235)."""
        for client in self.settings.clients:
            if client.client_id == client_id:
                return client
        return None

    @contextmanager
    def holding_loads(self) -> Iterator[None]:
        """No load of this manager runs while the block does.

        For a caller whose check against the declared configuration and the
        action that depends on it must not straddle a reload (#235: creating a
        runtime object under a name a concurrent reload is about to declare).
        Reentrant, like the load itself.
        """
        with self._load_lock:
            yield

    @property
    def _loaded_fingerprints(self) -> Tuple[Optional[Fingerprint], ...]:
        return self._loaded_state[0]

    @property
    def _loaded_racy(self) -> bool:
        return self._loaded_state[1]

    def refresh_if_changed(self) -> bool:
        """Adopt the files if another writer changed them since they were
        loaded: whether a reload happened (#354, step 4a).

        For a process that shares its runtime store with others, at the start
        of every operation. A stat of the two files is the fast negative; the
        revision of their bytes is the answer, so the same bytes under a new
        fingerprint are no reload.

        A reload that fails leaves the loaded configuration in force and is
        said once for that pair of files. What happens next depends on what
        failed. Files the bytes alone refuse (they do not parse or validate)
        are remembered and not tried again until the bytes change. A failure
        that depends on something outside them (an I/O error, an activation
        whose external key is not there yet, a plugin) is tried again, not
        sooner than ``_TRANSIENT_RETRY_SECONDS`` later, the same files
        included; bytes that change end any wait at once. A lock that cannot
        be taken is neither: LockUnavailableError, since the files could not
        be observed at all. And a failure after the load was committed (the
        after_load step) is raised as it is.
        """
        arrived = self._established
        quick = self._quick_answer()
        if quick is not None:
            return quick
        # One check at a time. The others wait for it a moment (an ordinary
        # reload is quick) and then answer from what it established; one
        # that waits for a peer's lock does not hold them past the moment.
        if not self._freshness_lock.acquire(timeout=_FOLLOWER_WAIT_SECONDS):
            raise LockUnavailableError(
                f"the configuration in {self.config_dir} is being looked at by another request; try again",
                kind="freshness_in_progress",
            )
        try:
            if self._established != arrived:
                # A check made since this request arrived established the
                # files: its result is this request's too, racy stat or not.
                return False
            quick = self._quick_answer()
            if quick is not None:
                return quick
            return self._refresh_now(self._pending)
        finally:
            self._freshness_lock.release()

    def _quick_answer(self) -> Optional[bool]:
        """What the stat alone can say: False, nothing to do; None, the
        files have to be looked at."""
        pending = self._pending
        if pending is not None and pending.revisions is None and _now() < pending.retry_after:
            # The files could not be read a moment ago: not at request rate.
            return False
        try:
            current = tuple(self._store.fingerprint_of(name) for name in _FILES)
        except OSError as failure:
            return self._unreadable(failure)
        if pending is not None:
            # The fast negative is not "the loaded files" while a failure is
            # waiting to be tried again, or the wait would never end.
            if current == pending.fingerprints and _now() < pending.retry_after:
                return False
            return None
        # A stat as recent as the read is not trusted (racily clean): a write
        # in place within the timestamp's tick leaves it as it was.
        fingerprints, racy = self._loaded_state
        if current == fingerprints and not racy:
            return False
        if self._refused is not None and current == self._refused[1] and not self._refused[2]:
            return False
        return None

    def _refresh_now(self, pending: Optional[_Pending]) -> bool:
        """The slow path of refresh_if_changed, one caller at a time."""
        with self._load_lock:
            read_at = _wall_ns()
            try:
                observed = self._store.read_snapshot(_FILES)
            except OSError as failure:
                return self._unreadable(failure)
            revisions = _identity_of(observed)
            fingerprints = tuple(observed[name].fingerprint for name in _FILES)
            if revisions == self._loaded_identity:
                # The bytes this configuration was loaded from: their
                # fingerprint is theirs too, trusted once it is older than
                # this read by the margin.
                self._loaded_state = (fingerprints, _racy(fingerprints, read_at))
                self._pending = None
                self._established += 1
                return False
            if self._refused is not None and revisions == self._refused[0]:
                self._refused = (revisions, fingerprints, _racy(fingerprints, read_at))
                self._pending = None
                self._established += 1
                return False
            pending = self._pending
            if pending is not None and revisions == pending.revisions and _now() < pending.retry_after:
                self._pending = _Pending(revisions, fingerprints, pending.retry_after)
                return False
            commits = self._commits
            self._last_observed = None
            try:
                self.reload_local()
            except Exception as failure:
                lock = _lock_behind(failure)
                if lock is not None:
                    raise lock from failure
                if self._commits != commits:
                    # Files loaded and were committed (these, or newer ones a
                    # peer wrote in between): what failed ran after, in the
                    # after_load step, and is not the files' to say.
                    raise
                # What is refused is what the load read, which a peer may
                # have changed since the look above.
                if self._last_observed is not None:
                    revisions, fingerprints, read_at = self._last_observed
                said = pending is not None and pending.revisions == revisions
                if _decided_by_the_bytes(failure):
                    self._refused = (revisions, fingerprints, _racy(fingerprints, read_at))
                    self._pending = None
                    self._established += 1
                    until = "until they change again"
                else:
                    self._pending = _Pending(revisions, fingerprints, _now() + _TRANSIENT_RETRY_SECONDS)
                    until = f"and they are tried again in {_TRANSIENT_RETRY_SECONDS:g} s"
                (logger.debug if said else logger.warning)(
                    "The configuration files in %s changed and could not be loaded (%s); the configuration "
                    "loaded before stays in force, %s",
                    self.config_dir,
                    failure,
                    until,
                )
                return False
            self._refused = None
            self._pending = None
            self._established += 1
            return True

    def _unreadable(self, failure: OSError) -> bool:
        """The files could not even be looked at (a permission, an I/O
        error): the configuration loaded stays in force, and they are looked
        at again in a while. Said once for as long as it lasts."""
        pending = self._pending
        said = pending is not None and pending.revisions is None
        self._pending = _Pending(None, None, _now() + _TRANSIENT_RETRY_SECONDS)
        (logger.debug if said else logger.warning)(
            "The configuration files in %s could not be read (%s); the configuration loaded before stays in "
            "force, and they are looked at again in %g s",
            self.config_dir,
            failure,
            _TRANSIENT_RETRY_SECONDS,
        )
        return False

    def act_on_current_files(self, act: Callable[[], _T]) -> _T:
        """``act()`` with the directory lock held and the loaded configuration
        the files' (#354, step 4a).

        For a mutation whose check against the declared configuration and
        whose effect must not straddle a writer of another process: the
        creation of a runtime user or client. The lock is not reentrant
        (#246), so when the files moved it is released for the reload and
        taken again, and the files looked at again, since they may move once
        more in between: only the last pass, in which the loaded
        configuration is the files', acts. A reload that fails refuses the
        act. A writer that does not take the lock is not held off.
        """
        with self._load_lock:
            while True:
                with self._store.locked():
                    try:
                        observed = self._store.read_snapshot_within_lock(_FILES)
                    except OSError as unreadable:
                        # Not observed at all: nothing to check against, and
                        # coming back may help.
                        raise DeclaredConfigurationUnloadable(
                            f"the configuration files in {self.config_dir} could not be read, so this cannot be "
                            f"checked against them: {unreadable}",
                            temporary=True,
                        ) from unreadable
                    if _identity_of(observed) == self._loaded_identity:
                        return act()
                try:
                    self.reload_local()
                except (ConfigurationRejected, HookError) as rejected:
                    lock = _lock_behind(rejected)
                    if lock is not None:
                        raise lock from rejected
                    raise DeclaredConfigurationUnloadable(
                        f"the configuration files in {self.config_dir} do not load, so this cannot be checked "
                        f"against them: {rejected.message}",
                        temporary=not _decided_by_the_bytes(rejected),
                    ) from rejected

    def act_if_files_are_loaded(self, act: Callable[[], _T]) -> Tuple[bool, Optional[_T]]:
        """``act()`` with the directory lock held, if the files are still the
        loaded ones; ``(False, None)`` and nothing done, nothing loaded,
        otherwise (#354, step 4b).

        For a caller inside a load (the after_load step), where
        act_on_current_files would reload and so load inside a load. Files
        that moved since are the next load's to decide on: a destructive
        decision is never made on a declaration known not to be the files'
        any more."""
        with self._load_lock:
            with self._store.locked():
                if _identity_of(self._store.read_snapshot_within_lock(_FILES)) != self._loaded_identity:
                    return False, None
                return True, act()

    def reload(self) -> None:
        """Reload configuration from files: the EXTERNAL reload.

        Runs on_before_load first (render from a store, ...), then reads the
        files. This is what startup, POST /api/config/reload and the MCP
        reload_config tool do.
        """
        self._load_config()
        logger.info("Configuration reloaded")

    def reload_local(self) -> None:
        """Refresh the in-memory configuration from the LOCAL files only.

        No on_before_load: this is the post-write refresh. After a local
        write the files on disk are the newest state by definition, and
        letting on_before_load pull from a mirror that has not caught up yet
        (or whose push just failed) would silently roll the write back
        (#185 review). Only an explicit reload() consults the mirror.
        """
        self._load_config(run_before_load=False)
        logger.info("Configuration refreshed from local files")

    def save(
        self,
        expected_users_revision: Optional[str] = None,
        expected_settings_revision: Optional[str] = None,
    ) -> None:
        """Save current configuration to YAML files, as one coordinated,
        conflict-checked save (#229) - not a filesystem transaction: see
        compare_and_replace_many's docstring for exactly what is and
        isn't atomic across the two files.

        Both files' expected_*_revision (when given) are checked against
        their on-disk revision before either file is written -
        compare_and_replace_many refuses the whole save with
        ConflictError, naming the stale file, before touching anything.
        A stale settings revision must not leave a freshly-written
        users.yaml on disk with the in-memory settings change silently
        dropped (#229 review on phase 2). This is a write-side guarantee
        only until #246: the read side now goes through the same boundary,
        so _stage_directory acquires the directory once and observes both
        files together, and a concurrent save() in another process can no
        longer land its users.yaml between this process's two reads. None
        (the default) keeps a file's write unconditional, same as
        compare_and_replace's own default.

        Once both files are written, each fires its own on_config_saved
        hook; the runtime is then refreshed from disk exactly once - not
        after each file, which would let the users.yaml reload's fresh
        Settings/User objects discard the very in-memory settings.yaml
        change this call just persisted.

        Three distinct outcomes past this point, in priority order
        (#229 review, blocking 3 - a caller must be able to tell these
        apart, so each is a different exception):

        1. Nothing was written: ConflictError, from the check above.
        2. Both files were written, but a hook failed under
           hooks.strict: HookError, raised after the runtime refresh
           (matching YamlWriter._atomic_write's write -> notify ->
           reload_local -> raise contract, per the #229 sign-off) - by
           the time it's raised, both files are on disk and the runtime
           reflects them; only the mirror push failed. Takes priority
           over outcome 3 if both happen, since "the mirror failed" is
           the contract callers already rely on.
        3. Both files were written, hooks succeeded (or none configured
           strict), but reload_local() itself raised while re-parsing
           what was just written: ReloadAfterSaveError. The write is not
           rolled back - the file is authoritative - but the in-memory
           ConfigManager keeps whatever it had before this call, same as
           any other failed _load_config. This does not replace or
           swallow a pending HookError; both are logged, only one is
           raised.
        """
        users_file = self.config_dir / "users.yaml"
        settings_file = self.config_dir / "settings.yaml"

        # Through the store, like every other access to this directory
        # (#246): the directory's own writes go through its store, named by
        # file rather than by path, because a store writes its own
        # directory. Not yet every write in the codebase - YamlWriter's
        # per-field saves still call compare_and_replace directly, through
        # the same protocol but not through this door.
        # One observation for both documents (#406): the lambdas run under
        # the directory lock, but a load commits outside it, so reading the
        # configuration twice here wrote users.yaml from one load and
        # settings.yaml from another.
        loaded = self.snapshot
        self._store.compare_and_replace_many(
            [
                (
                    "users.yaml",
                    expected_users_revision,
                    lambda doc: apply_users_document(doc, loaded.users),
                ),
                (
                    "settings.yaml",
                    expected_settings_revision,
                    # Declared state, not effective state (#172): see persistable_settings().
                    lambda doc: apply_settings_document(
                        doc, _persistable(loaded), defaults=document_defaults()
                    ),
                ),
            ],
            # Both documents are checked together, before either is
            # written (#366): a save that would leave a file the next
            # process cannot load is refused with nothing on disk.
            validate=reject_unloadable,
        )

        hook_error: Optional[HookError] = None
        try:
            self.notify_saved(users_file, "users")
        except HookError as exc:
            hook_error = exc
        try:
            self.notify_saved(settings_file, "settings")
        except HookError as exc:
            hook_error = hook_error or exc

        reload_error: Optional[Exception] = None
        try:
            self.reload_local()
        except Exception as exc:
            reload_error = exc
            logger.error(
                f"Configuration was written to {self.config_dir}, but the "
                f"runtime failed to reload it: {exc}"
            )

        if hook_error is not None:
            raise hook_error
        if reload_error is not None:
            raise ReloadAfterSaveError(
                f"Configuration was saved to {self.config_dir}, but the "
                f"runtime could not adopt it: {reload_error}"
            ) from reload_error
        logger.info(f"Configuration saved to {self.config_dir}")

    def _save_users(self, expected_revision: Optional[str] = None) -> None:
        """Save users.yaml alone via the shared compare-and-replace
        primitive (#229): still one shared builder, read-modify-write
        (#83), now also refusing a write against a stale
        expected_revision instead of silently overwriting it. save()
        does not call this - it writes both files as one coordinated
        save via compare_and_replace_many; this stays for a caller that
        legitimately wants only one file written and notified (existing
        direct-call tests in test_hooks.py)."""
        users_file = self.config_dir / "users.yaml"
        loaded = self.snapshot
        compare_and_replace(
            users_file,
            expected_revision,
            lambda doc: apply_users_document(doc, loaded.users),
            validate=reject_unloadable,
        )
        self.notify_saved(users_file, "users")

    def _save_settings(self, expected_revision: Optional[str] = None) -> None:
        """Save settings.yaml alone via the shared compare-and-replace
        primitive (#229). save() does not call this - see _save_users's
        docstring.

        Read-modify-write: keys this codebase doesn't manage (jwt, session,
        logging.level, custom keys) are preserved instead of deleted (#87).
        """
        settings_file = self.config_dir / "settings.yaml"
        # Declared state, not effective state (#172): see persistable_settings().
        compare_and_replace(
            settings_file,
            expected_revision,
            lambda doc: apply_settings_document(
                doc, self.persistable_settings(), defaults=document_defaults()
            ),
            # The same refusal save() gets (#366): one class, one contract,
            # rather than a second way in that still writes what will not
            # load back.
            validate=reject_unloadable,
        )
        self.notify_saved(settings_file, "settings")


# Global config instance
_config: Optional[ConfigManager] = None
_config_lock = threading.Lock()


def get_config_if_loaded() -> Optional[ConfigManager]:
    """The global config instance if one exists, without constructing it.

    For callers that must never trigger a load (the audit log, which may be
    written from inside a hook while the singleton is being built under
    _config_lock): None means "no configuration yet", not an error.
    """
    return _config


def get_config() -> ConfigManager:
    """Get the global config instance (thread-safe lazy init, issue #43)."""
    global _config
    if _config is None:
        with _config_lock:
            if _config is None:
                _config = ConfigManager()
    return _config


def init_config(
    config_dir: Optional[str] = None,
    profile_override: Optional[str] = None,
    strict_config: Optional[bool] = None,
    activate: Optional[Activation] = None,
    after_load: Optional[AfterLoad] = None,
) -> ConfigManager:
    """Initialize the global config instance.

    profile_override is the CLI --profile: it wins over settings.yaml's
    security_profile for the life of the process and is re-applied on every
    reload() without ever being persisted (#172). strict_config is the CLI
    --strict-config, with the same contract over config_validation (#175).
    activate is the activation step every load of this manager runs (#359);
    the server and the MCP server pass the signing service's. after_load
    runs after every successful load (#235); the server passes the runtime
    identity reconciliation.
    """
    global _config
    _config = ConfigManager(
        config_dir,
        profile_override=profile_override,
        strict_config=strict_config,
        activate=activate,
        after_load=after_load,
    )
    return _config
