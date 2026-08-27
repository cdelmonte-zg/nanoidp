"""
Configuration management for NanoIDP.
Loads settings and users from YAML files.
Uses Pydantic for validation and schema enforcement.
"""

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
)
from .hooks import SOURCE_SETTINGS, HookRegistry, bootstrap_registry
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
    atomic_write_yaml,
    check_config_version,
    load_yaml_document,
)
from .serialization import expand_env_vars as _expand_env_vars

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages configuration loading and access."""

    def __init__(
        self,
        config_dir: Optional[str] = None,
        profile_override: Optional[str] = None,
        strict_config: Optional[bool] = None,
    ) -> None:
        self.config_dir = Path(config_dir or self._find_config_dir())
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
        self.strict_config: bool = self._effective_strict(self._peek_validation_mode())
        self._declared: Dict[str, Any] = {}
        self.settings: Settings = Settings()
        self.users: Dict[str, User] = {}
        self.default_user: str = "admin"
        # Effective config schema version of the loaded files (#175): the
        # declared value, or 1 when a file carries no config_version key.
        self.config_version: int = IMPLICIT_CONFIG_VERSION
        # Hooks and plugins (#185): the bootstrap surface (bootstrap.yaml in
        # the config dir, NANOIDP_BOOTSTRAP_HOOK / _PLUGIN) is read before
        # the first load because settings.yaml may be what a hook renders;
        # settings.yaml's own hooks: / plugins: are merged in after each load.
        # bootstrap.yaml is read before settings.yaml (it may be what renders
        # it), so the strictness it follows comes from a raw peek at
        # settings.yaml's config_validation above: one contract per directory.
        self.hooks: HookRegistry = bootstrap_registry(
            self.config_dir, strict_config=self.strict_config
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

    def _peek_validation_mode(self) -> str:
        """``config_validation`` as declared by settings.yaml, read raw.

        Needed before the document loader runs (it decides how that loader
        reports) and before bootstrap.yaml is read. A file that cannot be
        parsed at all returns the default here and fails with its real error
        a moment later, in _stage_directory, where the message belongs.
        """
        settings_file = self.config_dir / "settings.yaml"
        if not settings_file.exists():
            return "warn"
        try:
            with open(settings_file, "r") as f:
                data = yaml.safe_load(f) or {}
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
        settings, users, default_user, strict_config, config_version, the
        profile hardening and the hook registry exactly as they were.
        """
        # on_before_load: bootstrap hooks run once (first load only), the
        # settings.yaml-declared ones on every load. The registry enforces
        # the once-only rule; under hooks.strict a failure raises HookError
        # here, before anything is read.
        if run_before_load:
            self.hooks.run_before_load(self.config_dir)
        staged = self._stage_directory()
        self._commit_directory(staged)
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

    def persistable_settings(self) -> Settings:
        """The declared configuration state, as opposed to the effective one.

        Identical to self.settings except for the fields _apply_profile()
        forced, which carry the value the file declared. This is what the
        writer serializes: a transient --profile, or the hardening a profile
        implies, must never be written into the operator's file, where it
        would survive the next start without the flag.
        """
        if not self._declared:
            return self.settings
        return self.settings.model_copy(update=self._declared)

    def _stage_directory(self) -> Dict[str, Any]:
        """Parse and validate the whole directory into candidates, committing
        nothing. Any exception here leaves the manager untouched."""
        staged: Dict[str, Any] = {}
        settings_file = self.config_dir / "settings.yaml"
        if not settings_file.exists():
            logger.warning(f"Settings file not found: {settings_file}, using defaults")
            staged["settings_missing"] = True
            staged["strict"] = self._effective_strict("warn")
            staged["version"] = IMPLICIT_CONFIG_VERSION
            staged["settings"] = self._default_settings()
            staged["hooks_section"] = None
            staged["plugins"] = {}
        else:
            with open(settings_file, "r") as f:
                data = yaml.safe_load(f) or {}
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
        if not users_file.exists():
            logger.warning(f"Users file not found: {users_file}, using defaults")
            staged["users"], staged["default_user"] = self._default_users(), "admin"
        else:
            with open(users_file, "r") as f:
                udata = yaml.safe_load(f) or {}
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
            staged["users"], staged["default_user"] = load_users_document(
                udata, users_file, strict=staged["strict"]
            ).to_users()
        return staged

    def _commit_directory(self, staged: Dict[str, Any]) -> None:
        """Promote a fully validated staging to the runtime.

        The hook registry goes first because it is the only step that can
        still fail (strict plugin load), and replace_source() rolls itself
        back on failure (#200 review); everything after is plain assignment.
        """
        if staged["settings_missing"]:
            # A vanished settings.yaml takes its hooks, plugins and policy
            # with it (#185 review); bootstrap entries stay.
            self.hooks.drop_source(SOURCE_SETTINGS)
            self._hooks_snapshot = None
        else:
            self._configure_hooks_from(staged["hooks_section"], staged["plugins"])
        self.settings = staged["settings"]
        self._declared = staged["declared"]
        self.strict_config = staged["strict"]
        self.config_version = staged["version"]
        self.users = staged["users"]
        self.default_user = staged["default_user"]

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
        write; under hooks.strict the hook's failure is raised to the caller
        while the file on disk stays what was written. ConfigManager's own
        saves serialize in-memory state, so disk and runtime already agree
        when the error propagates; YamlWriter reloads before re-raising."""
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
        """Get a user by username."""
        return self.users.get(username)

    def persona_picker_entries(self) -> List[Tuple[str, str]]:
        """(username, description) pairs for the persona login picker,
        shared by all four interactive surfaces (UI, OAuth, SAML, device) so
        they can never drift on what's shown next to a user's name."""
        return [(username, user.description) for username, user in self.users.items()]

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user. Supports bcrypt when password_hashing is enabled.

        A password-less user (``password is None``) never authenticates here.
        A stored password that isn't valid bcrypt-hash format falls back to
        plaintext comparison unless enforce_password_check is on, in which
        case it's rejected outright (see Settings.enforce_password_check).
        """
        user = self.get_user(username)
        if not user or user.password is None:
            return None

        if self.settings.password_hashing:
            import bcrypt
            try:
                # Password stored as bcrypt hash
                if bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                    return user
            except (ValueError, TypeError):
                # Invalid hash format
                if self.settings.enforce_password_check:
                    logger.warning(
                        f"Invalid bcrypt hash for user {username}, rejecting login "
                        "(enforce_password_check)"
                    )
                    return None
                # Fall back to plaintext comparison
                logger.warning(f"Invalid bcrypt hash for user {username}, falling back to plaintext")
                if user.password == password:
                    return user
        else:
            # Plaintext comparison (dev mode)
            if user.password == password:
                return user

        return None

    def interactive_authenticate(self, username: str, password: str) -> Optional[User]:
        """Single choke point for the four interactive login surfaces (UI
        ``/login``, OIDC ``/authorize``, SAML ``/saml/sso``, device
        ``/device``): consults ``persona_mode_enabled`` so the persona/
        password branch isn't hand-copied at each call site.

        Persona mode: identity selection only, a non-empty ``username``
        selects the user - no credential check. Password mode: unchanged,
        delegates to ``authenticate()`` and requires both fields.
        """
        if self.settings.persona_mode_enabled:
            return self.get_user(username) if username else None
        return self.authenticate(username, password) if username and password else None

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        import bcrypt
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_client(self, client_id: Optional[str], client_secret: Optional[str]) -> bool:
        """Check client credentials.

        Accepts ``None`` (Flask's ``request.authorization`` fields are
        Optional) and fails closed: missing credentials never match.
        """
        if client_id is None or client_secret is None:
            return False
        for client in self.settings.clients:
            if client.client_id == client_id and client.client_secret == client_secret:
                return True
        return False

    def get_client(self, client_id: str) -> Optional[OAuthClient]:
        """Get a client by ID."""
        for client in self.settings.clients:
            if client.client_id == client_id:
                return client
        return None

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

    def save(self) -> None:
        """Save current configuration to YAML files."""
        self._save_users()
        self._save_settings()
        logger.info(f"Configuration saved to {self.config_dir}")

    def _save_users(self) -> None:
        """Save users to users.yaml (shared builder, read-modify-write, #83)."""
        users_file = self.config_dir / "users.yaml"
        document = load_yaml_document(users_file)
        apply_users_document(document, self.users, self.default_user)
        atomic_write_yaml(users_file, document)
        self.notify_saved(users_file, "users")

    def _save_settings(self) -> None:
        """Save settings to settings.yaml (shared builder, #83).

        Read-modify-write: keys this codebase doesn't manage (jwt, session,
        logging.level, custom keys) are preserved instead of deleted (#87).
        """
        settings_file = self.config_dir / "settings.yaml"
        document = load_yaml_document(settings_file)
        # Declared state, not effective state (#172): see persistable_settings().
        apply_settings_document(document, self.persistable_settings(), defaults=document_defaults())
        atomic_write_yaml(settings_file, document)
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
) -> ConfigManager:
    """Initialize the global config instance.

    profile_override is the CLI --profile: it wins over settings.yaml's
    security_profile for the life of the process and is re-applied on every
    reload() without ever being persisted (#172). strict_config is the CLI
    --strict-config, with the same contract over config_validation (#175).
    """
    global _config
    _config = ConfigManager(
        config_dir, profile_override=profile_override, strict_config=strict_config
    )
    return _config
