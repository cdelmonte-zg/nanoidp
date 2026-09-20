"""The effective identities of the IdP (#235): declared users and clients
from the configuration, composed with the runtime ones.

Three roles, kept apart:

- ``ConfigManager`` is the declared state, loaded from the YAML files.
- ``RuntimeIdentityStore`` is ephemeral state, created while the IdP runs.
- ``IdentityResolver`` is the effective read model the protocol surfaces
  use: every login, grant and client check resolves users and clients here.

The rules live here and nowhere else:

- **Declared first.** A name resolves to the declared object when there is
  one, and to the runtime object only otherwise.
- **No shadowing on creation.** A runtime object cannot be created under a
  name the configuration already declares.
- **Declared wins on reload.** A reload that introduces a declared name also
  held by a runtime object removes the runtime one, with a warning and an
  audit event (``reconcile_runtime_identities``, run after every load).
- **Promotion** (#192) writes a runtime object into the declared file and
  retires it as promoted; see ``IdentityResolver._promote``.

The observation surfaces (``/api/users`` and its token endpoint, the persona
picker, the UI lists) show the effective identities with their origin. The
edit forms and the MCP server work on the declared configuration only.
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple

from ..config import ConfigManager, ConfigurationRejected, OAuthClient, Settings, User, get_config
from ..hooks import HookError
from .audit import get_audit_log
from .client_metadata import cached_client, cached_entries, looks_like_client_id_url
from .runtime_identities import (
    MemoryRuntimeIdentityStore,
    MemoryRuntimeRepository,
    get_runtime_identity_store,
)
from .runtime_repository import Entry, RepositoryTransaction, T
from .yaml_writer import EntryAlreadyExists, PostWriteError, get_yaml_writer

logger = logging.getLogger(__name__)

# Where an identity came from. The two are not the same list: a client can
# also come from a metadata document the client itself publishes (#196),
# and there is no such thing for a user. One alias for both would make
# ResolvedUser(origin="cimd") expressible, which is not a state.
UserOrigin = Literal["declared", "runtime"]
ClientOrigin = Literal["declared", "runtime", "cimd"]


@dataclass(frozen=True)
class ResolvedUser:
    user: User
    origin: UserOrigin


@dataclass(frozen=True)
class ResolvedClient:
    client: OAuthClient
    origin: ClientOrigin


class DeclaredNameCollision(ValueError):
    """A runtime object was to be created, or promoted, under a declared name."""


class RuntimeObjectNotFound(LookupError):
    """No runtime object with that name."""


class PromotionInProgress(ValueError):
    """The runtime object is being promoted; it cannot be deleted or promoted
    again until that finishes."""


Kind = Literal["user", "client"]

# ---- the claim of a promotion (#192, #405) ------------------------------------
#
# A runtime object being promoted carries a hold, the store's own notion of a
# claim by an operation in progress (#404). It used to be a mark in a dict of
# this module, which only this process could see: another process sharing the
# store deleted the object in the middle of its promotion, or retired it on a
# reload and, knowing of no promotion, recorded an ordinary removal, so that
# the promotion was never recorded at all. On the entry, the claim is seen by
# whoever reads the entry, and travels with it to whoever retires it.
#
# The store keeps the hold and compares it; what it means is said here and
# nowhere else. ``writing``: the entry is being written into the file.
# ``written``: it reached the file and the reload after it failed, so a later
# successful load has to say how it ended.

_WRITING = "writing"
_WRITTEN = "written"


def promotion_hold(context: Dict[str, Any], state: str = _WRITING) -> Dict[str, Any]:
    """The payload of a promotion's hold. ``context`` is the promoting
    request's, for the audit entry of whoever retires the object."""
    return {"promotion": {"state": state, "context": dict(context)}}


def _promotion_of(entry: Entry[Any]) -> Optional[Dict[str, Any]]:
    """The promotion this entry is claimed by, if it is one this module
    understands: a state it knows and a context. Anything else, whoever put
    it there, is not a promotion, and nothing below has to doubt the shape
    of what this returns."""
    claim = entry.hold.payload.get("promotion") if entry.hold is not None else None
    if not isinstance(claim, dict) or claim.get("state") not in (_WRITING, _WRITTEN):
        return None
    if claim["state"] == _WRITTEN and not isinstance(claim.get("written_at"), (int, float)):
        return None  # written, and no saying when: not one of ours
    context = claim.get("context")
    return {**claim, "context": context if isinstance(context, dict) else {}}


# The hold this thread is writing the entry of, if it is in the middle of a
# promotion. Not promotion state to be shared: it is the one causal proof
# there is that a declaration about to be loaded is this promotion's own,
# since the load runs inside the write that made it, and only the writer
# has it.
_writing_here = threading.local()


@dataclass(frozen=True)
class PromotionOutcome:
    """A promotion whose file write happened. ``mirror_error`` names a strict
    on_config_saved hook that failed after the write and the reload (#185):
    the object is declared and in effect all the same."""

    mirror_error: Optional[str] = None


def _find_client(settings: Settings, client_id: str) -> Optional[OAuthClient]:
    return next((c for c in settings.clients if c.client_id == client_id), None)


class IdentityResolver:
    """Declared configuration composed with the runtime identity store."""

    def __init__(self, config: ConfigManager, store: MemoryRuntimeIdentityStore) -> None:
        self.config = config
        self.store = store

    # ---- users ----------------------------------------------------------

    def resolve_user(self, username: str) -> Optional[ResolvedUser]:
        # The store is read before the declared users: a reload assigns the
        # declared users before it removes a runtime object they now shadow,
        # so a lookup spanning that reload finds one of the two, never neither.
        runtime = self.store.users.get(username)
        declared = self.config.get_user(username)
        if declared is not None:
            return ResolvedUser(declared, "declared")
        return ResolvedUser(runtime, "runtime") if runtime is not None else None

    def get_user(self, username: str) -> Optional[User]:
        resolved = self.resolve_user(username)
        return resolved.user if resolved is not None else None

    def list_users(self) -> List[ResolvedUser]:
        # Store first, as in resolve_user: a listing spanning a reload that
        # declares a runtime object's name shows one of the two.
        runtime_users = self.store.users.list()
        declared_users = self.config.users
        declared = [ResolvedUser(user, "declared") for user in declared_users.values()]
        runtime = [
            ResolvedUser(user, "runtime")
            for user in runtime_users
            if user.username not in declared_users
        ]
        return declared + runtime

    def persona_picker_entries(self) -> List[Tuple[str, str]]:
        """(username, description) pairs for the persona login picker, shared
        by the four interactive surfaces (UI, OAuth, SAML, device) so they can
        never drift on what's shown next to a user's name. Declared and
        runtime users (#192): persona login resolves both."""
        return [(entry.user.username, entry.user.description) for entry in self.list_users()]

    def create_runtime_user(self, user: User) -> User:
        # Check and insert with loads held off: a reload declaring the name in
        # between would reconcile an empty store, then see this insert land
        # under its declared name.
        with self.config.holding_loads():
            if self.config.get_user(user.username) is not None:
                raise DeclaredNameCollision(f"user {user.username!r} is declared in users.yaml")
            return self.store.users.create(user)

    # ---- clients --------------------------------------------------------

    def resolve_client(
        self, client_id: str, settings: Optional[Settings] = None
    ) -> Optional[ResolvedClient]:
        """``settings`` is the snapshot a caller already holds (a token
        response is built from one, #359); omitted, the current settings.

        The store is read first, for the reason given in resolve_user. A
        snapshot can predate the reload that removed a runtime client, so
        when neither the snapshot nor the store has it, the current settings
        are consulted too.

        Precedence is declared, then runtime, then a cached metadata
        document (#196). A client an operator declared, or a test created,
        wins over one that published its own metadata under the same name,
        and is answered without the cache being consulted at all: an
        ``https`` client_id does not by itself make a client a CIMD one, and
        the draft contemplates pre-registered client identifier URLs.

        **This method never fetches.** It reads a cache that something else
        fills: nothing does yet, and when one does it will be ``/authorize``
        and only ``/authorize``. Every other caller, ``/token`` included,
        reads what is there or gets nothing.
        """
        runtime = self.store.clients.get(client_id)
        declared = _find_client(settings or self.config.settings, client_id)
        if declared is None and runtime is None and settings is not None:
            declared = _find_client(self.config.settings, client_id)
        if declared is not None:
            return ResolvedClient(declared, "declared")
        if runtime is not None:
            return ResolvedClient(runtime, "runtime")
        return self._resolve_cimd(client_id, settings)

    def _resolve_cimd(
        self, client_id: str, settings: Optional[Settings]
    ) -> Optional[ResolvedClient]:
        """A client from a metadata document, if one is cached and the
        feature is on.

        Unlike a client registered through #190, which keeps working as an
        ordinary client when dynamic registration is switched off, this one
        stops resolving: it is a cached copy of a document belonging to
        someone else, and the switch is what says whether such documents are
        honoured at all.
        """
        # The switch is the server's, not the request's: read from the
        # current settings even when the caller holds a snapshot, so
        # turning the feature off takes effect at the same moment on every
        # path. A snapshot exists to keep a token response consistent with
        # the settings it was built from, which is about values, not about
        # whether a capability is offered.
        if not self.config.settings.client_id_metadata_documents_enabled:
            return None
        if not looks_like_client_id_url(client_id):
            return None
        cached = cached_client(client_id)
        return ResolvedClient(cached, "cimd") if cached is not None else None

    def get_client(
        self, client_id: str, settings: Optional[Settings] = None
    ) -> Optional[OAuthClient]:
        resolved = self.resolve_client(client_id, settings)
        return resolved.client if resolved is not None else None

    def list_clients(self) -> List[ResolvedClient]:
        runtime_clients = self.store.clients.list()  # store first, see list_users
        declared_clients = self.config.settings.clients
        declared_ids = {client.client_id for client in declared_clients}
        declared = [ResolvedClient(client, "declared") for client in declared_clients]
        runtime = [
            ResolvedClient(client, "runtime")
            for client in runtime_clients
            if client.client_id not in declared_ids
        ]
        return declared + runtime + self._cimd_clients(declared_ids | {
            client.client_id for client in runtime_clients
        })

    def _cimd_clients(self, taken: Set[str]) -> List[ResolvedClient]:
        """Cached metadata-document clients, in the same order of precedence.

        Listed here rather than composed by each read surface: one place
        decides which clients exist, and a page that combined the cache
        itself would be a second answer to that question.
        """
        if not self.config.settings.client_id_metadata_documents_enabled:
            return []
        return [
            ResolvedClient(entry.client, "cimd")
            for entry in cached_entries()
            if entry.client.client_id not in taken
        ]

    def create_runtime_client(self, client: OAuthClient) -> OAuthClient:
        return self.create_runtime_client_entry(client).value

    def create_runtime_client_entry(self, client: OAuthClient) -> Entry[OAuthClient]:
        """``create_runtime_client``, returning the entry stored: how a
        caller that keeps a record about the client (#190) learns which
        instance it is about, so that a client created under the same id
        later is not taken for this one (#403, #404)."""
        # See create_runtime_user.
        with self.config.holding_loads():
            if _find_client(self.config.settings, client.client_id) is not None:
                raise DeclaredNameCollision(
                    f"client {client.client_id!r} is declared in settings.yaml"
                )
            return self.store.clients.create_entry(client)

    # ---- lifecycle (#192) ------------------------------------------------

    def delete_runtime_user(self, username: str) -> None:
        self._delete(self.store.users, "user", username)

    def delete_runtime_client(
        self, client_id: str, instance_id: Optional[str] = None
    ) -> Entry[OAuthClient]:
        """Remove the runtime client and return the entry removed.

        ``instance_id`` names the instance that is meant: a client created
        under the same id after that one went is a different client, and is
        answered as not found rather than deleted (#403). Left out, whatever
        runtime client holds the id goes, which is what an operator deleting
        by name means.
        """
        return self._delete(self.store.clients, "client", client_id, instance_id)

    def reset_runtime_identities(self) -> Tuple[int, int]:
        """Remove every runtime user and client; returns (users, clients).

        Never touches the declared configuration, and leaves alone every
        object a promotion holds, whether its entry is being written or is
        waiting for a successful load to say how it ended: that object is on
        its way to being declared. A promotion of this process is waited
        for, since it holds loads off; one of another process sharing the
        store is not, and its object is simply not counted (#405).
        """
        with self.config.holding_loads():
            return _delete_unheld(self.store.users), _delete_unheld(self.store.clients)

    def promote_runtime_user(self, username: str, context: Dict[str, Any]) -> PromotionOutcome:
        return self._promote("user", username, lambda user: get_yaml_writer().save_user(user, is_new=True), context)

    def promote_runtime_client(self, client_id: str, context: Dict[str, Any]) -> PromotionOutcome:
        return self._promote(
            "client", client_id, lambda client: get_yaml_writer().save_client(client, is_new=True), context
        )

    def _repository(self, kind: Kind) -> Any:
        return self.store.users if kind == "user" else self.store.clients

    def _delete(
        self,
        repository: MemoryRuntimeRepository[T],
        kind: Kind,
        name: str,
        instance_id: Optional[str] = None,
    ) -> Entry[T]:
        def decide(view: RepositoryTransaction[T]) -> Entry[T]:
            # The instance first, the promotion after: a caller that names
            # an instance which is gone is told exactly that, and nothing
            # about whoever holds the name now, a promotion included.
            current = view.entry(name)
            if current is None or (instance_id is not None and current.instance_id != instance_id):
                raise RuntimeObjectNotFound(f"no runtime {kind} {name!r}")
            _refuse_if_held(current, kind)
            view.delete(name)
            return current

        return repository.transact(decide)

    def _promote(
        self, kind: Kind, name: str, write: Callable[[Any], Any], context: Dict[str, Any]
    ) -> PromotionOutcome:
        """Promotion order (#192, #405): claim, write the entry, let a reload
        retire the claimed object as promoted.

        The claim is a hold on the object's entry in the store, so every
        process sharing the store sees it. Within this process the whole
        promotion also runs with loads held off (holding_loads), so a
        declaration of the same name by someone else here either lands first
        (the write finds the name: 409) or waits.

        1. The object is claimed; while it is, a delete, a reset or a second
           promotion, from any process, answers PromotionInProgress or
           leaves it alone.
        2. The per-entry writer adds the claimed value as a new entry. When
           the file is not replaced (the name is already in the file, a
           revision conflict, an I/O error), the claim is released, the
           object stays and the error propagates; no audit event.
        3. Once the file is replaced, the writer reloads; the reconciliation
           of whichever process loads the new file first retires the claimed
           object and records the one ``promoted`` event, with this
           request's context, and no collision warning.
        4. A strict on_config_saved hook failing after the write and the
           reload does not undo the promotion (PromotionOutcome.mirror_error).
           A failure after the file was replaced (the configuration is
           rejected, a strict plugin does not load, or anything else the
           writer reports as a PostWriteError) turns the claim to written;
           the next successful load retires the object as promoted, or, if
           the entry is no longer declared by then, abandons the promotion
           with a warning and releases the claim.
        """
        repository = self._repository(kind)
        # Looked at before waiting for loads, so a second promotion of the
        # same object answers at once instead of queuing behind the first.
        # Not the check that counts: the claim below is.
        seen = repository.entry(name)
        if seen is not None:
            _refuse_if_held(seen, kind)
        with self.config.holding_loads():
            claimed = _claim(repository, kind, name, context)
            _writing_here.hold_id = claimed.hold.hold_id if claimed.hold is not None else None
            try:
                # The value that was claimed, not whatever goes by the name
                # by now: the promotion is of one snapshot.
                write(claimed.value)
            except HookError as exc:
                if exc.kind == "on_config_saved":
                    _release(repository, claimed)
                    return PromotionOutcome(mirror_error=exc.message)
                _mark_written(repository, claimed)  # the reload after the write failed
                raise
            except (ConfigurationRejected, PostWriteError):
                # The entry reached the file; only what follows it failed.
                _mark_written(repository, claimed)
                raise
            except EntryAlreadyExists as exc:
                _release(repository, claimed)
                raise DeclaredNameCollision(f"{kind} {name!r} is already declared") from exc
            except Exception:
                _release(repository, claimed)
                raise
            finally:
                # A BaseException (the worker is going away) is deliberately
                # not handled above. Whether the entry reached the file is
                # then not known, and ``written`` means that it did: marking
                # it so would have a later declaration by somebody else
                # recorded as this promotion. The claim stays ``writing``,
                # which says exactly what is known. Nothing in this process
                # resolves it; the process going takes it along, and with a
                # store that outlives the process it is the recovery #354
                # owes, which looks at the declared configuration first.
                _writing_here.hold_id = None
            _release(repository, claimed)  # nothing to do once the reconciliation has retired it
            return PromotionOutcome()

    # ---- authentication -------------------------------------------------

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
        settings = self.config.settings

        if settings.password_hashing:
            import bcrypt

            try:
                # Password stored as bcrypt hash
                if bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                    return user
            except (ValueError, TypeError):
                # Invalid hash format
                if settings.enforce_password_check:
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
        if self.config.settings.persona_mode_enabled:
            return self.get_user(username) if username else None
        return self.authenticate(username, password) if username and password else None

    def check_client(self, client_id: Optional[str], client_secret: Optional[str]) -> bool:
        """Check client credentials.

        Accepts ``None`` (Flask's ``request.authorization`` fields are
        Optional) and fails closed: missing credentials never match.
        """
        if client_id is None or client_secret is None:
            return False
        client = self.get_client(client_id)
        # A public client (token_endpoint_auth_method 'none', #188) can
        # never authenticate: a stored-but-ignored secret must not become a
        # credential, and client.client_secret may be None.
        if client is None or client.is_public or client.client_secret is None:
            return False
        return client.client_secret == client_secret


def identities_for(config: ConfigManager) -> IdentityResolver:
    """The effective identities over ``config`` (the process's one manager,
    #230) and the runtime identity store."""
    return IdentityResolver(config, get_runtime_identity_store())


def get_identities() -> IdentityResolver:
    """The effective identities over the process's one ConfigManager."""
    return identities_for(get_config())


def reconcile_runtime_identities(config: ConfigManager) -> None:
    """After every successful load: declared wins (#235), and promotions
    resolve (#192).

    - A runtime object whose name the configuration now declares is
      removed. When it is being promoted, that is its promotion: one
      ``runtime_identity_promoted`` audit event, no warning. Otherwise it is
      a collision: a warning and a ``runtime_identity_removed_on_reload``
      event.
    - A promotion left in the written state by a failed reload resolves too:
      promoted if its name is declared now, abandoned with a warning if it
      is not, so a written claim does not outlive a successful load that
      is new enough to tell. A claim still writing can, on purpose: it is
      its writer's to resolve (see ``_retire``).

    What is recorded is decided by the entry each step takes out or
    releases, so with several processes on one store one winner records
    each outcome (#405). That is a guarantee against concurrency, not
    against a crash: a process that dies after taking an object out and
    before its audit entry is written records nothing, and only a durable
    audit could close that gap.

    Runs inside the load, once the new configuration is assigned; with the
    resolver reading the store before the declared state, a lookup spanning
    the reload resolves the runtime object or the declared one, never
    neither. Must not raise (AfterLoad).
    """
    store = get_runtime_identity_store()
    declared_ids = {client.client_id for client in config.settings.clients}

    def declared(kind: Kind, name: str) -> bool:
        return config.get_user(name) is not None if kind == "user" else name in declared_ids

    repositories: List[Tuple[Kind, MemoryRuntimeRepository[Any]]] = [
        ("user", store.users),
        ("client", store.clients),
    ]
    for kind, repository in repositories:
        for seen in repository.entries():
            if declared(kind, seen.name):
                _retire(repository, kind, seen.name)
            else:
                _abandon_if_written(repository, kind, seen, config.observed_at)


def _retire(repository: MemoryRuntimeRepository[Any], kind: Kind, name: str) -> None:
    """Remove the runtime object the configuration now declares, and say
    what that was.

    By name: "declared wins" is a rule about the name, whatever instance
    goes by it. What is said is decided by the entry this call took out, not
    by one seen earlier, in a listing or by another process: whoever wins
    the removal holds the claim that was on it, so a promotion is recorded
    once, as a promotion, with its own context; and whoever loses it says
    nothing, because the winner did.

    A ``written`` claim under a declared name is a promotion, for whoever
    retires it: its entry reached the file. A claim still ``writing`` is its
    writer's to resolve and nobody else's. A name can be declared by
    somebody else while an object is claimed (a hand edit, another
    process), and nothing in what was declared says who declared it, not
    even its being equal to what was claimed: the writer refuses a name
    that is taken whatever is under it, and that promotion answers 409. So
    only the thread writing the entry treats the declaration as its own;
    any other leaves the object where it is. It stays under a declared name
    for a while, which resolves to the declared one; the writer's own
    reload retires it, or its refusal frees it for the next load to remove.
    """
    mine = getattr(_writing_here, "hold_id", None)

    def decide(view: RepositoryTransaction[Any]) -> Optional[Entry[Any]]:
        current = view.entry(name)
        if current is None:
            return None
        promotion = _promotion_of(current)
        if promotion is not None and promotion["state"] == _WRITING:
            if current.hold is None or current.hold.hold_id != mine:
                return None
        view.delete(name)
        return current

    retired = repository.transact(decide)
    if retired is None:
        return
    promotion = _promotion_of(retired)
    if promotion is not None:
        _audit("runtime_identity_promoted", kind, name, promotion["context"])
        return
    logger.warning("Runtime %s %r removed: the configuration now declares that name", kind, name)
    _audit("runtime_identity_removed_on_reload", kind, name, {"endpoint": "reload", "method": "internal"})


def _abandon_if_written(
    repository: MemoryRuntimeRepository[Any], kind: Kind, seen: Entry[Any], observed_at: float
) -> None:
    """A promotion that wrote its entry, lost its reload, and whose name a
    successful load does not declare after all: the claim is released and
    the object stays. One decision, so that one caller gets the claim and
    records it; ``writing`` is left alone, its promotion being in the middle
    of its write.

    "Does not declare" is only worth something from a configuration read
    after the entry was written. A process that read the files first and
    reconciles afterwards is looking at a directory older than the entry,
    and leaves the claim to a load that can tell.
    """
    if seen.hold is None:
        return
    hold_id = seen.hold.hold_id

    def decide(view: RepositoryTransaction[Any]) -> Optional[Dict[str, Any]]:
        current = view.entry(seen.name)
        if current is None or current.hold is None or current.hold.hold_id != hold_id:
            return None
        promotion = _promotion_of(current)
        if promotion is None or promotion["state"] != _WRITTEN:
            return None
        if observed_at <= promotion["written_at"]:
            return None
        view.release_hold(seen.name, hold_id)
        return promotion

    abandoned = repository.transact(decide)
    if abandoned is None:
        return
    logger.warning(
        "Promotion of runtime %s %r abandoned: the reloaded configuration does not "
        "declare it; the runtime object stays",
        kind,
        seen.name,
    )
    _audit("runtime_identity_promotion_abandoned", kind, seen.name, abandoned["context"])


def _refuse_if_held(entry: Entry[Any], kind: str) -> None:
    # Promotions are the only operation that holds a runtime object.
    if entry.hold is not None:
        raise PromotionInProgress(f"runtime {kind} {entry.name!r} is being promoted")


def _claim(
    repository: MemoryRuntimeRepository[T], kind: Kind, name: str, context: Dict[str, Any]
) -> Entry[T]:
    """Hold the object for a promotion and return the entry that is held:
    its instance, its hold, and the value the promotion is of."""

    def decide(view: RepositoryTransaction[T]) -> Entry[T]:
        current = view.entry(name)
        if current is None:
            raise RuntimeObjectNotFound(f"no runtime {kind} {name!r}")
        _refuse_if_held(current, kind)
        held = view.hold(name, promotion_hold(context))
        return Entry(current.name, current.value, current.instance_id, held)

    return repository.transact(decide)


def _release(repository: MemoryRuntimeRepository[T], claimed: Entry[T]) -> None:
    """Give the claim up. By its own id, so never somebody else's; nothing
    to do when the object has been retired with it."""
    if claimed.hold is not None:
        hold_id = claimed.hold.hold_id
        repository.transact(lambda view: view.release_hold(claimed.name, hold_id))


def _mark_written(repository: MemoryRuntimeRepository[T], claimed: Entry[T]) -> None:
    """Turn the claim to ``written``, from what the claim itself carries:
    the context is the one given when it was made, and there is no second
    source for it. ``written_at`` is taken after the write, so a
    configuration read later than that has seen the entry if it is there."""
    promotion = _promotion_of(claimed)
    if claimed.hold is None or promotion is None:
        return
    hold_id = claimed.hold.hold_id
    payload = {"promotion": {**promotion, "state": _WRITTEN, "written_at": time.time()}}
    repository.transact(lambda view: view.update_hold(claimed.name, hold_id, payload))


def _delete_unheld(repository: MemoryRuntimeRepository[T]) -> int:
    """Remove every object nobody holds, as one step, and say how many."""

    def decide(view: RepositoryTransaction[T]) -> int:
        removed = 0
        for entry in view.entries():
            if entry.hold is None and view.delete(entry.name):
                removed += 1
        return removed

    return repository.transact(decide)


def _audit(event_type: str, kind: str, name: str, context: Dict[str, Any]) -> None:
    """An audit event from inside a load, where no request context exists and
    nothing may raise (AfterLoad)."""
    try:
        get_audit_log().log(
            event_type=event_type,
            endpoint=context.get("endpoint", "reload"),
            method=context.get("method", "internal"),
            status="success",
            username=name if kind == "user" else None,
            client_id=name if kind == "client" else None,
            ip_address=context.get("ip_address", "unknown"),
            user_agent=context.get("user_agent", "unknown"),
            details={"kind": kind, "name": name},
        )
    except Exception:  # pragma: no cover - the audit must not fail a load
        logger.exception("Could not record %s for runtime %s %r", event_type, kind, name)
