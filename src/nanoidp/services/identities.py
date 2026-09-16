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
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

from ..config import ConfigManager, ConfigurationRejected, OAuthClient, Settings, User, get_config
from ..hooks import HookError
from .audit import get_audit_log
from .client_metadata import cached_client, looks_like_client_id_url
from .runtime_identities import MemoryRuntimeIdentityStore, get_runtime_identity_store
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

@dataclass
class _Promotion:
    """A runtime object being promoted (#192). ``written`` turns true when its
    entry reached the file but the reload after it failed; any later
    successful load resolves it (reconcile_runtime_identities)."""

    context: Dict[str, Any]
    written: bool = False


# Composition state, not repository state: the store holds only users and
# clients (#235).
_promoting: Dict[Tuple[Kind, str], _Promotion] = {}
_promoting_lock = threading.Lock()


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

        **This method never fetches.** The cache is filled by ``/authorize``,
        the one surface allowed to reach the network; every other caller,
        ``/token`` included, reads what is there or gets nothing.
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
        effective = settings or self.config.settings
        if not effective.client_id_metadata_documents_enabled:
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
        return declared + runtime

    def create_runtime_client(self, client: OAuthClient) -> OAuthClient:
        # See create_runtime_user.
        with self.config.holding_loads():
            if _find_client(self.config.settings, client.client_id) is not None:
                raise DeclaredNameCollision(
                    f"client {client.client_id!r} is declared in settings.yaml"
                )
            return self.store.clients.create(client)

    # ---- lifecycle (#192) ------------------------------------------------

    def delete_runtime_user(self, username: str) -> None:
        self._delete("user", username)

    def delete_runtime_client(self, client_id: str) -> None:
        self._delete("client", client_id)

    def reset_runtime_identities(self) -> Tuple[int, int]:
        """Remove every runtime user and client; returns (users, clients).

        Never touches the declared configuration. Waits for a promotion in
        progress, and keeps an object whose promotion wrote its entry but
        is still waiting for a successful reload: that object is on its way
        to being declared, and the next successful load resolves it.
        """
        with self.config.holding_loads():
            with _promoting_lock:
                marked = set(_promoting)
            return self._reset("user", marked), self._reset("client", marked)

    def _reset(self, kind: Kind, marked: set) -> int:
        repository = self._repository(kind)
        if not any(k == kind for k, _ in marked):
            return int(repository.delete_all())
        names = [_name_of(kind, obj) for obj in repository.list()]
        return sum(1 for name in names if (kind, name) not in marked and repository.delete(name))

    def promote_runtime_user(self, username: str, context: Dict[str, Any]) -> PromotionOutcome:
        return self._promote("user", username, lambda user: get_yaml_writer().save_user(user, is_new=True), context)

    def promote_runtime_client(self, client_id: str, context: Dict[str, Any]) -> PromotionOutcome:
        return self._promote(
            "client", client_id, lambda client: get_yaml_writer().save_client(client, is_new=True), context
        )

    def _repository(self, kind: Kind) -> Any:
        return self.store.users if kind == "user" else self.store.clients

    def _delete(self, kind: Kind, name: str) -> None:
        with _promoting_lock:
            if (kind, name) in _promoting:
                raise PromotionInProgress(f"runtime {kind} {name!r} is being promoted")
            if not self._repository(kind).delete(name):
                raise RuntimeObjectNotFound(f"no runtime {kind} {name!r}")

    def _promote(
        self, kind: Kind, name: str, write: Callable[[Any], Any], context: Dict[str, Any]
    ) -> PromotionOutcome:
        """Promotion order (#192): mark, write the entry, let the writer's
        reload retire the marked object as promoted.

        The whole promotion runs with loads held off (holding_loads): the
        only reload that can see its mark in the writing state is the one
        its own write triggers, so a declaration of the same name by someone
        else either lands first (the write finds the name: 409) or waits.

        1. The object is marked; while marked, a delete or a second promotion
           answers PromotionInProgress.
        2. The per-entry writer adds it as a new entry. When the file is not
           replaced (the name is already in the file, a revision conflict, an
           I/O error), the mark is cleared, the object stays and the error
           propagates; no audit event.
        3. Once the file is replaced, the writer reloads; the reconciliation
           removes the marked object and records the one ``promoted`` event,
           with no collision warning.
        4. A strict on_config_saved hook failing after the write and the
           reload does not undo the promotion (PromotionOutcome.mirror_error).
           A failure after the file was replaced (the configuration is
           rejected, a strict plugin does not load, or anything else the
           writer reports as a PostWriteError) leaves the object marked as
           written; the
           next successful load retires it as promoted, or, if the entry is
           no longer declared by then, abandons the promotion with a warning.
        """
        key = (kind, name)
        # Checked before waiting for loads, so a second promotion of the same
        # object answers at once instead of queuing behind the first; and
        # again under the lock, for one that started in between.
        with _promoting_lock:
            if key in _promoting:
                raise PromotionInProgress(f"runtime {kind} {name!r} is being promoted")
        with self.config.holding_loads():
            with _promoting_lock:
                if key in _promoting:
                    raise PromotionInProgress(f"runtime {kind} {name!r} is being promoted")
                obj = self._repository(kind).get(name)
                if obj is None:
                    raise RuntimeObjectNotFound(f"no runtime {kind} {name!r}")
                _promoting[key] = _Promotion(context)
            try:
                write(obj)
            except HookError as exc:
                if exc.kind == "on_config_saved":
                    _discard_promotion(key)
                    return PromotionOutcome(mirror_error=exc.message)
                _mark_written(key)  # the reload after the write failed
                raise
            except (ConfigurationRejected, PostWriteError):
                # The entry reached the file; only what follows it failed.
                _mark_written(key)
                raise
            except EntryAlreadyExists as exc:
                _discard_promotion(key)
                raise DeclaredNameCollision(f"{kind} {name!r} is already declared") from exc
            except Exception:
                _discard_promotion(key)
                raise
            _discard_promotion(key)  # already retired by the reconciliation
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
      promoted if its name is declared now (even when the object is already
      gone), abandoned with a warning if it is not, so no mark outlives a
      successful load.

    Runs inside the load, once the new configuration is assigned; with the
    resolver reading the store before the declared state, a lookup spanning
    the reload resolves the runtime object or the declared one, never
    neither. Must not raise (AfterLoad).
    """
    store = get_runtime_identity_store()
    declared_ids = {client.client_id for client in config.settings.clients}

    def declared(kind: Kind, name: str) -> bool:
        return config.get_user(name) is not None if kind == "user" else name in declared_ids

    shadowed: List[Tuple[Kind, str]] = [
        ("user", user.username) for user in store.users.list() if declared("user", user.username)
    ] + [
        ("client", client.client_id)
        for client in store.clients.list()
        if declared("client", client.client_id)
    ]
    for kind, name in shadowed:
        (store.users if kind == "user" else store.clients).delete(name)
        with _promoting_lock:
            promotion = _promoting.pop((kind, name), None)
        if promotion is not None:
            _audit("runtime_identity_promoted", kind, name, promotion.context)
            continue
        logger.warning(
            "Runtime %s %r removed: the configuration now declares that name", kind, name
        )
        _audit("runtime_identity_removed_on_reload", kind, name, {"endpoint": "reload", "method": "internal"})

    with _promoting_lock:
        pending = [(key, p) for key, p in _promoting.items() if p.written]
        for key, _ in pending:
            del _promoting[key]
    for (pending_kind, pending_name), promotion in pending:
        if declared(pending_kind, pending_name):
            _audit("runtime_identity_promoted", pending_kind, pending_name, promotion.context)
        else:
            logger.warning(
                "Promotion of runtime %s %r abandoned: the reloaded configuration does not "
                "declare it; the runtime object stays",
                pending_kind,
                pending_name,
            )
            _audit("runtime_identity_promotion_abandoned", pending_kind, pending_name, promotion.context)


def _name_of(kind: str, obj: Any) -> str:
    return str(obj.username if kind == "user" else obj.client_id)


def _discard_promotion(key: Tuple[Kind, str]) -> None:
    with _promoting_lock:
        _promoting.pop(key, None)


def _mark_written(key: Tuple[Kind, str]) -> None:
    with _promoting_lock:
        promotion = _promoting.get(key)
        if promotion is not None:
            promotion.written = True


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
