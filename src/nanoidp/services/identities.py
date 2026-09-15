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
  held by a runtime object removes the runtime one, with a warning
  (``reconcile_runtime_identities``, run after every load).

Management surfaces keep working on the declared configuration: the UI
forms and pages, the persona picker, the management API under ``/api/users``
(its token endpoint, ``POST /api/users/<username>/token``, included) and the
MCP server. Exposing runtime objects there is #192's.
"""

import logging
from dataclasses import dataclass
from typing import List, Literal, Optional

from ..config import ConfigManager, OAuthClient, Settings, User, get_config
from .runtime_identities import MemoryRuntimeIdentityStore, get_runtime_identity_store

logger = logging.getLogger(__name__)

Origin = Literal["declared", "runtime"]


@dataclass(frozen=True)
class ResolvedUser:
    user: User
    origin: Origin


@dataclass(frozen=True)
class ResolvedClient:
    client: OAuthClient
    origin: Origin


class DeclaredNameCollision(ValueError):
    """A runtime object was to be created under a declared name."""


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
        declared = [ResolvedUser(user, "declared") for user in self.config.users.values()]
        runtime = [
            ResolvedUser(user, "runtime")
            for user in self.store.users.list()
            if user.username not in self.config.users
        ]
        return declared + runtime

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
        """
        runtime = self.store.clients.get(client_id)
        declared = _find_client(settings or self.config.settings, client_id)
        if declared is None and runtime is None and settings is not None:
            declared = _find_client(self.config.settings, client_id)
        if declared is not None:
            return ResolvedClient(declared, "declared")
        return ResolvedClient(runtime, "runtime") if runtime is not None else None

    def get_client(
        self, client_id: str, settings: Optional[Settings] = None
    ) -> Optional[OAuthClient]:
        resolved = self.resolve_client(client_id, settings)
        return resolved.client if resolved is not None else None

    def list_clients(self) -> List[ResolvedClient]:
        declared_clients = self.config.settings.clients
        declared_ids = {client.client_id for client in declared_clients}
        declared = [ResolvedClient(client, "declared") for client in declared_clients]
        runtime = [
            ResolvedClient(client, "runtime")
            for client in self.store.clients.list()
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
    """Declared wins on reload (#235): after a load, remove every runtime
    user or client whose name the configuration now declares.

    Runs inside the load, once the new configuration is assigned; with the
    resolver reading the store before the declared state, a lookup spanning
    the reload resolves the runtime object or the declared one, never
    neither.
    """
    store = get_runtime_identity_store()
    for user in store.users.list():
        if config.get_user(user.username) is not None:
            store.users.delete(user.username)
            logger.warning(
                "Runtime user %r removed: the configuration now declares that name",
                user.username,
            )
    declared_ids = {client.client_id for client in config.settings.clients}
    for client in store.clients.list():
        if client.client_id in declared_ids:
            store.clients.delete(client.client_id)
            logger.warning(
                "Runtime client %r removed: the configuration now declares that name",
                client.client_id,
            )
