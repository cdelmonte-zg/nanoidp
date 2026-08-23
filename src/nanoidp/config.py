"""
Configuration management for NanoIDP.
Loads settings and users from YAML files.
Uses Pydantic for validation and schema enforcement.
"""

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

# Re-exported for compatibility: the models were defined here until #86, and
# every consumer (routes, services, MCP, tests) imports them from this module.
from .models import (  # noqa: F401
    SECURITY_PROFILES,
    OAuthClient,
    Settings,
    User,
    _coerce_additional_audiences,
    _coerce_client_str_list,
)
from .serialization import (
    CONFIG_VERSION,
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
        self, config_dir: Optional[str] = None, profile_override: Optional[str] = None
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
        self._declared: Dict[str, Any] = {}
        self.settings: Settings = Settings()
        self.users: Dict[str, User] = {}
        self.default_user: str = "admin"
        # Effective config schema version of the loaded files (#175): the
        # declared value, or 1 when a file carries no config_version key.
        self.config_version: int = CONFIG_VERSION
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

    def _load_config(self) -> None:
        """Load all configuration files."""
        self._load_settings()
        self._load_users()
        logger.info(f"Loaded configuration from {self.config_dir}")
        logger.info(f"Loaded {len(self.users)} users")

    def _load_settings(self) -> None:
        """Load settings from settings.yaml, then apply the effective profile."""
        self._read_settings()
        self._apply_profile()

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

    def _apply_profile(self) -> None:
        """Make the effective security profile real on the freshly built Settings.

        Two things used to happen once in create_app() and were lost on the
        first reload() - i.e. on the first UI/MCP save (#172): the CLI
        --profile override, and the stricter-dev runtime hardening. Both
        belong here, next to the only place Settings is rebuilt, so every
        reload re-derives them.

        self.settings is the EFFECTIVE state. Every value this method forces
        is recorded in self._declared with the value the file declared (or
        the model default), so persistable_settings() can hand the writer
        the declared state and neither the override nor its derived effects
        ever reach settings.yaml (#172 review). oauth21 needs no mutation;
        its protocol strictness derives from security_profile via Settings
        properties (#68).
        """
        self._declared = {}
        if self.profile_override is not None:
            self._declared["security_profile"] = self.settings.security_profile
            self.settings.security_profile = self.profile_override
        if self.settings.security_profile == "stricter-dev":
            for field, forced in self._STRICTER_DEV_HARDENING.items():
                self._declared[field] = getattr(self.settings, field)
                setattr(self.settings, field, forced)

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

    def _read_settings(self) -> None:
        """Build Settings from settings.yaml (defaults when the file is absent)."""
        settings_file = self.config_dir / "settings.yaml"

        if not settings_file.exists():
            logger.warning(f"Settings file not found: {settings_file}, using defaults")
            self._set_default_settings()
            return

        with open(settings_file, "r") as f:
            data = yaml.safe_load(f) or {}

        # Refuse files written for a newer contract before reading any key
        # (#175): a silently half-understood file is worse than a clear stop.
        self.config_version = check_config_version(data, settings_file)
        data = _expand_env_vars(data)

        server = data.get("server", {})
        oauth = data.get("oauth", {})
        saml = data.get("saml", {})
        jwt_config = data.get("jwt", {})
        session = data.get("session", {})
        logging_config = data.get("logging", {})
        # `or {}` (not the `, {}` default) because a bare `login:` line in
        # YAML parses to `{"login": None}`, not a missing key.
        login = data.get("login") or {}

        # Parse OAuth clients
        clients = []
        for client_data in oauth.get("clients", []):
            client_id = client_data.get("client_id", "")
            clients.append(OAuthClient(
                client_id=client_id,
                client_secret=client_data.get("client_secret", ""),
                description=client_data.get("description", ""),
                background_color=client_data.get("background_color"),
                header_color=client_data.get("header_color"),
                footer_color=client_data.get("footer_color"),
                show_client_id=client_data.get("show_client_id", True),
                show_description=client_data.get("show_description", False),
                additional_audiences=_coerce_additional_audiences(
                    client_data.get("additional_audiences", []), client_id
                ),
                redirect_uris=_coerce_client_str_list(
                    client_data.get("redirect_uris", []), client_id, "redirect_uris"
                ),
            ))

        # A client_id must be unique. Duplicates - including two ${VAR}
        # placeholders that expand to the same value - make client lookup
        # ambiguous and cause the settings-save merge to match the wrong raw
        # entry, which can materialize an env-backed secret (#127/#151). Fail
        # fast rather than silently corrupt settings.yaml on the next save.
        seen_client_ids: set[str] = set()
        for parsed_client in clients:
            if parsed_client.client_id in seen_client_ids:
                raise ValueError(
                    f"Duplicate OAuth client_id '{parsed_client.client_id}' in "
                    "settings.yaml; client ids must be unique (check for env "
                    "placeholders that expand to the same value)"
                )
            seen_client_ids.add(parsed_client.client_id)

        self.settings = Settings(
            # Server
            host=server.get("host", "127.0.0.1"),
            port=server.get("port", 8000),
            debug=server.get("debug", False),
            # OAuth
            issuer=oauth.get("issuer", "http://localhost:8000"),
            issuer_from_request=oauth.get("issuer_from_request", False),
            issuer_allowlist=oauth.get("issuer_allowlist", []) or [],
            device_verification_base_url=oauth.get("device_verification_base_url"),
            issuer_from_proxy_headers=oauth.get("issuer_from_proxy_headers", False),
            audience=oauth.get("audience", "default"),
            token_expiry_minutes=oauth.get("token_expiry_minutes", 60),
            refresh_token_rotation=oauth.get("refresh_token_rotation", False),
            require_pkce=oauth.get("require_pkce", False),
            clients=clients,
            logos_dir=oauth.get("logos_dir"),
            # SAML
            saml_entity_id=saml.get("entity_id", "http://localhost:8000/saml"),
            saml_sso_url=saml.get("sso_url", "http://localhost:8000/saml/sso"),
            default_acs_url=saml.get("default_acs_url", "http://localhost:8080/login/saml2/sso/samlIdp"),
            saml_sign_responses=saml.get("sign_responses", True),
            saml_export_roles=saml.get("export_roles", False),
            saml_export_groups=saml.get("export_groups", False),
            saml_roles_attr_name=saml.get("roles_attr_name", "roles"),
            saml_groups_attr_name=saml.get("groups_attr_name", "groups"),
            saml_c14n_algorithm=saml.get("c14n_algorithm", "exc_c14n"),
            saml_want_authn_requests_signed=saml.get(
                "want_authn_requests_signed", False
            ),
            saml_sp_certificates=saml.get("sp_certificates", []) or [],
            strict_saml_binding=saml.get("strict_binding", False),
            # JWT
            jwt_algorithm=jwt_config.get("algorithm", "RS256"),
            keys_dir=jwt_config.get("keys_dir", "./keys"),
            # Login mode (persona = passwordless interactive login, local dev convenience)
            login_mode=login.get("mode", "password"),
            # Security profile (top-level; CLI --profile overrides it, #68)
            security_profile=data.get("security_profile", "dev"),
            # Authority prefixes
            authority_prefixes=data.get("authority_prefixes", {}),
            # Allowed identity classes
            allowed_identity_classes=data.get("allowed_identity_classes", []),
            # Session
            secret_key=session.get("secret_key", "dev-secret-key-change-in-production"),
            require_ui_login=session.get("require_ui_login", False),
            enforce_password_check=session.get("enforce_password_check", False),
            # Logging
            log_level=logging_config.get("level", "INFO"),
            log_token_requests=logging_config.get("log_token_requests", True),
            log_saml_requests=logging_config.get("log_saml_requests", True),
            verbose_logging=logging_config.get("verbose_logging", True),
        )

    def _set_default_settings(self) -> None:
        """Set default settings with demo client."""
        self.settings = Settings(
            clients=[OAuthClient(
                client_id="demo-client",
                client_secret="demo-secret",
                description="Default demo client"
            )],
            authority_prefixes={
                "roles": "ROLE_",
                "groups": "GROUP_",
                "identity_class": "IDENTITY_",
                "entitlements": "ENT_",
            },
            allowed_identity_classes=["INTERNAL", "EXTERNAL", "PARTNER", "SERVICE"],
        )

    def _load_users(self) -> None:
        """Load users from users.yaml."""
        users_file = self.config_dir / "users.yaml"

        if not users_file.exists():
            logger.warning(f"Users file not found: {users_file}, using defaults")
            self._set_default_users()
            return

        with open(users_file, "r") as f:
            data = yaml.safe_load(f) or {}

        # config_version is checked BEFORE placeholder expansion on purpose:
        # it must be a literal integer, never ${VAR} (#175 review).
        check_config_version(data, users_file)
        # users.yaml takes the same ${VAR} / ${VAR:default} placeholders as
        # settings.yaml (passwords, emails, attributes); until #175 only the
        # settings loader expanded them.
        data = _expand_env_vars(data)
        self.default_user = data.get("default_user", "admin")

        for username, user_data in data.get("users", {}).items():
            # Extract known fields
            known_fields = {
                "password", "email", "identity_class", "entitlements",
                "roles", "groups", "tenant", "source_acl", "attributes"
            }

            # Get explicit attributes or collect unknown fields as attributes
            attributes = user_data.get("attributes", {})

            # Any field not in known_fields becomes an attribute (for backward compatibility)
            for key, value in user_data.items():
                if key not in known_fields and key not in attributes:
                    attributes[key] = value

            self.users[username] = User(
                username=username,
                # Missing key -> None (persona-mode-only user), not "" - a
                # user without a password must never accidentally validate
                # against an empty password.
                password=user_data.get("password"),
                email=user_data.get("email", f"{username}@example.org"),
                identity_class=user_data.get("identity_class"),
                entitlements=user_data.get("entitlements", []),
                roles=user_data.get("roles", ["USER"]),
                groups=user_data.get("groups", []),
                tenant=user_data.get("tenant", "default"),
                source_acl=user_data.get("source_acl", []),
                attributes=attributes,
            )

    def _set_default_users(self) -> None:
        """Set default users."""
        self.users = {
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
        """Reload configuration from files."""
        self._load_config()
        logger.info("Configuration reloaded")

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

    def _save_settings(self) -> None:
        """Save settings to settings.yaml (shared builder, #83).

        Read-modify-write: keys this codebase doesn't manage (jwt, session,
        logging.level, custom keys) are preserved instead of deleted (#87).
        """
        settings_file = self.config_dir / "settings.yaml"
        document = load_yaml_document(settings_file)
        # Declared state, not effective state (#172): see persistable_settings().
        apply_settings_document(document, self.persistable_settings())
        atomic_write_yaml(settings_file, document)


# Global config instance
_config: Optional[ConfigManager] = None
_config_lock = threading.Lock()


def get_config() -> ConfigManager:
    """Get the global config instance (thread-safe lazy init, issue #43)."""
    global _config
    if _config is None:
        with _config_lock:
            if _config is None:
                _config = ConfigManager()
    return _config


def init_config(
    config_dir: Optional[str] = None, profile_override: Optional[str] = None
) -> ConfigManager:
    """Initialize the global config instance.

    profile_override is the CLI --profile: it wins over settings.yaml's
    security_profile for the life of the process and is re-applied on every
    reload() without ever being persisted (#172).
    """
    global _config
    _config = ConfigManager(config_dir, profile_override=profile_override)
    return _config
