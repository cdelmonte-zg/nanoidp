"""
Configuration management for NanoIDP.
Loads settings and users from YAML files.
Uses Pydantic for validation and schema enforcement.
"""

import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from pydantic import BaseModel, Field, field_validator, ConfigDict

logger = logging.getLogger(__name__)


class User(BaseModel):
    """Represents a user in the system."""
    model_config = ConfigDict(extra="allow")

    username: str = Field(..., min_length=1, description="Unique username")
    password: str = Field(..., min_length=1, description="User password")
    email: str = Field(default="", description="User email address")
    identity_class: Optional[str] = Field(default=None, description="Identity classification")
    entitlements: List[str] = Field(default_factory=list, description="User entitlements")
    roles: List[str] = Field(default_factory=list, description="User roles")
    tenant: str = Field(default="default", description="User tenant")
    source_acl: List[str] = Field(default_factory=list, description="Source ACL list")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Custom attributes")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Basic email validation - empty or contains @."""
        if v and "@" not in v:
            raise ValueError("Invalid email format")
        return v

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "username": self.username,
            "email": self.email,
            "identity_class": self.identity_class,
            "entitlements": self.entitlements,
            "roles": self.roles,
            "tenant": self.tenant,
            "source_acl": self.source_acl,
            "attributes": self.attributes,
        }


class OAuthClient(BaseModel):
    """Represents an OAuth client."""
    client_id: str = Field(..., min_length=1, description="OAuth client ID")
    client_secret: str = Field(..., min_length=1, description="OAuth client secret")
    description: str = Field(default="", description="Client description")


class Settings(BaseModel):
    """Application settings with validation."""
    # Server
    host: str = Field(default="0.0.0.0", description="Server host address")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")
    debug: bool = Field(default=False, description="Enable debug mode")

    # OAuth
    issuer: str = Field(default="http://localhost:8000", description="OAuth issuer URL")
    audience: str = Field(default="default", min_length=1, description="OAuth audience")
    token_expiry_minutes: int = Field(default=60, gt=0, le=1440, description="Token expiry in minutes")
    clients: List[OAuthClient] = Field(default_factory=list, description="OAuth clients")

    # SAML
    saml_entity_id: str = Field(default="http://localhost:8000/saml", description="SAML entity ID")
    saml_sso_url: str = Field(default="http://localhost:8000/saml/sso", description="SAML SSO URL")
    default_acs_url: str = Field(default="http://localhost:8080/login/saml2/sso/samlIdp", description="Default ACS URL")
    saml_sign_responses: bool = Field(default=True, description="Sign SAML responses (set to false for testing unsigned flows)")
    saml_c14n_algorithm: str = Field(
        default="exc_c14n",
        description="XML canonicalization algorithm: 'exc_c14n' (Exclusive 1.0, default), 'c14n' (1.0), or 'c14n11' (1.1)"
    )
    strict_saml_binding: bool = Field(
        default=False,
        description="Enforce strict SAML binding compliance (reject GET with uncompressed data)"
    )

    # JWT
    jwt_algorithm: str = Field(default="RS256", description="JWT signing algorithm")
    keys_dir: str = Field(default="./keys", description="RSA keys directory")

    # Authority prefixes
    authority_prefixes: Dict[str, str] = Field(default_factory=dict, description="Authority claim prefixes")

    # Allowed identity classes
    allowed_identity_classes: List[str] = Field(default_factory=list, description="Allowed identity classes")

    # Session
    secret_key: str = Field(default="dev-secret-key-change-in-production", description="Flask secret key")

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_token_requests: bool = Field(default=True, description="Log token requests")
    log_saml_requests: bool = Field(default=True, description="Log SAML requests")
    verbose_logging: bool = Field(default=True, description="Include usernames/client_ids in logs (dev convenience)")

    # Security (stricter-dev profile)
    security_profile: str = Field(default="dev", description="Security profile: dev or stricter-dev")
    cors_allowed_origins: List[str] = Field(default_factory=lambda: ["*"], description="CORS allowed origins")
    rate_limit_enabled: bool = Field(default=False, description="Enable rate limiting")
    rate_limit_token_endpoint: str = Field(default="10/minute", description="Rate limit for /token endpoint")
    password_hashing: bool = Field(default=False, description="Use bcrypt for password hashing")

    # Key management
    external_private_key: Optional[str] = Field(default=None, description="Path to external private PEM key")
    external_public_key: Optional[str] = Field(default=None, description="Path to external public PEM key")
    external_key_id: Optional[str] = Field(default=None, description="Key ID for external keys")
    max_previous_keys: int = Field(default=2, ge=0, le=10, description="Max previous keys to keep in JWKS")

    @field_validator("security_profile")
    @classmethod
    def validate_security_profile(cls, v: str) -> str:
        """Validate security profile."""
        valid_profiles = {"dev", "stricter-dev"}
        if v not in valid_profiles:
            raise ValueError(f"Security profile must be one of: {valid_profiles}")
        return v

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate issuer is a valid URL."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("Issuer must be a valid HTTP(S) URL")
        return v.rstrip("/")  # Normalize: remove trailing slash

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()


class ConfigManager:
    """Manages configuration loading and access."""

    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir or self._find_config_dir())
        self.settings: Settings = Settings()
        self.users: Dict[str, User] = {}
        self.default_user: str = "admin"
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

    def _load_config(self):
        """Load all configuration files."""
        self._load_settings()
        self._load_users()
        logger.info(f"Loaded configuration from {self.config_dir}")
        logger.info(f"Loaded {len(self.users)} users")

    def _load_settings(self):
        """Load settings from settings.yaml."""
        settings_file = self.config_dir / "settings.yaml"

        if not settings_file.exists():
            logger.warning(f"Settings file not found: {settings_file}, using defaults")
            self._set_default_settings()
            return

        with open(settings_file, "r") as f:
            data = yaml.safe_load(f) or {}

        server = data.get("server", {})
        oauth = data.get("oauth", {})
        saml = data.get("saml", {})
        jwt_config = data.get("jwt", {})
        session = data.get("session", {})
        logging_config = data.get("logging", {})

        # Parse OAuth clients
        clients = []
        for client_data in oauth.get("clients", []):
            clients.append(OAuthClient(
                client_id=client_data.get("client_id", ""),
                client_secret=client_data.get("client_secret", ""),
                description=client_data.get("description", ""),
            ))

        self.settings = Settings(
            # Server
            host=server.get("host", "0.0.0.0"),
            port=server.get("port", 8000),
            debug=server.get("debug", False),
            # OAuth
            issuer=oauth.get("issuer", "http://localhost:8000"),
            audience=oauth.get("audience", "default"),
            token_expiry_minutes=oauth.get("token_expiry_minutes", 60),
            clients=clients,
            # SAML
            saml_entity_id=saml.get("entity_id", "http://localhost:8000/saml"),
            saml_sso_url=saml.get("sso_url", "http://localhost:8000/saml/sso"),
            default_acs_url=saml.get("default_acs_url", "http://localhost:8080/login/saml2/sso/samlIdp"),
            saml_sign_responses=saml.get("sign_responses", True),
            saml_c14n_algorithm=saml.get("c14n_algorithm", "exc_c14n"),
            strict_saml_binding=saml.get("strict_binding", False),
            # JWT
            jwt_algorithm=jwt_config.get("algorithm", "RS256"),
            keys_dir=jwt_config.get("keys_dir", "./keys"),
            # Authority prefixes
            authority_prefixes=data.get("authority_prefixes", {}),
            # Allowed identity classes
            allowed_identity_classes=data.get("allowed_identity_classes", []),
            # Session
            secret_key=session.get("secret_key", "dev-secret-key-change-in-production"),
            # Logging
            log_level=logging_config.get("level", "INFO"),
            log_token_requests=logging_config.get("log_token_requests", True),
            log_saml_requests=logging_config.get("log_saml_requests", True),
            verbose_logging=logging_config.get("verbose_logging", True),
        )

    def _set_default_settings(self):
        """Set default settings with demo client."""
        self.settings = Settings(
            clients=[OAuthClient(
                client_id="demo-client",
                client_secret="demo-secret",
                description="Default demo client"
            )],
            authority_prefixes={
                "roles": "ROLE_",
                "identity_class": "IDENTITY_",
                "entitlements": "ENT_",
            },
            allowed_identity_classes=["INTERNAL", "EXTERNAL", "PARTNER", "SERVICE"],
        )

    def _load_users(self):
        """Load users from users.yaml."""
        users_file = self.config_dir / "users.yaml"

        if not users_file.exists():
            logger.warning(f"Users file not found: {users_file}, using defaults")
            self._set_default_users()
            return

        with open(users_file, "r") as f:
            data = yaml.safe_load(f) or {}

        self.default_user = data.get("default_user", "admin")

        for username, user_data in data.get("users", {}).items():
            # Extract known fields
            known_fields = {
                "password", "email", "identity_class", "entitlements",
                "roles", "tenant", "source_acl", "attributes"
            }

            # Get explicit attributes or collect unknown fields as attributes
            attributes = user_data.get("attributes", {})

            # Any field not in known_fields becomes an attribute (for backward compatibility)
            for key, value in user_data.items():
                if key not in known_fields and key not in attributes:
                    attributes[key] = value

            self.users[username] = User(
                username=username,
                password=user_data.get("password", ""),
                email=user_data.get("email", f"{username}@example.org"),
                identity_class=user_data.get("identity_class"),
                entitlements=user_data.get("entitlements", []),
                roles=user_data.get("roles", ["USER"]),
                tenant=user_data.get("tenant", "default"),
                source_acl=user_data.get("source_acl", []),
                attributes=attributes,
            )

    def _set_default_users(self):
        """Set default users."""
        self.users = {
            "admin": User(
                username="admin",
                password="admin",
                email="admin@example.org",
                identity_class="INTERN",
                roles=["USER", "ADMIN"],
                tenant="default",
            ),
        }

    def get_user(self, username: str) -> Optional[User]:
        """Get a user by username."""
        return self.users.get(username)

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user. Supports bcrypt when password_hashing is enabled."""
        user = self.get_user(username)
        if not user:
            return None

        if self.settings.password_hashing:
            import bcrypt
            try:
                # Password stored as bcrypt hash
                if bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                    return user
            except (ValueError, TypeError):
                # Invalid hash format - fall back to plaintext comparison
                logger.warning(f"Invalid bcrypt hash for user {username}, falling back to plaintext")
                if user.password == password:
                    return user
        else:
            # Plaintext comparison (dev mode)
            if user.password == password:
                return user

        return None

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        import bcrypt
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_client(self, client_id: str, client_secret: str) -> bool:
        """Check client credentials."""
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

    def reload(self):
        """Reload configuration from files."""
        self._load_config()
        logger.info("Configuration reloaded")

    def save(self):
        """Save current configuration to YAML files."""
        self._save_users()
        self._save_settings()
        logger.info(f"Configuration saved to {self.config_dir}")

    def _save_users(self):
        """Save users to users.yaml."""
        users_file = self.config_dir / "users.yaml"

        users_data = {}
        for username, user in self.users.items():
            user_dict = {
                "password": user.password,
                "email": user.email,
                "roles": user.roles,
                "tenant": user.tenant,
            }
            if user.identity_class:
                user_dict["identity_class"] = user.identity_class
            if user.entitlements:
                user_dict["entitlements"] = user.entitlements
            if user.source_acl:
                user_dict["source_acl"] = user.source_acl
            if user.attributes:
                user_dict["attributes"] = user.attributes
            users_data[username] = user_dict

        data = {
            "users": users_data,
            "default_user": self.default_user,
        }

        with open(users_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def _save_settings(self):
        """Save settings to settings.yaml."""
        settings_file = self.config_dir / "settings.yaml"

        clients_data = []
        for client in self.settings.clients:
            clients_data.append({
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "description": client.description,
            })

        data = {
            "server": {
                "host": self.settings.host,
                "port": self.settings.port,
            },
            "oauth": {
                "issuer": self.settings.issuer,
                "audience": self.settings.audience,
                "token_expiry_minutes": self.settings.token_expiry_minutes,
                "clients": clients_data,
            },
            "saml": {
                "entity_id": self.settings.saml_entity_id,
                "sso_url": self.settings.saml_sso_url,
                "default_acs_url": self.settings.default_acs_url,
                "sign_responses": self.settings.saml_sign_responses,
                "c14n_algorithm": self.settings.saml_c14n_algorithm,
                "strict_binding": self.settings.strict_saml_binding,
            },
            "logging": {
                "verbose_logging": self.settings.verbose_logging,
            },
            "authority_prefixes": self.settings.authority_prefixes,
        }

        if self.settings.allowed_identity_classes:
            data["allowed_identity_classes"] = self.settings.allowed_identity_classes

        with open(settings_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Global config instance
_config: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get the global config instance."""
    global _config
    if _config is None:
        _config = ConfigManager()
    return _config


def init_config(config_dir: Optional[str] = None) -> ConfigManager:
    """Initialize the global config instance."""
    global _config
    _config = ConfigManager(config_dir)
    return _config
