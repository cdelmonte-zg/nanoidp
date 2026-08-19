"""
Configuration models for NanoIDP (#86, split out of config.py).

The Pydantic models - ``User``, ``OAuthClient``, ``Settings`` with its
field validators and the profile-derived protocol properties (#68) - plus
the YAML shape coercers used when loading them. Persistence lives in
``serialization.py``, loading and the runtime singleton in ``config.py``,
which re-exports everything here for compatibility.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

_SAML_ATTR_NAME_DEFAULTS = {
    "saml_roles_attr_name": "roles",
    "saml_groups_attr_name": "groups",
}


def normalize_saml_attr_name(field_name: str, v: Any) -> str:
    """Missing or blank falls back to the default name; the export flags,
    not the name, decide whether the attribute is emitted."""
    name = (v or "").strip() if isinstance(v, (str, type(None))) else v
    return name or _SAML_ATTR_NAME_DEFAULTS[field_name]


def _coerce_client_str_list(raw: Any, client_id: str, field: str) -> List[str]:
    """Coerce a client's list-of-strings YAML value into a clean list.

    Fields like ``additional_audiences`` and ``redirect_uris`` are ``List[str]``
    on the model, but a single value is an easy footgun in YAML
    (``additional_audiences: api://x``). Rather than let a raw Pydantic
    ``ValidationError`` abort startup, accept a scalar string by wrapping it,
    and raise a clear, client-scoped error for unsupported shapes (#35).
    """
    label = client_id or "<missing client_id>"
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (list, tuple)):
        non_strings = [a for a in raw if not isinstance(a, str)]
        if non_strings:
            raise ValueError(
                f"Client '{label}': {field} must be a list of strings, "
                f"got non-string item(s): {non_strings!r}"
            )
        return [a for a in raw if a]
    raise ValueError(
        f"Client '{label}': {field} must be a string or a list of "
        f"strings, got {type(raw).__name__}"
    )


def _coerce_additional_audiences(raw: Any, client_id: str) -> List[str]:
    """Coerce a client's ``additional_audiences`` YAML value (see above)."""
    return _coerce_client_str_list(raw, client_id, "additional_audiences")


class User(BaseModel):
    """Represents a user in the system."""
    model_config = ConfigDict(extra="allow")

    username: str = Field(..., min_length=1, description="Unique username")
    password: str = Field(..., min_length=1, description="User password")
    email: str = Field(default="", description="User email address")
    identity_class: Optional[str] = Field(default=None, description="Identity classification")
    entitlements: List[str] = Field(default_factory=list, description="User entitlements")
    roles: List[str] = Field(default_factory=list, description="User roles")
    groups: List[str] = Field(default_factory=list, description="User groups")
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
            "groups": self.groups,
            "tenant": self.tenant,
            "source_acl": self.source_acl,
            "attributes": self.attributes,
        }


class OAuthClient(BaseModel):
    """Represents an OAuth client."""
    # Validate on direct attribute assignment too (e.g. MCP update_client), so the
    # field constraints below are enforced beyond construction time (#37).
    model_config = ConfigDict(validate_assignment=True)

    client_id: str = Field(..., min_length=1, description="OAuth client ID")
    client_secret: str = Field(..., min_length=1, description="OAuth client secret")
    description: str = Field(default="", description="Client description")
    additional_audiences: List[str] = Field(
        default_factory=list,
        description="Extra audiences added to the ID Token 'aud' alongside the client_id",
    )
    redirect_uris: List[str] = Field(
        default_factory=list,
        description=(
            "Registered redirect URIs; when non-empty, /authorize enforces exact "
            "string matching (RFC 6749 §3.1.2.3, OAuth 2.1 §4.1.1). Empty = any "
            "syntactically valid URI is accepted (dev default)."
        ),
    )


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
    refresh_token_rotation: bool = Field(
        default=False,
        description="Rotate refresh tokens: each refresh invalidates the consumed "
        "refresh token, so its reuse fails (lets clients test rotation handling, #46)",
    )
    clients: List[OAuthClient] = Field(default_factory=list, description="OAuth clients")

    # SAML
    saml_entity_id: str = Field(default="http://localhost:8000/saml", description="SAML entity ID")
    saml_sso_url: str = Field(default="http://localhost:8000/saml/sso", description="SAML SSO URL")
    default_acs_url: str = Field(default="http://localhost:8080/login/saml2/sso/samlIdp", description="Default ACS URL")
    saml_sign_responses: bool = Field(default=True, description="Sign SAML responses (set to false for testing unsigned flows)")
    saml_export_roles: bool = Field(
        default=False,
        description="Emit the user's roles as a SAML attribute (off by default)",
    )
    saml_export_groups: bool = Field(
        default=False,
        description="Emit the user's groups as a SAML attribute (off by default)",
    )
    saml_roles_attr_name: str = Field(
        default="roles",
        description="SAML attribute name carrying the roles when saml_export_roles is on",
    )
    saml_groups_attr_name: str = Field(
        default="groups",
        description="SAML attribute name carrying the groups when saml_export_groups is on",
    )
    saml_c14n_algorithm: str = Field(
        default="exc_c14n",
        description="XML canonicalization algorithm: 'exc_c14n' (Exclusive 1.0, default), 'c14n' (1.0), or 'c14n11' (1.1)"
    )
    saml_want_authn_requests_signed: bool = Field(
        default=False,
        description="Require and verify signatures on AuthnRequests, both "
        "bindings (#69); advertised as WantAuthnRequestsSigned in metadata",
    )
    saml_sp_certificates: List[str] = Field(
        default_factory=list,
        description="PEM certificate files of SPs whose AuthnRequest "
        "signatures are accepted",
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
    security_profile: str = Field(
        default="dev", description="Security profile: dev, stricter-dev or oauth21"
    )
    cors_allowed_origins: List[str] = Field(default_factory=lambda: ["*"], description="CORS allowed origins")
    rate_limit_enabled: bool = Field(default=False, description="Enable rate limiting")
    rate_limit_token_endpoint: str = Field(default="10/minute", description="Rate limit for /token endpoint")
    password_hashing: bool = Field(default=False, description="Use bcrypt for password hashing")
    require_pkce: bool = Field(
        default=False,
        description="Reject /authorize requests without a PKCE code_challenge "
        "(enabled by the stricter-dev profile, #47)",
    )

    # Key management
    external_private_key: Optional[str] = Field(default=None, description="Path to external private PEM key")
    external_public_key: Optional[str] = Field(default=None, description="Path to external public PEM key")
    external_key_id: Optional[str] = Field(default=None, description="Key ID for external keys")
    max_previous_keys: int = Field(default=2, ge=0, le=10, description="Max previous keys to keep in JWKS")

    @field_validator("saml_roles_attr_name", "saml_groups_attr_name", mode="before")
    @classmethod
    def _validate_saml_attr_name(cls, v: Any, info: ValidationInfo) -> str:
        return normalize_saml_attr_name(str(info.field_name), v)

    @field_validator("security_profile")
    @classmethod
    def validate_security_profile(cls, v: str) -> str:
        """Validate security profile."""
        valid_profiles = {"dev", "stricter-dev", "oauth21"}
        if v not in valid_profiles:
            raise ValueError(f"Security profile must be one of: {valid_profiles}")
        return v

    # ------------------------------------------------------------------
    # Derived protocol behavior (#68). Routes and the shared discovery
    # builder consume these properties instead of raw fields, so a profile
    # means the same thing whether it comes from --profile or settings.yaml,
    # and discovery can never advertise something the endpoints don't do.
    # oauth21 = draft-ietf-oauth-v2-1 protocol strictness only; runtime
    # hardening (bcrypt, CORS, rate limiting) stays stricter-dev's job.
    # ------------------------------------------------------------------

    @property
    def pkce_required(self) -> bool:
        """PKCE mandatory on the authorization code flow (OAuth 2.1 §4.1.1)."""
        return self.require_pkce or self.security_profile == "oauth21"

    @property
    def pkce_plain_allowed(self) -> bool:
        """'plain' is rejected by stricter-dev (#47) and oauth21 (§7.5.2)."""
        return self.security_profile not in ("stricter-dev", "oauth21")

    @property
    def rotation_enabled(self) -> bool:
        """Refresh token rotation, forced on by oauth21 (§4.3.1)."""
        return self.refresh_token_rotation or self.security_profile == "oauth21"

    @property
    def password_grant_enabled(self) -> bool:
        """OAuth 2.1 removes the resource-owner password grant entirely."""
        return self.security_profile != "oauth21"

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
