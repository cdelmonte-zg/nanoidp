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


# The three security profiles, in one place: Settings.security_profile's
# validator, the CLI --profile choices and ConfigManager's override check all
# read this tuple (#172).
SECURITY_PROFILES: tuple[str, ...] = ("dev", "stricter-dev", "oauth21")

# Today's fixed scope list (#186), now Settings.scopes_supported's default
# instead of being hardcoded in discovery.py - so discovery keeps advertising
# the same four scopes out of the box, but an operator can grow the
# vocabulary without patching code.
DEFAULT_SCOPES_SUPPORTED: tuple[str, ...] = ("openid", "profile", "email", "offline_access")


class User(BaseModel):
    """Represents a user in the system."""
    model_config = ConfigDict(extra="allow")

    username: str = Field(..., min_length=1, description="Unique username")
    password: Optional[str] = Field(
        default=None,
        min_length=1,
        description="User password. Optional - omit for a user that only "
        "authenticates via persona-mode interactive login (settings "
        "'login.mode: persona'); such a user cannot authenticate via "
        "password-mode login or the OAuth password grant.",
    )
    description: str = Field(
        default="",
        max_length=200,
        description="Optional display-only description shown in the persona login picker.",
    )
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
            "description": self.description,
            "email": self.email,
            "identity_class": self.identity_class,
            "entitlements": self.entitlements,
            "roles": self.roles,
            "groups": self.groups,
            "tenant": self.tenant,
            "source_acl": self.source_acl,
            "attributes": self.attributes,
        }


# Shared with mcp_server's pre-mutation check, so the MCP tool and this model
# can never diverge on what a valid color is (#150 review).
HEX_COLOR_PATTERN = r"^#[0-9a-fA-F]{6}$"


class OAuthClient(BaseModel):
    """Represents an OAuth client."""
    # Validate on direct attribute assignment too (e.g. MCP update_client), so the
    # field constraints below are enforced beyond construction time (#37).
    model_config = ConfigDict(validate_assignment=True)

    client_id: str = Field(..., min_length=1, description="OAuth client ID")
    client_secret: str = Field(..., min_length=1, description="OAuth client secret")
    description: str = Field(default="", description="Client description")
    background_color: Optional[str] = Field(
        default=None, pattern=HEX_COLOR_PATTERN,
        description="Optional hex background color for the /authorize page (behind the login card)",
    )
    header_color: Optional[str] = Field(
        default=None, pattern=HEX_COLOR_PATTERN,
        description="Optional hex color for the /authorize login card header band",
    )
    footer_color: Optional[str] = Field(
        default=None, pattern=HEX_COLOR_PATTERN,
        description="Optional hex color for the /authorize login card footer band",
    )
    show_client_id: bool = Field(default=True, description="Show client_id on the /authorize login page")
    show_description: bool = Field(default=False, description="Show description on the /authorize login page")
    additional_audiences: List[str] = Field(
        default_factory=list,
        description="Extra audiences added to the ID Token 'aud' alongside the client_id",
    )
    redirect_uris: List[str] = Field(
        default_factory=list,
        description=(
            "Registered redirect URIs; when non-empty, /authorize enforces exact "
            "string matching (RFC 6749 §3.1.2.3, OAuth 2.1 §4.1.1), except that a "
            "registered loopback URI (http://127.0.0.1:{port}/..., "
            "http://[::1]:{port}/...) matches any port (RFC 8252 §7.3, native "
            "apps). Private-use scheme URIs (com.example.app:/cb, RFC 8252 §7.1) "
            "are accepted when the scheme is reverse-domain based (contains a "
            "period); myapp://cb is rejected. Empty = any absolute URI with an "
            "acceptable scheme is accepted (dev default)."
        ),
    )
    allowed_scopes: List[str] = Field(
        default_factory=list,
        description=(
            "Per-client scope allow-list (issue #186). When non-empty, "
            "/authorize and /token (every grant) reject a requested scope "
            "outside this set with invalid_scope (RFC 6749 4.1.2.1/5.2); an "
            "omitted 'scope' parameter defaults to this client's full set. "
            "Empty = this client may obtain any scope in the global "
            "'oauth.scopes_supported' vocabulary (dev default) - the same "
            "'empty allow-list = unrestricted' convention as redirect_uris "
            "above. A scope outside 'oauth.scopes_supported' is always "
            "invalid_scope, for every client, regardless of this field."
        ),
    )


class Settings(BaseModel):
    """Application settings with validation."""
    # Server
    host: str = Field(default="127.0.0.1", description="Server host address")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")
    debug: bool = Field(default=False, description="Enable debug mode")

    # OAuth
    issuer: str = Field(default="http://localhost:8000", description="OAuth issuer URL")
    issuer_from_request: bool = Field(
        default=False,
        description="Derive the issuer (discovery 'issuer', token 'iss', device "
        "verification_uri) from each request's own Host header instead of the "
        "fixed 'issuer' above. Lets the same NanoIDP be reachable under more "
        "than one hostname (e.g. Docker Compose service name vs. localhost) "
        "without a discovery/token issuer mismatch. Off by default; the MCP "
        "tools have no request to derive from and always report the fixed "
        "'issuer'. The Host header is trusted as-is unless 'issuer_allowlist' "
        "below is non-empty - only enable this on trusted networks. The device "
        "flow's verification_uri follows the same derivation unless "
        "'device_verification_base_url' below overrides it - see that field "
        "when a backend/container Host would otherwise leak into a URL the "
        "human's own browser can't reach.",
    )
    issuer_allowlist: List[str] = Field(
        default_factory=list,
        description="Origins (scheme+host[:port], e.g. 'http://localhost:8000') "
        "allowed to be reflected back by 'issuer_from_request'. Empty (default) "
        "allows any Host header, matching prior behavior. When non-empty, a "
        "request whose Host doesn't match falls back to the fixed 'issuer' "
        "instead of trusting an arbitrary Host header.",
    )
    device_verification_base_url: Optional[str] = Field(
        default=None,
        description="Fixed base URL for the device flow's verification_uri "
        "(e.g. 'https://idp.example.com'), used instead of the request-derived "
        "issuer. Discovery's 'issuer' and a token's 'iss' must match the "
        "request that fetched/requested them, but the device flow's "
        "verification_uri is opened by a human, often on a different host "
        "than whatever backend/container called /device_authorization - set "
        "this to pin it to a hostname the human can actually reach. Only "
        "consulted when 'issuer_from_request' is on; ignored otherwise.",
    )
    issuer_from_proxy_headers: bool = Field(
        default=False,
        description="Trust 'X-Forwarded-Proto'/'X-Forwarded-Host'/'X-Forwarded-For' "
        "from a single reverse proxy hop in front of NanoIDP (applies werkzeug's "
        "ProxyFix). Fixes 'request.scheme'/'host_url', which the "
        "'issuer_from_request' derivation above depends on - has no visible "
        "effect on the issuer/iss/verification_uri unless 'issuer_from_request' "
        "is also on. Also affects rate-limit and audit-log client IPs "
        "regardless. Off by "
        "default; only enable this when NanoIDP is deployed directly behind "
        "exactly one trusted proxy, since these headers are otherwise trivially "
        "spoofable by any client. ProxyFix is wired at app startup, so a value "
        "changed at runtime (e.g. via the Settings page or the MCP "
        "update_settings tool) only takes effect after the process restarts.",
    )
    audience: str = Field(default="default", min_length=1, description="OAuth audience")
    token_expiry_minutes: int = Field(default=60, gt=0, le=1440, description="Token expiry in minutes")
    refresh_token_rotation: bool = Field(
        default=False,
        description="Rotate refresh tokens: each refresh invalidates the consumed "
        "refresh token, so its reuse fails (lets clients test rotation handling, #46)",
    )
    clients: List[OAuthClient] = Field(default_factory=list, description="OAuth clients")
    scopes_supported: List[str] = Field(
        default_factory=lambda: list(DEFAULT_SCOPES_SUPPORTED),
        description=(
            "The global scope vocabulary (issue #186): a requested scope "
            "outside this list is invalid_scope for every client, regardless "
            "of that client's own 'allowed_scopes'. Also what discovery's "
            "'scopes_supported' advertises, so metadata never lies about what "
            "/authorize and /token will actually grant. YAML-only "
            "(oauth.scopes_supported) - like secret_key and require_ui_login, "
            "not on the Settings page or the MCP update_settings tool."
        ),
    )
    scope_enforcement: bool = Field(
        default=True,
        description=(
            "The declared value; combined with security_profile via the "
            "'scope_enforcement_active' property below - false only actually "
            "disables enforcement under the 'dev' profile (issue #186). "
            "YAML-only (oauth.scope_enforcement), like scopes_supported above."
        ),
    )
    logos_dir: Optional[str] = Field(
        default=None,
        description="Directory path where per-client logo files are stored for the "
        "/authorize login page (relative to the process cwd, or absolute). "
        "When unset (default), resolves to the Flask app's 'static/logos' "
        "subdirectory (src/nanoidp/static/logos).",
    )

    # SAML
    # None means "derived from the effective issuer" (#181): <issuer>/saml and
    # <issuer>/saml/sso, where the issuer follows issuer_from_request, the
    # proxy headers and the allowlist exactly as OIDC discovery does. An
    # explicit value wins. SAML 2.0 Metadata 2.3.2 requires entityID to be the
    # value the IdP uses as <Issuer> (Core 2.2.5), so every SAML surface reads
    # these through resolve_saml_entity_id()/resolve_saml_sso_url(), never the
    # raw fields.
    saml_entity_id: Optional[str] = Field(
        default=None,
        description="SAML entity ID; unset = derived from the effective issuer as <issuer>/saml",
    )
    saml_sso_url: Optional[str] = Field(
        default=None,
        description="SAML SSO URL; unset = derived from the effective issuer as <issuer>/saml/sso",
    )
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
    require_ui_login: bool = Field(
        default=False,
        description="Require a logged-in session (via /login) to use the config "
        "web UI - dashboard, users, clients, settings, keys, claims, audit log "
        "and token tester. Off by default: the whole management surface is "
        "unauthenticated by design for local dev use (see docs/SECURITY.md), and "
        "/login existing today does not by itself enforce anything - this setting "
        "is what makes it real. Does not affect the separate /api/* management "
        "API, which stays unauthenticated by design regardless. Satisfied by "
        "logging in via /login or via the SAML SSO inline login at /saml/sso - "
        "both authenticate through interactive_authenticate() and set the same "
        "session. With login_mode: persona (see 'login_mode' above), that "
        "authentication is identity selection only, not a credential check - so "
        "this gate then confirms a user was chosen, not that anyone was "
        "verified, and is not protection against anyone who can reach the port.",
    )
    enforce_password_check: bool = Field(
        default=False,
        description="When password_hashing is on, reject login for a user whose "
        "stored users.yaml password isn't a valid bcrypt hash, instead of "
        "silently falling back to plaintext comparison. Off by default: the "
        "plaintext fallback exists so stricter-dev/password_hashing can be "
        "turned on without instantly locking out every user until each one is "
        "re-hashed. Turning this on closes that gap - a user whose password "
        "field isn't already a bcrypt hash simply can't log in, rather than "
        "being protected only by a plaintext comparison. No effect when "
        "password_hashing is off (that path is intentionally plaintext, dev "
        "mode). YAML-only, like require_ui_login and secret_key.",
    )
    management_secret: Optional[str] = Field(
        default=None,
        description="Shared secret gating state-changing calls across all three "
        "management surfaces: the MCP server's MUTATING_TOOLS, api_bp's "
        "POST/PUT/DELETE routes, and ui_bp's mutating form actions. Off by "
        "default - unset, nothing is enforced, identical to today. Each "
        "surface proves knowledge of it differently: MCP via the existing "
        "'admin_secret' tool argument, api_bp via an 'X-Management-Secret' "
        "request header (also satisfied by an already-unlocked ui_bp session, "
        "so the dashboard's own same-origin fetch() calls keep working), "
        "ui_bp via a one-time unlock form that then trusts the session - "
        "session['management_verified'] holds an HMAC of this secret itself "
        "(keyed by secret_key), not a bare flag, so forging it requires "
        "knowing the secret too, not just secret_key (see docs/SECURITY.md, "
        "'Session Cookie Trust'). require_ui_login's session['user'] has no "
        "such binding. Independent of require_ui_login: that gate is the "
        "UI's session front door (controls who can view the dashboard), this "
        "is the write guard (controls who can change anything) - either, "
        "both, or neither can be on; ui.management_unlock is exempt from "
        "require_ui_login's redirect regardless, since gating one independent "
        "axis on the other would make it unreachable. Loadable from "
        "settings.yaml (session.management_secret) - an explicit key here, "
        "even empty/null, wins over the env vars below - or the "
        "NANOIDP_MANAGEMENT_SECRET env var; NANOIDP_MCP_ADMIN_SECRET (the "
        "MCP-only predecessor of this setting) keeps working as an alias so "
        "existing MCP setups aren't broken. YAML-only, like require_ui_login "
        "and secret_key - never on the Settings page or in the MCP "
        "update_settings schema, since a secret editable through the surface "
        "it protects isn't a secret. Must be printable ASCII: Werkzeug "
        "decodes request headers as latin-1, so a non-ASCII secret can never "
        "be matched via the X-Management-Secret header - enforced at "
        "startup, not just on that one surface, so header, form and MCP "
        "JSON all see the same secret.",
    )


    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_token_requests: bool = Field(default=True, description="Log token requests")
    log_saml_requests: bool = Field(default=True, description="Log SAML requests")
    verbose_logging: bool = Field(default=True, description="Include usernames/client_ids in logs (dev convenience)")

    # Login (persona mode, local dev convenience)
    login_mode: str = Field(
        default="password",
        description="Interactive login mode: 'password' (default) requires "
        "the configured password on /login, /authorize, /saml/sso and the "
        "device flow; 'persona' lists the configured users and logs in by "
        "selecting one, no password prompt. Opt-in, off by default - a local "
        "development/testing convenience, not an authentication mode for "
        "deployed environments. Orthogonal to 'security_profile' and to the "
        "OAuth password grant, which is unaffected either way.",
    )

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

    def resolve_saml_entity_id(self, issuer: str) -> str:
        """The entityID to advertise for ``issuer``: explicit value, else derived (#181)."""
        return self.saml_entity_id or f"{issuer.rstrip('/')}/saml"

    def resolve_saml_sso_url(self, issuer: str) -> str:
        """The SSO location to advertise for ``issuer``: explicit value, else derived (#181)."""
        return self.saml_sso_url or f"{issuer.rstrip('/')}/saml/sso"

    @field_validator("security_profile")
    @classmethod
    def validate_security_profile(cls, v: str) -> str:
        """Validate security profile."""
        if v not in SECURITY_PROFILES:
            raise ValueError(f"Security profile must be one of: {set(SECURITY_PROFILES)}")
        return v

    @field_validator("login_mode")
    @classmethod
    def validate_login_mode(cls, v: str) -> str:
        """Validate login mode."""
        valid_modes = {"password", "persona"}
        if v not in valid_modes:
            raise ValueError(f"Login mode must be one of: {valid_modes}")
        return v

    @field_validator("management_secret")
    @classmethod
    def validate_management_secret_is_ascii(cls, v: Optional[str]) -> Optional[str]:
        """Werkzeug decodes request headers as latin-1, so a non-ASCII
        management_secret never matches over the X-Management-Secret header -
        only the unlock form and MCP's JSON argument could reach it, leaving
        the header path (and any non-browser API client) permanently unable
        to authenticate (#163 review, round 2). Fail loud at startup rather
        than ship a secret that silently only half-works."""
        if v is not None and not (v.isascii() and v.isprintable()):
            raise ValueError(
                "management_secret must be printable ASCII - a non-ASCII or "
                "control character can never be matched via the "
                "X-Management-Secret request header (Werkzeug decodes "
                "headers as latin-1)"
            )
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

    @property
    def persona_mode_enabled(self) -> bool:
        """Interactive logins select a configured user instead of a password
        (local dev/testing convenience only; unrelated to 'security_profile'
        and to the OAuth password grant - see 'login_mode' above)."""
        return self.login_mode == "persona"

    @property
    def scope_enforcement_active(self) -> bool:
        """Effective scope enforcement (#186): the same 'raw field OR profile
        decides' shape as pkce_required/rotation_enabled above, just with the
        opposite polarity - this one force-ENABLES rather than force-relaxes.
        The raw scope_enforcement flag may turn enforcement off, but only
        under 'dev'; stricter-dev and oauth21 always enforce regardless of
        the raw value, exactly like a --profile override that mutates
        security_profile after construction (bypassing field validation)
        still can't be used to silently smuggle enforcement off."""
        return self.scope_enforcement or self.security_profile != "dev"

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
