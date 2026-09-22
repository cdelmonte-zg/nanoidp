"""
Configuration models for NanoIDP (#86, split out of config.py).

The Pydantic models - ``User``, ``OAuthClient``, ``Settings`` with its
field validators and the profile-derived protocol properties (#68) - plus
the YAML shape coercers used when loading them. Persistence lives in
``serialization.py``, loading and the runtime singleton in ``config.py``,
which re-exports everything here for compatibility.
"""

from typing import Any, Dict, List, Literal, Optional, Tuple, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from .totp_secret import canonical_secret

_SAML_ATTR_NAME_DEFAULTS = {
    "saml_roles_attr_name": "roles",
    "saml_groups_attr_name": "groups",
}

# The two closed sets, written once for both the domain model and the
# configuration document that feeds it (#297).
LoginMode = Literal["password", "persona"]
SamlC14nAlgorithm = Literal["exc_c14n", "c14n", "c14n11"]
# The kinds of runtime store a configuration can ask for (#354). Only the ones
# nanoidp has: the schema offers no backend that is not there.
RuntimeStoreKind = Literal["memory", "sqlite"]
SAML_C14N_DEFAULT: SamlC14nAlgorithm = "exc_c14n"


def normalize_saml_attr_name(field_name: str, v: Any) -> str:
    """Missing or blank falls back to the default name; the export flags,
    not the name, decide whether the attribute is emitted."""
    name = (v or "").strip() if isinstance(v, (str, type(None))) else v
    return name or _SAML_ATTR_NAME_DEFAULTS[field_name]


def normalize_saml_c14n_algorithm(v: Any) -> Any:
    """Missing or blank keeps the default algorithm.

    Same contract as the two attribute names above, and what lets the
    closed set be introduced without breaking a configuration that loaded
    before: ``config.py`` expands ``${VAR}`` before the document is
    validated and an unset variable expands to "", so a
    ``c14n_algorithm: ${SAML_C14N}`` that used to mean "the default" keeps
    meaning it. A non-empty value is checked against the set.
    """
    if isinstance(v, str) and not v.strip():
        return SAML_C14N_DEFAULT
    return v


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
    # Validate on direct attribute assignment too (e.g. MCP update_user), so
    # field constraints like description's max_length are enforced beyond
    # construction time - the same rule OAuthClient follows (#37).
    # hide_input_in_errors keeps a rejected totp_secret out of validation
    # error text (#348 review round 2, blocking): without it, pydantic
    # appends input_value=<the secret> to every ValueError raised on this
    # model, contradicting totp_secret.py's "the message never repeats the
    # value" promise - a persona-only user with a secret would otherwise
    # echo the whole user dict, secret included, in that same text.
    model_config = ConfigDict(
        extra="allow", validate_assignment=True, hide_input_in_errors=True
    )

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
    totp_secret: Optional[str] = Field(
        default=None,
        description="Base32 TOTP secret for the declarative second factor "
        "(settings 'login.totp', #348). The presence of a secret is the "
        "enrolment - there is no separate 'enabled' flag. A demo factor, "
        "not IdP hardening: the operator writes it in users.yaml (${VAR} "
        "allowed like any value), it is never accepted or returned by the "
        "users form, MCP create_user/update_user, or any read surface - "
        "the same treatment as 'password'.",
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Basic email validation - empty or contains @."""
        if v and "@" not in v:
            raise ValueError("Invalid email format")
        return v

    @field_validator("totp_secret")
    @classmethod
    def validate_totp_secret(cls, v: Optional[str]) -> Optional[str]:
        """Base32 or rejected (#348) - the one validation rule the issue
        specifies. ``canonical_secret`` owns both the accepted alphabet and
        the stored spelling (upper-case, unpadded), and the verifier decodes
        from that same function, so config loading and verification cannot
        drift. Two spellings of one secret therefore compare equal on the
        model.

        Only ``None`` (the field omitted) is passed through: an empty
        string reaches ``canonical_secret``, which raises "totp_secret must
        not be empty", exactly like an unset ``${VAR}`` placeholder on
        ``password`` aborts the load today. Mapping "" to None here used to
        paper over that instead, which silently disabled the factor for
        `totp_secret: "${VAR}"` with VAR unset - the user logs in on the
        password alone with no second factor and no error (#348 review,
        blocking 2). That mapping served no real surface: the users form
        and MCP create_user/update_user never send this field at all.
        """
        if v is None:
            return None
        return canonical_secret(v)

    @model_validator(mode="after")
    def _validate_totp_requires_password(self) -> "User":
        """A factor has to follow a password (#348): a secret on a
        password-less (persona-only) user is rejected at the model, the
        one home every constructor - YAML load, the users form, MCP
        create_user/update_user - shares."""
        if self.totp_secret and not self.password:
            raise ValueError(
                "totp_secret requires a password: a second factor has "
                "nothing to follow on a password-less (persona-only) user"
            )
        return self

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


#: The ``token_endpoint_auth_method`` of a client identified by its
#: client_id alone (#188), and the refusal every surface words for its own
#: audience when a confidential client is asked for without a secret.
PUBLIC_AUTH_METHOD = "none"
CLIENT_SECRET_REQUIRED = "client_secret is required unless token_endpoint_auth_method is 'none'"


class OAuthClient(BaseModel):
    """Represents an OAuth client."""
    # Validate on direct attribute assignment too (e.g. MCP update_client), so the
    # field constraints below are enforced beyond construction time (#37).
    # hide_input_in_errors: a rejected client_secret never appears in the
    # error text, like User's secrets (#352).
    model_config = ConfigDict(validate_assignment=True, hide_input_in_errors=True)

    client_id: str = Field(..., min_length=1, description="OAuth client ID")
    client_secret: Optional[str] = Field(
        default=None, min_length=1,
        description=(
            "OAuth client secret. Required unless token_endpoint_auth_method "
            "is 'none' (public client); ignored when it is."
        ),
    )
    token_endpoint_auth_method: Literal[
        "client_secret_basic", "client_secret_post", "none"
    ] = Field(
        default="client_secret_basic",
        description=(
            "How this client authenticates as a confidential client (issue "
            "#188/#262, RFC 7591). The registered method is ENFORCED, not just "
            "documented, at EVERY client-authenticated endpoint - /token, "
            "/introspect, /revoke and /device_authorization: "
            "'client_secret_basic' (default) requires the secret over HTTP "
            "Basic and rejects a body secret; 'client_secret_post' requires "
            "client_id + client_secret as POST body parameters and rejects "
            "Basic (RFC 6749 §2.3.1); presenting two methods in one request is "
            "rejected (RFC 6749 §2.3). Using the one registered method across "
            "all these endpoints is nanoidp's consistency policy: RFC 7009 and "
            "RFC 8628 tie /revoke and /device_authorization to the "
            "token-endpoint method, while RFC 7662 permits client "
            "authentication at /introspect without mandating the same method - "
            "nanoidp applies it there too rather than add a second field. "
            "Confidential clients MUST "
            "authenticate for every grant, authorization_code included "
            "(RFC 6749 §3.2.1). 'none' is a public client (CLI, desktop app, "
            "SPA, MCP client - anything that cannot keep a secret, "
            "RFC 8252/OAuth 2.1): identified by client_id alone, MUST use "
            "PKCE with S256 on /authorize regardless of profile, is refused "
            "the client_credentials grant (unauthorized_client), and always "
            "gets refresh token rotation."
        ),
    )
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
    allowed_resources: List[str] = Field(
        default_factory=list,
        description=(
            "Per-client RFC 8707 resource allow-list (issue #187). When "
            "non-empty, a 'resource' indicator requested on /authorize or "
            "/token must be one of these, otherwise the request is "
            "invalid_target. Empty = this client may target any "
            "syntactically valid resource (an absolute URI without a "
            "fragment), the dev default - same 'empty = unrestricted' "
            "convention as allowed_scopes and redirect_uris. Sending no "
            "resource at all is always allowed and leaves the access token "
            "aud at oauth.audience."
        ),
    )
    layout: Literal["vertical", "horizontal"] = Field(
        default="vertical",
        description=(
            "/authorize login card composition (issue #249). 'vertical' "
            "(default) is the single-column card: header, client block "
            "(logo, client id, description, scope badges), the form, "
            "footer. 'horizontal' places the client block and the form "
            "side by side, header and footer still full width; it "
            "collapses back to the vertical stack on narrow viewports. "
            "One of two nanoidp-owned layouts - not a general styling "
            "knob, so there is no per-client CSS or markup here."
        ),
    )

    @model_validator(mode="after")
    def _confidential_clients_need_a_secret(self) -> "OAuthClient":
        """A confidential client without a secret is a configuration error;
        only token_endpoint_auth_method 'none' makes client_secret optional.
        Runs on assignment too (validate_assignment), so switching a
        secret-less public client back to a confidential method requires
        setting the secret first."""
        if self.token_endpoint_auth_method != PUBLIC_AUTH_METHOD and not self.client_secret:
            raise ValueError(
                CLIENT_SECRET_REQUIRED
            )
        return self

    @property
    def is_public(self) -> bool:
        """Public client (issue #188): identified by client_id alone."""
        return self.token_endpoint_auth_method == PUBLIC_AUTH_METHOD


class Settings(BaseModel):
    """Application settings with validation."""
    # secret_key and management_secret are validated here; a rejected value
    # (the printable-ASCII rule on management_secret) must not reappear as
    # input_value=... in the error (#352).
    model_config = ConfigDict(hide_input_in_errors=True)

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
    client_id_metadata_documents_enabled: bool = Field(
        default=False,
        description="Accept a Client ID Metadata Document as a client source "
        "(#196): an https client_id whose metadata this server reads from a "
        "document the client publishes. Off by default, because honouring "
        "one means fetching a URL the client chose. Cached documents live "
        "in process memory, are lost on restart, and are never written to "
        "settings.yaml. The fetch itself is not implemented yet, so turning "
        "this on has no effect on its own.",
    )
    client_id_metadata_documents_allowed_hosts: List[str] = Field(
        default_factory=list,
        description="Hostnames whose client ID metadata documents this "
        "server will fetch (#196). Exact DNS names, no wildcards. Empty, the "
        "default, means none: a host is opted in one at a time.",
    )
    client_id_metadata_documents_allow_loopback: bool = Field(
        default=False,
        description="Allow a client ID metadata document on a loopback "
        "address (#196), for a test harness on the same machine. Applies "
        "only when this server is itself bound to loopback, and only to the "
        "address family it is bound to. Private, link-local and unique-local "
        "addresses are refused either way.",
    )
    dynamic_registration_enabled: bool = Field(
        default=False,
        description="Accept RFC 7591 dynamic client registration on /register "
        "(#190). Off by default: it is an unauthenticated endpoint that "
        "creates runtime clients on an instance that may be reachable from a "
        "network. Registered clients live in the runtime store, are lost on "
        "restart, and are never written to settings.yaml unless an operator "
        "promotes one through /api/runtime.",
    )
    dynamic_registration_max_clients: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="How many live dynamic registrations may exist at once "
        "(#190). A promoted or deleted client frees its slot immediately; "
        "further registrations answer 429 until one does.",
    )
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
    # A closed set in the type, not only in a tool schema (#297): an unknown
    # value used to reach routes/saml.py, which silently signed with
    # Exclusive C14N, so a typo changed the algorithm without a word. Blank
    # still means the default - see normalize_saml_c14n_algorithm.
    saml_c14n_algorithm: SamlC14nAlgorithm = Field(
        default=SAML_C14N_DEFAULT,
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
    login_mode: LoginMode = Field(
        default="password",
        description="Interactive login mode: 'password' (default) requires "
        "the configured password on /login, /authorize, /saml/sso and the "
        "device flow; 'persona' lists the configured users and logs in by "
        "selecting one, no password prompt. Opt-in, off by default - a local "
        "development/testing convenience, not an authentication mode for "
        "deployed environments. Orthogonal to 'security_profile' and to the "
        "OAuth password grant, which is unaffected either way.",
    )
    auto_login: bool = Field(
        default=False,
        description="With login_mode: persona, OIDC /authorize accepts "
        "login_hint values prefixed 'persona-auto-login:USERNAME' and logs "
        "that user in directly, no picker (#250) - for driving a real OIDC "
        "client library in automated integration tests. Opt-in, off by "
        "default; inert unless login_mode is also 'persona'. A prefixed "
        "login_hint is otherwise ignored, same as an unset flag.",
    )
    two_step: bool = Field(
        default=False,
        description="Collect username and password on separate screens, "
        "everywhere login_mode: password renders a combined form - "
        "/authorize, /login, /saml/sso and the device flow (#322/#323). "
        "Opt-in, off by default; inert under login_mode: persona, which is "
        "passwordless and has no password screen to split off.",
    )
    totp: bool = Field(
        default=False,
        description="After a successful password check, require a "
        "time-based one-time code (RFC 6238, 6 digits, 30s period, SHA-1) "
        "from any user carrying a totp_secret - on /authorize, /login, "
        "/saml/sso and the device flow, riding the same phase machinery as "
        "two_step (#348). A declarative demo factor, not IdP hardening: "
        "the secret is a plain field of the user entry, there is no "
        "enrolment, no replay protection, and no admin reset - see the "
        "'Second factor (TOTP)' docs. Opt-in, off by default; inert under "
        "login_mode: persona, which is passwordless. A user with no "
        "totp_secret sees no change either way.",
    )

    # Security (stricter-dev profile)
    security_profile: str = Field(
        default="dev", description="Security profile: dev, stricter-dev or oauth21"
    )
    cors_allowed_origins: List[str] = Field(default_factory=lambda: ["*"], description="CORS allowed origins")
    rate_limit_enabled: bool = Field(default=False, description="Enable rate limiting")
    rate_limit_token_endpoint: str = Field(default="10/minute", description="Rate limit for /token endpoint")

    @field_validator("rate_limit_token_endpoint")
    @classmethod
    def validate_rate_limit_notation(cls, v: str) -> str:
        """Reject an unparsable rate string at the config boundary (#314
        review). flask-limiter does NOT raise on a malformed string passed
        to limit(): it logs and falls back to the defaults - which nanoidp
        sets to [] - so 'rate_limit_token_endpoint: banana' would silently
        recreate the exact lie #304 exists to end (enabled-but-unenforced).
        No fallback either: a default swapped in behind the operator's back
        is just another form of configuration that lies.
        """
        from limits import parse

        try:
            parse(v)
        except Exception as e:
            raise ValueError(
                f"not a valid rate limit string (e.g. '10/minute'): {v!r}"
            ) from e
        return v
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
    runtime_store: RuntimeStoreKind = Field(
        default="memory",
        description="Where runtime state is kept (runtime.store). Chosen when the process starts: "
        "a reload that changes it is refused (#354)",
    )
    runtime_path: Optional[str] = Field(
        default=None,
        description=(
            "The file of the SQLite runtime store (runtime.path), as declared: relative to the "
            "configuration directory, or absolute. None with the in-memory store (#354)."
        ),
    )

    @field_validator("saml_roles_attr_name", "saml_groups_attr_name", mode="before")
    @classmethod
    def _validate_saml_attr_name(cls, v: Any, info: ValidationInfo) -> str:
        return normalize_saml_attr_name(str(info.field_name), v)

    @field_validator("saml_c14n_algorithm", mode="before")
    @classmethod
    def _normalize_saml_c14n_algorithm(cls, v: Any) -> Any:
        return normalize_saml_c14n_algorithm(v)

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
    def auto_login_enabled(self) -> bool:
        """'auto_login' only takes effect together with persona mode (#250);
        set without it, it is inert rather than rejected - orthogonal
        composition, same as 'persona_mode_enabled' above."""
        return self.persona_mode_enabled and self.auto_login

    @property
    def two_step_login_active(self) -> bool:
        """'two_step' is inert under persona mode (#322/#323 review round
        2): passwordless login has no password screen to split off. Single
        home for the predicate every password-form surface (/authorize,
        /login, /saml/sso, the device flow) shares, so they can never
        disagree on whether the two-screen flow is active."""
        return self.two_step and not self.persona_mode_enabled

    @property
    def totp_active(self) -> bool:
        """'totp' is inert under persona mode (#348), same composition as
        'two_step_login_active': persona login checks no password, so
        there is nothing for a second factor to follow. Single home for
        the predicate every interactive-login surface shares."""
        return self.totp and not self.persona_mode_enabled

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

    @property
    def userinfo_scope_gating_active(self) -> bool:
        """Whether /userinfo gates the standard claims by the granted scope
        (OIDC Core §5.4, #102): enforced under the stricter profiles, while
        the permissive 'dev' default keeps returning email and profile
        unconditionally.

        Deliberately not 'scope_enforcement_active' above, close as the two
        read: under 'dev' with scope_enforcement on, that one is active
        while UserInfo still returns those claims ungated. One predicate
        answering both questions would change behaviour, not just move it.
        """
        return self.security_profile in ("stricter-dev", "oauth21")

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


def login_modes() -> Tuple[str, ...]:
    """The accepted ``login_mode`` values, read from the type itself so the
    closed set is written once (#297)."""
    return get_args(LoginMode)


def validate_login_mode(value: str) -> str:
    """Check a login mode for a caller that writes YAML without building a
    Settings first (services.yaml_writer), so an invalid value never reaches
    the file."""
    if value not in login_modes():
        raise ValueError(f"Login mode must be one of: {set(login_modes())}")
    return value


def saml_c14n_algorithms() -> Tuple[str, ...]:
    """The accepted ``saml_c14n_algorithm`` values (see ``login_modes``)."""
    return get_args(SamlC14nAlgorithm)


def validate_saml_c14n_algorithm(value: str) -> str:
    """Check a canonicalization algorithm for the same caller and the same
    reason as ``validate_login_mode``, with one more consequence since #297
    closed the set: the writer replaces settings.yaml before the load that
    would reject the value, so an unchecked typo leaves behind a file the
    next process cannot load at all."""
    if value not in saml_c14n_algorithms():
        raise ValueError(
            f"SAML canonicalization algorithm must be one of: {set(saml_c14n_algorithms())}"
        )
    return value
