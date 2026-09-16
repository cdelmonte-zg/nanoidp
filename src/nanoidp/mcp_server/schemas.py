"""Tool declarations: JSON Schemas, compiled validators (#286).

Split out of the monolithic mcp_server module; every schema is
byte-identical in semantics to the pre-split declarations (the #283/#284
parity tests and MCP clients depend on them).
"""

from typing import Any

from jsonschema import Draft202012Validator
from mcp.types import Tool
from pydantic import BaseModel

from ..models import OAuthClient, Settings, User
from .field_schemas import field_property


def _domain(model: type[BaseModel], field: str, description: str, **overrides: Any) -> dict[str, Any]:
    """A tool property whose value shape is the domain field's (#297): the
    model states type, enum, bounds, length, pattern and item type; the
    description here states what the argument means for this tool."""
    return field_property(model, field, description, overrides=overrides or None)

# Shared by create_user's and create_persona_user's input_schema (#10): every
# field but username/password is identical between the two tools, and
# _build_user_from_arguments() reads all of these from either one - a
# property missing here would be silently ignored on that tool alone.
_USER_COMMON_PROPERTIES: dict[str, Any] = {
    "description": _domain(User, "description", "Display-only note shown in the persona login picker (optional, max 200 chars)"),
    "email": _domain(User, "email", "Email address (optional)"),
    "roles": _domain(User, "roles", "List of roles (optional, default: ['USER'])"),
    "groups": _domain(User, "groups", "List of groups (optional)"),
    "tenant": _domain(User, "tenant", "Tenant identifier (optional, default: 'default')"),
    "identity_class": _domain(User, "identity_class", "Identity class (e.g., INTERNAL, EXTERNAL)"),
    "entitlements": _domain(User, "entitlements", "List of entitlements"),
    "source_acl": _domain(User, "source_acl", "Source ACL entries for document-level security"),
    "attributes": _domain(User, "attributes", "Custom key-value attributes (optional)"),
}



# =============================================================================
# Tool Definitions
# =============================================================================

# Tool definitions, also indexed by name in call_tool() to validate arguments
# against each tool's input_schema before dispatch (the SDK no longer does
# this itself - see call_tool).
_TOOLS: list[Tool] = [
    # User Management
    Tool(
        name="list_users",
        description="List all configured users in NanoIDP",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="get_user",
        description="Get details of a specific user",
        input_schema={
            "type": "object",
            "properties": {
                "username": _domain(User, "username", "Username to look up"),
            },
            "required": ["username"],
        },
    ),
    Tool(
        name="create_user",
        description="Create a new user in NanoIDP",
        input_schema={
            "type": "object",
            "properties": {
                "username": _domain(User, "username", "Username for the new user"),
                "password": _domain(User, "password", "Password for the new user"),
                **_USER_COMMON_PROPERTIES,
            },
            "required": ["username", "password"],
        },
    ),
    Tool(
        name="create_persona_user",
        description=(
            "Create a password-less user for persona login mode (local "
            "dev/testing convenience, 'login.mode: persona' in settings). "
            "The user can only authenticate by identity selection in the "
            "interactive login UI - never via password-mode login or the "
            "OAuth password grant. To keep 'create_user' unambiguous "
            "(always creates a normal, password-protected user), this is a "
            "separate tool rather than an optional password on create_user."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "username": _domain(User, "username", "Username for the new persona-mode-only user"),
                **_USER_COMMON_PROPERTIES,
            },
            "required": ["username"],
        },
    ),
    Tool(
        name="delete_user",
        description="Delete a user from NanoIDP",
        input_schema={
            "type": "object",
            "properties": {
                "username": _domain(User, "username", "Username to delete"),
            },
            "required": ["username"],
        },
    ),
    Tool(
        name="update_user",
        description="Update an existing user's attributes",
        input_schema={
            "type": "object",
            "properties": {
                "username": _domain(User, "username", "Username to update"),
                "password": _domain(User, "password", "New password (optional)"),
                "description": _domain(User, "description", "New display-only persona picker note (optional, max 200 chars)"),
                "email": _domain(User, "email", "New email (optional)"),
                "roles": _domain(User, "roles", "New roles list (optional)"),
                "groups": _domain(User, "groups", "New groups list (optional)"),
                "tenant": _domain(User, "tenant", "New tenant (optional)"),
                "identity_class": _domain(User, "identity_class", "New identity class (optional)"),
                "entitlements": _domain(User, "entitlements", "New entitlements list (optional)"),
                "source_acl": _domain(User, "source_acl", "New source ACL entries (optional)"),
                "attributes": _domain(User, "attributes", "New custom key-value attributes (optional; replaces the "
                        "whole mapping, like every other field here - #280)"),
            },
            "required": ["username"],
        },
    ),
    # Token Operations
    Tool(
        name="generate_token",
        description=(
            "Generate an OAuth2 access token for a user. Mints the token "
            "directly (a testing/simulation affordance, not an OAuth grant): "
            "scope and resource are stamped as given, with no "
            "scopes_supported vocabulary check and no per-client "
            "allowed_scopes/allowed_resources ceiling even when client_id is "
            "supplied - minting an out-of-ceiling token is how you test a "
            "resource server's rejection path. The ceilings live on the "
            "grant endpoints (/authorize, /device_authorization, /token)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "username": _domain(User, "username", "Username to generate token for"),
                "expires_in_minutes": {
                    "type": "integer",
                    "description": "Token expiration in minutes (optional, default: 60)",
                },
                "client_id": _domain(OAuthClient, "client_id", "Bind the token to this client (optional; must name a "
                        "real client). Stamps the client_id claim and issues a "
                        "refresh token spendable by that client. Omit for an "
                        "unbound token: NO refresh token is issued (an unbound "
                        "one could not be spent since 3.0, #73), just an access "
                        "token, fine for a one-shot test"),
                "extra_claims": {
                    "type": "object",
                    "description": "Additional claims to include in the token",
                },
                "scope": {
                    "type": "string",
                    "description": (
                        "Space-separated OAuth scopes (optional). Include "
                        "'openid' to also receive an ID Token; the scope is "
                        "persisted in the refresh token so refreshing "
                        "re-issues an ID Token (OIDC Core §12.2)"
                    ),
                },
                "id_token_claims": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Claim names to embed in the ID Token, mirroring the "
                        "OIDC `claims` request parameter (§5.5). Requires an "
                        "'openid' scope. Resolved from the user (e.g. 'email', "
                        "'preferred_username', or a custom attribute); names "
                        "nanoidp cannot supply are skipped."
                    ),
                },
                "userinfo_claims": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Claim names /userinfo should return for this access "
                        "token, mirroring the `userinfo` member of the OIDC "
                        "`claims` request parameter (§5.5). Stamped on the "
                        "access token as `req_userinfo_claims` and honoured "
                        "by /userinfo even under a stricter profile that "
                        "would scope-gate them out."
                    ),
                },
                "resource": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Audience value(s) to place in the access token's 'aud' "
                        "claim (a string for one, an array for several) instead "
                        "of oauth.audience, so a token minted for one MCP server "
                        "is rejected by another (#187). Unlike the 'resource' "
                        "parameter on the OAuth grant endpoints, this "
                        "administrative/testing tool has no client context: it "
                        "applies no RFC 8707 syntax validation and no per-client "
                        "allowed_resources ceiling. The supplied values are used "
                        "directly as the audience (optional)"
                    ),
                },
            },
            "required": ["username"],
        },
    ),
    Tool(
        name="decode_token",
        description="Decode and display the claims in a JWT token (without signature verification)",
        input_schema={
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "JWT token to decode",
                },
            },
            "required": ["token"],
        },
    ),
    Tool(
        name="verify_token",
        description=(
            "Verify a JWT token's signature and expiration. Simulates a "
            "STATELESS resource server (the #191 model): it does not check "
            "revocation or the token_use claim, so a revoked access token or "
            "an ID Token presented as an access token still reports valid. "
            "Revocation is /introspect's answer, not this tool's."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "JWT token to verify",
                },
                # Not Settings.audience: this is the audience the caller
                # wants the token tested against, a resource server's own
                # identifier. Deriving it would let a future constraint on
                # the IdP's configured audience narrow what can be probed,
                # and "" is the tool's way of asking for a match against
                # the empty audience, which it answers with valid: false.
                "audience": {
                    "type": "string",
                    "description": "Expected audience (#187). Omit to verify signature "
                        "and expiry only and return the claims (so a "
                        "resource-bound access token is not falsely reported "
                        "invalid). Provide a value to also require the token's "
                        "'aud' to match it - how you simulate a resource "
                        "server accepting a token for itself and rejecting one "
                        "minted for another (optional)",
                },
            },
            "required": ["token"],
        },
    ),
    # Client Management
    Tool(
        name="list_clients",
        description="List all configured OAuth clients",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="get_client",
        description="Get details of a specific OAuth client",
        input_schema={
            "type": "object",
            "properties": {
                "client_id": _domain(OAuthClient, "client_id", "Client ID to look up"),
            },
            "required": ["client_id"],
        },
    ),
    Tool(
        name="create_client",
        description="Create a new OAuth client",
        input_schema={
            "type": "object",
            "properties": {
                "client_id": _domain(OAuthClient, "client_id", "Unique client identifier"),
                "client_secret": _domain(OAuthClient, "client_secret", "Client secret for authentication. Required unless "
                        "token_endpoint_auth_method is 'none'", minLength=None),
                "token_endpoint_auth_method": _domain(OAuthClient, "token_endpoint_auth_method", "How the client authenticates as a confidential client "
                        "(optional, default client_secret_basic). The method is "
                        "enforced at every client-authenticated endpoint - "
                        "/token, /introspect, /revoke, /device_authorization "
                        "(#188/#262): basic uses HTTP Basic, post uses the "
                        "request body, and the wrong channel is rejected. "
                        "'none' = public client (#188): no secret, PKCE S256 "
                        "mandatory on /authorize, client_credentials refused, "
                        "refresh rotation forced"),
                "description": _domain(OAuthClient, "description", "Human-readable description (optional)"),
                "background_color": _domain(OAuthClient, "background_color", "Hex color (e.g. '#1a1a2e') behind the /authorize login card (optional)", pattern=None),
                "header_color": _domain(OAuthClient, "header_color", "Hex color (e.g. '#0d6efd') for the /authorize login card header band (optional)", pattern=None),
                "footer_color": _domain(OAuthClient, "footer_color", "Hex color (e.g. '#ffffff') for the /authorize login card footer band (optional)", pattern=None),
                "show_client_id": _domain(OAuthClient, "show_client_id", "Show client_id on the /authorize login page (optional, default true)"),
                "show_description": _domain(OAuthClient, "show_description", "Show description on the /authorize login page (optional, default false)"),
                "layout": _domain(OAuthClient, "layout", "/authorize login card composition (#249): 'vertical' (default) is the single-column card; 'horizontal' places the client info and the login form side by side, collapsing back to a single column on narrow viewports (optional, default vertical)"),
                "additional_audiences": _domain(OAuthClient, "additional_audiences", "Extra audiences added to the ID Token 'aud' alongside the client_id (optional)"),
                "redirect_uris": _domain(OAuthClient, "redirect_uris", "Registered redirect URIs; when non-empty, /authorize enforces exact matching, except a registered loopback URI (http://127.0.0.1:{port}/..., http://[::1]:{port}/...) matches any port per RFC 8252 section 7.3; reverse-domain private-use schemes like com.example.app:/cb are accepted, schemes without a period such as myapp:// are rejected per section 7.1 (optional)"),
                "allowed_scopes": _domain(OAuthClient, "allowed_scopes", "Per-client scope allow-list (#186); when non-empty, /authorize and /token reject a requested scope outside this set with invalid_scope (RFC 6749 4.1.2.1/5.2). Empty = any scope in the global oauth.scopes_supported vocabulary is allowed (optional)"),
                "allowed_resources": _domain(OAuthClient, "allowed_resources", "Per-client RFC 8707 resource allow-list (#187); when non-empty, a resource requested on /authorize or /token must be one of these or the request is invalid_target. Empty = any valid resource (an absolute URI without a fragment) is allowed (optional)"),
            },
            # client_secret is validated in the handler: required for every
            # auth method except 'none' (#188).
            "required": ["client_id"],
        },
    ),
    Tool(
        name="update_client",
        description="Update an existing OAuth client",
        input_schema={
            "type": "object",
            "properties": {
                "client_id": _domain(OAuthClient, "client_id", "Client ID to update"),
                "client_secret": _domain(OAuthClient, "client_secret", "New client secret (optional)", minLength=None),
                "token_endpoint_auth_method": _domain(OAuthClient, "token_endpoint_auth_method", "New token endpoint auth method (optional). Switching "
                        "a secret-less client to a confidential method "
                        "requires supplying client_secret in the same call"),
                "description": _domain(OAuthClient, "description", "New description (optional)"),
                "background_color": _domain(OAuthClient, "background_color", "New hex color (e.g. '#1a1a2e') behind the /authorize login card; empty string clears it (optional)", pattern=None),
                "header_color": _domain(OAuthClient, "header_color", "New hex color (e.g. '#0d6efd') for the /authorize login card header band; empty string clears it (optional)", pattern=None),
                "footer_color": _domain(OAuthClient, "footer_color", "New hex color (e.g. '#ffffff') for the /authorize login card footer band; empty string clears it (optional)", pattern=None),
                "show_client_id": _domain(OAuthClient, "show_client_id", "Show client_id on the /authorize login page (optional)"),
                "show_description": _domain(OAuthClient, "show_description", "Show description on the /authorize login page (optional)"),
                "layout": _domain(OAuthClient, "layout", "/authorize login card composition (#249): 'horizontal' places the client info and the login form side by side, collapsing back to a single column on narrow viewports (optional)"),
                "additional_audiences": _domain(OAuthClient, "additional_audiences", "Replace the client's extra ID Token audiences (optional)"),
                "redirect_uris": _domain(OAuthClient, "redirect_uris", "Replace the client's registered redirect URIs (loopback URIs match any port per RFC 8252 section 7.3, reverse-domain private-use schemes accepted, myapp:// rejected per section 7.1); empty list removes the restriction (optional)"),
                "allowed_scopes": _domain(OAuthClient, "allowed_scopes", "Replace the client's scope allow-list (#186); empty list removes the restriction (optional)"),
                "allowed_resources": _domain(OAuthClient, "allowed_resources", "Replace the client's RFC 8707 resource allow-list (#187); empty list removes the restriction (optional)"),
            },
            "required": ["client_id"],
        },
    ),
    Tool(
        name="delete_client",
        description="Delete an OAuth client",
        input_schema={
            "type": "object",
            "properties": {
                "client_id": _domain(OAuthClient, "client_id", "Client ID to delete"),
            },
            "required": ["client_id"],
        },
    ),
    # Configuration
    Tool(
        name="get_settings",
        description="Get current NanoIDP settings",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="reload_config",
        description="Reload configuration from files",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="validate_config",
        description="Validate the running configuration directory (settings.yaml, "
        "users.yaml, bootstrap.yaml): unknown keys as warnings, wrong types and "
        "refused values as errors. settings.yaml and users.yaml findings are what "
        "a startup or the next reload would hit; bootstrap.yaml findings are what "
        "would stop the NEXT startup (the bootstrap surface loads at startup only). Read-only and inert: it re-reads the files through the same "
        "loaders, runs no hook and loads no plugin. 'valid' is false on any error, "
        "and on a warning too under strict mode, which is when a start would refuse. "
        "'strict' defaults to this server's effective validation mode; pass it "
        "explicitly to override.",
        input_schema={
            "type": "object",
            "properties": {
                "strict": {
                    "type": "boolean",
                    "description": "Treat warnings as failures, like the server's "
                    "--strict-config. A directory declaring config_validation: "
                    "strict is strict regardless.",
                },
            },
            "required": [],
        },
    ),
    Tool(
        name="update_settings",
        description="Update NanoIDP settings (issuer, audience, token expiry, SAML options, etc.). "
        "hooks: and plugins: (#185) are YAML-only, like secret_key and require_ui_login: "
        "they are reported by get_settings but cannot be changed here, since a command "
        "editable through the surface it observes would be a remote-execution primitive.",
        input_schema={
            "type": "object",
            "properties": {
                "issuer": _domain(Settings, "issuer", "OAuth2/OIDC issuer URL"),
                "issuer_from_request": _domain(Settings, "issuer_from_request", "Derive the issuer from each request's own Host "
                    "header instead of the fixed 'issuer' (dev convenience for "
                    "setups reachable under more than one hostname). MCP tools "
                    "have no request of their own, so this only affects HTTP "
                    "discovery/token/device-flow responses, never MCP ones."),
                "issuer_allowlist": _domain(Settings, "issuer_allowlist", "Origins (e.g. 'http://localhost:8000') allowed "
                    "to be reflected back by 'issuer_from_request'. Empty (default) "
                    "allows any Host header. A non-matching Host falls back to the "
                    "fixed 'issuer'."),
                "device_verification_base_url": _domain(Settings, "device_verification_base_url", "Fixed base URL for the device flow's "
                    "verification_uri (e.g. 'https://idp.example.com'), used "
                    "instead of the request-derived issuer so a backend/container "
                    "caller's Host doesn't leak into a URL a human's browser can't "
                    "reach. Only consulted when 'issuer_from_request' is on; empty "
                    "string clears it back to following the request Host."),
                "issuer_from_proxy_headers": _domain(Settings, "issuer_from_proxy_headers", "Trust 'X-Forwarded-Proto'/'X-Forwarded-Host'/"
                    "'X-Forwarded-For' from a single reverse-proxy hop in front of "
                    "NanoIDP (applies werkzeug's ProxyFix). Only affects the "
                    "'issuer_from_request' derivation - and only when that toggle "
                    "is also on; it always affects rate-limit client IP "
                    "attribution regardless. Only enable this when NanoIDP is "
                    "deployed directly behind exactly one trusted proxy - these "
                    "headers are otherwise spoofable by any client. Takes effect "
                    "on the next app restart, not the running process."),
                "audience": _domain(Settings, "audience", "Default token audience"),
                "token_expiry_minutes": _domain(Settings, "token_expiry_minutes", "Token expiration in minutes"),
                "saml_entity_id": _domain(Settings, "saml_entity_id", "SAML IdP entityID. Empty string clears it so "
                    "it is derived again from the effective issuer as "
                    "<issuer>/saml (#181)"),
                "saml_sso_url": _domain(Settings, "saml_sso_url", "SAML SingleSignOnService location. Empty string "
                    "clears it so it is derived again as <issuer>/saml/sso (#181)"),
                "saml_sign_responses": _domain(Settings, "saml_sign_responses", "Enable/disable SAML response signing"),
                "saml_export_roles": _domain(Settings, "saml_export_roles", "Emit the user's roles as a SAML attribute (off by default)"),
                "saml_export_groups": _domain(Settings, "saml_export_groups", "Emit the user's groups as a SAML attribute (off by default)"),
                "saml_roles_attr_name": _domain(Settings, "saml_roles_attr_name", "SAML attribute name for the roles (default: 'roles')"),
                "saml_groups_attr_name": _domain(Settings, "saml_groups_attr_name", "SAML attribute name for the groups (default: 'groups')"),
                "saml_c14n_algorithm": _domain(Settings, "saml_c14n_algorithm", "XML canonicalization algorithm: 'c14n' (1.0), 'c14n11' (1.1), or 'exc_c14n' (Exclusive 1.0)"),
                "saml_want_authn_requests_signed": _domain(Settings, "saml_want_authn_requests_signed", "Require and verify AuthnRequest signatures, both bindings (#69)"),
                "saml_sp_certificates": _domain(Settings, "saml_sp_certificates", "PEM certificate files of SPs whose AuthnRequest signatures are accepted"),
                "strict_saml_binding": _domain(Settings, "strict_saml_binding", "Enforce strict SAML binding compliance (reject GET with uncompressed data)"),
                "verbose_logging": _domain(Settings, "verbose_logging", "Include usernames/client_ids in log messages (dev convenience)"),
                "refresh_token_rotation": _domain(Settings, "refresh_token_rotation", "Rotate refresh tokens: each refresh invalidates the consumed refresh token (#46)"),
                "require_pkce": _domain(Settings, "require_pkce", "Reject /authorize requests without a PKCE code_challenge (#47)"),
                "login_mode": _domain(Settings, "login_mode", "Interactive login mode: 'password' (default) "
                    "requires the configured password on /login, /authorize, "
                    "/saml/sso and the device flow; 'persona' lists the "
                    "configured users and logs in by selecting one, no password "
                    "prompt. Opt-in, off by default - a local development/testing "
                    "convenience, not an authentication mode for deployed "
                    "environments. Orthogonal to 'security_profile' and to the "
                    "OAuth password grant, which is unaffected either way."),
                "auto_login": _domain(Settings, "auto_login", "With login_mode: persona, OIDC /authorize "
                    "accepts login_hint values prefixed "
                    "'persona-auto-login:USERNAME' and logs that user in "
                    "directly, no picker (#250) - for driving a real OIDC "
                    "client library in automated integration tests. Opt-in, "
                    "off by default; inert unless login_mode is also "
                    "'persona'."),
                "two_step": _domain(Settings, "two_step", "Collect username and password on "
                    "separate screens, everywhere login_mode: password "
                    "renders a combined form - /authorize, /login, "
                    "/saml/sso and the device flow (#322/#323). Opt-in, "
                    "off by default; inert under login_mode: persona."),
                "totp": _domain(Settings, "totp", "After a successful password check, "
                    "require a time-based one-time code (RFC 6238, 6 "
                    "digits, 30s period, SHA-1) from any user carrying a "
                    "totp_secret - on /authorize, /login, /saml/sso and "
                    "the device flow (#348). A declarative demo factor: "
                    "the secret is a plain field of the user entry, "
                    "written directly in users.yaml, with no enrolment, "
                    "no replay protection and no admin reset. Opt-in, "
                    "off by default; inert under login_mode: persona."),
            },
            "required": [],
        },
    ),
    Tool(
        name="save_config",
        description=(
            "Save current configuration to YAML files (persists changes made "
            "via create/update tools without persist=True support). Writes "
            "users.yaml and settings.yaml as one coordinated, conflict-checked "
            "save (#229) and then refreshes the running configuration from "
            "what was just written. To refuse the save if another writer "
            "(the web UI, another agent, a second nanoidp process on the "
            "same directory) changed a file since you read it, pass the "
            "expected_users_revision / expected_settings_revision a read "
            "tool handed back (list_users and get_user carry "
            "users_revision; list_clients, get_client and get_settings "
            "carry settings_revision; reload_config and a successful "
            "save_config carry both). save_config always writes both "
            "files, so there are exactly two modes: omitting both "
            "revisions keeps today's unconditional last-write-wins, and "
            "supplying either makes the WHOLE save conflict-checked - "
            "the omitted revision defaults to the one this runtime was "
            "loaded from, so a save guarded on users.yaml cannot "
            "silently overwrite a settings.yaml another writer changed, "
            "or vice versa. A failure response's 'kind' "
            "distinguishes four outcomes: 'conflict' (nothing was written - "
            "a supplied revision was stale; call reload_config, reapply "
            "your change on the fresh state and save with the revisions "
            "from its response), 'lock_timeout' or 'lock_unsupported' "
            "(nothing was written either - the write never started; "
            "lock_timeout is worth retrying, lock_unsupported means this "
            "config directory's filesystem does not support advisory locks "
            "and will not succeed on retry), a hook's own 'kind' under "
            "hooks.strict (both files ARE written; only the mirror push "
            "failed), or 'reload_after_save' (both files ARE written but "
            "the runtime could not adopt them - do not retry expecting a "
            "different result, the file on disk is authoritative)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "expected_users_revision": {
                    "type": "string",
                    "description": (
                        "users.yaml revision from a read tool; the save is "
                        "refused with kind 'conflict' if the file no longer "
                        "matches it. Supplying either revision makes the "
                        "whole two-file save conflict-checked (the omitted "
                        "one defaults to this runtime's loaded revision); "
                        "omit both for unconditional last-write-wins."
                    ),
                },
                "expected_settings_revision": {
                    "type": "string",
                    "description": (
                        "settings.yaml revision from a read tool; same "
                        "contract as expected_users_revision."
                    ),
                },
            },
            "required": [],
        },
    ),
    # Discovery
    Tool(
        name="get_oidc_discovery",
        description="Get OIDC discovery document (/.well-known/openid-configuration)",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="get_jwks",
        description="Get JSON Web Key Set for token verification",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    # Audit log (mirrors /api/audit*, issue #48)
    Tool(
        name="get_audit_log",
        description="Get audit log entries (what the IdP recorded: token requests, logins, SAML flows)",
        input_schema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum entries to return (default: 100)",
                },
                "event_type": {
                    "type": "string",
                    "description": "Filter by event type (e.g. token_request, authorization_request)",
                },
                # A filter, not a username to act on: get_entries treats a
                # blank one as "no filter", a vocabulary User.username does
                # not have, so the minLength does not carry over.
                "username": _domain(User, "username", "Filter by username", minLength=None),
            },
            "required": [],
        },
    ),
    Tool(
        name="get_audit_stats",
        description="Get audit log statistics (event counts by type/status)",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="clear_audit_log",
        description="Clear the audit log",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    # Key management (mirrors /api/keys*, issue #48)
    Tool(
        name="get_keys_info",
        description="Get information about the signing keys (active kid, previous keys)",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="rotate_keys",
        description="Rotate the signing keys: the active key moves to 'previous' (still valid for verification) and a new active key is generated - useful to test clients' JWKS refresh handling",
        input_schema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
]

_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {tool.name: tool.input_schema for tool in _TOOLS}
# Compile each tool's schema once at import instead of recompiling on every
# call. check_schema() comes first because the constructor assumes its schema
# is already valid (per the jsonschema docs); only the explicit check makes a
# malformed tool schema fail here, at import, rather than behave undefined on
# the first tools/call.
for _schema in _TOOL_SCHEMAS.values():
    Draft202012Validator.check_schema(_schema)
_TOOL_VALIDATORS: dict[str, Draft202012Validator] = {
    name: Draft202012Validator(schema) for name, schema in _TOOL_SCHEMAS.items()
}

