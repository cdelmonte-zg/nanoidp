"""Tool declarations: JSON Schemas, compiled validators (#286).

Split out of the monolithic mcp_server module; every schema is
byte-identical in semantics to the pre-split declarations (the #283/#284
parity tests and MCP clients depend on them).
"""

from typing import Any

from jsonschema import Draft202012Validator
from mcp.types import Tool

# Shared by create_user's and create_persona_user's input_schema (#10): every
# field but username/password is identical between the two tools, and
# _build_user_from_arguments() reads all of these from either one - a
# property missing here would be silently ignored on that tool alone.
_USER_COMMON_PROPERTIES: dict[str, Any] = {
    "description": {
        "type": "string",
        "maxLength": 200,
        "description": "Display-only note shown in the persona login picker (optional, max 200 chars)",
    },
    "email": {
        "type": "string",
        "description": "Email address (optional)",
    },
    "roles": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of roles (optional, default: ['USER'])",
    },
    "groups": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of groups (optional)",
    },
    "tenant": {
        "type": "string",
        "description": "Tenant identifier (optional, default: 'default')",
    },
    "identity_class": {
        "type": "string",
        "description": "Identity class (e.g., INTERNAL, EXTERNAL)",
    },
    "entitlements": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of entitlements",
    },
    "source_acl": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Source ACL entries for document-level security",
    },
    "attributes": {
        "type": "object",
        "description": "Custom key-value attributes (optional)",
    },
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
                "username": {
                    "type": "string",
                    "description": "Username to look up",
                },
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
                "username": {
                    "type": "string",
                    "description": "Username for the new user",
                },
                "password": {
                    "type": "string",
                    "description": "Password for the new user",
                },
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
                "username": {
                    "type": "string",
                    "description": "Username for the new persona-mode-only user",
                },
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
                "username": {
                    "type": "string",
                    "description": "Username to delete",
                },
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
                "username": {
                    "type": "string",
                    "description": "Username to update",
                },
                "password": {
                    "type": "string",
                    "description": "New password (optional)",
                },
                "description": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "New display-only persona picker note (optional, max 200 chars)",
                },
                "email": {
                    "type": "string",
                    "description": "New email (optional)",
                },
                "roles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "New roles list (optional)",
                },
                "groups": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "New groups list (optional)",
                },
                "tenant": {
                    "type": "string",
                    "description": "New tenant (optional)",
                },
                "identity_class": {
                    "type": "string",
                    "description": "New identity class (optional)",
                },
                "entitlements": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "New entitlements list (optional)",
                },
                "source_acl": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "New source ACL entries (optional)",
                },
                "attributes": {
                    "type": "object",
                    "description": (
                        "New custom key-value attributes (optional; replaces the "
                        "whole mapping, like every other field here - #280)"
                    ),
                },
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
                "username": {
                    "type": "string",
                    "description": "Username to generate token for",
                },
                "expires_in_minutes": {
                    "type": "integer",
                    "description": "Token expiration in minutes (optional, default: 60)",
                },
                "client_id": {
                    "type": "string",
                    "description": (
                        "Bind the token to this client (optional; must name a "
                        "real client). Stamps the client_id claim and issues a "
                        "refresh token spendable by that client. Omit for an "
                        "unbound token: NO refresh token is issued (an unbound "
                        "one could not be spent since 3.0, #73), just an access "
                        "token, fine for a one-shot test"
                    ),
                },
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
                "audience": {
                    "type": "string",
                    "description": (
                        "Expected audience (#187). Omit to verify signature "
                        "and expiry only and return the claims (so a "
                        "resource-bound access token is not falsely reported "
                        "invalid). Provide a value to also require the token's "
                        "'aud' to match it - how you simulate a resource "
                        "server accepting a token for itself and rejecting one "
                        "minted for another (optional)"
                    ),
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
                "client_id": {
                    "type": "string",
                    "description": "Client ID to look up",
                },
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
                "client_id": {
                    "type": "string",
                    "description": "Unique client identifier",
                },
                "client_secret": {
                    "type": "string",
                    "description": (
                        "Client secret for authentication. Required unless "
                        "token_endpoint_auth_method is 'none'"
                    ),
                },
                "token_endpoint_auth_method": {
                    "type": "string",
                    "enum": ["client_secret_basic", "client_secret_post", "none"],
                    "description": (
                        "How the client authenticates as a confidential client "
                        "(optional, default client_secret_basic). The method is "
                        "enforced at every client-authenticated endpoint - "
                        "/token, /introspect, /revoke, /device_authorization "
                        "(#188/#262): basic uses HTTP Basic, post uses the "
                        "request body, and the wrong channel is rejected. "
                        "'none' = public client (#188): no secret, PKCE S256 "
                        "mandatory on /authorize, client_credentials refused, "
                        "refresh rotation forced"
                    ),
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description (optional)",
                },
                "background_color": {
                    "type": "string",
                    "description": "Hex color (e.g. '#1a1a2e') behind the /authorize login card (optional)",
                },
                "header_color": {
                    "type": "string",
                    "description": "Hex color (e.g. '#0d6efd') for the /authorize login card header band (optional)",
                },
                "footer_color": {
                    "type": "string",
                    "description": "Hex color (e.g. '#ffffff') for the /authorize login card footer band (optional)",
                },
                "show_client_id": {
                    "type": "boolean",
                    "description": "Show client_id on the /authorize login page (optional, default true)",
                },
                "show_description": {
                    "type": "boolean",
                    "description": "Show description on the /authorize login page (optional, default false)",
                },
                "layout": {
                    "type": "string",
                    "enum": ["vertical", "horizontal"],
                    "description": "/authorize login card composition (#249): 'vertical' (default) is the single-column card; 'horizontal' places the client info and the login form side by side, collapsing back to a single column on narrow viewports (optional, default vertical)",
                },
                "additional_audiences": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Extra audiences added to the ID Token 'aud' alongside the client_id (optional)",
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Registered redirect URIs; when non-empty, /authorize enforces exact matching, except a registered loopback URI (http://127.0.0.1:{port}/..., http://[::1]:{port}/...) matches any port per RFC 8252 section 7.3; reverse-domain private-use schemes like com.example.app:/cb are accepted, schemes without a period such as myapp:// are rejected per section 7.1 (optional)",
                },
                "allowed_scopes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Per-client scope allow-list (#186); when non-empty, /authorize and /token reject a requested scope outside this set with invalid_scope (RFC 6749 4.1.2.1/5.2). Empty = any scope in the global oauth.scopes_supported vocabulary is allowed (optional)",
                },
                "allowed_resources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Per-client RFC 8707 resource allow-list (#187); when non-empty, a resource requested on /authorize or /token must be one of these or the request is invalid_target. Empty = any valid resource (an absolute URI without a fragment) is allowed (optional)",
                },
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
                "client_id": {
                    "type": "string",
                    "description": "Client ID to update",
                },
                "client_secret": {
                    "type": "string",
                    "description": "New client secret (optional)",
                },
                "token_endpoint_auth_method": {
                    "type": "string",
                    "enum": ["client_secret_basic", "client_secret_post", "none"],
                    "description": (
                        "New token endpoint auth method (optional). Switching "
                        "a secret-less client to a confidential method "
                        "requires supplying client_secret in the same call"
                    ),
                },
                "description": {
                    "type": "string",
                    "description": "New description (optional)",
                },
                "background_color": {
                    "type": "string",
                    "description": "New hex color (e.g. '#1a1a2e') behind the /authorize login card; empty string clears it (optional)",
                },
                "header_color": {
                    "type": "string",
                    "description": "New hex color (e.g. '#0d6efd') for the /authorize login card header band; empty string clears it (optional)",
                },
                "footer_color": {
                    "type": "string",
                    "description": "New hex color (e.g. '#ffffff') for the /authorize login card footer band; empty string clears it (optional)",
                },
                "show_client_id": {
                    "type": "boolean",
                    "description": "Show client_id on the /authorize login page (optional)",
                },
                "show_description": {
                    "type": "boolean",
                    "description": "Show description on the /authorize login page (optional)",
                },
                "layout": {
                    "type": "string",
                    "enum": ["vertical", "horizontal"],
                    "description": "/authorize login card composition (#249): 'horizontal' places the client info and the login form side by side, collapsing back to a single column on narrow viewports (optional)",
                },
                "additional_audiences": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replace the client's extra ID Token audiences (optional)",
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replace the client's registered redirect URIs (loopback URIs match any port per RFC 8252 section 7.3, reverse-domain private-use schemes accepted, myapp:// rejected per section 7.1); empty list removes the restriction (optional)",
                },
                "allowed_scopes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replace the client's scope allow-list (#186); empty list removes the restriction (optional)",
                },
                "allowed_resources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replace the client's RFC 8707 resource allow-list (#187); empty list removes the restriction (optional)",
                },
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
                "client_id": {
                    "type": "string",
                    "description": "Client ID to delete",
                },
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
                "issuer": {
                    "type": "string",
                    "description": "OAuth2/OIDC issuer URL",
                },
                "issuer_from_request": {
                    "type": "boolean",
                    "description": "Derive the issuer from each request's own Host "
                    "header instead of the fixed 'issuer' (dev convenience for "
                    "setups reachable under more than one hostname). MCP tools "
                    "have no request of their own, so this only affects HTTP "
                    "discovery/token/device-flow responses, never MCP ones.",
                },
                "issuer_allowlist": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Origins (e.g. 'http://localhost:8000') allowed "
                    "to be reflected back by 'issuer_from_request'. Empty (default) "
                    "allows any Host header. A non-matching Host falls back to the "
                    "fixed 'issuer'.",
                },
                "device_verification_base_url": {
                    "type": "string",
                    "description": "Fixed base URL for the device flow's "
                    "verification_uri (e.g. 'https://idp.example.com'), used "
                    "instead of the request-derived issuer so a backend/container "
                    "caller's Host doesn't leak into a URL a human's browser can't "
                    "reach. Only consulted when 'issuer_from_request' is on; empty "
                    "string clears it back to following the request Host.",
                },
                "issuer_from_proxy_headers": {
                    "type": "boolean",
                    "description": "Trust 'X-Forwarded-Proto'/'X-Forwarded-Host'/"
                    "'X-Forwarded-For' from a single reverse-proxy hop in front of "
                    "NanoIDP (applies werkzeug's ProxyFix). Only affects the "
                    "'issuer_from_request' derivation - and only when that toggle "
                    "is also on; it always affects rate-limit client IP "
                    "attribution regardless. Only enable this when NanoIDP is "
                    "deployed directly behind exactly one trusted proxy - these "
                    "headers are otherwise spoofable by any client. Takes effect "
                    "on the next app restart, not the running process.",
                },
                "audience": {
                    "type": "string",
                    "description": "Default token audience",
                },
                "token_expiry_minutes": {
                    "type": "integer",
                    "description": "Token expiration in minutes",
                },
                "saml_entity_id": {
                    "type": "string",
                    "description": "SAML IdP entityID. Empty string clears it so "
                    "it is derived again from the effective issuer as "
                    "<issuer>/saml (#181)",
                },
                "saml_sso_url": {
                    "type": "string",
                    "description": "SAML SingleSignOnService location. Empty string "
                    "clears it so it is derived again as <issuer>/saml/sso (#181)",
                },
                "saml_sign_responses": {
                    "type": "boolean",
                    "description": "Enable/disable SAML response signing",
                },
                "saml_export_roles": {
                    "type": "boolean",
                    "description": "Emit the user's roles as a SAML attribute (off by default)",
                },
                "saml_export_groups": {
                    "type": "boolean",
                    "description": "Emit the user's groups as a SAML attribute (off by default)",
                },
                "saml_roles_attr_name": {
                    "type": "string",
                    "description": "SAML attribute name for the roles (default: 'roles')",
                },
                "saml_groups_attr_name": {
                    "type": "string",
                    "description": "SAML attribute name for the groups (default: 'groups')",
                },
                "saml_c14n_algorithm": {
                    "type": "string",
                    "enum": ["c14n", "c14n11", "exc_c14n"],
                    "description": "XML canonicalization algorithm: 'c14n' (1.0), 'c14n11' (1.1), or 'exc_c14n' (Exclusive 1.0)",
                },
                "saml_want_authn_requests_signed": {
                    "type": "boolean",
                    "description": "Require and verify AuthnRequest signatures, both bindings (#69)",
                },
                "saml_sp_certificates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "PEM certificate files of SPs whose AuthnRequest signatures are accepted",
                },
                "strict_saml_binding": {
                    "type": "boolean",
                    "description": "Enforce strict SAML binding compliance (reject GET with uncompressed data)",
                },
                "verbose_logging": {
                    "type": "boolean",
                    "description": "Include usernames/client_ids in log messages (dev convenience)",
                },
                "refresh_token_rotation": {
                    "type": "boolean",
                    "description": "Rotate refresh tokens: each refresh invalidates the consumed refresh token (#46)",
                },
                "require_pkce": {
                    "type": "boolean",
                    "description": "Reject /authorize requests without a PKCE code_challenge (#47)",
                },
                "login_mode": {
                    "type": "string",
                    "enum": ["password", "persona"],
                    "description": "Interactive login mode: 'password' (default) "
                    "requires the configured password on /login, /authorize, "
                    "/saml/sso and the device flow; 'persona' lists the "
                    "configured users and logs in by selecting one, no password "
                    "prompt. Opt-in, off by default - a local development/testing "
                    "convenience, not an authentication mode for deployed "
                    "environments. Orthogonal to 'security_profile' and to the "
                    "OAuth password grant, which is unaffected either way.",
                },
                "auto_login": {
                    "type": "boolean",
                    "description": "With login_mode: persona, OIDC /authorize "
                    "accepts login_hint values prefixed "
                    "'persona-auto-login:USERNAME' and logs that user in "
                    "directly, no picker (#250) - for driving a real OIDC "
                    "client library in automated integration tests. Opt-in, "
                    "off by default; inert unless login_mode is also "
                    "'persona'.",
                },
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
                "username": {
                    "type": "string",
                    "description": "Filter by username",
                },
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

