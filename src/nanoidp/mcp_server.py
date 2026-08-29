"""
MCP Server for NanoIDP.
Exposes Identity Provider functionality via Model Context Protocol.

Security Note:
    The MCP server should ONLY be used locally on developer machines or in
    isolated development environments. It exposes powerful administrative tools.

    Security modes:
    - When management_secret is configured (settings.yaml, NANOIDP_MANAGEMENT_SECRET,
      or the legacy NANOIDP_MCP_ADMIN_SECRET env var), mutating operations
      require the admin_secret parameter to match. The same setting also
      gates api_bp and ui_bp mutations - see Settings.management_secret.
    - When --readonly flag or NANOIDP_MCP_READONLY=true, mutating tools
      are completely disabled.

isError contract:
    A tool result is flagged ``is_error=True`` only when the call failed. A
    query that answers negatively is NOT a failure. call_tool applies this
    once, via ``failed = result.get("success") is False or "error" in result``.

    | Outcome                                    | key           | is_error |
    |--------------------------------------------|---------------|----------|
    | success                                    | success/data  | False    |
    | negative query (get_user/get_client miss)  | found: False  | False    |
    | negative query (verify_token invalid)      | valid: False  | False    |
    |                                            | (+ ``reason``)|          |
    | mutation failure (not found / exists / IO) | success: False| True     |
    |                                            | (+ ``error``) |          |
    | guard rejection (readonly/secret/unknown/  | error + code  | True     |
    |   bad args), via _reject                   | + tool        |          |
    | uncaught exception                         | error + code  | True     |
    |                                            | + tool        |          |

    Negative queries must therefore avoid the top-level ``error`` key (use
    ``reason`` / ``found``) so the heuristic does not misclassify them.
"""

import argparse
import asyncio
import json
import logging
import os
import re
from typing import Any, Callable, Optional, Tuple

import jwt as pyjwt
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from . import __version__
from .config import ConfigManager, OAuthClient, ReloadAfterSaveError, User, init_config
from .config_validation import validate_config_result
from .config_writer import ConflictError, LockUnavailableError
from .hooks import HookError
from .models import HEX_COLOR_PATTERN, normalize_saml_attr_name
from .routes._auth import verify_secret
from .services import (
    build_discovery_document,
    get_audit_log,
    get_crypto_service,
    get_token_service,
    init_crypto_service,
)

logger = logging.getLogger(__name__)

# The MCP server itself is constructed at the bottom of this module: the SDK
# takes its handlers as constructor arguments, so they must be defined first.

# Global config - initialized on startup
_config: ConfigManager | None = None

# Global readonly mode flag
_readonly_mode: bool = False

# Tools that modify state and require admin secret when configured
MUTATING_TOOLS = {
    "create_user",
    "create_persona_user",
    "update_user",
    "delete_user",
    "create_client",
    "update_client",
    "delete_client",
    "generate_token",
    "update_settings",
    "save_config",
    "clear_audit_log",
    "rotate_keys",
}


def _check_admin_secret(
    config: ConfigManager, tool_name: str, arguments: dict[str, Any]
) -> Tuple[bool, str]:
    """Check if the management secret is required and valid for this tool.

    Source of truth is the caller's own ConfigManager (config.settings.
    management_secret), NOT routes._auth.get_management_secret(). That
    helper reads nanoidp.config.get_config()'s module-global singleton, which
    is a different object from mcp_server._config whenever anything (a test,
    or a future code path) sets mcp_server._config directly instead of via
    init_config() - in production the two happen to be the same object today,
    but this function must not depend on that (#163 review, blocking: was
    silently evaluating the gate against whichever ConfigManager get_config()
    last built, not the one actually serving this MCP request). Callers pass
    _ensure_config()'s return value. Still only gates MUTATING_TOOLS and
    still pops 'admin_secret' off arguments so downstream tool schemas never
    see it.

    Args:
        config: The ConfigManager serving this request (from _ensure_config())
        tool_name: Name of the tool being called
        arguments: Tool arguments (admin_secret will be removed if present)

    Returns:
        Tuple of (allowed: bool, error_message: str)
    """
    secret = config.settings.management_secret
    if not secret:
        return True, ""  # No secret configured = allow all (dev mode)

    if tool_name not in MUTATING_TOOLS:
        return True, ""  # Read-only tools don't need secret

    provided_secret = arguments.pop("admin_secret", None)
    if not provided_secret:
        return (
            False,
            f"A management secret is configured. Provide 'admin_secret' parameter for {tool_name}.",
        )
    if not verify_secret(provided_secret, secret):
        return False, "Invalid admin_secret"

    return True, ""


def _check_readonly_mode(tool_name: str) -> Tuple[bool, str]:
    """Check if tool is blocked due to readonly mode.

    Args:
        tool_name: Name of the tool being called

    Returns:
        Tuple of (allowed: bool, error_message: str)
    """
    if not _readonly_mode:
        return True, ""

    if tool_name in MUTATING_TOOLS:
        return (
            False,
            f"Tool '{tool_name}' is disabled in readonly mode. Start without --readonly to enable mutating operations.",
        )

    return True, ""


def _log_mcp_tool(tool_name: str, success: bool, details: Optional[dict] = None) -> None:
    """Log MCP tool call to audit log."""
    try:
        audit = get_audit_log()
        audit.log(
            event_type="mcp_tool",
            endpoint="mcp",
            method=tool_name,
            status="success" if success else "error",
            details=details or {},
        )
    except Exception as e:
        logger.warning(f"Failed to log MCP tool call: {e}")


def _ensure_config() -> ConfigManager:
    """Ensure config is initialized."""
    global _config
    if _config is None:
        config_dir = os.getenv("NANOIDP_CONFIG_DIR", "./config")
        _config = init_config(config_dir)
        init_crypto_service(_config.settings.keys_dir)
    return _config


def _user_to_dict(user: User) -> dict[str, Any]:
    """Convert User to dictionary."""
    return {
        "username": user.username,
        "description": user.description,
        "email": user.email,
        "roles": user.roles,
        "groups": user.groups,
        "tenant": user.tenant,
        "identity_class": user.identity_class,
        "entitlements": user.entitlements,
        "source_acl": user.source_acl,
        "attributes": user.attributes,
    }


def _build_user_from_arguments(
    username: str, password: Optional[str], arguments: dict[str, Any]
) -> User:
    """Build a ``User`` from ``create_user``/``create_persona_user`` arguments.

    Shared so the two tools can never drift on the non-password fields -
    ``create_persona_user`` is the same shape with ``password`` fixed to
    ``None`` instead of taken from the caller.
    """
    return User(
        username=username,
        password=password,
        description=arguments.get("description", ""),
        email=arguments.get("email", ""),
        roles=arguments.get("roles", ["USER"]),
        groups=arguments.get("groups", []),
        tenant=arguments.get("tenant", "default"),
        identity_class=arguments.get("identity_class"),
        entitlements=arguments.get("entitlements", []),
        source_acl=arguments.get("source_acl", []),
        attributes=arguments.get("attributes", {}),
    )


def _client_to_dict(client: OAuthClient) -> dict[str, Any]:
    """Convert OAuthClient to dictionary (without secret)."""
    return {
        "client_id": client.client_id,
        "description": client.description,
        "background_color": client.background_color,
        "header_color": client.header_color,
        "footer_color": client.footer_color,
        "show_client_id": client.show_client_id,
        "show_description": client.show_description,
        "additional_audiences": client.additional_audiences,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
    }


def _normalize_str_list(value: Any, field: str) -> list[str]:
    """Coerce a raw list argument into a list of non-empty strings.

    Only ``None`` (argument omitted) and an empty list mean "no values"; any
    other non-list (``""``, ``0``, ``False``) is a type error and is rejected,
    rather than silently coerced to ``[]`` (#37).
    """
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(a, str) for a in value):
        raise ValueError(f"{field} must be a list of strings")
    return [a for a in value if a]


def _normalize_audiences(value: Any) -> list[str]:
    """Coerce a raw audiences argument (see ``_normalize_str_list``)."""
    return _normalize_str_list(value, "additional_audiences")


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


_HEX_COLOR_RE = re.compile(HEX_COLOR_PATTERN)


def _normalize_hex_color(value: Any, field: str) -> Optional[str]:
    """Coerce a raw color argument: falsy (omitted/empty) clears it, otherwise
    it must match OAuthClient's own hex pattern - checked here too so a bad
    value is caught before any other field on the client is mutated (#37).
    """
    if not value:
        return None
    if not isinstance(value, str) or not _HEX_COLOR_RE.match(value):
        raise ValueError(f"{field} must be a hex color like '#1a1a2e'")
    return value


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
            },
            "required": ["username"],
        },
    ),
    # Token Operations
    Tool(
        name="generate_token",
        description="Generate an OAuth2 access token for a user",
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
        description="Verify a JWT token's signature and expiration",
        input_schema={
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "JWT token to verify",
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
                    "description": "Client secret for authentication",
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
            },
            "required": ["client_id", "client_secret"],
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


async def list_tools(
    ctx: ServerRequestContext, params: PaginatedRequestParams | None
) -> ListToolsResult:
    """List available MCP tools."""
    return ListToolsResult(tools=_TOOLS)


# =============================================================================
# Tool Implementations
# =============================================================================


def _text_result(payload: dict[str, Any], *, is_error: bool = False) -> CallToolResult:
    """Serialize a tool payload into the JSON text result clients expect."""
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, indent=2))],
        is_error=is_error,
    )


def _reject(name: str, code: str, message: str) -> CallToolResult:
    """Build a rejection result and its matching audit entry.

    Pins the shape shared by call_tool's early-exit branches (readonly mode,
    missing/invalid admin secret, unknown tool, bad arguments), which had
    drifted from each other - e.g. the admin-secret audit entry used to omit
    `tool`.
    """
    _log_mcp_tool(name, success=False, details={"error": code, "tool": name})
    return _text_result({"error": message, "code": code, "tool": name}, is_error=True)


async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
    """Handle tool calls with readonly and admin secret checks, plus audit logging.

    The whole body runs under one try/except: the SDK no longer turns a
    handler exception into an is_error result (mcp 1.x's @server.call_tool()
    did), so an exception raised by _ensure_config() or _execute_tool() would
    otherwise reach the client as a raw JSON-RPC error instead of this
    handler's graceful {"error": ..., "tool": ...} payload.
    """
    name = params.name
    try:
        config = _ensure_config()
        # Copied because _check_admin_secret pops admin_secret off it, and params
        # is a validated protocol model. `arguments` is None when the call
        # carried none.
        arguments = dict(params.arguments or {})

        # Check readonly mode first (completely blocks mutating tools)
        allowed, error_msg = _check_readonly_mode(name)
        if not allowed:
            return _reject(name, "MCP_READONLY_MODE", error_msg)

        # Check admin secret for mutating operations
        allowed, error_msg = _check_admin_secret(config, name, arguments)
        if not allowed:
            return _reject(name, "MCP_ADMIN_SECRET_REQUIRED", error_msg)

        # mcp 1.x's @server.call_tool(validate_input=True) ran this same check
        # before dispatch; the 2.0 on_call_tool path does not, so it is done
        # here to keep required-field/type errors from reaching _execute_tool
        # as bare KeyErrors.
        validator = _TOOL_VALIDATORS.get(name)
        if validator is None:
            return _reject(name, "MCP_UNKNOWN_TOOL", f"Unknown tool: {name}")
        error = best_match(validator.iter_errors(arguments))
        if error is not None:
            field = ".".join(str(p) for p in error.absolute_path)
            message = f"{field}: {error.message}" if field else error.message
            return _reject(name, "MCP_INVALID_ARGUMENTS", f"Input validation error: {message}")

        result = await _execute_tool(name, arguments, config)
        # Domain-level failures ({"success": False, ...} or an "error" key,
        # e.g. "user not found") are results, not exceptions, so they don't
        # go through the except branch below - but they still failed and must
        # be flagged the same way (CHANGELOG: "failed MCP tool calls now set
        # is_error: true"). See the isError contract in the module docstring.
        failed = result.get("success") is False or "error" in result
        details = {"tool": name}
        if failed:
            details["error"] = result.get("error") or "tool reported failure"
        _log_mcp_tool(name, success=not failed, details=details)
        return _text_result(result, is_error=failed)
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        _log_mcp_tool(name, success=False, details={"error": str(e), "tool": name})
        return _text_result(
            {"error": str(e), "code": "MCP_INTERNAL_ERROR", "tool": name},
            is_error=True,
        )


server = Server(
    "nanoidp",
    version=__version__,
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


# User Management
def _tool_list_users(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    users = [_user_to_dict(user) for user in config.users.values()]
    return {
        "count": len(users),
        "default_user": config.default_user,
        # The users.yaml revision this runtime was loaded from (#229 phase
        # 5): pass it to save_config as expected_users_revision to refuse
        # the save if another writer moved the file since.
        "users_revision": config.users_revision,
        "users": users,
    }


def _tool_get_user(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    user = config.get_user(username)
    if user:
        return {"found": True, "user": _user_to_dict(user), "users_revision": config.users_revision}
    # Meaningful on the not-found branch too: get_user -> create_user ->
    # save_config(expected_users_revision=...) is "create this user only
    # if the file still looks like it did when I saw them absent".
    return {"found": False, "username": username, "users_revision": config.users_revision}


def _tool_create_user(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    if username in config.users:
        return {"success": False, "error": f"User '{username}' already exists"}

    user = _build_user_from_arguments(username, arguments["password"], arguments)
    config.users[username] = user
    return {"success": True, "user": _user_to_dict(user)}


def _tool_create_persona_user(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    if username in config.users:
        return {"success": False, "error": f"User '{username}' already exists"}

    user = _build_user_from_arguments(username, None, arguments)
    config.users[username] = user
    return {"success": True, "user": _user_to_dict(user)}


def _tool_delete_user(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    if username not in config.users:
        return {"success": False, "error": f"User '{username}' not found"}
    del config.users[username]
    return {"success": True, "deleted": username}


def _tool_update_user(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    if username not in config.users:
        return {"success": False, "error": f"User '{username}' not found"}

    # Apply every assignment to a scratch copy first, so a later field's
    # validation failure (User.model_config now has validate_assignment=True)
    # can never leave earlier fields already committed on the live user - the
    # same half-update hazard update_client's own comment documents. The live
    # object is only replaced once every requested field has validated
    # (deep copy, not model_copy(update=...), which skips validation entirely).
    candidate = config.users[username].model_copy(deep=True)
    if "password" in arguments:
        candidate.password = arguments["password"]
    if "description" in arguments:
        candidate.description = arguments["description"]
    if "email" in arguments:
        candidate.email = arguments["email"]
    if "roles" in arguments:
        candidate.roles = arguments["roles"]
    if "groups" in arguments:
        candidate.groups = arguments["groups"]
    if "tenant" in arguments:
        candidate.tenant = arguments["tenant"]
    if "identity_class" in arguments:
        candidate.identity_class = arguments["identity_class"]
    if "entitlements" in arguments:
        candidate.entitlements = arguments["entitlements"]
    if "source_acl" in arguments:
        candidate.source_acl = arguments["source_acl"]
    user = config.users[username] = candidate

    return {"success": True, "user": _user_to_dict(user)}


# Token Operations
def _tool_generate_token(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    username = arguments["username"]
    user = config.get_user(username)
    if not user:
        return {"success": False, "error": f"User '{username}' not found"}

    token_service = get_token_service()
    token_response = token_service.create_token(
        user=user,
        exp_minutes=arguments.get("expires_in_minutes", config.settings.token_expiry_minutes),
        extra_claims=arguments.get("extra_claims"),
        scope=arguments.get("scope"),
        # _execute_tool is also reachable directly (see tests), bypassing
        # call_tool's input_schema validation; reject a non-list with a
        # clean error here too instead of minting a token whose malformed
        # claim only misbehaves later at /userinfo (same precedent as
        # additional_audiences, #37).
        id_token_claims=_normalize_str_list(arguments.get("id_token_claims"), "id_token_claims")
        or None,
        userinfo_claims=_normalize_str_list(arguments.get("userinfo_claims"), "userinfo_claims")
        or None,
    )
    result = {
        "success": True,
        "access_token": token_response["access_token"],
        "refresh_token": token_response["refresh_token"],
        "token_type": token_response["token_type"],
        "expires_in": token_response["expires_in"],
    }
    if "id_token" in token_response:
        result["id_token"] = token_response["id_token"]
    return result


def _tool_decode_token(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    token = arguments["token"]
    try:
        payload = pyjwt.decode(token, options={"verify_signature": False})
        return {"success": True, "claims": payload}
    except Exception as e:
        return {"success": False, "error": f"Failed to decode token: {str(e)}"}


def _tool_verify_token(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    token = arguments["token"]
    crypto = get_crypto_service(config.settings.keys_dir)
    try:
        payload = crypto.verify_jwt(token, config.settings.audience)
        return {"valid": True, "claims": payload}
    except Exception as e:
        # A rejected token is verify_token's designed answer, not a tool
        # failure: use "reason" (not "error") so call_tool does not flag
        # the result is_error (see the isError contract in the docstring).
        return {"valid": False, "reason": str(e)}


# Client Management
def _tool_list_clients(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    clients = [_client_to_dict(c) for c in config.settings.clients]
    # Clients live in settings.yaml, so their precondition is the
    # settings revision (#229 phase 5).
    return {
        "count": len(clients),
        "settings_revision": config.settings_revision,
        "clients": clients,
    }


def _tool_get_client(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    client_id = arguments["client_id"]
    client = config.get_client(client_id)
    if client:
        return {
            "found": True,
            "client": _client_to_dict(client),
            "settings_revision": config.settings_revision,
        }
    return {"found": False, "client_id": client_id, "settings_revision": config.settings_revision}


def _tool_create_client(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    client_id = arguments["client_id"]
    # Check if client already exists
    if config.get_client(client_id):
        return {"success": False, "error": f"Client '{client_id}' already exists"}

    new_client = OAuthClient(
        client_id=client_id,
        client_secret=arguments["client_secret"],
        description=arguments.get("description", ""),
        background_color=_normalize_hex_color(
            arguments.get("background_color"), "background_color"
        ),
        header_color=_normalize_hex_color(arguments.get("header_color"), "header_color"),
        footer_color=_normalize_hex_color(arguments.get("footer_color"), "footer_color"),
        show_client_id=arguments.get("show_client_id", True),
        show_description=arguments.get("show_description", False),
        additional_audiences=_normalize_audiences(arguments.get("additional_audiences")),
        redirect_uris=_normalize_str_list(arguments.get("redirect_uris"), "redirect_uris"),
        allowed_scopes=_normalize_str_list(arguments.get("allowed_scopes"), "allowed_scopes"),
    )
    config.settings.clients.append(new_client)
    return {"success": True, "client": _client_to_dict(new_client)}


def _tool_update_client(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    client_id = arguments["client_id"]
    client = config.get_client(client_id)
    if not client:
        return {"success": False, "error": f"Client '{client_id}' not found"}

    # Validate/normalize every input up front so a bad value cannot leave the
    # client half-updated: with validate_assignment=True, assigning each field
    # can raise, and OAuthClient is mutated in place.
    new_audiences = (
        _normalize_audiences(arguments["additional_audiences"])
        if "additional_audiences" in arguments
        else None
    )
    new_redirect_uris = (
        _normalize_str_list(arguments["redirect_uris"], "redirect_uris")
        if "redirect_uris" in arguments
        else None
    )
    new_allowed_scopes = (
        _normalize_str_list(arguments["allowed_scopes"], "allowed_scopes")
        if "allowed_scopes" in arguments
        else None
    )
    new_background_color = (
        _normalize_hex_color(arguments["background_color"], "background_color")
        if "background_color" in arguments
        else None
    )
    new_header_color = (
        _normalize_hex_color(arguments["header_color"], "header_color")
        if "header_color" in arguments
        else None
    )
    new_footer_color = (
        _normalize_hex_color(arguments["footer_color"], "footer_color")
        if "footer_color" in arguments
        else None
    )

    if "client_secret" in arguments:
        client.client_secret = arguments["client_secret"]
    if "description" in arguments:
        client.description = arguments["description"]
    if "background_color" in arguments:
        client.background_color = new_background_color
    if "header_color" in arguments:
        client.header_color = new_header_color
    if "footer_color" in arguments:
        client.footer_color = new_footer_color
    if "show_client_id" in arguments:
        client.show_client_id = arguments["show_client_id"]
    if "show_description" in arguments:
        client.show_description = arguments["show_description"]
    if new_audiences is not None:
        client.additional_audiences = new_audiences
    if new_redirect_uris is not None:
        client.redirect_uris = new_redirect_uris
    if new_allowed_scopes is not None:
        client.allowed_scopes = new_allowed_scopes

    return {"success": True, "client": _client_to_dict(client)}


def _tool_delete_client(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    client_id = arguments["client_id"]
    client = config.get_client(client_id)
    if not client:
        return {"success": False, "error": f"Client '{client_id}' not found"}

    config.settings.clients = [c for c in config.settings.clients if c.client_id != client_id]
    return {"success": True, "deleted": client_id}


# Configuration
def _tool_get_settings(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    settings = config.settings
    return {
        # Same key as GET /api/config (#175): the contract an agent targets.
        "config_version": config.config_version,
        "config_validation": "strict" if config.strict_config else "warn",
        # The settings.yaml revision this runtime was loaded from (#229
        # phase 5), for save_config's expected_settings_revision.
        "settings_revision": config.settings_revision,
        "issuer": settings.issuer,
        "issuer_from_request": settings.issuer_from_request,
        "issuer_allowlist": settings.issuer_allowlist,
        "device_verification_base_url": settings.device_verification_base_url,
        "issuer_from_proxy_headers": settings.issuer_from_proxy_headers,
        "audience": settings.audience,
        "token_expiry_minutes": settings.token_expiry_minutes,
        # YAML-only (oauth.scopes_supported / oauth.scope_enforcement, #186)
        # - reported for visibility, like secret_key and require_ui_login,
        # but not in update_settings' input_schema below.
        "scopes_supported": settings.scopes_supported,
        "scope_enforcement": settings.scope_enforcement_active,
        "security_profile": settings.security_profile,
        # Same as GET /api/config (#172): whether the profile comes from
        # the CLI, and the values the effective profile forces.
        "profile_override": config.profile_override,
        "effective": {
            "require_pkce": settings.require_pkce,
            "password_hashing": settings.password_hashing,
            "rate_limit_enabled": settings.rate_limit_enabled,
            "debug": settings.debug,
        },
        "login_mode": settings.login_mode,
        "refresh_token_rotation": settings.refresh_token_rotation,
        "require_pkce": settings.require_pkce,
        "jwt_algorithm": settings.jwt_algorithm,
        "saml": {
            # MCP has no HTTP request, so derived values (#181) resolve
            # against the fixed settings.issuer, the same exception the
            # MCP discovery tools already make for issuer_from_request.
            "entity_id": settings.resolve_saml_entity_id(settings.issuer),
            "entity_id_derived": settings.saml_entity_id is None,
            "sso_url": settings.resolve_saml_sso_url(settings.issuer),
            "sso_url_derived": settings.saml_sso_url is None,
            "sign_responses": settings.saml_sign_responses,
            "c14n_algorithm": settings.saml_c14n_algorithm,
            "strict_binding": settings.strict_saml_binding,
            "want_authn_requests_signed": (settings.saml_want_authn_requests_signed),
            "sp_certificates": settings.saml_sp_certificates,
            "export_roles": settings.saml_export_roles,
            "export_groups": settings.saml_export_groups,
            "roles_attr_name": settings.saml_roles_attr_name,
            "groups_attr_name": settings.saml_groups_attr_name,
        },
        "logging": {
            "verbose_logging": settings.verbose_logging,
        },
        "authority_prefixes": settings.authority_prefixes,
        "allowed_identity_classes": settings.allowed_identity_classes,
        # Hooks and plugins (#185): same block as GET /api/config.
        "hooks": config.hooks.describe(),
    }


def _tool_reload_config(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    try:
        config.reload()
    except HookError as exc:
        return {"success": False, "error": f"Reload failed: {exc.message}", "kind": exc.kind}
    # Fresh revisions right in the response (#229 phase 5): after a
    # save_config conflict, reload -> reapply the change -> save with
    # these, without another read call in between.
    return {
        "success": True,
        "message": "Configuration reloaded",
        "users_revision": config.users_revision,
        "settings_revision": config.settings_revision,
    }


def _tool_validate_config(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    # The CLI's code path exactly (nanoidp.config_validation): no
    # ConfigManager is built, no hook runs, no plugin is imported, and
    # the running configuration is not touched or reloaded.
    # strict defaults to the manager's effective mode, so "what the next
    # reload would hit" stays true for a ConfigManager started with
    # --strict-config (#204 review); an explicit argument still wins.
    strict_arg = arguments.get("strict")
    effective = config.strict_config if strict_arg is None else bool(strict_arg)
    return validate_config_result(config.config_dir, effective)


def _blank_to_none(name: str, value: Any) -> Any:
    """ "" = clear: back to the derived/unset value (#181), mirroring the UI."""
    return value or None


def _normalize_update_list(name: str, value: Any) -> Any:
    return _normalize_str_list(value, name)


def _normalize_update_attr_name(name: str, value: Any) -> Any:
    return normalize_saml_attr_name(name, value)


# update_settings' writable fields, in the response's updated_fields order.
# Names double as Settings attribute names; tests/test_settings_plumbing_parity.py
# asserts this tuple against the tool's input_schema, so the two cannot drift.
_UPDATE_SETTINGS_FIELDS: tuple[str, ...] = (
    "issuer",
    "issuer_from_request",
    "issuer_allowlist",
    "device_verification_base_url",
    "issuer_from_proxy_headers",
    "audience",
    "token_expiry_minutes",
    "saml_entity_id",
    "saml_sso_url",
    "saml_sign_responses",
    "saml_export_roles",
    "saml_export_groups",
    "saml_roles_attr_name",
    "saml_groups_attr_name",
    "saml_c14n_algorithm",
    "strict_saml_binding",
    "saml_want_authn_requests_signed",
    "saml_sp_certificates",
    "verbose_logging",
    "refresh_token_rotation",
    "require_pkce",
    "login_mode",
)

_UPDATE_SETTINGS_NORMALIZERS: dict[str, Callable[[str, Any], Any]] = {
    "issuer_allowlist": _normalize_update_list,
    "saml_sp_certificates": _normalize_update_list,
    "saml_roles_attr_name": _normalize_update_attr_name,
    "saml_groups_attr_name": _normalize_update_attr_name,
    "device_verification_base_url": _blank_to_none,
    "saml_entity_id": _blank_to_none,
    "saml_sso_url": _blank_to_none,
}


def _tool_update_settings(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    settings = config.settings

    # Settings (unlike OAuthClient) has no validate_assignment, but the
    # tool's input_schema declares "enum": ["password", "persona"] for
    # login_mode, so call_tool()'s jsonschema pass already rejects an
    # invalid value before this handler ever runs.
    updated = []
    for field in _UPDATE_SETTINGS_FIELDS:
        if field not in arguments:
            continue
        value = arguments[field]
        normalize = _UPDATE_SETTINGS_NORMALIZERS.get(field)
        if normalize is not None:
            value = normalize(field, value)
        setattr(settings, field, value)
        updated.append(field)

    return {
        "success": True,
        "updated_fields": updated,
        "current_settings": {
            "issuer": settings.issuer,
            "issuer_from_request": settings.issuer_from_request,
            "issuer_allowlist": settings.issuer_allowlist,
            "device_verification_base_url": settings.device_verification_base_url,
            "issuer_from_proxy_headers": settings.issuer_from_proxy_headers,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "refresh_token_rotation": settings.refresh_token_rotation,
            "require_pkce": settings.require_pkce,
            "login_mode": settings.login_mode,
            "saml_sign_responses": settings.saml_sign_responses,
            "saml_c14n_algorithm": settings.saml_c14n_algorithm,
            "strict_saml_binding": settings.strict_saml_binding,
            "saml_want_authn_requests_signed": (settings.saml_want_authn_requests_signed),
            "saml_sp_certificates": settings.saml_sp_certificates,
            "saml_export_roles": settings.saml_export_roles,
            "saml_export_groups": settings.saml_export_groups,
            "saml_roles_attr_name": settings.saml_roles_attr_name,
            "saml_groups_attr_name": settings.saml_groups_attr_name,
            "verbose_logging": settings.verbose_logging,
        },
    }


def _tool_save_config(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    try:
        # Optional preconditions (#229 phase 5): the revisions a read tool
        # (list_users/get_user, list_clients/get_client/get_settings) or
        # reload_config handed back. save() always writes BOTH files, so
        # there are exactly two modes and no third (#252 review): with no
        # revision supplied the save is unconditional last-write-wins,
        # same as save()'s own default and the UI's revision-less forms;
        # with EITHER revision supplied the whole save is conflict-checked,
        # the omitted one defaulting to the revision this runtime was
        # loaded from. Passing a caller's partial precondition straight
        # through would guard one file while this runtime's stale snapshot
        # silently overwrote the other - the exact lost update the
        # revisions exist to catch. "is None", not falsy: an explicit
        # empty string is a supplied (and stale) revision, refused as a
        # conflict rather than silently replaced.
        users_rev = arguments.get("expected_users_revision")
        settings_rev = arguments.get("expected_settings_revision")
        if users_rev is not None or settings_rev is not None:
            if users_rev is None:
                users_rev = config.users_revision
            if settings_rev is None:
                settings_rev = config.settings_revision
        config.save(
            expected_users_revision=users_rev,
            expected_settings_revision=settings_rev,
        )
        # The post-save reload refreshed the tracked revisions to what was
        # just written, so a follow-up save can chain from this response.
        return {
            "success": True,
            "message": "Configuration saved to YAML files",
            "users_revision": config.users_revision,
            "settings_revision": config.settings_revision,
        }
    except ConflictError as exc:
        # Nothing was written - a supplied expected_*_revision was stale.
        return {"success": False, "error": exc.message, "kind": exc.kind}
    except LockUnavailableError as exc:
        # Nothing was written either - the lock is acquired before
        # compare_and_replace_many touches any file (#229 review,
        # blocking 4). "lock_timeout" is worth retrying; the file's
        # filesystem does not support advisory locks at all under
        # "lock_unsupported", which a retry cannot fix.
        return {"success": False, "error": exc.message, "kind": exc.kind}
    except HookError as exc:
        # Both files were written; only the on_config_saved mirror push
        # failed under hooks.strict (#229).
        return {"success": False, "error": f"Save succeeded, mirror failed: {exc.message}", "kind": exc.kind}
    except ReloadAfterSaveError as exc:
        # Both files were written, but the runtime could not reload what
        # was just saved - the file on disk is authoritative; a caller
        # should not retry save() expecting a different outcome (#229
        # review, blocking 3).
        return {"success": False, "error": exc.message, "kind": exc.kind}
    except Exception as e:
        return {"success": False, "error": f"Failed to save config: {str(e)}"}


# Discovery
def _tool_get_oidc_discovery(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    # Shared with the HTTP /.well-known/openid-configuration endpoint so
    # the two documents can never drift apart (issue #40).
    return build_discovery_document(config.settings)


def _tool_get_jwks(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    crypto = get_crypto_service(config.settings.keys_dir)
    return crypto.get_jwks()


# Audit log (mirrors /api/audit*, issue #48)
def _tool_get_audit_log(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    audit = get_audit_log()
    entries = audit.get_entries(
        limit=arguments.get("limit", 100),
        event_type=arguments.get("event_type"),
        username=arguments.get("username"),
    )
    return {"entries": entries, "count": len(entries)}


def _tool_get_audit_stats(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    return get_audit_log().get_stats()


def _tool_clear_audit_log(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    get_audit_log().clear()
    return {"success": True, "message": "Audit log cleared"}


# Key management (mirrors /api/keys*, issue #48)
def _tool_get_keys_info(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    crypto = get_crypto_service(config.settings.keys_dir)
    return {
        "active_kid": crypto.kid,
        "previous_keys_count": len(crypto.previous_keys),
        "previous_kids": [k.kid for k in crypto.previous_keys],
        "max_previous_keys": crypto.max_previous_keys,
    }


def _tool_rotate_keys(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    crypto = get_crypto_service(config.settings.keys_dir)
    result = crypto.rotate_keys()
    get_audit_log().log(
        event_type="key_rotation",
        endpoint="mcp:rotate_keys",
        method="MCP",
        username="mcp",
        status="success",
        details={"old_kid": result["old_kid"], "new_kid": result["new_kid"]},
    )
    return {"success": True, **result}


# One handler per tool, dispatched by _execute_tool. tests/test_mcp.py
# asserts this table and _TOOLS declare exactly the same names.
_TOOL_HANDLERS: dict[str, Callable[[dict[str, Any], ConfigManager], dict[str, Any]]] = {
    "list_users": _tool_list_users,
    "get_user": _tool_get_user,
    "create_user": _tool_create_user,
    "create_persona_user": _tool_create_persona_user,
    "delete_user": _tool_delete_user,
    "update_user": _tool_update_user,
    "generate_token": _tool_generate_token,
    "decode_token": _tool_decode_token,
    "verify_token": _tool_verify_token,
    "list_clients": _tool_list_clients,
    "get_client": _tool_get_client,
    "create_client": _tool_create_client,
    "update_client": _tool_update_client,
    "delete_client": _tool_delete_client,
    "get_settings": _tool_get_settings,
    "reload_config": _tool_reload_config,
    "validate_config": _tool_validate_config,
    "update_settings": _tool_update_settings,
    "save_config": _tool_save_config,
    "get_oidc_discovery": _tool_get_oidc_discovery,
    "get_jwks": _tool_get_jwks,
    "get_audit_log": _tool_get_audit_log,
    "get_audit_stats": _tool_get_audit_stats,
    "clear_audit_log": _tool_clear_audit_log,
    "get_keys_info": _tool_get_keys_info,
    "rotate_keys": _tool_rotate_keys,
}


async def _execute_tool(
    name: str, arguments: dict[str, Any], config: ConfigManager
) -> dict[str, Any]:
    """Execute a tool by dispatching to its handler in _TOOL_HANDLERS."""
    handler = _TOOL_HANDLERS.get(name)
    if handler is None:
        # Unreachable on the protocol path: call_tool rejects an unknown name
        # with MCP_UNKNOWN_TOOL before dispatching here. Raising (rather than
        # returning a divergent {"error": ...} shape) makes a direct mis-call
        # a clear bug.
        raise ValueError(f"Unknown tool: {name}")
    return handler(arguments, config)


# =============================================================================
# Main Entry Point
# =============================================================================


def main() -> None:  # pragma: no cover
    """Run the MCP server.

    Excluded from unit coverage on purpose (#222): this is process
    wiring (argparse + stdio bootstrap). The publish pipeline's
    wheel-smoke job executes the nanoidp-mcp entry point from the built
    wheel (--help, which runs this function's argparse) before anything
    is published; the stdio serve loop itself is exercised by every real
    MCP session.
    """
    global _readonly_mode

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="NanoIDP MCP Server - Identity Provider tools for Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security modes:
  --readonly                Disable mutating tools (create, update, delete, generate)
  NANOIDP_MCP_READONLY      Same as --readonly (env var)
  NANOIDP_MANAGEMENT_SECRET Require admin_secret parameter for mutating tools
                            (also gates api_bp/ui_bp mutations - see docs/SECURITY.md)
  NANOIDP_MCP_ADMIN_SECRET  Legacy alias for NANOIDP_MANAGEMENT_SECRET, still honored

Examples:
  nanoidp-mcp                    # Full access
  nanoidp-mcp --readonly         # Read-only access
  NANOIDP_MCP_READONLY=true nanoidp-mcp  # Read-only via env var
        """,
    )
    parser.add_argument(
        "--readonly",
        action="store_true",
        help="Disable mutating tools (create_user, delete_user, generate_token, etc.)",
    )
    args = parser.parse_args()

    # Set readonly mode from CLI flag or environment variable
    _readonly_mode = args.readonly or os.getenv("NANOIDP_MCP_READONLY", "").lower() in (
        "true",
        "1",
        "yes",
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if _readonly_mode:
        logger.info("Starting NanoIDP MCP Server in READONLY mode - mutating tools disabled")
    else:
        logger.info("Starting NanoIDP MCP Server...")

    # Initialize config
    _ensure_config()

    # Run the server. stdio_server() is an async context manager yielding the
    # (read, write) streams the Server pumps messages through - the previous
    # `asyncio.run(stdio_server(server))` crashed at startup (found by mypy,
    # #55: "a coroutine was expected").
    async def _serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(_serve())


if __name__ == "__main__":  # pragma: no cover
    main()
