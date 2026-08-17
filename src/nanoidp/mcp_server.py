"""
MCP Server for NanoIDP.
Exposes Identity Provider functionality via Model Context Protocol.

Security Note:
    The MCP server should ONLY be used locally on developer machines or in
    isolated development environments. It exposes powerful administrative tools.

    Security modes:
    - When NANOIDP_MCP_ADMIN_SECRET is set, mutating operations require
      the admin_secret parameter to match.
    - When --readonly flag or NANOIDP_MCP_READONLY=true, mutating tools
      are completely disabled.
"""

import argparse
import asyncio
import json
import logging
import os
from typing import Any, Optional, Tuple

import jsonschema
import jwt as pyjwt
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
from .config import ConfigManager, OAuthClient, User, init_config
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


def _check_admin_secret(tool_name: str, arguments: dict[str, Any]) -> Tuple[bool, str]:
    """Check if admin secret is required and valid.

    Args:
        tool_name: Name of the tool being called
        arguments: Tool arguments (admin_secret will be removed if present)

    Returns:
        Tuple of (allowed: bool, error_message: str)
    """
    required_secret = os.getenv("NANOIDP_MCP_ADMIN_SECRET")

    if not required_secret:
        return True, ""  # No secret configured = allow all (dev mode)

    if tool_name not in MUTATING_TOOLS:
        return True, ""  # Read-only tools don't need secret

    provided_secret = arguments.pop("admin_secret", None)
    if not provided_secret:
        return False, f"NANOIDP_MCP_ADMIN_SECRET is set. Provide 'admin_secret' parameter for {tool_name}."
    if provided_secret != required_secret:
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
        return False, f"Tool '{tool_name}' is disabled in readonly mode. Start without --readonly to enable mutating operations."

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
        "email": user.email,
        "roles": user.roles,
        "groups": user.groups,
        "tenant": user.tenant,
        "identity_class": user.identity_class,
        "entitlements": user.entitlements,
        "source_acl": user.source_acl,
        "attributes": user.attributes,
    }


def _client_to_dict(client: OAuthClient) -> dict[str, Any]:
    """Convert OAuthClient to dictionary (without secret)."""
    return {
        "client_id": client.client_id,
        "description": client.description,
        "additional_audiences": client.additional_audiences,
        "redirect_uris": client.redirect_uris,
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
            },
            "required": ["username", "password"],
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
                "additional_audiences": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Extra audiences added to the ID Token 'aud' alongside the client_id (optional)",
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Registered redirect URIs; when non-empty, /authorize enforces exact matching (optional)",
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
                "additional_audiences": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replace the client's extra ID Token audiences (optional)",
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replace the client's registered redirect URIs; empty list removes the restriction (optional)",
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
        name="update_settings",
        description="Update NanoIDP settings (issuer, audience, token expiry, SAML options, etc.)",
        input_schema={
            "type": "object",
            "properties": {
                "issuer": {
                    "type": "string",
                    "description": "OAuth2/OIDC issuer URL",
                },
                "audience": {
                    "type": "string",
                    "description": "Default token audience",
                },
                "token_expiry_minutes": {
                    "type": "integer",
                    "description": "Token expiration in minutes",
                },
                "saml_sign_responses": {
                    "type": "boolean",
                    "description": "Enable/disable SAML response signing",
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
            },
            "required": [],
        },
    ),
    Tool(
        name="save_config",
        description="Save current configuration to YAML files (persists changes)",
        input_schema={
            "type": "object",
            "properties": {},
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


async def call_tool(
    ctx: ServerRequestContext, params: CallToolRequestParams
) -> CallToolResult:
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
        allowed, error_msg = _check_admin_secret(name, arguments)
        if not allowed:
            return _reject(name, "MCP_ADMIN_SECRET_REQUIRED", error_msg)

        # mcp 1.x's @server.call_tool(validate_input=True) ran this same check
        # before dispatch; the 2.0 on_call_tool path does not, so it is done
        # here to keep required-field/type errors from reaching _execute_tool
        # as bare KeyErrors.
        schema = _TOOL_SCHEMAS.get(name)
        if schema is None:
            return _reject(name, "MCP_UNKNOWN_TOOL", f"Unknown tool: {name}")
        try:
            jsonschema.validate(instance=arguments, schema=schema)
        except jsonschema.ValidationError as e:
            field = ".".join(str(p) for p in e.absolute_path)
            message = f"{field}: {e.message}" if field else e.message
            return _reject(name, "MCP_INVALID_ARGUMENTS", f"Input validation error: {message}")

        result = await _execute_tool(name, arguments, config)
        # Domain-level failures ({"success": False, ...} or an "error" key,
        # e.g. "user not found") are results, not exceptions, so they don't
        # go through the except branch below - but they still failed and must
        # be flagged the same way (CHANGELOG: "failed MCP tool calls now set
        # is_error: true").
        failed = result.get("success") is False or "error" in result
        _log_mcp_tool(name, success=not failed, details={"tool": name})
        return _text_result(result, is_error=failed)
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        _log_mcp_tool(name, success=False, details={"error": str(e)})
        return _text_result({"error": str(e), "tool": name}, is_error=True)


server = Server(
    "nanoidp",
    version=__version__,
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


async def _execute_tool(name: str, arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    """Execute a tool and return the result."""

    # User Management
    if name == "list_users":
        users = [_user_to_dict(user) for user in config.users.values()]
        return {
            "count": len(users),
            "default_user": config.default_user,
            "users": users,
        }

    elif name == "get_user":
        username = arguments["username"]
        user = config.get_user(username)
        if user:
            return {"found": True, "user": _user_to_dict(user)}
        return {"found": False, "username": username}

    elif name == "create_user":
        username = arguments["username"]
        if username in config.users:
            return {"success": False, "error": f"User '{username}' already exists"}

        user = User(
            username=username,
            password=arguments["password"],
            email=arguments.get("email", ""),
            roles=arguments.get("roles", ["USER"]),
            groups=arguments.get("groups", []),
            tenant=arguments.get("tenant", "default"),
            identity_class=arguments.get("identity_class"),
            entitlements=arguments.get("entitlements", []),
            source_acl=arguments.get("source_acl", []),
            attributes=arguments.get("attributes", {}),
        )
        config.users[username] = user
        return {"success": True, "user": _user_to_dict(user)}

    elif name == "delete_user":
        username = arguments["username"]
        if username not in config.users:
            return {"success": False, "error": f"User '{username}' not found"}
        del config.users[username]
        return {"success": True, "deleted": username}

    elif name == "update_user":
        username = arguments["username"]
        if username not in config.users:
            return {"success": False, "error": f"User '{username}' not found"}

        user = config.users[username]
        if "password" in arguments:
            user.password = arguments["password"]
        if "email" in arguments:
            user.email = arguments["email"]
        if "roles" in arguments:
            user.roles = arguments["roles"]
        if "groups" in arguments:
            user.groups = arguments["groups"]
        if "tenant" in arguments:
            user.tenant = arguments["tenant"]
        if "identity_class" in arguments:
            user.identity_class = arguments["identity_class"]
        if "entitlements" in arguments:
            user.entitlements = arguments["entitlements"]
        if "source_acl" in arguments:
            user.source_acl = arguments["source_acl"]

        return {"success": True, "user": _user_to_dict(user)}

    # Token Operations
    elif name == "generate_token":
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
            id_token_claims=_normalize_str_list(
                arguments.get("id_token_claims"), "id_token_claims"
            ) or None,
            userinfo_claims=_normalize_str_list(
                arguments.get("userinfo_claims"), "userinfo_claims"
            ) or None,
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

    elif name == "decode_token":
        token = arguments["token"]
        try:
            payload = pyjwt.decode(token, options={"verify_signature": False})
            return {"success": True, "claims": payload}
        except Exception as e:
            return {"success": False, "error": f"Failed to decode token: {str(e)}"}

    elif name == "verify_token":
        token = arguments["token"]
        crypto = get_crypto_service(config.settings.keys_dir)
        try:
            payload = crypto.verify_jwt(token, config.settings.audience)
            return {"valid": True, "claims": payload}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    # Client Management
    elif name == "list_clients":
        clients = [_client_to_dict(c) for c in config.settings.clients]
        return {"count": len(clients), "clients": clients}

    elif name == "get_client":
        client_id = arguments["client_id"]
        client = config.get_client(client_id)
        if client:
            return {"found": True, "client": _client_to_dict(client)}
        return {"found": False, "client_id": client_id}

    elif name == "create_client":
        client_id = arguments["client_id"]
        # Check if client already exists
        if config.get_client(client_id):
            return {"success": False, "error": f"Client '{client_id}' already exists"}

        new_client = OAuthClient(
            client_id=client_id,
            client_secret=arguments["client_secret"],
            description=arguments.get("description", ""),
            additional_audiences=_normalize_audiences(arguments.get("additional_audiences")),
            redirect_uris=_normalize_str_list(
                arguments.get("redirect_uris"), "redirect_uris"
            ),
        )
        config.settings.clients.append(new_client)
        return {"success": True, "client": _client_to_dict(new_client)}

    elif name == "update_client":
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

        if "client_secret" in arguments:
            client.client_secret = arguments["client_secret"]
        if "description" in arguments:
            client.description = arguments["description"]
        if new_audiences is not None:
            client.additional_audiences = new_audiences
        if new_redirect_uris is not None:
            client.redirect_uris = new_redirect_uris

        return {"success": True, "client": _client_to_dict(client)}

    elif name == "delete_client":
        client_id = arguments["client_id"]
        client = config.get_client(client_id)
        if not client:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        config.settings.clients = [c for c in config.settings.clients if c.client_id != client_id]
        return {"success": True, "deleted": client_id}

    # Configuration
    elif name == "get_settings":
        settings = config.settings
        return {
            "issuer": settings.issuer,
            "audience": settings.audience,
            "token_expiry_minutes": settings.token_expiry_minutes,
            "security_profile": settings.security_profile,
            "refresh_token_rotation": settings.refresh_token_rotation,
            "require_pkce": settings.require_pkce,
            "jwt_algorithm": settings.jwt_algorithm,
            "saml": {
                "entity_id": settings.saml_entity_id,
                "sso_url": settings.saml_sso_url,
                "sign_responses": settings.saml_sign_responses,
                "c14n_algorithm": settings.saml_c14n_algorithm,
                "strict_binding": settings.strict_saml_binding,
                "want_authn_requests_signed": (
                    settings.saml_want_authn_requests_signed
                ),
                "sp_certificates": settings.saml_sp_certificates,
            },
            "logging": {
                "verbose_logging": settings.verbose_logging,
            },
            "authority_prefixes": settings.authority_prefixes,
            "allowed_identity_classes": settings.allowed_identity_classes,
        }

    elif name == "reload_config":
        config.reload()
        return {"success": True, "message": "Configuration reloaded"}

    elif name == "update_settings":
        settings = config.settings
        updated = []
        if "issuer" in arguments:
            settings.issuer = arguments["issuer"]
            updated.append("issuer")
        if "audience" in arguments:
            settings.audience = arguments["audience"]
            updated.append("audience")
        if "token_expiry_minutes" in arguments:
            settings.token_expiry_minutes = arguments["token_expiry_minutes"]
            updated.append("token_expiry_minutes")
        if "saml_sign_responses" in arguments:
            settings.saml_sign_responses = arguments["saml_sign_responses"]
            updated.append("saml_sign_responses")
        if "saml_c14n_algorithm" in arguments:
            settings.saml_c14n_algorithm = arguments["saml_c14n_algorithm"]
            updated.append("saml_c14n_algorithm")
        if "strict_saml_binding" in arguments:
            settings.strict_saml_binding = arguments["strict_saml_binding"]
            updated.append("strict_saml_binding")
        if "saml_want_authn_requests_signed" in arguments:
            settings.saml_want_authn_requests_signed = arguments[
                "saml_want_authn_requests_signed"
            ]
            updated.append("saml_want_authn_requests_signed")
        if "saml_sp_certificates" in arguments:
            settings.saml_sp_certificates = _normalize_str_list(
                arguments["saml_sp_certificates"], "saml_sp_certificates"
            )
            updated.append("saml_sp_certificates")
        if "verbose_logging" in arguments:
            settings.verbose_logging = arguments["verbose_logging"]
            updated.append("verbose_logging")
        if "refresh_token_rotation" in arguments:
            settings.refresh_token_rotation = arguments["refresh_token_rotation"]
            updated.append("refresh_token_rotation")
        if "require_pkce" in arguments:
            settings.require_pkce = arguments["require_pkce"]
            updated.append("require_pkce")

        return {
            "success": True,
            "updated_fields": updated,
            "current_settings": {
                "issuer": settings.issuer,
                "audience": settings.audience,
                "token_expiry_minutes": settings.token_expiry_minutes,
                "refresh_token_rotation": settings.refresh_token_rotation,
                "require_pkce": settings.require_pkce,
                "saml_sign_responses": settings.saml_sign_responses,
                "saml_c14n_algorithm": settings.saml_c14n_algorithm,
                "strict_saml_binding": settings.strict_saml_binding,
                "saml_want_authn_requests_signed": (
                    settings.saml_want_authn_requests_signed
                ),
                "saml_sp_certificates": settings.saml_sp_certificates,
                "verbose_logging": settings.verbose_logging,
            },
        }

    elif name == "save_config":
        try:
            config.save()
            return {"success": True, "message": "Configuration saved to YAML files"}
        except Exception as e:
            return {"success": False, "error": f"Failed to save config: {str(e)}"}

    # Discovery
    elif name == "get_oidc_discovery":
        # Shared with the HTTP /.well-known/openid-configuration endpoint so
        # the two documents can never drift apart (issue #40).
        return build_discovery_document(config.settings)

    elif name == "get_jwks":
        crypto = get_crypto_service(config.settings.keys_dir)
        return crypto.get_jwks()

    # Audit log (mirrors /api/audit*, issue #48)
    elif name == "get_audit_log":
        audit = get_audit_log()
        entries = audit.get_entries(
            limit=arguments.get("limit", 100),
            event_type=arguments.get("event_type"),
            username=arguments.get("username"),
        )
        return {"entries": entries, "count": len(entries)}

    elif name == "get_audit_stats":
        return get_audit_log().get_stats()

    elif name == "clear_audit_log":
        get_audit_log().clear()
        return {"success": True, "message": "Audit log cleared"}

    # Key management (mirrors /api/keys*, issue #48)
    elif name == "get_keys_info":
        crypto = get_crypto_service(config.settings.keys_dir)
        return {
            "active_kid": crypto.kid,
            "previous_keys_count": len(crypto.previous_keys),
            "previous_kids": [k.kid for k in crypto.previous_keys],
            "max_previous_keys": crypto.max_previous_keys,
        }

    elif name == "rotate_keys":
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

    else:
        return {"error": f"Unknown tool: {name}"}


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    """Run the MCP server."""
    global _readonly_mode

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="NanoIDP MCP Server - Identity Provider tools for Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security modes:
  --readonly              Disable mutating tools (create, update, delete, generate)
  NANOIDP_MCP_READONLY    Same as --readonly (env var)
  NANOIDP_MCP_ADMIN_SECRET  Require admin_secret parameter for mutating tools

Examples:
  nanoidp-mcp                    # Full access
  nanoidp-mcp --readonly         # Read-only access
  NANOIDP_MCP_READONLY=true nanoidp-mcp  # Read-only via env var
        """
    )
    parser.add_argument(
        "--readonly",
        action="store_true",
        help="Disable mutating tools (create_user, delete_user, generate_token, etc.)"
    )
    args = parser.parse_args()

    # Set readonly mode from CLI flag or environment variable
    _readonly_mode = args.readonly or os.getenv("NANOIDP_MCP_READONLY", "").lower() in ("true", "1", "yes")

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


if __name__ == "__main__":
    main()
