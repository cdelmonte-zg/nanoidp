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
from datetime import datetime, timezone
from typing import Any, Tuple

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .config import ConfigManager, User, OAuthClient, init_config, get_config
from .services import init_crypto_service, get_crypto_service, get_token_service, get_audit_log

logger = logging.getLogger(__name__)

# Initialize the MCP server
server = Server("nanoidp")

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
}


def _check_admin_secret(tool_name: str, arguments: dict) -> Tuple[bool, str]:
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


def _log_mcp_tool(tool_name: str, success: bool, details: dict = None):
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
    }


# =============================================================================
# Tool Definitions
# =============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        # User Management
        Tool(
            name="list_users",
            description="List all configured users in NanoIDP",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="get_user",
            description="Get details of a specific user",
            inputSchema={
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
            inputSchema={
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
            inputSchema={
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
            inputSchema={
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
            inputSchema={
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
                },
                "required": ["username"],
            },
        ),
        Tool(
            name="decode_token",
            description="Decode and display the claims in a JWT token (without signature verification)",
            inputSchema={
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
            inputSchema={
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
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="get_client",
            description="Get details of a specific OAuth client",
            inputSchema={
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
            inputSchema={
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
                },
                "required": ["client_id", "client_secret"],
            },
        ),
        Tool(
            name="update_client",
            description="Update an existing OAuth client",
            inputSchema={
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
                },
                "required": ["client_id"],
            },
        ),
        Tool(
            name="delete_client",
            description="Delete an OAuth client",
            inputSchema={
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
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="reload_config",
            description="Reload configuration from files",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="update_settings",
            description="Update NanoIDP settings (issuer, audience, token expiry, SAML options, etc.)",
            inputSchema={
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
                    "strict_saml_binding": {
                        "type": "boolean",
                        "description": "Enforce strict SAML binding compliance (reject GET with uncompressed data)",
                    },
                    "verbose_logging": {
                        "type": "boolean",
                        "description": "Include usernames/client_ids in log messages (dev convenience)",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="save_config",
            description="Save current configuration to YAML files (persists changes)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),

        # Discovery
        Tool(
            name="get_oidc_discovery",
            description="Get OIDC discovery document (/.well-known/openid-configuration)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="get_jwks",
            description="Get JSON Web Key Set for token verification",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    ]


# =============================================================================
# Tool Implementations
# =============================================================================

@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls with readonly and admin secret checks, plus audit logging."""
    config = _ensure_config()

    # Check readonly mode first (completely blocks mutating tools)
    allowed, error_msg = _check_readonly_mode(name)
    if not allowed:
        _log_mcp_tool(name, success=False, details={"error": "readonly_mode", "tool": name})
        return [TextContent(type="text", text=json.dumps({
            "error": error_msg,
            "code": "MCP_READONLY_MODE",
            "tool": name,
        }, indent=2))]

    # Check admin secret for mutating operations
    allowed, error_msg = _check_admin_secret(name, arguments)
    if not allowed:
        _log_mcp_tool(name, success=False, details={"error": "admin_secret_required"})
        return [TextContent(type="text", text=json.dumps({
            "error": error_msg,
            "code": "MCP_ADMIN_SECRET_REQUIRED",
            "tool": name,
        }, indent=2))]

    try:
        result = await _execute_tool(name, arguments, config)
        _log_mcp_tool(name, success=True, details={"tool": name})
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        _log_mcp_tool(name, success=False, details={"error": str(e)})
        return [TextContent(type="text", text=json.dumps({
            "error": str(e),
            "tool": name,
        }, indent=2))]


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
        )
        return {
            "success": True,
            "access_token": token_response["access_token"],
            "refresh_token": token_response["refresh_token"],
            "token_type": token_response["token_type"],
            "expires_in": token_response["expires_in"],
        }

    elif name == "decode_token":
        import jwt as pyjwt
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
        )
        config.settings.clients.append(new_client)
        return {"success": True, "client": _client_to_dict(new_client)}

    elif name == "update_client":
        client_id = arguments["client_id"]
        client = config.get_client(client_id)
        if not client:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        if "client_secret" in arguments:
            client.client_secret = arguments["client_secret"]
        if "description" in arguments:
            client.description = arguments["description"]

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
            "jwt_algorithm": settings.jwt_algorithm,
            "saml": {
                "entity_id": settings.saml_entity_id,
                "sso_url": settings.saml_sso_url,
                "sign_responses": settings.saml_sign_responses,
                "c14n_algorithm": settings.saml_c14n_algorithm,
                "strict_binding": settings.strict_saml_binding,
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
        if "verbose_logging" in arguments:
            settings.verbose_logging = arguments["verbose_logging"]
            updated.append("verbose_logging")

        return {
            "success": True,
            "updated_fields": updated,
            "current_settings": {
                "issuer": settings.issuer,
                "audience": settings.audience,
                "token_expiry_minutes": settings.token_expiry_minutes,
                "saml_sign_responses": settings.saml_sign_responses,
                "saml_c14n_algorithm": settings.saml_c14n_algorithm,
                "strict_saml_binding": settings.strict_saml_binding,
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
        settings = config.settings
        return {
            "issuer": settings.issuer,
            "authorization_endpoint": f"{settings.issuer}/authorize",
            "token_endpoint": f"{settings.issuer}/token",
            "userinfo_endpoint": f"{settings.issuer}/userinfo",
            "introspection_endpoint": f"{settings.issuer}/introspect",
            "revocation_endpoint": f"{settings.issuer}/revoke",
            "end_session_endpoint": f"{settings.issuer}/logout",
            "device_authorization_endpoint": f"{settings.issuer}/device_authorization",
            "jwks_uri": f"{settings.issuer}/.well-known/jwks.json",
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
                "password",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
        }

    elif name == "get_jwks":
        crypto = get_crypto_service(config.settings.keys_dir)
        return crypto.get_jwks()

    else:
        return {"error": f"Unknown tool: {name}"}


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
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

    # Run the server
    asyncio.run(stdio_server(server))


if __name__ == "__main__":
    main()
