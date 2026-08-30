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
from typing import Any, Callable, Optional, Tuple

from jsonschema.exceptions import best_match
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from .. import __version__
from ..config import ConfigManager, init_config
from ..security import verify_secret
from ..services import get_audit_log, init_crypto_service

# Split into a package (#286); these re-imports keep the EXPLICITLY listed
# names importable as before: `from nanoidp.mcp_server import <name>` and
# `mcp_server.<name>` resolve as they did when this was one module, for
# every name tests/src/e2e actually use (derived by AST walk at split
# time). Arbitrary internal symbols of the old monolith are not a
# compatibility surface - this is an internal module (#296 review).
# The two MUTABLE globals (_config, _readonly_mode) are DEFINED here, in the
# package module itself, because tests and conftest reset/monkeypatch them by
# attribute assignment on `nanoidp.mcp_server`.
from .handlers_clients import (  # noqa: F401
    _tool_create_client,
    _tool_delete_client,
    _tool_get_client,
    _tool_list_clients,
    _tool_update_client,
)
from .handlers_config import (  # noqa: F401
    _tool_clear_audit_log,
    _tool_get_audit_log,
    _tool_get_audit_stats,
    _tool_get_jwks,
    _tool_get_keys_info,
    _tool_get_oidc_discovery,
    _tool_get_settings,
    _tool_reload_config,
    _tool_rotate_keys,
    _tool_save_config,
    _tool_update_settings,
    _tool_validate_config,
)
from .handlers_tokens import (  # noqa: F401
    _tool_decode_token,
    _tool_generate_token,
    _tool_verify_token,
)
from .handlers_users import (  # noqa: F401
    _build_user_from_arguments,
    _tool_create_persona_user,
    _tool_create_user,
    _tool_delete_user,
    _tool_get_user,
    _tool_list_users,
    _tool_update_user,
)
from .normalize import (  # noqa: F401
    _HEX_COLOR_RE,
    _LAYOUTS,
    _TOKEN_ENDPOINT_AUTH_METHODS,
    _UPDATE_SETTINGS_FIELDS,
    _UPDATE_SETTINGS_NORMALIZERS,
    _blank_to_none,
    _normalize_audiences,
    _normalize_auth_method,
    _normalize_hex_color,
    _normalize_layout,
    _normalize_str_list,
    _normalize_update_attr_name,
    _normalize_update_list,
)
from .schemas import (  # noqa: F401
    _TOOL_SCHEMAS,
    _TOOL_VALIDATORS,
    _TOOLS,
    _USER_COMMON_PROPERTIES,
)
from .serializers import _client_to_dict, _user_to_dict  # noqa: F401

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

    THE MCP ERROR MODEL IS TWO DELIBERATE LAYERS (#287), not one shape:

    - DISPATCH refusals (this function): the call never reached a tool -
      ``{"error", "code", "tool"}`` with ``is_error=True``. The ``code``
      taxonomy (MCP_READONLY_MODE, MCP_ADMIN_SECRET_REQUIRED, MCP_UNKNOWN_TOOL,
      MCP_INVALID_ARGUMENTS, MCP_INTERNAL_ERROR) is transport-level.
    - DOMAIN results (the handlers): the tool ran and answered -
      ``{"success": False, "error", ...}`` (plus ``kind`` where a typed
      condition exists: conflict, hook policy). These DO come back with
      ``is_error=True`` as well: call_tool flags
      ``result.get("success") is False or "error" in result`` (the
      module-docstring isError contract). The "an answer, not an error"
      cases are the NEGATIVE QUERIES - ``found: False`` (get_user/
      get_client miss) and ``valid: False`` (verify_token) - which carry
      no ``success``/``error`` key and stay ``is_error=False``.

    Collapsing the two SHAPES into one would break every MCP consumer for
    a cosmetic gain; what matters is that each layer has exactly one
    shape, which this function, the handlers' conventions and the
    module-docstring table keep true. See CONTRIBUTING, "Error surfaces".
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

