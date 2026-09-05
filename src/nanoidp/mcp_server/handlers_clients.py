"""OAuth client tool handlers (#286).

Split out of the monolithic mcp_server module; bodies unchanged - including
the pre-validate-before-any-assignment ordering comments.
"""

from typing import Any

from ..config import ConfigManager, OAuthClient
from .normalize import (
    _normalize_audiences,
    _normalize_auth_method,
    _normalize_hex_color,
    _normalize_layout,
    _normalize_str_list,
)
from .serializers import _client_to_dict


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

    auth_method = _normalize_auth_method(
        arguments.get("token_endpoint_auth_method", "client_secret_basic")
    )
    client_secret = arguments.get("client_secret")
    if auth_method == "none":
        # A public client has no secret; drop a supplied one rather than
        # persisting a dead, ignored value (#188, parity with the UI create
        # form's server-side normalization).
        client_secret = None
    elif not client_secret:
        return {
            "success": False,
            "error": "client_secret is required unless token_endpoint_auth_method is 'none'",
        }

    new_client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint_auth_method=auth_method,  # type: ignore[arg-type]
        description=arguments.get("description", ""),
        background_color=_normalize_hex_color(
            arguments.get("background_color"), "background_color"
        ),
        header_color=_normalize_hex_color(arguments.get("header_color"), "header_color"),
        footer_color=_normalize_hex_color(arguments.get("footer_color"), "footer_color"),
        show_client_id=arguments.get("show_client_id", True),
        show_description=arguments.get("show_description", False),
        two_step_login=arguments.get("two_step_login", False),
        layout=_normalize_layout(arguments.get("layout", "vertical")),  # type: ignore[arg-type]
        additional_audiences=_normalize_audiences(arguments.get("additional_audiences")),
        redirect_uris=_normalize_str_list(arguments.get("redirect_uris"), "redirect_uris"),
        allowed_scopes=_normalize_str_list(arguments.get("allowed_scopes"), "allowed_scopes"),
        allowed_resources=_normalize_str_list(arguments.get("allowed_resources"), "allowed_resources"),
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
    new_allowed_resources = (
        _normalize_str_list(arguments["allowed_resources"], "allowed_resources")
        if "allowed_resources" in arguments
        else None
    )
    new_layout = (
        _normalize_layout(arguments["layout"]) if "layout" in arguments else None
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

    new_auth_method = (
        _normalize_auth_method(arguments["token_endpoint_auth_method"])
        if "token_endpoint_auth_method" in arguments
        else None
    )
    # Check the method/secret combination BEFORE any assignment (#188), so
    # the model validator can never reject mid-sequence and leave the live
    # client half-updated.
    effective_method = new_auth_method or client.token_endpoint_auth_method
    effective_secret = (
        (arguments["client_secret"] or None)
        if "client_secret" in arguments
        else client.client_secret
    )
    if effective_method != "none" and not effective_secret:
        return {
            "success": False,
            "error": "client_secret is required unless token_endpoint_auth_method is 'none'",
        }

    # Assignment order matters under validate_assignment (#188). A public
    # target (whether being switched to 'none' or already 'none') keeps NO
    # secret: set the method first so clearing the secret is valid, then
    # clear it - dropping any supplied or existing dead value, parity with
    # the UI's server-side normalization (#254 review). A confidential
    # target sets the new secret BEFORE flipping the method, or the model's
    # confidential-clients-need-a-secret check would reject mid-update.
    if effective_method == "none":
        if new_auth_method is not None:
            client.token_endpoint_auth_method = new_auth_method  # type: ignore[assignment]
        client.client_secret = None
    else:
        if "client_secret" in arguments:
            client.client_secret = arguments["client_secret"] or None
        if new_auth_method is not None:
            client.token_endpoint_auth_method = new_auth_method  # type: ignore[assignment]
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
    if "two_step_login" in arguments:
        client.two_step_login = arguments["two_step_login"]
    if new_layout is not None:
        client.layout = new_layout  # type: ignore[assignment]
    if new_audiences is not None:
        client.additional_audiences = new_audiences
    if new_redirect_uris is not None:
        client.redirect_uris = new_redirect_uris
    if new_allowed_scopes is not None:
        client.allowed_scopes = new_allowed_scopes
    if new_allowed_resources is not None:
        client.allowed_resources = new_allowed_resources

    return {"success": True, "client": _client_to_dict(client)}


def _tool_delete_client(arguments: dict[str, Any], config: ConfigManager) -> dict[str, Any]:
    client_id = arguments["client_id"]
    client = config.get_client(client_id)
    if not client:
        return {"success": False, "error": f"Client '{client_id}' not found"}

    config.settings.clients = [c for c in config.settings.clients if c.client_id != client_id]
    return {"success": True, "deleted": client_id}


