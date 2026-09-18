"""OAuth client tool handlers (#286).

Split out of the monolithic mcp_server module; bodies unchanged - including
the pre-validate-before-any-assignment ordering comments.
"""

from typing import Any

from ..config import ConfigManager, OAuthClient
from ..services.client_policy import (
    UNSET,
    ClientSecretRequired,
    apply_client_auth,
    resolve_client_auth,
)
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

    # An absent method is not defaulted here: the resolver owns what a
    # client with no method named gets (#300 review). A public client has no
    # secret, and a supplied one is dropped rather than persisted as a dead,
    # ignored value (#188), the rule the UI forms share since #300.
    auth_method = (
        _normalize_auth_method(arguments["token_endpoint_auth_method"])
        if "token_endpoint_auth_method" in arguments
        else UNSET
    )
    try:
        auth = resolve_client_auth(method=auth_method, secret=arguments.get("client_secret"))
    except ClientSecretRequired as refused:
        return {"success": False, "error": str(refused)}

    new_client = OAuthClient(
        client_id=client_id,
        client_secret=auth.secret,
        token_endpoint_auth_method=auth.method,  # type: ignore[arg-type]
        description=arguments.get("description", ""),
        background_color=_normalize_hex_color(
            arguments.get("background_color"), "background_color"
        ),
        header_color=_normalize_hex_color(arguments.get("header_color"), "header_color"),
        footer_color=_normalize_hex_color(arguments.get("footer_color"), "footer_color"),
        show_client_id=arguments.get("show_client_id", True),
        show_description=arguments.get("show_description", False),
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
        else UNSET
    )
    # The method/secret combination is resolved BEFORE any assignment
    # (#188), so the model validator can never reject mid-sequence and
    # leave the live client half-updated. An omitted secret keeps the
    # stored one; a supplied empty one is an attempt to clear it, which a
    # confidential client refuses (#300).
    try:
        auth = resolve_client_auth(
            method=new_auth_method,
            secret=arguments["client_secret"] or None if "client_secret" in arguments else UNSET,
            current_method=client.token_endpoint_auth_method,
            current_secret=client.client_secret,
        )
    except ClientSecretRequired as refused:
        return {"success": False, "error": str(refused)}

    # The assignment order is the model's rule, not this handler's (#300):
    # validate_assignment would refuse a half-applied state.
    apply_client_auth(client, auth)
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


