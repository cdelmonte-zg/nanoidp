"""Read-surface serializers for the MCP tools (#286).

Split out of the monolithic mcp_server module; bodies unchanged.
"""

from typing import Any

from ..config import OAuthClient, User


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



def _client_to_dict(client: OAuthClient) -> dict[str, Any]:
    """Convert OAuthClient to dictionary (without secret)."""
    return {
        "client_id": client.client_id,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "description": client.description,
        "background_color": client.background_color,
        "header_color": client.header_color,
        "footer_color": client.footer_color,
        "show_client_id": client.show_client_id,
        "show_description": client.show_description,
        "layout": client.layout,
        "additional_audiences": client.additional_audiences,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "allowed_resources": client.allowed_resources,
    }

