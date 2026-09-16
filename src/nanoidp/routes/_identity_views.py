"""The JSON shape of a user or a client on the management API, with its
origin (#192): one spelling for ``/api/users`` and ``/api/runtime``.

Never a password, a client secret or a TOTP secret.
"""

from typing import Any, Dict

from ..config import OAuthClient, User


def user_summary(user: User, origin: str) -> Dict[str, Any]:
    return {
        "username": user.username,
        "origin": origin,
        "description": user.description,
        "email": user.email,
        "identity_class": user.identity_class,
        "roles": user.roles,
        "groups": user.groups,
        "tenant": user.tenant,
        "has_acl": len(user.source_acl) > 0,
        "has_entitlements": len(user.entitlements) > 0,
    }


def client_summary(client: OAuthClient, origin: str) -> Dict[str, Any]:
    return {
        "client_id": client.client_id,
        "origin": origin,
        "description": client.description,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "allowed_resources": client.allowed_resources,
        "additional_audiences": client.additional_audiences,
    }
