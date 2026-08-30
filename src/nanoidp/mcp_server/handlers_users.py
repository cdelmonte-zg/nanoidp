"""User and persona tool handlers (#286).

Split out of the monolithic mcp_server module; bodies unchanged.
"""

from typing import Any, Optional

from ..config import ConfigManager, User
from .serializers import _user_to_dict


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
    if "attributes" in arguments:
        # create_user accepted this from day one; update_user silently lacked
        # it (#280) - the parity drift the user-field audit found.
        candidate.attributes = arguments["attributes"]
    user = config.users[username] = candidate

    return {"success": True, "user": _user_to_dict(user)}


