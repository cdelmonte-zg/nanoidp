"""Runtime identity tool handlers (#432): the MCP surface of the lifecycle
``/api/runtime`` offers over HTTP.

Disposable test users and clients on a running NanoIDP, created, read,
deleted, promoted and reset through the same services and the same rules
(``services.runtime_operations``, ``services.identities``): the same
parsers, the same refusal kinds, the same views. They act on the runtime
store, so the dispatcher refuses every one of them when that store is this
process's alone (``RUNTIME_STATE_TOOLS`` in the package): an identity
created there would exist nowhere else.
"""

from typing import Any, Callable, Dict, Union

from ..config import ConfigManager, ConfigSnapshot
from ..config_documents import EntryInvalid
from ..services import get_audit_log
from ..services import runtime_operations as operations
from ..services.dynamic_registration import delete_client_and_registration
from ..services.identities import IdentityResolver, identities_for
from ..services.identity_views import client_summary, user_summary
from ..services.runtime_operations import Refused


def _refused(refused: Refused) -> Dict[str, Any]:
    """A refusal as a tool result: the kind ``/api/runtime`` answers with.
    ``kind`` is in a refusal only, so it always names why. A lock also says
    whether coming back may help."""
    answer: Dict[str, Any] = {"success": False, "error": refused.message, "kind": refused.kind}
    if refused.kind == "lock_unavailable":
        answer["retryable"] = refused.retryable
    return answer


def _audit(event_type: str, tool: str, kind: str, name: str) -> None:
    """The event the HTTP route records for the same operation, said by
    this surface: endpoint ``mcp``, the tool as the method."""
    get_audit_log().log(
        event_type=event_type,
        endpoint="mcp",
        method=tool,
        status="success",
        username=name if kind == "user" else None,
        client_id=name if kind == "client" else None,
        details={"kind": kind, "name": name},
    )


def _resolver(config: ConfigManager, loaded: ConfigSnapshot) -> IdentityResolver:
    return identities_for(config, loaded)


def _created(tool: str, kind: str, name: str, make: Callable[[], Any], view: Callable[[Any], Dict[str, Any]]) -> Dict[str, Any]:
    created = operations.create(kind, name, make)
    if isinstance(created, Refused):
        return _refused(created)
    _audit(operations.CREATED, tool, kind, name)
    return {"success": True, kind: view(created)}


def _deleted(tool: str, kind: str, name: str, remove: Callable[[str], None]) -> Dict[str, Any]:
    refused = operations.delete(kind, name, remove)
    if refused is not None:
        return _refused(refused)
    _audit(operations.DELETED, tool, kind, name)
    return {"success": True, "deleted": name}


def _promoted(tool: str, kind: str, name: str, promote: Callable[[Dict[str, Any]], Any]) -> Dict[str, Any]:
    # What the reconciliation records the promotion with, once (#192).
    context = {"endpoint": "mcp", "method": tool}
    outcome: Union[Dict[str, Any], Refused] = operations.promote(kind, name, lambda: promote(context))
    if isinstance(outcome, Refused):
        return _refused(outcome)
    # Without the identity's kind: the tool's name says it, and ``kind`` in
    # a result of these tools is the reason of a refusal.
    return {"success": True, **{key: value for key, value in outcome.items() if key != "kind"}}


# ---- users ------------------------------------------------------------------


def _tool_create_runtime_user(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    try:
        user = operations.user_from(arguments, "create_runtime_user")
    except EntryInvalid as exc:
        return _refused(Refused("invalid", exc.message))
    return _created(
        "create_runtime_user",
        "user",
        user.username,
        lambda: _resolver(config, loaded).create_runtime_user(user),
        lambda created: user_summary(created, "runtime"),
    )


def _tool_list_runtime_users(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    users = [user_summary(user, "runtime") for user in _resolver(config, loaded).store.users.list()]
    return {"users": users, "count": len(users)}


def _tool_get_runtime_user(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    username = arguments["username"]
    user = _resolver(config, loaded).store.users.get(username)
    if user is None:
        # A lookup that finds nothing is an answer, not a failure: the
        # shape get_user gives (see the isError contract of the package).
        return {"found": False, "username": username}
    return {"found": True, "user": user_summary(user, "runtime")}


def _tool_delete_runtime_user(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    return _deleted("delete_runtime_user", "user", arguments["username"], _resolver(config, loaded).delete_runtime_user)


def _tool_promote_runtime_user(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    username = arguments["username"]
    resolver = _resolver(config, loaded)
    return _promoted(
        "promote_runtime_user", "user", username, lambda context: resolver.promote_runtime_user(username, context)
    )


# ---- clients ----------------------------------------------------------------


def _tool_create_runtime_client(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    try:
        client = operations.client_from(arguments, "create_runtime_client")
    except EntryInvalid as exc:
        return _refused(Refused("invalid", exc.message))
    return _created(
        "create_runtime_client",
        "client",
        client.client_id,
        lambda: _resolver(config, loaded).create_runtime_client(client),
        lambda created: client_summary(created, "runtime"),
    )


def _tool_list_runtime_clients(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    entries = _resolver(config, loaded).store.clients.entries()
    clients = [client_summary(entry.value, "runtime", operations.source_of(entry)) for entry in entries]
    return {"clients": clients, "count": len(clients)}


def _tool_get_runtime_client(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    client_id = arguments["client_id"]
    entry = _resolver(config, loaded).store.clients.entry(client_id)
    if entry is None:
        return {"found": False, "client_id": client_id}
    return {"found": True, "client": client_summary(entry.value, "runtime", operations.source_of(entry))}


def _tool_delete_runtime_client(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    resolver = _resolver(config, loaded)
    # With the record issued for it, if it was registered (#190, #403).
    return _deleted(
        "delete_runtime_client",
        "client",
        arguments["client_id"],
        lambda name: delete_client_and_registration(name, resolver),
    )


def _tool_promote_runtime_client(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    client_id = arguments["client_id"]
    resolver = _resolver(config, loaded)
    return _promoted(
        "promote_runtime_client",
        "client",
        client_id,
        lambda context: resolver.promote_runtime_client(client_id, context),
    )


# ---- reset ------------------------------------------------------------------


def _tool_reset_runtime_identities(arguments: dict[str, Any], config: ConfigManager, loaded: ConfigSnapshot) -> dict[str, Any]:
    counts = operations.reset(_resolver(config, loaded))
    get_audit_log().log(
        event_type=operations.RESET,
        endpoint="mcp",
        method="reset_runtime_identities",
        status="success",
        details=dict(counts),
    )
    return {"success": True, **counts}


# The tools of this module, by name: the package dispatches from this table
# and derives from it the group its not-shared-store guard covers, so a tool
# added here cannot be left outside the guard.
Handler = Callable[[dict[str, Any], ConfigManager, ConfigSnapshot], dict[str, Any]]
RUNTIME_STATE_HANDLERS: Dict[str, Handler] = {
    "create_runtime_user": _tool_create_runtime_user,
    "list_runtime_users": _tool_list_runtime_users,
    "get_runtime_user": _tool_get_runtime_user,
    "delete_runtime_user": _tool_delete_runtime_user,
    "promote_runtime_user": _tool_promote_runtime_user,
    "create_runtime_client": _tool_create_runtime_client,
    "list_runtime_clients": _tool_list_runtime_clients,
    "get_runtime_client": _tool_get_runtime_client,
    "delete_runtime_client": _tool_delete_runtime_client,
    "promote_runtime_client": _tool_promote_runtime_client,
    "reset_runtime_identities": _tool_reset_runtime_identities,
}
# The ones that only read; every other one writes, and is a mutating tool.
RUNTIME_STATE_READERS = frozenset(
    {"list_runtime_users", "get_runtime_user", "list_runtime_clients", "get_runtime_client"}
)
