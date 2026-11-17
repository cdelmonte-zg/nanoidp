"""``/api/runtime``: the lifecycle of runtime-created users and clients (#192).

Runtime identities are disposable test state: a CI job or a test creates
them on a running IdP, uses them in any protocol flow, and throws them away
without touching the declared configuration, unless one is explicitly
promoted into it. The operations are create, read, delete, reset and
promote; there is no update, since the store is by value (#235) and a change
is a delete and a create.

The rules (declared first, no runtime object under a declared name, the
promotion order, the reconciliation on reload) live in
``services.identities``; this module maps them onto HTTP. Access follows
every other management write (#163): the same gate as ``/api``.
"""

from typing import Any, Callable, Dict, Union

from flask import Blueprint, jsonify, request
from flask.typing import ResponseReturnValue

from ..config import get_config
from ..config_documents import EntryInvalid
from ..services import runtime_operations as operations
from ..services.dynamic_registration import delete_client_and_registration
from ..services.identities import identities_for
from ..services.identity_views import client_summary, user_summary
from ..services.runtime_operations import Refused
from ._audit import audit_event
from ._auth import management_secret_required_for_api
from ._config import request_config

runtime_bp = Blueprint("runtime", __name__, url_prefix="/api/runtime")
runtime_bp.before_request(management_secret_required_for_api)

# The status of each refusal of ``services.runtime_operations``: what a
# refusal is called is decided there, how HTTP says it here.
_STATUS = {
    "invalid": 400,
    "not_found": 404,
    "declared": 409,
    "exists": 409,
    "promotion_in_progress": 409,
    "conflict": 409,
    "unloadable": 422,
    "reload_failed": 500,
    "write_failed": 500,
    "lock_unavailable": 503,
}


def _refused(refused: Refused) -> ResponseReturnValue:
    return jsonify({"error": refused.message, "kind": refused.kind}), _STATUS[refused.kind]


def _json_object() -> Dict[str, Any]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise EntryInvalid(f"{request.method} {request.path}: expected a JSON object")
    return body


def _audit(event_type: str, kind: str, name: str, **details: Any) -> None:
    audit_event(
        event_type,
        "success",
        endpoint=request.path,
        username=name if kind == "user" else None,
        client_id=name if kind == "client" else None,
        details={"kind": kind, "name": name, **details},
    )


# ---- users ------------------------------------------------------------------


@runtime_bp.route("/users", methods=["POST"])
def create_user() -> ResponseReturnValue:
    """Create a runtime user from a ``users.yaml``-shaped entry plus
    ``username``; validated exactly like a declared user."""
    try:
        user = operations.user_from(_json_object(), "POST /api/runtime/users")
    except EntryInvalid as exc:
        return _refused(Refused("invalid", exc.message))
    return _create("user", user.username, lambda: identities_for(get_config(), request_config()).create_runtime_user(user),
                   lambda created: user_summary(created, "runtime"))


@runtime_bp.route("/users")
def list_users() -> ResponseReturnValue:
    users = [user_summary(user, "runtime") for user in identities_for(get_config(), request_config()).store.users.list()]
    return jsonify({"users": users, "count": len(users)})


@runtime_bp.route("/users/<username>")
def get_user(username: str) -> ResponseReturnValue:
    user = identities_for(get_config(), request_config()).store.users.get(username)
    if user is None:
        return _refused(operations.not_found("user", username))
    return jsonify(user_summary(user, "runtime"))


@runtime_bp.route("/users/<username>", methods=["DELETE"])
def delete_user(username: str) -> ResponseReturnValue:
    return _delete("user", username, identities_for(get_config(), request_config()).delete_runtime_user)


@runtime_bp.route("/users/<username>/promote", methods=["POST"])
def promote_user(username: str) -> ResponseReturnValue:
    resolver = identities_for(get_config(), request_config())
    return _promote("user", username, lambda context: resolver.promote_runtime_user(username, context))


# ---- clients ----------------------------------------------------------------


@runtime_bp.route("/clients", methods=["POST"])
def create_client() -> ResponseReturnValue:
    """Create a runtime client from an ``oauth.clients[]``-shaped entry;
    validated exactly like a declared client."""
    try:
        client = operations.client_from(_json_object(), "POST /api/runtime/clients")
    except EntryInvalid as exc:
        return _refused(Refused("invalid", exc.message))
    return _create("client", client.client_id,
                   lambda: identities_for(get_config(), request_config()).create_runtime_client(client),
                   lambda created: client_summary(created, "runtime"))


@runtime_bp.route("/clients")
def list_clients() -> ResponseReturnValue:
    entries = identities_for(get_config(), request_config()).store.clients.entries()
    clients = [client_summary(entry.value, "runtime", operations.source_of(entry)) for entry in entries]
    return jsonify({"clients": clients, "count": len(clients)})


@runtime_bp.route("/clients/<client_id>")
def get_client(client_id: str) -> ResponseReturnValue:
    entry = identities_for(get_config(), request_config()).store.clients.entry(client_id)
    if entry is None:
        return _refused(operations.not_found("client", client_id))
    return jsonify(client_summary(entry.value, "runtime", operations.source_of(entry)))


@runtime_bp.route("/clients/<client_id>", methods=["DELETE"])
def delete_client(client_id: str) -> ResponseReturnValue:
    resolver = identities_for(get_config(), request_config())
    # With the record issued for it, if it was registered (#190, #403).
    return _delete(
        "client", client_id, lambda name: delete_client_and_registration(name, resolver)
    )


@runtime_bp.route("/clients/<client_id>/promote", methods=["POST"])
def promote_client(client_id: str) -> ResponseReturnValue:
    resolver = identities_for(get_config(), request_config())
    return _promote("client", client_id, lambda context: resolver.promote_runtime_client(client_id, context))


# ---- reset ------------------------------------------------------------------


@runtime_bp.route("", methods=["DELETE"])
def reset() -> ResponseReturnValue:
    """Remove every runtime user and client. Never touches the declared
    configuration."""
    counts = operations.reset(identities_for(get_config(), request_config()))
    audit_event(operations.RESET, "success", endpoint=request.path, details=counts)
    return jsonify(counts)


# ---- shared -----------------------------------------------------------------


def _create(kind: str, name: str, create: Callable[[], Any], view: Callable[[Any], Dict[str, Any]]) -> ResponseReturnValue:
    created = operations.create(kind, name, create)
    if isinstance(created, Refused):
        return _refused(created)
    _audit(operations.CREATED, kind, name)
    return jsonify(view(created)), 201


def _delete(kind: str, name: str, delete: Callable[[str], None]) -> ResponseReturnValue:
    refused = operations.delete(kind, name, delete)
    if refused is not None:
        return _refused(refused)
    _audit(operations.DELETED, kind, name)
    return jsonify({"deleted": name, "kind": kind})


def _promote(kind: str, name: str, promote: Callable[[Dict[str, Any]], Any]) -> ResponseReturnValue:
    context = {
        "endpoint": request.path,
        "method": request.method,
        "ip_address": request.remote_addr or "unknown",
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }
    outcome: Union[Dict[str, Any], Refused] = operations.promote(kind, name, lambda: promote(context))
    if isinstance(outcome, Refused):
        return _refused(outcome)
    return jsonify(outcome)
