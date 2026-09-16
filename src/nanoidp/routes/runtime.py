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

from typing import Any, Callable, Dict, Optional

from flask import Blueprint, current_app, jsonify, request
from flask.typing import ResponseReturnValue

from ..config import ConfigurationRejected, get_config
from ..config_documents import EntryInvalid, parse_client_entry, parse_user_entry
from ..config_writer import ConflictError, LockUnavailableError
from ..hooks import HookError
from ..services.dynamic_registration import (
    forget_registration,
    live_registration,
    prune_stale_registrations,
)
from ..services.identities import (
    DeclaredNameCollision,
    IdentityResolver,
    PromotionInProgress,
    PromotionOutcome,
    RuntimeObjectNotFound,
    identities_for,
)
from ..services.runtime_identities import RuntimeObjectExists
from ..services.yaml_writer import PostWriteError
from ._audit import audit_event
from ._auth import management_secret_required_for_api
from ._identity_views import client_summary, user_summary

runtime_bp = Blueprint("runtime", __name__, url_prefix="/api/runtime")
runtime_bp.before_request(management_secret_required_for_api)


def _error(status: int, message: str, kind: str) -> ResponseReturnValue:
    return jsonify({"error": message, "kind": kind}), status


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
        body = _json_object()
        username = body.pop("username", None)
        if not isinstance(username, str) or not username:
            raise EntryInvalid("POST /api/runtime/users: username is required")
        user = parse_user_entry(username, body, "POST /api/runtime/users")
    except EntryInvalid as exc:
        return _error(400, exc.message, "invalid")
    return _create("user", user.username, lambda: identities_for(get_config()).create_runtime_user(user),
                   lambda created: user_summary(created, "runtime"))


@runtime_bp.route("/users")
def list_users() -> ResponseReturnValue:
    users = [user_summary(user, "runtime") for user in identities_for(get_config()).store.users.list()]
    return jsonify({"users": users, "count": len(users)})


@runtime_bp.route("/users/<username>")
def get_user(username: str) -> ResponseReturnValue:
    user = identities_for(get_config()).store.users.get(username)
    if user is None:
        return _error(404, f"no runtime user {username!r}", "not_found")
    return jsonify(user_summary(user, "runtime"))


@runtime_bp.route("/users/<username>", methods=["DELETE"])
def delete_user(username: str) -> ResponseReturnValue:
    return _delete("user", username, identities_for(get_config()).delete_runtime_user)


@runtime_bp.route("/users/<username>/promote", methods=["POST"])
def promote_user(username: str) -> ResponseReturnValue:
    resolver = identities_for(get_config())
    return _promote("user", username, "users.yaml", lambda context: resolver.promote_runtime_user(username, context))


# ---- clients ----------------------------------------------------------------


@runtime_bp.route("/clients", methods=["POST"])
def create_client() -> ResponseReturnValue:
    """Create a runtime client from an ``oauth.clients[]``-shaped entry;
    validated exactly like a declared client."""
    try:
        client = parse_client_entry(_json_object(), "POST /api/runtime/clients")
    except EntryInvalid as exc:
        return _error(400, exc.message, "invalid")
    return _create("client", client.client_id,
                   lambda: identities_for(get_config()).create_runtime_client(client),
                   lambda created: client_summary(created, "runtime"))


def _source_of(client_id: str, resolver: IdentityResolver) -> Optional[str]:
    """``dcr`` when a live registration record manages this client (#190).

    Read from the record rather than from the shape of the id, which is only
    a hint for a human reading a log - and through the liveness check, so a
    record that outlived its client cannot label the next client to hold
    that name as one somebody registered.
    """
    return "dcr" if live_registration(client_id, resolver) is not None else None


@runtime_bp.route("/clients")
def list_clients() -> ResponseReturnValue:
    resolver = identities_for(get_config())
    clients = [
        client_summary(c, "runtime", _source_of(c.client_id, resolver))
        for c in resolver.store.clients.list()
    ]
    return jsonify({"clients": clients, "count": len(clients)})


@runtime_bp.route("/clients/<client_id>")
def get_client(client_id: str) -> ResponseReturnValue:
    resolver = identities_for(get_config())
    client = resolver.store.clients.get(client_id)
    if client is None:
        return _error(404, f"no runtime client {client_id!r}", "not_found")
    return jsonify(client_summary(client, "runtime", _source_of(client_id, resolver)))


@runtime_bp.route("/clients/<client_id>", methods=["DELETE"])
def delete_client(client_id: str) -> ResponseReturnValue:
    return _delete("client", client_id, identities_for(get_config()).delete_runtime_client)


@runtime_bp.route("/clients/<client_id>/promote", methods=["POST"])
def promote_client(client_id: str) -> ResponseReturnValue:
    resolver = identities_for(get_config())
    return _promote(
        "client", client_id, "settings.yaml", lambda context: resolver.promote_runtime_client(client_id, context)
    )


# ---- reset ------------------------------------------------------------------


@runtime_bp.route("", methods=["DELETE"])
def reset() -> ResponseReturnValue:
    """Remove every runtime user and client. Never touches the declared
    configuration."""
    resolver = identities_for(get_config())
    users_deleted, clients_deleted = resolver.reset_runtime_identities()
    # Same reason as in _delete: a record must not outlive its client and be
    # inherited by the next one to hold that id (#190).
    prune_stale_registrations(resolver)
    audit_event(
        "runtime_identities_reset",
        "success",
        endpoint=request.path,
        details={"users_deleted": users_deleted, "clients_deleted": clients_deleted},
    )
    return jsonify({"users_deleted": users_deleted, "clients_deleted": clients_deleted})


# ---- shared -----------------------------------------------------------------


def _create(kind: str, name: str, create: Callable[[], Any], view: Callable[[Any], Dict[str, Any]]) -> ResponseReturnValue:
    try:
        created = create()
    except DeclaredNameCollision:
        return _error(409, f"{kind} {name!r} is declared in the configuration", "declared")
    except RuntimeObjectExists:
        return _error(409, f"a runtime {kind} {name!r} already exists", "exists")
    _audit("runtime_identity_created", kind, name)
    return jsonify(view(created)), 201


def _delete(kind: str, name: str, delete: Callable[[str], None]) -> ResponseReturnValue:
    try:
        delete(name)
    except RuntimeObjectNotFound:
        return _error(404, f"no runtime {kind} {name!r}", "not_found")
    except PromotionInProgress:
        return _error(409, f"runtime {kind} {name!r} is being promoted", "promotion_in_progress")
    if kind == "client":
        # The registration record goes with the client, rather than waiting
        # for the next sweep (#190): a client created again under the same
        # id would otherwise inherit it, and the credential handed to
        # whoever registered the first one would read and delete the
        # second, operator-created one.
        forget_registration(name)
    _audit("runtime_identity_deleted", kind, name)
    return jsonify({"deleted": name, "kind": kind})


def _promote(
    kind: str, name: str, file_name: str, promote: Callable[[Dict[str, Any]], PromotionOutcome]
) -> ResponseReturnValue:
    context = {
        "endpoint": request.path,
        "method": request.method,
        "ip_address": request.remote_addr or "unknown",
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }
    try:
        outcome = promote(context)
    except RuntimeObjectNotFound:
        return _error(404, f"no runtime {kind} {name!r}", "not_found")
    except PromotionInProgress:
        return _error(409, f"runtime {kind} {name!r} is being promoted", "promotion_in_progress")
    except DeclaredNameCollision:
        return _error(409, f"{kind} {name!r} is already declared in {file_name}", "declared")
    except ConflictError:
        return _error(
            409, f"{file_name} changed since it was read; nothing was written", "conflict"
        )
    except LockUnavailableError:
        return _error(503, f"{file_name} is locked by another write; try again", "lock_unavailable")
    except PostWriteError as exc:
        # Written, but the state after the write did not complete; the object
        # stays marked until a reload succeeds (#192).
        current_app.logger.error("Promotion of runtime %s %r: %s", kind, name, exc)
        return _error(
            500,
            f"{name!r} was written to {file_name}, but the configuration could not be "
            f"reloaded; a successful reload completes the promotion",
            "reload_failed",
        )
    except (ConfigurationRejected, HookError) as exc:
        # The entry is in the file; the configuration around it did not load.
        # The runtime object stays until a reload succeeds, which retires it
        # as promoted.
        return _error(
            500,
            f"{name!r} was written to {file_name}, but the configuration could not be "
            f"reloaded: {exc.message}",
            "reload_failed",
        )
    except Exception:
        # Anything else stopped the write itself (an unreadable or malformed
        # file on disk, an I/O error): nothing was written, the object stays.
        # The reason goes to the log, not to the caller.
        current_app.logger.exception("Promotion of runtime %s %r could not write %s", kind, name, file_name)
        return _error(500, f"{name!r} could not be written to {file_name}", "write_failed")
    body: Dict[str, Any] = {"promoted": name, "kind": kind, "file": file_name}
    if outcome.mirror_error is not None:
        body["mirror_hook_error"] = outcome.mirror_error
    return jsonify(body)

