"""``/register``: dynamic client registration, RFC 7591 and RFC 7592 (#190).

Open on purpose when ``oauth.dynamic_registration.enabled`` is on: a client
that was handed nothing but this server's URL registers itself, which is what
an MCP host does. The ``management_secret`` does not gate it, the flag does,
and the flag is a decision for settings.yaml rather than for the settings
form.

What a registration creates is an ordinary runtime client (#235): in process
memory, gone on restart, never in the declared configuration unless an
operator promotes it through ``/api/runtime``. So the resolver keeps being
the single answer to which clients exist, and this module only adds the
record that RFC 7592 manages one of them with - see
``services.dynamic_registration``.
"""

from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, current_app, jsonify, request
from flask.typing import ResponseReturnValue

from ..config import OAuthClient, get_config
from ..config_documents import EntryInvalid, parse_client_entry
from ..services.discovery import build_discovery_document
from ..services.dynamic_registration import (
    DynamicRegistration,
    RegistrationRejected,
    delete_client_and_registration,
    forget_registration,
    live_registration,
    new_client_id,
    new_client_secret,
    new_registration_token,
    prune_stale_registrations,
    record_registration,
    registration_response,
    registrations,
    token_matches,
    translate_registration_request,
)
from ..services.identities import (
    DeclaredNameCollision,
    IdentityResolver,
    PromotionInProgress,
    RuntimeObjectNotFound,
    identities_for,
)
from ..services.runtime_identities import RuntimeObjectExists
from ._audit import audit_event
from ._auth import no_store
from ._issuer import effective_issuer

registration_bp = Blueprint("registration", __name__)


def _supported_grant_types(settings: Any) -> Tuple[str, ...]:
    """The grants this server actually runs: the discovery document's own
    list, so what /register accepts and what the metadata advertises are
    the same sentence."""
    document: Dict[str, Any] = build_discovery_document(settings)
    return tuple(document["grant_types_supported"])

# RFC 7591 lists no error for "this server will not hold any more
# registrations": its codes are about the metadata. Rather than bend one of
# them into saying something it does not mean, the answer is a 429 with a
# name of nanoidp's own, documented as an extension.
REGISTRATION_LIMIT_REACHED = "registration_limit_reached"


@registration_bp.before_request
def _only_when_enabled() -> Optional[ResponseReturnValue]:
    """One gate for all three operations.

    A 404 rather than a 403: with the flag off the capability is not
    offered at all, and discovery does not advertise it. Turning the flag
    off later does not delete anything - clients registered while it was on
    keep working as OAuth clients, they just stop being manageable here.
    """
    if not get_config().settings.dynamic_registration_enabled:
        return jsonify({"error": "not_found"}), 404
    return None


def _error(status: int, error: str, description: str) -> ResponseReturnValue:
    return jsonify({"error": error, "error_description": description}), status


def _unauthorized() -> ResponseReturnValue:
    """RFC 7592: an unknown registration and a wrong credential answer alike.

    Telling them apart would let anyone walk the client ids.
    """
    response = jsonify(
        {"error": "invalid_token", "error_description": "invalid registration access token"}
    )
    response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return response, 401


def _presented_token() -> Optional[str]:
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _authenticated(
    client_id: str, identities: IdentityResolver
) -> Optional[Tuple[OAuthClient, DynamicRegistration, str]]:
    """The client, its record and the token the caller presented, or nothing."""
    token = _presented_token()
    if token is None:
        return None
    registration = live_registration(client_id, identities)
    if registration is None or not token_matches(token, registration):
        return None
    resolved = identities.resolve_client(client_id)
    if resolved is None:
        return None
    return resolved.client, registration, token


class _Refused(Exception):
    """A registration refused inside the lifecycle scope, to be answered and
    audited once outside it: an audit entry runs hooks, and the scope holds
    off every load and every other client operation (#403)."""

    def __init__(self, status: int, error: str, description: str, audited: bool = True) -> None:
        super().__init__(description)
        self.status = status
        self.error = error
        self.description = description
        self.audited = audited


def _authenticated_in_scope(
    client_id: str, identities: IdentityResolver
) -> Optional[Tuple[OAuthClient, DynamicRegistration, str]]:
    """``_authenticated``, as one operation with whatever the caller does
    next inside the same scope (#403): the record names its client, so a
    client recreated under the id between the check and the read or the
    delete would be managed with the first one's credential.

    Asked once without the scope first. This endpoint is open and the scope
    waits for loads and promotions, so a caller with no credential, or not
    this client's, is told so without waiting and can hold nothing up. That
    first answer is not authoritative, and a wrong one can only be a 401 for
    a registration that is ending; the one that counts is the second.
    """
    if _authenticated(client_id, identities) is None:
        return None
    with identities.runtime_client_lifecycle():
        return _authenticated(client_id, identities)


def _audit(event_type: str, status: str, client_id: str, **details: Any) -> None:
    """Never the registration token and never the client secret (#190)."""
    audit_event(
        event_type,
        status,
        endpoint=request.path,
        client_id=client_id or None,
        details=details,
    )


@registration_bp.route("/register", methods=["POST"])
def register() -> ResponseReturnValue:
    """RFC 7591 client registration."""
    settings = get_config().settings
    identities = identities_for(get_config())

    body = request.get_json(silent=True)
    try:
        entry, grant_types = translate_registration_request(
            body,
            supported_grant_types=_supported_grant_types(settings),
            supported_auth_methods=("client_secret_basic", "client_secret_post", "none"),
            vocabulary=settings.scopes_supported,
        )
    except RegistrationRejected as rejected:
        _audit("client_registration_refused", "failure", "", error=rejected.error)
        return _error(400, rejected.error, rejected.description)

    include_secret = entry["token_endpoint_auth_method"] != "none"

    # The sweep, the capacity check and the two creates are separate visits
    # to the store; under a threaded server they would interleave and let
    # more registrations through than the limit allows, and the limit is
    # the only bound an open endpoint has. The same scope keeps a delete or
    # a reset from landing between the client and its record, which would
    # answer 201 for a client that is gone and leave the record to the next
    # one of that id (#403).
    try:
        with identities.runtime_client_lifecycle():
            # Sweeping first means the limit counts registrations whose
            # client is still there, not the records of promoted or deleted
            # ones.
            prune_stale_registrations(identities)
            if len(registrations().list()) >= settings.dynamic_registration_max_clients:
                raise _Refused(
                    429,
                    REGISTRATION_LIMIT_REACHED,
                    "this server is holding as many dynamic registrations as it accepts",
                )

            client_id = new_client_id(identities)
            entry["client_id"] = client_id
            if include_secret:
                entry["client_secret"] = new_client_secret()

            try:
                client = parse_client_entry(entry, "POST /register")
            except EntryInvalid as invalid:
                # The metadata passed the translation but not the client model.
                raise _Refused(400, "invalid_client_metadata", invalid.message) from invalid

            try:
                created = identities.create_runtime_client(client)
            except (DeclaredNameCollision, RuntimeObjectExists) as lost:
                # new_client_id checked, so this is a client created by code
                # that does not enter the scope. Nothing is half-created: the
                # record comes after.
                current_app.logger.warning("Registration lost a race for %s", client_id)
                raise _Refused(
                    400, "invalid_client_metadata", "could not register, please retry", audited=False
                ) from lost

            token = new_registration_token()
            registration = record_registration(client_id, grant_types, token)
    except _Refused as refused:
        if refused.audited:
            _audit("client_registration_refused", "failure", "", error=refused.error)
        return _error(refused.status, refused.error, refused.description)
    _audit(
        "client_registered",
        "success",
        client_id,
        token_endpoint_auth_method=created.token_endpoint_auth_method,
        grant_types=grant_types,
    )
    body = registration_response(
        created, registration, token, effective_issuer(settings), include_secret
    )
    return no_store(jsonify(body)), 201


@registration_bp.route("/register/<client_id>", methods=["GET"])
def read_registration(client_id: str) -> ResponseReturnValue:
    """RFC 7592 read.

    The response carries the registration access token again. It is the one
    the caller has just presented, which is why nothing has to keep it.
    """
    identities = identities_for(get_config())
    authenticated = _authenticated_in_scope(client_id, identities)
    if authenticated is None:
        # Not audited: the audit is a bounded deque, and anyone can reach
        # this branch without a credential, so recording it would let a
        # short loop evict every real entry, this endpoint's own
        # client_registered records included.
        return _unauthorized()
    client, registration, token = authenticated
    body = registration_response(
        client,
        registration,
        token,
        effective_issuer(get_config().settings),
        include_secret=client.client_secret is not None,
    )
    return no_store(jsonify(body)), 200


@registration_bp.route("/register/<client_id>", methods=["DELETE"])
def delete_registration(client_id: str) -> ResponseReturnValue:
    """RFC 7592 delete: the client goes with the registration."""
    identities = identities_for(get_config())
    # The credential check, the client and the record are one operation
    # (#403): authenticated as one client, the delete must not land on
    # another that took the id in between.
    if _authenticated(client_id, identities) is None:
        # Before the scope and not authoritative, for the reason given in
        # _authenticated_in_scope: no credential, no waiting.
        return _unauthorized()
    with identities.runtime_client_lifecycle():
        if _authenticated(client_id, identities) is None:
            return _unauthorized()
        try:
            delete_client_and_registration(client_id, identities)
        except PromotionInProgress:
            # A promotion in progress holds the scope, so this is one that
            # wrote its entry and whose reload failed: the client is on its
            # way to being declared and stays until a load succeeds. The
            # same 409 /api/runtime answers, and like there nothing has
            # changed: the record goes after the client.
            return _error(
                409,
                "invalid_request",
                "this client is being promoted; its registration ends when the "
                "configuration next loads",
            )
        except RuntimeObjectNotFound:
            # Code that removes clients without entering the scope took it
            # between the check and the delete. Nothing to manage, and the
            # caller learns no more than it would about any other unknown
            # registration.
            forget_registration(client_id)
            return _unauthorized()
    _audit("client_registration_deleted", "success", client_id)
    return "", 204

