"""
OAuth2/OIDC routes for token endpoint and discovery.
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qsl, urlencode

import jwt as pyjwt
from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import ClientDisconnected, RequestEntityTooLarge

from ..branding import effective_logos_dir, resolve_client_logo
from ..config import ConfigManager, ConfigSnapshot, OAuthClient, Settings, User, get_config
from ..services import (
    DeviceVerifyOutcome,
    build_discovery_document,
    get_auth_code_store,
    get_crypto_service,
    get_device_code_store,
    get_revocation_store,
    get_token_service,
    identities_for,
)
from ..services.auth_code import CODE_LIFETIME_SECONDS
from ..services.authenticated_sessions import (
    AuthenticatedSession,
    AuthenticatedSessionStoreFull,
    get_authenticated_session_store,
)
from ..services.authorization_transactions import (
    AuthorizationParameters,
    AuthorizationTransaction,
    LookupOutcome,
    TransactionState,
    TransactionStoreFull,
    get_authorization_transaction_store,
)
from ..services.client_metadata import (
    ClientIdUrlInvalid,
    DocumentInvalid,
    DocumentNotUsable,
    learn_client,
    looks_like_client_id_url,
)
from ..services.client_metadata import retain_until as retain_cached_client_until
from ..services.client_metadata_fetch import FetchRefused
from ..services.device_code import (
    DeviceCodeStoreBusy,
    DeviceCodeStoreFull,
)
from ..services.discovery import issuer_qualifies_for_iss_parameter
from ..services.id_token_hint_references import (
    UNPARKED_REFERENCE,
    ParkedHintStoreFull,
    get_parked_hint_store,
    is_reference,
)
from ..services.introspection import build_introspection_response
from ..services.redirect_uri import (
    RESPONSE_MODES,
    append_authorization_fragment,
    append_authorization_params,
    is_http_redirect_uri,
    redirect_uri_is_registered,
    redirect_uri_rejection_reason,
)
from ..services.resource import resolve_resources
from ..services.scope import resolve_scope
from ..services.token import extra_refusal, forbidden_extra_claims
from ..services.userinfo import build_userinfo_response
from ..token_subject import end_user_of
from ._audit import audit_event
from ._auth import (
    PENDING_SECOND_FACTOR_FIELD,
    SECOND_FACTOR_STORE_FULL,
    TOTP_CODE_FIELD,
    AuthMethod,
    SecondFactorPhase,
    TwoStepPhase,
    authenticate_interactively,
    authorization_credentials,
    bearer_header_credential,
    begin_second_factor,
    browser_flow_binding,
    check_second_factor,
    continue_second_factor,
    discard_pending_second_factor,
    no_store,
    no_store_responses,
    own_origin_only,
    two_step_phase,
)
from ._config import request_config
from ._issuer import effective_issuer
from ._oauth_error import bearer_challenge, bearer_error, invalid_client_error, oauth_error
from .oauth_grants import _GRANT_HANDLERS, _GrantContext, _GrantOutcome

logger = logging.getLogger(__name__)

oauth_bp = Blueprint("oauth", __name__)


def _parse_claims_parameter(raw: Optional[str]) -> Optional[Dict[str, list]]:
    """Parse the OIDC ``claims`` request parameter (OIDC Core §5.5, #104).

    Returns a normalized ``{"id_token": [names], "userinfo": [names]}`` mapping
    (members present only when non-empty), or ``None`` when the parameter is
    absent or malformed. Malformed input is ignored with a warning rather than
    failing the request, so a bad ``claims`` value never breaks an otherwise
    valid authorization flow. Only the claim *names* are kept; the voluntary
    (``null``) form is honoured, and ``essential``/``value`` refinements are
    accepted but not yet acted on.
    """
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("Ignoring malformed 'claims' request parameter (invalid JSON)")
        return None
    if not isinstance(parsed, dict):
        logger.warning("Ignoring 'claims' request parameter: top-level value is not an object")
        return None

    result: Dict[str, list] = {}
    for member in ("id_token", "userinfo"):
        spec = parsed.get(member)
        if isinstance(spec, dict):
            names = [name for name in spec if isinstance(name, str)]
            if names:
                result[member] = names
    return result or None


# Decorators apply bottom-up, so the OIDC rule is registered first and stays
# the one url_for() builds for this endpoint: the alias is the second name,
# not the canonical one.
@oauth_bp.route("/.well-known/oauth-authorization-server")
@oauth_bp.route("/.well-known/openid-configuration")
def oidc_config() -> ResponseReturnValue:
    """OIDC Discovery, and the same document under the RFC 8414
    authorization server metadata name (#190).

    One handler on both paths rather than two documents: the two
    specifications describe the same server, nanoidp advertises one set of
    endpoints, and a client asking under either name must not be told two
    different things. A client that speaks only OAuth looks under the RFC
    8414 name - n8n does, before falling back to the OIDC one - so a 404
    there only sends it the long way round to the same answer.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    return jsonify(
        build_discovery_document(loaded.settings, issuer=effective_issuer(loaded.settings))
    )


@oauth_bp.route("/.well-known/jwks.json")
def jwks() -> ResponseReturnValue:
    """JWKS endpoint for JWT verification.

    Returns all keys including previous keys for rotation support.
    """
    crypto = get_crypto_service()
    return jsonify(crypto.get_jwks())


@dataclass
class _AuthorizeParams:
    """The /authorize request parameters the validators work on.

    A new request reads them from its GET query string; every later step
    reads them from its authorization transaction (#346), never from the
    request again. ``scope`` and ``resources`` start as the raw request
    values and are replaced by the granted values once validation has run,
    which is the form a transaction stores.
    """

    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    nonce: str
    claims_param: str
    resources: List[str]
    # OIDC Core 3.1.2.1 (#250): read from the CURRENT GET only (a form POST
    # carrying the request becomes that GET, #467) and never stored -
    # unlike the fields above, login_hint decides WHO gets authenticated
    # (#318 review round 1, blocking 1; #325 review round 1, point 6).
    # Ignored unless it carries the reserved 'persona-auto-login:' prefix -
    # see _try_persona_auto_login.
    login_hint: str
    # OAuth 2.0 Multiple Response Type Encoding Practices 2.1 (#472): how
    # the response is to be delivered, resolved before any response is
    # built - "query" (the default, also for an empty value), "fragment"
    # or "form_post". ``response_mode_rejected`` is the reason the request
    # names no usable channel (an unknown value, or the parameter
    # repeated), refused locally before anything else.
    response_mode: str = "query"
    response_mode_rejected: Optional[str] = None
    # OIDC Core 3.1.2.1 (#468): the authentication constraints, as sent;
    # read into prompts / max_age_seconds by the validator.
    prompt: str = ""
    max_age: str = ""
    id_token_hint: str = ""
    # Sent more than once (RFC 6749 3.1): refused, whatever the values.
    id_token_hint_repeated: bool = False
    # A reference that resolved to nothing (_take_parked_hint).
    id_token_hint_unresolved: bool = False
    prompts: FrozenSet[str] = frozenset()
    max_age_seconds: Optional[int] = None
    # The subject a verified id_token_hint names (#468), else None.
    hint_subject: Optional[str] = None
    # OIDC Core 6.1 / 6.2 (#463): the request-object parameter a new
    # request's query string carries with a non-empty value - "request"
    # (Core 6.1), else "request_uri" (Core 6.2), else None - read only to
    # be refused. Presence, never the value: the object and the URI are
    # not read, so nothing here can record or leak them. A transaction is
    # created only for a request that carries neither.
    unsupported_request_parameter: Optional[str] = None


_AUTHORIZE_REQUEST_FIELDS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "resource",
    # Request fields although they are always refused (#463): a request
    # that carries one is a request, so it is validated and refused, never
    # resumed, forged into a POST body unnoticed, or added to a named
    # transaction's query string unnoticed.
    "request",
    "request_uri",
    # Request fields too (#468, #472), whatever their value: alone in a
    # query they are a request with no client, not a resume of the pending
    # page, and added to a named transaction's query they are noticed.
    "prompt",
    "max_age",
    "id_token_hint",
    "response_mode",
)


# Every field _read_authorize_params reads (#467): the request fields and
# login_hint, which is read but is not what makes a request. A
# form-serialized request carries exactly these into its GET form, so a
# field the reader gains must be added here (pinned by a test).
_AUTHORIZE_READ_FIELDS = _AUTHORIZE_REQUEST_FIELDS + ("login_hint",)


def _resolve_response_mode(values: List[str]) -> Tuple[str, Optional[str]]:
    """The response mode a request asks for (#472), from every value the
    parameter was sent with, and why it cannot be honoured when it cannot:
    ("query", None) for an omitted or empty parameter; (mode, None) for one
    of the three; ("query", reason) for an unknown value or a repeated
    parameter. Resolved from the raw query before any response to the
    client is built."""
    if len(values) > 1:
        return "query", "response_mode repeated"
    value = values[0] if values else ""
    if not value:
        return "query", None
    if value not in RESPONSE_MODES:
        # A fixed reason: this refusal runs before any client lookup, and
        # the audit log is not a place for whatever a caller sends.
        return "query", "unknown response_mode"
    return value, None

# What a non-empty request-object value becomes in the GET form of a form
# POST (#467): the GET refuses any non-empty value (#463) and never reads
# it, so the object itself has no reason to reach a URL.
_REQUEST_OBJECT_PLACEHOLDER = "unsupported"

# The fields a login POST carries (#467): any of them present, even empty,
# makes a POST a login - the continuation of a transaction, named by
# ``transaction_id`` or resumed - and never an authorization request to
# redirect to its GET form. The login page's forms send them; a script that
# posts credentials after its GET sends them; a form-serialized
# authorization request (Core 3.1.2.1) sends none of them.
_AUTHORIZE_LOGIN_FIELDS = (
    "transaction_id",
    "username",
    "password",
    TOTP_CODE_FIELD,
    PENDING_SECOND_FACTOR_FIELD,
    "change_username",
)


def _requested_fields(source: MultiDict) -> Dict[str, List[str]]:
    """The OAuth request fields ``source`` carries, as sent: a request's
    query string, or the body of a POST asked whether it is a
    form-serialized request (#467). A transaction stores this and compares
    it with the query of a POST that names it, so an ID token hint is kept
    as its digest: equal for that comparison, and no token in a record the
    shared store may persist (#468).

    Presence, not truthiness, makes a field part of the request (#329
    review): ``client_id=`` is a request with an empty client_id, not no
    request. Unrelated parameters are not request fields (#328).
    """
    return {
        field: [
            hashlib.sha256(value.encode("utf-8")).hexdigest()
            if field == "id_token_hint"
            else value
            for value in source.getlist(field)
        ]
        for field in _AUTHORIZE_REQUEST_FIELDS
        if field in source
    }


def _read_authorize_params() -> _AuthorizeParams:
    """A new request, read in full from this request's query string - a
    GET's, or the direct POST's - with empty defaults for what it omits
    (#328). A form POST carrying the request never reaches a reader: it is
    redirected to its GET form first (#467), so the query string is the one
    place a request is read from."""
    params = request.args
    response_mode, response_mode_rejected = _resolve_response_mode(params.getlist("response_mode"))
    return _AuthorizeParams(
        response_type=params.get("response_type", ""),
        client_id=params.get("client_id", ""),
        redirect_uri=params.get("redirect_uri", ""),
        scope=params.get("scope", ""),
        state=params.get("state", ""),
        code_challenge=params.get("code_challenge", ""),
        code_challenge_method=params.get("code_challenge_method", ""),
        nonce=params.get("nonce", ""),
        claims_param=params.get("claims", ""),
        # RFC 8707 resource is repeatable (#187): read every value.
        resources=params.getlist("resource"),
        login_hint=params.get("login_hint", ""),
        prompt=params.get("prompt", ""),
        max_age=params.get("max_age", ""),
        id_token_hint=params.get("id_token_hint", ""),
        id_token_hint_repeated=len(params.getlist("id_token_hint")) > 1,
        response_mode=response_mode,
        response_mode_rejected=response_mode_rejected,
        # Presence of a non-empty value, over every repetition
        # (request=&request=<object>, #463 review round 3): what is refused
        # is that an object was sent at all, not any one value of it. A
        # parameter sent without a value is an omitted parameter (RFC 6749
        # 3.1), as for every other field here - while its PRESENCE still
        # makes the GET a new request rather than a resume
        # (_requested_fields, #329), so ?request= alone is a request with
        # no client_id, not the pending transaction's login page.
        unsupported_request_parameter=next(
            (field for field in ("request", "request_uri") if any(params.getlist(field))),
            None,
        ),
    )


def _params_of(transaction: AuthorizationTransaction, login_hint: str = "") -> _AuthorizeParams:
    """The validated parameters a transaction holds, for the helpers that
    take ``_AuthorizeParams``."""
    stored = transaction.params
    return _AuthorizeParams(
        response_type=stored.response_type,
        client_id=stored.client_id,
        redirect_uri=stored.redirect_uri,
        scope=stored.scope,
        state=stored.state,
        code_challenge=stored.code_challenge,
        code_challenge_method=stored.code_challenge_method,
        nonce=stored.nonce,
        claims_param=stored.claims,
        resources=list(stored.resources),
        login_hint=login_hint,
        response_mode=stored.response_mode,
    )


def _audit_body_oauth_fields() -> None:
    """Keep the audit visibility a login POST /authorize carrying OAuth
    fields in its body has had since #325 (review round 1, point 5).

    The login form never legitimately carries them, so any of them showing
    up beside a login field, a ``transaction_id`` or the direct entry
    point's query string is a forged request; they are never read. A POST
    whose body carries them and nothing of a login is not a login but an
    authorization request, redirected to its GET form (#467) before this.
    """
    # Any non-empty value over every repetition, as the query reader does
    # for the two refused fields (#463): an empty first value hides nothing.
    forged = [field for field in _AUTHORIZE_REQUEST_FIELDS if any(request.form.getlist(field))]
    if not forged:
        return
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        client_id=request.form.get("client_id") or None,
        details={"reason": "OAuth parameters in POST body are ignored", "fields": forged},
    )


def _is_form_serialized_request(requested: Dict[str, List[str]], form: MultiDict) -> bool:
    """Whether a POST is an authorization request serialized as a form
    (OIDC Core 3.1.2.1, #467): its query string carries no request field
    (``requested``: those make it the direct entry point), its body
    carries no login field - present, even empty, a login field makes the
    POST a login, which never reads OAuth parameters from its body (#325)
    - and its body carries a request field. A login POST with no query
    string resumes or names a transaction.
    """
    if requested or any(field in form for field in _AUTHORIZE_LOGIN_FIELDS):
        return False
    return bool(_requested_fields(form))


def _redirect_form_request_to_get(config: ConfigManager, form: MultiDict) -> ResponseReturnValue:
    """Answer a form-serialized authorization request with a 303 to the
    same request in GET form (#467): the fields the GET reads, from the
    body only, as sent - empty and repeated values included, a repeated
    field's values in their order. The body is the request: the POST's own
    query string carries no request field (the classification above), and
    a ``login_hint`` in it is not the request's. Nothing else in the body
    reaches the URL: an unexpected field is not read by the GET anyway, and
    a non-empty ``request`` or ``request_uri`` value becomes a placeholder,
    so the GET refuses the request as it refuses any such (#463) without
    the object entering a URL, a log or a history.

    Served in place, a cross-site form POST would arrive without the
    session cookie - ``SameSite=Lax``, sent on a top-level GET navigation
    and not on a cross-site POST - and its login page would replace the
    browser's session, with the transactions, second factor and web UI
    login bound to it. The redirect is followed as a top-level GET, which
    carries the cookie, and the GET is the one reader of a request.
    """
    # One hint, or none (RFC 6749 3.1: a parameter is not repeated): a
    # repeated id_token_hint parks nothing, and is refused here, locally,
    # before any reference is written, as the GET refuses it.
    if len(form.getlist("id_token_hint")) > 1:
        return _authorize_reject(
            form.get("client_id") or None,
            "id_token_hint repeated",
            "invalid_request",
            "id_token_hint must not be repeated",
        )
    # A hint is parked only for a client this server already knows
    # (declared, runtime, or a cached metadata document): the parked store
    # is bounded, and a sender who names no real client fills nothing. For
    # a client it would first have to fetch, the hint becomes a reference
    # that resolves to nothing and the GET refuses the request
    # (invalid_request), rather than serving it without the hint.
    known_client = any(form.getlist("id_token_hint")) and bool(
        form.get("client_id")
        and identities_for(config, request_config()).get_client(form.get("client_id", ""))
    )
    try:
        carried = [
            (field, _carried_value(field, value, known_client))
            for field in _AUTHORIZE_READ_FIELDS
            for value in form.getlist(field)
        ]
    except ParkedHintStoreFull:
        # Nothing of the request was validated yet, so this stays local,
        # like a refusal before the redirect_uri; retryable, hence 503.
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            client_id=form.get("client_id") or None,
            details={"reason": "too many id_token_hint references parked"},
        )
        return (
            jsonify(
                {
                    "error": "temporarily_unavailable",
                    "error_description": "The authorization request could not be accepted, please try again",
                }
            ),
            503,
        )
    return redirect(f"{url_for('oauth.authorize')}?{urlencode(carried)}", code=303)


def _carried_value(field: str, value: str, known_client: bool) -> str:
    """What a body field's value becomes in the GET form (#467, #468): a
    request object a placeholder, an ID token hint a parked reference
    (or one that resolves to nothing, for a client not known), anything
    else itself."""
    if value and field in ("request", "request_uri"):
        return _REQUEST_OBJECT_PLACEHOLDER
    if value and field == "id_token_hint":
        return get_parked_hint_store().park(value) if known_client else UNPARKED_REFERENCE
    return value


def _refuse_without_transaction(
    reason: str, description: str, client_id: Optional[str] = None
) -> ResponseReturnValue:
    """A request that names no usable authorization transaction (#346).

    Local, never a redirect: a request refused here is not continuing a
    transaction, so there is no validated redirect_uri to deliver an error
    to. ``client_id`` is the transaction's, when there is one to name.
    """
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        client_id=client_id,
        details={"reason": reason},
    )
    return jsonify({"error": "invalid_request", "error_description": description}), 400


@dataclass(frozen=True)
class _Rejection:
    """What a side-effect-free verdict helper answers when it refuses: the
    OAuth error, its description, and a fixed reason naming the check.
    ``audited`` is False for the checks that have never written an audit
    event (the two required parameters, redirect_uri syntax); their reason
    is then only the label the request-object refusal records for what
    kept it local (#463)."""

    error: str
    description: str
    reason: str
    audited: bool = True


def _reject_locally(client_id: Optional[str], rejection: _Rejection) -> ResponseReturnValue:
    """A verdict's rejection, answered as the validators always have: a
    local 400, audited when that check audits."""
    return _authorize_reject(
        client_id,
        rejection.reason,
        rejection.error,
        rejection.description,
        audit=rejection.audited,
    )


def _failed_details(reason: str, details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The details of a failed authorization_request event: the caller's
    extras under the reason, which nothing can overwrite. One home for the
    local and the delivered refusal."""
    return {**(details or {}), "reason": reason}


def _authorize_reject(
    client_id: Optional[str],
    reason: str,
    error: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
    *,
    audit: bool = True,
) -> ResponseReturnValue:
    """Audit-then-reject, the shape every post-client-lookup check shares;
    the one builder of the local 400.

    The pre-lookup checks (response_type, missing client_id/redirect_uri,
    redirect_uri syntax) intentionally do NOT audit - they never have - and
    come through here with ``audit=False``. The pre-lookup callers that
    audit are the request-object refusal (#463) and the response_mode
    refusal (#472), because each is the request's whole answer;
    ``client_id`` is None when the request named none. ``details`` extends the event beyond its reason.
    """
    if audit:
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            client_id=client_id,
            details=_failed_details(reason, details),
        )
    return jsonify({"error": error, "error_description": description}), 400


def _authorize_error_redirect(
    config: ConfigManager,
    p: _AuthorizeParams,
    error: str,
    description: str,
    reason: str,
    *,
    username: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> ResponseReturnValue:
    """Deliver an authorization error to the client through the ALREADY
    VALIDATED redirect_uri (RFC 6749 §4.1.2.1), carrying iss so the client
    can still detect an authorization-server mix-up on an error (#189/RFC
    9207 §2: iss appears on error responses too). Reachable after
    _validate_authorize_redirect_uri has run, or after _undeliverable_because
    read the same rule (_redirect_uri_verdict) without side effects (#463),
    so this never redirects to an unvalidated URI - errors before that stay
    local (see _authorize_reject).

    ``username`` (#318 review round 1) is the attempted username, when one
    exists - e.g. an unknown persona in an auto-login hint - so a consumer
    filtering failed ``authorization_request`` events by ``username`` sees
    it structured, not only inside ``reason``'s free text. ``None`` for
    every other caller, exactly as before. ``details`` extends the event
    beyond its reason.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        client_id=p.client_id,
        username=username,
        details=_failed_details(reason, details),
    )
    params = {"error": error, "error_description": description}
    if p.state:
        params["state"] = p.state
    issuer = effective_issuer(loaded.settings)
    if issuer_qualifies_for_iss_parameter(issuer):
        params["iss"] = issuer
    return _deliver_authorization_response(p, params)


def _deliver_authorization_response(p: _AuthorizeParams, params: Dict[str, str]) -> ResponseReturnValue:
    """An authorization response - a code, or an error after the
    redirect_uri - delivered the way the request asked (#472): in the query
    (the default), in the fragment, or as a page whose form posts the
    parameters to the redirect_uri and submits itself (OAuth 2.0 Form Post
    Response Mode), with no-store, since it carries the code. The one place
    a response reaches the client; ``p.redirect_uri`` is validated by now,
    and ``form_post`` only ever posts to an HTTP(S) one
    (``_redirect_uri_verdict``). The page holds the code in its body, so
    other origins' scripts are kept from it (``own_origin_only``)."""
    if p.response_mode == "fragment":
        return redirect(append_authorization_fragment(p.redirect_uri, params))
    if p.response_mode == "form_post":
        return own_origin_only(
            no_store(render_template("form_post.html", action=p.redirect_uri, params=params))
        )
    return redirect(append_authorization_params(p.redirect_uri, params))



def _validate_authorize_client(
    config: ConfigManager, p: _AuthorizeParams
) -> Tuple[Optional[OAuthClient], Optional[ResponseReturnValue]]:
    """Required-parameter checks and client lookup: (client, None) or (None, error).

    response_type is NOT checked here: it is validated after the redirect_uri
    is trusted (#258 review), so an unsupported_response_type on a valid
    redirect_uri is delivered as an error redirect, not a local JSON."""
    client, rejection = _client_verdict(config, request_config(), p)
    if rejection is not None:
        return None, _reject_locally(p.client_id, rejection)
    return client, None


def _client_verdict(
    config: ConfigManager, loaded: ConfigSnapshot, p: _AuthorizeParams
) -> Tuple[Optional[OAuthClient], Optional[_Rejection]]:
    """The required-parameter checks and the client lookup: ``(client,
    None)`` or ``(None, rejection)``. The one home of "which client does
    this request name", read by the validator above and by the
    request-object refusal (#463) to decide whether an error may be
    delivered, so the two cannot name different clients. The lookup is the
    ordinary one, the metadata-document fetch included (#196): a refusal
    that looked only at the cache answered 302 or 400 by whether the
    document was cached, which told whoever chose the URL that the client
    had been here lately, a fact the ordinary path never discloses."""
    if not p.client_id:
        return None, _Rejection(
            "invalid_request", "client_id is required", "client_id is required", audited=False
        )
    if not p.redirect_uri:
        return None, _Rejection(
            "invalid_request",
            "redirect_uri is required",
            "redirect_uri is required",
            audited=False,
        )
    client = identities_for(config, loaded).get_client(p.client_id)
    if client is None:
        client = _client_from_metadata_document(config, p.client_id)
    if client is None:
        return None, _Rejection("invalid_client", "Unknown client_id", "Unknown client")
    return client, None


def _client_from_metadata_document(
    config: ConfigManager, client_id: str
) -> Optional[OAuthClient]:
    """Learn a client from the document it publishes (#196).

    **The only place nanoidp fetches one.** Reached only when no declared
    and no runtime client holds this name, so an operator who declares a
    client whose id is a URL never causes an outbound request, and only
    after the feature is enabled.

    Every failure answers the same "Unknown client_id" the caller already
    returns for a name nobody knows. Telling a caller which rule refused it
    would say whether a host is in ``allowed_hosts``, whether it resolved,
    what it answered - to whoever chose the URL.

    The reason goes to the server log only. ``GET /api/audit`` is readable
    by anyone who can reach it, so an audit entry carrying the reason would
    hand back through one surface exactly what the other withholds; the
    entry records that a document was refused, and the operator reads why
    where only the operator is.
    """
    # The configuration this request began with (#406), except for the
    # switch: whether the capability is offered at all is the server's, not
    # the request's, and the resolver reads it live for the same reason. A
    # request that began while it was on must not reach the one outbound
    # fetch this server makes after it was turned off.
    loaded = request_config()
    settings = loaded.settings
    if not config.settings.client_id_metadata_documents_enabled:
        return None
    if not looks_like_client_id_url(client_id):
        return None
    try:
        return learn_client(client_id, settings)
    except (
        ClientIdUrlInvalid,
        DocumentInvalid,
        DocumentNotUsable,
        FetchRefused,
    ) as refused:
        logger.info("Client ID metadata document refused for %s: %s", client_id, refused)
        audit_event(
            "client_metadata_document_refused",
            "failure",
            endpoint="/authorize",
            client_id=client_id,
        )
        return None


def _refuse_unsupported_request_parameter(
    config: ConfigManager, p: _AuthorizeParams, field: str
) -> ResponseReturnValue:
    """Request objects are not implemented, so a request that carries one is
    refused with the one error that explains why nothing in the object was
    read, whatever else the request says or lacks (#463): the object may
    hold the very parameter the query omits (Core 6.1 lets everything but
    response_type and client_id travel inside it), so no other error is
    the right answer. Discovery publishes both ``*_parameter_supported``
    flags as false, and this is the behaviour those flags describe.

    Delivered where every error goes once the redirect_uri is validated
    (to it, with state and iss), and locally otherwise - never to a URI
    the redirect_uri rule would refuse for this client (a client without
    registered URIs keeps #67's permissive dev behaviour here as
    everywhere; oauth21 requires registration). The request is refused
    before any validator runs, so it writes one authorization_request
    event, this refusal's (the client lookup may write its own
    client_metadata_document_refused, as for any request, #196);
    whether it may be delivered is read off the same two rules the
    validators apply, _client_verdict and _redirect_uri_verdict, which
    write no audit event of their own (the client lookup may fetch a
    metadata document and audit its refusal, as for any request). What
    kept a refusal local is
    recorded in the audit event (``delivered``, ``undeliverable``: the
    fixed reason of the rule that kept it), since the validators that
    used to say it no longer run for this request. The object and the URI
    themselves are never recorded."""
    error = f"{field}_not_supported"
    description = f"The {field} parameter is not supported"
    reason = f"{field} parameter is not supported"
    undeliverable = _undeliverable_because(config, p)
    if undeliverable is None:
        return _authorize_error_redirect(
            config, p, error, description, reason, details={"delivered": True}
        )
    return _authorize_reject(
        p.client_id or None,
        reason,
        error,
        description,
        details={"delivered": False, "undeliverable": undeliverable},
    )


def _undeliverable_because(config: ConfigManager, p: _AuthorizeParams) -> Optional[str]:
    """None when an error for this request may go to its redirect_uri, else
    the fixed reason it may not: see _refuse_unsupported_request_parameter."""
    loaded = request_config()
    client, rejection = _client_verdict(config, loaded, p)
    if rejection is not None:
        return rejection.reason
    assert client is not None
    rejection = _redirect_uri_verdict(loaded.settings, p, client)
    return rejection.reason if rejection is not None else None


def _validate_authorize_response_type(
    config: ConfigManager, p: _AuthorizeParams
) -> Optional[ResponseReturnValue]:
    """Only the authorization code flow is supported (#41). Checked after the
    redirect_uri is validated so an unsupported_response_type is delivered as
    an error redirect carrying iss (RFC 6749 §4.1.2.1, RFC 9207, #258
    review), not a local JSON - the implicit flow is intentionally absent."""
    if p.response_type != "code":
        return _authorize_error_redirect(
            config,
            p,
            "unsupported_response_type",
            "Only 'code' response_type is supported",
            f"unsupported response_type {p.response_type!r}",
        )
    return None


def _validate_authorize_scope(
    config: ConfigManager, p: _AuthorizeParams, client: OAuthClient
) -> Optional[ResponseReturnValue]:
    """Scope validation (issue #186): a requested scope outside the global
    vocabulary, or outside this client's own allowed_scopes when set, is
    invalid_scope (RFC 6749 §4.1.2.1). An omitted scope defaults to the
    client's full allowed set when restricted, or "openid" as before (#186).
    Checked before redirect_uri so an invalid_scope on an unregistered client
    reports the more specific problem first. Mutates p.scope to the granted
    value on success."""
    # The configuration this request began with (#406).
    loaded = request_config()
    scope_result = resolve_scope(
        p.scope,
        client,
        loaded.settings.scopes_supported,
        loaded.settings.scope_enforcement_active,
        default_when_omitted="openid",
    )
    if not scope_result.ok:
        return _authorize_error_redirect(
            config,
            p,
            "invalid_scope",
            scope_result.error_description or "invalid scope",
            scope_result.error_description or "invalid scope",
        )
    p.scope = scope_result.granted or ""
    return None


def _validate_authorize_redirect_uri(
    config: ConfigManager, p: _AuthorizeParams, client: OAuthClient
) -> Optional[ResponseReturnValue]:
    """The three redirect_uri checks, in their historical order.

    Syntactic validation (RFC 6749 §3.1.2): an absolute URI with no
    fragment. A scheme is required; an authority is not, so native-app
    private-use scheme URIs like com.example.app:/oauth2redirect (RFC 8252
    §7.1) pass (#81), while a private-use scheme without a period (myapp://)
    is rejected per §7.1's minimum rule. See services/redirect_uri.py.

    Matching against registered redirect URIs (issue #67). RFC 6749
    §3.1.2.3 / OAuth 2.1 §4.1.1 require simple string comparison - no
    prefix, host or path normalization - with the single exception RFC
    8252 §7.3 mandates for native apps: a registered loopback URI
    (http://127.0.0.1:{port}/..., http://[::1]:{port}/...) matches any
    port (#81). Clients without registered URIs keep the permissive dev
    behavior (hardening is opt-in, principle 3). A mismatch MUST NOT
    redirect (§3.1.2.4): the error is returned directly, never sent to
    the unvalidated URI.

    Under the oauth21 profile, registration is not optional: a client used
    at /authorize must have redirect_uris pinned (#68; OAuth 2.1 §2.3
    requires the AS to compare against registered values, which presumes
    they exist). Enforced here, not at config load, so other grants keep
    working for unregistered clients.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    rejection = _redirect_uri_verdict(loaded.settings, p, client)
    if rejection is None:
        return None
    return _reject_locally(p.client_id, rejection)


def _redirect_uri_verdict(
    settings: Settings, p: _AuthorizeParams, client: OAuthClient
) -> Optional[_Rejection]:
    """The redirect_uri rule, with no side effect: None when the request's
    redirect_uri is usable for this client, else the rejection. The one
    home of the rule, read by the validator above and by the request-object
    refusal (#463) to decide whether an error may be delivered to the
    URI."""
    syntax = redirect_uri_rejection_reason(p.redirect_uri)
    if syntax is not None:
        return _Rejection("invalid_request", syntax, "redirect_uri invalid", audited=False)
    if client.redirect_uris and not redirect_uri_is_registered(
        p.redirect_uri, client.redirect_uris
    ):
        return _Rejection(
            "invalid_request",
            "redirect_uri is not registered for this client",
            "redirect_uri not registered for client",
        )
    if settings.security_profile == "oauth21" and not client.redirect_uris:
        return _Rejection(
            "invalid_request",
            "the oauth21 profile requires this client to have registered redirect_uris",
            "oauth21 profile requires registered redirect_uris",
        )
    # A browser form posts to HTTP(S) only (#472): a native client's
    # private-scheme URI is no channel for form_post, and stays one for the
    # redirect modes.
    if p.response_mode == "form_post" and not is_http_redirect_uri(p.redirect_uri):
        return _Rejection(
            "invalid_request",
            "response_mode form_post requires an http or https redirect_uri",
            "form_post response_mode needs an http(s) redirect_uri",
        )
    return None


def _validate_authorize_pkce(
    config: ConfigManager, p: _AuthorizeParams, client: Optional[OAuthClient] = None
) -> Optional[ResponseReturnValue]:
    """PKCE enforcement (issues #47, #68). Via the require_pkce setting (on by
    default in the stricter-dev profile) or implied by the oauth21 profile
    (OAuth 2.1 §4.1.1 makes PKCE mandatory), an authorization request
    without a code_challenge is rejected, so developers can verify their
    client actually sends PKCE.

    A public client (token_endpoint_auth_method 'none', #188) is held to
    PKCE with S256 REGARDLESS of profile or require_pkce (OAuth 2.1
    §7.5.1, RFC 7636): with no client authentication at the token
    endpoint, the verifier is the only thing binding the code to the
    party that started the flow."""
    # The configuration this request began with (#406).
    loaded = request_config()
    if client is not None and client.is_public:
        if not p.code_challenge:
            return _authorize_error_redirect(
                config,
                p,
                "invalid_request",
                "This client's token_endpoint_auth_method is 'none': PKCE "
                "with code_challenge_method S256 is required",
                "Public client without PKCE",
            )
        if (p.code_challenge_method or "plain") != "S256":
            return _authorize_error_redirect(
                config,
                p,
                "invalid_request",
                "This client's token_endpoint_auth_method is 'none': "
                "code_challenge_method must be S256",
                "Public client with non-S256 PKCE",
            )

    if loaded.settings.pkce_required and not p.code_challenge:
        return _authorize_error_redirect(
            config,
            p,
            "invalid_request",
            "PKCE code_challenge is required " "(require_pkce setting or oauth21 profile)",
            "PKCE code_challenge required (require_pkce or oauth21)",
        )

    if not p.code_challenge:
        return None

    # RFC 7636 §4.3: an omitted code_challenge_method defaults to 'plain',
    # and the verifier honors that - so the method must be normalized
    # BEFORE validation or the stricter-dev rejection could be bypassed by
    # simply omitting the parameter (#56). Unsupported methods are
    # rejected at the authorization endpoint per §4.4.1.
    effective_method = p.code_challenge_method or "plain"
    if effective_method not in ("plain", "S256"):
        return _authorize_error_redirect(
            config,
            p,
            "invalid_request",
            f"Unsupported code_challenge_method " f"'{effective_method}'; use S256 or plain",
            f"Unsupported code_challenge_method: {effective_method}",
        )

    # The 'plain' method is only acceptable when S256 is unavailable
    # (RFC 7636 §4.2); the stricter-dev (#47) and oauth21 (#68, OAuth 2.1
    # §7.5.2) profiles reject it outright, whether requested explicitly
    # or via the implicit default.
    if effective_method == "plain" and not loaded.settings.pkce_plain_allowed:
        return _authorize_error_redirect(
            config,
            p,
            "invalid_request",
            "code_challenge_method 'plain' (including the "
            "implicit default when the parameter is omitted) "
            f"is not allowed by the {loaded.settings.security_profile} "
            "profile; use S256",
            "PKCE method 'plain' rejected by " f"{loaded.settings.security_profile} profile",
        )
    return None


def _validate_authorize_resources(
    config: ConfigManager, p: _AuthorizeParams, client: OAuthClient
) -> Optional[ResponseReturnValue]:
    """Validate the RFC 8707 ``resource`` indicators on /authorize (#187).

    Each must be a syntactically valid indicator and, when the client
    declares a non-empty ``allowed_resources``, one of that set; otherwise
    the request is rejected with ``invalid_target`` (RFC 8707 section 2). The
    validated resources travel with the authorization code, so /token binds
    the access token aud to them."""
    if not p.resources:
        return None
    result = resolve_resources(p.resources, client)
    if not result.ok:
        return _authorize_error_redirect(
            config, p, "invalid_target",
            result.error_description or "invalid resource",
            result.error_description or "invalid_target",
        )
    # Persist the de-duplicated granted list, not the raw request (#254
    # review, finding 3): the authorization code must not carry a repeated
    # resource that would become a duplicate entry in the token aud, the
    # same normalization the device flow already does.
    p.resources = result.granted or []
    return None


def _may_hold_a_refresh_token(
    config: ConfigManager, loaded: ConfigSnapshot, client_id: Optional[str]
) -> bool:
    """Whether a token for this client may carry a refresh token (#196).

    A client learned from a metadata document exists only in the cache, and
    the cache promises to keep an entry exactly as long as the
    authorization code issued against it. A refresh token lives days. One
    handed to such a client would be a credential this server can make
    useless long before its expiry, by expiring or evicting the entry -
    the same defect the code retention exists to prevent, one step further
    along, and this time with nothing to hold on to: there is no bound on
    how long the cache would have to keep a document it is no longer
    allowed to re-read on its own terms.

    So the rule for now is the simple one: what a cached client can carry
    is bounded by the authorization code lifetime, and nothing longer is
    issued. RFC 6749 §5.1 makes the refresh token optional, so a response
    without one is a complete response.

    Supporting refresh for these clients means something larger: a grant
    would take a lease on the client identity until its own expiry, and
    the cache's capacity and freshness rules would have to answer for days
    rather than minutes. That is a design, not a patch, and it is not this
    one.

    A client that does not resolve at all answers ``False``, not ``True``:
    this is decided after the grant handler has run, so an entry can go
    between the authorization code being consumed and this question being
    asked. Handing a long-lived refresh token to a client that has just
    disappeared is exactly the outcome the rule exists to prevent, and the
    conservative answer costs a caller who is still there nothing but a
    second login.
    """
    if client_id is None:
        # A token with no client at all cannot carry a refresh token in the
        # first place; create_token refuses that pairing. Left to the
        # existing rule rather than answered twice.
        return True
    resolved = identities_for(config, loaded).resolve_client(client_id)
    return resolved is not None and resolved.origin != "cimd"


def _hold_cached_client_for_the_code(
    config: ConfigManager, p: _AuthorizeParams
) -> bool:
    """Make the client survive the code before the code exists (#196).

    A client learned from a metadata document lives only in the cache, so
    an authorization code naming one is redeemable exactly as long as that
    entry is there. Holding it afterwards leaves a gap: the entry can be
    evicted or expire between the login being accepted and the code being
    minted, and the code would then be handed over already dead.

    So the order is: resolve again, hold, then mint. The resolution is
    local - the cache is read, never filled, and a declared or runtime
    client is answered without the cache being consulted at all - so this
    costs no network and cannot fetch.

    ``False`` means do not issue: either the client is no longer resolvable
    at all, or the cache has no room to promise anything about it.
    """
    resolved = identities_for(config, request_config()).resolve_client(p.client_id)
    if resolved is None:
        return False
    if resolved.origin != "cimd":
        # Declared and runtime clients do not depend on the cache, and a
        # code for one is not this function's business.
        return True
    return retain_cached_client_until(p.client_id, time.time() + CODE_LIFETIME_SECONDS)


def _record_authenticated_session(
    loaded: ConfigSnapshot,
    username: str,
    method: AuthMethod,
    auth_time: int,
    reused: Optional[AuthenticatedSession],
) -> str:
    """Keep the browser's authenticated session up to date for the code
    being issued (#468), and say what happened, for the audit: "reused",
    "established", "disabled" (``login.session_minutes`` is 0) or
    "not kept, store full"."""
    if reused is not None:
        return "reused"
    lifetime = loaded.settings.authenticated_session_seconds
    if lifetime <= 0:
        return "disabled"
    binding = browser_flow_binding(create=True)
    if not binding:
        # Never with create=True; and a session keyed by nothing would be
        # every cookieless browser's, so none is kept.
        return "not kept, no browser binding"
    try:
        get_authenticated_session_store().establish(
            browser_binding=binding,
            username=username,
            method=method.value,
            auth_time=auth_time,
            lifetime_seconds=lifetime,
        )
    except AuthenticatedSessionStoreFull:
        return "not kept, store full"
    return "established"


def _usable_session(
    config: ConfigManager, loaded: ConfigSnapshot
) -> Optional[Tuple[AuthenticatedSession, User]]:
    """This browser's live authenticated session (#468) with its user
    resolved again, or None.

    A session is only as good as the login it records is today: the user
    must still exist; a persona selection counts only while persona mode
    is on; a password login counts only while a password is what the
    login mode asks for, and not once a TOTP code has become required of
    that user (``login.totp`` turned on, or the user given a secret) that
    the session never checked. A password-and-code login counts under
    password mode whatever the TOTP setting now says.
    """
    settings = loaded.settings
    if settings.authenticated_session_seconds <= 0:
        # 0 disables reuse as well as keeping: a session established under
        # an earlier setting is not consulted.
        return None
    record = get_authenticated_session_store().live(browser_flow_binding())
    if record is None or record.age() > settings.authenticated_session_seconds:
        # The setting in force now bounds a session too: lowering it
        # shortens the sessions already established, as the reference says.
        return None
    user = identities_for(config, loaded).get_user(record.username)
    if user is None:
        return None
    persona = settings.persona_mode_enabled
    if record.method == AuthMethod.PERSONA.value:
        usable = persona
    elif record.method == AuthMethod.PASSWORD.value:
        usable = not persona and not (settings.totp_active and bool(user.totp_secret))
    elif record.method == AuthMethod.PASSWORD_OTP.value:
        usable = not persona
    else:
        usable = False
    return (record, user) if usable else None


def _session_amr(loaded: ConfigSnapshot, method: AuthMethod) -> Optional[Sequence[str]]:
    """The amr a reused session's code carries: the method's, gated on
    ``login.totp`` being active exactly as a fresh login's is
    (``authenticate_interactively``)."""
    return method.amr if loaded.settings.totp_active else None


def _issue_authorization_code(
    config: ConfigManager,
    p: _AuthorizeParams,
    username: str,
    *,
    transaction: Optional[AuthorizationTransaction] = None,
    verified_username: Optional[str] = None,
    auto_login: bool = False,
    method: AuthMethod,
    amr: Optional[Sequence[str]] = None,
    reused: Optional[AuthenticatedSession] = None,
) -> ResponseReturnValue:
    """Consume the transaction, mint the code, audit success and redirect to
    the client - shared by a normal inline login (``_handle_authorize_login``),
    the TOTP step (``_complete_second_factor``), #250's persona auto-login
    (``_try_persona_auto_login``) and the reuse of an authenticated session
    (#468), which are otherwise indistinguishable on the wire once a user
    is known. ``auto_login`` only affects the audit record and log line.
    ``method`` is how the user authenticated; ``amr`` (#348) is the OIDC amr
    for that login - ``None`` for a persona/auto-login, since no password
    was checked.

    ``reused`` is the authenticated session this code rests on (#468): its
    ``auth_time`` is the code's, and no new session is recorded. Otherwise
    the user authenticated now: ``auth_time`` is now, and the browser's
    session is established (replacing any it had) for
    ``login.session_minutes``, unless that is 0, or every slot is held by
    another browser, in which case the login completes without one and the
    audit says so.

    ``transaction`` is ``None`` only for an auto-login answered on the GET
    that carried the request, which never had a transaction. Otherwise it is
    consumed first: a transaction yields at most one code, and of two
    concurrent completions only the one that consumed it goes on.
    ``verified_username`` is passed on to the store for a completion resting
    on a password verified on an earlier request (see ``consume``).
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    if transaction is not None and (
        get_authorization_transaction_store().consume(
            transaction.id, browser_flow_binding(), verified_username=verified_username
        )
        is None
    ):
        return _refuse_without_transaction(
            "authorization transaction already completed or expired",
            "The authorization request is no longer pending",
            client_id=p.client_id,
        )

    # The subject a verified id_token_hint named is the only one this
    # request may be answered for (#468, Core 3.1.2.2): another user's
    # login, interactive or auto-login, is login_required to the client.
    # Decided after the transaction is consumed, so it yields nothing else.
    bound = transaction.bound_subject if transaction is not None else p.hint_subject
    if bound is not None and bound != username:
        return _authorize_error_redirect(
            config,
            p,
            "login_required",
            "The user who authenticated is not the one id_token_hint names",
            "login by another subject than id_token_hint names",
            username=username,
        )

    # Before the code exists, not after: a code whose client has gone is
    # one the client cannot redeem and cannot explain (#196). This is also
    # the continuity check of a transaction (#346): the client must still
    # resolve, whatever else about it changed since the GET.
    if not _hold_cached_client_for_the_code(config, p):
        return _authorize_error_redirect(
            config,
            p,
            "temporarily_unavailable",
            "The authorization request could not be completed, please try again",
            "the client no longer resolves, or its cached metadata document could not be held for the code",
            username=username,
        )

    # One instant for the code's creation, the session and the ID token:
    # a fresh login's auth_time is the code's created_at, so the two never
    # disagree at a second's boundary.
    created_at = datetime.now(timezone.utc)
    auth_time = reused.auth_time if reused is not None else int(created_at.timestamp())
    session_outcome = _record_authenticated_session(loaded, username, method, auth_time, reused)

    auth_code_store = get_auth_code_store()
    code = auth_code_store.create_code(
        client_id=p.client_id,
        redirect_uri=p.redirect_uri,
        username=username,
        scope=p.scope,
        code_challenge=p.code_challenge if p.code_challenge else None,
        code_challenge_method=p.code_challenge_method if p.code_challenge_method else None,
        nonce=p.nonce if p.nonce else None,
        state=p.state if p.state else None,
        claims=_parse_claims_parameter(p.claims_param),
        resource=list(p.resources) if p.resources else None,
        amr=amr,
        auth_time=auth_time,
        created_at=created_at,
    )

    # Build redirect URL with code
    redirect_params = {"code": code}
    if p.state:
        redirect_params["state"] = p.state
    # RFC 9207 (#189): return the effective issuer so the client can
    # detect an authorization-server mix-up. Sent exactly when it is
    # advertised as supported in discovery (#258 review): a single
    # predicate drives both, so a client never sees iss without the
    # metadata promising it, or vice versa. The value is the per-request
    # effective issuer, so it stays correct under issuer_from_request
    # (#126).
    issuer = effective_issuer(loaded.settings)
    if issuer_qualifies_for_iss_parameter(issuer):
        redirect_params["iss"] = issuer

    audit_event(
        "authorization_request",
        "success",
        endpoint="/authorize",
        username=username,
        client_id=p.client_id,
        details={
            "scope": p.scope,
            "pkce": bool(p.code_challenge),
            # Distinguishes a persona-picker/password login from a
            # login_hint-triggered auto-login (#250 design contract point 4).
            **({"auto_login": True} if auto_login else {}),
            # #468: what became of the browser's authenticated session.
            "auth_time": auth_time,
            "session": session_outcome,
        },
    )

    if loaded.settings.verbose_logging:
        logger.info(
            f"Authorization code issued for user '{username}', client '{p.client_id}'"
            + (" via auto-login" if auto_login else "")
        )
    else:
        logger.info("Authorization code issued")

    return _deliver_authorization_response(p, redirect_params)


# OIDC Core 3.1.2.1 (#250): the reserved login_hint prefix that opts an
# /authorize request into persona auto-login. Any other login_hint value is
# an ordinary hint outside this feature and is left untouched.
_AUTO_LOGIN_HINT_PREFIX = "persona-auto-login:"


def _try_persona_auto_login(
    config: ConfigManager,
    p: _AuthorizeParams,
    transaction: Optional[AuthorizationTransaction] = None,
) -> Optional[ResponseReturnValue]:
    """#250: with ``login.auto_login`` and a ``login_hint`` carrying the
    reserved ``persona-auto-login:`` prefix, authenticate the named persona
    directly - no picker, no HTML - by issuing the authorization code
    exactly as a successful inline login would.

    Returns ``None`` when inert: the flag is off, ``login.mode`` isn't
    ``persona`` (``auto_login_enabled`` covers both, #250-assumption 1), or
    ``login_hint`` is absent/unprefixed (an OP may ignore a ``login_hint`` it
    does not recognize, OIDC Core 3.1.2.1) - the caller then falls through
    to the ordinary login page/picker, unchanged.

    Called after every other ``/authorize`` validator has passed (or, for a
    hint-only GET, on a transaction that was validated when it was
    created), so an unknown persona is reported through
    ``_authorize_error_redirect`` with the fully resolved scope/PKCE/resource
    state, the same post-redirect_uri error channel every other validation
    failure already uses (contract point 3) - never a bare 400.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    if not loaded.settings.auto_login_enabled:
        return None
    if not p.login_hint.startswith(_AUTO_LOGIN_HINT_PREFIX):
        return None

    username = p.login_hint[len(_AUTO_LOGIN_HINT_PREFIX) :]
    user = identities_for(config, request_config()).interactive_authenticate(username, "")
    if user is None:
        return _authorize_error_redirect(
            config,
            p,
            "invalid_request",
            "Unknown persona for auto-login",
            f"auto-login: unknown persona {username!r}",
            username=username,
        )

    return _issue_authorization_code(
        config, p, user.username, transaction=transaction, auto_login=True,
        method=AuthMethod.PERSONA,
    )


def _handle_authorize_login(
    config: ConfigManager, transaction: AuthorizationTransaction, p: _AuthorizeParams
) -> Tuple[Optional[str], Optional[ResponseReturnValue], bool]:
    """The POST login leg of a pending transaction: (None, redirect, False)
    on success, (error_msg, None, totp_step) to fall through to the login
    page (failed, the password not yet submitted, or - #348 - the further
    TOTP code screen after a successful password check).

    The two-step username step stays stateless (#323 review round 1): the
    step is derived from what THIS request submits, and the password screen
    re-submits the username as a plain form field. A POST that carries a
    password always attempts a real login - whether it's the two-step
    flow's second screen or a combined-form POST (#323 review round 1,
    blocking 1: a request carrying full credentials must authenticate or be
    refused, never be half-consumed).

    A verified password with a code still outstanding is recorded on the
    transaction (#346), so the code screen carries only the transaction id
    and the code, never the password.

    ``login.two_step`` (#322/#323 review round 2) is a global setting, not
    per-client. The step-detection rule itself lives in
    ``_auth.two_step_phase`` (#323 review round 2, before-merge 5), shared by
    every password-form surface; the declarative TOTP second factor (#348)
    rides the same machinery via ``_auth.authenticate_interactively``.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    username = request.form.get("username", "").strip()
    password_submitted = "password" in request.form
    password = request.form.get("password", "")
    persona_mode = loaded.settings.persona_mode_enabled

    phase = two_step_phase(
        two_step_active=loaded.settings.two_step_login_active,
        username=username,
        password=password,
        password_submitted=password_submitted,
    )
    if phase is TwoStepPhase.USERNAME_REQUIRED:
        return "Username is required", None, False
    if phase is TwoStepPhase.PASSWORD_REQUIRED:
        # The password screen was resubmitted with a blank password.
        return "Password is required", None, False
    if phase is TwoStepPhase.USERNAME_STEP:
        # Nothing to authenticate yet - step 1 never verifies the username
        # exists - fall through to render the password screen with this
        # username carried forward.
        return None, None, False

    login = authenticate_interactively(config, request_config(), username=username, password=password)

    if login.phase.pending:
        store = get_authorization_transaction_store()
        verified = store.mark_primary_verified(
            transaction.id,
            browser_flow_binding(),
            username=username,
            amr=AuthMethod.PASSWORD.amr,
        ) or _verified_by_a_concurrent_submission(transaction, username)
        if verified is None:
            return None, _refuse_without_transaction(
                "authorization transaction no longer pending",
                "The authorization request is no longer pending",
                client_id=p.client_id,
            ), False
        if login.phase is SecondFactorPhase.CODE_INVALID:
            _audit_invalid_code(p, username, login.phase)
        return login.phase.error, None, True

    if login.user:
        return (
            None,
            _issue_authorization_code(
                config, p, login.user.username, transaction=transaction,
                method=login.method, amr=login.amr,
            ),
            False,
        )

    if (persona_mode and username) or (username and password):
        # A real (failed) selection/login attempt, not just missing input
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            username=username,
            client_id=p.client_id,
            details={"reason": "Invalid credentials"},
        )
        return "Invalid username or password", None, False

    if persona_mode:
        return "Select a user", None, False
    return "Username and password are required", None, False


def _verified_by_a_concurrent_submission(
    transaction: AuthorizationTransaction, username: str
) -> Optional[AuthorizationTransaction]:
    """The transaction, when another submission already verified this same
    user's password on it - a double-clicked password form, whose two POSTs
    both read the transaction as pending. That is the state this POST was
    about to write, so it goes on to the code screen instead of being
    refused. A transaction verified for a different user is not."""
    current = get_authorization_transaction_store().get_bound(
        transaction.id, browser_flow_binding()
    )
    if (
        current is not None
        and current.state is TransactionState.PRIMARY_VERIFIED
        and current.primary_username == username
    ):
        return current
    return None


def _audit_invalid_code(p: _AuthorizeParams, username: str, phase: SecondFactorPhase) -> None:
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        username=username,
        client_id=p.client_id,
        details={"reason": phase.error},
    )


def _complete_second_factor(
    config: ConfigManager, transaction: AuthorizationTransaction, p: _AuthorizeParams
) -> ResponseReturnValue:
    """The code screen of a transaction whose password is already verified
    (#346). The user is the one the transaction names: a username or
    password in this form is not read.

    The user is resolved again and the code checked against the current
    secret. Anything that makes the recorded password no longer lead to a
    TOTP check fails the flow rather than completing on the password alone:
    the user was deleted, lost their secret, TOTP was switched off, or
    persona mode was switched on.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    username = transaction.primary_username or ""
    settings = loaded.settings
    user = identities_for(config, request_config()).get_user(username)
    if (
        user is None
        or settings.persona_mode_enabled
        or not settings.totp_active
        or not user.totp_secret
    ):
        get_authorization_transaction_store().consume(transaction.id, browser_flow_binding())
        return _authorize_error_redirect(
            config,
            p,
            "access_denied",
            "The login could not be completed",
            "second factor no longer applicable to the verified user",
            username=username,
        )

    login = check_second_factor(config, request_config(), user)
    if login.phase.pending:
        if login.phase is SecondFactorPhase.CODE_INVALID:
            _audit_invalid_code(p, username, login.phase)
        return _render_authorize_login(config, transaction, login.phase.error)
    return _issue_authorization_code(
        config,
        p,
        username,
        transaction=transaction,
        verified_username=username,
        method=login.method,
        amr=login.amr,
    )


def _render_authorize_login(
    config: ConfigManager,
    transaction: AuthorizationTransaction,
    error_msg: Optional[str],
    login_username: str = "",
    *,
    name_transaction: bool = True,
) -> ResponseReturnValue:
    """The login page of a transaction (a GET, or a POST that did not
    authenticate).

    Every form on it carries the transaction id, unless ``name_transaction``
    is off: a direct POST's page, whose transaction has already ended and
    whose forms post back to the same query string instead. ``login_username`` is this
    request's username field, not a value remembered from a previous one
    (#323 review round 1) - "" on a GET, the just-submitted value on a
    POST. A transaction whose password is verified renders the TOTP code
    screen (#348) for the user it names. no_store is applied to that screen
    here, the one place that knows it is being rendered.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    client = transaction.client_snapshot
    totp_step = transaction.state is TransactionState.PRIMARY_VERIFIED
    if totp_step:
        login_username = transaction.primary_username or ""

    logo_url = None
    logos_dir = effective_logos_dir(loaded.settings.logos_dir, current_app.static_folder)
    if resolve_client_logo(logos_dir, client.client_id):
        logo_url = url_for("oauth.client_logo", client_id=client.client_id)

    response = render_template(
        "authorize.html",
        client_id=transaction.params.client_id,
        client=client,
        logo_url=logo_url,
        scope=transaction.params.scope,
        error=error_msg,
        persona_mode=loaded.settings.persona_mode_enabled,
        two_step_login=loaded.settings.two_step_login_active,
        login_username=login_username,
        totp_step=totp_step,
        transaction_id=transaction.id if name_transaction else None,
        users=identities_for(config, request_config()).persona_picker_entries(),
    )
    return no_store(response) if totp_step else response


def _begin_transaction(
    config: ConfigManager,
    p: _AuthorizeParams,
    client: OAuthClient,
    requested: Dict[str, List[str]],
    interaction_required: bool = False,
    bound_subject: Optional[str] = None,
) -> Tuple[Optional[AuthorizationTransaction], Optional[ResponseReturnValue]]:
    """Store a validated request as a transaction of this browser.

    A client learned from a metadata document exists only in the cache, so
    the transaction holds the cache entry for its own lifetime (#346), the
    way a code holds it for the code's (#196): a transaction must not
    outlive the only copy of the client it was validated against.
    """
    resolved = identities_for(config, request_config()).resolve_client(p.client_id)
    if resolved is None:
        return None, _authorize_error_redirect(
            config,
            p,
            "temporarily_unavailable",
            "The authorization request could not be completed, please try again",
            "the client no longer resolves",
        )
    store = get_authorization_transaction_store()
    binding = browser_flow_binding(create=True)
    assert binding is not None
    try:
        transaction = store.create(
            browser_binding=binding,
            params=AuthorizationParameters(
                response_mode=p.response_mode,
                response_type=p.response_type,
                client_id=p.client_id,
                redirect_uri=p.redirect_uri,
                scope=p.scope,
                state=p.state,
                code_challenge=p.code_challenge,
                code_challenge_method=p.code_challenge_method,
                nonce=p.nonce,
                claims=p.claims_param,
                resources=list(p.resources),
            ),
            requested=requested,
            interaction_required=interaction_required,
            bound_subject=bound_subject,
            client=client,
            client_origin=resolved.origin,
        )
    except TransactionStoreFull:
        return None, _authorize_error_redirect(
            config,
            p,
            "temporarily_unavailable",
            "Too many authorization requests are pending, please try again later",
            "authorization transaction store full",
        )
    if resolved.origin == "cimd" and not retain_cached_client_until(
        p.client_id, transaction.expires_at
    ):
        store.consume(transaction.id, binding)
        return None, _authorize_error_redirect(
            config,
            p,
            "temporarily_unavailable",
            "The authorization request could not be completed, please try again",
            "the cached metadata document could not be held for the transaction",
        )
    return transaction, None


_PROMPT_VALUES = frozenset({"none", "login", "consent", "select_account"})


def _validate_authorize_authentication_constraints(
    config: ConfigManager, p: _AuthorizeParams
) -> Optional[ResponseReturnValue]:
    """``prompt`` and ``max_age`` (OIDC Core 3.1.2.1, #468), read into
    ``p.prompts`` and ``p.max_age_seconds``: a space-separated list of the
    four defined values, ``none`` alone; a non-negative integer. Anything
    else is ``invalid_request``, delivered to the client like every error
    after the redirect_uri. Each is an omitted parameter when sent empty,
    as every other field (RFC 6749 3.1)."""
    prompts = frozenset(p.prompt.split()) if p.prompt else frozenset()
    unknown = sorted(prompts - _PROMPT_VALUES)
    if unknown:
        return _authorize_error_redirect(
            config, p, "invalid_request", "Unsupported prompt value",
            f"prompt carries an unknown value: {', '.join(unknown)}",
        )
    if "none" in prompts and len(prompts) > 1:
        return _authorize_error_redirect(
            config, p, "invalid_request", "prompt=none cannot be combined with another prompt value",
            "prompt=none combined with another value",
        )
    max_age: Optional[int] = None
    if p.max_age:
        # ASCII digits only, bounded: str.isdigit accepts other scripts'
        # digits and superscripts that int() refuses, and int() refuses
        # very long strings; neither is an answer this endpoint gives.
        if not (p.max_age.isascii() and p.max_age.isdigit() and len(p.max_age) <= 10):
            return _authorize_error_redirect(
                config, p, "invalid_request", "max_age must be a non-negative integer",
                "max_age is not a non-negative integer",
            )
        max_age = int(p.max_age)
    hint_subject: Optional[str] = None
    if p.id_token_hint_repeated:
        return _authorize_error_redirect(
            config, p, "invalid_request", "id_token_hint must not be repeated",
            "id_token_hint repeated",
        )
    if p.id_token_hint_unresolved:
        return _authorize_error_redirect(
            config, p, "invalid_request", "id_token_hint reference unknown, expired or already used",
            "id_token_hint reference not resolvable",
        )
    if p.id_token_hint:
        hint = p.id_token_hint
        # The settings are read before the signing service is resolved
        # (#359): the issuer this request answers for, then the keys.
        issuer = effective_issuer(request_config().settings)
        try:
            payload = get_crypto_service().verify_id_token_hint(hint)
        except ValueError as e:
            return _authorize_error_redirect(
                config, p, "invalid_request", "id_token_hint does not verify",
                f"id_token_hint does not verify: {e}",
            )
        if payload.get("iss") != issuer:
            return _authorize_error_redirect(
                config, p, "invalid_request", "id_token_hint does not verify",
                "id_token_hint was not issued by this issuer",
            )
        hint_subject = payload["sub"]
    p.prompts = prompts
    p.max_age_seconds = max_age
    p.hint_subject = hint_subject
    return None


def _interaction_required(p: _AuthorizeParams) -> bool:
    """Whether the request asks for the user's own interaction (#468):
    ``prompt=login``, ``prompt=select_account`` (the picker, where there is
    one) or ``max_age=0``. A live session is not reused for it, and persona
    auto-login does not stand in for it."""
    return (
        "login" in p.prompts or "select_account" in p.prompts or p.max_age_seconds == 0
    )


def _fresh_authentication_required(p: _AuthorizeParams) -> bool:
    """Once no session answered the request (#468): whether the user's own
    interaction is what must follow. ``_interaction_required`` asks for it
    outright; a ``max_age`` that no session satisfied asks for it too (Core
    3.1.2.1: the End-User MUST be actively re-authenticated), so persona
    auto-login does not stand in, now or on a later hint-only GET of the
    transaction this creates."""
    return _interaction_required(p) or p.max_age_seconds is not None


def _answer_from_session(
    config: ConfigManager, loaded: ConfigSnapshot, p: _AuthorizeParams, *, reuse: bool = True
) -> Optional[ResponseReturnValue]:
    """What a validated request gets before any login page is considered
    (#468): a code resting on the browser's authenticated session, an
    error the request's constraints call for, or None, meaning the login
    page (or persona auto-login, where the request allows it) comes next.

    ``prompt=consent`` is ``consent_required``: there is no consent screen.
    ``prompt=select_account`` under password mode is
    ``account_selection_required``: the login form selects no account;
    under persona mode the picker does, so it is an interaction like
    ``prompt=login``. A live session is reused when the request asks for
    no interaction and, with ``max_age``, the authentication is not older
    than that. ``prompt=none`` forbids every interaction: without a
    reusable session it is ``login_required``, whatever a ``login_hint``
    says (persona auto-login is no interaction either, and stands in for
    none). A hint that names a user - ``id_token_hint``'s subject, or the
    persona of an auto-login ``login_hint`` - is honoured: a session for
    another user is not reused for it. ``reuse`` is off for the direct
    POST, which carries credentials and authenticates with them: it never
    takes a code from the session, and ``prompt=none`` on it is
    ``login_required``.
    """
    prompts = p.prompts
    if "consent" in prompts:
        return _authorize_error_redirect(
            config, p, "consent_required", "Consent is required and this server has no consent screen",
            "prompt=consent: no consent screen",
        )
    if "select_account" in prompts and not loaded.settings.persona_mode_enabled:
        return _authorize_error_redirect(
            config, p, "account_selection_required",
            "Account selection is required and the login form selects no account",
            "prompt=select_account under password login mode",
        )
    interaction = _interaction_required(p)
    # Resolved only where it decides something: the store round-trip and
    # the user lookup are not paid for a request that asks for a login.
    usable = _usable_session(config, loaded) if reuse and not interaction else None
    hinted = p.hint_subject
    if hinted is None and loaded.settings.auto_login_enabled and p.login_hint.startswith(
        _AUTO_LOGIN_HINT_PREFIX
    ):
        hinted = p.login_hint[len(_AUTO_LOGIN_HINT_PREFIX) :]
    if usable is not None:
        record, user = usable
        fresh_enough = p.max_age_seconds is None or record.age() <= p.max_age_seconds
        hinted_user = hinted is None or hinted == user.username
        if fresh_enough and hinted_user:
            method = AuthMethod(record.method)
            return _issue_authorization_code(
                config, p, user.username, method=method, amr=_session_amr(loaded, method), reused=record
            )
    if "none" in prompts:
        if not reuse:
            reason = "prompt=none on a request carrying credentials"
        elif interaction:
            reason = "prompt=none with max_age=0"
        elif usable is None:
            reason = "prompt=none without an authenticated session"
        elif hinted is not None and hinted != usable[1].username:
            reason = "prompt=none with a session for another user than the hint names"
        else:
            reason = "prompt=none with a session older than max_age"
        return _authorize_error_redirect(
            config, p, "login_required", "Authentication is required and prompt=none forbids it", reason
        )
    return None


def _refuse_response_mode(p: _AuthorizeParams) -> ResponseReturnValue:
    """OIDC Core 3.1.2.6: an unknown response_mode is an HTTP 400 that
    carries no OAuth error parameters, since the request names no channel
    to deliver them on; a repeated one is treated alike (#472). Audited as
    any refusal of a request."""
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        client_id=p.client_id or None,
        details=_failed_details(p.response_mode_rejected or "", None),
    )
    return Response("Bad request: response_mode\n", status=400, content_type="text/plain")


def _take_parked_hint(p: _AuthorizeParams) -> None:
    """Swap a form POST's parked reference (#467, #468) for the hint it
    stands for. First thing in the validation, before anything can refuse
    the request: a refused request with one hint gives its slot of the
    bounded store back at once, whichever refusal it was. (A hand-built URL
    repeating references leaves the others to their minute, as a 303 nobody
    follows does.) An unknown, expired or used reference is judged where
    the hint is, after the redirect_uri."""
    if not is_reference(p.id_token_hint):
        return
    parked = get_parked_hint_store().take(p.id_token_hint)
    p.id_token_hint = parked or ""
    p.id_token_hint_unresolved = parked is None


def _validate_authorize_request(
    config: ConfigManager, p: _AuthorizeParams
) -> Tuple[Optional[OAuthClient], Optional[ResponseReturnValue]]:
    """Every check a request read from a query string goes through, in the
    historical order: (client, None) or (None, error). Mutates ``p`` to the
    granted scope and resources.

    Each step is a named helper; every rejection keeps its historical error
    body and audit behavior (#212). A rejected request creates nothing (#331).
    """
    _take_parked_hint(p)

    # The channel first (#472): a request whose response_mode names no
    # usable one is refused locally before any answer, the request-object
    # refusal below included, is built for the client.
    if p.response_mode_rejected is not None:
        return None, _refuse_response_mode(p)

    # A request object is refused whatever the rest of the request says,
    # before any validator runs (#463): one answer, one authorization_request
    # event.
    unsupported = p.unsupported_request_parameter
    if unsupported is not None:
        return None, _refuse_unsupported_request_parameter(config, p, unsupported)

    client, error = _validate_authorize_client(config, p)
    if error is not None:
        return None, error
    assert client is not None  # _validate_authorize_client returns one or the other

    # redirect_uri is validated BEFORE scope/PKCE/resource (#189/RFC 9207):
    # an unvalidated redirect_uri keeps its local error (never redirect to
    # it), but once it is trusted, every later error is delivered to the
    # client as an OAuth error redirect carrying iss (#258 review).
    for check in (
        lambda: _validate_authorize_redirect_uri(config, p, client),
        lambda: _validate_authorize_authentication_constraints(config, p),
        lambda: _validate_authorize_response_type(config, p),
        lambda: _validate_authorize_scope(config, p, client),
        lambda: _validate_authorize_pkce(config, p, client),
        lambda: _validate_authorize_resources(config, p, client),
    ):
        error = check()
        if error is not None:
            return None, error
    return client, None


def _authorize_new_request(
    config: ConfigManager, requested: Dict[str, List[str]]
) -> ResponseReturnValue:
    """A GET carrying an OAuth request: validate it once, then answer it by
    auto-login or store it as a transaction and render its login page."""
    p = _read_authorize_params()
    client, error = _validate_authorize_request(config, p)
    if error is not None:
        return error
    assert client is not None

    # #468: a browser whose login is still live is not asked to log in
    # again, unless the request asks for an interaction; prompt=none gets
    # a code or an error, never a page.
    loaded = request_config()
    answered = _answer_from_session(config, loaded, p)
    if answered is not None:
        return answered
    interaction_required = _fresh_authentication_required(p)

    # #250: a login_hint carrying the reserved auto-login prefix bypasses
    # the login page/picker entirely - inert (returns None) unless
    # login.auto_login and login.mode: persona are both active. Answered on
    # this GET, so no transaction is created for it. Not for a request that
    # asked for the user's own interaction (#468).
    if not interaction_required:
        auto_login_response = _try_persona_auto_login(config, p)
        if auto_login_response is not None:
            return auto_login_response

    transaction, error = _begin_transaction(
        config,
        p,
        client,
        requested,
        interaction_required=interaction_required,
        bound_subject=p.hint_subject,
    )
    if error is not None:
        return error
    assert transaction is not None
    return _render_authorize_login(config, transaction, None)


def _authorize_direct_post(
    config: ConfigManager, requested: Dict[str, List[str]]
) -> ResponseReturnValue:
    """A POST carrying a complete OAuth request in its query string and no
    ``transaction_id``: the documented direct entry point, with or without a
    GET before it.

    The request is validated here, once, exactly as a GET's would be, and
    the login runs against a transaction created for it. That transaction
    is kept only when it holds state a later request needs - a verified
    password waiting for its TOTP code. Otherwise it ends with this request,
    whatever the outcome, so a direct POST leaves the browser's pending
    requests as it found them (#328): its page is rendered without a
    transaction id, and its forms post back to the same URL, which is this
    entry point again.
    """
    # login_hint is read into p but never acted on here: auto-login is a GET
    # leg only (#325 review round 1, point 6).
    p = _read_authorize_params()
    client, error = _validate_authorize_request(config, p)
    if error is not None:
        return error
    assert client is not None
    # The constraints a GET decides first apply here too (#468), but the
    # credentials this POST carries are what it authenticates with: no
    # session is reused for it, and prompt=none is never a login.
    answered = _answer_from_session(config, request_config(), p, reuse=False)
    if answered is not None:
        return answered
    transaction, error = _begin_transaction(
        config,
        p,
        client,
        requested,
        interaction_required=_fresh_authentication_required(p),
        bound_subject=p.hint_subject,
    )
    if error is not None:
        return error
    assert transaction is not None

    outcome = _continue_authorize_login(config, transaction)
    store = get_authorization_transaction_store()
    current = store.get_bound(transaction.id, browser_flow_binding())
    if current is None:
        # Ended by an issued code or an error redirect: a response either way.
        return _render_after_login_attempt(config, transaction, outcome)
    if current.state is TransactionState.PRIMARY_VERIFIED:
        # Kept for the code step, whose form names it.
        return _render_after_login_attempt(config, current, outcome)
    store.consume(transaction.id, browser_flow_binding())
    return _render_after_login_attempt(config, current, outcome, name_transaction=False)


def _pending_transaction() -> Tuple[
    Optional[AuthorizationTransaction], Optional[ResponseReturnValue]
]:
    """The transaction a request that names none and carries no OAuth
    request fields resumes (#346): the one live transaction of this browser.
    None or several is refused rather than guessed."""
    lookup = get_authorization_transaction_store().find_unique_for_binding(browser_flow_binding())
    if lookup.outcome is LookupOutcome.UNIQUE:
        return lookup.transaction, None
    if lookup.outcome is LookupOutcome.AMBIGUOUS:
        return None, _refuse_without_transaction(
            "several pending /authorize requests, none named",
            "Several authorization requests are pending in this browser; "
            "submit the transaction_id of the one to continue",
        )
    return None, _refuse_without_transaction(
        "no pending /authorize request",
        "No pending authorization request",
    )


def _named_transaction(
    transaction_id: str, requested: Dict[str, List[str]]
) -> Tuple[Optional[AuthorizationTransaction], Optional[ResponseReturnValue]]:
    """The transaction a POST names with ``transaction_id``. When the POST's
    own query string carries OAuth request fields - a browser form has no
    ``action``, so it posts back to the URL of the GET that created the
    transaction - they must be exactly that GET's."""
    transaction = get_authorization_transaction_store().get_bound(
        transaction_id, browser_flow_binding()
    )
    if transaction is None:
        return None, _refuse_without_transaction(
            "unknown, expired or foreign authorization transaction",
            "Unknown or expired authorization request",
        )
    if requested and requested != transaction.requested:
        return None, _refuse_without_transaction(
            "query string does not match the authorization transaction",
            "The request does not match the pending authorization request",
            client_id=transaction.params.client_id,
        )
    return transaction, None


# The marker _continue_authorize_login returns when the login page is to be
# rendered again; carries what the render needs.
@dataclass(frozen=True)
class _RenderLogin:
    error_msg: Optional[str]
    login_username: str


def _continue_authorize_login(
    config: ConfigManager, transaction: AuthorizationTransaction
) -> Union[ResponseReturnValue, _RenderLogin]:
    """One login POST on a transaction: a response to send as it is, or a
    ``_RenderLogin`` when the login page is to be shown again."""
    p = _params_of(transaction)

    if "change_username" in request.form:
        reset = get_authorization_transaction_store().reset_login(
            transaction.id, browser_flow_binding()
        )
        if reset is None:
            return _refuse_without_transaction(
                "authorization transaction no longer pending",
                "The authorization request is no longer pending",
                client_id=transaction.params.client_id,
            )
        return _RenderLogin(None, "")

    if transaction.state is TransactionState.PRIMARY_VERIFIED:
        return _complete_second_factor(config, transaction, p)

    error_msg, response, _ = _handle_authorize_login(config, transaction, p)
    if response is not None:
        return response
    return _RenderLogin(error_msg, request.form.get("username", "").strip())


def _render_after_login_attempt(
    config: ConfigManager,
    transaction: AuthorizationTransaction,
    outcome: Union[ResponseReturnValue, _RenderLogin],
    *,
    name_transaction: bool = True,
) -> ResponseReturnValue:
    if not isinstance(outcome, _RenderLogin):
        return outcome
    return _render_authorize_login(
        config,
        transaction,
        outcome.error_msg,
        outcome.login_username,
        name_transaction=name_transaction,
    )


@oauth_bp.route("/authorize", methods=["GET", "POST"])
def authorize() -> ResponseReturnValue:
    """
    OAuth2 Authorization endpoint.
    Supports Authorization Code Flow with optional PKCE.

    GET with OAuth request parameters: validate the request, then answer it
    (persona auto-login) or store it as an authorization transaction (#346)
    and display its login page.
    GET without them (unrelated parameters are not OAuth request
    parameters): resume this browser's one pending transaction, which is
    how a GET carrying only ``login_hint`` applies the hint to it.
    POST with ``transaction_id``: continue that transaction.
    POST without one, with a complete OAuth request in its query string:
    the direct entry point, validated on that POST.
    POST with neither and no login field, with OAuth request parameters in
    its body: the authorization request serialized as a form (OIDC Core
    3.1.2.1, #467), answered with a 303 to the same request as a GET, which
    the browser follows with its session cookie.
    POST with none of those: continue this browser's one pending
    transaction.
    OAuth parameters are never read from a POST body (#325): a login
    field, even empty, or a ``transaction_id`` makes a POST a login.

    Required:
    - response_type: "code" for Authorization Code Flow
    - client_id: OAuth client ID
    - redirect_uri: Callback URL

    Optional:
    - scope: Space-separated scopes (default: "openid")
    - state: CSRF protection (recommended)
    - code_challenge: PKCE challenge
    - code_challenge_method: "plain" or "S256"
    - nonce: OIDC nonce for ID token
    """
    config = get_config()
    requested = _requested_fields(request.args)

    if request.method == "GET":
        if requested:
            return _authorize_new_request(config, requested)
        transaction, error = _pending_transaction()
        if error is not None:
            return error
        assert transaction is not None
        if not transaction.interaction_required:
            auto_login_response = _try_persona_auto_login(
                config,
                _params_of(transaction, login_hint=request.args.get("login_hint", "")),
                transaction,
            )
            if auto_login_response is not None:
                return auto_login_response
        return _render_authorize_login(config, transaction, None)

    if _is_form_serialized_request(requested, request.form):
        return _redirect_form_request_to_get(config, request.form)
    _audit_body_oauth_fields()
    transaction_id = request.form.get("transaction_id", "")
    if not transaction_id and requested:
        return _authorize_direct_post(config, requested)
    if transaction_id:
        transaction, error = _named_transaction(transaction_id, requested)
    else:
        transaction, error = _pending_transaction()
    if error is not None:
        return error
    assert transaction is not None

    outcome = _continue_authorize_login(config, transaction)
    current = get_authorization_transaction_store().get_bound(
        transaction.id, browser_flow_binding()
    )
    # A verified password or a reset changed the transaction: render what
    # it is now.
    return _render_after_login_attempt(config, current or transaction, outcome)


@oauth_bp.route("/client-logos/<client_id>")
def client_logo(client_id: str) -> ResponseReturnValue:
    """Serve a per-client logo file for the /authorize login page.

    A dedicated route rather than Flask's built-in static handler, which only
    ever serves the app's own static/ folder - so a configured 'logos_dir'
    override actually takes effect instead of silently only working for the
    default location (#150 review). resolve_client_logo() re-validates
    client_id against the charset whitelist, so this is as path-traversal-safe
    as the default case.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    logos_dir = effective_logos_dir(loaded.settings.logos_dir, current_app.static_folder)
    filename = resolve_client_logo(logos_dir, client_id)
    if not filename:
        abort(404)
    return send_from_directory(os.path.abspath(logos_dir), filename)


# ============================================================================
# Token endpoint: shared validation in token(), one handler per grant (#84)
# ============================================================================


def _basic_attempted() -> bool:
    """True when the request ATTEMPTED HTTP Basic authentication (#311).

    Read from the RAW Authorization header, not werkzeug's parsed
    ``request.authorization``: werkzeug returns None for a syntactically
    broken Basic header, which would misclassify a botched attempt as
    no-attempt - answering 400 with no challenge where RFC 6749 §5.2's
    401 + WWW-Authenticate MUST covers the attempt. The parsed object
    stays the only source of username/password.

    The SCHEME is compared for equality, not by prefix (#313 review):
    "BasicFoo xyz" is a different scheme, not a Basic attempt. A bare
    "Basic" with no credentials still counts - the scheme was named.
    """
    scheme, _ = authorization_credentials()
    return scheme.casefold() == "basic"


def _token_auth_failed(
    client_id: Optional[str], reason: str, *, basic_attempted: bool
) -> ResponseReturnValue:
    audit_event(
        "token_request",
        "failed",
        endpoint="/token",
        client_id=client_id,
        details={"reason": reason},
    )
    # WWW-Authenticate on an attempted-Basic failure is a §5.2 MUST
    # (#310 review); see invalid_client_error.
    return invalid_client_error(reason, basic_attempted=basic_attempted)


@dataclass(frozen=True)
class _ClientIdentity:
    """The client identity one request presents, resolved uniformly (#277)."""

    auth: Optional[Any]
    client_id: Optional[str]
    body_client_secret: Optional[str]
    # True when HTTP Basic and a body client_id name DIFFERENT clients - one
    # request claiming two identities. Callers reject it as invalid_client.
    mismatch: bool


def _request_client_identity() -> _ClientIdentity:
    """Resolve which client this request claims to be, one way for all four
    client-facing endpoints (#277).

    /token has always resolved body-first and rejected a Basic-vs-body
    client_id mismatch; /introspect, /revoke and /device_authorization used
    to resolve header-first and check nothing, so the same request meant
    different things at different endpoints. The precedence is only
    observable when the two disagree, and that is now uniformly an error -
    what remains is one rule: a request names one client, through either
    channel, and _enforce_registered_client_auth decides how it must prove it.
    """
    auth = request.authorization
    body_client_id = request.form.get("client_id")
    body_client_secret = request.form.get("client_secret") or None
    client_id = body_client_id or (auth.username if auth else None)
    mismatch = bool(auth and body_client_id and auth.username != body_client_id)
    return _ClientIdentity(
        auth=auth,
        client_id=client_id,
        body_client_secret=body_client_secret,
        mismatch=mismatch,
    )


def _enforce_token_endpoint_auth(
    config: ConfigManager,
    grant_type: str,
    auth: Optional[Any],
    client_id: str,
    body_client_secret: Optional[str],
) -> Optional[ResponseReturnValue]:
    """The single client-authentication boundary for /token (#188).

    Enforces the client's registered token_endpoint_auth_method for every
    grant, before dispatch. Returns an error response, or None when the
    request may proceed. RFC 7591 method semantics, RFC 6749 §3.2.1
    (confidential clients MUST authenticate, authorization_code included).
    """
    token_client = identities_for(config, request_config()).get_client(client_id)

    # Public client (token_endpoint_auth_method 'none'): identified by
    # client_id alone; any presented secret is ignored, never validated.
    if token_client is not None and token_client.is_public:
        # client_credentials IS client authentication, which a public
        # client does not have (OAuth 2.1 §2.1; RFC 6749 §5.2).
        if grant_type == "client_credentials":
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=client_id,
                details={
                    "reason": "client_credentials refused for a public client",
                    "grant_type": grant_type,
                },
            )
            return (
                jsonify(
                    {
                        "error": "unauthorized_client",
                        "error_description": (
                            "The client_credentials grant requires client "
                            "authentication; this client's "
                            "token_endpoint_auth_method is 'none'"
                        ),
                    }
                ),
                400,
            )
        return None

    reason = _enforce_registered_client_auth(config, client_id, auth, body_client_secret)
    return (
        _token_auth_failed(client_id, reason, basic_attempted=_basic_attempted())
        if reason is not None
        else None
    )


def _enforce_registered_client_auth(
    config: ConfigManager,
    client_id: Optional[str],
    auth: Optional[Any],
    body_client_secret: Optional[str],
) -> Optional[str]:
    """Enforce a CONFIDENTIAL client's registered token_endpoint_auth_method and
    reject presenting two authentication methods in one request. Returns None
    when the request may proceed, or a human-readable failure reason.

    The single home for the confidential client-auth rule, shared by /token,
    /introspect, /revoke and /device_authorization (#262). RFC 6749 §2.3 forbids
    more than one auth method per request, so a body secret is never accepted
    alongside Basic. Enforcing the client's REGISTERED method at all four
    endpoints is nanoidp's consistency policy: RFC 7009 §2.1 and RFC 8628 tie
    /revoke and /device_authorization to the token-endpoint method, while
    RFC 7662 requires some client authentication at /introspect but does not
    mandate reusing that method - nanoidp reuses it there too rather than add a
    second field. Callers handle any public-client policy FIRST, so this only
    ever sees confidential clients and unknown client_ids (both treated as
    client_secret_basic, the default); the wrong channel for the registered
    method is rejected instead of silently accepted.
    """
    client = identities_for(config, request_config()).get_client(client_id) if client_id else None
    method = client.token_endpoint_auth_method if client is not None else "client_secret_basic"

    # client_secret_post: credentials in the body only; Basic is rejected.
    if method == "client_secret_post":
        if auth is not None:
            return (
                "This client's token_endpoint_auth_method is "
                "'client_secret_post'; use client_id and client_secret in the "
                "request body, not HTTP Basic"
            )
        if not body_client_secret or not identities_for(config, request_config()).check_client(client_id, body_client_secret):
            return "Invalid client credentials"
        return None

    # client_secret_basic (the default) and unknown client_ids authenticate
    # via HTTP Basic. A body client_secret is never accepted here, whether or
    # not Basic is also present: for a basic client it is the wrong channel,
    # and presenting it ALONGSIDE Basic is two authentication methods in one
    # request (RFC 6749 §2.3, "MUST NOT use more than one").
    if body_client_secret is not None:
        return (
            "This client authenticates with HTTP Basic; a client_secret in "
            "the request body is not accepted, and must not be combined with "
            "HTTP Basic (RFC 6749 §2.3)"
        )
    if auth is None:
        return "Client authentication required"
    if not identities_for(config, request_config()).check_client(auth.username, auth.password):
        return "Invalid client credentials"
    return None


@oauth_bp.route("/token", methods=["POST"])
@no_store_responses
def token() -> ResponseReturnValue:
    """OAuth2 token endpoint: shared validation, then per-grant dispatch."""
    config = get_config()
    # The configuration this request began with, for the whole path (#406).
    loaded = request_config()

    grant_type = request.form.get("grant_type", "client_credentials")
    # client_secret_post (RFC 6749 §2.3.1, #188): discovery has always
    # advertised it; the body secret is validated, not silently ignored.
    identity = _request_client_identity()
    auth = identity.auth
    body_client_secret = identity.body_client_secret
    client_id = identity.client_id

    # Reject if client identity cannot be determined at all
    if not client_id:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            details={"reason": "Client authentication required", "grant_type": grant_type},
        )
        return invalid_client_error(
            "Client authentication required", basic_attempted=_basic_attempted()
        )

    # Reject if body client_id conflicts with the authenticated client in the header
    if identity.mismatch:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=auth.username if auth else None,
            details={"reason": "client_id mismatch", "body_client_id": client_id},
        )
        # identity.mismatch implies Basic was presented, so the §5.2
        # WWW-Authenticate MUST applies (#310 review).
        return invalid_client_error(
            "client_id in request body does not match authenticated client",
            basic_attempted=True,
        )

    # One client-authentication boundary for every grant (#188, #254
    # review): enforce the client's registered token_endpoint_auth_method
    # here, before grant dispatch, so no grant - authorization_code
    # included - can slip past it.
    auth_error = _enforce_token_endpoint_auth(
        config, grant_type, auth, client_id, body_client_secret
    )
    if auth_error is not None:
        return auth_error

    # Validate the grant-independent 'exp' and 'extra' params BEFORE the grant
    # dispatch: the rotation branch atomically consumes the refresh token at
    # the end of its validations, so nothing after it may reject the request
    # (#56 review follow-up). Validation is semantic, not just syntactic:
    # json.loads("42") succeeds but extra.update(42) raises later, and a huge
    # 'exp' passes int() but overflows the timedelta arithmetic - both would
    # be 500s after the token was consumed.
    try:
        exp_minutes = int(request.form.get("exp", request_config().settings.token_expiry_minutes))
    except (TypeError, ValueError):
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=client_id,
            details={"reason": "Invalid 'exp' parameter", "grant_type": grant_type},
        )
        return oauth_error("invalid_request", "'exp' must be an integer number of minutes")
    # Same bounds the Settings model enforces for token_expiry_minutes
    if not 1 <= exp_minutes <= 1440:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=client_id,
            details={"reason": "'exp' out of range", "grant_type": grant_type},
        )
        return oauth_error("invalid_request", "'exp' must be between 1 and 1440 minutes")

    extra_claims = None
    extra_raw = request.form.get("extra")
    if extra_raw:
        try:
            parsed_extra = json.loads(extra_raw)
        except json.JSONDecodeError:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=client_id,
                details={"reason": "Invalid JSON in 'extra'", "grant_type": grant_type},
            )
            return oauth_error("invalid_request", "Invalid JSON in 'extra'")
        # Any JSON scalar/array parses fine but is not a claims mapping
        if not isinstance(parsed_extra, dict):
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=client_id,
                details={"reason": "'extra' is not a JSON object", "grant_type": grant_type},
            )
            return oauth_error("invalid_request", "'extra' must be a JSON object")
        # extra adds claims, it never changes what the grant decided (#451):
        # a request naming a registered, protocol or user-identity claim is
        # refused here, before the grant, so no code or refresh token is
        # consumed by it. The token service strips the same set as well.
        forbidden = forbidden_extra_claims(parsed_extra)
        if forbidden:
            refusal = extra_refusal("extra", forbidden)
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=client_id,
                details={"reason": refusal, "grant_type": grant_type},
            )
            return oauth_error("invalid_request", refusal)
        extra_claims = parsed_extra

    # Per-grant dispatch
    handler = _GRANT_HANDLERS.get(grant_type)
    if handler is None:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=client_id,
            details={"reason": f"Unsupported grant type: {grant_type}", "grant_type": grant_type},
        )
        # FIXED text (#310 review, blocker 1): §5.2 restricts
        # error_description to a narrow ASCII subset, so the caller's
        # arbitrary grant_type value (emoji, quotes, newlines) must not be
        # reflected here - it is already recorded in the audit event above.
        return oauth_error(
            "unsupported_grant_type", "The requested grant_type is not supported"
        )

    ctx = _GrantContext(
        config=config,
        loaded=loaded,
        identities=identities_for(config, loaded),
        client_id=client_id,
        grant_type=grant_type,
        exp_minutes=exp_minutes,
    )
    result = handler(ctx)
    if not isinstance(result, _GrantOutcome):
        return result

    # Create token ('exp' and 'extra' were validated before the grant dispatch
    # so the rotation claim in the refresh handler is the last thing that can
    # reject)
    token_service = get_token_service(request_config())
    if result.user is None:
        # client_credentials: the client is the subject, no user (#445)
        assert client_id is not None, "client_credentials authenticates a client"
        token_response = token_service.create_client_credentials_token(
            client_id=client_id,
            exp_minutes=exp_minutes,
            extra_claims=extra_claims,
            scope=result.scope,
            issuer=effective_issuer(loaded.settings),
            resource=result.resource,
        )
        audit_event(
            "token_request",
            "success",
            endpoint="/token",
            client_id=client_id,
            details={"grant_type": grant_type},
        )
        if loaded.settings.log_token_requests:
            logger.info(f"Token issued to client '{client_id}' via {grant_type} grant")
        return jsonify(token_response)

    token_response = token_service.create_token(
        user=result.user,
        exp_minutes=exp_minutes,
        extra_claims=extra_claims,
        nonce=result.nonce,
        scope=result.scope,
        client_id=client_id,
        auth_time=result.auth_time,
        amr=result.amr,
        refresh_family=result.refresh_family,
        id_token_claims=result.id_token_claims,
        userinfo_claims=result.userinfo_claims,
        issuer=effective_issuer(loaded.settings),
        issue_refresh_token=(
            result.issue_refresh_token and _may_hold_a_refresh_token(config, loaded, client_id)
        ),
        resource=result.resource,
        refresh_resource=result.refresh_resource,
        access_jti=result.access_jti,
        issued_at=result.issued_at,
    )

    # Audit log
    audit_event(
        "token_request",
        "success",
        endpoint="/token",
        username=result.subject,
        client_id=client_id,
        details={
            "grant_type": grant_type,
            "authorities_count": len(token_service.build_authorities(result.user, loaded.settings)),
        },
    )

    if loaded.settings.log_token_requests:
        logger.info(f"Token issued for user '{result.subject}' via {grant_type} grant")

    return jsonify(token_response)


_USERINFO_REALM = "userinfo"


def _bearer_refusal(status: int, error: str, description: str) -> ResponseReturnValue:
    """An error answer of /userinfo to a presented credential: bearer_error
    with this resource's realm. Descriptions are FIXED text (the rule of
    routes/_oauth_error.py)."""
    return bearer_error(status, error, description, realm=_USERINFO_REALM)


def _bearer_challenge_alone() -> ResponseReturnValue:
    """The answer to a request with no bearer credentials: 401, the
    challenge with the realm, no error code and no body (RFC 6750 3.1,
    "SHOULD NOT include an error code or other error information")."""
    response = Response(status=401)
    del response.headers["Content-Type"]
    response.headers["WWW-Authenticate"] = bearer_challenge(realm=_USERINFO_REALM)
    return response


def _userinfo_refused(reason: str, description: str) -> Response:
    """A malformed or doubled credential (RFC 6750 3.1 invalid_request):
    audited, since a client sent something it must not, unlike a request
    with no credentials at all."""
    audit_event(
        "userinfo_request", "failed", endpoint="/userinfo", details={"reason": reason}
    )
    return bearer_error(400, "invalid_request", description, realm=_USERINFO_REALM)


@dataclass(frozen=True)
class _FormToken:
    """What this request's form-encoded body said about the token channel:
    ``present`` when the body used it (carried ``access_token``, or could
    not be read as a form at all); then either ``value``, the one token of
    a body that used it well, or ``malformed``, the audit reason and
    description of one that used it badly. A decodable body without the
    parameter is no channel."""

    present: bool
    value: Optional[str] = None
    malformed: Optional[Tuple[str, str]] = None


_NO_FORM_TOKEN = _FormToken(present=False)


def _form_token_malformed(reason: str, description: str) -> _FormToken:
    return _FormToken(present=True, malformed=(reason, description))


def _form_access_token() -> _FormToken:
    """The ``access_token`` parameter of this request's form-encoded body,
    read as RFC 6750 2.2 describes the body - form-encoded, ASCII - with
    the ASCII rule enforced on the token value and a non-ASCII field
    beside it tolerated.

    Read here, not through ``request.form``: werkzeug's parser drops a
    body it cannot decode without a word and raises a bare 413 past the
    form size limit, neither of which is an answer this endpoint gives.
    The read is bounded by that same limit, ``MAX_FORM_MEMORY_SIZE`` (read
    from the configuration, since the request attribute is Flask 3.1's;
    unlimited falls back to werkzeug's own default, a bearer form is never
    larger), plus one byte to tell "too large" from "at the limit", and by
    the declared length when there is one; it loops, since a WSGI input
    may answer a read short. A body that ends before its declared length,
    on a server that raises for it and on one that returns short, and one
    werkzeug refuses at the stream for ``MAX_CONTENT_LENGTH``, are bodies
    that used the channel badly, not a bare 400 or 413. A chunked body
    needs a server that terminates the input (``wsgi.input_terminated``,
    as the dev server and gunicorn do); elsewhere werkzeug hands over an
    empty stream and the body is no channel. What a refusal leaves unread
    is the server's to drain, as it is for werkzeug's own 413."""
    configured = current_app.config.get("MAX_FORM_MEMORY_SIZE", 500_000)
    limit = configured if configured is not None else 500_000
    declared = request.content_length
    # One byte past the limit tells "too large" from "at the limit"; a
    # declared length bounds the read further, so a small body does not
    # cost a buffer of the whole limit.
    wanted = limit + 1 if declared is None else min(limit + 1, declared + 1)
    expected = None if declared is None else min(declared, limit + 1)
    chunks: List[bytes] = []
    received = 0
    try:
        while wanted > 0:
            chunk = request.stream.read(wanted)
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            wanted -= len(chunk)
    except ClientDisconnected:
        return _form_token_malformed(
            "form body ended early", "The body ended before its declared length"
        )
    except RequestEntityTooLarge:
        # werkzeug's verdict on MAX_CONTENT_LENGTH: raised at the first
        # touch of the stream for a declared length past it, or by a
        # terminated input asked for the byte past it - which the extra
        # byte above does to a complete body that sits exactly at it. A
        # body received in full is read; anything else is too large.
        if declared is None or received < declared:
            return _form_token_malformed(
                "request body past the content length limit", "The body exceeds the size limit"
            )
    raw = b"".join(chunks)
    if expected is not None and len(raw) < expected:
        # The input ended short of what the request declared. The dev
        # server raises for this (caught above); a server that terminates
        # the input itself just returns short, and the verdict is the same.
        return _form_token_malformed(
            "form body ended early", "The body ended before its declared length"
        )
    if not raw:
        return _NO_FORM_TOKEN
    if len(raw) > limit:
        return _form_token_malformed("form body too large", "The body exceeds the size limit")
    # Parsed through latin-1, which maps every byte to one code point, so
    # the bytes survive the parse on every supported Python (3.10's
    # parse_qsl coerces bytes through ASCII and raises on anything else)
    # and are judged afterwards. RFC 6750 2.2 wants the whole body ASCII;
    # NanoIDP enforces that on the token value and tolerates a non-ASCII
    # field beside it, which is no channel.
    values = [
        value
        for name, value in parse_qsl(
            raw.decode("latin-1"), encoding="latin-1", keep_blank_values=True
        )
        if name == "access_token"
    ]
    if not values:
        return _NO_FORM_TOKEN
    if len(values) > 1:
        return _form_token_malformed("access_token repeated", "access_token is repeated")
    if not values[0]:
        return _form_token_malformed("access_token empty", "access_token is empty")
    if not values[0].isascii():
        return _form_token_malformed(
            "access_token not ASCII", "access_token is not ASCII (RFC 6750 2.2)"
        )
    return _FormToken(present=True, value=values[0])


def _bearer_token_of_request() -> Tuple[Optional[str], Optional[ResponseReturnValue]]:
    """The bearer token a /userinfo request presents, read once (#465):
    ``(token, None)``, or ``(None, refusal)``.

    Three channels are recognised by PRESENCE: the Authorization header
    with the Bearer scheme (bearer_header_credential, shared with the
    registration access token), the ``access_token`` parameter of a
    form-encoded POST body (_form_access_token: only on a method with body
    semantics, only under that content type, bounded), and ``access_token``
    in the query string (2.3). What a channel carries is judged after its
    presence:

    - the query string is refused whatever else the request carries:
      RFC 9700 4.3.2 forbids clients to use it, and NanoIDP says so rather
      than ignoring the parameter (#463's rule);
    - two channels are refused, even with the same token in both (section
      2: "MUST NOT use more than one method");
    - a channel present but malformed - a bare ``Bearer``, an empty or a
      repeated ``access_token``, a body that is not ASCII or exceeds the
      form size limit - is refused, and a valid header beside it is not
      fallen back on;
    - no channel is the challenge alone (section 3).
    """
    if "access_token" in request.args:
        # Refused before anything else is read: the body of a request that
        # is refused anyway is not worth reading.
        return None, _userinfo_refused(
            "access_token in the query string",
            "The access token must not be sent in the query string (RFC 9700 4.3.2)",
        )

    channels: List[str] = []
    malformed: Optional[Tuple[str, str]] = None
    token = ""

    attempted, credential = bearer_header_credential()
    if attempted:
        channels.append("header")
        token = credential
        if not token:
            malformed = ("bearer header without a token", "The Authorization header carries no token")

    if request.method == "POST" and request.mimetype == "application/x-www-form-urlencoded":
        form = _form_access_token()
        if form.present:
            channels.append("body")
        if form.malformed is not None:
            malformed = form.malformed
        elif form.value is not None:
            token = form.value

    if len(channels) > 1:
        return None, _userinfo_refused(
            "more than one token transmission method",
            "The access token was sent by more than one method (RFC 6750 2)",
        )
    if malformed is not None:
        return None, _userinfo_refused(*malformed)
    if not channels:
        return None, _bearer_challenge_alone()
    return token, None


@oauth_bp.route("/userinfo", methods=["GET", "POST"])
@no_store_responses
def userinfo() -> ResponseReturnValue:
    """
    OIDC UserInfo endpoint.
    Returns claims about the authenticated user.
    Requires a valid Bearer token.
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    config = get_config()

    # One reader of the bearer credentials, one shape for every error
    # answer (#465): see _bearer_token_of_request and _bearer_refusal.
    token, refusal = _bearer_token_of_request()
    if refusal is not None:
        return refusal
    assert token is not None

    # Verify token. Settings before the signing service (#359): see
    # get_crypto_service().
    settings = loaded.settings
    crypto = get_crypto_service()
    try:
        # /userinfo is the OP's own protected resource, so a token must be
        # audienced to oauth.audience here (OIDC Core §5.3). A resource-bound
        # access token (#187) carries an RFC 8707 resource as aud and belongs
        # at its resource server, not here - it is used against /introspect
        # by that server instead. A client that needs UserInfo requests a
        # token without a resource.
        payload = crypto.verify_jwt(token, settings.audience)
    except ValueError as e:
        audit_event(
            "userinfo_request",
            "failed",
            endpoint="/userinfo",
            details={"reason": str(e)},
        )
        return _bearer_refusal(401, "invalid_token", "Token validation failed")

    # UserInfo requires an *access* token (OIDC Core §5.3.1). Reject ID/refresh
    # tokens even if they verify against the resource audience (issue #34).
    #
    # Deliberate compat (not strict) choice: we reject tokens *marked* as id/refresh
    # rather than requiring token_use == "access". A validly-signed token without the
    # marker (legacy, or hand-crafted with the IdP key - a first-class workflow for a
    # dev IdP) is still accepted. The security goal still holds: the IdP marks every
    # ID/refresh token it issues, so an ID Token can never be spent as an access token.
    if payload.get("token_use") in ("id", "refresh"):
        audit_event(
            "userinfo_request",
            "failed",
            endpoint="/userinfo",
            details={"reason": "Not an access token", "token_use": payload.get("token_use")},
        )
        return _bearer_refusal(401, "invalid_token", "An access token is required")

    # Check if token is revoked
    jti = payload.get("jti")
    if get_revocation_store().is_revoked(jti):
        audit_event(
            "userinfo_request",
            "failed",
            endpoint="/userinfo",
            details={"reason": "Token has been revoked"},
        )
        return _bearer_refusal(401, "invalid_token", "Token has been revoked")

    # Get user info. A token whose subject is its client has no end user
    # behind it, and is never resolved as a user of the same name (#445).
    username = end_user_of(payload)
    user = identities_for(config, request_config()).get_user(username) if username else None

    # What this token's bearer may see is domain policy, and lives in
    # services/userinfo.py since #303: scope-to-claim gating, the claims
    # nanoidp has no standard scope to gate by, the raw attributes
    # passthrough, and the `claims` request parameter.
    response = build_userinfo_response(
        user,
        subject=payload.get("sub"),
        granted_scope=payload.get("scope"),
        scope_gating_active=settings.userinfo_scope_gating_active,
        requested_claims=payload.get("req_userinfo_claims"),
    )

    audit_event(
        "userinfo_request",
        "success",
        endpoint="/userinfo",
        username=username,
    )

    return jsonify(response)


@oauth_bp.route("/introspect", methods=["POST"])
@no_store_responses
def introspect() -> ResponseReturnValue:
    """
    Token Introspection endpoint (RFC 7662).
    Allows resource servers to validate tokens.
    Requires client authentication.
    """
    config = get_config()

    # Client authentication using the registered token_endpoint_auth_method
    # (#262): the method decides the channel and two auth methods in one
    # request are rejected. RFC 7662 requires client authentication here but
    # leaves the method open; reusing the registered method is nanoidp's
    # consistency policy, not an RFC 7662 mandate. Deliberately NOT relaxed for
    # public clients (RFC 7662 §2.1: this endpoint must resist token scanning,
    # a public client_id is identification not authentication, and 'none' is
    # not in introspection_endpoint_auth_methods_supported).
    identity = _request_client_identity()
    auth = identity.auth
    body_client_secret = identity.body_client_secret
    client_id = identity.client_id
    introspect_client = identities_for(config, request_config()).get_client(client_id) if client_id else None
    if identity.mismatch:
        # One request, two claimed identities (#277) - same rejection as
        # /token, where this check has always lived.
        auth_error: Optional[str] = "client_id in request body does not match Basic username"
    elif introspect_client is not None and introspect_client.is_public:
        auth_error = (
            "public clients cannot authenticate to the introspection endpoint "
            "(RFC 7662 §2.1)"
        )
    else:
        auth_error = _enforce_registered_client_auth(config, client_id, auth, body_client_secret)
    if auth_error is not None:
        audit_event(
            "introspection_request",
            "failed",
            endpoint="/introspect",
            client_id=client_id,
            details={"reason": auth_error},
        )
        return jsonify({"error": "invalid_client"}), 401

    # Get the token to introspect
    token = request.form.get("token")
    if not token:
        return jsonify({"active": False})

    # Try to verify the token (token_type_hint is intentionally ignored: with a
    # single signing key there is nothing to disambiguate, per RFC 7662 §2.1)
    crypto = get_crypto_service()
    try:
        # Resource-bound access tokens (#187) carry an RFC 8707 resource as
        # aud, not oauth.audience; verify signature+expiry, not audience.
        payload = crypto.verify_jwt(token, None)
    except ValueError:
        # Token is invalid or expired
        audit_event(
            "introspection_request",
            "success",
            endpoint="/introspect",
            client_id=client_id,
            details={"active": False, "reason": "Invalid or expired token"},
        )
        return jsonify({"active": False})

    # ID Tokens are OIDC artifacts, not OAuth access/refresh tokens. They must not
    # be reported as active here (or be usable as access tokens) (issue #34).
    if payload.get("token_use") == "id":
        audit_event(
            "introspection_request",
            "success",
            endpoint="/introspect",
            client_id=client_id,
            details={"active": False, "reason": "ID Token is not introspectable"},
        )
        return jsonify({"active": False})

    # Check if revoked: the token's own marker, and for a refresh token its
    # family's (#466; a family is revoked on a code reuse and on the reuse
    # of a rotated refresh token, #56).
    jti = payload.get("jti")
    revocations = get_revocation_store()
    if revocations.is_revoked(jti):
        return jsonify({"active": False})
    if payload.get("token_use") == "refresh" and revocations.is_family_revoked(
        payload.get("rt_family")
    ):
        return jsonify({"active": False})

    # What an introspection reports is RFC 7662 §2.2, and lives in
    # services/introspection.py since #303.
    response = build_introspection_response(payload, client_id)

    audit_event(
        "introspection_request",
        "success",
        endpoint="/introspect",
        client_id=client_id,
        username=end_user_of(payload),
        details={"active": True},
    )

    return jsonify(response)


@oauth_bp.route("/revoke", methods=["POST"])
def revoke() -> ResponseReturnValue:
    """
    Token Revocation endpoint (RFC 7009).
    Allows clients to revoke tokens.
    Requires client authentication.
    """
    config = get_config()

    # Client identification/authentication. Confidential clients present
    # credentials via Basic or client_secret_post; a public client
    # (token_endpoint_auth_method 'none', #188) is identified by client_id
    # alone, and the ownership check below is what stands in for
    # authentication (RFC 7009 §2.1).
    identity = _request_client_identity()
    auth = identity.auth
    body_client_secret = identity.body_client_secret
    client_id = identity.client_id
    revoking_client = identities_for(config, request_config()).get_client(client_id) if client_id else None
    is_public = revoking_client is not None and revoking_client.is_public

    # A confidential client authenticates as at the token endpoint (#262):
    # registered method enforced, two auth methods in one request rejected.
    # A mismatch between Basic and a body client_id is one request claiming
    # two identities (#277) - rejected for public and confidential alike.
    if identity.mismatch or not is_public:
        auth_error = (
            "client_id in request body does not match Basic username"
            if identity.mismatch
            else _enforce_registered_client_auth(config, client_id, auth, body_client_secret)
        )
        if auth_error is not None:
            audit_event(
                "revocation_request",
                "failed",
                endpoint="/revoke",
                client_id=client_id,
                details={"reason": auth_error},
            )
            return jsonify({"error": "invalid_client"}), 401

    # Get the token to revoke
    token = request.form.get("token")
    if not token:
        # RFC 7009 says we should return 200 OK even if token is missing
        return "", 200

    # VERIFY the token's signature before trusting any claim (#254 review,
    # blocking 1). The revocation store is keyed by jti, and the public
    # client's ownership check reads client_id: both must come from a
    # payload nanoidp actually signed, never from an attacker-supplied
    # unsigned JWT. A token that fails verification (bad signature or expired)
    # revokes nothing and still returns 200 - RFC 7009 requires 200 regardless
    # of outcome, and its privacy guidance forbids turning the endpoint into
    # an oracle for a token's validity or owner. Audience is NOT verified: a
    # resource-bound access token (#187) carries an RFC 8707 resource as aud,
    # and the client is still entitled to revoke it.
    crypto = get_crypto_service()
    try:
        payload = crypto.verify_jwt(token, None)
    except ValueError:
        return "", 200

    jti = payload.get("jti")

    # Ownership check for public clients (#188, RFC 7009 §2.1): with no
    # credentials, "this token is mine" is the entire authorization to
    # revoke. Now that the payload is verified, client_id is trustworthy; a
    # token bound to another client is left untouched, response still 200.
    if is_public and payload.get("client_id") != client_id:
        audit_event(
            "revocation_request",
            "failed",
            endpoint="/revoke",
            client_id=client_id,
            details={"reason": "Public client presented a token it does not own"},
        )
        return "", 200

    # A verified nanoidp token always carries a jti (crypto.create_jwt sets
    # one); the audit reflects only what was actually revoked, so a jti-less
    # edge token is not logged as revoked (#254 review, finding 3).
    if jti:
        # The payload is verified, so its exp is the exact horizon the
        # revocation needs remembering (#288) - and a verified payload
        # WITHOUT exp names a token that never expires, which the store
        # remembers indefinitely (three-state contract, #293 round 2).
        get_revocation_store().revoke(jti, expires_at=payload.get("exp"))
        logger.info(f"Token revoked: {jti[:8]}...")
        audit_event(
            "revocation_request",
            "success",
            endpoint="/revoke",
            client_id=client_id,
            username=end_user_of(payload),
            details={"revoked": True},
        )

    # RFC 7009 requires 200 OK response regardless of outcome
    return "", 200


# ============================================================================
# OIDC End Session / Logout (OpenID Connect RP-Initiated Logout 1.0)
# ============================================================================


@oauth_bp.route("/logout", methods=["GET", "POST"])
@oauth_bp.route("/end_session", methods=["GET", "POST"])
def end_session() -> ResponseReturnValue:
    """
    OIDC End Session / Logout endpoint.
    Allows clients to initiate logout.

    Parameters:
    - id_token_hint: Previously issued ID token (optional, helps identify user)
    - post_logout_redirect_uri: URL to redirect after logout (optional)
    - state: CSRF protection state (optional)
    - client_id: Client identifier (optional, required if no id_token_hint)
    """

    # Get parameters from query string or form
    params = request.args if request.method == "GET" else request.form

    id_token_hint = params.get("id_token_hint")
    post_logout_redirect_uri = params.get("post_logout_redirect_uri")
    state = params.get("state")
    client_id = params.get("client_id")

    username = None

    # If id_token_hint is provided, extract user info
    if id_token_hint:
        try:
            payload = pyjwt.decode(id_token_hint, options={"verify_signature": False})
            username = payload.get("sub")

            # Optionally revoke the token. The hint is decoded UNVERIFIED, so
            # NO claim from it - exp included - reaches the store: the store's
            # trust contract (#293 review) is that expires_at comes from a
            # verified payload only; here the bounded default applies.
            jti = payload.get("jti")
            if jti:
                get_revocation_store().revoke(jti)
        except Exception:
            pass  # Invalid token, continue anyway

    # The browser's authenticated session at /authorize ends here (#468),
    # before the cookie that names it goes.
    get_authenticated_session_store().end(browser_flow_binding())
    # Clear session
    session.clear()

    audit_event(
        "logout_request",
        "success",
        endpoint="/logout",
        username=username,
        client_id=client_id,
        details={"has_redirect": bool(post_logout_redirect_uri)},
    )

    logger.info(f"Logout completed for user '{username or 'unknown'}'")

    # Handle redirect (dev tool - no validation needed)
    if post_logout_redirect_uri:
        redirect_url = post_logout_redirect_uri
        if state:
            separator = "&" if "?" in redirect_url else "?"
            redirect_url = f"{redirect_url}{separator}state={state}"
        return redirect(redirect_url)  # noqa: S302 - dev tool, open redirect acceptable

    # No redirect - show logout confirmation page
    return render_template(
        "logout.html",
        message="You have been logged out successfully.",
    )


# ============================================================================
# Device Authorization Grant (RFC 8628)
# ============================================================================


def _device_client(
    config: ConfigManager, loaded: ConfigSnapshot, client_id: Optional[str]
) -> Optional[OAuthClient]:
    """The client for a device authorization request, which is never one
    learned from a metadata document (#196).

    A device code lives ten minutes and is redeemed later, by a different
    request, so it depends on the client still being there - and a cached
    client is kept only for the authorization code issued against it. The
    boundary is drawn where it can be stated simply: the deferred state a
    cached client can be named in is an authorization code, and nothing
    else.

    Not resolved rather than resolved-and-refused, so the endpoint answers
    exactly as it does for a name nobody knows. A distinct refusal here
    would say whether a given URL is in this server's cache, which is
    something the caller cannot otherwise find out.
    """
    if not client_id:
        return None
    resolved = identities_for(config, loaded).resolve_client(client_id)
    if resolved is None or resolved.origin == "cimd":
        return None
    return resolved.client


@oauth_bp.route("/device_authorization", methods=["POST"])
@oauth_bp.route("/device/code", methods=["POST"])
@no_store_responses
def device_authorization() -> ResponseReturnValue:
    """
    Device Authorization endpoint (RFC 8628).
    Initiates the device flow by returning device_code and user_code.

    Client identification:
    - A confidential client authenticates with its registered method.
    - A public client (token_endpoint_auth_method 'none') presents its
      client_id alone, no secret (RFC 8628 §3.1, #255).

    Optional:
    - scope: Requested scopes
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    config = get_config()

    # Client authentication. A confidential client authenticates as at the
    # token endpoint (#262): registered method enforced, two auth methods in
    # one request rejected. A PUBLIC client (token_endpoint_auth_method 'none')
    # presents its client_id alone with no secret (RFC 8628 §3.1, #255): the
    # issued device_code is bound to that client_id and only it can poll for
    # the token, which is what stands in for client authentication here (the
    # same shape as /revoke's public relaxation).
    identity = _request_client_identity()
    auth = identity.auth
    body_client_secret = identity.body_client_secret
    resolved_client_id = identity.client_id
    device_client = _device_client(config, loaded, resolved_client_id)
    if identity.mismatch:
        # One request, two claimed identities (#277) - same rejection as
        # /token, for public and confidential clients alike.
        auth_error: Optional[str] = "client_id in request body does not match Basic username"
    elif device_client is not None and device_client.is_public:
        # RFC 8628 §3.1: a public client provides its client_id as a parameter,
        # not via HTTP Basic or a client_secret. The client_id is public, so
        # this is about using the right channel (as /token enforces the
        # registered method), not secrecy - presenting either is rejected.
        if auth is not None or body_client_secret is not None:
            auth_error = (
                "a public client presents its client_id as a parameter, without "
                "HTTP Basic or a client_secret (RFC 8628 §3.1)"
            )
        else:
            auth_error = None
    else:
        auth_error = _enforce_registered_client_auth(
            config, resolved_client_id, auth, body_client_secret
        )
    if auth_error is not None:
        audit_event(
            "device_authorization_request",
            "failed",
            endpoint="/device_authorization",
            client_id=resolved_client_id,
            details={"reason": auth_error},
        )
        return jsonify({"error": "invalid_client"}), 401

    # check_client fails closed on a missing username, so it is present here;
    # the fallback only narrows the type.
    client_id = resolved_client_id or ""
    requested_scope = request.form.get("scope", "")

    # Scope validation (issue #186), same rule as /authorize including the
    # "openid" default when omitted on an unrestricted client.
    client = identities_for(config, request_config()).get_client(client_id)
    if client is not None:
        scope_result = resolve_scope(
            requested_scope,
            client,
            loaded.settings.scopes_supported,
            loaded.settings.scope_enforcement_active,
            default_when_omitted="openid",
        )
        if not scope_result.ok:
            audit_event(
                "device_authorization_request",
                "failed",
                endpoint="/device_authorization",
                client_id=client_id,
                details={"reason": scope_result.error_description},
            )
            return (
                jsonify(
                    {"error": "invalid_scope", "error_description": scope_result.error_description}
                ),
                400,
            )
        requested_scope = scope_result.granted or ""
    scope = requested_scope

    # Resource indicators (#187): validate and remember them on the device
    # grant, so the polled token binds its aud to them.
    validated_resources = None
    device_resources = request.form.getlist("resource")
    if device_resources and client is not None:
        resource_result = resolve_resources(device_resources, client)
        if not resource_result.ok:
            audit_event(
                "device_authorization_request",
                "failed",
                endpoint="/device_authorization",
                client_id=client_id,
                details={"reason": resource_result.error_description},
            )
            return (
                jsonify(
                    {
                        "error": "invalid_target",
                        "error_description": resource_result.error_description,
                    }
                ),
                400,
            )
        # Store the de-duplicated granted list, not the raw request (#254
        # review, finding 2): a repeated resource must not become a
        # duplicate entry in the token aud.
        validated_resources = resource_result.granted or None

    # Create the device authorization; the store drops stale entries and
    # keeps the user-code index, in the runtime store (#84, #363).
    # A hard cap bounds the in-memory store, which matters now that a public
    # client can create entries with its client_id alone (#255): at capacity,
    # refuse new authorizations rather than grow without bound or evict a live
    # one. Deliberately NOT an OAuth error code: RFC 8628 §3.2 says the device
    # authorization response's errors take the RFC 6749 §5.2 (token endpoint)
    # form, and §5.2 has no registered code for server saturation (server_error
    # is registered for the authorization endpoint only, and slow_down is the
    # token endpoint's POLLING signal, §3.5). So this is a plain HTTP 503 - the
    # correct semantics for a temporary capacity exhaustion - with a message and
    # a Retry-After hint, not a fabricated OAuth token error.
    try:
        device_code, user_code = get_device_code_store().create(
            client_id,
            scope,
            resource=validated_resources,
            expires_in=loaded.settings.device_code_expiry_seconds,
            interval=loaded.settings.device_polling_interval,
        )
    except DeviceCodeStoreFull as not_now:
        # At capacity, or (DeviceCodeStoreBusy) no pair could be made right
        # now: the same "come back" either way.
        if isinstance(not_now, DeviceCodeStoreBusy):
            reason = "could not allocate a device code"
            message = "Could not create a device authorization right now; retry later"
        else:
            reason = "device code store at capacity"
            message = "Too many pending device authorizations; retry later"
        audit_event(
            "device_authorization_request",
            "failed",
            endpoint="/device_authorization",
            client_id=client_id,
            details={"reason": reason},
        )
        response = jsonify({"message": message})
        response.status_code = 503
        response.headers["Retry-After"] = str(loaded.settings.device_polling_interval)
        return response

    audit_event(
        "device_authorization_request",
        "success",
        endpoint="/device_authorization",
        client_id=client_id,
        details={"user_code": user_code, "scope": scope},
    )

    logger.info(f"Device authorization initiated, user_code: {user_code}")

    # Build verification URI. device_verification_base_url overrides the
    # request-derived issuer here so a backend/container caller's Host
    # doesn't leak into a URL the human's own browser can't reach.
    settings = loaded.settings
    verification_base = settings.issuer
    if settings.issuer_from_request:
        verification_base = settings.device_verification_base_url or effective_issuer(settings)
    verification_uri = f"{verification_base}/device"
    verification_uri_complete = f"{verification_uri}?user_code={user_code}"

    return jsonify(
        {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": settings.device_code_expiry_seconds,
            "interval": settings.device_polling_interval,
        }
    )


@oauth_bp.route("/device", methods=["GET", "POST"])
def device_verify() -> ResponseReturnValue:
    """
    Device verification endpoint.
    Users enter their user_code here to authorize the device.

    GET: Show form to enter user_code
    POST: Process user_code and login
    """
    # The configuration this request began with (#406).
    loaded = request_config()
    config = get_config()
    persona_mode = loaded.settings.persona_mode_enabled
    two_step_login = loaded.settings.two_step_login_active

    error_msg = None
    # The user's decision, once one is recorded: "authorized" or "denied".
    # The page shows each as what it is; one success slot for both rendered
    # a denial as an authorization.
    decision: Optional[str] = None
    user_code = request.args.get("user_code", "")
    login_username = ""

    def render_device(
        error: Optional[str],
        *,
        decision: Optional[str] = None,
        pending_second_factor: str = "",
    ) -> ResponseReturnValue:
        # One render for every exit below (#348 review), the same closure
        # /login and /saml/sso already use. A pending second factor (#373)
        # renders the code screen; no_store applied here, not by each caller
        # (#348 review, cleanup), the one place that knows it is rendered.
        totp_step = bool(pending_second_factor)
        response = render_template(
            "device.html",
            user_code=user_code,
            error=error,
            decision=decision,
            persona_mode=persona_mode,
            two_step_login=two_step_login,
            login_username=login_username,
            totp_step=totp_step,
            pending_second_factor=pending_second_factor,
            users=identities_for(config, request_config()).persona_picker_entries(),
        )
        return no_store(response) if totp_step else response

    if request.method == "POST":
        user_code = request.form.get("user_code", "").upper().strip()
        username = request.form.get("username", "").strip()
        password_submitted = "password" in request.form
        password = request.form.get("password", "")
        action = request.form.get("action", "authorize")
        login_username = username
        # The context a pending second factor belongs to (#373).
        second_factor_context = {"user_code": user_code}
        store = get_device_code_store()
        decided_user: Optional[User] = None
        amr = None

        if "change_username" in request.form:
            discard_pending_second_factor(purpose="device", context=second_factor_context)
            login_username = ""
            return render_device(None)

        on_code_screen = bool(request.form.get(PENDING_SECOND_FACTOR_FIELD)) and not password_submitted
        if on_code_screen and (action == "deny" or store.pending_status(user_code) is not None):
            # A deny needs no credentials, and a dead user_code is reported
            # by verify() below exactly as it always has: either way the
            # pending second factor is over. Its username is the one the
            # deny's audit names, as the password form's would.
            username = (
                discard_pending_second_factor(purpose="device", context=second_factor_context)
                or username
            )
        elif on_code_screen:
            continuation = continue_second_factor(
                config, request_config(), purpose="device", context=second_factor_context
            )
            if continuation.error is not None:
                audit_event(
                    "device_verification",
                    "failed",
                    endpoint="/device",
                    username=continuation.username,
                    details={"user_code": user_code, "reason": continuation.reason},
                )
                login_username = ""
                return render_device(continuation.error)
            assert continuation.login is not None and continuation.username is not None
            login_username = continuation.username
            if continuation.pending is not None:
                if continuation.login.phase is SecondFactorPhase.CODE_INVALID:
                    audit_event(
                        "device_verification",
                        "failed",
                        endpoint="/device",
                        username=continuation.username,
                        details={"user_code": user_code, "reason": continuation.login.phase.error},
                    )
                return render_device(
                    continuation.login.phase.error,
                    pending_second_factor=continuation.pending.id,
                )
            decided_user = continuation.login.user
            amr = continuation.login.amr
            username = continuation.username

        # Step detection is shared with every other password-form surface
        # (#323 review round 2, before-merge 5); "deny" needs no
        # credentials at all (services/device_code.py checks it first, on
        # its own), so it folds into the caller's own gate here rather than
        # two_step_phase needing to know about device-specific actions.
        phase = two_step_phase(
            # The code screen is past both steps: its outcome, a verified
            # user or a dead user_code, goes to verify() below.
            two_step_active=(
                two_step_login and action != "deny" and not on_code_screen
            ),
            username=username,
            password=password,
            password_submitted=password_submitted,
        )
        if phase is not TwoStepPhase.ATTEMPT:
            # Username-only step (#322/#323): nothing to authenticate yet,
            # so this must never reach the device-code store - .verify()
            # below is the atomic check-status + transition (#43), and a
            # username-only submission has no business touching a pending
            # code's status. Deliberate trade-off, not an oversight (#323
            # review round 2, nit): the store has no non-mutating "peek at
            # this code's status" lookup, only the atomic verify() that
            # also transitions it - so an invalid or expired user_code is
            # only reported once the password step actually calls verify(),
            # one screen later than the combined form would report it.
            if phase is TwoStepPhase.USERNAME_REQUIRED:
                error_msg = "Username is required"
            elif phase is TwoStepPhase.PASSWORD_REQUIRED:
                error_msg = "Password is required"
            return render_device(error_msg)

        # Message-only: whether this is a "nothing filled in" attempt rather
        # than a wrong selection/credential, so the two outcomes get distinct
        # copy below. The actual auth decision lives in interactive_authenticate().
        missing_input = action != "deny" and not on_code_screen and (
            (persona_mode and not username) or (not persona_mode and (not username or not password))
        )

        # Declarative TOTP second factor (#348), riding the same phase
        # machinery as two_step above. The credential check runs here, once,
        # and only for a code that is pending and live (pending_status is a
        # non-mutating look): a dead user_code must not turn /device into a
        # password oracle, and verify() below reports it exactly as it always
        # has. A code screen returns early WITHOUT touching the store -
        # .verify() is the atomic check-status + transition (#43), and a
        # code-step render has no business touching a pending code's
        # status, exactly like the username-only step above. store.verify()
        # takes the already-resolved user (``None`` on a failed, incomplete,
        # or "deny" attempt) rather than a credential-check callback, so the
        # check above runs exactly once - it used to be rebound only on
        # success via a closure, so a wrong password was checked twice (once
        # here, once by store.verify()'s own call to the original
        # authenticate, serialized inside the store's lock) - under
        # password_hashing that was two bcrypt rounds per attempt instead of
        # one (#348 review, cleanup).
        if (
            not on_code_screen
            and action != "deny"
            and not missing_input
            and store.pending_status(user_code) is None
        ):
            login = authenticate_interactively(config, request_config(), username=username, password=password)
            if login.phase.pending:
                if login.phase is SecondFactorPhase.CODE_INVALID:
                    audit_event(
                        "device_verification",
                        "failed",
                        endpoint="/device",
                        username=username,
                        details={"user_code": user_code, "reason": login.phase.error},
                    )
                # The verified password is recorded server-side, bound to
                # this user_code (#373); the code screen carries its id.
                # A POST carrying the password and the code together
                # completed both above, statelessly, as before.
                pending_id = begin_second_factor(
                    purpose="device", context=second_factor_context, username=username
                )
                if pending_id is None:
                    return render_device(SECOND_FACTOR_STORE_FULL)
                return render_device(login.phase.error, pending_second_factor=pending_id)
            decided_user = login.user
            amr = login.amr

        # The store runs check-status + transition atomically so two
        # concurrent verifications can't both claim the same pending code
        # (issue #43). Persona vs. password login is decided once in
        # interactive_authenticate(), not here.
        outcome, user = store.verify(
            user_code,
            action,
            decided_user,
            amr=amr,
        )
        if outcome is DeviceVerifyOutcome.INVALID_CREDENTIALS and missing_input:
            outcome = DeviceVerifyOutcome.MISSING_CREDENTIALS

        if outcome is DeviceVerifyOutcome.INVALID_CODE:
            error_msg = "Invalid or expired user code"
        elif outcome is DeviceVerifyOutcome.ALREADY_USED:
            error_msg = "This code has already been used"
        elif outcome is DeviceVerifyOutcome.EXPIRED:
            error_msg = "This code has expired"
        elif outcome is DeviceVerifyOutcome.DENIED:
            decision = "denied"
            audit_event(
                "device_verification",
                "denied",
                endpoint="/device",
                username=username,
                details={"user_code": user_code},
            )
        elif outcome is DeviceVerifyOutcome.MISSING_CREDENTIALS:
            error_msg = "Select a user" if persona_mode else "Username and password are required"
        elif outcome is DeviceVerifyOutcome.INVALID_CREDENTIALS:
            error_msg = "Invalid username or password"
            audit_event(
                "device_verification",
                "failed",
                endpoint="/device",
                username=username,
                details={"user_code": user_code, "reason": "Invalid credentials"},
            )
        elif outcome is DeviceVerifyOutcome.AUTHORIZED and user is not None:
            decision = "authorized"
            audit_event(
                "device_verification",
                "success",
                endpoint="/device",
                username=user.username,
                details={"user_code": user_code},
            )
            logger.info(f"Device authorized for user '{user.username}', user_code: {user_code}")

    return render_device(error_msg, decision=decision)
