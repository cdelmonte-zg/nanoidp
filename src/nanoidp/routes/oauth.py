"""
OAuth2/OIDC routes for token endpoint and discovery.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import jwt as pyjwt
from flask import (
    Blueprint,
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

from ..branding import effective_logos_dir, resolve_client_logo
from ..config import ConfigManager, OAuthClient, get_config
from ..services import (
    DeviceVerifyOutcome,
    build_discovery_document,
    get_auth_code_store,
    get_crypto_service,
    get_device_code_store,
    get_revocation_store,
    get_token_service,
)
from ..services.device_code import DEVICE_CODE_EXPIRES_IN, DEVICE_POLL_INTERVAL
from ..services.discovery import issuer_qualifies_for_iss_parameter
from ..services.redirect_uri import (
    append_authorization_params,
    redirect_uri_is_registered,
    redirect_uri_rejection_reason,
)
from ..services.resource import resolve_resources
from ..services.scope import resolve_scope
from ..services.token import resolve_user_claim, sanitize_claim_names
from ._audit import audit_event
from ._issuer import effective_issuer
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


@oauth_bp.route("/.well-known/openid-configuration")
def oidc_config() -> ResponseReturnValue:
    """OIDC Discovery endpoint."""
    config = get_config()
    return jsonify(
        build_discovery_document(config.settings, issuer=effective_issuer(config.settings))
    )


@oauth_bp.route("/.well-known/jwks.json")
def jwks() -> ResponseReturnValue:
    """JWKS endpoint for JWT verification.

    Returns all keys including previous keys for rotation support.
    """
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)
    return jsonify(crypto.get_jwks())


@dataclass
class _AuthorizeParams:
    """The nine /authorize request parameters, read once per request.

    On GET they come from the query string; on the login-form POST leg they
    come from the form with the session as fallback (the GET leg stored them
    there). ``scope`` starts as the raw request value and is replaced by the
    resolved/granted value once _validate_authorize_scope has run.
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


def _read_authorize_params() -> _AuthorizeParams:
    """Extract the request parameters and persist them for the POST leg.

    Storing on GET happens before any validation, exactly as it always has:
    an invalid request still leaves its parameters in the session, and the
    login POST leg re-validates everything from scratch.
    """
    params = request.args if request.method == "GET" else request.form

    p = _AuthorizeParams(
        response_type=params.get("response_type", session.get("oauth_response_type", "")),
        client_id=params.get("client_id", session.get("oauth_client_id", "")),
        redirect_uri=params.get("redirect_uri", session.get("oauth_redirect_uri", "")),
        scope=params.get("scope", session.get("oauth_scope", "")),
        state=params.get("state", session.get("oauth_state", "")),
        code_challenge=params.get("code_challenge", session.get("oauth_code_challenge", "")),
        code_challenge_method=params.get(
            "code_challenge_method", session.get("oauth_code_challenge_method", "")
        ),
        nonce=params.get("nonce", session.get("oauth_nonce", "")),
        claims_param=params.get("claims", session.get("oauth_claims", "")),
        # RFC 8707 resource is repeatable (#187): read every value, not one.
        resources=params.getlist("resource") or session.get("oauth_resources", []),
    )

    if request.method == "GET":
        session["oauth_response_type"] = p.response_type
        session["oauth_client_id"] = p.client_id
        session["oauth_redirect_uri"] = p.redirect_uri
        session["oauth_scope"] = p.scope
        session["oauth_state"] = p.state
        session["oauth_code_challenge"] = p.code_challenge
        session["oauth_code_challenge_method"] = p.code_challenge_method
        session["oauth_nonce"] = p.nonce
        session["oauth_claims"] = p.claims_param
        session["oauth_resources"] = p.resources

    return p


def _authorize_reject(
    client_id: str, reason: str, error: str, description: str
) -> ResponseReturnValue:
    """Audit-then-reject, the shape every post-client-lookup check shares.

    The pre-lookup checks (response_type, missing client_id/redirect_uri,
    redirect_uri syntax) intentionally do NOT audit - they never have - so
    they build their responses directly instead of calling this.
    """
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        client_id=client_id,
        details={"reason": reason},
    )
    return jsonify({"error": error, "error_description": description}), 400


def _authorize_error_redirect(
    config: ConfigManager, p: _AuthorizeParams, error: str, description: str, reason: str
) -> ResponseReturnValue:
    """Deliver an authorization error to the client through the ALREADY
    VALIDATED redirect_uri (RFC 6749 §4.1.2.1), carrying iss so the client
    can still detect an authorization-server mix-up on an error (#189/RFC
    9207 §2: iss appears on error responses too). Only reachable after
    _validate_authorize_redirect_uri has run, so this never redirects to an
    unvalidated URI - errors before that stay local (see _authorize_reject).
    """
    audit_event(
        "authorization_request",
        "failed",
        endpoint="/authorize",
        client_id=p.client_id,
        details={"reason": reason},
    )
    params = {"error": error, "error_description": description}
    if p.state:
        params["state"] = p.state
    issuer = effective_issuer(config.settings)
    if issuer_qualifies_for_iss_parameter(issuer):
        params["iss"] = issuer
    return redirect(append_authorization_params(p.redirect_uri, params))


def _validate_authorize_client(
    config: ConfigManager, p: _AuthorizeParams
) -> Tuple[Optional[OAuthClient], Optional[ResponseReturnValue]]:
    """Required-parameter checks and client lookup: (client, None) or (None, error).

    response_type is NOT checked here: it is validated after the redirect_uri
    is trusted (#258 review), so an unsupported_response_type on a valid
    redirect_uri is delivered as an error redirect, not a local JSON."""
    if not p.client_id:
        return None, (
            jsonify({"error": "invalid_request", "error_description": "client_id is required"}),
            400,
        )

    if not p.redirect_uri:
        return None, (
            jsonify({"error": "invalid_request", "error_description": "redirect_uri is required"}),
            400,
        )

    client = config.get_client(p.client_id)
    if not client:
        return None, _authorize_reject(
            p.client_id, "Unknown client", "invalid_client", "Unknown client_id"
        )
    return client, None


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
    scope_result = resolve_scope(
        p.scope,
        client,
        config.settings.scopes_supported,
        config.settings.scope_enforcement_active,
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
    rejection = redirect_uri_rejection_reason(p.redirect_uri)
    if rejection is not None:
        return jsonify({"error": "invalid_request", "error_description": rejection}), 400

    if client.redirect_uris and not redirect_uri_is_registered(
        p.redirect_uri, client.redirect_uris
    ):
        return _authorize_reject(
            p.client_id,
            "redirect_uri not registered for client",
            "invalid_request",
            "redirect_uri is not registered for this client",
        )

    if config.settings.security_profile == "oauth21" and not client.redirect_uris:
        return _authorize_reject(
            p.client_id,
            "oauth21 profile requires registered redirect_uris",
            "invalid_request",
            "the oauth21 profile requires this client to have " "registered redirect_uris",
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

    if config.settings.pkce_required and not p.code_challenge:
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
    if effective_method == "plain" and not config.settings.pkce_plain_allowed:
        return _authorize_error_redirect(
            config,
            p,
            "invalid_request",
            "code_challenge_method 'plain' (including the "
            "implicit default when the parameter is omitted) "
            f"is not allowed by the {config.settings.security_profile} "
            "profile; use S256",
            "PKCE method 'plain' rejected by " f"{config.settings.security_profile} profile",
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


def _handle_authorize_login(
    config: ConfigManager, p: _AuthorizeParams
) -> Tuple[Optional[str], Optional[ResponseReturnValue]]:
    """The POST login leg: (None, redirect) on success, (error_msg, None) to
    fall through to the login page (failed or incomplete credentials)."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    persona_mode = config.settings.persona_mode_enabled

    user = config.interactive_authenticate(username, password)

    if user:
        # Authentication successful - generate authorization code
        auth_code_store = get_auth_code_store()
        code = auth_code_store.create_code(
            client_id=p.client_id,
            redirect_uri=p.redirect_uri,
            username=user.username,
            scope=p.scope,
            code_challenge=p.code_challenge if p.code_challenge else None,
            code_challenge_method=p.code_challenge_method if p.code_challenge_method else None,
            nonce=p.nonce if p.nonce else None,
            state=p.state if p.state else None,
            claims=_parse_claims_parameter(p.claims_param),
            resource=list(p.resources) if p.resources else None,
        )

        # Clear OAuth session data
        for key in list(session.keys()):
            if key.startswith("oauth_"):
                session.pop(key, None)

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
        issuer = effective_issuer(config.settings)
        if issuer_qualifies_for_iss_parameter(issuer):
            redirect_params["iss"] = issuer

        callback_url = append_authorization_params(p.redirect_uri, redirect_params)

        audit_event(
            "authorization_request",
            "success",
            endpoint="/authorize",
            username=user.username,
            client_id=p.client_id,
            details={
                "scope": p.scope,
                "pkce": bool(p.code_challenge),
            },
        )

        if config.settings.verbose_logging:
            logger.info(
                f"Authorization code issued for user '{user.username}', client '{p.client_id}'"
            )
        else:
            logger.info("Authorization code issued")

        return None, redirect(callback_url)

    if (persona_mode and username) or (not persona_mode and username and password):
        # A real (failed) selection/login attempt, not just missing input
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            username=username,
            client_id=p.client_id,
            details={"reason": "Invalid credentials"},
        )
        return "Invalid username or password", None

    return ("Select a user" if persona_mode else "Username and password are required"), None


def _render_authorize_login(
    config: ConfigManager,
    p: _AuthorizeParams,
    client: Optional[OAuthClient],
    error_msg: Optional[str],
) -> ResponseReturnValue:
    """The login page (GET, or a POST that did not authenticate)."""
    logo_url = None
    if client:
        logos_dir = effective_logos_dir(config.settings.logos_dir, current_app.static_folder)
        if resolve_client_logo(logos_dir, client.client_id):
            logo_url = url_for("oauth.client_logo", client_id=client.client_id)

    return render_template(
        "authorize.html",
        client_id=p.client_id,
        client=client,
        logo_url=logo_url,
        scope=p.scope,
        error=error_msg,
        persona_mode=config.settings.persona_mode_enabled,
        users=config.persona_picker_entries(),
    )


@oauth_bp.route("/authorize", methods=["GET", "POST"])
def authorize() -> ResponseReturnValue:
    """
    OAuth2 Authorization endpoint.
    Supports Authorization Code Flow with optional PKCE.

    GET: Display login page or process already logged-in user
    POST: Process login form submission

    Required parameters:
    - response_type: "code" for Authorization Code Flow
    - client_id: OAuth client ID
    - redirect_uri: Callback URL

    Optional parameters:
    - scope: Space-separated scopes (default: "openid")
    - state: CSRF protection (recommended)
    - code_challenge: PKCE challenge
    - code_challenge_method: "plain" or "S256"
    - nonce: OIDC nonce for ID token

    Each step below is a named helper; every rejection keeps its historical
    error body and audit behavior (#212).
    """
    config = get_config()
    p = _read_authorize_params()

    client, error = _validate_authorize_client(config, p)
    if error is not None:
        return error
    assert client is not None  # _validate_authorize_client returns one or the other

    # redirect_uri is validated BEFORE scope/PKCE/resource (#189/RFC 9207):
    # an unvalidated redirect_uri keeps its local error (never redirect to
    # it), but once it is trusted, every later error is delivered to the
    # client as an OAuth error redirect carrying iss (#258 review).
    error = _validate_authorize_redirect_uri(config, p, client)
    if error is not None:
        return error
    error = _validate_authorize_response_type(config, p)
    if error is not None:
        return error
    error = _validate_authorize_scope(config, p, client)
    if error is not None:
        return error
    error = _validate_authorize_pkce(config, p, client)
    if error is not None:
        return error
    error = _validate_authorize_resources(config, p, client)
    if error is not None:
        return error

    error_msg = None
    if request.method == "POST":
        error_msg, response = _handle_authorize_login(config, p)
        if response is not None:
            return response

    return _render_authorize_login(config, p, client, error_msg)


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
    config = get_config()
    logos_dir = effective_logos_dir(config.settings.logos_dir, current_app.static_folder)
    filename = resolve_client_logo(logos_dir, client_id)
    if not filename:
        abort(404)
    return send_from_directory(os.path.abspath(logos_dir), filename)


# ============================================================================
# Token endpoint: shared validation in token(), one handler per grant (#84)
# ============================================================================


def _token_auth_failed(client_id: Optional[str], reason: str) -> ResponseReturnValue:
    audit_event(
        "token_request",
        "failed",
        endpoint="/token",
        client_id=client_id,
        details={"reason": reason},
    )
    return jsonify({"error": "invalid_client", "error_description": reason}), 401


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
    token_client = config.get_client(client_id)

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
    return _token_auth_failed(client_id, reason) if reason is not None else None


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
    client = config.get_client(client_id) if client_id else None
    method = client.token_endpoint_auth_method if client is not None else "client_secret_basic"

    # client_secret_post: credentials in the body only; Basic is rejected.
    if method == "client_secret_post":
        if auth is not None:
            return (
                "This client's token_endpoint_auth_method is "
                "'client_secret_post'; use client_id and client_secret in the "
                "request body, not HTTP Basic"
            )
        if not body_client_secret or not config.check_client(client_id, body_client_secret):
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
    if not config.check_client(auth.username, auth.password):
        return "Invalid client credentials"
    return None


@oauth_bp.route("/token", methods=["POST"])
def token() -> ResponseReturnValue:
    """OAuth2 token endpoint: shared validation, then per-grant dispatch."""
    config = get_config()

    auth = request.authorization
    grant_type = request.form.get("grant_type", "client_credentials")
    body_client_id = request.form.get("client_id")
    # client_secret_post (RFC 6749 §2.3.1, #188): discovery has always
    # advertised it; the body secret is now actually validated instead of
    # silently ignored.
    body_client_secret = request.form.get("client_secret") or None
    auth_client_id = auth.username if auth else None
    client_id = body_client_id or auth_client_id

    # Reject if client identity cannot be determined at all
    if not client_id:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            details={"reason": "Client authentication required", "grant_type": grant_type},
        )
        return abort(401, description="Client authentication required")

    # Reject if body client_id conflicts with the authenticated client in the header
    if auth and body_client_id and auth.username != body_client_id:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=auth.username,
            details={"reason": "client_id mismatch", "body_client_id": body_client_id},
        )
        return abort(
            401, description="client_id in request body does not match authenticated client"
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
        exp_minutes = int(request.form.get("exp", config.settings.token_expiry_minutes))
    except (TypeError, ValueError):
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=client_id,
            details={"reason": "Invalid 'exp' parameter", "grant_type": grant_type},
        )
        return abort(400, description="'exp' must be an integer number of minutes")
    # Same bounds the Settings model enforces for token_expiry_minutes
    if not 1 <= exp_minutes <= 1440:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=client_id,
            details={"reason": "'exp' out of range", "grant_type": grant_type},
        )
        return abort(400, description="'exp' must be between 1 and 1440 minutes")

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
            return abort(400, description="Invalid JSON in 'extra'")
        # Any JSON scalar/array parses fine but is not a claims mapping
        if not isinstance(parsed_extra, dict):
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=client_id,
                details={"reason": "'extra' is not a JSON object", "grant_type": grant_type},
            )
            return abort(400, description="'extra' must be a JSON object")
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
        return abort(400, description=f"Unsupported grant_type: {grant_type}")

    ctx = _GrantContext(
        config=config,
        client_id=client_id,
        grant_type=grant_type,
    )
    result = handler(ctx)
    if not isinstance(result, _GrantOutcome):
        return result

    # Create token ('exp' and 'extra' were validated before the grant dispatch
    # so the rotation claim in the refresh handler is the last thing that can
    # reject)
    token_service = get_token_service()
    token_response = token_service.create_token(
        user=result.user,
        exp_minutes=exp_minutes,
        extra_claims=extra_claims,
        nonce=result.nonce,
        scope=result.scope,
        client_id=client_id,
        auth_time=result.auth_time,
        refresh_family=result.refresh_family,
        id_token_claims=result.id_token_claims,
        userinfo_claims=result.userinfo_claims,
        issuer=effective_issuer(config.settings),
        issue_refresh_token=result.issue_refresh_token,
        resource=result.resource,
        refresh_resource=result.refresh_resource,
    )

    # Audit log
    audit_event(
        "token_request",
        "success",
        endpoint="/token",
        username=result.username,
        client_id=client_id,
        details={
            "grant_type": grant_type,
            "authorities_count": len(token_service.build_authorities(result.user)),
        },
    )

    if config.settings.log_token_requests:
        logger.info(f"Token issued for user '{result.username}' via {grant_type} grant")

    return jsonify(token_response)


def _extract_bearer_token() -> str | None:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


@oauth_bp.route("/userinfo", methods=["GET", "POST"])
def userinfo() -> ResponseReturnValue:
    """
    OIDC UserInfo endpoint.
    Returns claims about the authenticated user.
    Requires a valid Bearer token.
    """
    config = get_config()

    # Extract Bearer token
    token = _extract_bearer_token()
    if not token:
        return jsonify({"error": "invalid_token", "error_description": "Missing Bearer token"}), 401

    # Verify token
    crypto = get_crypto_service(config.settings.keys_dir)
    try:
        # /userinfo is the OP's own protected resource, so a token must be
        # audienced to oauth.audience here (OIDC Core §5.3). A resource-bound
        # access token (#187) carries an RFC 8707 resource as aud and belongs
        # at its resource server, not here - it is used against /introspect
        # by that server instead. A client that needs UserInfo requests a
        # token without a resource.
        payload = crypto.verify_jwt(token, config.settings.audience)
    except ValueError as e:
        audit_event(
            "userinfo_request",
            "failed",
            endpoint="/userinfo",
            details={"reason": str(e)},
        )
        return (
            jsonify({"error": "invalid_token", "error_description": "Token validation failed"}),
            401,
        )

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
        return (
            jsonify({"error": "invalid_token", "error_description": "An access token is required"}),
            401,
        )

    # Check if token is revoked
    jti = payload.get("jti")
    if get_revocation_store().is_revoked(jti):
        return (
            jsonify({"error": "invalid_token", "error_description": "Token has been revoked"}),
            401,
        )

    # Get user info
    username = payload.get("sub")
    user = config.get_user(username) if username else None

    # Build response
    response = {
        "sub": username,
    }

    if user:
        # Standard OIDC scope-to-claim gating (OIDC Core §5.4): the email and
        # profile claims are only returned when the matching scope was granted.
        # Enforced only under the stricter profiles; the permissive `dev`
        # default keeps returning them unconditionally so this is not a breaking
        # change for existing setups (#102). The granted scope is read from the
        # access token's `scope` claim (RFC 9068 §2.2.3).
        granted_scopes = set((payload.get("scope") or "").split())
        strict_scopes = config.settings.security_profile in ("stricter-dev", "oauth21")

        # The scope-gated standard claims and the nanoidp-specific claims below
        # all resolve through resolve_user_claim - the same resolver that backs
        # the `claims` request parameter - so those two mappings cannot diverge
        # (#113). A claim the resolver cannot supply is omitted. The raw
        # `attributes` passthrough further down is the one deliberate
        # exception: the whole dict is not a resolvable claim name.
        def _put(claim_name: str) -> None:
            found, value = resolve_user_claim(user, claim_name)
            if found:
                response[claim_name] = value

        if not strict_scopes or "email" in granted_scopes:
            _put("email")
            _put("email_verified")
        if not strict_scopes or "profile" in granted_scopes:
            _put("preferred_username")

        # nanoidp-specific claims have no standard OIDC scope, so they are always
        # returned for a valid token; gating them would be arbitrary and has no
        # spec basis (#102).
        _put("roles")
        _put("groups")
        _put("tenant")
        _put("identity_class")
        if user.attributes:
            response["attributes"] = user.attributes

        # Honour the UserInfo member of the OIDC `claims` request parameter
        # (§5.5, #104): claim names the client asked for are added even when
        # scope-gating above would have omitted them, provided nanoidp can
        # supply them. Never overwrites a claim already set. Sanitized because
        # the value comes straight from the token payload, which may be
        # hand-crafted (a malformed value must not 500 the endpoint).
        for claim_name in sanitize_claim_names(payload.get("req_userinfo_claims")) or []:
            if claim_name not in response:
                _put(claim_name)

    audit_event(
        "userinfo_request",
        "success",
        endpoint="/userinfo",
        username=username,
    )

    return jsonify(response)


@oauth_bp.route("/introspect", methods=["POST"])
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
    auth = request.authorization
    body_client_id = request.form.get("client_id")
    body_client_secret = request.form.get("client_secret") or None
    client_id = (auth.username if auth else None) or body_client_id
    introspect_client = config.get_client(client_id) if client_id else None
    if introspect_client is not None and introspect_client.is_public:
        auth_error: Optional[str] = (
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
    crypto = get_crypto_service(config.settings.keys_dir)
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

    # Check if revoked
    jti = payload.get("jti")
    if get_revocation_store().is_revoked(jti):
        return jsonify({"active": False})

    # Token is valid - return introspection response. RFC 7662 §2.2:
    # client_id is the client the TOKEN was issued to, not the caller doing
    # the introspection - the access token carries that claim since #188.
    # Fall back to the caller only for a legacy token without the claim.
    response = {
        "active": True,
        "token_type": "Bearer",
        "client_id": payload.get("client_id", client_id),
        "username": payload.get("sub"),
        "sub": payload.get("sub"),
        "aud": payload.get("aud"),
        "iss": payload.get("iss"),
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
        "nbf": payload.get("nbf"),
    }

    # Add scope if present
    if "scope" in payload:
        response["scope"] = payload["scope"]
    else:
        response["scope"] = "openid"

    audit_event(
        "introspection_request",
        "success",
        endpoint="/introspect",
        client_id=client_id,
        username=payload.get("sub"),
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
    auth = request.authorization
    body_client_id = request.form.get("client_id")
    body_client_secret = request.form.get("client_secret") or None
    client_id = (auth.username if auth else None) or body_client_id
    revoking_client = config.get_client(client_id) if client_id else None
    is_public = revoking_client is not None and revoking_client.is_public

    # A confidential client authenticates as at the token endpoint (#262):
    # registered method enforced, two auth methods in one request rejected.
    if not is_public:
        auth_error = _enforce_registered_client_auth(config, client_id, auth, body_client_secret)
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
    crypto = get_crypto_service(config.settings.keys_dir)
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
        get_revocation_store().revoke(jti)
        logger.info(f"Token revoked: {jti[:8]}...")
        audit_event(
            "revocation_request",
            "success",
            endpoint="/revoke",
            client_id=client_id,
            username=payload.get("sub"),
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

            # Optionally revoke the token
            jti = payload.get("jti")
            if jti:
                get_revocation_store().revoke(jti)
        except Exception:
            pass  # Invalid token, continue anyway

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


@oauth_bp.route("/device_authorization", methods=["POST"])
@oauth_bp.route("/device/code", methods=["POST"])
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
    config = get_config()

    # Client authentication. A confidential client authenticates as at the
    # token endpoint (#262): registered method enforced, two auth methods in
    # one request rejected. A PUBLIC client (token_endpoint_auth_method 'none')
    # presents its client_id alone with no secret (RFC 8628 §3.1, #255): the
    # issued device_code is bound to that client_id and only it can poll for
    # the token, which is what stands in for client authentication here (the
    # same shape as /revoke's public relaxation).
    auth = request.authorization
    body_client_id = request.form.get("client_id")
    body_client_secret = request.form.get("client_secret") or None
    resolved_client_id = (auth.username if auth else None) or body_client_id
    device_client = config.get_client(resolved_client_id) if resolved_client_id else None
    if device_client is not None and device_client.is_public:
        auth_error: Optional[str] = None
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
    client = config.get_client(client_id)
    if client is not None:
        scope_result = resolve_scope(
            requested_scope,
            client,
            config.settings.scopes_supported,
            config.settings.scope_enforcement_active,
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

    # Create the device authorization; the store prunes stale entries and
    # keeps the user-code index internally (#84, previously module globals).
    device_code, user_code = get_device_code_store().create(
        client_id, scope, resource=validated_resources
    )

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
    settings = config.settings
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
            "expires_in": DEVICE_CODE_EXPIRES_IN,
            "interval": DEVICE_POLL_INTERVAL,
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
    config = get_config()
    persona_mode = config.settings.persona_mode_enabled

    error_msg = None
    success_msg = None
    user_code = request.args.get("user_code", "")

    if request.method == "POST":
        user_code = request.form.get("user_code", "").upper().strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        action = request.form.get("action", "authorize")

        # Message-only: whether this is a "nothing filled in" attempt rather
        # than a wrong selection/credential, so the two outcomes get distinct
        # copy below. The actual auth decision lives in interactive_authenticate().
        missing_input = action != "deny" and (
            (persona_mode and not username) or (not persona_mode and (not username or not password))
        )

        # The store runs check-status + transition atomically so two
        # concurrent verifications can't both claim the same pending code
        # (issue #43); credential validation happens inside its lock, as
        # it did when this logic lived here. Persona vs. password login is
        # decided once in interactive_authenticate(), not here.
        outcome, user = get_device_code_store().verify(
            user_code,
            action,
            username,
            password,
            config.interactive_authenticate,
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
            success_msg = "Device authorization denied"
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
            success_msg = "Device authorized successfully! You can close this window."
            audit_event(
                "device_verification",
                "success",
                endpoint="/device",
                username=user.username,
                details={"user_code": user_code},
            )
            logger.info(f"Device authorized for user '{user.username}', user_code: {user_code}")

    return render_template(
        "device.html",
        user_code=user_code,
        error=error_msg,
        success=success_msg,
        persona_mode=persona_mode,
        users=config.persona_picker_entries(),
    )
