"""
OAuth2/OIDC routes for token endpoint and discovery.
"""

import json
import logging
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union
from urllib.parse import urlencode, urlparse

import jwt as pyjwt
from flask import Blueprint, abort, jsonify, redirect, render_template, request, session
from flask.typing import ResponseReturnValue

from ..config import ConfigManager, User, get_config
from ..services import (
    DevicePollOutcome,
    DeviceVerifyOutcome,
    build_discovery_document,
    get_auth_code_store,
    get_crypto_service,
    get_device_code_store,
    get_revocation_store,
    get_token_service,
)
from ..services.device_code import DEVICE_CODE_EXPIRES_IN, DEVICE_POLL_INTERVAL
from ..services.token import resolve_user_claim
from ._audit import audit_event

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
    return jsonify(build_discovery_document(config.settings))


@oauth_bp.route("/.well-known/jwks.json")
def jwks() -> ResponseReturnValue:
    """JWKS endpoint for JWT verification.

    Returns all keys including previous keys for rotation support.
    """
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)
    return jsonify(crypto.get_jwks())


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
    """
    config = get_config()

    # Get OAuth parameters (from query string for GET, form for POST)
    if request.method == "GET":
        params = request.args
    else:
        # For POST, check form first, then fall back to session
        params = request.form

    response_type = params.get("response_type", session.get("oauth_response_type", ""))
    client_id = params.get("client_id", session.get("oauth_client_id", ""))
    redirect_uri = params.get("redirect_uri", session.get("oauth_redirect_uri", ""))
    scope = params.get("scope", session.get("oauth_scope", "openid"))
    state = params.get("state", session.get("oauth_state", ""))
    code_challenge = params.get("code_challenge", session.get("oauth_code_challenge", ""))
    code_challenge_method = params.get("code_challenge_method", session.get("oauth_code_challenge_method", ""))
    nonce = params.get("nonce", session.get("oauth_nonce", ""))
    claims_param = params.get("claims", session.get("oauth_claims", ""))

    # Store OAuth params in session for POST handling
    if request.method == "GET":
        session["oauth_response_type"] = response_type
        session["oauth_client_id"] = client_id
        session["oauth_redirect_uri"] = redirect_uri
        session["oauth_scope"] = scope
        session["oauth_state"] = state
        session["oauth_code_challenge"] = code_challenge
        session["oauth_code_challenge_method"] = code_challenge_method
        session["oauth_nonce"] = nonce
        session["oauth_claims"] = claims_param

    # Validate required parameters
    if response_type != "code":
        return jsonify({
            "error": "unsupported_response_type",
            "error_description": "Only 'code' response_type is supported"
        }), 400

    if not client_id:
        return jsonify({
            "error": "invalid_request",
            "error_description": "client_id is required"
        }), 400

    if not redirect_uri:
        return jsonify({
            "error": "invalid_request",
            "error_description": "redirect_uri is required"
        }), 400

    # Validate client exists
    client = config.get_client(client_id)
    if not client:
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            client_id=client_id,
            details={"reason": "Unknown client"},
        )
        return jsonify({
            "error": "invalid_client",
            "error_description": "Unknown client_id"
        }), 400

    # Syntactic validation: must at least parse as an absolute URL.
    try:
        parsed = urlparse(redirect_uri)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
    except Exception:
        return jsonify({
            "error": "invalid_request",
            "error_description": "Invalid redirect_uri"
        }), 400

    # Exact matching against registered redirect URIs (issue #67). RFC 6749
    # §3.1.2.3 / OAuth 2.1 §4.1.1 require simple string comparison - no
    # prefix, host or path normalization. Clients without registered URIs
    # keep the permissive dev behavior (hardening is opt-in, principle 3).
    # A mismatch MUST NOT redirect (§3.1.2.4): the error is returned
    # directly, never sent to the unvalidated URI.
    if client.redirect_uris and redirect_uri not in client.redirect_uris:
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            client_id=client_id,
            details={"reason": "redirect_uri not registered for client"},
        )
        return jsonify({
            "error": "invalid_request",
            "error_description": "redirect_uri is not registered for this client"
        }), 400

    # Under the oauth21 profile, registration is not optional: a client used
    # at /authorize must have redirect_uris pinned (#68; OAuth 2.1 §2.3
    # requires the AS to compare against registered values, which presumes
    # they exist). Enforced here, not at config load, so other grants keep
    # working for unregistered clients.
    if config.settings.security_profile == "oauth21" and not client.redirect_uris:
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            client_id=client_id,
            details={"reason": "oauth21 profile requires registered redirect_uris"},
        )
        return jsonify({
            "error": "invalid_request",
            "error_description": "the oauth21 profile requires this client to have "
                                 "registered redirect_uris"
        }), 400

    # PKCE enforcement (issues #47, #68). Via the require_pkce setting (on by
    # default in the stricter-dev profile) or implied by the oauth21 profile
    # (OAuth 2.1 §4.1.1 makes PKCE mandatory), an authorization request
    # without a code_challenge is rejected, so developers can verify their
    # client actually sends PKCE.
    if config.settings.pkce_required and not code_challenge:
        audit_event(
            "authorization_request",
            "failed",
            endpoint="/authorize",
            client_id=client_id,
            details={"reason": "PKCE code_challenge required (require_pkce or oauth21)"},
        )
        return jsonify({
            "error": "invalid_request",
            "error_description": "PKCE code_challenge is required "
                                 "(require_pkce setting or oauth21 profile)"
        }), 400

    if code_challenge:
        # RFC 7636 §4.3: an omitted code_challenge_method defaults to 'plain',
        # and the verifier honors that - so the method must be normalized
        # BEFORE validation or the stricter-dev rejection could be bypassed by
        # simply omitting the parameter (#56). Unsupported methods are
        # rejected at the authorization endpoint per §4.4.1.
        effective_method = code_challenge_method or "plain"
        if effective_method not in ("plain", "S256"):
            audit_event(
                "authorization_request",
                "failed",
                endpoint="/authorize",
                client_id=client_id,
                details={"reason": f"Unsupported code_challenge_method: {effective_method}"},
            )
            return jsonify({
                "error": "invalid_request",
                "error_description": f"Unsupported code_challenge_method "
                                     f"'{effective_method}'; use S256 or plain"
            }), 400

        # The 'plain' method is only acceptable when S256 is unavailable
        # (RFC 7636 §4.2); the stricter-dev (#47) and oauth21 (#68, OAuth 2.1
        # §7.5.2) profiles reject it outright, whether requested explicitly
        # or via the implicit default.
        if (
            effective_method == "plain"
            and not config.settings.pkce_plain_allowed
        ):
            audit_event(
                "authorization_request",
                "failed",
                endpoint="/authorize",
                client_id=client_id,
                details={
                    "reason": "PKCE method 'plain' rejected by "
                    f"{config.settings.security_profile} profile"
                },
            )
            return jsonify({
                "error": "invalid_request",
                "error_description": "code_challenge_method 'plain' (including the "
                                     "implicit default when the parameter is omitted) "
                                     f"is not allowed by the {config.settings.security_profile} "
                                     "profile; use S256"
            }), 400

    error_msg = None

    # Handle POST (login form submission)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username and password:
            user = config.authenticate(username, password)
            if user:
                # Authentication successful - generate authorization code
                auth_code_store = get_auth_code_store()
                code = auth_code_store.create_code(
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    username=user.username,
                    scope=scope,
                    code_challenge=code_challenge if code_challenge else None,
                    code_challenge_method=code_challenge_method if code_challenge_method else None,
                    nonce=nonce if nonce else None,
                    state=state if state else None,
                    claims=_parse_claims_parameter(claims_param),
                )

                # Clear OAuth session data
                for key in list(session.keys()):
                    if key.startswith("oauth_"):
                        session.pop(key, None)

                # Build redirect URL with code
                redirect_params = {"code": code}
                if state:
                    redirect_params["state"] = state

                callback_url = f"{redirect_uri}?{urlencode(redirect_params)}"

                audit_event(
                    "authorization_request",
                    "success",
                    endpoint="/authorize",
                    username=user.username,
                    client_id=client_id,
                    details={
                        "scope": scope,
                        "pkce": bool(code_challenge),
                    },
                )

                if config.settings.verbose_logging:
                    logger.info(f"Authorization code issued for user '{user.username}', client '{client_id}'")
                else:
                    logger.info("Authorization code issued")

                return redirect(callback_url)
            else:
                error_msg = "Invalid username or password"
                audit_event(
                    "authorization_request",
                    "failed",
                    endpoint="/authorize",
                    username=username,
                    client_id=client_id,
                    details={"reason": "Invalid credentials"},
                )
        else:
            error_msg = "Username and password are required"

    # Show login page (GET or failed POST)
    return render_template(
        "authorize.html",
        client_id=client_id,
        scope=scope,
        error=error_msg,
    )


# ============================================================================
# Token endpoint: shared validation in token(), one handler per grant (#84)
# ============================================================================


@dataclass
class _GrantOutcome:
    """Issuance parameters a grant handler hands back to token()."""

    user: User
    username: str
    nonce: Optional[str] = None
    scope: Optional[str] = None
    auth_time: Optional[int] = None
    refresh_family: Optional[str] = None
    # Claim names requested via the OIDC `claims` parameter (§5.5, #104).
    id_token_claims: Optional[list] = None
    userinfo_claims: Optional[list] = None


@dataclass
class _GrantContext:
    """Request-scoped facts shared by every grant handler."""

    config: ConfigManager
    # token() rejects requests without a client identity before dispatching,
    # so handlers always see a concrete id.
    client_id: str
    grant_type: str


# A handler returns either issuance parameters or a finished error response.
GrantResult = Union[_GrantOutcome, ResponseReturnValue]


def _grant_refresh_token(ctx: _GrantContext) -> GrantResult:
    """refresh_token grant (RFC 6749 §6; rotation per RFC 9700 §4.14)."""
    refresh_token = request.form.get("refresh_token", "")
    if not refresh_token:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Missing refresh_token", "grant_type": ctx.grant_type},
        )
        return abort(400, description="refresh_token is required")

    # Verify and decode refresh token
    crypto = get_crypto_service(ctx.config.settings.keys_dir)
    try:
        payload = crypto.verify_jwt(refresh_token, ctx.config.settings.audience)
    except Exception as e:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={
                "reason": f"Invalid refresh token: {str(e)}",
                "grant_type": ctx.grant_type,
            },
        )
        return abort(401, description=f"Invalid refresh token: {str(e)}")

    # Check if it's actually a refresh token
    if payload.get("token_type") != "refresh":
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Not a refresh token", "grant_type": ctx.grant_type},
        )
        return abort(400, description="Invalid token type")

    # A refresh token may only be spent by the client it was issued to
    # (RFC 9700 §4.14, #56). The binding claim was added in #56; tokens
    # minted before it carry no client_id and stay usable (legacy compat).
    bound_client = payload.get("client_id")
    if bound_client and bound_client != ctx.client_id:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={
                "reason": "Refresh token was issued to a different client",
                "grant_type": ctx.grant_type,
                "bound_client": bound_client,
            },
        )
        return abort(401, description="Refresh token was not issued to this client")

    # Extract username and get user data
    username = payload.get("sub")
    if not username:
        return abort(400, description="Invalid token: missing subject")

    user = ctx.config.get_user(username)
    if not user:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            username=username,
            client_id=ctx.client_id,
            details={"reason": "User not found", "grant_type": ctx.grant_type},
        )
        return abort(401, description="User not found")

    # Recover the originally granted scope persisted in the refresh token
    # so an ID Token is re-issued when 'openid' was granted (OIDC Core
    # §12.2, issue #39). A 'scope' form parameter may narrow, but never
    # broaden, the original grant (RFC 6749 §6). Refresh tokens minted
    # before scope was persisted carry no scope claim and keep the old
    # behavior: tokens are refreshed without an ID Token. The refreshed
    # ID Token intentionally carries no nonce - that claim binds the
    # original authentication request, not later refreshes.
    original_scope = payload.get("scope") or ""
    requested_scope = request.form.get("scope")
    scope: Optional[str]
    if requested_scope:
        granted = set(original_scope.split())
        rejected = [s for s in requested_scope.split() if s not in granted]
        if rejected:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                username=username,
                client_id=ctx.client_id,
                details={
                    "reason": "Requested scope exceeds originally granted scope",
                    "grant_type": ctx.grant_type,
                    "rejected_scopes": rejected,
                },
            )
            return abort(
                400, description="Requested scope exceeds originally granted scope"
            )
        scope = requested_scope
    else:
        scope = original_scope or None

    # A refreshed ID Token must carry the ORIGINAL authentication time
    # (OIDC Core §12.2), persisted in the refresh token claims (#42).
    auth_time = payload.get("auth_time")

    # The family id survives rotation so descendants share it (#56).
    refresh_family = payload.get("rt_family")

    # Revocation check and (with rotation) consumption of this token, as a
    # single check-and-claim under the store's lock: two concurrent refreshes
    # of the same token can no longer both pass the check and both rotate
    # (#56). Reuse of an already-consumed token is treated as leakage and
    # revokes the whole family - attacker's copy and legitimate descendant
    # alike (RFC 9700 §4.14.2). This call sits after every validation that
    # may reject the request (binding, user, scope narrowing - and the
    # grant-independent 'exp'/'extra' params, validated before the grant
    # dispatch), so a rejected request never consumes the token: from here
    # on, issuance is local signing and cannot fail.
    jti = payload.get("jti")
    reuse_detected = get_revocation_store().check_and_claim_refresh(
        jti, refresh_family, ctx.config.settings.rotation_enabled
    )
    if reuse_detected:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            username=username,
            client_id=ctx.client_id,
            details={
                "reason": "Refresh token revoked (rotated, reused, or family revoked)",
                "grant_type": ctx.grant_type,
            },
        )
        return abort(401, description="Refresh token has been revoked")

    return _GrantOutcome(
        user=user,
        username=username,
        scope=scope,
        auth_time=auth_time,
        refresh_family=refresh_family,
    )


def _grant_password(ctx: _GrantContext) -> GrantResult:
    """password grant (RFC 6749 §4.3; removed by OAuth 2.1)."""
    # OAuth 2.1 removes the resource-owner password grant entirely; under
    # the oauth21 profile it is rejected (RFC 6749 §5.2) and absent from
    # the discovery document's grant_types_supported (#68).
    if not ctx.config.settings.password_grant_enabled:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={
                "reason": "password grant disabled by the oauth21 profile",
                "grant_type": ctx.grant_type,
            },
        )
        return abort(
            400,
            description="Unsupported grant_type: the password grant is "
            "disabled by the oauth21 profile",
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={
                "reason": "Missing username or password",
                "grant_type": ctx.grant_type,
            },
        )
        return abort(
            400, description="username and password required for password grant"
        )

    user = ctx.config.authenticate(username, password)
    if not user:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            username=username,
            client_id=ctx.client_id,
            details={"reason": "Invalid credentials", "grant_type": ctx.grant_type},
        )
        return abort(401, description="Invalid credentials")

    # An authenticated end-user is present, so honour an openid scope and
    # emit an ID Token (issue #36). nonce is non-standard for this grant but
    # accepted as a dev convenience; normalize an empty field to None so we
    # don't emit an empty nonce claim (matches the authorization_code path).
    return _GrantOutcome(
        user=user,
        username=username,
        nonce=request.form.get("nonce") or None,
        scope=request.form.get("scope"),
    )


def _grant_authorization_code(ctx: _GrantContext) -> GrantResult:
    """authorization_code grant (RFC 6749 §4.1, PKCE per RFC 7636)."""
    code = request.form.get("code", "")
    redirect_uri = request.form.get("redirect_uri", "")
    code_verifier = request.form.get("code_verifier")  # PKCE

    if not code:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Missing authorization code", "grant_type": ctx.grant_type},
        )
        return abort(400, description="code is required")

    if not redirect_uri:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Missing redirect_uri", "grant_type": ctx.grant_type},
        )
        return abort(400, description="redirect_uri is required")

    # Consume the authorization code
    auth_code_store = get_auth_code_store()
    auth_code = auth_code_store.consume_code(
        code=code,
        client_id=ctx.client_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )

    if not auth_code:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Invalid or expired authorization code", "grant_type": ctx.grant_type},
        )
        return abort(400, description="Invalid or expired authorization code")

    # Get the user from the authorization code
    username = auth_code.username
    user = ctx.config.get_user(username)
    if not user:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            username=username,
            client_id=ctx.client_id,
            details={"reason": "User not found", "grant_type": ctx.grant_type},
        )
        return abort(401, description="User not found")

    requested_claims = auth_code.claims or {}
    return _GrantOutcome(
        user=user,
        username=username,
        nonce=auth_code.nonce if auth_code.nonce is not None else None,
        scope=auth_code.scope if auth_code.scope is not None else None,
        # The user authenticated at the login page when the code was created,
        # not at this token exchange - use that moment as auth_time (#42).
        auth_time=int(auth_code.created_at.timestamp()),
        # Claims the client asked for through the OIDC `claims` parameter (#104).
        id_token_claims=requested_claims.get("id_token"),
        userinfo_claims=requested_claims.get("userinfo"),
    )


def _grant_client_credentials(ctx: _GrantContext) -> GrantResult:
    """client_credentials grant (RFC 6749 §4.4)."""
    # Use default user for client credentials
    default_username = ctx.config.default_user
    user = ctx.config.get_user(default_username)
    if not user:
        # Create a minimal service account user
        user = User(
            username="service-account",
            password="",
            roles=["user"],
            tenant="default",
        )
    return _GrantOutcome(user=user, username=user.username)


def _grant_device_code(ctx: _GrantContext) -> GrantResult:
    """device_code grant (RFC 8628 §3.4/§3.5)."""
    device_code = request.form.get("device_code", "")
    if not device_code:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Missing device_code", "grant_type": ctx.grant_type},
        )
        return jsonify({
            "error": "invalid_request",
            "error_description": "device_code is required"
        }), 400

    # The store runs the whole lookup-check-claim sequence under its lock so
    # two concurrent polls can't both claim the same authorized code
    # (one-time use, issue #43).
    outcome, user, grant = get_device_code_store().poll(
        device_code, ctx.client_id, ctx.config.get_user
    )

    if outcome is DevicePollOutcome.NOT_FOUND:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": "Invalid device_code", "grant_type": ctx.grant_type},
        )
        return jsonify({
            "error": "invalid_grant",
            "error_description": "Invalid device code"
        }), 400
    if outcome is DevicePollOutcome.WRONG_CLIENT:
        return jsonify({
            "error": "invalid_grant",
            "error_description": "Device code was not issued to this client"
        }), 400
    if outcome is DevicePollOutcome.EXPIRED:
        return jsonify({
            "error": "expired_token",
            "error_description": "Device code has expired"
        }), 400
    if outcome is DevicePollOutcome.PENDING:
        return jsonify({
            "error": "authorization_pending",
            "error_description": "User has not yet authorized the device"
        }), 400
    if outcome is DevicePollOutcome.DENIED:
        return jsonify({
            "error": "access_denied",
            "error_description": "User denied the authorization request"
        }), 400
    if outcome is DevicePollOutcome.USER_NOT_FOUND:
        return jsonify({
            "error": "server_error",
            "error_description": "User not found"
        }), 500
    if outcome is DevicePollOutcome.AUTHORIZED and user and grant:
        # The device flow authenticates an end-user, so honour the requested
        # scope and emit an ID Token when 'openid' was asked for (issue #36).
        # The user authenticated at /device, not at this poll (#42).
        return _GrantOutcome(
            user=user,
            username=user.username,
            scope=grant.scope,
            auth_time=grant.auth_time,
        )
    return jsonify({
        "error": "server_error",
        "error_description": "Unknown device code status"
    }), 500


_GRANT_HANDLERS: Dict[str, Callable[[_GrantContext], GrantResult]] = {
    "refresh_token": _grant_refresh_token,
    "password": _grant_password,
    "authorization_code": _grant_authorization_code,
    "client_credentials": _grant_client_credentials,
    "urn:ietf:params:oauth:grant-type:device_code": _grant_device_code,
}


@oauth_bp.route("/token", methods=["POST"])
def token() -> ResponseReturnValue:
    """OAuth2 token endpoint: shared validation, then per-grant dispatch."""
    config = get_config()

    auth = request.authorization
    grant_type = request.form.get("grant_type", "client_credentials")
    body_client_id = request.form.get("client_id")
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
        return abort(401, description="client_id in request body does not match authenticated client")

    # For grant types that require client authentication, enforce it
    if not auth and grant_type != "authorization_code":
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=client_id,
            details={"reason": "Client authentication required", "grant_type": grant_type},
        )
        return abort(401, description="Client authentication required")

    # Check client authentication
    if auth and not config.check_client(auth.username, auth.password):
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
        )
        return abort(401, description="Invalid client credentials")

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
        payload = crypto.verify_jwt(token, config.settings.audience)
    except ValueError as e:
        audit_event(
            "userinfo_request",
            "failed",
            endpoint="/userinfo",
            details={"reason": str(e)},
        )
        return jsonify({"error": "invalid_token", "error_description": "Token validation failed"}), 401

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
        return jsonify({"error": "invalid_token", "error_description": "An access token is required"}), 401

    # Check if token is revoked
    jti = payload.get("jti")
    if get_revocation_store().is_revoked(jti):
        return jsonify({"error": "invalid_token", "error_description": "Token has been revoked"}), 401

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

        if not strict_scopes or "email" in granted_scopes:
            response["email"] = user.email
            response["email_verified"] = True
        if not strict_scopes or "profile" in granted_scopes:
            response["preferred_username"] = user.username

        # nanoidp-specific claims have no standard OIDC scope, so they are always
        # returned for a valid token; gating them would be arbitrary and has no
        # spec basis (#102).
        response["roles"] = user.roles
        response["tenant"] = user.tenant
        if user.identity_class:
            response["identity_class"] = user.identity_class
        if user.attributes:
            response["attributes"] = user.attributes

        # Honour the UserInfo member of the OIDC `claims` request parameter
        # (§5.5, #104): claim names the client asked for are added even when
        # scope-gating above would have omitted them, provided nanoidp can
        # supply them. Never overwrites a claim already set.
        for claim_name in payload.get("req_userinfo_claims") or []:
            if claim_name not in response:
                found, value = resolve_user_claim(user, claim_name)
                if found:
                    response[claim_name] = value

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

    # Check client authentication (Basic auth)
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit_event(
            "introspection_request",
            "failed",
            endpoint="/introspect",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
        )
        return jsonify({"error": "invalid_client"}), 401

    client_id = auth.username

    # Get the token to introspect
    token = request.form.get("token")
    if not token:
        return jsonify({"active": False})

    # Try to verify the token (token_type_hint is intentionally ignored: with a
    # single signing key there is nothing to disambiguate, per RFC 7662 §2.1)
    crypto = get_crypto_service(config.settings.keys_dir)
    try:
        payload = crypto.verify_jwt(token, config.settings.audience)
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

    # Token is valid - return introspection response
    response = {
        "active": True,
        "token_type": "Bearer",
        "client_id": client_id,
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

    # Check client authentication (Basic auth)
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit_event(
            "revocation_request",
            "failed",
            endpoint="/revoke",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
        )
        return jsonify({"error": "invalid_client"}), 401

    client_id = auth.username

    # Get the token to revoke
    token = request.form.get("token")
    if not token:
        # RFC 7009 says we should return 200 OK even if token is missing
        return "", 200

    # Try to decode the token to get its JTI
    try:
        # Decode without verification to get the JTI
        payload = pyjwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")

        if jti:
            get_revocation_store().revoke(jti)
            logger.info(f"Token revoked: {jti[:8]}...")
        else:
            # If no JTI, add the token hash to blacklist
            import hashlib
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            get_revocation_store().revoke(token_hash)

        audit_event(
            "revocation_request",
            "success",
            endpoint="/revoke",
            client_id=client_id,
            username=payload.get("sub"),
            details={"revoked": True},
        )

    except Exception:
        # Even if we can't decode, we return 200 OK per RFC 7009
        pass

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

    Required:
    - Client authentication (Basic auth)

    Optional:
    - scope: Requested scopes
    """
    config = get_config()

    # Check client authentication
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit_event(
            "device_authorization_request",
            "failed",
            endpoint="/device_authorization",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
        )
        return jsonify({"error": "invalid_client"}), 401

    # check_client fails closed on a missing username, so it is present here;
    # the fallback only narrows the type.
    client_id = auth.username or ""
    scope = request.form.get("scope", "openid")

    # Create the device authorization; the store prunes stale entries and
    # keeps the user-code index internally (#84, previously module globals).
    device_code, user_code = get_device_code_store().create(client_id, scope)

    audit_event(
        "device_authorization_request",
        "success",
        endpoint="/device_authorization",
        client_id=client_id,
        details={"user_code": user_code, "scope": scope},
    )

    logger.info(f"Device authorization initiated, user_code: {user_code}")

    # Build verification URI
    verification_uri = f"{config.settings.issuer}/device"
    verification_uri_complete = f"{verification_uri}?user_code={user_code}"

    return jsonify({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": DEVICE_CODE_EXPIRES_IN,
        "interval": DEVICE_POLL_INTERVAL,
    })


@oauth_bp.route("/device", methods=["GET", "POST"])
def device_verify() -> ResponseReturnValue:
    """
    Device verification endpoint.
    Users enter their user_code here to authorize the device.

    GET: Show form to enter user_code
    POST: Process user_code and login
    """
    config = get_config()

    error_msg = None
    success_msg = None
    user_code = request.args.get("user_code", "")

    if request.method == "POST":
        user_code = request.form.get("user_code", "").upper().strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        action = request.form.get("action", "authorize")

        # The store runs check-status + transition atomically so two
        # concurrent verifications can't both claim the same pending code
        # (issue #43); credential validation happens inside its lock, as
        # it did when this logic lived here.
        outcome, user = get_device_code_store().verify(
            user_code, action, username, password, config.authenticate
        )

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
            error_msg = "Username and password are required"
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
    )
