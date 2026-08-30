"""OAuth /token grant handlers (extracted from routes/oauth.py, #84).

One handler per grant type, each taking a _GrantContext and returning a
_GrantOutcome (issuance parameters) or a Flask error response. token() in
routes/oauth.py does the shared validation and dispatches through
_GRANT_HANDLERS. These handlers depend on lower-level services/models and the
shared route audit helper (._audit), never back on routes.oauth, so the import
stays one-way and there is no cycle.
"""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple, Union

from flask import (
    abort,
    jsonify,
    request,
)
from flask.typing import ResponseReturnValue

from ..config import ConfigManager, OAuthClient, User
from ..services import (
    DevicePollOutcome,
    get_auth_code_store,
    get_crypto_service,
    get_device_code_store,
    get_revocation_store,
)
from ..services.resource import resolve_resources
from ..services.scope import resolve_scope
from ._audit import audit_event


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
    # False for grants with no end user: client_credentials must not hand
    # out a refresh token (RFC 6749 §4.4.3, #239).
    issue_refresh_token: bool = True
    # RFC 8707 resource indicators (#187). ``resource`` is the ACCESS token
    # aud - the (possibly narrowed) subset the /token request asked for.
    # ``refresh_resource`` is what the refresh token remembers: the FULL
    # original grant, so a later refresh can still request any resource the
    # original authorization covered, not only the narrowed subset the last
    # access token used (RFC 8707 §2.2, #254 review). None on either means
    # "no resource"; when refresh_resource is None it falls back to resource
    # (grants with no prior authorization step, where the request IS the
    # original grant).
    resource: Optional[List[str]] = None
    refresh_resource: Optional[List[str]] = None


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


def _resolve_token_resource(
    ctx: _GrantContext, client: Optional[OAuthClient], original: Optional[List[str]]
) -> Tuple[Optional[List[str]], Optional[ResponseReturnValue]]:
    """Resolve RFC 8707 resource indicators for a /token grant (#187).

    ``original`` is the resource set a prior step bound, with a deliberate
    three-way meaning (#254 review, finding 1): ``None`` = there was no prior
    authorization step (client_credentials, password authenticate directly),
    so a requested resource is gated only by ``allowed_resources``; ``[]`` =
    a prior step (an authorization code, a refresh token, a device code)
    bound NO resource, so the request may not introduce one - a token can
    only narrow what was authorized, never widen it (RFC 8707 section 2); a
    non-empty list = the ceiling the request must stay within. A request
    that sends no ``resource`` inherits ``original`` - but re-validated
    against the client's CURRENT ``allowed_resources``, so a resource
    removed from the allow-list after the grant was issued is not still
    minted on a later refresh (#256 review; the scope path re-validates the
    same way with validate_only, #186 B1). Returns
    ``(resource_list_or_None, error_response_or_None)``; an ``invalid_target``
    is an RFC 6749 §5.2-shaped JSON error.
    """
    requested = request.form.getlist("resource")
    if not requested:
        if not original:
            return None, None
        if client is None:
            # No client, no allow-list to enforce: inherit verbatim.
            return list(original), None
        # Re-validate the inherited resources against the current allow-list.
        result = resolve_resources(original, client)
        if not result.ok:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=ctx.client_id,
                details={"reason": result.error_description, "grant_type": ctx.grant_type},
            )
            return None, (
                jsonify(
                    {"error": "invalid_target", "error_description": result.error_description}
                ),
                400,
            )
        return (result.granted or None), None
    if client is None:
        return None, (
            jsonify({"error": "invalid_target", "error_description": "Unknown client"}),
            400,
        )
    result = resolve_resources(requested, client, allowed_subset=original)
    if not result.ok:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={"reason": result.error_description, "grant_type": ctx.grant_type},
        )
        return None, (
            jsonify({"error": "invalid_target", "error_description": result.error_description}),
            400,
        )
    return (result.granted or None), None


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
        # RFC 6749 §5.2 JSON, not Werkzeug HTML (#306 review, per the #287
        # "Error surfaces" rule: protocol endpoints never answer HTML). An
        # unverifiable refresh token - bad signature, expired, or missing
        # the exp the nanoidp token profile requires - is invalid_grant.
        return (
            jsonify(
                {
                    "error": "invalid_grant",
                    "error_description": f"Invalid refresh token: {str(e)}",
                }
            ),
            400,
        )

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
    # (RFC 9700 §4.14, #56). Since 3.0 the binding claim is MANDATORY (#73):
    # a refresh token with no client_id claim - minted before the binding
    # existed (pre-2.2.0/#56) - is refused, ending the transitional compat
    # that let any authenticated client spend such a token until it expired.
    bound_client = payload.get("client_id")
    if not bound_client:
        audit_event(
            "token_request",
            "failed",
            endpoint="/token",
            client_id=ctx.client_id,
            details={
                "reason": "Refresh token has no client_id binding claim",
                "grant_type": ctx.grant_type,
            },
        )
        return (
            jsonify(
                {
                    "error": "invalid_grant",
                    "error_description": (
                        "This refresh token predates client binding and is no "
                        "longer accepted; obtain a new one"
                    ),
                }
            ),
            400,
        )
    if bound_client != ctx.client_id:
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
            return (
                jsonify(
                    {
                        "error": "invalid_scope",
                        "error_description": "Requested scope exceeds originally granted scope",
                    }
                ),
                400,
            )
        scope = requested_scope
    else:
        scope = original_scope or None

    # Re-validate against the vocabulary and this client's allowed_scopes
    # (issue #186): both may have changed since the original grant, so
    # narrowing alone (above) isn't enough to guarantee the refreshed token
    # still only carries scopes this client may currently have.
    # validate_only=True: an absent scope here means the ORIGINAL grant had
    # none (a legacy refresh token predating this setting, or one issued
    # before allowed_scopes was set) - it must stay absent, not be defaulted
    # to the client's current full allowed set, or a refresh could silently
    # GRANT MORE than the original authorization ever did (#186 review, B1).
    client = ctx.config.get_client(ctx.client_id)
    if client is not None:
        scope_result = resolve_scope(
            scope,
            client,
            ctx.config.settings.scopes_supported,
            ctx.config.settings.scope_enforcement_active,
            validate_only=True,
        )
        if not scope_result.ok:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                username=username,
                client_id=ctx.client_id,
                details={
                    "reason": scope_result.error_description,
                    "grant_type": ctx.grant_type,
                },
            )
            return (
                jsonify(
                    {"error": "invalid_scope", "error_description": scope_result.error_description}
                ),
                400,
            )
        scope = scope_result.granted

    # A refreshed ID Token must carry the ORIGINAL authentication time
    # (OIDC Core §12.2), persisted in the refresh token claims (#42).
    auth_time = payload.get("auth_time")

    # Claim names requested via the OIDC `claims` parameter are persisted in
    # the refresh token like scope/auth_time (#112), so the refreshed ID Token
    # keeps the requested claims and the refreshed access token keeps its
    # `req_userinfo_claims` for /userinfo. Tokens minted before #112 carry
    # neither claim and simply refresh without them. Deliberately NOT
    # intersected with a narrowed scope: a claims request binds to the
    # original authorization and §5.5 is orthogonal to scope, so it keeps
    # being honoured when the client narrows the scope on refresh - narrowing
    # sheds scope-derived claims, not claims requested by name. The values are
    # taken as-is here; create_token sanitizes them (a hand-crafted refresh
    # token may carry anything), so issuance below cannot fail on them.
    id_token_claims = payload.get("req_id_token_claims")
    userinfo_claims = payload.get("req_userinfo_claims")

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
    # A public client always rotates (#188, OAuth 2.1 §4.3.1/§6.1): with no
    # client authentication, sender-constraining is unavailable, so one-time
    # refresh tokens with reuse detection are the only leash. Confidential
    # clients follow the refresh_token_rotation setting as before.
    rotation_enabled = ctx.config.settings.rotation_enabled or (
        client is not None and client.is_public
    )
    reuse_detected = get_revocation_store().check_and_claim_refresh(
        jti,
        refresh_family,
        rotation_enabled,
        # The verified refresh token's own exp: the claimed jti needs
        # remembering exactly that long (#288).
        expires_at=payload.get("exp"),
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

    # Resource indicators (#187): the refresh may narrow the bound resources
    # to a subset of what the refresh token remembers, never widen them - a
    # refresh token that bound none ([]) cannot introduce one (#254 review).
    resource, resource_error = _resolve_token_resource(
        ctx, client, payload.get("resource") or []
    )
    if resource_error is not None:
        return resource_error

    return _GrantOutcome(
        user=user,
        username=username,
        scope=scope,
        auth_time=auth_time,
        refresh_family=refresh_family,
        id_token_claims=id_token_claims,
        userinfo_claims=userinfo_claims,
        resource=resource,
        # The rotated refresh token keeps the FULL original grant, not the
        # subset this access token narrowed to (RFC 8707 §2.2, #254 review).
        refresh_resource=payload.get("resource") or None,
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
        return abort(400, description="username and password required for password grant")

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

    # Scope validation (issue #186), same rule as every other grant.
    client = ctx.config.get_client(ctx.client_id)
    requested_scope = request.form.get("scope")
    if client is not None:
        scope_result = resolve_scope(
            requested_scope,
            client,
            ctx.config.settings.scopes_supported,
            ctx.config.settings.scope_enforcement_active,
        )
        if not scope_result.ok:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                username=username,
                client_id=ctx.client_id,
                details={
                    "reason": scope_result.error_description,
                    "grant_type": ctx.grant_type,
                },
            )
            return (
                jsonify(
                    {"error": "invalid_scope", "error_description": scope_result.error_description}
                ),
                400,
            )
        requested_scope = scope_result.granted

    # An authenticated end-user is present, so honour an openid scope and
    # emit an ID Token (issue #36). nonce is non-standard for this grant but
    # accepted as a dev convenience; normalize an empty field to None so we
    # don't emit an empty nonce claim (matches the authorization_code path).
    resource, resource_error = _resolve_token_resource(ctx, client, None)
    if resource_error is not None:
        return resource_error
    return _GrantOutcome(
        user=user,
        username=username,
        nonce=request.form.get("nonce") or None,
        scope=requested_scope,
        resource=resource,
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
            details={
                "reason": "Invalid or expired authorization code",
                "grant_type": ctx.grant_type,
            },
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

    # Re-validate against the vocabulary and this client's allowed_scopes
    # (issue #186): both may have changed between /authorize issuing the
    # code and this exchange, so the check at issuance time isn't enough to
    # guarantee the token still only carries scopes this client may
    # currently have.
    # validate_only=True: an absent scope here means /authorize granted none
    # (not reachable today - it always resolves a non-empty scope before
    # minting a code - but kept safe against a future refactor, same
    # reasoning as the refresh grant's re-check, #186 review B1).
    code_scope: Optional[str] = auth_code.scope if auth_code.scope is not None else None
    client = ctx.config.get_client(ctx.client_id)
    if client is not None:
        scope_result = resolve_scope(
            code_scope,
            client,
            ctx.config.settings.scopes_supported,
            ctx.config.settings.scope_enforcement_active,
            validate_only=True,
        )
        if not scope_result.ok:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                username=username,
                client_id=ctx.client_id,
                details={
                    "reason": scope_result.error_description,
                    "grant_type": ctx.grant_type,
                },
            )
            return (
                jsonify(
                    {"error": "invalid_scope", "error_description": scope_result.error_description}
                ),
                400,
            )
        code_scope = scope_result.granted

    # Resource indicators (#187): the token request may narrow to a subset of
    # what /authorize bound into the code, never widen (RFC 8707 section 2);
    # a code that bound none ([]) cannot introduce one at /token (#254 review).
    resource, resource_error = _resolve_token_resource(
        ctx, client, auth_code.resource or []
    )
    if resource_error is not None:
        return resource_error

    requested_claims = auth_code.claims or {}
    return _GrantOutcome(
        user=user,
        username=username,
        nonce=auth_code.nonce if auth_code.nonce is not None else None,
        scope=code_scope,
        # The user authenticated at the login page when the code was created,
        # not at this token exchange - use that moment as auth_time (#42).
        auth_time=int(auth_code.created_at.timestamp()),
        # Claims the client asked for through the OIDC `claims` parameter (#104).
        id_token_claims=requested_claims.get("id_token"),
        userinfo_claims=requested_claims.get("userinfo"),
        resource=resource,
        # The refresh token keeps the code's FULL original resource set, so a
        # later refresh can still request any resource the authorization
        # covered - not only the subset this access token narrowed to
        # (RFC 8707 §2.2, #254 review).
        refresh_resource=auth_code.resource or None,
    )


def _grant_client_credentials(ctx: _GrantContext) -> GrantResult:
    """client_credentials grant (RFC 6749 §4.4).

    §4.4 makes the 'scope' parameter optional for this grant; before #186 it
    was read nowhere, so a requested scope was silently dropped rather than
    granted or rejected. Validated the same as every other grant now.
    """
    requested_scope = request.form.get("scope")
    client = ctx.config.get_client(ctx.client_id)
    if client is not None:
        scope_result = resolve_scope(
            requested_scope,
            client,
            ctx.config.settings.scopes_supported,
            ctx.config.settings.scope_enforcement_active,
        )
        if not scope_result.ok:
            audit_event(
                "token_request",
                "failed",
                endpoint="/token",
                client_id=ctx.client_id,
                details={
                    "reason": scope_result.error_description,
                    "grant_type": ctx.grant_type,
                },
            )
            return (
                jsonify(
                    {"error": "invalid_scope", "error_description": scope_result.error_description}
                ),
                400,
            )
        requested_scope = scope_result.granted
        if requested_scope:
            # client_credentials has no end-user context (RFC 6749 §4.4 has
            # no ID Token concept), but create_token()'s id_token issuance is
            # grant-agnostic - it mints one whenever 'openid' is in scope, no
            # matter the grant. Accepted at validation (it's a real,
            # vocabulary-listed scope) but silently dropped from what's
            # actually granted, rather than rejected, matching this grant's
            # pre-#186 behavior of never producing an ID Token.
            remaining = [t for t in requested_scope.split() if t != "openid"]
            requested_scope = " ".join(remaining) or None

    # Use default user for client credentials
    default_username = ctx.config.default_user
    user = ctx.config.get_user(default_username)
    if not user:
        # Create a minimal service account user. No password: it never
        # authenticates with one, and User.password rejects "" since #158
        # (min_length=1) - the old empty string made this path a 500 (#241).
        user = User(
            username="service-account",
            password=None,
            roles=["user"],
            tenant="default",
        )
    # RFC 6749 §4.4.3: "A refresh token SHOULD NOT be included." The client
    # authenticates itself on every request; a refresh token here would be a
    # second, 7-day credential bound to the default user (or the synthetic
    # service account) that the grant never authenticated, spendable at
    # grant_type=refresh_token to obtain user-context tokens (#239).
    resource, resource_error = _resolve_token_resource(ctx, client, None)
    if resource_error is not None:
        return resource_error
    return _GrantOutcome(
        user=user,
        username=user.username,
        scope=requested_scope,
        issue_refresh_token=False,
        resource=resource,
    )


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
        return (
            jsonify({"error": "invalid_request", "error_description": "device_code is required"}),
            400,
        )

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
        return jsonify({"error": "invalid_grant", "error_description": "Invalid device code"}), 400
    if outcome is DevicePollOutcome.WRONG_CLIENT:
        return (
            jsonify(
                {
                    "error": "invalid_grant",
                    "error_description": "Device code was not issued to this client",
                }
            ),
            400,
        )
    if outcome is DevicePollOutcome.EXPIRED:
        return (
            jsonify({"error": "expired_token", "error_description": "Device code has expired"}),
            400,
        )
    if outcome is DevicePollOutcome.PENDING:
        return (
            jsonify(
                {
                    "error": "authorization_pending",
                    "error_description": "User has not yet authorized the device",
                }
            ),
            400,
        )
    if outcome is DevicePollOutcome.DENIED:
        return (
            jsonify(
                {
                    "error": "access_denied",
                    "error_description": "User denied the authorization request",
                }
            ),
            400,
        )
    if outcome is DevicePollOutcome.USER_NOT_FOUND:
        return jsonify({"error": "server_error", "error_description": "User not found"}), 500
    if outcome is DevicePollOutcome.AUTHORIZED and user and grant:
        # The device flow authenticates an end-user, so honour the requested
        # scope and emit an ID Token when 'openid' was asked for (issue #36).
        # The user authenticated at /device, not at this poll (#42).
        #
        # Re-validate the stored scope against the CURRENT vocabulary and
        # this client's allowed_scopes (#276): both may have changed between
        # /device_authorization and this poll, exactly as they may change
        # between /authorize and code redemption - the authorization_code and
        # refresh grants both re-check for that reason, and this grant redeems
        # a prior authorization the same way. validate_only=True: an absent
        # stored scope stays absent, never defaulted (#186 review, B1).
        device_scope: Optional[str] = grant.scope
        device_client = ctx.config.get_client(ctx.client_id)
        if device_client is not None:
            scope_result = resolve_scope(
                device_scope,
                device_client,
                ctx.config.settings.scopes_supported,
                ctx.config.settings.scope_enforcement_active,
                validate_only=True,
            )
            if not scope_result.ok:
                audit_event(
                    "token_request",
                    "failed",
                    endpoint="/token",
                    username=user.username,
                    client_id=ctx.client_id,
                    details={
                        "reason": scope_result.error_description,
                        "grant_type": ctx.grant_type,
                    },
                )
                return (
                    jsonify(
                        {
                            "error": "invalid_scope",
                            "error_description": scope_result.error_description,
                        }
                    ),
                    400,
                )
            device_scope = scope_result.granted
        resource, resource_error = _resolve_token_resource(
            ctx, ctx.config.get_client(ctx.client_id), grant.resource or []
        )
        if resource_error is not None:
            return resource_error
        return _GrantOutcome(
            user=user,
            username=user.username,
            scope=device_scope,
            auth_time=grant.auth_time,
            resource=resource,
            # Full original grant on the refresh token (RFC 8707 §2.2).
            refresh_resource=grant.resource or None,
        )
    return (
        jsonify({"error": "server_error", "error_description": "Unknown device code status"}),
        500,
    )


_GRANT_HANDLERS: Dict[str, Callable[[_GrantContext], GrantResult]] = {
    "refresh_token": _grant_refresh_token,
    "password": _grant_password,
    "authorization_code": _grant_authorization_code,
    "client_credentials": _grant_client_credentials,
    "urn:ietf:params:oauth:grant-type:device_code": _grant_device_code,
}
