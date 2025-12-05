"""
OAuth2/OIDC routes for token endpoint and discovery.
"""

import json
import logging
from urllib.parse import urlencode, urlparse
from flask import Blueprint, request, jsonify, abort, redirect, render_template, session, url_for

from ..config import get_config, User
from ..services import get_token_service, get_crypto_service, get_audit_log, get_auth_code_store

logger = logging.getLogger(__name__)

oauth_bp = Blueprint("oauth", __name__)


def _get_request_info():
    """Get request info for audit logging."""
    return {
        "ip_address": request.remote_addr or "unknown",
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }


@oauth_bp.route("/.well-known/openid-configuration")
def oidc_config():
    """OIDC Discovery endpoint."""
    config = get_config()
    settings = config.settings

    return jsonify(
        {
            "issuer": settings.issuer,
            "authorization_endpoint": f"{settings.issuer}/authorize",
            "token_endpoint": f"{settings.issuer}/token",
            "userinfo_endpoint": f"{settings.issuer}/userinfo",
            "introspection_endpoint": f"{settings.issuer}/introspect",
            "revocation_endpoint": f"{settings.issuer}/revoke",
            "end_session_endpoint": f"{settings.issuer}/logout",
            "device_authorization_endpoint": f"{settings.issuer}/device_authorization",
            "jwks_uri": f"{settings.issuer}/.well-known/jwks.json",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "response_types_supported": ["code", "token"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "nbf",
                "email", "email_verified", "preferred_username",
                "roles", "tenant", "identity_class", "entitlements",
                "source_acl", "attributes", "authorities"
            ],
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
                "password",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "code_challenge_methods_supported": ["plain", "S256"],
        }
    )


@oauth_bp.route("/.well-known/jwks.json")
def jwks():
    """JWKS endpoint for JWT verification.

    Returns all keys including previous keys for rotation support.
    """
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)
    return jsonify(crypto.get_jwks())


@oauth_bp.route("/authorize", methods=["GET", "POST"])
def authorize():
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
    audit = get_audit_log()
    req_info = _get_request_info()

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
        audit.log(
            event_type="authorization_request",
            endpoint="/authorize",
            method=request.method,
            status="failed",
            client_id=client_id,
            details={"reason": "Unknown client"},
            **req_info,
        )
        return jsonify({
            "error": "invalid_client",
            "error_description": "Unknown client_id"
        }), 400

    # Validate redirect_uri (basic validation - in production should check against registered URIs)
    try:
        parsed = urlparse(redirect_uri)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
    except Exception:
        return jsonify({
            "error": "invalid_request",
            "error_description": "Invalid redirect_uri"
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

                audit.log(
                    event_type="authorization_request",
                    endpoint="/authorize",
                    method="POST",
                    status="success",
                    username=user.username,
                    client_id=client_id,
                    details={
                        "scope": scope,
                        "pkce": bool(code_challenge),
                    },
                    **req_info,
                )

                logger.info(f"Authorization code issued for user '{user.username}', client '{client_id}'")

                return redirect(callback_url)
            else:
                error_msg = "Invalid username or password"
                audit.log(
                    event_type="authorization_request",
                    endpoint="/authorize",
                    method="POST",
                    status="failed",
                    username=username,
                    client_id=client_id,
                    details={"reason": "Invalid credentials"},
                    **req_info,
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


@oauth_bp.route("/token", methods=["POST"])
def token():
    """OAuth2 token endpoint."""
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    # Check client authentication
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit.log(
            event_type="token_request",
            endpoint="/token",
            method="POST",
            status="failed",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
            **req_info,
        )
        return abort(401, description="Invalid client credentials")

    client_id = auth.username
    grant_type = request.form.get("grant_type", "client_credentials")

    # Refresh token grant
    if grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token", "")
        if not refresh_token:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Missing refresh_token", "grant_type": grant_type},
                **req_info,
            )
            return abort(400, description="refresh_token is required")

        # Verify and decode refresh token
        crypto = get_crypto_service(config.settings.keys_dir)
        try:
            payload = crypto.verify_jwt(refresh_token, config.settings.audience)
        except Exception as e:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={
                    "reason": f"Invalid refresh token: {str(e)}",
                    "grant_type": grant_type,
                },
                **req_info,
            )
            return abort(401, description=f"Invalid refresh token: {str(e)}")

        # Check if it's actually a refresh token
        if payload.get("token_type") != "refresh":
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Not a refresh token", "grant_type": grant_type},
                **req_info,
            )
            return abort(400, description="Invalid token type")

        # Extract username and get user data
        username = payload.get("sub")
        if not username:
            return abort(400, description="Invalid token: missing subject")

        user = config.get_user(username)
        if not user:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                username=username,
                client_id=client_id,
                details={"reason": "User not found", "grant_type": grant_type},
                **req_info,
            )
            return abort(401, description="User not found")

    # Password grant
    elif grant_type == "password":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={
                    "reason": "Missing username or password",
                    "grant_type": grant_type,
                },
                **req_info,
            )
            return abort(
                400, description="username and password required for password grant"
            )

        user = config.authenticate(username, password)
        if not user:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                username=username,
                client_id=client_id,
                details={"reason": "Invalid credentials", "grant_type": grant_type},
                **req_info,
            )
            return abort(401, description="Invalid credentials")

    # Authorization code grant
    elif grant_type == "authorization_code":
        code = request.form.get("code", "")
        redirect_uri = request.form.get("redirect_uri", "")
        code_verifier = request.form.get("code_verifier")  # PKCE

        if not code:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Missing authorization code", "grant_type": grant_type},
                **req_info,
            )
            return abort(400, description="code is required")

        if not redirect_uri:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Missing redirect_uri", "grant_type": grant_type},
                **req_info,
            )
            return abort(400, description="redirect_uri is required")

        # Consume the authorization code
        auth_code_store = get_auth_code_store()
        auth_code = auth_code_store.consume_code(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        if not auth_code:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Invalid or expired authorization code", "grant_type": grant_type},
                **req_info,
            )
            return abort(400, description="Invalid or expired authorization code")

        # Get the user from the authorization code
        username = auth_code.username
        user = config.get_user(username)
        if not user:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                username=username,
                client_id=client_id,
                details={"reason": "User not found", "grant_type": grant_type},
                **req_info,
            )
            return abort(401, description="User not found")

    # Client credentials grant
    elif grant_type == "client_credentials":
        # Use default user for client credentials
        default_username = config.default_user
        user = config.get_user(default_username)
        if not user:
            # Create a minimal service account user
            user = User(
                username="service-account",
                password="",
                roles=["user"],
                tenant="default",
            )
        username = user.username

    # Device code grant (RFC 8628)
    elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        device_code = request.form.get("device_code", "")
        if not device_code:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Missing device_code", "grant_type": grant_type},
                **req_info,
            )
            return jsonify({
                "error": "invalid_request",
                "error_description": "device_code is required"
            }), 400

        # Look up device code
        device_info = _device_codes.get(device_code)
        if not device_info:
            audit.log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="failed",
                client_id=client_id,
                details={"reason": "Invalid device_code", "grant_type": grant_type},
                **req_info,
            )
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Invalid device code"
            }), 400

        # Check client_id matches
        if device_info["client_id"] != client_id:
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Device code was not issued to this client"
            }), 400

        # Check expiration
        import time as time_module
        if time_module.time() > device_info["expires_at"]:
            device_info["status"] = "expired"
            return jsonify({
                "error": "expired_token",
                "error_description": "Device code has expired"
            }), 400

        # Check status
        status = device_info["status"]
        if status == "pending":
            # User hasn't authorized yet - tell client to slow down/retry
            return jsonify({
                "error": "authorization_pending",
                "error_description": "User has not yet authorized the device"
            }), 400
        elif status == "denied":
            # User denied the request
            return jsonify({
                "error": "access_denied",
                "error_description": "User denied the authorization request"
            }), 400
        elif status == "expired":
            return jsonify({
                "error": "expired_token",
                "error_description": "Device code has expired"
            }), 400
        elif status == "authorized":
            # Success! Get the user and issue tokens
            username = device_info["username"]
            user = config.get_user(username)
            if not user:
                return jsonify({
                    "error": "server_error",
                    "error_description": "User not found"
                }), 500

            # Clean up the device code (one-time use)
            user_code = device_info["user_code"]
            del _device_codes[device_code]
            del _device_codes[f"user:{user_code}"]
        else:
            return jsonify({
                "error": "server_error",
                "error_description": "Unknown device code status"
            }), 500

    # Unknown grant type
    else:
        audit.log(
            event_type="token_request",
            endpoint="/token",
            method="POST",
            status="failed",
            client_id=client_id,
            details={"reason": f"Unsupported grant type: {grant_type}", "grant_type": grant_type},
            **req_info,
        )
        return abort(400, description=f"Unsupported grant_type: {grant_type}")

    # Get expiration from request or use default
    exp_minutes = int(request.form.get("exp", config.settings.token_expiry_minutes))

    # Parse extra claims if provided
    extra_claims = None
    extra_raw = request.form.get("extra")
    if extra_raw:
        try:
            extra_claims = json.loads(extra_raw)
        except json.JSONDecodeError:
            return abort(400, description="Invalid JSON in 'extra'")

    # Create token
    token_service = get_token_service()
    token_response = token_service.create_token(
        user=user,
        exp_minutes=exp_minutes,
        extra_claims=extra_claims,
    )

    # Audit log
    audit.log(
        event_type="token_request",
        endpoint="/token",
        method="POST",
        status="success",
        username=username,
        client_id=client_id,
        details={
            "grant_type": grant_type,
            "authorities_count": len(token_service.build_authorities(user)),
        },
        **req_info,
    )

    if config.settings.log_token_requests:
        logger.info(f"Token issued for user '{username}' via {grant_type} grant")

    return jsonify(token_response)


# Token blacklist for revocation (in-memory)
_revoked_tokens: set = set()


def _extract_bearer_token() -> str | None:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


@oauth_bp.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    """
    OIDC UserInfo endpoint.
    Returns claims about the authenticated user.
    Requires a valid Bearer token.
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    # Extract Bearer token
    token = _extract_bearer_token()
    if not token:
        return jsonify({"error": "invalid_token", "error_description": "Missing Bearer token"}), 401

    # Verify token
    crypto = get_crypto_service(config.settings.keys_dir)
    try:
        payload = crypto.verify_jwt(token, config.settings.audience)
    except ValueError as e:
        audit.log(
            event_type="userinfo_request",
            endpoint="/userinfo",
            method=request.method,
            status="failed",
            details={"reason": str(e)},
            **req_info,
        )
        return jsonify({"error": "invalid_token", "error_description": str(e)}), 401

    # Check if token is revoked
    jti = payload.get("jti")
    if jti and jti in _revoked_tokens:
        return jsonify({"error": "invalid_token", "error_description": "Token has been revoked"}), 401

    # Get user info
    username = payload.get("sub")
    user = config.get_user(username) if username else None

    # Build response
    response = {
        "sub": username,
    }

    if user:
        response["email"] = user.email
        response["email_verified"] = True
        response["preferred_username"] = user.username
        response["roles"] = user.roles
        response["tenant"] = user.tenant
        if user.identity_class:
            response["identity_class"] = user.identity_class
        if user.attributes:
            response["attributes"] = user.attributes

    audit.log(
        event_type="userinfo_request",
        endpoint="/userinfo",
        method=request.method,
        status="success",
        username=username,
        **req_info,
    )

    return jsonify(response)


@oauth_bp.route("/introspect", methods=["POST"])
def introspect():
    """
    Token Introspection endpoint (RFC 7662).
    Allows resource servers to validate tokens.
    Requires client authentication.
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    # Check client authentication (Basic auth)
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit.log(
            event_type="introspection_request",
            endpoint="/introspect",
            method="POST",
            status="failed",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
            **req_info,
        )
        return jsonify({"error": "invalid_client"}), 401

    client_id = auth.username

    # Get the token to introspect
    token = request.form.get("token")
    if not token:
        return jsonify({"active": False})

    token_type_hint = request.form.get("token_type_hint", "access_token")

    # Try to verify the token
    crypto = get_crypto_service(config.settings.keys_dir)
    try:
        payload = crypto.verify_jwt(token, config.settings.audience)
    except ValueError:
        # Token is invalid or expired
        audit.log(
            event_type="introspection_request",
            endpoint="/introspect",
            method="POST",
            status="success",
            client_id=client_id,
            details={"active": False, "reason": "Invalid or expired token"},
            **req_info,
        )
        return jsonify({"active": False})

    # Check if revoked
    jti = payload.get("jti")
    if jti and jti in _revoked_tokens:
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

    audit.log(
        event_type="introspection_request",
        endpoint="/introspect",
        method="POST",
        status="success",
        client_id=client_id,
        username=payload.get("sub"),
        details={"active": True},
        **req_info,
    )

    return jsonify(response)


@oauth_bp.route("/revoke", methods=["POST"])
def revoke():
    """
    Token Revocation endpoint (RFC 7009).
    Allows clients to revoke tokens.
    Requires client authentication.
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    # Check client authentication (Basic auth)
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit.log(
            event_type="revocation_request",
            endpoint="/revoke",
            method="POST",
            status="failed",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
            **req_info,
        )
        return jsonify({"error": "invalid_client"}), 401

    client_id = auth.username

    # Get the token to revoke
    token = request.form.get("token")
    if not token:
        # RFC 7009 says we should return 200 OK even if token is missing
        return "", 200

    # Try to decode the token to get its JTI
    crypto = get_crypto_service(config.settings.keys_dir)
    try:
        # Decode without verification to get the JTI
        import jwt as pyjwt
        payload = pyjwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")

        if jti:
            _revoked_tokens.add(jti)
            logger.info(f"Token revoked: {jti[:8]}...")
        else:
            # If no JTI, add the token hash to blacklist
            import hashlib
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            _revoked_tokens.add(token_hash)

        audit.log(
            event_type="revocation_request",
            endpoint="/revoke",
            method="POST",
            status="success",
            client_id=client_id,
            username=payload.get("sub"),
            details={"revoked": True},
            **req_info,
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
def end_session():
    """
    OIDC End Session / Logout endpoint.
    Allows clients to initiate logout.

    Parameters:
    - id_token_hint: Previously issued ID token (optional, helps identify user)
    - post_logout_redirect_uri: URL to redirect after logout (optional)
    - state: CSRF protection state (optional)
    - client_id: Client identifier (optional, required if no id_token_hint)
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    # Get parameters from query string or form
    params = request.args if request.method == "GET" else request.form

    id_token_hint = params.get("id_token_hint")
    post_logout_redirect_uri = params.get("post_logout_redirect_uri")
    state = params.get("state")
    client_id = params.get("client_id")

    username = None

    # If id_token_hint is provided, extract user info
    if id_token_hint:
        crypto = get_crypto_service(config.settings.keys_dir)
        try:
            import jwt as pyjwt
            payload = pyjwt.decode(id_token_hint, options={"verify_signature": False})
            username = payload.get("sub")

            # Optionally revoke the token
            jti = payload.get("jti")
            if jti:
                _revoked_tokens.add(jti)
        except Exception:
            pass  # Invalid token, continue anyway

    # Clear session
    session.clear()

    audit.log(
        event_type="logout_request",
        endpoint="/logout",
        method=request.method,
        status="success",
        username=username,
        client_id=client_id,
        details={"has_redirect": bool(post_logout_redirect_uri)},
        **req_info,
    )

    logger.info(f"Logout completed for user '{username or 'unknown'}'")

    # Handle redirect
    if post_logout_redirect_uri:
        # In production, should validate against registered URIs
        redirect_url = post_logout_redirect_uri
        if state:
            separator = "&" if "?" in redirect_url else "?"
            redirect_url = f"{redirect_url}{separator}state={state}"
        return redirect(redirect_url)

    # No redirect - show logout confirmation page
    return render_template(
        "logout.html",
        message="You have been logged out successfully.",
    )


# ============================================================================
# Device Authorization Grant (RFC 8628)
# ============================================================================

import secrets
import time
from datetime import datetime, timedelta

# In-memory storage for device codes
_device_codes: dict = {}


def _generate_user_code() -> str:
    """Generate a user-friendly code (8 alphanumeric chars, uppercase)."""
    # Use only uppercase letters and digits that are easy to read/type
    # Exclude confusing characters: 0, O, I, 1, L
    chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(chars) for _ in range(8))


def _generate_device_code() -> str:
    """Generate a secure device code."""
    return secrets.token_urlsafe(32)


@oauth_bp.route("/device_authorization", methods=["POST"])
@oauth_bp.route("/device/code", methods=["POST"])
def device_authorization():
    """
    Device Authorization endpoint (RFC 8628).
    Initiates the device flow by returning device_code and user_code.

    Required:
    - Client authentication (Basic auth)

    Optional:
    - scope: Requested scopes
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    # Check client authentication
    auth = request.authorization
    if not auth or not config.check_client(auth.username, auth.password):
        audit.log(
            event_type="device_authorization_request",
            endpoint="/device_authorization",
            method="POST",
            status="failed",
            client_id=auth.username if auth else None,
            details={"reason": "Invalid client credentials"},
            **req_info,
        )
        return jsonify({"error": "invalid_client"}), 401

    client_id = auth.username
    scope = request.form.get("scope", "openid")

    # Generate codes
    device_code = _generate_device_code()
    user_code = _generate_user_code()

    # Device code expires in 10 minutes (600 seconds)
    expires_in = 600
    interval = 5  # Polling interval in seconds

    # Store device code info
    _device_codes[device_code] = {
        "user_code": user_code,
        "client_id": client_id,
        "scope": scope,
        "expires_at": time.time() + expires_in,
        "interval": interval,
        "status": "pending",  # pending, authorized, denied, expired
        "username": None,
    }

    # Also index by user_code for easy lookup during verification
    _device_codes[f"user:{user_code}"] = device_code

    audit.log(
        event_type="device_authorization_request",
        endpoint="/device_authorization",
        method="POST",
        status="success",
        client_id=client_id,
        details={"user_code": user_code, "scope": scope},
        **req_info,
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
        "expires_in": expires_in,
        "interval": interval,
    })


@oauth_bp.route("/device", methods=["GET", "POST"])
def device_verify():
    """
    Device verification endpoint.
    Users enter their user_code here to authorize the device.

    GET: Show form to enter user_code
    POST: Process user_code and login
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    error_msg = None
    success_msg = None
    user_code = request.args.get("user_code", "")

    if request.method == "POST":
        user_code = request.form.get("user_code", "").upper().strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        action = request.form.get("action", "authorize")

        # Look up the device code
        device_code_key = f"user:{user_code}"
        device_code = _device_codes.get(device_code_key)

        if not device_code:
            error_msg = "Invalid or expired user code"
        else:
            device_info = _device_codes.get(device_code)
            if not device_info:
                error_msg = "Invalid or expired user code"
            elif device_info["status"] != "pending":
                error_msg = "This code has already been used"
            elif time.time() > device_info["expires_at"]:
                device_info["status"] = "expired"
                error_msg = "This code has expired"
            elif action == "deny":
                device_info["status"] = "denied"
                success_msg = "Device authorization denied"
                audit.log(
                    event_type="device_verification",
                    endpoint="/device",
                    method="POST",
                    status="denied",
                    username=username,
                    details={"user_code": user_code},
                    **req_info,
                )
            else:
                # Validate user credentials
                if not username or not password:
                    error_msg = "Username and password are required"
                else:
                    user = config.authenticate(username, password)
                    if not user:
                        error_msg = "Invalid username or password"
                        audit.log(
                            event_type="device_verification",
                            endpoint="/device",
                            method="POST",
                            status="failed",
                            username=username,
                            details={"user_code": user_code, "reason": "Invalid credentials"},
                            **req_info,
                        )
                    else:
                        # Authorization successful
                        device_info["status"] = "authorized"
                        device_info["username"] = user.username
                        success_msg = "Device authorized successfully! You can close this window."

                        audit.log(
                            event_type="device_verification",
                            endpoint="/device",
                            method="POST",
                            status="success",
                            username=user.username,
                            details={"user_code": user_code},
                            **req_info,
                        )
                        logger.info(f"Device authorized for user '{user.username}', user_code: {user_code}")

    return render_template(
        "device.html",
        user_code=user_code,
        error=error_msg,
        success=success_msg,
    )
