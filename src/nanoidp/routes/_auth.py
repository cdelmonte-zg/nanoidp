"""
Login-gate helper for ui_bp (opt-in, off by default - see require_ui_login
in models.py), the management_secret mutation gate shared by ui_bp, api_bp
and the MCP server (opt-in, off by default - see management_secret in
models.py), and the two-step login phase shared by every interactive
password-form surface (#322/#323 review round 2).
"""

import hashlib
import hmac
from enum import Enum

from flask import current_app, jsonify, redirect, request, session, url_for
from flask.typing import ResponseReturnValue

from ..config import get_config

# Re-exported: verify_secret moved to the framework-free nanoidp.security
# (#286) so the stdio MCP process stops importing Flask to reach it; this
# module stays the import path its own callers and tests already use.
from ..security import verify_secret  # noqa: F401


class TwoStepPhase(str, Enum):
    """Where a login submission stands under two-step (#322/#323 review
    round 2, before-merge 5): derived purely from what THIS request's form
    carries, never from session state - the single home every password-form
    surface (/authorize, /login, /saml/sso, /device) shares, so they cannot
    independently drift on the rule. Round 1's half-consumed combined POST
    was exactly the kind of drift a fifth hand-written copy would risk
    again.
    """

    ATTEMPT = "attempt"  # a password was submitted: authenticate now
    USERNAME_REQUIRED = "username_required"  # the username-only step was resubmitted blank
    PASSWORD_REQUIRED = "password_required"  # the password step was resubmitted blank
    USERNAME_STEP = "username_step"  # nothing to authenticate yet: render the next screen


def two_step_phase(
    *,
    two_step_active: bool,
    username: str,
    password: str,
    password_submitted: bool,
    username_submitted: bool = True,
) -> TwoStepPhase:
    """Classify a login submission under two-step; each caller keeps its
    own transport (render vs. redirect, which fields it reads).

    ``two_step_active`` is the caller's own gate - already combining
    ``Settings.two_step_login_active`` with anything surface-specific (the
    device flow's "deny needs no credentials" carve-out). When it's False
    the answer is always ATTEMPT, unconditionally - true for the combined
    form too, which makes this safe to call regardless of what the request
    carries.

    A blank username is rejected before a submitted password is even
    considered: a tampered POST that pairs an empty username with a
    password would otherwise short-circuit straight to ATTEMPT and
    authenticate (or audit a failed login) against username='' instead of
    answering USERNAME_REQUIRED like every other blank-username submission
    (#322/#323 review round 3, before-merge 1). Only once a username is
    present does a submitted password mean ATTEMPT: a request that already
    carries both fields authenticates directly rather than being
    half-consumed as the username-only step (#323 review round 1,
    blocking 1).

    ``username_submitted`` defaults to True: every caller but one only ever
    reaches this function from a POST whose username-only form always
    carries the field (even blank), so "blank" and "absent" are the same
    thing there. SAML's inline login is the exception - it serves a fresh,
    field-less SAMLRequest through this same code path (GET or POST binding
    both lack a username field entirely), and passes ``"username" in
    request.form`` explicitly so a genuinely fresh request renders the
    blank username screen instead of a spurious "Username is required".
    """
    if not two_step_active:
        return TwoStepPhase.ATTEMPT
    if username_submitted and not username:
        return TwoStepPhase.USERNAME_REQUIRED
    if password:
        return TwoStepPhase.ATTEMPT
    if password_submitted:
        return TwoStepPhase.PASSWORD_REQUIRED
    return TwoStepPhase.USERNAME_STEP

_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

# Endpoints management_secret_required_for_ui must never gate, even though
# they're non-GET: ui.login is the identity front door, ui.management_unlock
# is the write-guard unlock action itself (gating it would be circular).
# ui.logout is GET-only, so it never reaches this check (safe methods return
# above it) - it isn't listed here.
_UI_MANAGEMENT_EXEMPT_ENDPOINTS = {"ui.login", "ui.management_unlock"}


def is_ui_authenticated() -> bool:
    """True when the current Flask session carries a logged-in UI user.

    Set by ui.login's POST handler and by the SAML SSO inline-login form
    (routes/saml.py) - both authenticate via config.interactive_authenticate(),
    so either is sufficient here. Under login_mode: persona that call is
    identity selection only, not a credential check (see Settings.login_mode).
    """
    return bool(session.get("user"))


def ui_login_required() -> ResponseReturnValue | None:
    """ui_bp.before_request hook: enforce /login when opted in.

    ui.management_unlock is exempt alongside ui.login itself: management_secret
    is an independent axis from require_ui_login (either, both, or neither can
    be on - see Settings.management_secret), so proving knowledge of it must
    not first require a login session that may not even be configured to
    exist yet. Without this exemption, an anonymous POST here would be
    redirected to /login before the view ran, and the unlock form login.html
    renders whenever management_secret is configured would silently do
    nothing (#163 review).
    """
    if not get_config().settings.require_ui_login:
        return None
    if request.endpoint in ("ui.login", "ui.management_unlock"):
        return None
    if is_ui_authenticated():
        return None
    return redirect(url_for("ui.login"))


def get_management_secret() -> str | None:
    """The configured management_secret, or None when the gate is off."""
    return get_config().settings.management_secret


def verify_management_secret(candidate: object) -> bool:
    """verify_secret against the globally configured management_secret.

    Used by ui_bp/api_bp, which both read config through
    nanoidp.config.get_config() (the same global create_app() initializes).
    The MCP server keeps its own ConfigManager singleton and must not go
    through this function - see mcp_server._check_admin_secret.
    """
    return verify_secret(candidate, get_management_secret())


def _management_verified_marker(secret: str) -> str:
    """The value a legitimate unlock stores in session['management_verified'].

    An HMAC of management_secret itself, keyed by the app's secret_key -
    not a bare boolean. Flask signs the whole session cookie with secret_key,
    which defaults to a public, well-known value; a bare True flag would let
    anyone who knows that default forge an unlocked session without ever
    knowing management_secret (#163 review, blocking). Binding the marker to
    management_secret means forging it also requires knowing the secret being
    protected, regardless of whether secret_key was ever changed. See
    docs/SECURITY.md for the secret_key caveat this still doesn't remove.
    """
    key = current_app.secret_key
    if key is None:
        # create_app() always sets app.secret_key from settings.secret_key
        # (which itself defaults to a non-None string) before ui_bp/api_bp
        # ever see a request - Flask's own stub just types the attribute
        # Optional because it's unset on a bare, freshly-constructed Flask().
        raise RuntimeError("current_app.secret_key is not set")
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()


def mark_management_verified() -> None:
    """Record a successful unlock in the session (called by ui.management_unlock)."""
    secret = get_management_secret()
    if secret:
        session["management_verified"] = _management_verified_marker(secret)


def _unlocked_in_session() -> bool:
    """True when this session already proved knowledge of management_secret."""
    secret = get_management_secret()
    if not secret:
        return False
    marker = session.get("management_verified")
    return isinstance(marker, str) and hmac.compare_digest(
        marker, _management_verified_marker(secret)
    )


def management_secret_required_for_api() -> ResponseReturnValue | None:
    """api_bp.before_request hook: require X-Management-Secret on mutations.

    Off by default (no-op when management_secret isn't configured) - same
    zero-config behavior as today. Read requests (GET/HEAD/OPTIONS) are never
    gated; only state-changing calls are. An already-unlocked ui_bp session
    (same Flask session cookie, same app) also satisfies this, so the
    dashboard's own same-origin fetch() calls (users.html, test.html,
    audit.html) keep working after unlocking once, without each template
    needing to attach the header itself (#163 review) - the header remains
    the contract for non-browser API clients, which have no such session.
    """
    if not get_management_secret():
        return None
    if request.method in _SAFE_METHODS:
        return None
    if _unlocked_in_session():
        return None
    if verify_management_secret(request.headers.get("X-Management-Secret")):
        return None
    return jsonify({"error": "X-Management-Secret header required or invalid"}), 401


def management_secret_required_for_ui() -> ResponseReturnValue | None:
    """ui_bp.before_request hook: require the write guard on mutating actions.

    Independent of ui_login_required/require_ui_login (the session front
    door) - this is the write guard, checked regardless of whether a login
    session exists. Proven once via POST /management/unlock, then trusted for
    the rest of the session, the same way ui_login_required trusts
    session['user'] without re-prompting for a password on every request.
    """
    if not get_management_secret():
        return None
    if request.method in _SAFE_METHODS:
        return None
    if request.endpoint in _UI_MANAGEMENT_EXEMPT_ENDPOINTS:
        return None
    if _unlocked_in_session():
        return None
    # login.html renders an `error` query param, not Flask's flash() messages
    # (only base.html does that) - match the page's own convention rather
    # than a message that would silently never appear here.
    return redirect(url_for("ui.login", error="Enter the management secret to perform this action."))
