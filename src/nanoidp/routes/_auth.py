"""
Login-gate helper for ui_bp (opt-in, off by default - see require_ui_login
in models.py), the management_secret mutation gate shared by ui_bp, api_bp
and the MCP server (opt-in, off by default - see management_secret in
models.py), the two-step login phase shared by every interactive
password-form surface (#322/#323 review round 2), and the declarative
TOTP second-factor phase riding the same machinery (#348).
"""

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from flask import Response, current_app, jsonify, make_response, redirect, request, session, url_for
from flask.typing import ResponseReturnValue

from ..config import ConfigManager, User, get_config

# Re-exported: verify_secret moved to the framework-free nanoidp.security
# (#286) so the stdio MCP process stops importing Flask to reach it; this
# module stays the import path its own callers and tests already use.
from ..security import verify_secret  # noqa: F401
from ..services.identities import identities_for
from ..services.totp import verify_totp


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


class AuthMethod(str, Enum):
    """How establish_login_session authenticated this session (#301,
    extended #348 for the declarative TOTP second factor).

    The single vocabulary session['auth_method'] is written and read
    through: the SAML assertion's AuthnContextClassRef is derived from it
    (``saml_context``), and so is the OIDC ``amr`` claim (``amr``).
    """

    PERSONA = "persona"
    PASSWORD = "password"
    PASSWORD_OTP = "password_otp"

    @property
    def amr(self) -> Optional[Sequence[str]]:
        """OIDC ``amr`` values (RFC 8176 §2), or ``None`` when nothing
        should be claimed at all. Persona login checks no password
        (identity selection only - see Settings.login_mode), so claiming
        'pwd' there would be a claim about a check that never happened -
        VISION principle 2, "metadata never lies" (#348)."""
        return _AMR[self]

    @property
    def saml_context(self) -> str:
        """SAML V2.0 AuthnContextClassRef for this method (SAML V2.0
        Authentication Context). TimeSyncToken is the class for a
        time-synchronized one-time token, next to the pre-existing
        password/unspecified pair (#348)."""
        return _SAML_CONTEXT[self]


# Static tables behind the two AuthMethod properties: built once, not per
# login (review of #348).
_AMR: dict[AuthMethod, Optional[tuple[str, ...]]] = {
    AuthMethod.PERSONA: None,
    AuthMethod.PASSWORD: ("pwd",),
    AuthMethod.PASSWORD_OTP: ("pwd", "otp"),
}
_SAML_CONTEXT: dict[AuthMethod, str] = {
    AuthMethod.PERSONA: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
    AuthMethod.PASSWORD: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    AuthMethod.PASSWORD_OTP: "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
}


def establish_login_session(username: str, *, method: AuthMethod) -> None:
    """Log ``username`` into the Flask session - the single writer of
    session['user'] and session['auth_method'] (#301, extended #348).

    The two surfaces that establish a UI session (ui.login's POST handler,
    the SAML SSO inline-login form in routes/saml.py) call this right after
    the login (and, when active, the TOTP second factor) succeeds, instead
    of assigning the keys themselves; a future surface that establishes one
    must go through this helper too, and tests/test_login_session_contract.py
    holds every module but this one to that. /authorize and /device also
    authenticate through interactive_authenticate but establish no UI
    session, so they never call this. The two keys must travel together:
    the SAML assertion's AuthnContextClassRef and the OIDC amr claim are
    both derived from 'auth_method' (AuthMethod.saml_context / .amr), and a
    persona login (identity selection, no password) must not claim either a
    password or a second factor it never checked. Before this helper each
    surface wrote both lines by hand, and a third surface that set 'user'
    alone would have silently defaulted every persona login to the password
    context.

    The 'auth_method' literal is spelled here and in session_auth_method
    only, on purpose: the contract test looks for the string constant,
    which a named alias would hide from it.
    """
    session["user"] = username
    session["auth_method"] = method.value
    session.permanent = True


def session_auth_method() -> AuthMethod:
    """The AuthMethod this session was established with - the single
    reader of session['auth_method'] (#301, extended #348).

    An absent key means AuthMethod.PASSWORD: sessions predating the
    persona feature, and sessions seeded directly in tests with only
    session['user'], keep the prior unconditional PasswordProtectedTransport
    behavior. So does a value outside the enum (a cookie written by a
    build with a method this one does not know): the reader this replaced
    treated every non-persona string as the password context, and a SAML
    response must not turn into a 500 over an unrecognised label.
    """
    try:
        return AuthMethod(session.get("auth_method", AuthMethod.PASSWORD.value))
    except ValueError:
        return AuthMethod.PASSWORD


class SecondFactorPhase(str, Enum):
    """Where a login submission stands under the declarative TOTP second
    factor (#348), once two_step_phase (or the combined form) has already
    decided ATTEMPT and the password has been checked. Derived purely from
    settings, the just-authenticated user, and this request's form - the
    single home every interactive-login surface shares, exactly like
    two_step_phase above.
    """

    NOT_REQUIRED = "not_required"  # totp inactive, or this user has no secret: no change
    CODE_STEP = "code_step"  # nothing submitted yet: render the code screen
    CODE_REQUIRED = "code_required"  # the code screen was resubmitted blank
    CODE_INVALID = "code_invalid"  # a non-blank code was submitted but did not verify
    VERIFIED = "verified"  # a valid code was submitted

    @property
    def pending(self) -> bool:
        """The password passed but the login is not complete: render the
        code screen. One predicate for the four surfaces, so none of them
        re-spells the set of pending phases."""
        return self in _PENDING_PHASES

    @property
    def error(self) -> Optional[str]:
        """The message the code screen shows for this phase, ``None`` for
        the first arrival at it. Spelled once here rather than at each
        surface (review of #348)."""
        return _CODE_SCREEN_ERRORS.get(self)


_PENDING_PHASES = frozenset(
    {SecondFactorPhase.CODE_STEP, SecondFactorPhase.CODE_REQUIRED, SecondFactorPhase.CODE_INVALID}
)
_CODE_SCREEN_ERRORS: dict[SecondFactorPhase, str] = {
    SecondFactorPhase.CODE_REQUIRED: "Code is required",
    SecondFactorPhase.CODE_INVALID: "Invalid code",
}


def second_factor_phase(
    *,
    totp_active: bool,
    user: Optional[User],
    code_submitted: bool,
    code: str,
) -> SecondFactorPhase:
    """Classify a just-password-authenticated login under the declarative
    TOTP second factor (#348). ``user`` is the account interactive_authenticate
    just returned (``None`` on a failed password check - callers only reach
    here on success). A user without a totp_secret sees no change, same
    composition as Settings.totp_active being inert under persona mode.
    """
    if not totp_active or user is None or not user.totp_secret:
        return SecondFactorPhase.NOT_REQUIRED
    if code:
        return (
            SecondFactorPhase.VERIFIED
            if verify_totp(user.totp_secret, code)
            else SecondFactorPhase.CODE_INVALID
        )
    if code_submitted:
        return SecondFactorPhase.CODE_REQUIRED
    return SecondFactorPhase.CODE_STEP


@dataclass(frozen=True)
class InteractiveLogin:
    """What authenticate_interactively decided for one submission (#348).

    ``user`` is set only when the login is COMPLETE - the password (or
    persona selection) passed and no second factor is outstanding. While
    the TOTP code screen is pending, ``user`` is ``None`` on purpose: a
    surface that keeps the pre-#348 idiom ``if user: <issue code /
    establish session>`` therefore fails closed (it shows its usual
    invalid-credentials response) instead of minting a credential with no
    code checked. ``phase.pending`` tells such a surface to render the code
    screen instead, with ``phase.error`` as its message.

    ``method`` is how the completed login authenticated (the session
    writer's and the SAML context's vocabulary); ``amr`` is the OIDC claim
    to mint, already gated: ``None`` unless ``login.totp`` is active, so
    the feature is opt-in on the wire too - a deployment that never turned
    it on sees no new claim in its ID Tokens.
    """

    user: Optional[User]
    phase: SecondFactorPhase
    method: AuthMethod
    amr: Optional[Sequence[str]]


def authenticate_interactively(
    config: ConfigManager,
    *,
    username: str,
    password: str,
) -> InteractiveLogin:
    """The one call every interactive surface makes once two_step_phase (or
    the combined form) says ATTEMPT (#348): runs the existing password/
    persona check, then - only when it succeeds and login.totp is active -
    the further TOTP phase, riding the same phase machinery as two_step
    (#322/#323). The submitted code is read from this request's form here
    (``totp_code``), so the field name too is spelled once - stripped like
    ``username`` on every one of these forms, so a pasted or autofilled
    code with trailing whitespace verifies instead of being audited as a
    failed attempt (#348 review, cleanup). Each route only renders what
    the returned ``InteractiveLogin`` says; the rule is here.
    """
    user = identities_for(config).interactive_authenticate(username, password)
    if user is None:
        return InteractiveLogin(None, SecondFactorPhase.NOT_REQUIRED, AuthMethod.PASSWORD, None)
    if config.settings.persona_mode_enabled:
        return InteractiveLogin(user, SecondFactorPhase.NOT_REQUIRED, AuthMethod.PERSONA, None)
    return check_second_factor(config, user)


def check_second_factor(config: ConfigManager, user: User) -> InteractiveLogin:
    """The TOTP phase for a user whose password has already been verified,
    reading the submitted code from this request's form (#348).

    ``authenticate_interactively`` calls it right after the password check.
    ``/authorize`` also calls it on its own when an authorization
    transaction already records the verified password (#346), so the code
    screen does not have to send the password back: the phase rule and the
    field name stay spelled once either way.
    """
    totp_active = config.settings.totp_active
    phase = second_factor_phase(
        totp_active=totp_active,
        user=user,
        code_submitted="totp_code" in request.form,
        code=request.form.get("totp_code", "").strip(),
    )
    method = AuthMethod.PASSWORD_OTP if phase is SecondFactorPhase.VERIFIED else AuthMethod.PASSWORD
    return InteractiveLogin(
        user=None if phase.pending else user,
        phase=phase,
        method=method,
        amr=method.amr if totp_active else None,
    )


def no_store(response: ResponseReturnValue) -> Response:
    """Mark a code-screen response uncacheable (#348 review). The screen
    carries the password forward as a hidden field - the price of keeping
    the step stateless like two_step - so it must never sit in a shared or
    back/forward cache."""
    resp = make_response(response)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def is_ui_authenticated() -> bool:
    """True when the current Flask session carries a logged-in UI user.

    Set by establish_login_session, which ui.login's POST handler and the
    SAML SSO inline-login form (routes/saml.py) both call after
    IdentityResolver.interactive_authenticate() succeeds, so either is sufficient
    here. Under login_mode: persona that call is identity selection only,
    not a credential check (see Settings.login_mode).
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
    The MCP server gates its tools in mcp_server._check_admin_secret, off
    the ConfigManager each call is handed.
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
