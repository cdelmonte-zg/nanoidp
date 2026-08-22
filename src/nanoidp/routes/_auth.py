"""
Login-gate helper for ui_bp (opt-in, off by default - see require_ui_login
in models.py).
"""

from flask import redirect, request, session, url_for
from flask.typing import ResponseReturnValue

from ..config import get_config


def is_ui_authenticated() -> bool:
    """True when the current Flask session carries a logged-in UI user.

    Set by ui.login's POST handler and by the SAML SSO inline-login form
    (routes/saml.py) - both authenticate via config.interactive_authenticate(),
    so either is sufficient here. Under login_mode: persona that call is
    identity selection only, not a credential check (see Settings.login_mode).
    """
    return bool(session.get("user"))


def ui_login_required() -> ResponseReturnValue | None:
    """ui_bp.before_request hook: enforce /login when opted in."""
    if not get_config().settings.require_ui_login:
        return None
    if request.endpoint == "ui.login":
        return None
    if is_ui_authenticated():
        return None
    return redirect(url_for("ui.login"))
