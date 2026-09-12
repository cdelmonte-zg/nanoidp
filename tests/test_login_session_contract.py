"""
Login-session contract (#301): session['user'] and session['auth_method']
have exactly one writer, routes/_auth.establish_login_session, and
'auth_method' exactly one reader, session_authenticated_via_persona.

The SAML assertion's AuthnContextClassRef is derived from 'auth_method'.
Before #301 the dashboard's /login and SAML's inline login each wrote both
keys by hand; a third login surface that set 'user' alone would have made
every persona login through it claim PasswordProtectedTransport, with no
test able to notice. The unit tests here pin what the helper writes; the
structural test holds every other module in src/nanoidp to calling it.

The structural test is a tripwire, not a proof: it is a line-by-line regex
over the source, so it catches the forms a hand-written login surface would
use (subscript and annotated assignment, session.update with a keyword or a
dict literal, session.setdefault, and any mention of the 'auth_method'
key), but not a key held in a variable or a dict built on another line. The
review that goes with a new login surface still has to look for the call.
"""

import re
from pathlib import Path

from flask import session

from nanoidp.routes._auth import (
    establish_login_session,
    session_authenticated_via_persona,
)

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "nanoidp"
SINGLE_WRITER = SRC_ROOT / "routes" / "_auth.py"

# Any direct write of the 'user' key, or any mention of the 'auth_method'
# key. Reads of 'user' (session.get("user"), comparisons) are fine and
# common, so only the write forms are matched. 'token_endpoint_auth_method'
# is a different thing entirely and never appears as a bare quoted key, so
# the quote before 'auth_method' keeps it out.
DIRECT_SESSION_ACCESS = re.compile(
    # session["user"] = ...  and the annotated form  session["user"]: str = ...
    r"""session\[\s*["']user["']\s*\]\s*(?::[^=]*)?=(?!=)"""
    # session.update(user=...), session.update({"user": ...}),
    # session.setdefault("user", ...), and the same with auth_method
    r"""|session\.(?:update|setdefault)\([^)]*\b(?:user|auth_method)\b"""
    # the key literal anywhere: subscript, .get, .update, .setdefault, .pop
    r"""|["']auth_method["']"""
)


class TestEstablishLoginSession:
    def test_persona_login_records_persona(self, app):
        with app.test_request_context():
            establish_login_session("admin", persona_mode=True)

            assert session["user"] == "admin"
            assert session["auth_method"] == "persona"
            assert session.permanent is True
            assert session_authenticated_via_persona() is True

    def test_password_login_records_password(self, app):
        with app.test_request_context():
            establish_login_session("admin", persona_mode=False)

            assert session["user"] == "admin"
            assert session["auth_method"] == "password"
            assert session.permanent is True
            assert session_authenticated_via_persona() is False

    def test_absent_key_means_password(self, app):
        """Sessions predating the persona feature, and tests that seed only
        session['user'], keep the prior PasswordProtectedTransport behavior."""
        with app.test_request_context():
            session["user"] = "admin"

            assert session_authenticated_via_persona() is False


class TestSingleWriter:
    def test_no_module_but_auth_touches_the_login_session_keys_directly(self):
        offenders = []
        for path in sorted(SRC_ROOT.rglob("*.py")):
            if path == SINGLE_WRITER:
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if DIRECT_SESSION_ACCESS.search(line):
                    offenders.append(f"{path.relative_to(SRC_ROOT)}:{lineno}: {line.strip()}")

        assert not offenders, (
            "session['user'] and session['auth_method'] must only be written through "
            "routes/_auth.establish_login_session and read through "
            "session_authenticated_via_persona (#301), so a login surface cannot record "
            "a user without recording how it authenticated. Direct access found in:\n  "
            + "\n  ".join(offenders)
        )

    def test_the_guard_pattern_matches_what_it_claims_to(self):
        """The structural test is only worth having if its regex fires on the
        exact lines the two call sites used to contain."""
        assert DIRECT_SESSION_ACCESS.search('session["user"] = username')
        assert DIRECT_SESSION_ACCESS.search("session['user'] = username")
        assert DIRECT_SESSION_ACCESS.search('session["user"]: str = username')
        assert DIRECT_SESSION_ACCESS.search("session.update(user=username)")
        assert DIRECT_SESSION_ACCESS.search('session.update({"user": username})')
        assert DIRECT_SESSION_ACCESS.search('session.setdefault("user", username)')
        assert DIRECT_SESSION_ACCESS.search('session["auth_method"] = "persona"')
        assert DIRECT_SESSION_ACCESS.search('session.get("auth_method", "password")')
        assert DIRECT_SESSION_ACCESS.search('session.update(auth_method="persona")')
        assert not DIRECT_SESSION_ACCESS.search('session.get("user")')
        assert not DIRECT_SESSION_ACCESS.search('client.token_endpoint_auth_method')
        assert not DIRECT_SESSION_ACCESS.search('if session["user"] == "admin":')
        assert not DIRECT_SESSION_ACCESS.search('current_user=session.get("user"),')
