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

The structural test is a tripwire, not a proof. It walks the AST of every
module under src/nanoidp (the same rglob tests/test_token_issuance_parity.py
uses) and flags three things outside _auth.py: a store into (or del of)
session['user'], a session.update(...) whose keyword, dict-literal
argument or unpacked ``**{...}`` names 'user' (and a session.setdefault
whose key argument is 'user'), and the string constant 'auth_method'
anywhere but a docstring (subscript, .get, .pop, a dict key). Working on
the AST rather than the source text means a read like ``if
session["user"]:`` or ``actor=session.get("user")`` passes, comments and
docstrings are never matched, and a session.update( call split across
lines is still caught. What still passes: a key held in a variable
(``session[key] = ...``) and a dict built on another line and splatted in.
The review that goes with a new login surface still has to look for the
call.
"""

import ast
from pathlib import Path

from flask import session

from nanoidp.routes._auth import (
    establish_login_session,
    session_authenticated_via_persona,
)

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "nanoidp"
SINGLE_WRITER = SRC_ROOT / "routes" / "_auth.py"

_LOGIN_KEYS = {"user", "auth_method"}


def _is_session(node: ast.expr) -> bool:
    """``session`` or ``<anything>.session`` (``flask.session``)."""
    return (isinstance(node, ast.Name) and node.id == "session") or (
        isinstance(node, ast.Attribute) and node.attr == "session"
    )


def _const(node: ast.expr | None) -> object:
    return node.value if isinstance(node, ast.Constant) else None


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """ids of the Constant nodes that are docstrings: ast.walk yields them
    like any other string, and a docstring is documentation, not a write."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                ids.add(id(first.value))
    return ids


def _dict_names_user(node: ast.expr) -> bool:
    return isinstance(node, ast.Dict) and any(_const(k) == "user" for k in node.keys)


def _update_call_writes_user(call: ast.Call) -> bool:
    """session.update(user=...), session.update({"user": ...}), and the
    unpacked form session.update(**{"user": ...}) (review round 2)."""
    for kw in call.keywords:
        if kw.arg in _LOGIN_KEYS:
            return True
        if kw.arg is None and _dict_names_user(kw.value):
            return True
    return any(_dict_names_user(arg) for arg in call.args)


def login_session_key_offenders(tree: ast.AST) -> list[ast.AST]:
    """Nodes in ``tree`` that touch the login-session keys directly.

    Reads of 'user' are fine and common (is_ui_authenticated, templates'
    current_user), so for that key only the write forms are matched. Any
    mention of 'auth_method' outside a docstring is flagged: the key has
    one reader too, and 'token_endpoint_auth_method' is a different
    constant, so the exact comparison never confuses the two.
    """
    docstrings = _docstring_nodes(tree)
    offenders: list[ast.AST] = []
    for node in ast.walk(tree):
        # session["user"] = ...   session["user"]: str = ...   del session["user"]
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _is_session(node.value)
            and _const(node.slice) == "user"
        ):
            offenders.append(node)
        # the key literal anywhere: session["auth_method"], .get, .pop, a dict key
        elif (
            isinstance(node, ast.Constant)
            and node.value == "auth_method"
            and id(node) not in docstrings
        ):
            offenders.append(node)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _is_session(node.func.value)
        ):
            # session.setdefault("user", ...): only the key argument is a
            # write; the value may legitimately be any dict.
            if node.func.attr == "setdefault":
                if node.args and _const(node.args[0]) == "user":
                    offenders.append(node)
            elif node.func.attr == "update" and _update_call_writes_user(node):
                offenders.append(node)
    return offenders


def _offends(snippet: str) -> bool:
    return bool(login_session_key_offenders(ast.parse(snippet)))


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
            source = path.read_text(encoding="utf-8")
            lines = source.splitlines()
            for node in login_session_key_offenders(ast.parse(source, filename=str(path))):
                lineno = getattr(node, "lineno", 0)
                text = lines[lineno - 1].strip() if lineno else ast.dump(node)
                offenders.append(f"{path.relative_to(SRC_ROOT)}:{lineno}: {text}")

        assert not offenders, (
            "session['user'] and session['auth_method'] must only be written through "
            "routes/_auth.establish_login_session and read through "
            "session_authenticated_via_persona (#301), so a login surface cannot record "
            "a user without recording how it authenticated. Direct access found in:\n  "
            + "\n  ".join(offenders)
        )

    def test_the_guard_matches_what_it_claims_to(self):
        """The structural test is only worth having if it fires on the exact
        lines the two call sites used to contain, and stays quiet on the
        reads a route legitimately makes (review round 1 found the earlier
        regex firing on four of those)."""
        # the forms a hand-written login surface would use
        assert _offends('session["user"] = username')
        assert _offends("session['user'] = username")
        assert _offends('session["user"]: str = username')
        assert _offends('del session["user"]')
        assert _offends('flask.session["user"] = username')
        assert _offends("session.update(user=username)")
        assert _offends('session.update({"user": username})')
        assert _offends('session.update(\n    {\n        "user": username,\n    }\n)')
        assert _offends('session.update(**{"user": username})')
        assert _offends('session.setdefault("user", username)')
        assert _offends('session["auth_method"] = "persona"')
        assert _offends('session.get("auth_method", "password")')
        assert _offends('session.pop("auth_method", None)')
        assert _offends('session.update(auth_method="persona")')
        assert _offends('session.update({"auth_method": "persona"})')
        # reads and unrelated names
        assert not _offends('session.get("user")')
        assert not _offends("client.token_endpoint_auth_method")
        assert not _offends('if session["user"] == "admin":\n    pass')
        assert not _offends('if not session["user"]:\n    return redirect(url_for("ui.login", error=e))')
        assert not _offends('if session["user"]:\n    x = 1')
        assert not _offends('current_user=session.get("user"),')
        assert not _offends('session.update(actor=session.get("user"))')
        assert not _offends('session.setdefault("hint", user.username)')
        assert not _offends('session.setdefault("hint", {"user": username})')
        assert not _offends('"""session["auth_method"] is described here, not touched."""')
        assert not _offends('def f():\n    """auth_method"""')
        assert not _offends('class C:\n    """auth_method"""')
        assert not _offends('"""auth_method"""')  # a module docstring
        assert not _offends('# session["user"] = username')
