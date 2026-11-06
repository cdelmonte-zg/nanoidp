"""Authenticated browser sessions at /authorize (#468).

A successful login leaves one record per browser for login.session_minutes;
a later request of the same browser reuses it instead of showing a login
page, and the ID token's auth_time is the session's. The record is only as
good as the login it records is today, ends with a logout or a runtime
reset, and is never the web UI's own session.
"""

import time

import jwt
import pytest

from nanoidp.config import get_config
from nanoidp.services.authenticated_sessions import (
    MAX_AUTHENTICATED_SESSIONS,
    AuthenticatedSessionStoreFull,
    get_authenticated_session_store,
)
from nanoidp.services.totp import generate_totp
from tests.conftest import (
    authorization_response_params,
    pending_transaction_ids,
    transaction_id_of,
)

CALLBACK = "http://localhost:3000/callback"
QS = f"response_type=code&client_id=demo-client&redirect_uri={CALLBACK}&scope=openid&state=s"
LOGIN = {"username": "admin", "password": "admin"}
_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _exchange(client, response):
    code = authorization_response_params(response)["code"][0]
    token = client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK},
        auth=("demo-client", "demo-secret"),
    ).get_json()
    return jwt.decode(token["id_token"], options={"verify_signature": False})


def _login(client, extra=""):
    """A full login through the page: the ID token's claims."""
    page = client.get(f"/authorize?{QS}{extra}")
    assert page.status_code == 200, page.data[:200]
    done = client.post(
        "/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN}
    )
    assert done.status_code == 302
    return _exchange(client, done)


def _is_login_page(response):
    return response.status_code == 200 and b'name="transaction_id"' in response.data


def _session_of(client):
    with client.session_transaction() as s:
        binding = s.get("authorize_binding")
    return get_authenticated_session_store().live(binding)


def _audit_sessions(app):
    with app.app_context():
        from nanoidp.services import get_audit_log

        return [
            e["details"].get("session")
            for e in get_audit_log().get_entries(event_type="authorization_request")
            if e["status"] == "success"
        ]


class TestStore:
    def test_one_record_per_browser_replaced_by_a_new_login(self):
        store = get_authenticated_session_store()
        now = int(time.time())
        store.establish(
            browser_binding="b", username="admin", method="password", auth_time=now - 100, lifetime_seconds=3600
        )
        store.establish(
            browser_binding="b", username="user1", method="persona", auth_time=now, lifetime_seconds=3600
        )

        record = store.live("b")
        assert record is not None
        assert (record.username, record.method, record.auth_time) == ("user1", "persona", now)
        assert store.live("other") is None
        assert store.live(None) is None

    def test_expiry_counts_from_the_authentication(self):
        store = get_authenticated_session_store()
        now = int(time.time())
        store.establish(
            browser_binding="b", username="admin", method="password", auth_time=now - 10, lifetime_seconds=5
        )
        assert store.live("b") is None

    def test_end_drops_the_record_once(self):
        store = get_authenticated_session_store()
        store.establish(
            browser_binding="b", username="admin", method="password", auth_time=int(time.time()), lifetime_seconds=3600
        )
        assert store.end("b") is not None
        assert store.end("b") is None
        assert store.live("b") is None

    def test_the_cap_counts_other_browsers_and_a_replacement_needs_no_room(self, monkeypatch):
        import nanoidp.services.authenticated_sessions as module

        monkeypatch.setattr(module, "MAX_AUTHENTICATED_SESSIONS", 2)
        store = get_authenticated_session_store()
        now = int(time.time())
        for binding in ("a", "b"):
            store.establish(
                browser_binding=binding, username="admin", method="password", auth_time=now, lifetime_seconds=3600
            )
        with pytest.raises(AuthenticatedSessionStoreFull):
            store.establish(
                browser_binding="c", username="admin", method="password", auth_time=now, lifetime_seconds=3600
            )
        # A browser with a record replaces its own.
        store.establish(
            browser_binding="a", username="user1", method="password", auth_time=now + 1, lifetime_seconds=3600
        )
        assert store.live("a").username == "user1"
        assert MAX_AUTHENTICATED_SESSIONS == 1000


class TestSingleSignOn:
    def test_a_second_request_reuses_the_login_with_the_same_auth_time(self, client, app):
        first = _login(client)
        time.sleep(1.1)

        again = client.get(f"/authorize?{QS}")

        assert again.status_code == 302
        second = _exchange(client, again)
        assert second["sub"] == first["sub"] == "admin"
        assert second["auth_time"] == first["auth_time"]
        assert pending_transaction_ids(client) == []
        assert _audit_sessions(app) == ["reused", "established"]

    def test_the_session_is_not_renewed_by_reuse(self, client, app):
        _login(client)
        record = _session_of(client)
        client.get(f"/authorize?{QS}")

        assert _session_of(client).expires_at == record.expires_at

    def test_session_minutes_zero_keeps_no_session(self, client, app):
        with app.app_context():
            get_config().settings.session_minutes = 0

        _login(client)

        assert _session_of(client) is None
        assert _is_login_page(client.get(f"/authorize?{QS}"))
        assert _audit_sessions(app) == ["disabled"]

    def test_lowering_the_setting_shortens_a_session_already_established(self, client, app):
        _login(client)
        with client.session_transaction() as s:
            binding = s["authorize_binding"]
        store = get_authenticated_session_store()
        record = store.live(binding)
        store.establish(
            browser_binding=binding,
            username=record.username,
            method=record.method,
            auth_time=int(time.time()) - 120,
            lifetime_seconds=3600,
        )
        assert client.get(f"/authorize?{QS}").status_code == 302
        with app.app_context():
            get_config().settings.session_minutes = 1

        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_code_created_at_an_instant_counts_everything_from_it(self):
        from datetime import datetime, timedelta, timezone

        from nanoidp.services.auth_code import CODE_LIFETIME_SECONDS, get_auth_code_store

        instant = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        store = get_auth_code_store()
        code = store.create_code(
            client_id="demo-client",
            redirect_uri=CALLBACK,
            username="admin",
            created_at=instant,
        )
        record = store._repository.get(code)

        assert record.created_at == instant
        assert record.expires_at == instant + timedelta(seconds=CODE_LIFETIME_SECONDS)
        assert record.auth_time == int(instant.timestamp())

    def test_an_expired_session_shows_the_login_page(self, client, app, monkeypatch):
        _login(client)
        record = _session_of(client)
        import nanoidp.services.authenticated_sessions as module

        monkeypatch.setattr(module.time, "time", lambda: record.expires_at + 1)

        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_new_login_replaces_the_session_and_its_auth_time(self, client, app):
        first = _login(client)
        time.sleep(1.1)
        with app.app_context():
            get_config().settings.session_minutes = 0  # force the page
        page = client.get(f"/authorize?{QS}")
        with app.app_context():
            get_config().settings.session_minutes = 60
        done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})
        second = _exchange(client, done)

        assert second["auth_time"] > first["auth_time"]
        assert _session_of(client).auth_time == second["auth_time"]

    def _binding(self, client):
        with client.session_transaction() as s:
            return s["authorize_binding"]

    def test_logout_ends_the_session(self, client):
        """The record goes, not only the cookie that names it: a binding
        that leaked would otherwise still answer until expiry."""
        _login(client)
        binding = self._binding(client)

        client.get("/logout")

        assert get_authenticated_session_store().live(binding) is None
        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_the_ui_logout_ends_it_too(self, client):
        _login(client)
        binding = self._binding(client)

        client.get("/ui/logout", follow_redirects=False)

        assert get_authenticated_session_store().live(binding) is None
        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_runtime_reset_ends_every_session(self, client):
        _login(client)

        reset = client.delete("/api/runtime")

        assert reset.get_json()["sessions_ended"] == 1
        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_the_session_is_not_the_web_ui_login(self, client):
        _login(client)
        with client.session_transaction() as s:
            assert "user" not in s


class TestTheCodeRecordAndOlderProcesses:
    def test_a_fresh_login_writes_no_auth_time_key_and_a_reused_session_does(self, client):
        """A code issued at the login reads back on a 3.4.0 process sharing
        the store (#466's guarantee); only a code resting on an earlier
        authentication carries the new key."""
        from nanoidp.services.auth_code import get_auth_code_store

        page = client.get(f"/authorize?{QS}")
        done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})
        fresh_code = authorization_response_params(done)["code"][0]
        time.sleep(1.1)
        reused_code = authorization_response_params(client.get(f"/authorize?{QS}"))["code"][0]

        store = get_auth_code_store()
        written = {code: store._repository.entry(code) for code in (fresh_code, reused_code)}
        from nanoidp.services.auth_code import _CODEC

        fresh = _CODEC.dump(written[fresh_code].value)
        reused = _CODEC.dump(written[reused_code].value)
        assert "auth_time" not in fresh
        assert reused["auth_time"] == written[reused_code].value.auth_time
        loaded = _CODEC.load(fresh)
        assert loaded.auth_time == int(loaded.created_at.timestamp())


class TestTheSessionIsOnlyAsGoodAsTheLoginIsToday:
    def test_a_user_that_no_longer_exists(self, client, app):
        _login(client)
        with app.app_context():
            get_config().users.pop("admin")

        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_password_login_is_not_reused_under_persona_mode(self, client, app):
        _login(client)
        with app.app_context():
            get_config().settings.login_mode = "persona"

        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_persona_login_is_not_reused_under_password_mode(self, client, app):
        with app.app_context():
            get_config().settings.login_mode = "persona"
        page = client.get(f"/authorize?{QS}")
        done = client.post(
            "/authorize", data={"transaction_id": transaction_id_of(page), "username": "admin"}
        )
        assert done.status_code == 302
        assert _session_of(client).method == "persona"
        assert client.get(f"/authorize?{QS}").status_code == 302
        with app.app_context():
            get_config().settings.login_mode = "password"

        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_password_login_is_not_reused_once_a_code_became_required(self, client, app):
        _login(client)
        with app.app_context():
            get_config().settings.totp = True
            get_config().users["admin"].totp_secret = _SECRET

        assert _is_login_page(client.get(f"/authorize?{QS}"))

    def test_a_password_and_code_login_is_reused_and_carries_its_amr(self, client, app):
        with app.app_context():
            get_config().settings.totp = True
            get_config().users["admin"].totp_secret = _SECRET
        page = client.get(f"/authorize?{QS}")
        tid = transaction_id_of(page)
        client.post("/authorize", data={"transaction_id": tid, **LOGIN})
        done = client.post(
            "/authorize", data={"transaction_id": tid, "totp_code": generate_totp(_SECRET)}
        )
        assert done.status_code == 302
        first = _exchange(client, done)
        assert first["amr"] == ["pwd", "otp"]
        assert _session_of(client).method == "password_otp"

        again = client.get(f"/authorize?{QS}")

        assert again.status_code == 302
        second = _exchange(client, again)
        assert second["amr"] == ["pwd", "otp"]
        assert second["auth_time"] == first["auth_time"]

    def test_auto_login_establishes_a_session(self, client, app):
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True

        first = client.get(f"/authorize?{QS}&login_hint=persona-auto-login:user1")

        assert first.status_code == 302
        assert _session_of(client).username == "user1"
        again = client.get(f"/authorize?{QS}")
        assert again.status_code == 302
        assert _exchange(client, again)["sub"] == "user1"

    def test_a_full_store_lets_the_login_complete_without_a_session(self, client, app, monkeypatch):
        import nanoidp.services.authenticated_sessions as module

        monkeypatch.setattr(module, "MAX_AUTHENTICATED_SESSIONS", 1)
        get_authenticated_session_store().establish(
            browser_binding="another-browser",
            username="admin",
            method="password",
            auth_time=int(time.time()),
            lifetime_seconds=3600,
        )

        claims = _login(client)

        assert claims["sub"] == "admin"
        assert _session_of(client) is None
        assert _audit_sessions(app) == ["not kept, store full"]
