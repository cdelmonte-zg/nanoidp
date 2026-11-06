"""prompt and max_age at /authorize (#468, OIDC Core 3.1.2.1).

Decided after redirect_uri, so every answer reaches the client: prompt=none
is a code resting on the browser's authenticated session or login_required,
never a page; prompt=login, prompt=select_account and max_age=0 ask for the
user's own interaction, which no session and no persona auto-login stand in
for; max_age=N reuses a session no older than N; consent is
consent_required; select_account is account_selection_required under
password mode and the picker under persona mode; a malformed value is
invalid_request.
"""

import time

import jwt

from nanoidp.config import get_config
from tests.conftest import (
    authorization_response_params,
    pending_transaction_ids,
    transaction_id_of,
)

CALLBACK = "http://localhost:3000/callback"
QS = f"response_type=code&client_id=demo-client&redirect_uri={CALLBACK}&scope=openid&state=s"
LOGIN = {"username": "admin", "password": "admin"}


def _exchange(client, response):
    code = authorization_response_params(response)["code"][0]
    token = client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK},
        auth=("demo-client", "demo-secret"),
    ).get_json()
    return jwt.decode(token["id_token"], options={"verify_signature": False})


def _login(client, extra=""):
    page = client.get(f"/authorize?{QS}{extra}")
    assert page.status_code == 200, page.data[:200]
    done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})
    assert done.status_code == 302, done.data[:200]
    return _exchange(client, done)


def _is_login_page(response):
    return response.status_code == 200 and b'name="transaction_id"' in response.data


def _error_of(response):
    assert response.status_code == 302, response.data[:200]
    assert response.headers["Location"].startswith(CALLBACK)
    params = authorization_response_params(response)
    assert params["state"] == ["s"]
    return params.get("error", [None])[0]


def _enable_auto_login(app):
    with app.app_context():
        get_config().settings.login_mode = "persona"
        get_config().settings.auto_login = True


class TestPromptNone:
    def test_without_a_session_it_is_login_required(self, client):
        response = client.get(f"/authorize?{QS}&prompt=none")

        assert _error_of(response) == "login_required"
        assert pending_transaction_ids(client) == []

    def test_with_a_session_it_is_a_code_with_the_same_auth_time(self, client):
        first = _login(client)
        time.sleep(1.1)

        response = client.get(f"/authorize?{QS}&prompt=none")

        second = _exchange(client, response)
        assert second["auth_time"] == first["auth_time"]
        assert second["sub"] == "admin"

    def test_with_a_session_older_than_max_age_it_is_login_required(self, client):
        _login(client)
        time.sleep(2.1)

        response = client.get(f"/authorize?{QS}&prompt=none&max_age=1")

        assert _error_of(response) == "login_required"

    def test_with_max_age_zero_it_is_login_required(self, client):
        _login(client)

        assert _error_of(client.get(f"/authorize?{QS}&prompt=none&max_age=0")) == "login_required"

    def test_persona_auto_login_never_stands_in_for_it(self, client, app):
        _enable_auto_login(app)

        response = client.get(f"/authorize?{QS}&prompt=none&login_hint=persona-auto-login:admin")

        assert _error_of(response) == "login_required"
        assert pending_transaction_ids(client) == []

    def test_on_the_direct_post_it_is_never_a_login(self, client):
        refused = client.post(f"/authorize?{QS}&prompt=none", data=LOGIN)

        assert _error_of(refused) == "login_required"

        _login(client)
        reused = client.post(f"/authorize?{QS}&prompt=none", data=LOGIN)

        assert "code" in authorization_response_params(reused)


class TestPromptLoginAndMaxAgeZero:
    def test_prompt_login_shows_the_page_despite_a_session_and_renews_auth_time(self, client):
        first = _login(client)
        time.sleep(1.1)

        second = _login(client, "&prompt=login")

        assert second["auth_time"] > first["auth_time"]

    def test_max_age_zero_shows_the_page_despite_a_session(self, client):
        _login(client)

        assert _is_login_page(client.get(f"/authorize?{QS}&max_age=0"))

    def test_the_transaction_refuses_auto_login_on_a_later_hint_only_get(self, client, app):
        _enable_auto_login(app)
        page = client.get(f"/authorize?{QS}&prompt=login")
        assert _is_login_page(page)

        resumed = client.get("/authorize?login_hint=persona-auto-login:admin")

        assert _is_login_page(resumed)
        assert transaction_id_of(resumed) == transaction_id_of(page)

    def test_auto_login_does_not_answer_a_request_that_asks_for_interaction(self, client, app):
        _enable_auto_login(app)

        for extra in ("&prompt=login", "&max_age=0"):
            response = client.get(f"/authorize?{QS}{extra}&login_hint=persona-auto-login:admin")
            assert _is_login_page(response), extra


class TestMaxAge:
    def test_a_session_within_max_age_is_reused(self, client):
        first = _login(client)

        response = client.get(f"/authorize?{QS}&max_age=10000")

        assert response.status_code == 302
        assert _exchange(client, response)["auth_time"] == first["auth_time"]

    def test_a_session_older_than_max_age_shows_the_page_and_the_new_auth_time_is_later(
        self, client
    ):
        first = _login(client)
        time.sleep(2.1)

        page = client.get(f"/authorize?{QS}&max_age=1")
        assert _is_login_page(page)
        done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})
        second = _exchange(client, done)

        assert second["auth_time"] > first["auth_time"]
        assert second["auth_time"] >= int(time.time()) - 5

    def test_auth_time_is_present_when_max_age_was_requested(self, client):
        claims = _login(client, "&max_age=300")

        assert isinstance(claims["auth_time"], int)


class TestConsentAndSelectAccount:
    def test_consent_is_consent_required(self, client):
        _login(client)

        assert _error_of(client.get(f"/authorize?{QS}&prompt=consent")) == "consent_required"

    def test_select_account_under_password_mode_is_account_selection_required(self, client):
        _login(client)

        response = client.get(f"/authorize?{QS}&prompt=select_account")

        assert _error_of(response) == "account_selection_required"

    def test_select_account_under_persona_mode_shows_the_picker_despite_a_session(
        self, client, app
    ):
        with app.app_context():
            get_config().settings.login_mode = "persona"
        page = client.get(f"/authorize?{QS}")
        done = client.post(
            "/authorize", data={"transaction_id": transaction_id_of(page), "username": "admin"}
        )
        assert done.status_code == 302
        assert client.get(f"/authorize?{QS}").status_code == 302

        picker = client.get(f"/authorize?{QS}&prompt=select_account")

        assert _is_login_page(picker)
        assert b"user1" in picker.data


class TestMalformedValues:
    def test_each_is_invalid_request_to_the_client(self, client):
        for extra in (
            "&prompt=bogus",
            "&prompt=none%20login",
            "&prompt=login%20none",
            "&max_age=abc",
            "&max_age=-1",
            "&max_age=1.5",
        ):
            assert _error_of(client.get(f"/authorize?{QS}{extra}")) == "invalid_request", extra
        assert pending_transaction_ids(client) == []

    def test_an_empty_value_is_an_omitted_parameter(self, client):
        assert _is_login_page(client.get(f"/authorize?{QS}&prompt=&max_age="))

    def test_the_refusal_stays_local_before_the_redirect_uri(self, client):
        refused = client.get(
            "/authorize?response_type=code&client_id=registered-client"
            "&redirect_uri=http://evil.example/cb&scope=openid&prompt=bogus"
        )

        assert refused.status_code == 400
        assert "Location" not in refused.headers


class TestFormPost:
    def test_prompt_and_max_age_travel_into_the_get_form(self, client):
        answer = client.post(
            "/authorize",
            data={
                "response_type": "code",
                "client_id": "demo-client",
                "redirect_uri": CALLBACK,
                "scope": "openid",
                "state": "s",
                "prompt": "none",
                "max_age": "60",
            },
        )

        assert answer.status_code == 303
        assert "prompt=none" in answer.headers["Location"]
        assert "max_age=60" in answer.headers["Location"]
