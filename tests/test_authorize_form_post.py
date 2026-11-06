"""An authorization request sent to /authorize as a form POST (#467, OIDC
Core 3.1.2.1).

A POST that carries OAuth request fields in its body and no login field is
an authorization request in another serialization, and takes the GET's
path: the same validators, persona auto-login under the same guards,
otherwise a transaction and its login page. A POST that carries a login
field, even empty, or names a transaction, keeps the contract #325 and
#346 gave it: it never reads OAuth parameters from its body, and the
fields it carries are audited as a forged request.
"""


import re
from pathlib import Path

from nanoidp.config import get_config
from nanoidp.routes.oauth import _AUTHORIZE_LOGIN_FIELDS
from tests.conftest import (
    authorization_response_params,
    pending_transaction_ids,
    transaction_id_of,
)

CALLBACK = "http://localhost:3000/callback"


def _request(**overrides):
    body = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": CALLBACK,
        "scope": "openid",
        "state": "stA",
        "nonce": "nA",
    }
    body.update(overrides)
    return body


REQUEST_A = _request()
REQUEST_B = _request(state="stB", nonce="nB")
QS_B = "&".join(f"{k}={v}" for k, v in REQUEST_B.items())
LOGIN = {"username": "admin", "password": "admin"}
BODY_FIELDS = ["response_type", "client_id", "redirect_uri", "scope", "state", "nonce"]


def _failed_authorization_events(app):
    with app.app_context():
        from nanoidp.services import get_audit_log

        entries = get_audit_log().get_entries(event_type="authorization_request")
    return [entry for entry in entries if entry["status"] == "failed"]


def _ignored_body_fields(app):
    return [
        event["details"]["fields"]
        for event in _failed_authorization_events(app)
        if event["details"].get("reason") == "OAuth parameters in POST body are ignored"
    ]


def _enable_auto_login(app):
    with app.app_context():
        get_config().settings.login_mode = "persona"
        get_config().settings.auto_login = True


class TestAFormPostIsAnAuthorizationRequest:
    def test_the_suites_shape_renders_a_login_page_and_then_issues_a_code(self, client, app):
        """The conformance suite posts the authorization URL's query string
        as the body of a POST to the bare path, then fills the login form."""
        page = client.post("/authorize", data=REQUEST_A)

        assert page.status_code == 200
        transaction_id = transaction_id_of(page)
        assert pending_transaction_ids(client) == [transaction_id]
        assert _ignored_body_fields(app) == []

        done = client.post("/authorize", data={"transaction_id": transaction_id, **LOGIN})

        assert done.status_code == 302
        params = authorization_response_params(done)
        assert done.headers["Location"].startswith(CALLBACK)
        assert params["state"] == ["stA"]
        assert "code" in params
        assert pending_transaction_ids(client) == []

    def test_a_and_b_in_one_browser(self, client):
        """With B pending from a GET, the initial POST of A renders A's login
        page, its form completes A, and B stays pending."""
        page_b = client.get(f"/authorize?{QS_B}")
        transaction_b = transaction_id_of(page_b)

        page_a = client.post("/authorize", data=REQUEST_A)

        assert page_a.status_code == 200
        transaction_a = transaction_id_of(page_a)
        assert transaction_a != transaction_b
        assert pending_transaction_ids(client) == sorted([transaction_a, transaction_b])

        done = client.post("/authorize", data={"transaction_id": transaction_a, **LOGIN})

        assert done.status_code == 302
        assert authorization_response_params(done)["state"] == ["stA"]
        assert pending_transaction_ids(client) == [transaction_b]

    def test_the_same_validators_as_a_get_before_the_redirect_uri(self, client, app):
        """A body request refused before its redirect_uri is validated is a
        local 400 without Location, the GET's answer to the same request,
        never a resumed page or a redirect."""
        client.get(f"/authorize?{QS_B}")
        before = pending_transaction_ids(client)

        for body in (
            _request(client_id="unknown-client"),
            _request(client_id="registered-client", redirect_uri="http://evil.example/cb"),
            _request(client_id=""),
            {"client_id": ""},
        ):
            refused = client.post("/authorize", data=body)
            as_a_get = client.get("/authorize", query_string=body)
            assert refused.status_code == 400, body
            assert "Location" not in refused.headers
            assert refused.get_json() == as_a_get.get_json()
            assert refused.get_json()["error_description"] != "No pending authorization request"
        assert pending_transaction_ids(client) == before
        assert _ignored_body_fields(app) == []

    def test_the_same_validators_as_a_get_after_the_redirect_uri(self, client):
        """An error after the redirect_uri is validated goes to it with the
        body's state, as a GET's would."""
        refused = client.post("/authorize", data=_request(response_type="token"))

        assert refused.status_code == 302
        params = authorization_response_params(refused)
        assert refused.headers["Location"].startswith(CALLBACK)
        assert params["error"] == ["unsupported_response_type"]
        assert params["state"] == ["stA"]
        assert pending_transaction_ids(client) == []

    def test_persona_auto_login_answers_a_body_request(self, client, app):
        _enable_auto_login(app)

        response = client.post(
            "/authorize", data=_request(login_hint="persona-auto-login:admin")
        )

        assert response.status_code == 302
        params = authorization_response_params(response)
        assert "code" in params
        assert params["state"] == ["stA"]
        assert pending_transaction_ids(client) == []

    def test_an_unknown_persona_in_a_body_request_is_reported_to_the_redirect_uri(
        self, client, app
    ):
        _enable_auto_login(app)

        response = client.post(
            "/authorize", data=_request(login_hint="persona-auto-login:nobody")
        )

        assert response.status_code == 302
        params = authorization_response_params(response)
        assert params["error"] == ["invalid_request"]
        assert params["state"] == ["stA"]

    def test_a_hint_alone_in_the_body_is_not_a_request(self, client, app):
        """A body carrying only login_hint resumes the pending page without
        applying the hint: a hint applies to a request it is sent with."""
        _enable_auto_login(app)
        page_b = client.get(f"/authorize?{QS_B}")

        response = client.post("/authorize", data={"login_hint": "persona-auto-login:admin"})

        assert response.status_code == 200
        assert transaction_id_of(response) == transaction_id_of(page_b)
        assert pending_transaction_ids(client) == [transaction_id_of(page_b)]

    def test_the_login_page_of_a_body_request_carries_the_same_forms_as_a_gets(
        self, client
    ):
        from_get = client.get(f"/authorize?{QS_B}").get_data(as_text=True)
        from_post = client.post("/authorize", data=REQUEST_B).get_data(as_text=True)

        def shape(html):
            return html.replace(transaction_id_of_html(html), "TID")

        def transaction_id_of_html(html):
            return re.search(r'name="transaction_id" value="([^"]+)"', html).group(1)

        assert shape(from_get) == shape(from_post)

    def test_a_multipart_body_is_read_as_a_form_too(self, client):
        page = client.post(
            "/authorize", data=REQUEST_A, content_type="multipart/form-data"
        )

        assert page.status_code == 200
        assert pending_transaction_ids(client) == [transaction_id_of(page)]

    def test_a_form_post_without_the_session_cookie_starts_a_new_browser_session(
        self, app
    ):
        """A browser sends a SameSite=Lax cookie on a top-level GET but not
        on a cross-site POST, so a form POST from another site's page
        arrives without one, and the login page's response sets a new
        session cookie that replaces the browser's. This pins the fact the
        reference documents: the request is served, with a new session."""
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

        page = app.test_client().post("/authorize", data=REQUEST_A)

        assert page.status_code == 200
        assert "Set-Cookie" in page.headers
        assert "session=" in page.headers["Set-Cookie"]


class TestTheLoginFieldsAreTheTemplatesFields:
    def test_every_field_a_login_form_sends_is_a_login_field(self):
        """The classification keys on the fields the login screens send:
        a field added to a template without being added to the tuple would
        let a POST carrying it beside a body request be taken for a
        request. The templates are the source of truth here."""
        import nanoidp

        templates = Path(nanoidp.__file__).parent / "templates"
        sent = set()
        for name in ("authorize.html", "_macros.html"):
            html = (templates / name).read_text()
            sent.update(
                re.findall(r'<(?:input|button|select|textarea)\b[^>]*\bname="([^"]+)"', html)
            )
        assert sent, "no form field found in the templates"
        assert sent <= set(_AUTHORIZE_LOGIN_FIELDS), sent - set(_AUTHORIZE_LOGIN_FIELDS)


class TestALoginFieldKeepsThePreexistingPath:
    """Presence of a login field, even empty, or of transaction_id, keeps the
    POST on the paths #325 and #346 defined; its body fields are audited
    and ignored."""

    def test_a_body_carrying_a_request_and_credentials_logs_in_on_the_pending_request(
        self, client, app
    ):
        client.get(f"/authorize?{QS_B}")

        done = client.post("/authorize", data={**REQUEST_A, **LOGIN})

        assert done.status_code == 302
        assert authorization_response_params(done)["state"] == ["stB"]
        assert pending_transaction_ids(client) == []
        assert _ignored_body_fields(app) == [BODY_FIELDS]

    def test_a_body_carrying_a_request_and_credentials_with_nothing_pending_is_refused(
        self, client, app
    ):
        refused = client.post("/authorize", data={**REQUEST_A, **LOGIN})

        assert refused.status_code == 400
        assert refused.get_json()["error_description"] == "No pending authorization request"
        assert pending_transaction_ids(client) == []
        assert _ignored_body_fields(app) == [BODY_FIELDS]

    def test_an_empty_transaction_id_keeps_the_preexisting_path(self, client, app):
        page_b = client.get(f"/authorize?{QS_B}")

        resumed = client.post("/authorize", data={**REQUEST_A, "transaction_id": ""})

        assert resumed.status_code == 200
        assert transaction_id_of(resumed) == transaction_id_of(page_b)
        assert pending_transaction_ids(client) == [transaction_id_of(page_b)]
        assert _ignored_body_fields(app) == [BODY_FIELDS]

    def test_an_empty_login_field_keeps_the_preexisting_path(self, client, app):
        for field in ("username", "password", "totp_code", "pending_second_factor", "change_username"):
            refused = client.post("/authorize", data={**REQUEST_A, field: ""})
            assert refused.status_code == 400, field
            assert refused.get_json()["error_description"] == "No pending authorization request"
        assert pending_transaction_ids(client) == []
        assert len(_ignored_body_fields(app)) == 5

    def test_a_named_transaction_ignores_the_request_in_its_body(self, client, app):
        page_b = client.get(f"/authorize?{QS_B}")

        done = client.post(
            "/authorize", data={**REQUEST_A, "transaction_id": transaction_id_of(page_b), **LOGIN}
        )

        assert done.status_code == 302
        assert authorization_response_params(done)["state"] == ["stB"]
        assert _ignored_body_fields(app) == [BODY_FIELDS]

    def test_the_direct_entry_point_reads_the_query_not_the_body(self, client, app):
        done = client.post(f"/authorize?{QS_B}", data={**REQUEST_A, **LOGIN})

        assert done.status_code == 302
        assert authorization_response_params(done)["state"] == ["stB"]
        assert _ignored_body_fields(app) == [BODY_FIELDS]

    def test_the_direct_entry_point_wins_over_a_body_request_without_login_fields(
        self, client, app
    ):
        """Query and body both carrying a request, no login field: the query
        is the documented entry point, the body is forged."""
        page = client.post(f"/authorize?{QS_B}", data=REQUEST_A)

        assert page.status_code == 200
        assert 'name="transaction_id"' not in page.get_data(as_text=True)
        assert pending_transaction_ids(client) == []
        assert _ignored_body_fields(app) == [BODY_FIELDS]
