"""An authorization request sent to /authorize as a form POST (#467, OIDC
Core 3.1.2.1).

A POST that carries OAuth request fields in its body and no login field is
an authorization request in another serialization. It is answered with a
303 to the same request in GET form: the browser follows it as a top-level
GET, which carries the SameSite=Lax session cookie a cross-site POST does
not, and the GET is the one reader of a request. A POST that carries a
login field, even empty, or names a transaction, keeps the contract #325
and #346 gave it: it never reads OAuth parameters from its body, and the
fields it carries are audited as a forged request.
"""

import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from werkzeug.datastructures import MultiDict

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


def _redirected_to_get(response):
    """The 303 a form-serialized request is answered with: its target is
    /authorize with a query string, and the query string parsed."""
    assert response.status_code == 303
    target = urlsplit(response.headers["Location"])
    assert target.path == "/authorize"
    return target, parse_qs(target.query, keep_blank_values=True)


class TestAFormPostIsAnAuthorizationRequest:
    def test_the_suites_shape_is_redirected_to_its_get_and_then_issues_a_code(
        self, client, app
    ):
        """The conformance suite posts the authorization URL's query string
        as the body of a POST to the bare path, then fills the login form."""
        answer = client.post("/authorize", data=REQUEST_A)

        target, query = _redirected_to_get(answer)
        assert query == {field: [value] for field, value in REQUEST_A.items()}
        assert "Set-Cookie" not in answer.headers
        assert pending_transaction_ids(client) == []
        assert _ignored_body_fields(app) == []

        page = client.get(f"/authorize?{target.query}")
        assert page.status_code == 200
        transaction_id = transaction_id_of(page)
        assert pending_transaction_ids(client) == [transaction_id]

        done = client.post("/authorize", data={"transaction_id": transaction_id, **LOGIN})

        assert done.status_code == 302
        params = authorization_response_params(done)
        assert done.headers["Location"].startswith(CALLBACK)
        assert params["state"] == ["stA"]
        assert "code" in params
        assert pending_transaction_ids(client) == []

    def test_a_and_b_in_one_browser(self, client):
        """With B pending from a GET, the initial POST of A leads to A's login
        page in the same session, its form completes A, and B stays pending."""
        page_b = client.get(f"/authorize?{QS_B}")
        transaction_b = transaction_id_of(page_b)

        target, _ = _redirected_to_get(client.post("/authorize", data=REQUEST_A))
        page_a = client.get(f"/authorize?{target.query}")

        assert page_a.status_code == 200
        transaction_a = transaction_id_of(page_a)
        assert transaction_a != transaction_b
        assert pending_transaction_ids(client) == sorted([transaction_a, transaction_b])

        done = client.post("/authorize", data={"transaction_id": transaction_a, **LOGIN})

        assert done.status_code == 302
        assert authorization_response_params(done)["state"] == ["stA"]
        assert pending_transaction_ids(client) == [transaction_b]

    def test_every_body_field_is_carried_as_sent(self, client):
        """Repeated fields (resource, RFC 8707), unrelated ones (ignored by
        the GET, #328), empty values and login_hint all travel: the GET
        decides what they mean, the redirect does not."""
        body = [
            ("response_type", "code"),
            ("client_id", "demo-client"),
            ("redirect_uri", CALLBACK),
            ("scope", "openid"),
            ("resource", "https://api.example/a"),
            ("resource", "https://api.example/b"),
            ("state", ""),
            ("login_hint", "persona-auto-login:admin"),
            ("utm_source", "mail"),
        ]

        _, query = _redirected_to_get(client.post("/authorize", data=MultiDict(body)))

        assert query == {
            "response_type": ["code"],
            "client_id": ["demo-client"],
            "redirect_uri": [CALLBACK],
            "scope": ["openid"],
            "resource": ["https://api.example/a", "https://api.example/b"],
            "state": [""],
            "login_hint": ["persona-auto-login:admin"],
            "utm_source": ["mail"],
        }

    def test_a_request_the_get_refuses_is_refused_after_the_redirect(self, client):
        """The redirect validates nothing: a body the GET refuses before its
        redirect_uri lands on the GET's local 400."""
        body = _request(client_id="registered-client", redirect_uri="http://evil.example/cb")

        target, _ = _redirected_to_get(client.post("/authorize", data=body))
        refused = client.get(f"/authorize?{target.query}")

        assert refused.status_code == 400
        assert "Location" not in refused.headers
        assert refused.get_json() == client.get("/authorize", query_string=body).get_json()

    def test_persona_auto_login_answers_a_body_request_through_its_get(self, client, app):
        _enable_auto_login(app)

        target, _ = _redirected_to_get(
            client.post("/authorize", data=_request(login_hint="persona-auto-login:admin"))
        )
        response = client.get(f"/authorize?{target.query}")

        assert response.status_code == 302
        params = authorization_response_params(response)
        assert "code" in params
        assert params["state"] == ["stA"]
        assert pending_transaction_ids(client) == []

    def test_a_hint_alone_in_the_body_is_not_a_request(self, client, app):
        """A body carrying only login_hint resumes the pending page without
        applying the hint: a hint applies to a request it is sent with."""
        _enable_auto_login(app)
        page_b = client.get(f"/authorize?{QS_B}")

        response = client.post("/authorize", data={"login_hint": "persona-auto-login:admin"})

        assert response.status_code == 200
        assert transaction_id_of(response) == transaction_id_of(page_b)
        assert pending_transaction_ids(client) == [transaction_id_of(page_b)]

    def test_a_multipart_body_is_a_form_too(self, client):
        _, query = _redirected_to_get(
            client.post("/authorize", data=REQUEST_A, content_type="multipart/form-data")
        )

        assert query["client_id"] == ["demo-client"]

    def test_the_redirect_needs_no_cookie_and_sets_none(self, app):
        """A cross-site form POST arrives without the SameSite=Lax cookie.
        The 303 serves it without one and sets none, so the GET the browser
        follows with runs in the session the browser already has."""
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

        answer = app.test_client().post("/authorize", data=REQUEST_A)

        assert answer.status_code == 303
        assert "Set-Cookie" not in answer.headers


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
