"""response_mode at /authorize (#472, OAuth 2.0 Multiple Response Type
Encoding Practices 2.1, OAuth 2.0 Form Post Response Mode).

Three modes for the code flow, query the default: a code and every error
after the redirect_uri are delivered in the query, in the fragment, or as
a self-submitting form that posts to the redirect_uri. The mode is resolved
before any response is built, the request-object refusal included; an
unknown value or a repeated parameter is a local 400; a form_post cannot
reach a private-scheme redirect_uri. Discovery says so.
"""

import re
from urllib.parse import parse_qs, urlencode, urlsplit

from nanoidp.config import get_config
from tests.conftest import pending_transaction_ids, transaction_id_of

CALLBACK = "http://localhost:3000/callback"
BASE = {
    "response_type": "code",
    "client_id": "registered-client",
    "redirect_uri": CALLBACK,
    "scope": "openid",
    "state": "s",
}
LOGIN = {"username": "admin", "password": "admin"}


def _query_of(response):
    return parse_qs(urlsplit(response.headers["Location"]).query)


def _fragment_of(response):
    return parse_qs(urlsplit(response.headers["Location"]).fragment)


def _form_of(response):
    """The action and the hidden fields of a form_post page."""
    html = response.get_data(as_text=True)
    action = re.search(r'<form method="post" action="([^"]+)">', html).group(1)
    fields = dict(re.findall(r'name="([^"]+)" value="([^"]*)"', html))
    return action, fields


def _assert_plain_400(response):
    """OIDC Core 3.1.2.6: an unknown response_mode is a 400 that carries no
    OAuth error parameters."""
    assert response.status_code == 400
    assert "Location" not in response.headers
    assert response.get_json(silent=True) is None
    assert b"invalid_request" not in response.data
    assert b"error" not in response.data


def _login(client, **extra):
    """The response that carries the code: after the login, or at once
    when the browser's session is reused (#468)."""
    page = client.get("/authorize", query_string={**BASE, **extra})
    if b'name="transaction_id"' not in page.data:
        return page
    return client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})


class TestDiscovery:
    def test_the_three_modes_are_published(self, client):
        for path in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
            doc = client.get(path).get_json()
            assert doc["response_modes_supported"] == ["query", "fragment", "form_post"]


class TestACodeInEachMode:
    def test_query_is_the_default_and_the_explicit_one(self, client):
        for extra in ({}, {"response_mode": "query"}, {"response_mode": ""}):
            done = _login(client, **extra)
            assert done.status_code == 302
            assert done.headers["Location"].startswith(CALLBACK + "?")
            params = _query_of(done)
            assert "code" in params and params["state"] == ["s"]
            assert urlsplit(done.headers["Location"]).fragment == ""

    def test_fragment(self, client):
        done = _login(client, response_mode="fragment")

        assert done.status_code == 302
        assert done.headers["Location"].startswith(CALLBACK + "#")
        params = _fragment_of(done)
        assert "code" in params and params["state"] == ["s"]
        assert urlsplit(done.headers["Location"]).query == ""

    def test_form_post(self, client):
        done = _login(client, response_mode="form_post")

        assert done.status_code == 200
        assert "Location" not in done.headers
        assert done.headers["Cache-Control"] == "no-store"
        action, fields = _form_of(done)
        assert action == CALLBACK
        assert set(fields) >= {"code", "state"}
        assert fields["state"] == "s"
        assert 'onload="document.forms[0].submit()"' in done.get_data(as_text=True)

    def test_the_mode_is_kept_by_the_transaction_for_the_login_post(self, client):
        """The code is issued on the login POST, which carries no mode."""
        page = client.get("/authorize", query_string={**BASE, "response_mode": "fragment"})

        done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})

        assert "code" in _fragment_of(done)

    def test_a_code_in_a_fragment_reaches_a_native_client(self, client):
        native = {**BASE, "client_id": "ui-native", "redirect_uri": "com.example.app:/oauth2redirect"}
        page = client.get("/authorize", query_string={**native, "response_mode": "fragment"})
        done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **LOGIN})

        assert done.headers["Location"].startswith("com.example.app:/oauth2redirect#")


class TestAnErrorInEachMode:
    """Every deliverable error follows the mode: one after the redirect_uri
    (unsupported_response_type), one of #468 (login_required), and the
    request-object refusal of #463, which comes before the validators."""

    def _errors(self, client, mode):
        yield client.get(
            "/authorize", query_string={**BASE, "response_type": "token", "response_mode": mode}
        ), "unsupported_response_type"
        yield client.get(
            "/authorize", query_string={**BASE, "prompt": "none", "response_mode": mode}
        ), "login_required"
        yield client.get(
            "/authorize", query_string={**BASE, "request": "eyJ.obj.", "response_mode": mode}
        ), "request_not_supported"

    def test_in_the_query(self, client):
        for response, error in self._errors(client, "query"):
            assert _query_of(response)["error"] == [error]
            assert _query_of(response)["state"] == ["s"]

    def test_in_the_fragment(self, client):
        for response, error in self._errors(client, "fragment"):
            assert _fragment_of(response)["error"] == [error]
            assert _fragment_of(response)["state"] == ["s"]
            assert urlsplit(response.headers["Location"]).query == ""

    def test_as_a_form_post(self, client):
        for response, error in self._errors(client, "form_post"):
            assert response.status_code == 200
            assert response.headers["Cache-Control"] == "no-store"
            action, fields = _form_of(response)
            assert action == CALLBACK
            assert fields["error"] == error
            assert fields["state"] == "s"
            assert "error_description" in fields


class TestARequestThatNamesNoChannel:
    def test_an_unknown_mode_is_a_local_400_before_anything_else(self, client):
        for extra in (
            {"response_mode": "nonsense"},
            {"response_mode": "nonsense", "request": "eyJ.obj."},
            {"response_mode": "nonsense", "response_type": "token"},
            {"response_mode": "nonsense", "client_id": "unknown-client"},
        ):
            refused = client.get("/authorize", query_string={**BASE, **extra})
            _assert_plain_400(refused)
        assert pending_transaction_ids(client) == []

    def test_a_repeated_mode_is_a_local_400_even_with_valid_values(self, client):
        refused = client.get(
            "/authorize?response_type=code&client_id=registered-client"
            f"&redirect_uri={CALLBACK}&scope=openid&state=s"
            "&response_mode=query&response_mode=fragment"
        )

        _assert_plain_400(refused)

    def test_the_refusal_stays_audited(self, client, app):
        client.get("/authorize", query_string={**BASE, "response_mode": "nonsense"})

        with app.app_context():
            from nanoidp.services import get_audit_log

            entry = get_audit_log().get_entries(event_type="authorization_request")[0]
        assert entry["status"] == "failed"
        assert entry["client_id"] == "registered-client"

    def test_form_post_needs_an_explicit_host(self, client):
        """https:/callback passes as a scheme, but a browser resolves it
        against the page's own URL: the form would post the code to the IdP
        itself. Only an absolute URL with a host is a form action."""
        for uri in ("https:/callback", "https:///callback", "http:callback"):
            refused = client.get(
                "/authorize",
                query_string={
                    **BASE,
                    "client_id": "demo-client",
                    "redirect_uri": uri,
                    "response_mode": "form_post",
                },
            )
            assert refused.status_code == 400, uri
            assert "Location" not in refused.headers

    def test_form_post_to_a_private_scheme_is_a_local_400_after_the_redirect_uri(self, client):
        native = {**BASE, "client_id": "ui-native", "redirect_uri": "com.example.app:/oauth2redirect"}

        refused = client.get("/authorize", query_string={**native, "response_mode": "form_post"})

        assert refused.status_code == 400
        assert "Location" not in refused.headers
        assert refused.get_json()["error"] == "invalid_request"
        assert pending_transaction_ids(client) == []

    def test_the_request_object_refusal_stays_local_for_form_post_to_a_private_scheme(
        self, client
    ):
        native = {**BASE, "client_id": "ui-native", "redirect_uri": "com.example.app:/oauth2redirect"}

        refused = client.get(
            "/authorize", query_string={**native, "response_mode": "form_post", "request": "eyJ.obj."}
        )

        assert refused.status_code == 400
        assert refused.get_json()["error"] == "request_not_supported"

    def test_an_unregistered_redirect_uri_stays_local_whatever_the_mode(self, client):
        for mode in ("fragment", "form_post"):
            refused = client.get(
                "/authorize",
                query_string={**BASE, "redirect_uri": "http://evil.example/cb", "response_mode": mode},
            )
            assert refused.status_code == 400
            assert "Location" not in refused.headers


class TestFormPostRequest:
    def test_a_refused_request_gives_its_parked_hint_back(self, client):
        """The reference is taken before any refusal, so a request refused
        locally leaves no slot of the bounded store held until expiry."""
        from nanoidp.services.id_token_hint_references import get_parked_hint_store

        native = {**BASE, "client_id": "ui-native", "redirect_uri": "com.example.app:/oauth2redirect"}
        answer = client.post(
            "/authorize", data={**native, "response_mode": "form_post", "id_token_hint": "any"}
        )
        assert len(get_parked_hint_store()._repository.list()) == 1

        refused = client.get(answer.headers["Location"])

        assert refused.status_code == 400
        assert get_parked_hint_store()._repository.list() == []

    def test_the_mode_travels_into_the_get_form(self, client):
        answer = client.post("/authorize", data={**BASE, "response_mode": "form_post"})

        assert answer.status_code == 303
        assert "response_mode=form_post" in answer.headers["Location"]


class TestTheValueIsEscaped:
    def test_a_state_with_markup_cannot_break_out_of_the_form(self, client):
        done = _login(client, response_mode="form_post", state='"><script>x</script>')

        html = done.get_data(as_text=True)
        assert "<script>x</script>" not in html
        assert "&lt;script&gt;" in html


class TestAReusedSession:
    def test_the_code_follows_the_mode_of_the_request_that_reuses_it(self, client):
        _login(client)

        page = client.get("/authorize", query_string={**BASE, "response_mode": "form_post"})

        assert page.status_code == 200
        assert "code" in _form_of(page)[1]


class TestAFormPostPageIsNotReadableCrossOrigin:
    def test_the_app_wide_cors_rule_does_not_open_it(self, client, app):
        """In the query mode a code leaves in a Location a script cannot
        read; in a 200 body the app-wide CORS rule would hand it to any
        origin, with persona auto-login needing no cookie."""
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True
        origin = {"Origin": "http://evil.example"}

        page = client.get(
            "/authorize",
            query_string={
                **BASE,
                "response_mode": "form_post",
                "login_hint": "persona-auto-login:admin",
            },
            headers=origin,
        )

        assert "code" in _form_of(page)[1]
        assert page.headers.get("Access-Control-Allow-Origin") not in ("*", origin["Origin"])
        other = client.get("/.well-known/openid-configuration", headers=origin)
        assert other.headers.get("Access-Control-Allow-Origin") is not None


class TestTheConstraintsAreRequestFields:
    """response_mode, prompt, max_age and id_token_hint make a request like
    the others: never dropped, never a resume of the pending page."""

    def test_alone_in_a_query_they_are_a_request_not_a_resume(self, client):
        client.get("/authorize", query_string=BASE)

        for query in ("prompt=none", "max_age=0", "id_token_hint=x", "response_mode=fragment"):
            answer = client.get(f"/authorize?{query}")
            assert answer.status_code == 400, query
            assert b'name="transaction_id"' not in answer.data

    def test_a_query_that_adds_one_to_a_named_transaction_is_refused(self, client):
        page = client.get("/authorize", query_string=BASE)
        query = urlencode({**BASE, "response_mode": "nonsense"})

        refused = client.post(
            f"/authorize?{query}", data={"transaction_id": transaction_id_of(page), **LOGIN}
        )

        assert refused.status_code == 400

    def test_one_in_the_query_of_a_form_post_is_not_dropped_silently(self, client):
        """A query field makes the POST the direct entry point, read from
        that query: here it lacks the client, so a local 400, not a code in
        another mode than the one asked."""
        answer = client.post("/authorize?response_mode=form_post", data=BASE)

        assert answer.status_code == 400
        assert "Location" not in answer.headers

    def test_the_audit_reason_does_not_carry_the_value(self, client, app):
        client.get("/authorize", query_string={**BASE, "response_mode": "x" * 5000})

        with app.app_context():
            from nanoidp.services import get_audit_log

            entries = get_audit_log().get_entries(event_type="authorization_request")
        assert entries[0]["details"]["reason"] == "unknown response_mode"
