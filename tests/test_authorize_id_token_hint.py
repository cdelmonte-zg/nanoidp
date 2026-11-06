"""id_token_hint at /authorize (#468, OIDC Core 3.1.2.2).

The hint is verified with the server keys (signature by kid, issuer, type;
an expired one still names its subject) and binds the subject: a session
for that user is reused, a session for another is not; when a login is
needed, the code goes only to a login of that user; with prompt=none a
mismatch is login_required; a hint that does not verify is invalid_request.
A form POST's hint never enters the URL: the 303 carries a single-use
reference the GET resolves.
"""

import time

import jwt as pyjwt

from nanoidp.config import get_config
from nanoidp.services import get_crypto_service
from tests.conftest import (
    authorization_response_params,
    pending_transaction_ids,
    transaction_id_of,
)

CALLBACK = "http://localhost:3000/callback"
QS = f"response_type=code&client_id=demo-client&redirect_uri={CALLBACK}&scope=openid&state=s"
ADMIN = {"username": "admin", "password": "admin"}
USER1 = {"username": "user1", "password": "password"}


def _exchange(client, response):
    code = authorization_response_params(response)["code"][0]
    token = client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK},
        auth=("demo-client", "demo-secret"),
    ).get_json()
    return token["id_token"]


def _login(client, credentials=ADMIN, extra=""):
    """A full login through the page: the raw ID token."""
    page = client.get(f"/authorize?{QS}{extra}")
    assert page.status_code == 200, page.data[:200]
    done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **credentials})
    assert done.status_code == 302, done.data[:200]
    return _exchange(client, done)


def _is_login_page(response):
    return response.status_code == 200 and b'name="transaction_id"' in response.data


def _error_of(response):
    assert response.status_code == 302, response.data[:200]
    params = authorization_response_params(response)
    assert params["state"] == ["s"]
    return params.get("error", [None])[0]


def _mint(app, **claims):
    """An ID-token-shaped JWT signed by the server, with overrides."""
    with app.app_context():
        settings = get_config().settings
        extra = {"token_use": "id"}
        extra.update({k: v for k, v in claims.items() if k not in ("sub", "issuer", "exp_minutes")})
        return get_crypto_service().create_jwt(
            sub=claims.get("sub", "admin"),
            issuer=claims.get("issuer", settings.issuer),
            audience="demo-client",
            exp_minutes=claims.get("exp_minutes", 60),
            extra=extra,
        )


class TestWithASession:
    def test_a_hint_for_the_session_user_reuses_it(self, client):
        first = _login(client)
        first_claims = pyjwt.decode(first, options={"verify_signature": False})
        time.sleep(1.1)

        response = client.get(f"/authorize?{QS}&prompt=none&id_token_hint={first}")

        second = pyjwt.decode(_exchange(client, response), options={"verify_signature": False})
        assert second["sub"] == "admin"
        assert second["auth_time"] == first_claims["auth_time"]

    def test_an_expired_hint_still_names_its_subject(self, client, app):
        _login(client)
        expired = _mint(app, sub="admin", exp_minutes=-5)

        response = client.get(f"/authorize?{QS}&prompt=none&id_token_hint={expired}")

        assert "code" in authorization_response_params(response)

    def test_a_hint_for_another_user_with_prompt_none_is_login_required(self, client, app):
        _login(client)
        other = _mint(app, sub="user1")

        response = client.get(f"/authorize?{QS}&prompt=none&id_token_hint={other}")

        assert _error_of(response) == "login_required"

    def test_a_hint_for_another_user_without_prompt_none_asks_that_user_to_log_in(
        self, client, app
    ):
        _login(client)
        other = _mint(app, sub="user1")

        page = client.get(f"/authorize?{QS}&id_token_hint={other}")

        assert _is_login_page(page)
        done = client.post("/authorize", data={"transaction_id": transaction_id_of(page), **USER1})
        assert "code" in authorization_response_params(done)
        assert pyjwt.decode(_exchange(client, done), options={"verify_signature": False})["sub"] == "user1"


class TestTheBoundSubject:
    def test_a_login_by_another_user_is_login_required_and_ends_the_transaction(
        self, client, app
    ):
        hint = _mint(app, sub="user1")
        page = client.get(f"/authorize?{QS}&id_token_hint={hint}")
        assert _is_login_page(page)
        transaction_id = transaction_id_of(page)

        done = client.post("/authorize", data={"transaction_id": transaction_id, **ADMIN})

        assert _error_of(done) == "login_required"
        assert pending_transaction_ids(client) == []
        again = client.post("/authorize", data={"transaction_id": transaction_id, **USER1})
        assert again.status_code == 400

    def test_persona_auto_login_of_another_user_is_login_required(self, client, app):
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True
        hint = _mint(app, sub="user1")

        response = client.get(
            f"/authorize?{QS}&id_token_hint={hint}&login_hint=persona-auto-login:admin"
        )

        assert _error_of(response) == "login_required"

    def test_a_later_hint_only_get_cannot_auto_login_another_user(self, client, app):
        with app.app_context():
            get_config().settings.login_mode = "persona"
            get_config().settings.auto_login = True
        hint = _mint(app, sub="user1")
        page = client.get(f"/authorize?{QS}&id_token_hint={hint}")
        assert _is_login_page(page)

        resumed = client.get("/authorize?login_hint=persona-auto-login:admin")

        assert _error_of(resumed) == "login_required"


class TestTheTransactionDoesNotKeepTheToken:
    def _transaction(self):
        from nanoidp.services.authorization_transactions import (
            get_authorization_transaction_store,
        )

        (record,) = get_authorization_transaction_store()._repository.list()
        return record

    def test_requested_holds_a_digest_of_the_hint(self, client, app):
        hint = _mint(app, sub="admin")

        client.get(f"/authorize?{QS}&id_token_hint={hint}")

        assert hint not in self._transaction().model_dump_json()

    def test_the_login_form_posting_back_to_the_url_still_matches(self, client, app):
        """A browser form has no action: it posts to the GET's URL, whose
        query must be that request's, digest and all."""
        hint = _mint(app, sub="admin")
        url = f"/authorize?{QS}&id_token_hint={hint}"
        page = client.get(url)

        done = client.post(url, data={"transaction_id": transaction_id_of(page), **ADMIN})

        assert "code" in authorization_response_params(done)

    def test_another_hint_in_the_query_does_not_match(self, client, app):
        page = client.get(f"/authorize?{QS}&id_token_hint={_mint(app, sub='admin')}")
        other = _mint(app, sub="user1")

        refused = client.post(
            f"/authorize?{QS}&id_token_hint={other}",
            data={"transaction_id": transaction_id_of(page), **ADMIN},
        )

        assert refused.status_code == 400


class TestAHintThatDoesNotVerify:
    def test_each_is_invalid_request(self, client, app):
        with app.app_context():
            settings = get_config().settings
        garbage = "not.a.jwt"
        access = _mint(app, sub="admin", token_use="access")
        other_issuer = _mint(app, sub="admin", issuer="https://other.example")
        unsigned = pyjwt.encode(
            {"sub": "admin", "iss": settings.issuer, "token_use": "id"}, "secret", algorithm="HS256"
        )
        for hint in (garbage, access, other_issuer, unsigned):
            response = client.get(f"/authorize?{QS}&id_token_hint={hint}")
            assert _error_of(response) == "invalid_request", hint[:20]
        assert pending_transaction_ids(client) == []

    def test_the_refusal_stays_local_before_the_redirect_uri(self, client):
        refused = client.get(
            "/authorize?response_type=code&client_id=registered-client"
            "&redirect_uri=http://evil.example/cb&scope=openid&id_token_hint=garbage"
        )

        assert refused.status_code == 400
        assert "Location" not in refused.headers


class TestFormPost:
    def _body(self, hint):
        return {
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": CALLBACK,
            "scope": "openid",
            "state": "s",
            "id_token_hint": hint,
        }

    def test_the_hint_never_enters_the_url_and_the_reference_resolves_once(self, client, app):
        _login(client)
        hint = _mint(app, sub="admin")

        answer = client.post("/authorize", data=self._body(hint))

        assert answer.status_code == 303
        location = answer.headers["Location"]
        assert hint not in location
        assert "id_token_hint=ref%3A" in location
        query = location.split("?", 1)[1]
        followed = client.get(f"/authorize?{query}")
        assert "code" in authorization_response_params(followed)
        reused = client.get(f"/authorize?{query}")
        assert _error_of(reused) == "invalid_request"

    def test_a_hint_is_parked_only_for_a_known_client(self, client, app):
        """A sender naming no real client fills nothing: the hint becomes a
        reference that resolves to nothing, and the GET refuses the request
        rather than serving it without the hint."""
        from nanoidp.services.id_token_hint_references import get_parked_hint_store

        hint = _mint(app, sub="admin")
        answer = client.post("/authorize", data={**self._body(hint), "client_id": "nobody"})

        assert answer.status_code == 303
        assert "id_token_hint=ref%3Aunparked" in answer.headers["Location"]
        assert get_parked_hint_store()._repository.list() == []

    def test_a_repeated_hint_parks_nothing_and_is_refused(self, client, app):
        """One POST cannot fill the parked store: a repeated id_token_hint
        is refused locally before any reference is written."""
        from werkzeug.datastructures import MultiDict

        from nanoidp.services.id_token_hint_references import get_parked_hint_store

        body = MultiDict(list(self._body(_mint(app, sub="admin")).items()))
        body.add("id_token_hint", _mint(app, sub="user1"))

        refused = client.post("/authorize", data=body)

        assert refused.status_code == 400
        assert refused.get_json()["error"] == "invalid_request"
        assert get_parked_hint_store()._repository.list() == []

    def test_a_repeated_hint_on_a_get_is_invalid_request(self, client, app):
        hint = _mint(app, sub="admin")

        response = client.get(f"/authorize?{QS}&id_token_hint={hint}&id_token_hint={hint}")

        assert _error_of(response) == "invalid_request"
        assert pending_transaction_ids(client) == []

    def test_a_runtime_reset_drops_parked_references(self, client, app):
        hint = _mint(app, sub="admin")
        answer = client.post("/authorize", data=self._body(hint))
        query = answer.headers["Location"].split("?", 1)[1]

        client.delete("/api/runtime")

        assert _error_of(client.get(f"/authorize?{query}")) == "invalid_request"

    def test_a_hint_in_a_login_posts_body_is_audited_as_ignored(self, client, app):
        """#325's visibility: the three fields a request may carry beside
        the request fields are audited like them when a login POST body
        carries them; they are never read there."""
        page = client.get(f"/authorize?{QS}")
        hint = _mint(app, sub="user1")

        done = client.post(
            "/authorize",
            data={
                "transaction_id": transaction_id_of(page),
                **ADMIN,
                "id_token_hint": hint,
                "prompt": "none",
                "max_age": "0",
                "response_mode": "fragment",
            },
        )

        assert "code" in authorization_response_params(done)  # in the query: not read
        with app.app_context():
            from nanoidp.services import get_audit_log

            ignored = [
                e["details"]["fields"]
                for e in get_audit_log().get_entries(event_type="authorization_request")
                if e["details"].get("reason") == "OAuth parameters in POST body are ignored"
            ]
        assert ignored == [["prompt", "max_age", "id_token_hint", "response_mode"]]

    def test_an_unknown_reference_is_invalid_request(self, client, app):
        response = client.get(f"/authorize?{QS}&id_token_hint=ref:nothing")

        assert _error_of(response) == "invalid_request"
        with app.app_context():
            from nanoidp.services import get_audit_log

            failed = [
                e for e in get_audit_log().get_entries(event_type="authorization_request")
                if e["status"] == "failed"
            ]
        assert failed[0]["details"]["reason"] == "id_token_hint reference not resolvable"

    def test_an_expired_reference_is_invalid_request(self, client, app, monkeypatch):
        hint = _mint(app, sub="admin")
        answer = client.post("/authorize", data=self._body(hint))
        query = answer.headers["Location"].split("?", 1)[1]
        import nanoidp.services.id_token_hint_references as module

        real_time = time.time
        monkeypatch.setattr(module.time, "time", lambda: real_time() + 120)

        assert _error_of(client.get(f"/authorize?{query}")) == "invalid_request"
