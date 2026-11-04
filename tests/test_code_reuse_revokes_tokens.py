"""
Issue #466, RFC 6749 4.1.2: a reused authorization code is denied (as
before) and revokes the tokens issued from it: the access token of the
first exchange until its own expiry, and the whole refresh family.

The ids are drawn before the code is consumed and recorded with it in the
same decision, so a replay that arrives after the consumption and before
the first token is signed still finds them; the binding of the request to
the code (client, redirect URI, verifier) is verified before a reuse is
recognised, so whoever merely knows a used code revokes nothing; the
record stays until the code's own expiry, so a later reuse revokes again.
Introspection reads the family marker for a refresh token.
"""

import base64
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest

from nanoidp.config import get_config
from nanoidp.services.auth_code import CodeReused, IssuedTokens, get_auth_code_store
from nanoidp.services.revocation import get_revocation_store

REDIRECT = "http://localhost:3000/callback"
CLIENT = "registered-client"
BASIC = {
    "Authorization": "Basic " + base64.b64encode(b"registered-client:registered-secret").decode()
}
OTHER = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def _code(client, **extra):
    query = {
        "response_type": "code",
        "client_id": CLIENT,
        "redirect_uri": REDIRECT,
        "scope": "openid offline_access",
        "state": "s",
        **extra,
    }
    client.get("/authorize", query_string=query)
    resp = client.post(
        "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
    )
    return parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]


def _exchange(client, code, headers=BASIC, **extra):
    return client.post(
        "/token",
        headers=headers,
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, **extra},
    )


def _active(client, token):
    return client.post("/introspect", headers=BASIC, data={"token": token}).get_json()["active"]


def _failed_token_events(app):
    with app.app_context():
        from nanoidp.services import get_audit_log

        return [
            e
            for e in get_audit_log().get_entries(event_type="token_request")
            if e["status"] == "failed"
        ]


class TestAReuseRevokesWhatTheCodeIssued:
    def test_the_suite_shape(self, client, app):
        """oidcc-codereuse-30seconds: exchange, use the access token, reuse
        the code, use the access token again."""
        code = _code(client)
        first = _exchange(client, code).get_json()
        bearer = {"Authorization": "Bearer " + first["access_token"]}
        assert client.get("/userinfo", headers=bearer).status_code == 200

        reuse = _exchange(client, code)
        assert reuse.status_code == 400
        assert reuse.get_json() == {
            "error": "invalid_grant",
            "error_description": "Invalid or expired authorization code",
        }
        assert client.get("/userinfo", headers=bearer).status_code == 401
        assert _active(client, first["access_token"]) is False

    def test_the_refresh_family_goes_with_it(self, client):
        code = _code(client)
        first = _exchange(client, code).get_json()
        _exchange(client, code)
        refreshed = client.post(
            "/token",
            headers=BASIC,
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
        )
        assert refreshed.status_code == 400
        assert refreshed.get_json()["error"] == "invalid_grant"
        assert _active(client, first["refresh_token"]) is False

    def test_the_audit_names_the_reuse(self, client, app):
        code = _code(client)
        _exchange(client, code)
        _exchange(client, code)
        event = _failed_token_events(app)[0]
        assert (
            event["details"]["reason"]
            == "Authorization code reused: the tokens issued from it are revoked"
        )
        assert event["details"]["tokens_revoked"] is True
        assert event["client_id"] == CLIENT
        assert event["username"] == "admin"

    def test_a_later_reuse_revokes_again(self, client):
        """The record stays until the code's expiry: a reuse after a failed
        commit, or simply a third attempt, writes the same two markers."""
        code = _code(client)
        first = _exchange(client, code).get_json()
        _exchange(client, code)
        with client.application.app_context():
            get_revocation_store().clear()
        assert _active(client, first["access_token"]) is True
        assert _exchange(client, code).status_code == 400
        assert _active(client, first["access_token"]) is False
        assert _active(client, first["refresh_token"]) is False

    def test_the_access_token_carries_the_recorded_id_and_expiry(self, client):
        """What the code recorded before minting is what the token says:
        the same jti and the same exp, so the marker outlives the token by
        nothing and falls short of it by nothing."""
        code = _code(client)
        first = _exchange(client, code, exp="7").get_json()
        payload = jwt.decode(first["access_token"], options={"verify_signature": False})
        with client.application.app_context():
            record = get_auth_code_store().get_code_info(code)
        assert record.used is True
        assert record.issued.access_jti == payload["jti"]
        assert record.issued.access_exp == payload["exp"]
        assert int(record.issued_at) == payload["iat"]
        assert payload["exp"] - payload["iat"] == 7 * 60
        refresh = jwt.decode(first["refresh_token"], options={"verify_signature": False})
        assert record.issued.refresh_family == refresh["rt_family"]

    def test_the_instant_is_drawn_after_the_wait_for_the_store(self, client, app, monkeypatch):
        """A redemption may wait for a shared store; the token is minted at
        the instant of the decision, not at an instant drawn before the
        wait (review round 2)."""
        from nanoidp.services import auth_code as auth_code_module

        original = auth_code_module.AuthCodeStore.redeem_code

        def slow(self, *args, **kwargs):
            time.sleep(1.5)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(auth_code_module.AuthCodeStore, "redeem_code", slow)
        code = _code(client)
        started = time.time()
        first = _exchange(client, code).get_json()
        payload = jwt.decode(first["access_token"], options={"verify_signature": False})
        assert payload["iat"] >= int(started) + 1

    def test_the_token_is_minted_at_the_recorded_instant_however_late(
        self, client, app, monkeypatch
    ):
        """Between the decision and the signing anything may take a while
        (the user lookup, the key service); the token still carries the
        instant and the expiry the record holds, not a later one."""
        from nanoidp.routes import oauth_grants

        original = oauth_grants._issue_for_code

        def slow(*args, **kwargs):
            time.sleep(1.2)
            return original(*args, **kwargs)

        monkeypatch.setattr(oauth_grants, "_issue_for_code", slow)
        code = _code(client)
        first = _exchange(client, code).get_json()
        payload = jwt.decode(first["access_token"], options={"verify_signature": False})
        with app.app_context():
            record = get_auth_code_store().get_code_info(code)
        assert payload["iat"] == int(record.issued_at)
        assert payload["exp"] == record.issued.access_exp

    def test_an_exchange_that_fails_after_the_redemption_issued_nothing(
        self, client, app, monkeypatch
    ):
        """The user, the scope and the resource are checked after the code
        is consumed; a refusal there issued no token, so the record keeps
        nothing to revoke and a later presentation says so (review round
        2: no phantom markers, no audit of a revocation that did not
        happen)."""
        import types

        from nanoidp.routes import oauth_grants

        code = _code(client)
        monkeypatch.setattr(
            oauth_grants,
            "resolve_scope",
            lambda *a, **k: types.SimpleNamespace(
                ok=False, granted=None, error_description="narrowed"
            ),
        )
        assert _exchange(client, code).get_json()["error"] == "invalid_scope"
        monkeypatch.undo()
        with app.app_context():
            record = get_auth_code_store().get_code_info(code)
        assert record.used is True
        assert record.issued is None
        assert _exchange(client, code).status_code == 400
        event = _failed_token_events(app)[0]
        assert event["details"]["tokens_revoked"] is False
        assert event["details"]["reason"] == "Authorization code reused: nothing recorded to revoke"


class TestTheBindingIsVerifiedFirst:
    """A request that does not bind to the used code is refused and revokes
    nothing: whoever merely knows a used code cannot make its tokens
    revoked."""

    def test_another_client(self, client):
        code = _code(client)
        first = _exchange(client, code).get_json()
        assert _exchange(client, code, headers=OTHER).status_code == 400
        assert _active(client, first["access_token"]) is True
        assert _active(client, first["refresh_token"]) is True

    def test_another_redirect_uri(self, client):
        code = _code(client)
        first = _exchange(client, code).get_json()
        resp = client.post(
            "/token",
            headers=BASIC,
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT + "x"},
        )
        assert resp.status_code == 400
        assert _active(client, first["access_token"]) is True

    def test_a_wrong_verifier(self, client, pkce_verifier, pkce_challenge_s256):
        code = _code(client, code_challenge=pkce_challenge_s256, code_challenge_method="S256")
        first = _exchange(client, code, code_verifier=pkce_verifier).get_json()
        assert _exchange(client, code, code_verifier="not-the-verifier").status_code == 400
        assert _exchange(client, code).status_code == 400
        assert _active(client, first["access_token"]) is True
        assert _active(client, first["refresh_token"]) is True
        # The right verifier, replayed, is the reuse.
        assert _exchange(client, code, code_verifier=pkce_verifier).status_code == 400
        assert _active(client, first["access_token"]) is False


class TestTheReplayBeforeTheSignature:
    def test_a_token_delivered_after_the_replay_is_unusable(self, client, app, monkeypatch):
        """The interleaving: the code is consumed, the replay arrives, then
        the first token is signed and delivered. The ids were recorded with
        the consumption, so the replay revoked them, and the token carries
        exactly those."""
        from nanoidp.services import token as token_module

        code = _code(client)
        replay = app.test_client()
        original = token_module.TokenService.create_token
        seen = {}

        def replay_then_mint(self, *args, **kwargs):
            if not seen:
                seen["replay"] = _exchange(replay, code)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(token_module.TokenService, "create_token", replay_then_mint)
        first = _exchange(client, code)
        assert first.status_code == 200
        assert seen["replay"].status_code == 400
        delivered = first.get_json()
        bearer = {"Authorization": "Bearer " + delivered["access_token"]}
        assert client.get("/userinfo", headers=bearer).status_code == 401
        assert _active(client, delivered["access_token"]) is False
        assert _active(client, delivered["refresh_token"]) is False


class TestTheStore:
    def test_redeem_code_records_the_issued_ids_and_answers_a_reuse(self, app):
        with app.app_context():
            store = get_auth_code_store()
            code = store.create_code(CLIENT, REDIRECT, "admin")
            first = store.redeem_code(
                code,
                CLIENT,
                REDIRECT,
                access_jti="jti-1",
                refresh_family="family-1",
                access_lifetime_seconds=60,
            )
            assert first.used is True
            assert first.issued == IssuedTokens("jti-1", first.issued.access_exp, "family-1")
            assert 59 <= first.issued.access_exp - first.issued_at <= 61
            second = store.redeem_code(
                code,
                CLIENT,
                REDIRECT,
                access_jti="jti-2",
                refresh_family="family-2",
                access_lifetime_seconds=60,
            )
            assert second == CodeReused(first.issued, "admin")
            assert store.get_code_info(code).issued == first.issued  # the record stays as it was

    def test_the_issued_ids_go_together(self, app):
        """Half of what a redemption issues is refused, not recorded as
        nothing (review round 3)."""
        with app.app_context():
            store = get_auth_code_store()
            code = store.create_code(CLIENT, REDIRECT, "admin")
            with pytest.raises(ValueError):
                store.redeem_code(
                    code, CLIENT, REDIRECT, access_jti="jti", access_lifetime_seconds=60
                )
            assert store.get_code_info(code).used is False

    def test_an_unredeemed_code_is_written_without_the_new_keys(self, app):
        """A 3.4.0 process sharing the store reads a code this version
        created and did not redeem; only a redeemed record carries what
        it cannot read (review round 4)."""
        from nanoidp.services.auth_code import _CODEC

        with app.app_context():
            store = get_auth_code_store()
            code = store.create_code(CLIENT, REDIRECT, "admin")
            fresh = _CODEC.dump(store.get_code_info(code))
            assert "issued" not in fresh and "issued_at" not in fresh
            assert _CODEC.load(fresh).issued is None
            store.redeem_code(
                code,
                CLIENT,
                REDIRECT,
                access_jti="j",
                refresh_family="f",
                access_lifetime_seconds=60,
            )
            redeemed = _CODEC.dump(store.get_code_info(code))
            assert redeemed["issued"]["access_jti"] == "j" and redeemed["issued_at"] is not None
            assert _CODEC.load(redeemed).issued.access_jti == "j"

    def test_an_exception_after_the_redemption_forgets_the_ids(self, client, app, monkeypatch):
        from nanoidp.routes import oauth_grants

        code = _code(client)

        def boom(*args, **kwargs):
            raise RuntimeError("the signer is away")

        monkeypatch.setattr(oauth_grants, "_issue_for_code", boom)
        with pytest.raises(RuntimeError):
            _exchange(client, code)
        monkeypatch.undo()
        with app.app_context():
            record = get_auth_code_store().get_code_info(code)
        assert record.used is True and record.issued is None

    def test_a_record_without_an_instant_is_not_minted_at_the_epoch(self):
        """A redeemed code this version did not write carries no instant:
        refused loudly, never a token dated 1970 delivered with a 200
        (review round 3)."""
        from nanoidp.routes.oauth_grants import _minted_at
        from nanoidp.services.auth_code import AuthorizationCode

        record = AuthorizationCode(
            code="c",
            client_id=CLIENT,
            redirect_uri=REDIRECT,
            scope="openid",
            username="admin",
            used=True,
        )
        with pytest.raises(RuntimeError):
            _minted_at(record)

    def test_consume_code_keeps_its_contract(self, app):
        """The simpler reader: the code or None; a reuse is None, and a code
        it redeemed recorded nothing to revoke."""
        with app.app_context():
            store = get_auth_code_store()
            code = store.create_code(CLIENT, REDIRECT, "admin")
            assert store.consume_code(code, CLIENT, REDIRECT) is not None
            assert store.consume_code(code, CLIENT, REDIRECT) is None
            assert store.redeem_code(code, CLIENT, REDIRECT) == CodeReused(None, "admin")

    def test_a_reuse_with_nothing_recorded_revokes_nothing_and_says_so(self, client, app):
        """A code redeemed before #466 (or through consume_code) carries no
        ids: the reuse is denied, nothing is revoked, the audit says so."""
        with app.app_context():
            store = get_auth_code_store()
            code = store.create_code(CLIENT, REDIRECT, "admin")
            store.consume_code(code, CLIENT, REDIRECT)
        assert _exchange(client, code).status_code == 400
        event = _failed_token_events(app)[0]
        assert event["details"]["tokens_revoked"] is False

    def test_revoke_issued_is_one_decision_and_monotonic(self, app):
        with app.app_context():
            revocations = get_revocation_store()
            revocations.clear()
            access_exp = float(int(time.time())) + 3600
            revocations.revoke_issued("jti-a", access_exp, "family-a")
            assert revocations.is_revoked("jti-a") is True
            # The access marker lives exactly as long as the token; the
            # family's gets the bounded default from now, longer than that.
            assert revocations._markers.entry("jti:jti-a").expires_at == access_exp
            assert revocations._markers.entry("family:family-a").expires_at > access_exp
            assert revocations.is_family_revoked("family-a") is True
            assert revocations.is_family_revoked("family-b") is False
            assert revocations.is_family_revoked(None) is False
            # Again: nothing is written when both markers are there, so
            # neither is cut short nor moved.
            later = revocations._markers.entry("jti:jti-a").expires_at
            family_until = revocations._markers.entry("family:family-a").expires_at
            time.sleep(0.01)
            revocations.revoke_issued("jti-a", time.time() + 60, "family-a")
            assert revocations._markers.entry("jti:jti-a").expires_at == later
            assert revocations._markers.entry("family:family-a").expires_at == family_until


class TestIntrospectionReadsTheFamily:
    def test_a_descendant_of_a_revoked_family_is_inactive(self, client, app, auth_header):
        """The gap of #56: with rotation on, the reuse of a rotated refresh
        token revokes its family, and a descendant was still reported
        active by introspection."""
        with app.app_context():
            get_config().settings.refresh_token_rotation = True
        first = client.post(
            "/token",
            headers=auth_header,
            data={
                "grant_type": "password",
                "username": "admin",
                "password": "admin",
                "scope": "openid offline_access",
            },
        ).get_json()
        rotated = client.post(
            "/token",
            headers=auth_header,
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
        ).get_json()
        reuse = client.post(
            "/token",
            headers=auth_header,
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
        )
        assert reuse.status_code == 400
        resp = client.post(
            "/introspect", headers=auth_header, data={"token": rotated["refresh_token"]}
        )
        assert resp.get_json() == {"active": False}
