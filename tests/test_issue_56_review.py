"""
Tests for the five review follow-ups of the 2026-06-11 merge block (issue #56).

1. Refresh tokens are bound to the client they were issued to.
2. Rotation consumes tokens atomically; reuse revokes the whole family.
3. stricter-dev rejects PKCE 'plain' even when the method is omitted
   (RFC 7636 §4.3 default) and unknown methods are rejected everywhere.
4. require_pkce survives a save/reload roundtrip.
5. The token response reports the scope actually granted (RFC 6749 §5.1).
"""

import json
import threading

import pytest

from nanoidp.config import get_config


@pytest.fixture(autouse=True)
def clean_revocation_state():
    from nanoidp.routes.oauth import _revoked_token_families, _revoked_tokens
    _revoked_tokens.clear()
    _revoked_token_families.clear()
    yield
    _revoked_tokens.clear()
    _revoked_token_families.clear()


def _password_grant(client, headers, scope="openid"):
    data = {"grant_type": "password", "username": "admin", "password": "admin"}
    if scope is not None:
        data["scope"] = scope
    resp = client.post("/token", data=data, headers=headers)
    assert resp.status_code == 200
    return json.loads(resp.data)


def _refresh(client, headers, refresh_token, scope=None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if scope is not None:
        data["scope"] = scope
    return client.post("/token", data=data, headers=headers)


class TestRefreshTokenClientBinding:
    """Finding 1: a refresh token may only be spent by its issuing client."""

    def test_other_client_cannot_spend_the_refresh_token(
        self, client, auth_header, test_auth_header
    ):
        tokens = _password_grant(client, auth_header)  # issued to demo-client
        resp = _refresh(client, test_auth_header, tokens["refresh_token"])
        assert resp.status_code == 401
        assert b"not issued to this client" in resp.data

    def test_issuing_client_can_refresh_and_aud_is_preserved(self, client, auth_header):
        import jwt as pyjwt

        tokens = _password_grant(client, auth_header)
        original_aud = pyjwt.decode(
            tokens["id_token"], options={"verify_signature": False}
        )["aud"]

        resp = _refresh(client, auth_header, tokens["refresh_token"])
        assert resp.status_code == 200
        refreshed_aud = pyjwt.decode(
            json.loads(resp.data)["id_token"], options={"verify_signature": False}
        )["aud"]
        # OIDC Core §12.2: the refreshed ID Token aud MUST equal the original
        assert refreshed_aud == original_aud == "demo-client"

    def test_legacy_refresh_token_without_binding_still_works(self, app, client, auth_header):
        """Tokens minted before the client_id claim existed keep working."""
        with app.app_context():
            from nanoidp.services import get_crypto_service
            settings = get_config().settings
            legacy = get_crypto_service(settings.keys_dir).create_jwt(
                sub="admin",
                issuer=settings.issuer,
                audience=settings.audience,
                extra={"token_type": "refresh", "token_use": "refresh"},
            )
        resp = _refresh(client, auth_header, legacy)
        assert resp.status_code == 200


class TestAtomicRotationAndFamilies:
    """Finding 2: atomic consumption + family revocation on reuse."""

    @pytest.fixture(autouse=True)
    def enable_rotation(self, app):
        with app.app_context():
            get_config().settings.refresh_token_rotation = True
        yield

    def test_malformed_extra_does_not_consume_the_token(self, client, auth_header):
        """'exp'/'extra' are validated before the grant dispatch, so a 400
        there never burns the refresh token (post-#56 review note)."""
        tokens = _password_grant(client, auth_header)

        bad = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "extra": "{not-json",
            },
            headers=auth_header,
        )
        assert bad.status_code == 400

        retry = _refresh(client, auth_header, tokens["refresh_token"])
        assert retry.status_code == 200

    def test_non_numeric_exp_is_a_400_and_does_not_consume(self, client, auth_header):
        """A non-numeric 'exp' used to raise an unhandled ValueError (500)."""
        tokens = _password_grant(client, auth_header)

        bad = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "exp": "abc",
            },
            headers=auth_header,
        )
        assert bad.status_code == 400

        retry = _refresh(client, auth_header, tokens["refresh_token"])
        assert retry.status_code == 200

    def test_non_object_extra_is_a_400_and_does_not_consume(self, client, auth_header):
        """json.loads('42') succeeds, but extra.update(42) would be a 500
        AFTER the claim — 'extra' must be a JSON object (second review)."""
        tokens = _password_grant(client, auth_header)

        for bad_extra in ("42", '"hello"', "[1, 2]"):
            resp = client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "extra": bad_extra,
                },
                headers=auth_header,
            )
            assert resp.status_code == 400, f"extra={bad_extra!r}"
            assert b"JSON object" in resp.data

        retry = _refresh(client, auth_header, tokens["refresh_token"])
        assert retry.status_code == 200

    def test_out_of_range_exp_is_a_400_and_does_not_consume(self, client, auth_header):
        """A huge 'exp' passes int() but overflows the timedelta arithmetic
        after the claim; the HTTP param now enforces the same 1..1440 bounds
        as the Settings model (second review)."""
        tokens = _password_grant(client, auth_header)

        for bad_exp in ("0", "-5", "2000", "9" * 30):
            resp = client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "exp": bad_exp,
                },
                headers=auth_header,
            )
            assert resp.status_code == 400, f"exp={bad_exp!r}"
            assert b"between 1 and 1440" in resp.data

        retry = _refresh(client, auth_header, tokens["refresh_token"])
        assert retry.status_code == 200

    def test_concurrent_double_refresh_succeeds_exactly_once(self, app, auth_header):
        tokens = _password_grant(app.test_client(), auth_header)
        refresh_token = tokens["refresh_token"]

        n = 6
        barrier = threading.Barrier(n)
        statuses = []
        lock = threading.Lock()

        def attempt():
            c = app.test_client()  # one client per thread
            barrier.wait()
            resp = _refresh(c, auth_header, refresh_token)
            with lock:
                statuses.append(resp.status_code)

        threads = [threading.Thread(target=attempt) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert statuses.count(200) == 1, (
            f"{statuses.count(200)} concurrent refreshes rotated the same token; "
            "atomic consumption requires exactly 1"
        )
        assert statuses.count(401) == n - 1

    def test_reuse_revokes_the_whole_family(self, client, auth_header):
        """RFC 9700 §4.14.2: reusing a consumed token must also kill the
        legitimate descendant, not just reject the stale copy."""
        tokens = _password_grant(client, auth_header)
        old = tokens["refresh_token"]

        rotated = json.loads(_refresh(client, auth_header, old).data)["refresh_token"]

        # Attacker replays the consumed token...
        assert _refresh(client, auth_header, old).status_code == 401
        # ...and the live descendant is now dead too.
        assert _refresh(client, auth_header, rotated).status_code == 401

    def test_separate_grants_are_separate_families(self, client, auth_header):
        """Reuse in one family must not affect tokens from other grants."""
        family_a = _password_grant(client, auth_header)["refresh_token"]
        family_b = _password_grant(client, auth_header)["refresh_token"]

        _refresh(client, auth_header, family_a)               # rotate A
        assert _refresh(client, auth_header, family_a).status_code == 401  # reuse A

        assert _refresh(client, auth_header, family_b).status_code == 200  # B unaffected


class TestImplicitPlainPkce:
    """Finding 3: omitted code_challenge_method defaults to 'plain'."""

    AUTHORIZE = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": "http://localhost:9000/callback",
    }

    def test_stricter_dev_rejects_omitted_method(self, app, client):
        with app.app_context():
            get_config().settings.security_profile = "stricter-dev"
        resp = client.get(
            "/authorize",
            query_string={**self.AUTHORIZE, "code_challenge": "x" * 43},
        )
        assert resp.status_code == 400
        assert "plain" in json.loads(resp.data)["error_description"]

    def test_dev_profile_still_accepts_omitted_method(self, client):
        resp = client.get(
            "/authorize",
            query_string={**self.AUTHORIZE, "code_challenge": "x" * 43},
        )
        assert resp.status_code == 200

    def test_unknown_method_rejected_in_any_profile(self, client):
        resp = client.get(
            "/authorize",
            query_string={
                **self.AUTHORIZE,
                "code_challenge": "x" * 43,
                "code_challenge_method": "S512",
            },
        )
        assert resp.status_code == 400
        assert "S512" in json.loads(resp.data)["error_description"]


class TestRequirePkcePersistence:
    """Finding 4: require_pkce must survive save() + reload."""

    def test_save_reload_roundtrip(self, app, preserve_config_files):
        with app.app_context():
            config = get_config()
            config.settings.require_pkce = True
            config.settings.refresh_token_rotation = True
            config.save()
            config.reload()
            assert config.settings.require_pkce is True
            assert config.settings.refresh_token_rotation is True


class TestHonestScopeResponse:
    """Finding 5: the response 'scope' reflects what was actually granted."""

    def test_password_grant_reports_granted_scope(self, client, auth_header):
        data = _password_grant(client, auth_header, "openid profile")
        assert data["scope"] == "openid profile"

    def test_narrowed_refresh_reports_narrowed_scope(self, client, auth_header):
        tokens = _password_grant(client, auth_header, "openid profile")
        resp = _refresh(client, auth_header, tokens["refresh_token"], scope="profile")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["scope"] == "profile"
        assert "id_token" not in data

    def test_scopeless_grant_omits_scope(self, client, auth_header):
        data = _password_grant(client, auth_header, scope=None)
        assert "scope" not in data

    def test_client_credentials_omits_scope_when_none_granted(self, client, auth_header):
        resp = client.post(
            "/token", data={"grant_type": "client_credentials"}, headers=auth_header
        )
        assert resp.status_code == 200
        assert "scope" not in json.loads(resp.data)
