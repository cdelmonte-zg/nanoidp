"""
Tests for optional refresh token rotation (issue #46).

Off by default: the same refresh token can be reused indefinitely (old
behavior). When ``oauth.refresh_token_rotation`` is enabled, each refresh
invalidates the consumed refresh token (its jti joins the revocation list),
so reuse fails with 401 — letting clients test rotation and reuse-detection
handling (OAuth 2.0 Security BCP §4.14.2).
"""

import json

import pytest

from nanoidp.config import get_config


@pytest.fixture(autouse=True)
def clean_revoked_tokens():
    """The revocation list is module-global; keep tests isolated."""
    from nanoidp.routes.oauth import _revoked_tokens
    _revoked_tokens.clear()
    yield
    _revoked_tokens.clear()


def _password_grant(client, auth_header):
    resp = client.post(
        "/token",
        data={
            "grant_type": "password",
            "username": "admin",
            "password": "admin",
            "scope": "openid",
        },
        headers=auth_header,
    )
    assert resp.status_code == 200
    return json.loads(resp.data)


def _refresh(client, auth_header, refresh_token):
    return client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers=auth_header,
    )


class TestRotationDisabled:
    def test_default_is_off(self, app):
        with app.app_context():
            assert get_config().settings.refresh_token_rotation is False

    def test_refresh_token_is_reusable(self, client, auth_header):
        tokens = _password_grant(client, auth_header)
        first = _refresh(client, auth_header, tokens["refresh_token"])
        second = _refresh(client, auth_header, tokens["refresh_token"])
        assert first.status_code == 200
        assert second.status_code == 200


class TestRotationEnabled:
    @pytest.fixture(autouse=True)
    def enable_rotation(self, app):
        with app.app_context():
            get_config().settings.refresh_token_rotation = True
        yield

    def test_reuse_of_rotated_token_fails(self, client, auth_header):
        tokens = _password_grant(client, auth_header)
        first = _refresh(client, auth_header, tokens["refresh_token"])
        assert first.status_code == 200

        reuse = _refresh(client, auth_header, tokens["refresh_token"])
        assert reuse.status_code == 401

    def test_rotated_replacement_works(self, client, auth_header):
        tokens = _password_grant(client, auth_header)
        first = _refresh(client, auth_header, tokens["refresh_token"])
        rotated = json.loads(first.data)["refresh_token"]

        second = _refresh(client, auth_header, rotated)
        assert second.status_code == 200
        # The rotated chain still re-issues ID Tokens (scope persisted, #39)
        assert "id_token" in json.loads(second.data)

    def test_failed_refresh_does_not_consume_the_token(self, client, auth_header):
        """Revocation happens only after successful issuance: a rejected
        request (e.g. broadened scope, RFC 6749 §6) must leave the refresh
        token valid."""
        tokens = _password_grant(client, auth_header)
        broadened = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "scope": "openid profile email something-never-granted",
            },
            headers=auth_header,
        )
        assert broadened.status_code == 400

        retry = _refresh(client, auth_header, tokens["refresh_token"])
        assert retry.status_code == 200
