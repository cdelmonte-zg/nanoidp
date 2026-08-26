"""
Issue #239: the client_credentials grant must not hand out a refresh token.

RFC 6749 §4.4.3: "A refresh token SHOULD NOT be included." The client
authenticates itself on every request; a refresh token bound to the default
user (or the synthetic service account) would be a second, long-lived
credential for a user the grant never authenticated. Every other grant keeps
issuing one.
"""

import base64
import json

import jwt as pyjwt
import pytest

from nanoidp.config import User, get_config
from nanoidp.routes.oauth import _GrantOutcome
from nanoidp.services.token import get_token_service

BASIC = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


@pytest.fixture
def oauth21(app):
    """Switch the active config to the oauth21 profile for one test."""
    with app.app_context():
        settings = get_config().settings
        settings.security_profile = "oauth21"
    yield settings
    settings.security_profile = "dev"


def _client_credentials(client, **form):
    response = client.post(
        "/token", data={"grant_type": "client_credentials", **form}, headers=BASIC
    )
    assert response.status_code == 200, response.data
    return json.loads(response.data)


class TestClientCredentialsResponse:
    def test_response_has_no_refresh_token_key(self, client):
        data = _client_credentials(client)

        assert "access_token" in data
        # The key is absent, not present with a null value.
        assert "refresh_token" not in data
        assert set(data) == {"access_token", "token_type", "expires_in"}

    def test_still_no_refresh_token_with_a_granted_scope(self, client):
        data = _client_credentials(client, scope="profile")

        assert data["scope"] == "profile"
        assert "refresh_token" not in data

    def test_still_no_refresh_token_under_oauth21(self, client, oauth21):
        data = _client_credentials(client)

        assert "access_token" in data
        assert "refresh_token" not in data

    def test_access_token_cannot_be_spent_as_a_refresh_token(self, client):
        """There is nothing to refresh with: the only token handed out is an
        access token, and the refresh grant rejects it as not a refresh token."""
        data = _client_credentials(client)

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": data["access_token"]},
            headers=BASIC,
        )

        assert response.status_code == 400
        assert b"Invalid token type" in response.data

    def test_grant_outcome_defaults_to_issuing_a_refresh_token(self):
        """Only client_credentials opts out; a new handler gets a refresh token
        unless it says otherwise."""
        outcome = _GrantOutcome(user=User(username="u", password="p"), username="u")

        assert outcome.issue_refresh_token is True


class TestOtherGrantsUnchanged:
    def test_password_grant_still_issues_a_refresh_token(self, client):
        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=BASIC,
        )
        data = json.loads(response.data)

        assert response.status_code == 200
        payload = pyjwt.decode(data["refresh_token"], options={"verify_signature": False})
        assert payload["token_type"] == "refresh"

    def test_refresh_grant_still_issues_a_refresh_token(self, client):
        first = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=BASIC,
        )
        refresh_token = json.loads(first.data)["refresh_token"]

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers=BASIC,
        )
        data = json.loads(response.data)

        assert response.status_code == 200
        assert "refresh_token" in data


class TestTokenServiceFlag:
    @pytest.fixture
    def user(self):
        return User(username="svc", password="x", roles=["user"], tenant="default")

    def test_flag_false_omits_the_refresh_token(self, app, user):
        with app.app_context():
            result = get_token_service().create_token(user, issue_refresh_token=False)

        assert "refresh_token" not in result
        assert "access_token" in result

    def test_flag_defaults_to_true(self, app, user):
        with app.app_context():
            result = get_token_service().create_token(user)

        payload = pyjwt.decode(result["refresh_token"], options={"verify_signature": False})
        assert payload["token_use"] == "refresh"
        assert "rt_family" in payload

    def test_flag_false_leaves_the_id_token_alone(self, app, user):
        """The refresh decision is independent of the ID Token decision."""
        with app.app_context():
            result = get_token_service().create_token(
                user, scope="openid", client_id="demo-client", issue_refresh_token=False
            )

        assert "id_token" in result
        assert "refresh_token" not in result
