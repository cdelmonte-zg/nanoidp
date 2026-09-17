"""
Integration tests for OAuth2 flows.
Tests complete authorization code flow, password grant, client credentials, and refresh token.
"""

import base64
import json

import pytest

from tests.conftest import (
    authorization_response_params,
    authorize_error,
    pending_transaction_ids,
    transaction_id_of,
)


class TestAuthorizationCodeFlow:
    """Tests for OAuth2 Authorization Code Flow."""

    def test_authorize_get_shows_login_form(self, client):
        """Test that GET /authorize shows the login form."""
        response = client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )

        assert response.status_code == 200
        assert b'username' in response.data
        assert b'password' in response.data

    def test_authorize_requires_response_type(self, client):
        """Test that response_type is required."""
        response = client.get(
            '/authorize?client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback'
        )

        assert response.status_code == 302
        assert authorize_error(response)["error"] == "unsupported_response_type"

    def test_authorize_requires_client_id(self, client):
        """Test that client_id is required."""
        response = client.get(
            '/authorize?response_type=code'
            '&redirect_uri=http://localhost:3000/callback'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"

    def test_authorize_requires_redirect_uri(self, client):
        """Test that redirect_uri is required."""
        response = client.get(
            '/authorize?response_type=code&client_id=demo-client'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"

    def test_authorize_validates_client_id(self, client):
        """Test that invalid client_id is rejected."""
        response = client.get(
            '/authorize?response_type=code&client_id=unknown-client'
            '&redirect_uri=http://localhost:3000/callback'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "invalid_client"

    def test_authorize_post_invalid_credentials(self, client):
        """Test that invalid login credentials show error."""
        # First GET to set session
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )

        # POST with wrong credentials
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'wrong-password'
        })

        assert response.status_code == 200
        assert b'Invalid username or password' in response.data

    def test_authorize_post_success_redirects(self, client):
        """Test that successful login redirects with code."""
        # First GET to set session
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=test123'
        )

        # POST with valid credentials
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        assert response.status_code == 302
        location = response.headers.get('Location')
        assert 'http://localhost:3000/callback' in location
        assert 'code=' in location
        assert 'state=test123' in location

    def test_authorize_post_ignores_form_body_oauth_params(self, client, app):
        """#325: forged OAuth parameters in the login
        POST body must not override the request validated on GET - the
        issued code must still be bound to what the user actually approved.
        """
        # First GET to set session with the real request.
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=test123'
        )

        # POST with valid credentials PLUS a forged set of OAuth params
        # trying to redirect the issued code to an attacker-controlled URI.
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin',
            'response_type': 'token',
            'client_id': 'test-client',
            'redirect_uri': 'http://evil.example/cb',
            'state': 'evil-state',
            'scope': 'admin-only',
        }, follow_redirects=False)

        assert response.status_code == 302
        location = response.headers.get('Location')
        assert location.startswith('http://localhost:3000/callback')
        assert 'evil.example' not in location
        assert 'code=' in location
        assert 'state=test123' in location
        assert 'state=evil-state' not in location

        with app.app_context():
            from nanoidp.services import get_audit_log

            entries = get_audit_log().get_entries(event_type='authorization_request')
        forged = next(entry for entry in entries if entry['status'] == 'failed')
        assert 'response_type' in forged['details']['fields']

    def test_authorize_post_survives_another_tab_clearing_the_session(self, client):
        """#325 review round 1, point 1 ("cross-tab clearing"): a completed
        login in another tab sharing the same cookie jar consumes only that
        tab's own authorization transaction (#346). The login form has no
        ``action``, so this tab's POST lands back on the exact
        ``/authorize?...`` URL of its GET, which names its own transaction.
        """
        qs = (
            'response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )
        client.get(f'/authorize?{qs}')

        # A second tab, same cookie jar: a different client's request
        # completes.
        tab_b = (
            'response_type=code&client_id=test-client'
            '&redirect_uri=http://localhost:4000/callback&scope=openid&state=tab-b'
        )
        client.get(f'/authorize?{tab_b}')
        completed = client.post(
            f'/authorize?{tab_b}', data={'username': 'admin', 'password': 'admin'}
        )
        assert completed.status_code == 302

        # Tab A submits valid credentials on its OWN URL.
        response = client.post(f'/authorize?{qs}', data={
            'username': 'admin',
            'password': 'admin',
        }, follow_redirects=False)

        assert response.status_code == 302
        location = response.headers['Location']
        assert location.startswith('http://localhost:3000/callback')
        assert 'state=tab-a' in location

    def test_authorize_post_is_not_hijacked_by_another_tabs_get(self, client):
        """#325 review round 1, point 1 ("cross-tab overwrite"): a second
        tab's mere GET creates a transaction of its own (#346) and touches
        nothing of Tab A's. Tab A's POST, landing back on its own
        ``/authorize?...`` URL, stays bound to what Tab A's user actually
        saw and approved, not Tab B's client.
        """
        qs = (
            'response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )
        client.get(f'/authorize?{qs}')

        # A second tab, same cookie jar, merely opens a different request -
        # never logs in.
        client.get(
            '/authorize?response_type=code&client_id=test-client'
            '&redirect_uri=http://localhost:4000/callback&scope=openid&state=tab-b'
        )

        response = client.post(f'/authorize?{qs}', data={
            'username': 'admin',
            'password': 'admin',
        }, follow_redirects=False)

        assert response.status_code == 302
        location = response.headers['Location']
        assert location.startswith('http://localhost:3000/callback')
        assert 'state=tab-a' in location
        assert 'localhost:4000' not in location

    def test_authorize_does_not_inherit_optional_params_from_abandoned_request(
        self, client, app, test_auth_header
    ):
        """#328: an earlier request's optional parameters - here left behind
        by tab A, never completed - must not leak into a distinct, later
        request from a different client that simply doesn't send them (a
        client not sending ``state``/``nonce``/PKCE/``claims``/``resource``
        at all, not one sending them empty). Each request is its own
        transaction (#346), so there is nothing to inherit from.
        """
        # Tab A: a request carrying every optional value, then abandoned.
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid%20profile'
            '&state=tab-a-state&nonce=tab-a-nonce'
            '&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'
            '&code_challenge_method=plain'
            '&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%7D%7D'
            '&resource=https%3A%2F%2Fapi.example.com%2Fv1'
        )

        # Tab B: a different client's fresh request that omits scope and all
        # optional binding parameters.
        tab_b = (
            '/authorize?response_type=code&client_id=test-client'
            '&redirect_uri=http://localhost:4000/callback'
        )
        client.get(tab_b)
        response = client.post(
            tab_b,
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )

        assert response.status_code == 302
        location = response.headers['Location']
        assert location.startswith('http://localhost:4000/callback')
        assert 'state=' not in location
        assert 'tab-a-state' not in location

        code = location.split('code=')[1].split('&')[0]
        with app.app_context():
            from nanoidp.services.auth_code import get_auth_code_store

            info = get_auth_code_store().get_code_info(code)
        assert info is not None
        assert info.state is None
        assert info.nonce is None
        assert info.scope == 'openid'
        assert info.code_challenge is None
        assert info.code_challenge_method is None
        assert info.claims is None
        assert info.resource is None

        # A stale PKCE challenge would make this exchange fail without a
        # verifier; successful redemption proves it was not inherited.
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:4000/callback',
        }, headers=test_auth_header)
        assert response.status_code == 200

    def test_fresh_get_for_same_client_clears_abandoned_optional_params(self, client, app):
        """#328: a new attempt is complete even when it reuses the same client."""
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
            '&state=old-state&nonce=old-nonce'
        )

        page = client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )
        response = client.post(
            '/authorize',
            data={
                'username': 'admin',
                'password': 'admin',
                'transaction_id': transaction_id_of(page),
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert 'state=' not in response.headers['Location']
        code = response.headers['Location'].split('code=')[1].split('&')[0]
        with app.app_context():
            from nanoidp.services.auth_code import get_auth_code_store

            info = get_auth_code_store().get_code_info(code)
        assert info is not None
        assert info.state is None
        assert info.nonce is None

    def test_authorize_unrelated_query_param_preserves_pending_request(self, client):
        """#328: non-OAuth query parameters must not disable whole-request fallback."""
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )

        response = client.post(
            '/authorize?tracking=abc',
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers['Location'].startswith('http://localhost:3000/callback')
        assert 'state=tab-a' in response.headers['Location']

    def test_empty_client_id_is_a_new_request_and_does_not_replace_pending(self, client):
        """#329 review: presence, not truthiness, selects the query-string request."""
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )
        partial = (
            '/authorize?response_type=code&client_id='
            '&redirect_uri=http://localhost:4000/callback&state=evil'
        )

        assert client.get(partial).status_code == 400
        assert client.post(
            partial,
            data={'username': 'admin', 'password': 'admin'},
        ).status_code == 400

        response = client.post(
            '/authorize',
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers['Location'].startswith('http://localhost:3000/callback')
        assert 'state=tab-a' in response.headers['Location']

    def test_incomplete_get_does_not_replace_pending_request(self, client):
        """#329 review: only a complete GET becomes the resumable request."""
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )

        assert client.get('/authorize?client_id=demo-client').status_code == 400

        response = client.post(
            '/authorize',
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers['Location'].startswith('http://localhost:3000/callback')
        assert 'state=tab-a' in response.headers['Location']

    @pytest.mark.parametrize(
        ("rejected_query", "expected_status"),
        [
            (
                "response_type=code&client_id=demo-client"
                "&redirect_uri=http://localhost:3000/callback"
                "&scope=not-a-real-scope&state=evil",
                302,
            ),
            (
                "response_type=code&client_id=unknown-client"
                "&redirect_uri=http://localhost:3000/callback"
                "&scope=openid&state=evil",
                400,
            ),
            (
                "response_type=code&client_id=demo-client"
                "&redirect_uri=http://localhost:3000/unregistered"
                "&scope=openid&state=evil",
                400,
            ),
            (
                "response_type=token&client_id=demo-client"
                "&redirect_uri=http://localhost:3000/callback"
                "&scope=openid&state=evil",
                302,
            ),
            (
                "response_type=code&client_id=demo-client"
                "&redirect_uri=http://localhost:3000/callback"
                "&scope=openid&state=evil&code_challenge=challenge"
                "&code_challenge_method=invalid",
                302,
            ),
            (
                "response_type=code&client_id=demo-client"
                "&redirect_uri=http://localhost:3000/callback"
                "&scope=openid&state=evil&resource=https%3A%2F%2Fapi.example%2F%23fragment",
                302,
            ),
        ],
        ids=(
            "invalid-scope",
            "unknown-client",
            "unregistered-redirect-uri",
            "unsupported-response-type",
            "invalid-pkce",
            "invalid-resource",
        ),
    )
    def test_rejected_get_preserves_pending_request(
        self, app, client, rejected_query, expected_status
    ):
        """#331: a rejected GET is not an authorization request in flight."""
        with app.app_context():
            from nanoidp.config import get_config

            get_config().get_client("demo-client").redirect_uris = [
                "http://localhost:3000/callback"
            ]

        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )
        captured = pending_transaction_ids(client)

        rejected = client.get(f"/authorize?{rejected_query}", follow_redirects=False)

        assert rejected.status_code == expected_status
        assert pending_transaction_ids(client) == captured

        response = client.post(
            '/authorize',
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers['Location'].startswith('http://localhost:3000/callback')
        response_params = authorization_response_params(response)
        assert response_params["state"] == ["tab-a"]
        assert "error" not in response_params
        assert len(response_params["code"]) == 1

        with app.app_context():
            from nanoidp.services.auth_code import get_auth_code_store

            info = get_auth_code_store().get_code_info(response_params["code"][0])
        assert info is not None
        assert info.client_id == "demo-client"
        assert info.redirect_uri == "http://localhost:3000/callback"
        assert info.scope == "openid"
        assert info.state == "tab-a"

    def test_valid_get_stores_the_validated_request(self, app, client):
        """#346: a transaction holds the request as validated and normalized
        once; the POST that completes it does not validate it again."""
        resource = "https%3A%2F%2Fapi.example.com%2Fv1"

        response = client.get(
            "/authorize?response_type=code&client_id=demo-client"
            "&redirect_uri=http://localhost:3000/callback"
            f"&resource={resource}&resource={resource}"
        )

        assert response.status_code == 200
        with app.app_context():
            from nanoidp.services.authorization_transactions import (
                get_authorization_transaction_store,
            )

            (transaction,) = [
                t
                for t in get_authorization_transaction_store()._repository.list()
                if t.id == transaction_id_of(response)
            ]
        assert transaction.params.scope == "openid"
        assert transaction.params.resources == ["https://api.example.com/v1"]
        assert transaction.requested["resource"] == [
            "https://api.example.com/v1",
            "https://api.example.com/v1",
        ]

        resumed = client.post(
            "/authorize",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )

        assert resumed.status_code == 302
        response_params = authorization_response_params(resumed)
        assert "error" not in response_params
        with app.app_context():
            from nanoidp.services.auth_code import get_auth_code_store

            info = get_auth_code_store().get_code_info(response_params["code"][0])
        assert info is not None
        assert info.scope == "openid"
        assert info.resource == ["https://api.example.com/v1"]

    def test_rejected_get_without_pending_request_creates_no_capture(self, client):
        """#331: a rejected request creates no transaction."""
        response = client.get(
            "/authorize?response_type=code&client_id=unknown-client"
            "&redirect_uri=http://localhost:3000/callback&state=evil"
        )

        assert response.status_code == 400
        assert pending_transaction_ids(client) == []

    def test_post_naming_another_request_is_refused(self, client):
        """#346: a POST whose query string names a request no GET of this
        browser created has no transaction to continue, and the pending one
        is left as it was."""
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )

        refused = client.post(
            '/authorize?response_type=code&client_id=test-client'
            '&redirect_uri=http://localhost:4000/callback&scope=openid&state=tab-b',
            data={'username': 'admin', 'password': 'admin'},
        )
        assert refused.status_code == 400
        assert refused.get_json()['error'] == 'invalid_request'

        response = client.post(
            '/authorize',
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers['Location'].startswith('http://localhost:3000/callback')
        assert 'state=tab-a' in response.headers['Location']

    def test_bare_post_with_several_pending_requests_is_refused(self, client):
        """#346: a POST that names no transaction resumes the browser's one
        pending request; with several it refuses rather than guesses which,
        and a POST naming one still completes it."""
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid&state=tab-a'
        )
        page_b = client.get(
            '/authorize?response_type=code&client_id=test-client'
            '&redirect_uri=http://localhost:4000/callback&scope=openid&state=tab-b'
        )

        ambiguous = client.post(
            '/authorize',
            data={'username': 'admin', 'password': 'admin'},
            follow_redirects=False,
        )
        assert ambiguous.status_code == 400
        assert 'Several authorization requests' in ambiguous.get_json()['error_description']
        assert len(pending_transaction_ids(client)) == 2

        response = client.post(
            '/authorize',
            data={
                'username': 'admin',
                'password': 'admin',
                'transaction_id': transaction_id_of(page_b),
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers['Location'].startswith('http://localhost:4000/callback')
        assert 'state=tab-b' in response.headers['Location']

    def test_authorize_code_exchange(self, client, auth_header):
        """Test exchanging authorization code for tokens."""
        # Get authorization code
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback&scope=openid'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange code for tokens
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'id_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'

    def test_authorize_code_one_time_use(self, client, auth_header):
        """Test that authorization codes can only be used once."""
        # Get authorization code
        client.get(
            '/authorize?response_type=code&client_id=demo-client'
            '&redirect_uri=http://localhost:3000/callback'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # First exchange - should succeed
        response1 = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)
        assert response1.status_code == 200

        # Second exchange - should fail
        response2 = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)
        assert response2.status_code == 400


class TestAuthorizationCodeFlowWithPKCE:
    """Tests for Authorization Code Flow with PKCE."""

    def test_pkce_s256_flow(self, client, auth_header, pkce_verifier, pkce_challenge_s256):
        """Test complete flow with PKCE S256."""
        # Get authorization code with code_challenge
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange with code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data

    def test_pkce_plain_flow(self, client, auth_header, pkce_verifier):
        """Test complete flow with PKCE plain method."""
        # Get authorization code with plain challenge
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_verifier}&code_challenge_method=plain'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange with code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        }, headers=auth_header)

        assert response.status_code == 200

    def test_pkce_body_client_id_mismatch_with_auth_header(self, client, auth_header, pkce_verifier):
        """Test that client_id in body mismatching the auth header client is rejected."""
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_verifier}&code_challenge_method=plain'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Auth header is demo-client, but body client_id is a different client
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': 'other-client',
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        }, headers=auth_header)

        assert response.status_code == 401

    def test_pkce_no_client_id_fails(self, client, pkce_verifier):
        """Test that token exchange with no client_id anywhere is rejected."""
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback&scope=openid'
            f'&code_challenge={pkce_verifier}&code_challenge_method=plain'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # No auth header, no client_id in body
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': pkce_verifier
        })

        # 400 since #310: no Authorization header attempted (RFC 9110).
        assert response.status_code == 400

    def test_pkce_missing_verifier_fails(self, client, auth_header, pkce_challenge_s256):
        """Test that missing code_verifier fails when challenge was provided."""
        # Get authorization code with code_challenge
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange WITHOUT code_verifier - should fail
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_pkce_wrong_verifier_fails(self, client, auth_header, pkce_challenge_s256):
        """Test that wrong code_verifier fails."""
        # Get authorization code
        client.get(
            f'/authorize?response_type=code&client_id=demo-client'
            f'&redirect_uri=http://localhost:3000/callback'
            f'&code_challenge={pkce_challenge_s256}&code_challenge_method=S256'
        )
        response = client.post('/authorize', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=False)

        location = response.headers.get('Location')
        code = location.split('code=')[1].split('&')[0]

        # Exchange with WRONG code_verifier
        response = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:3000/callback',
            'code_verifier': 'wrong_verifier'
        }, headers=auth_header)

        assert response.status_code == 400


class TestPasswordGrant:
    """Tests for OAuth2 Password Grant."""

    def test_password_grant_success(self, client, auth_header):
        """Test successful password grant."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'

    def test_password_grant_invalid_credentials(self, client, auth_header):
        """Test password grant with invalid credentials."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'wrong-password'
        }, headers=auth_header)

        # invalid_grant JSON since #308 (was a 401 HTML abort): §5.2 keeps
        # 401 for client authentication, not resource-owner credentials.
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_password_grant_missing_username(self, client, auth_header):
        """Test password grant without username."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'password': 'admin'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_password_grant_missing_password(self, client, auth_header):
        """Test password grant without password."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_password_grant_no_client_auth_fails(self, client):
        """Test that password grant requires client authentication."""
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        })

        # 400 since #310: no Authorization header attempted (RFC 9110).
        assert response.status_code == 400


class TestClientCredentialsGrant:
    """Tests for OAuth2 Client Credentials Grant."""

    def test_client_credentials_success(self, client, auth_header):
        """Test successful client credentials grant."""
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'

    def test_client_credentials_invalid_client(self, client):
        """Test client credentials with invalid client."""
        invalid_auth = base64.b64encode(b'wrong:credentials').decode()
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        }, headers={'Authorization': f'Basic {invalid_auth}'})

        assert response.status_code == 401

    def test_client_credentials_no_auth_fails(self, client):
        """Test that client credentials requires client authentication."""
        response = client.post('/token', data={
            'grant_type': 'client_credentials'
        })

        # 400 since #310: no Authorization header attempted (RFC 9110).
        assert response.status_code == 400


class TestRefreshTokenGrant:
    """Tests for OAuth2 Refresh Token Grant."""

    def test_refresh_token_success(self, client, auth_header):
        """Test successful refresh token grant."""
        # First get tokens via password grant
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)
        refresh_token = tokens['refresh_token']

        # Use refresh token to get new tokens
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }, headers=auth_header)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'refresh_token' in data

    def test_refresh_token_missing_token(self, client, auth_header):
        """Test refresh token grant without refresh_token."""
        response = client.post('/token', data={
            'grant_type': 'refresh_token'
        }, headers=auth_header)

        assert response.status_code == 400

    def test_refresh_token_invalid_token(self, client, auth_header):
        """An unverifiable refresh token is invalid_grant, RFC 6749 §5.2
        JSON - it used to be a Werkzeug 401 HTML abort (#306/#287)."""
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'invalid-token'
        }, headers=auth_header)

        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_grant"

    def test_refresh_token_with_access_token_fails(self, client, auth_header):
        """Test that using access_token as refresh_token fails."""
        # Get tokens
        response = client.post('/token', data={
            'grant_type': 'password',
            'username': 'admin',
            'password': 'admin'
        }, headers=auth_header)
        tokens = json.loads(response.data)
        access_token = tokens['access_token']

        # Try to use access_token as refresh_token
        response = client.post('/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': access_token
        }, headers=auth_header)

        assert response.status_code == 400


class TestUnsupportedGrantType:
    """Tests for unsupported grant types."""

    def test_unsupported_grant_type(self, client, auth_header):
        """Test that unsupported grant types return error."""
        response = client.post('/token', data={
            'grant_type': 'implicit'  # Not supported
        }, headers=auth_header)

        assert response.status_code == 400
