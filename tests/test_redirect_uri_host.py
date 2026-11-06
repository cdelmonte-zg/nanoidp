"""An HTTP(S) redirect URI names its host (#486).

``https:/callback`` passes as a scheme and a path, but a browser resolves it
against the current URL: the code would go to the IdP's own host. The rule
lives in the gate the three callers share; a private-use scheme, which has
no authority by design (RFC 8252 7.1), stays accepted.
"""

import pytest

from nanoidp.services.client_metadata import DocumentInvalid, client_from_document
from nanoidp.services.redirect_uri import redirect_uri_rejection_reason
from tests.test_client_metadata_origin import URL, _document
from tests.test_dynamic_registration_api import _app, _register

HOSTLESS = ["https:/callback", "http:callback", "https:///callback", "http:///x", "http://:80/cb"]
ACCEPTED = [
    "https://app.example/cb",
    "http://127.0.0.1:3000/cb",
    "http://[::1]:3000/cb",
    "com.example.app:/oauth2redirect",
    "com.example.app://oauth2redirect",
]


class TestTheGate:
    @pytest.mark.parametrize("uri", HOSTLESS)
    def test_no_host_is_refused(self, uri):
        assert redirect_uri_rejection_reason(uri) == "Invalid redirect_uri"

    @pytest.mark.parametrize("uri", ACCEPTED)
    def test_a_host_or_a_private_scheme_passes(self, uri):
        assert redirect_uri_rejection_reason(uri) is None


class TestTheCallers:
    @pytest.mark.parametrize("uri", HOSTLESS)
    def test_authorize_refuses_locally(self, client, uri):
        refused = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "demo-client",
                "redirect_uri": uri,
                "scope": "openid",
            },
        )

        assert refused.status_code == 400
        assert "Location" not in refused.headers
        assert refused.get_json()["error"] == "invalid_request"

    def test_authorize_still_takes_a_private_scheme(self, client):
        page = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "ui-native",
                "redirect_uri": "com.example.app:/oauth2redirect",
                "scope": "openid",
            },
        )

        assert page.status_code == 200

    def test_dynamic_registration(self, tmp_path):
        client = _app(tmp_path).test_client()

        refused = _register(client, redirect_uris=["https:/callback"])
        accepted = _register(client, redirect_uris=["com.example.app:/oauth2redirect"])

        assert refused.status_code == 400
        assert refused.get_json()["error"] == "invalid_redirect_uri"
        assert accepted.status_code == 201

    def test_a_client_metadata_document(self):
        with pytest.raises(DocumentInvalid, match="redirect_uris"):
            client_from_document(URL, _document(redirect_uris=["https:/callback"]), [])

        accepted = client_from_document(
            URL, _document(redirect_uris=["com.example.app:/oauth2redirect"]), []
        )

        assert accepted.redirect_uris == ["com.example.app:/oauth2redirect"]
