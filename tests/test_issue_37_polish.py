"""
Tests for the minor polish items from the #32 review (issue #37):

1. ``OAuthClient`` validates on direct attribute assignment.
2. Discovery advertises ``azp`` in ``claims_supported``.
3. ``_normalize_audiences`` rejects falsy non-list inputs instead of silently
   returning ``[]``.
"""

import json

import pytest
from pydantic import ValidationError

from nanoidp.config import OAuthClient
from nanoidp.mcp_server import _normalize_audiences


class TestValidateAssignment:
    def test_blank_secret_assignment_raises(self):
        client = OAuthClient(client_id="c1", client_secret="s1")
        with pytest.raises(ValidationError):
            client.client_secret = ""

    def test_blank_client_id_assignment_raises(self):
        client = OAuthClient(client_id="c1", client_secret="s1")
        with pytest.raises(ValidationError):
            client.client_id = ""

    def test_non_list_audiences_assignment_raises(self):
        client = OAuthClient(client_id="c1", client_secret="s1")
        with pytest.raises(ValidationError):
            client.additional_audiences = "api://x"

    def test_valid_assignment_succeeds(self):
        client = OAuthClient(client_id="c1", client_secret="s1")
        client.additional_audiences = ["api://x"]
        client.client_secret = "s2"
        assert client.additional_audiences == ["api://x"]
        assert client.client_secret == "s2"


class TestDiscoveryAdvertisesAzp:
    def test_azp_in_claims_supported(self, client):
        resp = client.get("/.well-known/openid-configuration")
        claims = json.loads(resp.data).get("claims_supported", [])
        assert "azp" in claims


class TestNormalizeAudiencesStrictness:
    def test_none_returns_empty(self):
        assert _normalize_audiences(None) == []

    def test_empty_list_returns_empty(self):
        assert _normalize_audiences([]) == []

    def test_list_of_strings_passthrough(self):
        assert _normalize_audiences(["a", "b"]) == ["a", "b"]

    @pytest.mark.parametrize("falsy", ["", 0, False])
    def test_falsy_non_list_rejected(self, falsy):
        with pytest.raises(ValueError):
            _normalize_audiences(falsy)

    def test_non_string_items_rejected(self):
        with pytest.raises(ValueError):
            _normalize_audiences([123])
