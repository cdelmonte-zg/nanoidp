"""
Tests for the shared OIDC discovery document (issues #40 and #41).

The HTTP ``/.well-known/openid-configuration`` endpoint and the MCP
``get_oidc_discovery`` tool both build their response via
``services.discovery.build_discovery_document``, so the two documents must be
identical - the MCP tool used to return an abbreviated dict that omitted
``claims_supported``/``azp`` and the auth-method metadata (#40).

The document must also only advertise what the endpoints implement: the
implicit flow was never supported, so ``response_types_supported`` must not
list ``token`` (#41).
"""

import json

import pytest

from nanoidp.config import get_config
from nanoidp.mcp_server import _execute_tool


class TestDiscoveryParity:
    """MCP and HTTP discovery come from one helper and can't drift (#40)."""

    @pytest.mark.asyncio
    async def test_mcp_discovery_matches_http_document(self, client):
        http_doc = json.loads(client.get("/.well-known/openid-configuration").data)
        mcp_doc = await _execute_tool("get_oidc_discovery", {}, get_config())
        assert mcp_doc == http_doc

    @pytest.mark.asyncio
    async def test_mcp_discovery_advertises_azp(self):
        doc = await _execute_tool("get_oidc_discovery", {}, get_config())
        assert "azp" in doc["claims_supported"]

    @pytest.mark.asyncio
    async def test_mcp_discovery_advertises_pkce_and_auth_methods(self):
        doc = await _execute_tool("get_oidc_discovery", {}, get_config())
        assert doc["code_challenge_methods_supported"] == ["plain", "S256"]
        assert "client_secret_basic" in doc["token_endpoint_auth_methods_supported"]
        assert "RS256" in doc["id_token_signing_alg_values_supported"]


class TestResponseTypesHonest:
    """Discovery only advertises response types /authorize accepts (#41)."""

    def test_response_types_supported_is_code_only(self, client):
        doc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert doc["response_types_supported"] == ["code"]

    def test_authorize_rejects_token_response_type(self, client):
        resp = client.get(
            "/authorize",
            query_string={
                "response_type": "token",
                "client_id": "demo-client",
                "redirect_uri": "http://localhost:9000/callback",
            },
        )
        data = json.loads(resp.data)
        assert resp.status_code == 400
        assert data["error"] == "unsupported_response_type"
