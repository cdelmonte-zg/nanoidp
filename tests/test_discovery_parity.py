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
from flask import url_for

from nanoidp.config import get_config
from nanoidp.mcp_server import _execute_tool
from tests.conftest import authorize_error


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
        assert resp.status_code == 302
        assert authorize_error(resp)["error"] == "unsupported_response_type"


class TestAuthorizationServerMetadata:
    """RFC 8414 metadata is the same document under a second name (#190).

    nanoidp is one server advertising one set of endpoints, so a client that
    speaks only OAuth and looks for ``/.well-known/oauth-authorization-server``
    must not be told something different from a client that reads the OIDC
    document, and must not be told nothing at all. n8n asks for this name
    first when its dynamic client registration toggle is on.
    """

    def test_the_two_documents_are_identical(self, client):
        rfc8414 = client.get("/.well-known/oauth-authorization-server")
        assert rfc8414.status_code == 200, "the RFC 8414 name is not served"
        oidc = json.loads(client.get("/.well-known/openid-configuration").data)
        assert json.loads(rfc8414.data) == oidc

    @pytest.mark.asyncio
    async def test_the_mcp_document_matches_it_too(self, client):
        rfc8414 = json.loads(client.get("/.well-known/oauth-authorization-server").data)
        assert await _execute_tool("get_oidc_discovery", {}, get_config()) == rfc8414

    def test_one_handler_answers_both_names(self, app):
        """The documents are equal because there is one handler, not because
        two were kept in step. Everything the alias inherits - the issuer
        resolution (#126), the absence of a gate on this blueprint, CORS -
        follows from that, so the day someone splits it in two this fails
        rather than the equality drifting later.
        """
        rules = {
            rule.rule: rule.endpoint
            for rule in app.url_map.iter_rules()
            if rule.rule.startswith("/.well-known/")
        }
        assert rules["/.well-known/oauth-authorization-server"] == rules[
            "/.well-known/openid-configuration"
        ]

    def test_the_oidc_name_stays_the_one_url_for_builds(self, app):
        """Two rules on one endpoint: the alias must not become the name the
        application generates for itself. Decorators apply bottom-up, so the
        OIDC rule has to be the inner one."""
        with app.test_request_context():
            assert url_for("oauth.oidc_config") == "/.well-known/openid-configuration"
