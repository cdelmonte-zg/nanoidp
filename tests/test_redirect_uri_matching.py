"""
Tests for registered redirect URIs with exact matching on /authorize (issue #67).

RFC 6749 §3.1.2.3 / OAuth 2.1 §4.1.1: when a client has registered redirect
URIs, the authorization endpoint compares the requested ``redirect_uri`` using
simple string comparison - no prefix, host or path normalization. A mismatch
MUST NOT redirect (§3.1.2.4); the error is returned directly. Clients without
registered URIs keep the permissive dev behavior (hardening is opt-in).
"""

import json

import pytest

from nanoidp.config import ConfigManager, OAuthClient, get_config
from nanoidp.services.yaml_writer import YamlWriter

REGISTERED = "http://localhost:3000/callback"


@pytest.fixture
def registered_client(app):
    """Register a client with pinned redirect URIs on the active config."""
    with app.app_context():
        config = get_config()
        config.settings.clients.append(
            OAuthClient(
                client_id="pinned-client",
                client_secret="pinned-secret",
                redirect_uris=[REGISTERED, "https://app.example.com/cb"],
            )
        )
    return "pinned-client"


def _authorize(client, client_id, redirect_uri):
    return client.get(
        f"/authorize?response_type=code&client_id={client_id}"
        f"&redirect_uri={redirect_uri}&scope=openid"
    )


class TestExactMatching:
    """Enforcement on GET /authorize for clients with registered URIs."""

    def test_exact_match_is_accepted(self, client, registered_client):
        response = _authorize(client, registered_client, REGISTERED)
        assert response.status_code == 200
        assert b"username" in response.data  # login form rendered

    def test_every_registered_uri_is_accepted(self, client, registered_client):
        response = _authorize(client, registered_client, "https://app.example.com/cb")
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "mismatch",
        [
            "http://localhost:3000/callback/",  # trailing slash
            "http://localhost:3000/other",  # different path
            "http://localhost:3001/callback",  # different port
            "http://localhost:3000/callback?x=1",  # extra query
            "http://localhost:3000/callbackevil",  # registered prefix + suffix
            "https://localhost:3000/callback",  # different scheme
            "http://evil.example.com/callback",  # different host
        ],
    )
    def test_mismatch_is_rejected_without_redirect(
        self, client, registered_client, mismatch
    ):
        response = _authorize(client, registered_client, mismatch)
        assert response.status_code == 400
        # §3.1.2.4: never redirect to an unvalidated URI
        assert "Location" not in response.headers
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"
        assert "not registered" in data["error_description"]

    def test_client_without_registered_uris_stays_permissive(self, client):
        """demo-client has no redirect_uris: any valid URI keeps working."""
        response = _authorize(client, "demo-client", "http://anything.example/cb")
        assert response.status_code == 200

    def test_mismatch_enforced_on_login_post_too(self, client, registered_client):
        """The POST leg (login form submit) revalidates against the registry."""
        response = client.post(
            "/authorize",
            data={
                "response_type": "code",
                "client_id": registered_client,
                "redirect_uri": "http://localhost:3000/callbackevil",
                "scope": "openid",
                "username": "admin",
                "password": "admin",
            },
        )
        assert response.status_code == 400
        assert "Location" not in response.headers


class TestConfigLoadAndPersistence:
    """redirect_uris round-trip through YAML load and the writer."""

    def _seed(self, tmp_path, redirect_yaml):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            "oauth:\n"
            '  issuer: "http://localhost:8000"\n'
            '  audience: "my-app"\n'
            "  clients:\n"
            '    - client_id: "c1"\n'
            '      client_secret: "s1"\n' + redirect_yaml
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        return config_dir

    def test_load_list(self, tmp_path):
        config_dir = self._seed(
            tmp_path, '      redirect_uris:\n        - "http://a/cb"\n        - "http://b/cb"\n'
        )
        manager = ConfigManager(str(config_dir))
        assert manager.get_client("c1").redirect_uris == ["http://a/cb", "http://b/cb"]

    def test_load_scalar_is_wrapped(self, tmp_path):
        """A single string is a YAML footgun, coerced like additional_audiences (#35)."""
        config_dir = self._seed(tmp_path, '      redirect_uris: "http://a/cb"\n')
        manager = ConfigManager(str(config_dir))
        assert manager.get_client("c1").redirect_uris == ["http://a/cb"]

    def test_load_non_string_items_rejected(self, tmp_path):
        config_dir = self._seed(tmp_path, "      redirect_uris:\n        - 123\n")
        with pytest.raises(ValueError, match="redirect_uris must be a list of strings"):
            ConfigManager(str(config_dir))

    def test_save_client_persists_redirect_uris(self, tmp_path):
        config_dir = self._seed(tmp_path, "")
        writer = YamlWriter(str(config_dir))

        writer.save_client(
            OAuthClient(
                client_id="c1", client_secret="s1", redirect_uris=["http://a/cb"]
            ),
            is_new=False,
        )

        reloaded = ConfigManager(str(config_dir))
        assert reloaded.get_client("c1").redirect_uris == ["http://a/cb"]


class TestMCPClientTools:
    """create_client/update_client expose redirect_uris (MCP/HTTP parity)."""

    def _config(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            "oauth:\n"
            '  issuer: "http://localhost:8000"\n'
            "  clients:\n"
            '    - client_id: "test"\n'
            '      client_secret: "test"\n'
        )
        (config_dir / "users.yaml").write_text(
            'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
        )
        return ConfigManager(str(config_dir))

    async def test_create_client_with_redirect_uris(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool

        config = self._config(tmp_path)
        result = await _execute_tool(
            "create_client",
            {
                "client_id": "pinned",
                "client_secret": "s",
                "redirect_uris": ["http://a/cb"],
            },
            config,
        )

        assert result["success"] is True
        assert result["client"]["redirect_uris"] == ["http://a/cb"]
        assert config.get_client("pinned").redirect_uris == ["http://a/cb"]

    async def test_update_client_replaces_and_clears_redirect_uris(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool

        config = self._config(tmp_path)
        await _execute_tool(
            "update_client",
            {"client_id": "test", "redirect_uris": ["http://a/cb"]},
            config,
        )
        assert config.get_client("test").redirect_uris == ["http://a/cb"]

        # empty list removes the restriction
        result = await _execute_tool(
            "update_client", {"client_id": "test", "redirect_uris": []}, config
        )
        assert result["success"] is True
        assert config.get_client("test").redirect_uris == []

    async def test_invalid_redirect_uris_type_rejected(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool

        config = self._config(tmp_path)
        with pytest.raises(ValueError, match="redirect_uris must be a list of strings"):
            await _execute_tool(
                "create_client",
                {"client_id": "bad", "client_secret": "s", "redirect_uris": "http://a"},
                config,
            )
