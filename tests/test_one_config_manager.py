"""One ConfigManager per process (#230).

The HTTP routes, the token service and the MCP tools resolve the same
``nanoidp.config`` instance; nothing keeps a manager, or a signing service
derived from one, from the moment it was first built.
"""

import asyncio
import base64
import itertools
import json
import shutil
from pathlib import Path

import jwt
import pytest

import nanoidp.mcp_server as mcp_server
from nanoidp.app import create_app
from nanoidp.config import get_config, get_config_if_loaded, init_config
from nanoidp.services.token import get_token_service

_REPO_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_AUTH = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def _config_dir(tmp_path: Path, keys_dir: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG_DIR / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    text = settings.read_text()
    assert "keys_dir: ./keys" in text
    settings.write_text(text.replace("keys_dir: ./keys", f'keys_dir: "{keys_dir}"'))
    return config_dir


def _password_grant(client) -> str:
    response = client.post(
        "/token",
        data={"grant_type": "password", "username": "admin", "password": "admin"},
        headers=_AUTH,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()["access_token"]


class TestTokenService:
    def test_token_service_follows_the_current_manager(self, tmp_path):
        first = init_config(str(_config_dir(tmp_path / "a", tmp_path / "keys-a")))
        assert get_token_service().config is first

        second = init_config(str(_config_dir(tmp_path / "b", tmp_path / "keys-b")))
        assert get_token_service().config is second

    def test_tokens_are_signed_with_the_key_the_jwks_serves_after_keys_dir_changes(
        self, tmp_path
    ):
        config_dir = _config_dir(tmp_path, tmp_path / "keys-1")
        app = create_app(str(config_dir))
        app.config["TESTING"] = True
        client = app.test_client()
        _password_grant(client)

        settings = config_dir / "settings.yaml"
        settings.write_text(
            settings.read_text().replace(str(tmp_path / "keys-1"), str(tmp_path / "keys-2"))
        )
        assert client.post("/api/config/reload").status_code == 200

        token = _password_grant(client)
        served = [key["kid"] for key in client.get("/.well-known/jwks.json").get_json()["keys"]]
        assert jwt.get_unverified_header(token)["kid"] in served
        introspection = client.post("/introspect", data={"token": token}, headers=_AUTH)
        assert introspection.get_json()["active"] is True

    def test_one_token_response_is_signed_with_one_key(self, tmp_path, monkeypatch):
        import nanoidp.services.token as token_module
        from nanoidp.services.crypto import CryptoService

        config = init_config(str(_config_dir(tmp_path, tmp_path / "keys-1")))
        services = itertools.cycle(
            [CryptoService(str(tmp_path / "keys-1")), CryptoService(str(tmp_path / "keys-2"))]
        )
        # A reload moving keys_dir in the middle of create_token: every lookup
        # after the first would see the other key.
        monkeypatch.setattr(token_module, "get_crypto_service", lambda: next(services))

        response = get_token_service().create_token(
            config.get_user("admin"), scope="openid", client_id="demo-client", issue_refresh_token=True
        )

        kids = {
            jwt.get_unverified_header(response[name])["kid"]
            for name in ("access_token", "id_token", "refresh_token")
        }
        assert len(kids) == 1


class TestMCPServer:
    def test_the_mcp_package_keeps_no_configuration_of_its_own(self):
        assert not hasattr(mcp_server, "_config")

    def test_mcp_uses_the_manager_already_loaded_in_the_process(self, tmp_path):
        manager = init_config(str(_config_dir(tmp_path, tmp_path / "keys")))
        assert mcp_server._ensure_config() is manager

    def test_mcp_loads_from_the_environment_and_publishes_the_process_manager(
        self, tmp_path, monkeypatch
    ):
        config_dir = _config_dir(tmp_path, tmp_path / "keys")
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
        assert get_config_if_loaded() is None

        manager = mcp_server._ensure_config()

        assert Path(manager.config_dir) == config_dir
        assert get_config() is manager

    def test_a_user_created_through_mcp_is_seen_by_the_routes_of_the_same_process(
        self, tmp_path, mcp_call_tool
    ):
        app = create_app(str(_config_dir(tmp_path, tmp_path / "keys")))
        app.config["TESTING"] = True
        client = app.test_client()

        result = asyncio.run(
            mcp_call_tool("create_user", {"username": "ci-alice", "password": "pw-alice"})
        )
        assert json.loads(result.content[0].text)["success"] is True

        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "ci-alice", "password": "pw-alice"},
            headers=_AUTH,
        )
        assert response.status_code == 200, response.get_data(as_text=True)

    @pytest.mark.parametrize("bind_client", [False, True])
    def test_mcp_generate_token_signs_with_the_key_the_routes_serve(
        self, tmp_path, mcp_call_tool, bind_client
    ):
        app = create_app(str(_config_dir(tmp_path, tmp_path / "keys")))
        app.config["TESTING"] = True
        client = app.test_client()

        arguments = {"username": "admin"}
        if bind_client:
            arguments["client_id"] = "demo-client"
        result = asyncio.run(mcp_call_tool("generate_token", arguments))
        token = json.loads(result.content[0].text)["access_token"]

        introspection = client.post("/introspect", data={"token": token}, headers=_AUTH)
        assert introspection.get_json()["active"] is True
