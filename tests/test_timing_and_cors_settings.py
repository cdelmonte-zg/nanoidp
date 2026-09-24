"""
Four settings.yaml keys that used to load and do nothing now do what they
say, and two that never could are reported like any unknown key (#441).

Supported, each with a default equal to the behaviour that was hardcoded:
``oauth.refresh_token_expiry_minutes`` (7 days), ``device_flow.
code_expiry_seconds`` (600) and ``device_flow.polling_interval`` (5), and
``cors_allowed_origins`` (absent: the security profile decides). Reported:
``logging.format`` and ``session.permanent``.

Each test sets a non-default value and observes the effect on the surface a
client sees, not on the Settings object alone: a setting that loads into
Settings and changes nothing is exactly what #441 was about.
"""

import json
import logging
import time

import jwt
import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import ConfigManager

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _set(config_dir, **top_level):
    """Merge keys into the per-test copy of the repo's settings.yaml."""
    path = config_dir / "settings.yaml"
    document = yaml.safe_load(path.read_text())
    for key, value in top_level.items():
        if isinstance(value, dict) and isinstance(document.get(key), dict):
            document[key].update(value)
        else:
            document[key] = value
    path.write_text(yaml.safe_dump(document))


def _client(config_dir, **top_level):
    _set(config_dir, **top_level)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _write(tmp_path, settings):
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {}}))
    return str(tmp_path)


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


class TestRefreshTokenLifetime:
    def test_the_default_is_the_seven_days_it_always_was(self, client, auth_header):
        tokens = client.post("/token", headers=auth_header, data={
            "grant_type": "password", "username": "admin", "password": "admin",
            "scope": "openid offline_access",
        }).get_json()
        claims = _claims(tokens["refresh_token"])
        assert claims["exp"] - claims["iat"] == 7 * 24 * 60 * 60

    def test_a_configured_lifetime_is_the_refresh_tokens(self, isolated_repo_config, auth_header):
        client = _client(isolated_repo_config, oauth={"refresh_token_expiry_minutes": 90})
        tokens = client.post("/token", headers=auth_header, data={
            "grant_type": "password", "username": "admin", "password": "admin",
            "scope": "openid offline_access",
        }).get_json()
        claims = _claims(tokens["refresh_token"])
        assert claims["exp"] - claims["iat"] == 90 * 60
        # and the access token keeps its own lifetime
        access = _claims(tokens["access_token"])
        assert access["exp"] - access["iat"] != 90 * 60

    def test_a_rotated_refresh_token_gets_the_configured_lifetime_too(
        self, isolated_repo_config, auth_header
    ):
        client = _client(isolated_repo_config, oauth={
            "refresh_token_expiry_minutes": 90, "refresh_token_rotation": True,
        })
        first = client.post("/token", headers=auth_header, data={
            "grant_type": "password", "username": "admin", "password": "admin",
            "scope": "openid offline_access",
        }).get_json()
        rotated = client.post("/token", headers=auth_header, data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"],
        }).get_json()
        claims = _claims(rotated["refresh_token"])
        assert claims["exp"] - claims["iat"] == 90 * 60


class TestDeviceFlowTiming:
    def test_the_defaults_are_the_ones_that_were_hardcoded(self, client, auth_header):
        answer = client.post("/device_authorization", headers=auth_header).get_json()
        assert answer["expires_in"] == 600
        assert answer["interval"] == 5

    def test_the_stores_own_defaults_are_the_settings_defaults(self):
        from nanoidp.models import Settings
        from nanoidp.services.device_code import DEVICE_CODE_EXPIRES_IN, DEVICE_POLL_INTERVAL

        assert Settings().device_code_expiry_seconds == DEVICE_CODE_EXPIRES_IN
        assert Settings().device_polling_interval == DEVICE_POLL_INTERVAL

    def test_the_configured_values_are_announced(self, isolated_repo_config, auth_header):
        client = _client(isolated_repo_config, device_flow={
            "code_expiry_seconds": 120, "polling_interval": 2,
        })
        answer = client.post("/device_authorization", headers=auth_header).get_json()
        assert answer["expires_in"] == 120
        assert answer["interval"] == 2

    def test_a_full_store_says_come_back_after_the_configured_interval(
        self, isolated_repo_config, auth_header, monkeypatch
    ):
        from nanoidp.services import device_code

        monkeypatch.setattr(device_code, "MAX_PENDING_DEVICE_CODES", 1)
        client = _client(isolated_repo_config, device_flow={"polling_interval": 2})
        assert client.post("/device_authorization", headers=auth_header).status_code == 200
        full = client.post("/device_authorization", headers=auth_header)
        assert full.status_code == 503
        assert full.headers["Retry-After"] == "2"

    def test_a_code_expires_after_the_configured_seconds(self, isolated_repo_config, auth_header):
        client = _client(isolated_repo_config, device_flow={"code_expiry_seconds": 1})
        answer = client.post("/device_authorization", headers=auth_header).get_json()
        time.sleep(1.2)
        poll = client.post("/token", headers=auth_header, data={
            "grant_type": DEVICE_GRANT, "device_code": answer["device_code"],
        })
        assert poll.status_code == 400
        assert poll.get_json()["error"] == "expired_token"


class TestCorsAllowedOrigins:
    def _allowed(self, client, origin):
        response = client.get("/.well-known/openid-configuration", headers={"Origin": origin})
        return response.headers.get("Access-Control-Allow-Origin")

    def test_absent_leaves_the_dev_profile_open(self, client):
        assert self._allowed(client, "http://anywhere.test") in ("*", "http://anywhere.test")

    def test_a_list_restricts_the_dev_profile(self, isolated_repo_config):
        client = _client(isolated_repo_config, cors_allowed_origins=["http://app.test:3000"])
        assert self._allowed(client, "http://app.test:3000") == "http://app.test:3000"
        assert self._allowed(client, "http://other.test") is None

    def test_a_list_replaces_the_stricter_dev_default(self, isolated_repo_config):
        client = _client(
            isolated_repo_config,
            security_profile="stricter-dev",
            cors_allowed_origins=["http://app.test:3000"],
        )
        assert self._allowed(client, "http://app.test:3000") == "http://app.test:3000"
        # localhost is the profile's default, not added to an explicit list
        assert self._allowed(client, "http://localhost:5173") is None

    def test_a_star_under_stricter_dev_opens_cors_and_says_so(self, isolated_repo_config, caplog):
        with caplog.at_level(logging.WARNING, logger="nanoidp.app"):
            client = _client(
                isolated_repo_config, security_profile="stricter-dev", cors_allowed_origins=["*"]
            )
        assert self._allowed(client, "http://other.test") in ("*", "http://other.test")
        assert "every origin may call nanoidp" in caplog.text

    def test_no_warning_for_a_list_without_a_star(self, isolated_repo_config, caplog):
        with caplog.at_level(logging.WARNING, logger="nanoidp.app"):
            _client(
                isolated_repo_config,
                security_profile="stricter-dev",
                cors_allowed_origins=["http://app.test"],
            )
        assert "every origin may call nanoidp" not in caplog.text

    def test_absent_keeps_the_stricter_dev_default(self, isolated_repo_config):
        client = _client(isolated_repo_config, security_profile="stricter-dev")
        assert self._allowed(client, "http://localhost:5173") == "http://localhost:5173"
        assert self._allowed(client, "http://other.test") is None

    @pytest.mark.parametrize("origin, allowed", [
        ("http://localhost", True),
        ("http://localhost:5173", True),
        ("http://127.0.0.1:8080", True),
        # flask-cors matches a pattern with re.match, anchored at the start
        # only: "http://localhost:*" used to admit all of these
        ("http://localhost.evil.test", False),
        ("http://localhost:5173.evil.test", False),
        ("http://127.0.0.1.nip.io", False),
        ("http://127a0b0c1.test", False),
        # only the dots differ: an unescaped "." in the pattern admits it
        ("http://127a0a0a1:8080", False),
        ("https://localhost.evil.test", False),
    ])
    def test_the_stricter_dev_default_is_localhost_and_nothing_that_starts_like_it(
        self, isolated_repo_config, origin, allowed
    ):
        client = _client(isolated_repo_config, security_profile="stricter-dev")
        assert (self._allowed(client, origin) == origin) is allowed

    def test_an_empty_list_allows_no_origin(self, isolated_repo_config):
        client = _client(isolated_repo_config, cors_allowed_origins=[])
        assert self._allowed(client, "http://localhost:5173") is None


class TestOneDefaultPerSetting:
    """The defaults are written in the document model and in Settings; a
    file that says nothing must land on Settings' own defaults."""

    def test_the_document_defaults_are_the_domain_defaults(self):
        from nanoidp.config_documents import SettingsDocument
        from nanoidp.models import Settings

        loaded, domain = SettingsDocument().to_settings(), Settings()
        for field in (
            "refresh_token_expiry_minutes",
            "device_code_expiry_seconds",
            "device_polling_interval",
            "cors_allowed_origins",
        ):
            assert getattr(loaded, field) == getattr(domain, field), field


class TestInvalidValuesAreErrors:
    """The keys used to load with any value; now they are validated like
    every other key, so a value that means nothing refuses to load."""

    @pytest.mark.parametrize("settings, path", [
        ({"oauth": {"refresh_token_expiry_minutes": "soon"}}, "oauth.refresh_token_expiry_minutes"),
        ({"oauth": {"refresh_token_expiry_minutes": 0}}, "refresh_token_expiry_minutes"),
        ({"oauth": {"refresh_token_expiry_minutes": 43201}}, "refresh_token_expiry_minutes"),
        ({"device_flow": {"code_expiry_seconds": 0}}, "code_expiry_seconds"),
        ({"device_flow": {"code_expiry_seconds": 3601}}, "code_expiry_seconds"),
        ({"device_flow": {"polling_interval": 0}}, "polling_interval"),
        ({"device_flow": {"polling_interval": 61}}, "polling_interval"),
        ({"device_flow": "whatever"}, "device_flow"),
        # A bare `device_flow:` line: null is not an empty section, the rule
        # every section but login follows (#197 review)
        ({"device_flow": None}, "device_flow"),
        ({"cors_allowed_origins": "*"}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://ok.test", ""]}, "cors_allowed_origins"),
        # a pattern would be matched at the start only (#441 review)
        ({"cors_allowed_origins": ["http://localhost:*"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://*.example.test"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["^http://a.test$"]}, "cors_allowed_origins"),
    ])
    def test_refused(self, tmp_path, settings, path):
        with pytest.raises(ValueError, match=path.replace(".", r"\.")):
            ConfigManager(_write(tmp_path, settings))

    def test_the_bounds_themselves_load(self, tmp_path):
        settings = ConfigManager(_write(tmp_path, {
            "oauth": {"refresh_token_expiry_minutes": 43200},
            "device_flow": {"code_expiry_seconds": 3600, "polling_interval": 60},
            "cors_allowed_origins": ["*"],
        })).settings
        assert settings.refresh_token_expiry_minutes == 43200
        assert settings.device_code_expiry_seconds == 3600
        assert settings.device_polling_interval == 60
        assert settings.cors_allowed_origins == ["*"]


class TestTheTwoKeysNothingReads:
    @pytest.mark.parametrize("settings, path", [
        ({"logging": {"format": "%(message)s"}}, "logging.format"),
        ({"session": {"permanent": True}}, "session.permanent"),
    ])
    def test_warned_about_by_default(self, tmp_path, caplog, settings, path):
        with caplog.at_level(logging.WARNING):
            ConfigManager(_write(tmp_path, settings))
        assert f"unknown key {path} (ignored)" in caplog.text

    @pytest.mark.parametrize("settings, path", [
        ({"logging": {"format": "%(message)s"}}, "logging.format"),
        ({"session": {"permanent": True}}, "session.permanent"),
    ])
    def test_refused_under_strict(self, tmp_path, settings, path):
        with pytest.raises(ValueError, match=f"unknown key {path.replace('.', '[.]')}"):
            ConfigManager(_write(tmp_path, {**settings, "config_validation": "strict"}))

    def test_the_shipped_default_config_carries_neither(self, tmp_path, caplog):
        from pathlib import Path

        shipped = Path(__file__).resolve().parent.parent / "config"
        with caplog.at_level(logging.WARNING):
            ConfigManager(str(shipped), strict_config=True)
        assert "unknown key" not in caplog.text


class TestReportedWhereTheNeighboursAre:
    def test_api_config(self, isolated_repo_config, auth_header):
        client = _client(
            isolated_repo_config,
            oauth={"refresh_token_expiry_minutes": 90},
            device_flow={"code_expiry_seconds": 120, "polling_interval": 2},
            cors_allowed_origins=["http://app.test"],
        )
        config = client.get("/api/config").get_json()
        assert config["oauth"]["refresh_token_expiry_minutes"] == 90
        assert config["device_flow"] == {"code_expiry_seconds": 120, "polling_interval": 2}
        assert config["cors_allowed_origins"] == ["http://app.test"]
        assert config["cors_applied_origins"] == ["http://app.test"]

    def test_api_config_reports_the_origins_in_force_not_only_the_file(self, isolated_repo_config):
        """CORS is set up at startup; a reload changes the declared list but
        not what the server applies, so the report names both (#441 review)."""
        client = _client(isolated_repo_config)
        _set(isolated_repo_config, cors_allowed_origins=["http://app.test"])
        assert client.post("/api/config/reload").status_code == 200
        config = client.get("/api/config").get_json()
        assert config["cors_allowed_origins"] == ["http://app.test"]
        assert config["cors_applied_origins"] == ["*"]
        # and that is what a browser meets
        response = client.get(
            "/.well-known/openid-configuration", headers={"Origin": "http://other.test"}
        )
        assert response.headers.get("Access-Control-Allow-Origin") in ("*", "http://other.test")

    def test_api_config_says_when_cors_is_left_to_the_profile(self, client):
        config = client.get("/api/config").get_json()
        assert config["cors_allowed_origins"] is None
        assert config["cors_applied_origins"] == ["*"]

    @pytest.mark.asyncio
    async def test_mcp_get_settings(self, isolated_repo_config, mcp_call_tool, monkeypatch):
        _set(
            isolated_repo_config,
            oauth={"refresh_token_expiry_minutes": 90},
            device_flow={"code_expiry_seconds": 120, "polling_interval": 2},
            cors_allowed_origins=["http://app.test"],
        )
        monkeypatch.setattr("nanoidp.config._config", ConfigManager(str(isolated_repo_config)))
        result = await mcp_call_tool("get_settings", {})
        assert result.is_error is not True, result.content[0].text
        settings = json.loads(result.content[0].text)
        assert settings["refresh_token_expiry_minutes"] == 90
        assert settings["device_code_expiry_seconds"] == 120
        assert settings["device_polling_interval"] == 2
        assert settings["cors_allowed_origins"] == ["http://app.test"]


class TestWrittenOnlyWhileNotAtTheDefault:
    """Files that never set these keys must not gain them on the next save:
    they are written while they differ from the default and removed when
    they return to it, like the login keys (#319)."""

    def _document(self, config_dir):
        return yaml.safe_load((config_dir / "settings.yaml").read_text())

    def test_a_config_save_at_the_defaults_adds_nothing(self, isolated_repo_config):
        config = ConfigManager(str(isolated_repo_config))
        config.settings.verbose_logging = not config.settings.verbose_logging
        config.save()
        document = self._document(isolated_repo_config)
        assert "refresh_token_expiry_minutes" not in document["oauth"]
        assert "device_flow" not in document

    def test_a_config_save_writes_a_changed_value_and_removes_it_at_the_default(
        self, isolated_repo_config
    ):
        config = ConfigManager(str(isolated_repo_config))
        config.settings.refresh_token_expiry_minutes = 90
        config.settings.device_code_expiry_seconds = 30
        config.save()
        document = self._document(isolated_repo_config)
        assert document["oauth"]["refresh_token_expiry_minutes"] == 90
        assert document["device_flow"] == {"code_expiry_seconds": 30}

        config = ConfigManager(str(isolated_repo_config))
        config.settings.refresh_token_expiry_minutes = 10080
        config.settings.device_code_expiry_seconds = 600
        config.save()
        document = self._document(isolated_repo_config)
        assert "refresh_token_expiry_minutes" not in document["oauth"]
        assert "device_flow" not in document

    def test_the_settings_form_writer(self, isolated_repo_config):
        from nanoidp.services.yaml_writer import YamlWriter

        writer = YamlWriter(str(isolated_repo_config))
        writer.update_oauth_settings(refresh_token_expiry_minutes=10080)
        assert "refresh_token_expiry_minutes" not in self._document(isolated_repo_config)["oauth"]
        writer.update_oauth_settings(refresh_token_expiry_minutes=90)
        assert self._document(isolated_repo_config)["oauth"]["refresh_token_expiry_minutes"] == 90
        writer.update_oauth_settings(refresh_token_expiry_minutes=10080)
        assert "refresh_token_expiry_minutes" not in self._document(isolated_repo_config)["oauth"]

    def test_the_settings_page_round_trip(self, isolated_repo_config, client):
        page = client.get("/settings")
        assert b'name="refresh_token_expiry_minutes"' in page.data
        assert b'value="10080"' in page.data

    @pytest.mark.asyncio
    async def test_mcp_update_then_save_reaches_the_file(
        self, isolated_repo_config, mcp_call_tool, monkeypatch
    ):
        import nanoidp.mcp_server as mcp

        config = ConfigManager(str(isolated_repo_config))
        monkeypatch.setattr("nanoidp.config._config", config)
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
        monkeypatch.delenv("NANOIDP_MANAGEMENT_SECRET", raising=False)

        updated = await mcp_call_tool("update_settings", {
            "refresh_token_expiry_minutes": 90,
            "device_code_expiry_seconds": 30,
            "device_polling_interval": 2,
        })
        assert updated.is_error is not True, updated.content[0].text
        saved = await mcp_call_tool("save_config", {})
        assert saved.is_error is not True, saved.content[0].text

        reloaded = ConfigManager(str(isolated_repo_config)).settings
        assert reloaded.refresh_token_expiry_minutes == 90
        assert reloaded.device_code_expiry_seconds == 30
        assert reloaded.device_polling_interval == 2

    @pytest.mark.asyncio
    async def test_mcp_refuses_a_value_out_of_bounds(
        self, isolated_repo_config, mcp_call_tool, monkeypatch
    ):
        import nanoidp.mcp_server as mcp

        config = ConfigManager(str(isolated_repo_config))
        monkeypatch.setattr("nanoidp.config._config", config)
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("update_settings", {"device_code_expiry_seconds": 0})
        payload = json.loads(result.content[0].text)
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert config.settings.device_code_expiry_seconds == 600
