"""
#175 piece 1: the config_version contract. Absent = 1, positive integers up
to the supported version load, anything else is refused at load time with a
message naming the file; writers preserve an existing key and never add one;
/api/config and the MCP get_settings tool expose the effective value.
"""

import re

import pytest
import yaml

from nanoidp.config import ConfigManager
from nanoidp.serialization import CONFIG_VERSION, check_config_version


def _write(tmp_path, settings_extra=None, users_extra=None):
    settings = {"server": {"host": "127.0.0.1", "port": 8000}}
    settings.update(settings_extra or {})
    users = {"users": {"alice": {"password": "x"}}}
    users.update(users_extra or {})
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
    (tmp_path / "users.yaml").write_text(yaml.safe_dump(users))
    return str(tmp_path)


class TestLoader:
    def test_supported_version_is_one(self):
        assert CONFIG_VERSION == 1

    def test_absent_means_one(self, tmp_path):
        config = ConfigManager(_write(tmp_path))
        assert config.config_version == 1

    def test_explicit_one_loads(self, tmp_path):
        config = ConfigManager(_write(tmp_path, {"config_version": 1}, {"config_version": 1}))
        assert config.config_version == 1
        assert "alice" in config.users

    @pytest.mark.parametrize("bad", [0, -1, "one", 1.5, True, None])
    def test_non_positive_integer_rejected_in_settings(self, tmp_path, bad):
        with pytest.raises(ValueError, match=r"settings\.yaml: config_version must be a positive integer"):
            ConfigManager(_write(tmp_path, {"config_version": bad}))

    def test_newer_version_rejected_in_settings(self, tmp_path):
        with pytest.raises(ValueError) as exc:
            ConfigManager(_write(tmp_path, {"config_version": 2}))
        message = str(exc.value)
        assert "settings.yaml" in message
        assert "config_version 2" in message
        assert f"config_version {CONFIG_VERSION}" in message

    def test_newer_version_rejected_in_users(self, tmp_path):
        with pytest.raises(ValueError, match=r"users\.yaml: config_version 2 is newer"):
            ConfigManager(_write(tmp_path, None, {"config_version": 2}))

    def test_string_rejected_in_users(self, tmp_path):
        with pytest.raises(ValueError, match=r"users\.yaml: config_version must be a positive integer"):
            ConfigManager(_write(tmp_path, None, {"config_version": "1"}))

    def test_check_helper_returns_effective_value(self, tmp_path):
        path = tmp_path / "settings.yaml"
        assert check_config_version({}, path) == CONFIG_VERSION
        assert check_config_version({"config_version": 1}, path) == 1


class TestWriterPreservesKey:
    def test_save_keeps_existing_key_in_both_files(self, tmp_path):
        config = ConfigManager(_write(tmp_path, {"config_version": 1}, {"config_version": 1}))
        config.settings.audience = "changed"
        config.save()
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["config_version"] == 1
        assert yaml.safe_load((tmp_path / "users.yaml").read_text())["config_version"] == 1

    def test_save_does_not_add_key_to_files_without_it(self, tmp_path):
        config = ConfigManager(_write(tmp_path))
        config.settings.audience = "changed"
        config.save()
        assert "config_version" not in yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert "config_version" not in yaml.safe_load((tmp_path / "users.yaml").read_text())

    def test_yaml_writer_keeps_key(self, tmp_path):
        from nanoidp.config import init_config
        from nanoidp.services.yaml_writer import YamlWriter

        init_config(_write(tmp_path, {"config_version": 1}))
        YamlWriter(str(tmp_path)).update_login_settings(mode="persona")
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert on_disk["config_version"] == 1
        assert on_disk["login"]["mode"] == "persona"


class TestGeneratedFilesDeclareIt:
    def test_nanoidp_init_writes_version(self, tmp_path):
        from nanoidp.__main__ import init_config as cli_init

        cli_init(str(tmp_path / "cfg"))
        for name in ("settings.yaml", "users.yaml"):
            assert yaml.safe_load((tmp_path / "cfg" / name).read_text())["config_version"] == 1
        # and the generated files load under the contract
        assert ConfigManager(str(tmp_path / "cfg")).config_version == 1

    def test_wizard_templates_declare_version(self):
        import inspect

        from nanoidp import wizard

        src = inspect.getsource(wizard)
        assert len(re.findall(r"^config_version: 1$", src, flags=re.M)) == 2


class TestExposure:
    def test_api_config_reports_version(self, tmp_path):
        from nanoidp.app import create_app

        app = create_app(config_dir=_write(tmp_path))
        app.config["TESTING"] = True
        with app.test_client() as client:
            assert client.get("/api/config").get_json()["config_version"] == 1

    @pytest.mark.asyncio
    async def test_mcp_get_settings_reports_version(self, tmp_path):
        from nanoidp.mcp_server import _execute_tool

        config = ConfigManager(_write(tmp_path, {"config_version": 1}))
        result = await _execute_tool("get_settings", {}, config)
        assert result["config_version"] == 1
