"""
#175 piece 1: the config_version contract. Absent = 1, positive integers up
to the supported version load, anything else is refused at load time with a
message naming the file; writers preserve an existing key and never add one;
/api/config and the MCP get_settings tool expose the effective value.
"""

import re

import pytest
import yaml

from nanoidp import serialization
from nanoidp.config import ConfigManager
from nanoidp.serialization import CONFIG_VERSION, IMPLICIT_CONFIG_VERSION, check_config_version


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

    @pytest.mark.parametrize("file", ["settings.yaml", "users.yaml"])
    def test_placeholder_is_not_a_valid_version(self, tmp_path, monkeypatch, file):
        """config_version is checked before ${VAR} expansion: literal only."""
        monkeypatch.setenv("CONFIG_VERSION", "1")
        _write(tmp_path)
        path = tmp_path / file
        path.write_text("config_version: ${CONFIG_VERSION:1}\n" + path.read_text())
        with pytest.raises(ValueError, match=r"must be a positive integer, found '\$\{CONFIG_VERSION:1\}'"):
            ConfigManager(str(tmp_path))

    def test_both_files_validated_against_one_contract(self, tmp_path):
        """v1: each file checked independently against CONFIG_VERSION; the
        manager reports the single contract version."""
        config = ConfigManager(_write(tmp_path, {"config_version": 1}, None))
        assert config.config_version == 1
        config = ConfigManager(_write(tmp_path, None, {"config_version": 1}))
        assert config.config_version == 1

    def test_check_helper_returns_effective_value(self, tmp_path):
        path = tmp_path / "settings.yaml"
        assert IMPLICIT_CONFIG_VERSION == 1
        assert check_config_version({}, path) == 1
        assert check_config_version({"config_version": 1}, path) == 1

    def test_absent_stays_v1_after_a_future_bump(self, tmp_path, monkeypatch):
        """#175 review: "absent = 1" must not silently become "absent = newest"
        when CONFIG_VERSION moves. Simulate the first bump."""
        monkeypatch.setattr(serialization, "CONFIG_VERSION", 2)
        path = tmp_path / "settings.yaml"
        assert check_config_version({}, path) == 1
        assert check_config_version({"config_version": 1}, path) == 1
        assert check_config_version({"config_version": 2}, path) == 2
        with pytest.raises(ValueError, match="newer than this release"):
            check_config_version({"config_version": 3}, path)

    def test_files_must_agree_on_the_contract_version(self, tmp_path, monkeypatch):
        """One version for the whole directory: a mismatch between
        settings.yaml and users.yaml is refused. Needs a simulated v2, since
        with only v1 both supported values are necessarily equal."""
        monkeypatch.setattr(serialization, "CONFIG_VERSION", 2)
        with pytest.raises(ValueError, match="does not match settings.yaml's config_version 2"):
            ConfigManager(_write(tmp_path, {"config_version": 2}, None))
        with pytest.raises(ValueError, match="config_version 2 does not match settings.yaml's config_version 1"):
            ConfigManager(_write(tmp_path, None, {"config_version": 2}))
        # both explicit and equal, or both absent, load fine
        assert ConfigManager(_write(tmp_path, {"config_version": 2}, {"config_version": 2})).config_version == 2
        assert ConfigManager(_write(tmp_path, None, None)).config_version == 1


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


class TestUsersPlaceholders:
    """users.yaml expands ${VAR} like settings.yaml (#175 review)."""

    USERS = {
        "users": {
            "alice": {
                "password": "${ALICE_PASSWORD}",
                "email": "${ALICE_EMAIL:alice@example.org}",
                "roles": ["${ALICE_ROLE:reader}"],
                "attributes": {"dept": "${ALICE_DEPT:eng}"},
            },
            "bob": {"password": "bob-pw"},
        }
    }

    def _write_users(self, tmp_path):
        settings = {
            "server": {"port": 8000},
            "oauth": {"clients": [{"client_id": "demo-client", "client_secret": "demo-secret"}]},
        }
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
        (tmp_path / "users.yaml").write_text(yaml.safe_dump(self.USERS))
        return str(tmp_path)

    def test_placeholders_expand_on_load(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALICE_PASSWORD", "s3cret")
        monkeypatch.delenv("ALICE_EMAIL", raising=False)
        config = ConfigManager(self._write_users(tmp_path))
        alice = config.users["alice"]
        assert alice.password == "s3cret"
        assert alice.email == "alice@example.org"
        assert alice.roles == ["reader"]
        assert alice.attributes["dept"] == "eng"

    def test_unset_placeholder_without_default_fails_validation(self, tmp_path, monkeypatch):
        """${ALICE_PASSWORD} with the variable unset expands to "", which the
        User model refuses: a missing secret is a loud load failure, not a
        user with an empty password."""
        monkeypatch.delenv("ALICE_PASSWORD", raising=False)
        with pytest.raises(ValueError, match="password"):
            ConfigManager(self._write_users(tmp_path))

    def test_login_with_expanded_password(self, tmp_path, monkeypatch):
        from nanoidp.app import create_app

        monkeypatch.setenv("ALICE_PASSWORD", "s3cret")
        app = create_app(config_dir=self._write_users(tmp_path))
        app.config["TESTING"] = True
        import base64

        auth = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}
        with app.test_client() as client:
            ok = client.post("/token", data={
                "grant_type": "password", "username": "alice", "password": "s3cret",
            }, headers=auth)
            bad = client.post("/token", data={
                "grant_type": "password", "username": "alice", "password": "${ALICE_PASSWORD}",
            }, headers=auth)
        assert ok.status_code == 200, ok.get_json()
        assert bad.status_code in (400, 401)

    def test_saving_another_user_keeps_placeholder_text(self, tmp_path, monkeypatch):
        from nanoidp.config import init_config
        from nanoidp.models import User
        from nanoidp.services.yaml_writer import YamlWriter

        monkeypatch.setenv("ALICE_PASSWORD", "s3cret")
        init_config(self._write_users(tmp_path))
        YamlWriter(str(tmp_path)).save_user(User(username="carol", password="c"), is_new=True)
        raw = (tmp_path / "users.yaml").read_text()
        assert "${ALICE_PASSWORD}" in raw
        assert "${ALICE_EMAIL:alice@example.org}" in raw
        assert "s3cret" not in raw

    def test_full_save_materializes_placeholders_documented_behaviour(self, tmp_path, monkeypatch):
        """ConfigManager.save() (MCP save_config) rewrites the whole user map
        from the loaded values; documented in configuration.md, not changed
        here (the users writer has no per-field is_unchanged merge)."""
        monkeypatch.setenv("ALICE_PASSWORD", "s3cret")
        config = ConfigManager(self._write_users(tmp_path))
        config.save()
        raw = (tmp_path / "users.yaml").read_text()
        assert "${ALICE_PASSWORD}" not in raw
        assert "s3cret" in raw
