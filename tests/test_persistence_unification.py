"""
Tests for the single YAML persistence path (issue #83) and the lossy-save fix
(issue #87).

Both ``ConfigManager.save()`` and the web UI's ``YamlWriter`` must produce
identical entries (they used to drift: #32, #78, #82), and saving must never
delete keys the codebase doesn't manage.
"""

from typing import Any, Dict

import yaml

from nanoidp.config import ConfigManager, OAuthClient, User
from nanoidp.serialization import client_to_yaml, user_to_yaml
from nanoidp.services.yaml_writer import YamlWriter


def _seed(tmp_path, settings_yaml: str) -> Any:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.yaml").write_text(settings_yaml)
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


BASE_SETTINGS = (
    "oauth:\n"
    '  issuer: "http://localhost:8000"\n'
    '  audience: "my-app"\n'
    "  clients:\n"
    '    - client_id: "c1"\n'
    '      client_secret: "s1"\n'
)


def _read(path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text())


class TestSingleClientEntry:
    """One builder, byte-identical entries from both persistence paths."""

    CLIENT = OAuthClient(
        client_id="c1",
        client_secret="s1",
        description="d",
        additional_audiences=["https://api.example.com"],
        redirect_uris=["http://localhost:3000/cb"],
    )

    def test_both_paths_write_the_same_client_entry(self, tmp_path):
        # Path 1: ConfigManager.save()
        dir1 = _seed(tmp_path / "a", BASE_SETTINGS)
        manager = ConfigManager(str(dir1))
        manager.settings.clients = [self.CLIENT]
        manager.save()
        entry1 = _read(dir1 / "settings.yaml")["oauth"]["clients"][0]

        # Path 2: YamlWriter.save_client()
        dir2 = _seed(tmp_path / "b", BASE_SETTINGS)
        ConfigManager(str(dir2))  # writer resolves the active config dir lazily
        writer = YamlWriter(str(dir2))
        writer.save_client(self.CLIENT, is_new=False)
        entry2 = _read(dir2 / "settings.yaml")["oauth"]["clients"][0]

        assert entry1 == entry2 == client_to_yaml(self.CLIENT)

    def test_optional_fields_omitted_when_empty(self):
        entry = client_to_yaml(OAuthClient(client_id="c", client_secret="s"))
        assert "additional_audiences" not in entry
        assert "redirect_uris" not in entry


class TestSaveIsNotLossy:
    """#87: ConfigManager.save() must preserve keys it doesn't manage."""

    def test_foreign_sections_survive_save(self, tmp_path):
        config_dir = _seed(
            tmp_path,
            BASE_SETTINGS
            + "server:\n  host: 0.0.0.0\n  port: 8000\n  debug: true\n"
            + "jwt:\n  keys_dir: /custom/keys\n  max_previous_keys: 5\n"
            + "session:\n  secret_key: super-secret\n"
            + "logging:\n  level: DEBUG\n  log_token_requests: false\n"
            + "my_custom_extension:\n  enabled: true\n",
        )
        manager = ConfigManager(str(config_dir))
        manager.save()

        doc = _read(config_dir / "settings.yaml")
        assert doc["jwt"] == {"keys_dir": "/custom/keys", "max_previous_keys": 5}
        assert doc["session"] == {"secret_key": "super-secret"}
        assert doc["logging"]["level"] == "DEBUG"
        assert doc["logging"]["log_token_requests"] is False
        assert doc["server"]["debug"] is True
        assert doc["my_custom_extension"] == {"enabled": True}
        # ...while owned keys are written
        assert doc["oauth"]["issuer"] == "http://localhost:8000"

    def test_cleared_optional_keys_are_removed(self, tmp_path):
        config_dir = _seed(
            tmp_path,
            BASE_SETTINGS
            + "security_profile: oauth21\n"
            + "allowed_identity_classes: [INTERNAL]\n",
        )
        manager = ConfigManager(str(config_dir))
        manager.settings.security_profile = "dev"
        manager.settings.allowed_identity_classes = []
        manager.save()

        doc = _read(config_dir / "settings.yaml")
        assert "security_profile" not in doc
        assert "allowed_identity_classes" not in doc

    def test_save_creates_backup(self, tmp_path):
        config_dir = _seed(tmp_path, BASE_SETTINGS)
        ConfigManager(str(config_dir)).save()
        assert (config_dir / "settings.yaml.bak").exists()


class TestSingleUserEntry:
    """Users serialize sparsely and identically from both paths."""

    USER = User(
        username="alice",
        password="pw",
        email="alice@example.org",
        roles=["USER"],
    )

    def test_both_paths_write_the_same_user_entry(self, tmp_path):
        dir1 = _seed(tmp_path / "a", BASE_SETTINGS)
        manager = ConfigManager(str(dir1))
        manager.users["alice"] = self.USER
        manager.save()
        entry1 = _read(dir1 / "users.yaml")["users"]["alice"]

        dir2 = _seed(tmp_path / "b", BASE_SETTINGS)
        ConfigManager(str(dir2))
        writer = YamlWriter(str(dir2))
        writer.save_user(self.USER, is_new=True)
        entry2 = _read(dir2 / "users.yaml")["users"]["alice"]

        assert entry1 == entry2 == user_to_yaml(self.USER)

    def test_defaults_are_omitted_and_round_trip(self, tmp_path):
        """Sparse form: default tenant / empty lists are dropped on disk and
        restored by the loader's defaults - semantics unchanged."""
        entry = user_to_yaml(self.USER)
        assert "tenant" not in entry  # default
        assert "entitlements" not in entry  # empty

        config_dir = _seed(tmp_path, BASE_SETTINGS)
        manager = ConfigManager(str(config_dir))
        manager.users["alice"] = self.USER
        manager.save()

        reloaded = ConfigManager(str(config_dir)).users["alice"]
        assert reloaded.tenant == "default"
        assert reloaded.roles == ["USER"]
        assert reloaded.entitlements == []

    def test_unknown_top_level_users_key_preserved(self, tmp_path):
        config_dir = _seed(tmp_path, BASE_SETTINGS)
        users_file = config_dir / "users.yaml"
        users_file.write_text(users_file.read_text() + "my_note: keep me\n")

        manager = ConfigManager(str(config_dir))
        manager.save()
        assert _read(users_file)["my_note"] == "keep me"
