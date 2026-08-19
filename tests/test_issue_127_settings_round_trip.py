"""
Tests for issue #127: saving settings used to silently discard comments,
inline ``#`` text and ``${VAR:default}`` placeholders in ``settings.yaml``.

Covers the fix's contract:
  - A block comment survives a settings save.
  - An untouched ``${VAR:default}`` placeholder survives a save that changed
    an unrelated field, via both ``ConfigManager.save()`` (MCP `save_config`)
    and ``YamlWriter`` (web UI full-form resubmit).
  - A quoted value containing ``#`` stays intact across a save.
"""

from pathlib import Path
from typing import Any

import yaml

from nanoidp.config import ConfigManager
from nanoidp.services.yaml_writer import YamlWriter

SETTINGS_WITH_PLACEHOLDER_AND_COMMENT = """\
server:
  host: 0.0.0.0
  port: ${PORT:8000}
  debug: false
oauth:
  issuer: http://localhost:${PORT:8000}
  audience: my-app
  token_expiry_minutes: 60
  clients:
  - client_id: c1
    client_secret: s1
    description: 'registered client (exact matching, issue #67)'
saml:
  entity_id: http://localhost:8000/saml
  sso_url: http://localhost:8000/saml/sso
  default_acs_url: http://localhost:8080/sso
  sign_responses: true
  c14n_algorithm: exc_c14n
  strict_binding: false
  # Roles/groups are not standard SAML attributes; enable and name them here.
  export_roles: false
  export_groups: false
  roles_attr_name: roles
  groups_attr_name: groups
"""


def _seed(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.yaml").write_text(SETTINGS_WITH_PLACEHOLDER_AND_COMMENT)
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


def _seed_custom_settings(tmp_path: Path, settings_text: str) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.yaml").write_text(settings_text)
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


def _raw(config_dir: Path) -> str:
    return (config_dir / "settings.yaml").read_text()


def _parsed(config_dir: Path) -> dict[str, Any]:
    return yaml.safe_load(_raw(config_dir))


class TestCommentSurvivesSave:
    def test_saml_comment_survives_a_config_manager_save(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PORT", raising=False)
        config_dir = _seed(tmp_path)
        manager = ConfigManager(str(config_dir))

        manager.settings.audience = "changed-audience"
        manager.save()

        assert (
            "# Roles/groups are not standard SAML attributes; enable and name"
            " them here."
        ) in _raw(config_dir)


class TestPlaceholderSurvivesUnrelatedSave:
    def test_via_config_manager_save(self, tmp_path, monkeypatch):
        """MCP update_settings + save_config: only the touched field changes."""
        monkeypatch.delenv("PORT", raising=False)
        config_dir = _seed(tmp_path)
        manager = ConfigManager(str(config_dir))
        assert manager.settings.port == 8000  # expanded default

        manager.settings.audience = "changed-audience"
        manager.save()

        raw = _raw(config_dir)
        assert "port: ${PORT:8000}" in raw
        assert "issuer: http://localhost:${PORT:8000}" in raw
        parsed = _parsed(config_dir)
        assert parsed["oauth"]["audience"] == "changed-audience"

    def test_via_yaml_writer_full_form_resubmit(self, tmp_path, monkeypatch):
        """Web UI resubmits the whole form; unchanged fields carry the
        already-expanded value the template rendered - the writer must not
        clobber the raw placeholder for those."""
        monkeypatch.delenv("PORT", raising=False)
        config_dir = _seed(tmp_path)
        ConfigManager(str(config_dir))
        writer = YamlWriter(str(config_dir))

        # Simulate the form: issuer field shows the expanded value (unchanged
        # by the user), audience is a genuine edit.
        writer.update_oauth_settings(
            issuer="http://localhost:8000",  # expanded, same as on-disk placeholder
            audience="changed-audience",
        )

        raw = _raw(config_dir)
        assert "issuer: http://localhost:${PORT:8000}" in raw
        parsed = _parsed(config_dir)
        assert parsed["oauth"]["audience"] == "changed-audience"

    def test_placeholder_is_overwritten_when_genuinely_changed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PORT", raising=False)
        config_dir = _seed(tmp_path)
        ConfigManager(str(config_dir))
        writer = YamlWriter(str(config_dir))

        writer.update_oauth_settings(issuer="http://example.com")

        parsed = _parsed(config_dir)
        assert parsed["oauth"]["issuer"] == "http://example.com"


class TestHashInQuotedValueStaysIntact:
    def test_quoted_description_with_hash_survives_unrelated_save(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("PORT", raising=False)
        config_dir = _seed(tmp_path)
        manager = ConfigManager(str(config_dir))

        manager.settings.audience = "changed-audience"
        manager.save()

        parsed = _parsed(config_dir)
        assert (
            parsed["oauth"]["clients"][0]["description"]
            == "registered client (exact matching, issue #67)"
        )

    def test_new_description_with_hash_is_quoted_on_write(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PORT", raising=False)
        config_dir = _seed(tmp_path)
        manager = ConfigManager(str(config_dir))

        manager.settings.clients[0].description = "new text with a # character"
        manager.save()

        raw = _raw(config_dir)
        assert "'new text with a # character'" in raw
        parsed = _parsed(config_dir)
        assert (
            parsed["oauth"]["clients"][0]["description"]
            == "new text with a # character"
        )


class TestEnvBackedSecretsAndEmptyPlaceholders:
    def test_env_backed_client_secret_is_not_materialized_when_editing_other_client(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("APP1_SECRET", "SUPERSECRET")
        config_dir = _seed_custom_settings(
            tmp_path,
            """\
server:
  host: 0.0.0.0
  port: 8000
oauth:
  audience: my-app
  clients:
  - client_id: app1
    client_secret: ${APP1_SECRET:dev}
    description: first
  - client_id: app2
    client_secret: foo
    description: second
""",
        )
        manager = ConfigManager(str(config_dir))

        manager.settings.clients[1].description = "updated second client"
        manager.save()

        raw = _raw(config_dir)
        assert "client_secret: ${APP1_SECRET:dev}" in raw
        assert "SUPERSECRET" not in raw
        assert "client_secret: 'SUPERSECRET'" not in raw

        reloaded = ConfigManager(str(config_dir))
        assert reloaded.settings.clients[0].client_secret == "SUPERSECRET"
        assert reloaded.settings.clients[1].description == "updated second client"

    def test_empty_default_placeholder_stays_in_file_when_other_fields_change(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("DEVICE_URL", raising=False)
        config_dir = _seed_custom_settings(
            tmp_path,
            """\
server:
  host: 0.0.0.0
  port: 8000
oauth:
  audience: my-app
  device_verification_base_url: ${DEVICE_URL:}
  clients: []
""",
        )
        manager = ConfigManager(str(config_dir))

        manager.settings.audience = "changed-audience"
        manager.save()

        raw = _raw(config_dir)
        assert "device_verification_base_url: ${DEVICE_URL:}" in raw
        assert "device_verification_base_url: ''" not in raw
        parsed = _parsed(config_dir)
        assert parsed["oauth"]["audience"] == "changed-audience"
