"""
The settings plumbing derives from one table, and the table derives from
the models (#214).

serialization.OWNED_SETTINGS is the single description of which
settings.yaml keys the codebase manages; apply_settings_document and
yaml_writer's update_oauth_settings/update_saml_settings drive from it,
and mcp_server._UPDATE_SETTINGS_FIELDS is the MCP tool's writable-field
list. These tests pin every one of those surfaces to the document models
and the Settings model, so a new setting that misses a surface (or a
table row that names a key the models do not know) fails the suite
instead of silently drifting - the same treatment the client fields get
in tests/test_client_field_parity.py.
"""

import inspect

from nanoidp import config_documents as cd
from nanoidp.mcp_server import _TOOL_SCHEMAS, _UPDATE_SETTINGS_FIELDS
from nanoidp.models import Settings
from nanoidp.serialization import OWNED_SETTINGS
from nanoidp.services.yaml_writer import YamlWriter

_SECTION_MODELS = {
    "server": cd.ServerSection,
    "oauth": cd.OAuthSection,
    "saml": cd.SamlSection,
    "logging": cd.LoggingSection,
    "": cd.SettingsDocument,
}


class TestOwnedSettingsDeriveFromTheModels:
    def test_every_row_names_a_settings_attribute(self):
        for row in OWNED_SETTINGS:
            assert row.attr in Settings.model_fields, row

    def test_every_row_names_a_document_model_field(self):
        for row in OWNED_SETTINGS:
            model = _SECTION_MODELS[row.section]
            assert row.key in model.model_fields, row

    def test_rows_are_unique_per_key(self):
        keys = [(row.section, row.key) for row in OWNED_SETTINGS]
        assert len(keys) == len(set(keys))


class TestYamlWriterMatchesTheTable:
    def _writer_params(self, method_name):
        # expected_revision (#229 phase 3) is a stale-write precondition,
        # not a settings field - excluded from the table comparison the
        # same way self is.
        signature = inspect.signature(getattr(YamlWriter, method_name))
        return set(signature.parameters) - {"self", "expected_revision"}

    def test_update_oauth_settings_covers_exactly_the_oauth_rows(self):
        # `clients` is a merged list with its own save_client path, not a
        # scalar row, and stays out of both the table and this method.
        table = {row.key for row in OWNED_SETTINGS if row.section == "oauth"}
        assert self._writer_params("update_oauth_settings") == table

    def test_update_saml_settings_covers_exactly_the_saml_rows(self):
        table = {row.key for row in OWNED_SETTINGS if row.section == "saml"}
        assert self._writer_params("update_saml_settings") == table


class TestMcpUpdateSettingsMatchesItsSchema:
    def test_field_tuple_equals_the_tool_schema(self):
        schema = set(_TOOL_SCHEMAS["update_settings"]["properties"])
        assert set(_UPDATE_SETTINGS_FIELDS) == schema

    def test_every_field_is_a_settings_attribute(self):
        for field in _UPDATE_SETTINGS_FIELDS:
            assert field in Settings.model_fields, field


class TestBlankClearsTheSamlAttrNames:
    """Regression for the #226 review finding: blank means REMOVE the key.

    The writer's historical contract for roles_attr_name/groups_attr_name is
    "empty string drops the key so the default name applies again"; the
    first table version flattened them to plain rows and persisted a literal
    "" instead. The runtime masked it (the Settings validator normalizes
    blank back to the defaults), so only the persisted document showed the
    regression - which is exactly what this test reads.
    """

    def _seed(self, tmp_path):
        import shutil
        from pathlib import Path

        import yaml

        from nanoidp.config import ConfigManager

        repo_config = Path(__file__).resolve().parent.parent / "config"
        for name in ("settings.yaml", "users.yaml"):
            shutil.copy(repo_config / name, tmp_path / name)
        data = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        data["saml"]["roles_attr_name"] = "memberOf"
        data["saml"]["groups_attr_name"] = "memberGroups"
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(data))
        ConfigManager(str(tmp_path))  # the writer resolves its dir from this
        return YamlWriter(str(tmp_path))

    def test_blank_removes_the_keys_from_yaml(self, tmp_path):
        import yaml

        writer = self._seed(tmp_path)
        writer.update_saml_settings(roles_attr_name="", groups_attr_name="")
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert "roles_attr_name" not in saml
        assert "groups_attr_name" not in saml

    def test_custom_value_still_persists(self, tmp_path):
        import yaml

        writer = self._seed(tmp_path)
        writer.update_saml_settings(roles_attr_name="entitlementsOf")
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert saml["roles_attr_name"] == "entitlementsOf"
        assert saml["groups_attr_name"] == "memberGroups"


class TestTheAlgorithmNeverReachesTheFileUnchecked:
    """``saml.c14n_algorithm`` is a closed set since #297, so an unchecked
    value written here leaves a settings.yaml the next process cannot load:
    ``_atomic_write`` replaces the file first and only then reloads. Same
    guard, and the same reason, as ``login_mode``.
    """

    def _seed(self, tmp_path):
        import shutil
        from pathlib import Path

        from nanoidp.config import ConfigManager

        repo_config = Path(__file__).resolve().parent.parent / "config"
        for name in ("settings.yaml", "users.yaml"):
            shutil.copy(repo_config / name, tmp_path / name)
        ConfigManager(str(tmp_path))
        return YamlWriter(str(tmp_path))

    def test_an_invalid_algorithm_is_refused_before_anything_is_written(self, tmp_path):
        import pytest

        writer = self._seed(tmp_path)
        before = (tmp_path / "settings.yaml").read_text()
        with pytest.raises(ValueError, match="canonicalization algorithm"):
            writer.update_saml_settings(c14n_algorithm="exc-c14n")
        assert (tmp_path / "settings.yaml").read_text() == before

    def test_the_composed_form_write_is_guarded_too(self, tmp_path):
        import pytest

        writer = self._seed(tmp_path)
        before = (tmp_path / "settings.yaml").read_text()
        with pytest.raises(ValueError, match="canonicalization algorithm"):
            writer.update_settings_form(
                oauth_fields={}, saml_fields={"c14n_algorithm": "exc-c14n"}
            )
        assert (tmp_path / "settings.yaml").read_text() == before

    def test_blank_clears_the_key_so_the_default_applies(self, tmp_path):
        import yaml

        writer = self._seed(tmp_path)
        writer.update_saml_settings(c14n_algorithm="")
        saml = yaml.safe_load((tmp_path / "settings.yaml").read_text())["saml"]
        assert "c14n_algorithm" not in saml


class TestASettingOffTheTableSurvivesTheWriters:
    """Not being in OWNED_SETTINGS means "not managed by the settings form
    and the MCP update_settings tool", never "dropped by the next save".

    ``oauth.dynamic_registration`` (#190) is deliberately off the table: it
    opens an unauthenticated mutation endpoint, so it is a decision for the
    file. That only holds if a plain settings save leaves it alone, through
    both write paths: the form's own writer, and ConfigManager.save(), which
    is what the MCP save_config tool calls.
    """

    def _seed(self, tmp_path):
        import shutil
        from pathlib import Path

        from nanoidp.config import ConfigManager

        repo_config = Path(__file__).resolve().parent.parent / "config"
        for name in ("settings.yaml", "users.yaml"):
            shutil.copy(repo_config / name, tmp_path / name)
        text = (tmp_path / "settings.yaml").read_text()
        text = text.replace(
            "oauth:\n",
            "oauth:\n  dynamic_registration:\n    enabled: true\n    max_clients: 7\n",
            1,
        )
        (tmp_path / "settings.yaml").write_text(text)
        return ConfigManager(str(tmp_path))

    def _block(self, tmp_path):
        import yaml

        document = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        return document["oauth"].get("dynamic_registration")

    def test_the_form_writer_leaves_it_alone(self, tmp_path):
        self._seed(tmp_path)
        YamlWriter(str(tmp_path)).update_oauth_settings(audience="something-else")
        assert self._block(tmp_path) == {"enabled": True, "max_clients": 7}

    def test_config_save_leaves_it_alone(self, tmp_path):
        config = self._seed(tmp_path)
        config.settings.verbose_logging = False
        config.save()
        assert self._block(tmp_path) == {"enabled": True, "max_clients": 7}
        assert config.settings.dynamic_registration_max_clients == 7
