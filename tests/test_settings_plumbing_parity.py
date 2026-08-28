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
