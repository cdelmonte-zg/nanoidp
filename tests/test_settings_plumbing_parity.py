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
import re
from typing import Literal, Optional

import pytest

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


class TestTheSettingsPageDerivesFromTheTable:
    """#299: the settings route used to repeat the YAML key names the table
    owns. It now builds each section from the table, which only holds while
    the page actually carries a field per row, named after the attribute.
    """

    _SECTIONS = ("oauth", "saml")

    def _page(self):
        from pathlib import Path

        template = (
            Path(__file__).resolve().parent.parent
            / "src/nanoidp/templates/settings.html"
        )
        return set(re.findall(r'name="([A-Za-z0-9_]+)"', template.read_text()))

    def _rows(self):
        return [row for row in OWNED_SETTINGS if row.section in self._SECTIONS]

    def test_every_row_has_a_field_named_after_its_attribute(self):
        fields = self._page()
        for row in self._rows():
            assert row.attr in fields, row

    def test_which_rows_count_as_checkboxes_is_asked_of_the_reader(self):
        """The rule the test above applies, exercised on the shape no row
        has today: an ``Optional[bool]`` setting is a checkbox, and a test
        keyed on ``annotation is bool`` would skip it - and with it the
        missing-marker regression (#131) it exists to catch.
        """
        from nanoidp.routes.ui import _form_bool, _settings_form_reader

        assert _settings_form_reader(Optional[bool]) is _form_bool
        assert Optional[bool] is not bool

    def test_every_checkbox_row_has_its_on_form_marker(self):
        """Without the marker a cleared checkbox reads as "not on this form",
        so unchecking it would silently do nothing (#131).

        Which rows are checkboxes is asked of the reader, not of the raw
        annotation: ``Optional[bool]`` is a checkbox too, and keying this on
        ``is bool`` would skip it and let exactly that regression through.
        """
        from nanoidp.routes.ui import _form_bool, _settings_form_reader

        fields = self._page()
        for row in self._rows():
            reader = _settings_form_reader(Settings.model_fields[row.attr].annotation)
            if reader is _form_bool:
                assert f"{row.attr}__on_form" in fields, row

    def test_every_row_has_a_reader_for_its_declared_type(self):
        """A setting added as a shape the form reader does not know fails
        here, rather than being read as text."""
        from nanoidp.routes.ui import _settings_form_reader

        for row in self._rows():
            assert callable(_settings_form_reader(Settings.model_fields[row.attr].annotation))

    @pytest.mark.parametrize(
        "annotation",
        [
            dict[str, str],
            # A container without its item type spelled out: reading it as a
            # list of strings would write strings nobody said were strings.
            list,
            list[int],
            float,
            Optional[dict[str, str]],
        ],
        ids=("dict", "bare-list", "list-of-int", "float", "optional-dict"),
    )
    def test_an_unknown_shape_is_refused_rather_than_read_as_text(self, annotation):
        from nanoidp.routes.ui import _settings_form_reader

        with pytest.raises(TypeError):
            _settings_form_reader(annotation)

    @pytest.mark.parametrize(
        ("annotation", "reader_name"),
        [
            (bool, "_form_bool"),
            (Optional[bool], "_form_bool"),
            (int, "_form_int"),
            (Optional[int], "_form_int"),
            (str, "_form_text"),
            (Optional[str], "_form_text"),
            (Literal["a", "b"], "_form_text"),
            (list[str], "_form_textarea_list"),
            (Optional[list[str]], "_form_textarea_list"),
        ],
    )
    def test_each_shape_the_reader_knows(self, annotation, reader_name):
        from nanoidp.routes import ui

        assert ui._settings_form_reader(annotation) is getattr(ui, reader_name)

    def test_the_route_builds_exactly_the_writer_keywords(self, app):
        """What the route generates is what the writer takes: compared
        against the writer's own signature, not against the table both
        sides derive from."""
        from nanoidp.routes.ui import _settings_form_fields

        with app.test_request_context("/settings", method="POST", data={}):
            for section, method in (
                ("oauth", "update_oauth_settings"),
                ("saml", "update_saml_settings"),
            ):
                signature = inspect.signature(getattr(YamlWriter, method))
                keywords = set(signature.parameters) - {"self", "expected_revision"}
                assert set(_settings_form_fields(section)) == keywords


class TestTheSettingsPageReadsEachTypeAsItAlwaysHas:
    """The readers themselves, pinned per kind (#299). "Absent means
    unchanged" is the contract every one of them shares (#131)."""

    def _submitted(self, app, data):
        from nanoidp.routes.ui import _settings_form_fields

        with app.test_request_context("/settings", method="POST", data=data):
            return {**_settings_form_fields("oauth"), **_settings_form_fields("saml")}

    def test_an_empty_form_changes_nothing(self, app):
        assert set(self._submitted(app, {}).values()) == {None}

    def test_a_checkbox_tells_unchecked_from_absent(self, app):
        checked = self._submitted(app, {"require_pkce": "true"})
        unchecked = self._submitted(app, {"require_pkce__on_form": "1"})
        absent = self._submitted(app, {})

        assert checked["require_pkce"] is True
        assert unchecked["require_pkce"] is False
        assert absent["require_pkce"] is None

    def test_a_text_field_clears_when_blank(self, app):
        assert self._submitted(app, {"audience": "  api  "})["audience"] == "api"
        assert self._submitted(app, {"audience": ""})["audience"] == ""

    def test_a_list_field_reads_the_textarea(self, app):
        submitted = self._submitted(app, {"issuer_allowlist": "https://a\nhttps://b"})
        assert submitted["issuer_allowlist"] == ["https://a", "https://b"]
        assert self._submitted(app, {"issuer_allowlist": ""})["issuer_allowlist"] == []

    def test_a_number_treats_blank_as_unchanged_and_refuses_a_non_number(self, app):
        """Unlike a string, an int has no empty value to write; and "   " is
        the error it always was, not a quiet "unchanged"."""
        assert self._submitted(app, {"token_expiry_minutes": "60"})["token_expiry_minutes"] == 60
        assert self._submitted(app, {"token_expiry_minutes": ""})["token_expiry_minutes"] is None

        with pytest.raises(ValueError):
            self._submitted(app, {"token_expiry_minutes": "   "})
        with pytest.raises(ValueError):
            self._submitted(app, {"token_expiry_minutes": "abc"})

    def test_a_literal_field_is_read_as_text(self, app):
        assert self._submitted(app, {"saml_c14n_algorithm": "c14n11"})["c14n_algorithm"] == "c14n11"

    def test_the_saml_keys_are_the_yaml_names_not_the_attributes(self, app):
        """entity_id is the key; saml_entity_id is the form field."""
        submitted = self._submitted(app, {"saml_entity_id": "urn:x"})

        assert submitted["entity_id"] == "urn:x"
        assert "saml_entity_id" not in submitted


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
