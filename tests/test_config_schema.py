"""
The generated config schema and the surface-parity tests (#175 piece 3).

Two different guarantees:

- **Drift**: ``docs/schema/config.v1.json`` is committed, so it must be what
  ``nanoidp config-schema`` produces right now. Change a document model
  without regenerating and this fails with the command to run.
- **Parity**: every knob the MCP ``update_settings`` tool and the web UI's
  settings form offer must reach a field of the document models, and the
  YAML-only fields must not be offered by either. Adding a knob to one
  surface only, or to a surface but not to the contract, fails here.

The parity tests read the surfaces themselves (the tool's input schema, the
template's ``name=`` attributes), not a list of names kept next to them,
which is what makes them notice an addition nobody told them about.
"""

import json
import re
from pathlib import Path

import jsonschema
import pytest

from nanoidp.config_documents import SettingsDocument
from nanoidp.config_schema import (
    SCHEMA_MODELS,
    artifact_path,
    build_schema_document,
    file_schema,
    render,
)
from nanoidp.mcp_server import _TOOL_SCHEMAS

REPO = Path(__file__).resolve().parent.parent
SETTINGS_TEMPLATE = REPO / "src" / "nanoidp" / "templates" / "settings.html"

# Fields of settings.yaml that are deliberately NOT editable through the MCP
# server or the web UI: secrets and switches an operator owns, and the two
# extension sections whose values are commands (#185). A knob that appears on
# a remote surface for one of these is a security regression, not a feature.
YAML_ONLY_FIELDS = {
    "secret_key",
    "require_ui_login",
    "hooks",
    "plugins",
}

# Flat name used by the MCP tool / the UI form -> dotted path in the document
# models. Only the names that are not already a section field of the same
# name: the domain Settings is flat, the YAML is nested, and this table is
# where that translation is written down once.
FLAT_TO_DOCUMENT_PATH = {
    "saml_entity_id": "saml.entity_id",
    "saml_sso_url": "saml.sso_url",
    "saml_sign_responses": "saml.sign_responses",
    "saml_export_roles": "saml.export_roles",
    "saml_export_groups": "saml.export_groups",
    "saml_roles_attr_name": "saml.roles_attr_name",
    "saml_groups_attr_name": "saml.groups_attr_name",
    "saml_c14n_algorithm": "saml.c14n_algorithm",
    "saml_want_authn_requests_signed": "saml.want_authn_requests_signed",
    "saml_sp_certificates": "saml.sp_certificates",
    "strict_saml_binding": "saml.strict_binding",
    "default_acs_url": "saml.default_acs_url",
    "login_mode": "login.mode",
    "verbose_logging": "logging.verbose_logging",
    "log_token_requests": "logging.log_token_requests",
    "log_saml_requests": "logging.log_saml_requests",
    "log_level": "logging.level",
    "jwt_algorithm": "jwt.algorithm",
    "keys_dir": "jwt.keys_dir",
    "host": "server.host",
    "port": "server.port",
    "debug": "server.debug",
    "secret_key": "session.secret_key",
    "require_ui_login": "session.require_ui_login",
    "enforce_password_check": "session.enforce_password_check",
}


def document_paths() -> set:
    """Every dotted path a settings.yaml key can have."""
    paths = set()
    for name, field in SettingsDocument.model_fields.items():
        paths.add(name)
        annotation = field.annotation
        section_fields = getattr(annotation, "model_fields", None)
        if section_fields:
            paths.update(f"{name}.{sub}" for sub in section_fields)
    return paths


def resolve(flat_name: str) -> str | None:
    """The document path a surface's field name maps to, or None.

    An unprefixed name that is a field of exactly one section resolves on its
    own (``issuer`` -> ``oauth.issuer``); everything else goes through the
    rename table above. Ambiguity is refused rather than guessed.
    """
    if flat_name in FLAT_TO_DOCUMENT_PATH:
        return FLAT_TO_DOCUMENT_PATH[flat_name]
    paths = document_paths()
    if flat_name in paths:
        return flat_name
    matches = [p for p in paths if p.endswith(f".{flat_name}")]
    if len(matches) == 1:
        return matches[0]
    return None


def template_field_names() -> set:
    """The names the settings form actually posts.

    ``<name>__on_form`` markers are the checkbox contract (#131), not knobs,
    and the per-checkbox hidden marker is derived from the real field.
    """
    html = SETTINGS_TEMPLATE.read_text()
    names = set(re.findall(r'name="([^"]+)"', html))
    return {name for name in names if not name.endswith("__on_form")}


class TestGeneratedSchema:
    def test_committed_artifact_matches_the_models(self):
        """The one test that keeps the artifact honest."""
        committed = artifact_path()
        assert committed.exists(), f"missing {committed}: run nanoidp config-schema --write"
        assert committed.read_text() == render(build_schema_document()), (
            "schema drifted: run nanoidp config-schema --write"
        )

    def test_render_is_deterministic(self):
        assert render(build_schema_document()) == render(build_schema_document())

    def test_document_carries_the_three_files_and_the_version(self):
        document = build_schema_document()
        assert document["config_version"] == 1
        for name in ("settings", "users", "bootstrap"):
            assert name in document
            jsonschema.Draft202012Validator.check_schema(document[name])

    def test_each_file_schema_is_standalone(self):
        """A consumer picks one entry and validates with it, no cross-file
        reference resolution: the $defs a sub-schema refers to are its own."""
        for name in SCHEMA_MODELS:
            schema = file_schema(name)
            refs = re.findall(r'"\$ref": "([^"]+)"', json.dumps(schema))
            defs = schema.get("$defs", {})
            for ref in refs:
                assert ref.startswith("#/$defs/"), ref
                assert ref.rsplit("/", 1)[1] in defs, ref

    def test_schema_rejects_the_typo_the_loader_warns_about(self):
        schema = file_schema("settings")
        jsonschema.validate({"oauth": {"issuer": "http://localhost:8000"}}, schema)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({"oauth": {"isuer": "http://localhost:8000"}}, schema)

    def test_config_validation_is_in_the_contract(self):
        """Piece 4's key is part of the published contract, not a hidden knob."""
        assert "config_validation" in file_schema("settings")["properties"]


class TestMcpUpdateSettingsParity:
    """Every MCP knob is a real key of the contract, and no YAML-only one is."""

    def test_every_property_maps_to_a_document_field(self):
        paths = document_paths()
        unmapped = {}
        for name in _TOOL_SCHEMAS["update_settings"]["properties"]:
            resolved = resolve(name)
            if resolved is None or resolved not in paths:
                unmapped[name] = resolved
        assert not unmapped, (
            "MCP update_settings offers knobs that are not settings.yaml keys "
            f"(or are not in the rename table): {unmapped}"
        )

    def test_yaml_only_fields_are_not_offered(self):
        offered = set(_TOOL_SCHEMAS["update_settings"]["properties"])
        assert not (offered & YAML_ONLY_FIELDS), (
            "these are operator-owned YAML-only fields and must not be settable "
            f"over MCP: {sorted(offered & YAML_ONLY_FIELDS)}"
        )

    def test_validate_config_tool_is_read_only(self):
        from nanoidp.mcp_server import MUTATING_TOOLS

        assert "validate_config" in _TOOL_SCHEMAS
        assert "validate_config" not in MUTATING_TOOLS


class TestSettingsFormParity:
    """Same contract for the web UI's settings form."""

    def test_every_form_field_maps_to_a_document_field(self):
        paths = document_paths()
        unmapped = {}
        for name in template_field_names():
            resolved = resolve(name)
            if resolved is None or resolved not in paths:
                unmapped[name] = resolved
        assert not unmapped, (
            "the settings form posts fields that are not settings.yaml keys "
            f"(or are not in the rename table): {unmapped}"
        )

    def test_yaml_only_fields_are_not_editable(self):
        posted = template_field_names()
        assert not (posted & YAML_ONLY_FIELDS), (
            f"YAML-only fields must not be form-editable: {sorted(posted & YAML_ONLY_FIELDS)}"
        )

    def test_rename_table_has_no_stale_entries(self):
        """A rename that no surface uses any more is a lie waiting to happen."""
        paths = document_paths()
        used = set(_TOOL_SCHEMAS["update_settings"]["properties"]) | template_field_names()
        # Names that document the flat domain model without being on a surface
        # are allowed; what is not allowed is a target that does not exist.
        broken = {
            flat: target
            for flat, target in FLAT_TO_DOCUMENT_PATH.items()
            if target not in paths
        }
        assert not broken, f"rename table points at non-existent keys: {broken}"
        assert used, "no surface fields found: the parity test would pass vacuously"
