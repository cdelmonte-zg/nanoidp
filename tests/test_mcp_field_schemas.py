"""MCP tool properties take their value shape from the domain models (#297).

The census that reopened #297 found the published schemas were not drifting
from the models, they were quieter than them: 27 constraints the domain
enforces and the tools did not advertise. These tests hold the derivation in
place and keep a hand-written copy from creeping back.
"""

from typing import Any, Union

import pytest
from pydantic import BaseModel

from nanoidp.config_documents import LoginSection, SamlSection
from nanoidp.mcp_server.field_schemas import SHAPE_KEYS, DomainProperty, field_shape
from nanoidp.mcp_server.schemas import _TOOLS
from nanoidp.models import OAuthClient, Settings, User, login_modes

DOMAIN_FIELD_NAMES = set(User.model_fields) | set(OAuthClient.model_fields) | set(Settings.model_fields)

# Tool arguments that are not a domain field's value: the tool's own
# vocabulary, validated by the handler.
TOOL_ONLY = {
    ("generate_token", "expires_in_minutes"), ("generate_token", "extra_claims"),
    ("generate_token", "scope"), ("generate_token", "id_token_claims"),
    ("generate_token", "userinfo_claims"), ("generate_token", "resource"),
    ("decode_token", "token"), ("verify_token", "token"),
    ("verify_token", "audience"),
    ("validate_config", "strict"), ("save_config", "expected_users_revision"),
    ("save_config", "expected_settings_revision"), ("get_audit_log", "limit"),
    ("get_audit_log", "event_type"),
}


# Derivations where the argument is deliberately not named after its field.
# Empty today: every derived argument carries its field's own name, which is
# what makes the link checkable at all. An entry here should be a decision
# with a reason next to it, not a way to quiet the test below.
RENAMED_DERIVATIONS: dict = {}


def _properties():
    for tool in _TOOLS:
        for name, spec in (tool.input_schema or {}).get("properties", {}).items():
            yield tool.name, name, spec


class TestDerivation:
    def test_every_derived_property_still_matches_its_field(self):
        derived = [(t, n, s) for t, n, s in _properties() if isinstance(s, DomainProperty)]
        assert derived, "no property is derived any more"
        for tool, name, spec in derived:
            expected = {**field_shape(spec.model, spec.field), **spec.overrides}
            expected = {k: v for k, v in expected.items() if v is not None}
            shape = {k: v for k, v in spec.items() if k in SHAPE_KEYS}
            assert shape == expected, f"{tool}.{name} no longer matches {spec.model.__name__}.{spec.field}"

    def test_the_description_stays_the_tools_own(self):
        for tool, name, spec in _properties():
            if isinstance(spec, DomainProperty):
                assert spec["description"], f"{tool}.{name} has no description"
                # The tool describes the argument, the model the field; they
                # are allowed to differ, and mostly do.
                assert "description" not in {k: v for k, v in spec.items() if k in SHAPE_KEYS}

    def test_a_property_named_like_a_domain_field_is_derived_or_declared_tool_only(self):
        """The tripwire for the next client field (#190): a hand-written copy
        of a domain field's shape fails here instead of drifting quietly."""
        offenders = [
            (tool, name)
            for tool, name, spec in _properties()
            if not isinstance(spec, DomainProperty)
            and name in DOMAIN_FIELD_NAMES
            and (tool, name) not in TOOL_ONLY
        ]
        assert offenders == []

    def test_a_derived_argument_is_linked_to_the_field_it_is_named_after(self):
        """The parity test above recomputes the expected shape from
        ``spec.field``, so it compares a derivation with itself and cannot
        see one wired to the wrong field: ``"username": _domain(User,
        "email", ...)`` would match. The names are the check."""
        for tool, name, spec in _properties():
            if not isinstance(spec, DomainProperty):
                continue
            expected = RENAMED_DERIVATIONS.get((tool, name), name)
            assert spec.field == expected, (
                f"{tool}.{name} derives from {spec.model.__name__}.{spec.field}"
            )

    def test_requiredness_is_the_operations_own(self):
        """update_user patches a model whose full representation demands more."""
        tools = {tool.name: (tool.input_schema or {}) for tool in _TOOLS}
        assert tools["update_user"]["required"] == ["username"]
        assert tools["create_user"]["required"] == ["username", "password"]


class TestConstraintsNowPublished:
    @pytest.mark.parametrize(
        "tool, prop, key, value",
        [
            ("create_user", "username", "minLength", 1),
            ("create_user", "password", "minLength", 1),
            ("create_client", "client_id", "minLength", 1),
            ("update_settings", "token_expiry_minutes", "maximum", 1440),
            ("update_settings", "token_expiry_minutes", "exclusiveMinimum", 0),
        ],
    )
    def test_the_schema_advertises_what_the_domain_enforces(self, tool, prop, key, value):
        spec = {t.name: (t.input_schema or {}) for t in _TOOLS}[tool]["properties"][prop]
        assert spec[key] == value

    @pytest.mark.parametrize(
        "tool, prop, key",
        [
            ("create_client", "client_secret", "minLength"),
            ("create_client", "background_color", "pattern"),
            ("create_client", "header_color", "pattern"),
            ("create_client", "footer_color", "pattern"),
            ("update_client", "client_secret", "minLength"),
            ("update_client", "background_color", "pattern"),
            ("update_client", "header_color", "pattern"),
            ("update_client", "footer_color", "pattern"),
            ("get_audit_log", "username", "minLength"),
        ],
    )
    def test_an_argument_whose_vocabulary_is_wider_keeps_its_override(self, tool, prop, key):
        """'' means 'no secret', 'clear it' or - for the audit filter - 'no
        filter' to these tools, so the field's own constraint is dropped on
        purpose and the handler answers."""
        spec = {t.name: (t.input_schema or {}) for t in _TOOLS}[tool]["properties"][prop]
        assert key not in spec


class TestClosedSetsLiveInTheDomain:
    def test_login_mode_is_a_closed_set_in_the_model_and_the_document(self):
        assert login_modes() == ("password", "persona")
        assert field_shape(Settings, "login_mode")["enum"] == ["password", "persona"]
        with pytest.raises(ValueError):
            LoginSection.model_validate({"mode": "sudo"})

    def test_the_canonicalization_algorithm_is_a_closed_set(self):
        """An unknown value used to reach routes/saml.py, which silently
        signed with Exclusive C14N."""
        assert field_shape(Settings, "saml_c14n_algorithm")["enum"] == ["exc_c14n", "c14n", "c14n11"]
        with pytest.raises(ValueError):
            SamlSection.model_validate({"c14n_algorithm": "c14n99"})
        with pytest.raises(ValueError):
            Settings(saml_c14n_algorithm="c14n99")

    def test_a_blank_algorithm_still_means_the_default(self):
        """``config.py`` expands ``${VAR}`` before the document is validated
        and an unset variable expands to "", which has always meant "the
        default". Closing the set must not turn that into a failed load."""
        assert SamlSection.model_validate({"c14n_algorithm": ""}).c14n_algorithm == "exc_c14n"
        assert Settings(saml_c14n_algorithm="").saml_c14n_algorithm == "exc_c14n"


class TestAFieldWithNoSingleShape:
    """``field_shape`` publishes one shape or none at all: a field it cannot
    describe must fail here rather than reach a client as an argument with no
    constraints."""

    def test_a_union_of_value_types_is_refused(self):
        class M(BaseModel):
            either: Union[str, int] = "x"

        with pytest.raises(ValueError, match="union of 2 value types"):
            field_shape(M, "either")

    def test_a_field_with_nothing_to_publish_is_refused(self):
        class M(BaseModel):
            anything: Any = None

        with pytest.raises(ValueError, match="no publishable shape"):
            field_shape(M, "anything")
