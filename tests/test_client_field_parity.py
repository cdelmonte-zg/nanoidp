"""
Client-field parity across the declared surfaces of the client-field flow (#214).

The registry idea was declined: the manual flow works, but a forgotten leg
should become a suite failure instead of a review catch (the #32 shape)
wherever that check is cheap. These tests cover the DECLARATIVE surfaces -
the ones whose field lists can be introspected. They do NOT prove that the
imperative legs (client_to_yaml, merge_client_entry, the UI form parsers,
the MCP create/update handler bodies) actually apply a new field; those
stay covered by the per-feature tests the flow requires. Every field of
OAuthClient must appear in:

- config_documents.ClientEntry (the YAML load contract),
- mcp_server._client_to_dict (MCP read surface),
- the create_client and update_client tool schemas,
- the clients form template (UI create/edit surface).

The regenerate-secret leg needs no entry here: it copies the whole model
(model_copy, #218), so it cannot miss a field by construction. The settings
contract already gets the same treatment from #175 piece 3's parity tests.
"""

import re
from pathlib import Path

from nanoidp.config_documents import ClientEntry
from nanoidp.mcp_server import _TOOL_SCHEMAS, _client_to_dict
from nanoidp.models import OAuthClient

_MODEL_FIELDS = set(OAuthClient.model_fields)

_TEMPLATE = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "nanoidp"
    / "templates"
    / "clients_form.html"
)


class TestClientFieldParity:
    def test_yaml_load_contract_matches_the_model(self):
        assert set(ClientEntry.model_fields) == _MODEL_FIELDS

    def test_mcp_read_surface_matches_the_model(self):
        client = OAuthClient(client_id="parity", client_secret="s")
        # client_secret is the one intentional omission: the read surface
        # never echoes the secret back.
        assert set(_client_to_dict(client)) == _MODEL_FIELDS - {"client_secret"}

    def test_mcp_tool_schemas_match_the_model(self):
        for tool in ("create_client", "update_client"):
            assert set(_TOOL_SCHEMAS[tool]["properties"]) == _MODEL_FIELDS, tool

    def test_clients_form_has_an_input_per_field(self):
        html = _TEMPLATE.read_text()
        form_names = set(re.findall(r'name="([a-z_]+)"', html))
        missing = _MODEL_FIELDS - form_names
        assert not missing, f"clients_form.html has no input for: {sorted(missing)}"


class TestTheImperativeLegsCarryEveryField:
    """What the parity suite above deliberately left uncovered (#298).

    The docstring of this module says the imperative legs are not proven by
    it. Two of them are cheap to prove after all: the UI form reader, which
    is now one function that names every field, and the MCP update handler,
    whose membership tests can be observed.
    """

    def test_the_clients_form_reader_sets_every_field(self, app):
        """`model_fields_set` is the whole model, so nothing is left to a
        default. A field added to OAuthClient tomorrow and forgotten by the
        reader fails here instead of being erased on the next edit: the
        form routes are whole-record writers."""
        from nanoidp.routes.ui import _client_from_form

        with app.test_request_context("/clients/create", method="POST", data={
            "client_id": "parity", "client_secret": "s3cret",
        }):
            parsed = _client_from_form("parity", None)

        assert parsed.model_fields_set == _MODEL_FIELDS

    def test_the_reader_sets_every_field_on_the_edit_leg_too(self, app):
        """The leg that can delete: the create leg writes a new entry, this
        one replaces an existing record."""
        from nanoidp.routes.ui import _client_from_form

        existing = OAuthClient(client_id="parity", client_secret="stored")
        with app.test_request_context("/clients/parity/edit", method="POST", data={}):
            parsed = _client_from_form("parity", existing)

        assert parsed.model_fields_set == _MODEL_FIELDS

    def test_mcp_update_client_asks_about_every_mutable_field(self, app, recording_arguments):
        """client_id is the identity being updated, not a field the tool
        can change: it is read positionally, never asked about."""
        from nanoidp.config import get_config
        from nanoidp.mcp_server.handlers_clients import _tool_update_client

        arguments = recording_arguments({"client_id": "demo-client"})
        with app.app_context():
            result = _tool_update_client(arguments, get_config(), get_config().snapshot)

        assert result["success"] is True
        assert arguments.asked == _MODEL_FIELDS - {"client_id"}
