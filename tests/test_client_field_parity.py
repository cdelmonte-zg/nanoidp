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
