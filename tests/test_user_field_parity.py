"""
User-field parity across the declared surfaces of the user-field flow (#284).

The user record is the widest shape family in the codebase (nine shapes) and
had NO parity coverage: the drift was not hypothetical - the MCP update_user
schema and handler silently lost `attributes` (#280) with nothing to notice.
Same philosophy as test_client_field_parity.py: cover the DECLARATIVE
surfaces cheaply so a forgotten leg is a suite failure, leave the imperative
legs (user_to_yaml, the UI parsers, the MCP handler bodies) to per-feature
tests.

Documented exclusions, each intentional and each asserted (so an exclusion
that stops being true also fails):

- ``username`` is the YAML mapping key, not a UserEntry field.
- ``password`` never appears on a read surface (_user_to_dict, /api/users).
- The MCP _USER_COMMON_PROPERTIES block omits username/password because the
  create/update schemas declare those two separately.
- The UI users form has no input for ``attributes`` - the one write surface
  that cannot touch the field, recorded as #291 rather than silently skipped.
- ``/api/users/<u>`` adds derived ``authorities`` (not a stored field).
"""

import re
from pathlib import Path

from nanoidp.config_documents import UserEntry
from nanoidp.mcp_server import _TOOL_SCHEMAS, _USER_COMMON_PROPERTIES, _user_to_dict
from nanoidp.models import User

_MODEL_FIELDS = set(User.model_fields)

_TEMPLATE = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "nanoidp"
    / "templates"
    / "users_form.html"
)


class TestUserFieldParity:
    def test_yaml_load_contract_matches_the_model(self):
        # username is the mapping key in users.yaml, not an entry field.
        assert set(UserEntry.model_fields) == _MODEL_FIELDS - {"username"}

    def test_mcp_read_surface_matches_the_model(self):
        user = User(username="parity", password="p")
        # password is the one intentional omission on every read surface.
        assert set(_user_to_dict(user)) == _MODEL_FIELDS - {"password"}

    def test_mcp_common_properties_match_the_model(self):
        # The shared block omits username/password: the create/update schemas
        # declare those two separately (asserted below).
        assert set(_USER_COMMON_PROPERTIES) == _MODEL_FIELDS - {"username", "password"}

    def test_mcp_tool_schemas_match_the_model(self):
        for tool in ("create_user", "update_user"):
            assert set(_TOOL_SCHEMAS[tool]["properties"]) == _MODEL_FIELDS, tool

    def test_users_form_has_an_input_per_field(self):
        html = _TEMPLATE.read_text()
        form_names = set(re.findall(r'name="([a-z_]+)"', html))
        # attributes: the UI form cannot set custom attributes today - the
        # only write surface with that gap, tracked as #291. If this
        # assertion starts failing because the input EXISTS, close #291 and
        # delete the exclusion.
        missing = _MODEL_FIELDS - form_names - {"attributes"}
        assert not missing, f"users_form.html has no input for: {sorted(missing)}"
        assert "attributes" not in form_names, "attributes input exists: close #291"

    def test_api_read_surface_matches_the_model(self, client):
        resp = client.get("/api/users/admin")
        assert resp.status_code == 200
        keys = set(resp.get_json())
        # password elided; authorities is derived, not a stored field.
        assert keys == (_MODEL_FIELDS - {"password"}) | {"authorities"}
