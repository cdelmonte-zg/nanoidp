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
- ``attributes`` in the UI is a dynamic ``attr_key[]``/``attr_value[]``
  widget, not a single named input - recognized explicitly (#291 corrected:
  the input was never missing, the single-name regex just could not see it).
- ``/api/users/<u>`` adds derived ``authorities`` (not a stored field).
- ``totp_secret`` (#348) is YAML-only, strictly more excluded than
  ``password``: the operator writes it directly in users.yaml, and it is
  absent from every surface that isn't the YAML load contract itself - the
  users form, every MCP user tool (create_user/update_user included, unlike
  password, which those tools DO accept), _USER_COMMON_PROPERTIES, and every
  read surface. An edit through the form or MCP leaves whatever secret the
  file already has untouched (see routes/ui.py and the MCP update_user
  handler), rather than accepting a new one.
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
        # password and totp_secret are the intentional omissions on every
        # read surface.
        assert set(_user_to_dict(user)) == _MODEL_FIELDS - {"password", "totp_secret"}

    def test_mcp_common_properties_match_the_model(self):
        # The shared block omits username/password (declared separately by
        # create/update, asserted below) and totp_secret (YAML-only, #348).
        assert set(_USER_COMMON_PROPERTIES) == _MODEL_FIELDS - {
            "username", "password", "totp_secret",
        }

    def test_mcp_tool_schemas_match_the_model(self):
        # totp_secret is YAML-only (#348): neither create_user nor
        # update_user takes it, unlike password, which both do.
        for tool in ("create_user", "update_user"):
            assert set(_TOOL_SCHEMAS[tool]["properties"]) == _MODEL_FIELDS - {"totp_secret"}, tool

    def test_users_form_has_an_input_per_field(self):
        html = _TEMPLATE.read_text()
        form_names = set(re.findall(r'name="([a-z_]+)"', html))
        # attributes is a dynamic key/value widget, not a single named input:
        # attr_key[]/attr_value[] rows (brackets, so the regex above cannot
        # see them - the #291 premise error: this test originally declared
        # the input missing without reading the template). Recognized
        # explicitly instead of excluded.
        widget_names = set(re.findall(r'name="([a-z_\[\]]+)"', html))
        assert {"attr_key[]", "attr_value[]"} <= widget_names, (
            "the users form lost its attributes widget"
        )
        # totp_secret is YAML-only (#348): the operator writes it in
        # users.yaml, not through this form.
        missing = _MODEL_FIELDS - form_names - {"attributes", "totp_secret"}
        assert not missing, f"users_form.html has no input for: {sorted(missing)}"

    def test_api_read_surface_matches_the_model(self, client):
        resp = client.get("/api/users/admin")
        assert resp.status_code == 200
        keys = set(resp.get_json())
        # password/totp_secret elided; authorities is derived and origin (#192)
        # says declared or runtime, neither is a stored field.
        assert keys == (_MODEL_FIELDS - {"password", "totp_secret"}) | {"authorities", "origin"}
