"""
UI users form: non-string attributes survive an edit round-trip (#291).

Reproduced before the fix: the template rendered ``value="{{ value }}"``, so
a list-valued attribute (settable via YAML and MCP) rendered as its Python
repr and an UNTOUCHED edit stored ``"['alpha', 'beta']"`` (a string) in its
place. The fix is a JSON convention: the template renders non-string values
as JSON, and the shared parser reads a value starting with ``[`` or ``{``
back as JSON.
"""

import re

from werkzeug.datastructures import MultiDict

from nanoidp.config import get_config


def _resubmit_edit_form_unchanged(client, html, extra=None):
    """Post the edit form back exactly as a browser would (entities decoded)."""
    import html as html_mod

    keys = [html_mod.unescape(v) for v in re.findall(r'name="attr_key\[\]" value="([^"]*)"', html)]
    values = [html_mod.unescape(v) for v in re.findall(r'name="attr_value\[\]" value="([^"]*)"', html)]
    md = MultiDict(
        {
            "password": "",
            "description": "",
            "email": "admin@example.org",
            "tenant": "default",
            "roles": "USER",
            "groups": "",
            "entitlements": "",
            "source_acl": "",
        }
    )
    for k in keys:
        md.add("attr_key[]", k)
    for v in values:
        md.add("attr_value[]", v)
    m = re.search(r'name="expected_revision" value="([^"]*)"', html)
    if m:
        md.add("expected_revision", m.group(1))
    if extra:
        for k, v in extra.items():
            md.add(k, v)
    return client.post("/users/admin/edit", data=md)


class TestAttributeRoundTrip:
    def _login(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"

    def test_list_attribute_survives_untouched_edit(self, client, app):
        with app.app_context():
            get_config().get_user("admin").attributes = {
                "teams": ["alpha", "beta"],
                "plain": "x",
            }
        self._login(client)

        page = client.get("/users/admin/edit")
        html = page.data.decode()
        resp = _resubmit_edit_form_unchanged(client, html)
        assert resp.status_code == 302

        with app.app_context():
            stored = get_config().get_user("admin").attributes
        assert stored == {"teams": ["alpha", "beta"], "plain": "x"}

    def test_mapping_attribute_survives_untouched_edit(self, client, app):
        with app.app_context():
            get_config().get_user("admin").attributes = {"limits": {"rate": 5}}
        self._login(client)

        html = client.get("/users/admin/edit").data.decode()
        assert _resubmit_edit_form_unchanged(client, html).status_code == 302
        with app.app_context():
            assert get_config().get_user("admin").attributes == {"limits": {"rate": 5}}

    def test_operator_typed_json_container_is_parsed(self, client, app):
        """Typing a JSON list into the value box stores a list - the same
        convention in the write direction."""
        self._login(client)
        html = client.get("/users/admin/edit").data.decode()
        # Wipe any prefilled attribute rows; submit exactly one typed row.
        html_no_attrs = re.sub(r'name="attr_(?:key|value)\[\]" value="[^"]*"', "", html)
        resp = _resubmit_edit_form_unchanged(
            client, html_no_attrs, extra={"attr_key[]": "regions", "attr_value[]": '["eu", "us"]'}
        )
        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("admin").attributes == {"regions": ["eu", "us"]}

    def test_malformed_json_container_stays_a_string(self, client, app):
        self._login(client)
        html = client.get("/users/admin/edit").data.decode()
        html_no_attrs = re.sub(r'name="attr_(?:key|value)\[\]" value="[^"]*"', "", html)
        resp = _resubmit_edit_form_unchanged(
            client, html_no_attrs, extra={"attr_key[]": "oops", "attr_value[]": "[not json"}
        )
        assert resp.status_code == 302
        with app.app_context():
            assert get_config().get_user("admin").attributes == {"oops": "[not json"}

    def test_plain_string_value_stays_verbatim(self, client, app):
        self._login(client)
        html = client.get("/users/admin/edit").data.decode()
        html_no_attrs = re.sub(r'name="attr_(?:key|value)\[\]" value="[^"]*"', "", html)
        resp = _resubmit_edit_form_unchanged(
            client, html_no_attrs, extra={"attr_key[]": "note", "attr_value[]": "123"}
        )
        assert resp.status_code == 302
        with app.app_context():
            # Scalars typed in the UI are strings by design; only [ / { opt
            # into the JSON convention.
            assert get_config().get_user("admin").attributes == {"note": "123"}
