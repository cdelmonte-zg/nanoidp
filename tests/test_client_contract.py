"""
Parametric client contract (#231): one fully-populated OAuthClient survives
every imperative write leg, and a fully-cleared one survives the way back.

The #214/#226 parity tests pin the DECLARATIVE surfaces (load contract, MCP
read surface and tool schemas, form template). They cannot see whether the
imperative code actually reads a field from the form, applies it in the MCP
handler or writes it to YAML. This module closes that gap without a
registry: every field of OAuthClient is set to a non-default value (checked
against the model, so a new field with a default fails here first), pushed
through each leg, and read back from disk. A second fixture differs from the
first in every field, so an edit proves the parsers READ each field rather
than keep the previous value; a third is all defaults, so the way back
proves emptied fields are dropped rather than persisted as leftovers.

Legs:
1. pure YAML: client_to_yaml / merge_client_entry -> ClientEntry.to_client
2. UI: POST /clients/create and /clients/<id>/edit, then a fresh
   ConfigManager on the same directory
3. MCP: create_client, update_client, save_config, then a fresh ConfigManager

The form and MCP payloads are derived from the model generically, so a new
field is posted automatically; a new field TYPE the converters do not know
raises, which is the right failure.
"""

import json
from typing import Any, Dict

import pytest
from pydantic_core import PydanticUndefined

from nanoidp.config import ConfigManager, get_config
from nanoidp.config_documents import ClientEntry
from nanoidp.models import OAuthClient
from nanoidp.serialization import client_to_yaml, merge_client_entry

CLIENT_ID = "contract-client"

FULL_A = OAuthClient(
    client_id=CLIENT_ID,
    client_secret="secret-a",
    description="every field set, variant a",
    background_color="#112233",
    header_color="#445566",
    footer_color="#778899",
    show_client_id=False,
    show_description=True,
    additional_audiences=["aud-a1", "aud-a2"],
    redirect_uris=["https://a.example/cb", "http://127.0.0.1:7001/cb"],
    allowed_scopes=["openid", "profile"],
)

FULL_B = OAuthClient(
    client_id=CLIENT_ID,
    client_secret="secret-b",
    description="every field set, variant b",
    background_color="#aabbcc",
    header_color="#ddeeff",
    footer_color="#001122",
    show_client_id=False,
    show_description=True,
    additional_audiences=["aud-b1"],
    redirect_uris=["https://b.example/cb"],
    allowed_scopes=["openid", "email", "groups"],
)

# Every field at its default except the two required ones.
DEFAULTS = OAuthClient(client_id=CLIENT_ID, client_secret="secret-defaults")


def _as_form(client: OAuthClient) -> Dict[str, str]:
    """The clients_form.html POST body for ``client``: textareas are one item
    per line, checkboxes are present only when checked, None is a blank."""
    form: Dict[str, str] = {}
    for name, value in client.model_dump().items():
        if isinstance(value, bool):
            if value:
                form[name] = "on"
        elif isinstance(value, list):
            form[name] = "\n".join(value)
        elif value is None:
            form[name] = ""
        elif isinstance(value, str):
            form[name] = value
        else:  # pragma: no cover - a new field type needs a converter here
            raise TypeError(f"no form encoding for {name}={value!r}")
    return form


def _as_mcp_arguments(client: OAuthClient) -> Dict[str, Any]:
    """create_client/update_client arguments carrying every schema property
    (the tool schemas equal the model fields, see test_client_field_parity).
    The schemas type the colors as ``string`` and document that the empty
    string clears one, so a None color is sent as ``""``."""
    return {
        name: ("" if value is None else value) for name, value in client.model_dump().items()
    }


def _reload(config_dir) -> OAuthClient:
    fresh = ConfigManager(str(config_dir))
    client = fresh.get_client(CLIENT_ID)
    assert client is not None, f"{CLIENT_ID} not found after reload from {config_dir}"
    return client


def _assert_same(actual: OAuthClient, expected: OAuthClient) -> None:
    assert actual.model_dump() == expected.model_dump()


class TestFixturesCoverTheModel:
    """The fixtures are only meaningful if they really exercise every field."""

    @pytest.mark.parametrize("name", sorted(OAuthClient.model_fields))
    def test_full_a_and_full_b_are_non_default(self, name):
        field = OAuthClient.model_fields[name]
        if field.default is PydanticUndefined and field.default_factory is None:
            return  # required field: any value is a non-default
        default = field.get_default(call_default_factory=True)
        assert getattr(FULL_A, name) != default, f"FULL_A.{name} is the default"
        assert getattr(FULL_B, name) != default, f"FULL_B.{name} is the default"

    @pytest.mark.parametrize("name", sorted(set(OAuthClient.model_fields) - {"client_id"}))
    def test_full_a_and_full_b_differ_in_every_field(self, name):
        if isinstance(getattr(FULL_A, name), bool):
            # Both flip the default; a boolean cannot differ from the default
            # in two ways. The way back to DEFAULTS covers the other value.
            return
        assert getattr(FULL_A, name) != getattr(FULL_B, name), name

    def test_form_encoding_carries_every_field(self):
        # Unchecked boxes are absent from a real browser POST: FULL_A/FULL_B
        # uncheck show_client_id, DEFAULTS leaves show_description unchecked.
        assert set(_as_form(FULL_A)) == set(OAuthClient.model_fields) - {"show_client_id"}
        assert set(_as_form(DEFAULTS)) == set(OAuthClient.model_fields) - {"show_description"}

    def test_mcp_encoding_carries_every_field(self):
        for fixture in (FULL_A, FULL_B, DEFAULTS):
            assert set(_as_mcp_arguments(fixture)) == set(OAuthClient.model_fields)


class TestYamlLeg:
    def test_new_entry_round_trips(self):
        entry = json.loads(json.dumps(client_to_yaml(FULL_A)))
        _assert_same(ClientEntry.model_validate(entry).to_client(), FULL_A)

    def test_merge_replaces_every_field(self):
        entry = merge_client_entry(client_to_yaml(FULL_A), FULL_B)
        _assert_same(ClientEntry.model_validate(entry).to_client(), FULL_B)

    def test_merge_back_to_defaults_drops_the_optional_keys(self):
        entry = merge_client_entry(client_to_yaml(FULL_B), DEFAULTS)
        _assert_same(ClientEntry.model_validate(entry).to_client(), DEFAULTS)
        # Not just equivalent after load: the keys are gone from the document,
        # the same blank-means-clear contract #226 pinned for settings.
        assert set(entry) == {"client_id", "client_secret", "description"}


class TestUiLeg:
    """Through the real form parsers, read back from disk."""

    def test_create_edit_and_clear_through_the_form(self, app, client):
        with app.app_context():
            config_dir = get_config().config_dir

        resp = client.post("/clients/create", data=_as_form(FULL_A))
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/clients")
        _assert_same(_reload(config_dir), FULL_A)

        resp = client.post(f"/clients/{CLIENT_ID}/edit", data=_as_form(FULL_B))
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/clients")
        _assert_same(_reload(config_dir), FULL_B)

        resp = client.post(f"/clients/{CLIENT_ID}/edit", data=_as_form(DEFAULTS))
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/clients")
        _assert_same(_reload(config_dir), DEFAULTS)


class TestMcpLeg:
    """Through the real tool handlers over the in-memory MCP client, persisted
    with save_config and read back from disk."""

    @pytest.fixture
    def mcp_config(self, app, monkeypatch):
        import nanoidp.mcp_server as mcp

        with app.app_context():
            config = get_config()
        monkeypatch.setattr(mcp, "_config", config)
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
        monkeypatch.delenv("NANOIDP_MANAGEMENT_SECRET", raising=False)
        return config

    @staticmethod
    def _payload(result):
        assert result.is_error is not True, result.content[0].text
        return json.loads(result.content[0].text)

    @pytest.mark.asyncio
    async def test_create_update_and_clear_through_the_tools(self, mcp_config, mcp_call_tool):
        config_dir = mcp_config.config_dir

        self._payload(await mcp_call_tool("create_client", _as_mcp_arguments(FULL_A)))
        _assert_same(mcp_config.get_client(CLIENT_ID), FULL_A)
        self._payload(await mcp_call_tool("save_config", {}))
        _assert_same(_reload(config_dir), FULL_A)

        self._payload(await mcp_call_tool("update_client", _as_mcp_arguments(FULL_B)))
        _assert_same(mcp_config.get_client(CLIENT_ID), FULL_B)
        self._payload(await mcp_call_tool("save_config", {}))
        _assert_same(_reload(config_dir), FULL_B)

        self._payload(await mcp_call_tool("update_client", _as_mcp_arguments(DEFAULTS)))
        _assert_same(mcp_config.get_client(CLIENT_ID), DEFAULTS)
        self._payload(await mcp_call_tool("save_config", {}))
        _assert_same(_reload(config_dir), DEFAULTS)
