"""Stateful identity scenarios through MCP (#402): the same service as
``/api/runtime/scenarios``, as tools.

A scenario armed through MCP is fired by the NanoIDP that serves the
application's requests: here one process holds both surfaces over a SQLite
store, and what one does the other is asked about. The gates every tool of
the runtime state shares (the store that is not shared, read-only mode, the
management secret) are in ``test_mcp_runtime_identities.py``, by tool.
"""

import base64
import json
import shutil
from pathlib import Path

import jsonschema
import jwt as pyjwt
import pytest
import yaml

import nanoidp.mcp_server as mcp
from nanoidp.app import create_app
from nanoidp.config import User
from nanoidp.mcp_server.schemas import _TOOLS
from nanoidp.services import scenarios
from nanoidp.services.audit import get_audit_log
from nanoidp.services.protocol_events import EVENTS, USER_GRANT_TYPES
from nanoidp.services.runtime_store import get_runtime_store
from tests.conftest import claim_for_promotion

_REPO = Path(__file__).resolve().parent.parent
_BASIC = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}
URL = "/api/runtime/scenarios"


def _declaration(name="role-change", username="alice", **after):
    return {
        "name": name,
        "given": {"user": {"username": username, "password": "alice-pw", "roles": ["USER"]}},
        "steps": [{"after": {"event": "token_issued", **after}, "update_user": {"roles": ["ADMIN"]}}],
    }


def _payload(result):
    return json.loads(result.content[0].text)


def _events(kind):
    return [entry for entry in get_audit_log().get_entries(limit=500) if entry["event_type"] == kind]


@pytest.fixture
def idp(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "_readonly_mode", False)
    monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document["runtime"] = {"store": "sqlite", "path": "../state/runtime.db"}
    settings.write_text(yaml.safe_dump(document))
    monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
    application = create_app(str(config_dir))
    application.config["TESTING"] = True
    assert get_runtime_store().shared
    return application.test_client()


def _authorities(http, username="alice"):
    response = http.post(
        "/token", data={"grant_type": "password", "username": username, "password": "alice-pw"}, headers=_BASIC
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return pyjwt.decode(response.get_json()["access_token"], options={"verify_signature": False})["authorities"]


class TestTheRoleChangeThroughMcp:
    async def test_armed_through_mcp_fired_by_the_server_and_read_back_through_mcp(self, idp, mcp_call_tool):
        armed = await mcp_call_tool("arm_scenario", _declaration())

        assert armed.is_error is not True
        assert _payload(armed) == {"success": True, "scenario": idp.get(f"{URL}/role-change").get_json()}
        assert _payload(armed)["scenario"]["state"] == "armed"

        assert _authorities(idp) == ["ROLE_USER"]
        assert _authorities(idp) == ["ROLE_ADMIN"]

        read = _payload(await mcp_call_tool("get_scenario", {"name": "role-change"}))
        assert read["found"] is True
        assert read["scenario"]["steps"][0] == {
            "after": {"event": "token_issued", "count": 1},
            "update_user": {"roles": ["ADMIN"]},
            "seen": 1,
            "state": "applied",
        }

    async def test_the_views_are_the_ones_of_the_http_surface(self, idp, mcp_call_tool):
        await mcp_call_tool("arm_scenario", _declaration())
        idp.post(URL, json=_declaration(name="over-http", username="bob"))

        listed = _payload(await mcp_call_tool("list_scenarios", {}))

        assert listed == idp.get(URL).get_json()
        assert [scenario["name"] for scenario in listed["scenarios"]] == ["role-change", "over-http"]

    async def test_a_scenario_that_is_not_there_is_an_answer_not_a_failure(self, idp, mcp_call_tool):
        result = await mcp_call_tool("get_scenario", {"name": "nope"})

        assert result.is_error is not True
        assert _payload(result) == {"found": False, "name": "nope"}

    async def test_removing_it_removes_its_user_and_says_so(self, idp, mcp_call_tool):
        await mcp_call_tool("arm_scenario", _declaration())

        removed = await mcp_call_tool("remove_scenario", {"name": "role-change"})

        assert _payload(removed) == {"success": True, "deleted": "role-change", "user": "alice", "user_removed": True}
        assert idp.get(f"{URL}/role-change").status_code == 404
        assert idp.get("/api/runtime/users/alice").status_code == 404

    async def test_the_reset_tool_removes_the_scenarios(self, idp, mcp_call_tool):
        await mcp_call_tool("arm_scenario", _declaration())

        reset = _payload(await mcp_call_tool("reset_runtime_identities", {}))

        assert reset["scenarios_removed"] == 1 and reset["users_deleted"] == 1
        assert _payload(await mcp_call_tool("list_scenarios", {})) == {"scenarios": [], "count": 0}


class TestTheRefusalsOfTheService:
    """Each with the kind and the text ``/api/runtime/scenarios`` answers."""

    async def _both(self, idp, mcp_call_tool, declaration):
        over_http = idp.post(URL, json=declaration).get_json()
        through_mcp = await mcp_call_tool("arm_scenario", declaration)
        assert through_mcp.is_error is True
        return over_http, _payload(through_mcp)

    async def test_a_scenario_of_that_name(self, idp, mcp_call_tool):
        idp.post(URL, json=_declaration())

        over_http, through_mcp = await self._both(idp, mcp_call_tool, _declaration(username="bob"))

        assert through_mcp == {"success": False, "error": over_http["error"], "kind": "exists"}
        assert idp.get("/api/runtime/users/bob").status_code == 404

    async def test_a_declared_user_of_that_name(self, idp, mcp_call_tool):
        over_http, through_mcp = await self._both(idp, mcp_call_tool, _declaration(username="admin"))

        assert through_mcp == {"success": False, "error": over_http["error"], "kind": "declared"}
        assert _payload(await mcp_call_tool("list_scenarios", {}))["count"] == 0

    async def test_what_only_the_parser_of_a_user_can_refuse(self, idp, mcp_call_tool):
        """The schema says what a field is; the rules between fields are
        the parser's, and its refusal is the tool's."""
        declaration = _declaration()
        declaration["given"]["user"]["email"] = "not-an-address"

        refused = await mcp_call_tool("arm_scenario", declaration)

        assert refused.is_error is True
        assert _payload(refused) == {
            "success": False,
            "error": idp.post(URL, json=declaration).get_json()["error"].replace("POST /api/runtime/scenarios", "arm_scenario"),
            "kind": "invalid",
        }
        assert "given.user: email: Invalid email format" in _payload(refused)["error"]
        assert idp.get(URL).get_json()["count"] == 0

    async def test_a_grant_type_that_is_only_for_another_event(self, idp, mcp_call_tool):
        declaration = _declaration()
        declaration["steps"][0]["after"] = {"event": "authorization_completed", "grant_type": "password"}

        refused = _payload(await mcp_call_tool("arm_scenario", declaration))

        assert refused["kind"] == "invalid" and "grant_type is only for token_issued" in refused["error"]

    async def test_a_scenario_that_is_not_there_cannot_be_removed(self, idp, mcp_call_tool):
        refused = await mcp_call_tool("remove_scenario", {"name": "nope"})

        assert refused.is_error is True
        assert _payload(refused) == {"success": False, "error": "no scenario 'nope'", "kind": "not_found"}

    async def test_a_user_a_promotion_holds_keeps_the_scenario(self, idp, mcp_call_tool):
        await mcp_call_tool("arm_scenario", _declaration())
        claim_for_promotion("user", "alice", "writing")

        refused = _payload(await mcp_call_tool("remove_scenario", {"name": "role-change"}))

        assert refused["kind"] == "promotion_in_progress"
        assert refused["error"] == idp.delete(f"{URL}/role-change").get_json()["error"]
        assert _payload(await mcp_call_tool("get_scenario", {"name": "role-change"}))["found"] is True


class TestTheAudit:
    async def test_the_events_of_the_http_surface_said_by_mcp(self, idp, mcp_call_tool):
        await mcp_call_tool("arm_scenario", _declaration())
        await mcp_call_tool("remove_scenario", {"name": "role-change"})

        (armed,) = _events("runtime_scenario_armed")
        (removed,) = _events("runtime_scenario_removed")
        assert (armed["endpoint"], armed["method"], armed["username"]) == ("mcp", "arm_scenario", "alice")
        assert armed["details"] == {"kind": "scenario", "name": "role-change"}
        assert (removed["endpoint"], removed["method"], removed["username"]) == ("mcp", "remove_scenario", "alice")
        assert removed["details"] == {"kind": "scenario", "name": "role-change", "user_removed": True}

    async def test_a_refusal_records_no_lifecycle_event(self, idp, mcp_call_tool):
        await mcp_call_tool("arm_scenario", _declaration(username="admin"))
        await mcp_call_tool("remove_scenario", {"name": "nope"})

        assert _events("runtime_scenario_armed") == [] and _events("runtime_scenario_removed") == []


class TestTheSchemaOfTheDeclaration:
    """The input schema of arm_scenario is the declaration's own model: an
    agent sees the fields, the names and the limits without the guide."""

    @pytest.fixture
    def schema(self):
        (tool,) = [tool for tool in _TOOLS if tool.name == "arm_scenario"]
        return tool.input_schema

    def _resolved(self, schema, fragment):
        while "$ref" in fragment:
            fragment = schema["$defs"][fragment["$ref"].rsplit("/", 1)[1]]
        return fragment

    def test_it_is_the_models(self, schema):
        assert schema == scenarios.ScenarioDeclaration.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_the_scenario_its_name_and_its_steps(self, schema):
        assert schema["required"] == ["name", "given", "steps"] and schema["additionalProperties"] is False
        assert schema["properties"]["name"]["pattern"] == r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
        steps = schema["properties"]["steps"]
        assert (steps["minItems"], steps["maxItems"]) == (1, scenarios.MAX_STEPS)
        step = self._resolved(schema, steps["items"])
        assert step["required"] == ["after", "update_user"] and step["additionalProperties"] is False

    def test_the_events_and_the_grant_types_are_enums(self, schema):
        after = self._resolved(schema, self._resolved(schema, schema["properties"]["steps"]["items"])["properties"]["after"])

        assert after["additionalProperties"] is False and after["required"] == ["event"]
        assert after["properties"]["event"]["enum"] == list(EVENTS)
        grant_type = after["properties"]["grant_type"]
        assert [option.get("enum") for option in grant_type["anyOf"]] == [list(USER_GRANT_TYPES), None]
        count = after["properties"]["count"]
        assert (count["type"], count["minimum"], count["default"]) == ("integer", 1, 1)

    def test_the_user_it_creates_has_the_fields_of_the_user_model(self, schema):
        user = self._resolved(schema, schema["properties"]["given"])["properties"]["user"]
        fields = User.model_json_schema()["properties"]

        assert user["type"] == "object" and user["required"] == ["username"]
        assert user["properties"] == fields
        assert user["properties"]["roles"] == {
            "description": "User roles", "items": {"type": "string"}, "title": "Roles", "type": "array"
        }
        assert user["properties"]["username"]["minLength"] == 1
        # Other keys are attributes, as in a users.yaml entry.
        assert user["additionalProperties"] is True

    def test_a_step_sets_the_fields_that_carry_authority_and_no_other(self, schema):
        step = self._resolved(schema, schema["properties"]["steps"]["items"])
        update = step["properties"]["update_user"]
        fields = User.model_json_schema()["properties"]

        assert sorted(update["properties"]) == sorted(scenarios.UPDATABLE)
        assert update["additionalProperties"] is False and update["minProperties"] == 1
        for name in scenarios.UPDATABLE:
            assert update["properties"][name] == {k: v for k, v in fields[name].items() if k != "default"}, name
        assert update["properties"]["attributes"]["type"] == "object"

    @pytest.mark.parametrize(
        "change, says",
        [
            (lambda d: d.update(extra=1), "Additional properties"),
            (lambda d: d.update(name=".."), "name"),
            (lambda d: d["given"]["user"].pop("username"), "'username' is a required property"),
            (lambda d: d["given"]["user"].update(roles="USER"), "given.user.roles"),
            (lambda d: d.update(steps=[]), "steps"),
            (lambda d: d["steps"][0]["after"].update(event="userinfo_read"), "steps.0.after.event"),
            (lambda d: d["steps"][0]["after"].update(grant_type="client_credentials"), "steps.0.after.grant_type"),
            (lambda d: d["steps"][0]["after"].update(count=0), "steps.0.after.count"),
            (lambda d: d["steps"][0]["after"].update(user="alice"), "Additional properties"),
            (lambda d: d["steps"][0].update(update_user={}), "steps.0.update_user"),
            (lambda d: d["steps"][0].update(update_user={"password": "x"}), "Additional properties"),
            (lambda d: d["steps"][0].update(update_user={"roles": "ADMIN"}), "steps.0.update_user.roles"),
        ],
    )
    async def test_what_the_schema_refuses_never_reaches_the_service(self, idp, mcp_call_tool, change, says):
        declaration = _declaration()
        change(declaration)

        refused = await mcp_call_tool("arm_scenario", declaration)

        assert refused.is_error is True
        assert _payload(refused)["code"] == "MCP_INVALID_ARGUMENTS" and says in _payload(refused)["error"]
        assert idp.get(URL).get_json()["count"] == 0
        # And the service refuses the same declaration, for a caller that
        # did not validate: the schema promises nothing the service does not.
        assert idp.post(URL, json=declaration).status_code == 400

    async def test_what_the_schema_accepts_the_service_arms(self, idp, mcp_call_tool):
        declaration = _declaration(grant_type="refresh_token", count=3)
        declaration["given"]["user"].update(
            email="a@ci.test", groups=["ops"], attributes={"team": "blue"}, legacy_attr="old", identity_class=None
        )
        declaration["steps"][0]["update_user"] = {
            "roles": ["ADMIN"], "groups": [], "entitlements": ["e1"], "source_acl": ["s1"],
            "identity_class": "INTERNAL", "attributes": {"team": "red"},
        }
        (tool,) = [tool for tool in _TOOLS if tool.name == "arm_scenario"]
        jsonschema.Draft202012Validator(tool.input_schema).validate(declaration)

        armed = await mcp_call_tool("arm_scenario", declaration)

        assert armed.is_error is not True and _payload(armed)["scenario"]["state"] == "armed"
        assert get_runtime_store().users.get("alice").attributes == {"team": "blue", "legacy_attr": "old"}

    def test_the_other_scenario_tools_take_a_name_or_nothing(self):
        by_name = {tool.name: tool.input_schema for tool in _TOOLS}

        assert by_name["get_scenario"] == by_name["remove_scenario"]
        assert by_name["get_scenario"]["required"] == ["name"]
        assert by_name["list_scenarios"]["properties"] == {}
