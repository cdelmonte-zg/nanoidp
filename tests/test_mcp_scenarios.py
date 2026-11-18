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
from nanoidp.mcp_server.field_schemas import field_shape
from nanoidp.mcp_server.schemas import _TOOLS
from nanoidp.services import scenarios
from nanoidp.services.audit import get_audit_log
from nanoidp.services.protocol_events import (
    AUTHORIZATION_COMPLETED,
    EVENTS,
    TOKEN_ISSUED,
    USER_GRANT_TYPES,
)
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
    """The input schema of arm_scenario: the declaration's own model for
    what is the scenario's, the user model's field shapes for the user. An
    agent sees the fields, the names and the limits without the guide."""

    @pytest.fixture
    def schema(self):
        (tool,) = [tool for tool in _TOOLS if tool.name == "arm_scenario"]
        return tool.input_schema

    def test_it_is_flat_like_the_schema_of_every_other_tool(self, schema):
        """No definition to resolve, no null branch, none of the titles and
        docstrings pydantic would publish: what a host that does not follow
        local references still reads whole."""
        jsonschema.Draft202012Validator.check_schema(schema)
        text = json.dumps(schema)

        assert "$ref" not in text and "$defs" not in text and "anyOf" not in text
        assert '"title"' not in text and "description" not in schema
        for tool in _TOOLS:
            assert "$ref" not in json.dumps(tool.input_schema), tool.name

    def test_what_is_the_scenarios_comes_from_its_model(self, schema):
        model = scenarios.ScenarioDeclaration.model_json_schema()

        assert schema["required"] == model["required"] == ["name", "given", "steps"]
        assert schema["additionalProperties"] is False
        assert schema["properties"]["name"]["pattern"] == model["properties"]["name"]["pattern"]
        assert schema["properties"]["name"]["pattern"] == r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
        steps = schema["properties"]["steps"]
        assert (steps["minItems"], steps["maxItems"]) == (1, scenarios.MAX_STEPS)
        assert steps["items"]["required"] == ["after", "update_user"] and steps["items"]["additionalProperties"] is False
        assert schema["properties"]["given"]["required"] == ["user"]
        assert schema["properties"]["given"]["additionalProperties"] is False

    def test_the_events_and_the_grant_types_are_enums(self, schema):
        after = schema["properties"]["steps"]["items"]["properties"]["after"]

        assert after["additionalProperties"] is False and after["required"] == ["event"]
        assert after["properties"]["event"]["enum"] == [TOKEN_ISSUED, AUTHORIZATION_COMPLETED]
        assert after["properties"]["grant_type"]["enum"] == list(USER_GRANT_TYPES)
        assert after["properties"]["grant_type"]["type"] == "string"
        count = after["properties"]["count"]
        assert (count["type"], count["minimum"], count["default"]) == ("integer", 1, 1)

    def test_the_names_a_step_may_declare_are_the_ones_the_protocol_emits(self):
        """The enum is a type and the emitted names are constants: this is
        what holds them together."""
        assert EVENTS == (TOKEN_ISSUED, AUTHORIZATION_COMPLETED)

    def test_the_user_it_creates_has_the_shapes_of_the_user_model(self, schema):
        user = schema["properties"]["given"]["properties"]["user"]

        assert user["type"] == "object" and user["required"] == ["username"]
        assert sorted(user["properties"]) == sorted(User.model_fields)
        for name in User.model_fields:
            shape = {key: value for key, value in user["properties"][name].items() if key != "description"}
            assert shape == field_shape(User, name), name
            assert user["properties"][name]["description"], name
        assert user["properties"]["roles"]["type"] == "array" and user["properties"]["roles"]["items"] == {"type": "string"}
        assert user["properties"]["username"]["minLength"] == 1
        # Other keys are attributes, as in a users.yaml entry.
        assert user["additionalProperties"] is True

    def test_the_defaults_it_states_are_the_ones_the_parser_gives(self, schema, idp):
        user = schema["properties"]["given"]["properties"]["user"]["properties"]
        _, made = scenarios.scenario_from(
            {
                "name": "defaults",
                "given": {"user": {"username": "newcomer", "password": "pw"}},
                "steps": [{"after": {"event": "token_issued"}, "update_user": {"roles": []}}],
            },
            "test",
        )

        assert (made.email, made.roles, made.tenant) == ("newcomer@example.org", ["USER"], "default")
        assert "<username>@example.org" in user["email"]["description"]
        assert "['USER']" in user["roles"]["description"]
        assert "'default'" in user["tenant"]["description"]
        assert "default" not in json.dumps({name: {k: v for k, v in p.items() if k != "description"} for name, p in user.items()})

    def test_a_step_sets_the_fields_that_carry_authority_and_no_other(self, schema):
        update = schema["properties"]["steps"]["items"]["properties"]["update_user"]

        assert sorted(update["properties"]) == sorted(scenarios.UPDATABLE)
        assert update["additionalProperties"] is False and update["minProperties"] == 1
        for name in scenarios.UPDATABLE:
            shape = {key: value for key, value in update["properties"][name].items() if key != "description"}
            assert shape == field_shape(User, name), name
        assert update["properties"]["attributes"]["type"] == "object"

    def test_it_takes_the_management_secret_and_no_other_key(self, schema):
        """The declaration takes no key of its own, and a client that builds
        its arguments from the schema has to be able to send the secret."""
        validator = jsonschema.Draft202012Validator(schema)

        assert schema["properties"]["admin_secret"]["type"] == "string"
        assert list(validator.iter_errors({**_declaration(), "admin_secret": "the-secret"})) == []
        assert [error.message for error in validator.iter_errors({**_declaration(), "other": 1})] == [
            "Additional properties are not allowed ('other' was unexpected)"
        ]

    @pytest.mark.parametrize(
        "user",
        [
            ["alice", "hunter2-in-a-list"],
            '{"username": "alice", "password": "hunter2-in-a-string"}',
            {"username": "alice", "password": 20261118},
            {"username": "alice", "password": "pw", "totp_secret": 20261119},
        ],
    )
    async def test_a_mistyped_user_is_refused_without_its_secrets_in_the_answer(self, idp, mcp_call_tool, user):
        declaration = _declaration()
        declaration["given"]["user"] = user

        refused = await mcp_call_tool("arm_scenario", declaration)

        assert refused.is_error is True
        text = refused.content[0].text
        assert "hunter2" not in text and "20261118" not in text and "20261119" not in text
        assert "given.user" in text
        assert idp.get(URL).get_json()["count"] == 0

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

    async def test_no_tool_repeats_a_value_of_the_wrong_type(self, idp, mcp_call_tool):
        """The rule is the dispatcher's, for every tool: a password sent
        as a number to create_user is not said back either."""
        refused = await mcp_call_tool("create_user", {"username": "typo", "password": 20261120})

        assert _payload(refused) == {
            "error": "Input validation error: password: the value is not of type 'string'",
            "code": "MCP_INVALID_ARGUMENTS",
            "tool": "create_user",
        }

    async def test_a_value_of_the_right_type_is_still_named_in_its_refusal(self, idp, mcp_call_tool):
        declaration = _declaration()
        declaration["steps"][0]["after"]["event"] = "userinfo_read"

        refused = _payload(await mcp_call_tool("arm_scenario", declaration))

        assert refused["error"].startswith("Input validation error: steps.0.after.event: 'userinfo_read' is not one of")

    async def test_what_the_schema_accepts_the_service_arms(self, idp, mcp_call_tool):
        declaration = _declaration(grant_type="refresh_token", count=3)
        declaration["given"]["user"].update(
            email="a@ci.test", groups=["ops"], attributes={"team": "blue"}, legacy_attr="old", identity_class="EXTERNAL"
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
