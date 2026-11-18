"""Runtime identities through MCP (#432): the lifecycle ``/api/runtime``
offers over HTTP, as tools.

The MCP server is a process of its own. Since a runtime store can be shared
between processes (#354), what a tool creates there is served by the
NanoIDP that shares it; with a store of its own, the tools refuse instead
of acting on a state nobody else can see. Same services, same rules, same
refusal kinds and views as the HTTP surface.
"""

import base64
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

import nanoidp.mcp_server as mcp
from nanoidp.app import create_app
from nanoidp.config import ConfigurationRejected
from nanoidp.config_documents import DocumentRejected
from nanoidp.config_writer import ConflictError, LockUnavailableError
from nanoidp.mcp_server import MUTATING_TOOLS, RUNTIME_STATE_TOOLS
from nanoidp.mcp_server.schemas import _TOOLS
from nanoidp.refusal_texts import RUNTIME_STORE_NOT_SHARED_TEXT
from nanoidp.services.audit import get_audit_log
from nanoidp.services.dynamic_registration import registrations
from nanoidp.services.identities import DeclaredNameCollision, IdentityResolver, PromotionInProgress
from nanoidp.services.runtime_store import get_runtime_store
from nanoidp.services.yaml_writer import PostWriteError

_REPO = Path(__file__).resolve().parent.parent
_BASIC = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}
_WRITING = {
    "create_runtime_user",
    "delete_runtime_user",
    "promote_runtime_user",
    "create_runtime_client",
    "delete_runtime_client",
    "promote_runtime_client",
    "reset_runtime_identities",
}
_READING = {"list_runtime_users", "get_runtime_user", "list_runtime_clients", "get_runtime_client"}
# Arguments that pass each tool's schema, for the checks made before a tool runs.
_VALID_ARGUMENTS = {
    "create_runtime_user": {"username": "rt-user", "password": "pw"},
    "list_runtime_users": {},
    "get_runtime_user": {"username": "rt-user"},
    "delete_runtime_user": {"username": "rt-user"},
    "promote_runtime_user": {"username": "rt-user"},
    "create_runtime_client": {"client_id": "rt-client", "client_secret": "s3cret"},
    "list_runtime_clients": {},
    "get_runtime_client": {"client_id": "rt-client"},
    "delete_runtime_client": {"client_id": "rt-client"},
    "promote_runtime_client": {"client_id": "rt-client"},
    "reset_runtime_identities": {},
}


def _config_dir(tmp_path, store="sqlite", dynamic_registration=False):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    if store == "sqlite":
        document["runtime"] = {"store": "sqlite", "path": "../state/runtime.db"}
    if dynamic_registration:
        document["oauth"]["dynamic_registration"] = {"enabled": True}
    settings.write_text(yaml.safe_dump(document))
    return config_dir


def _payload(result):
    return json.loads(result.content[0].text)


def _events(kind):
    return [entry for entry in get_audit_log().get_entries(limit=500) if entry["event_type"] == kind]


@pytest.fixture
def mcp_process(monkeypatch):
    monkeypatch.setattr(mcp, "_readonly_mode", False)
    monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)


@pytest.fixture
def idp(tmp_path, monkeypatch, mcp_process):
    """One process holding both surfaces over a SQLite store: the HTTP app
    and the MCP tools resolve the same configuration and the same store, so
    what one does the other is asked about."""
    config_dir = _config_dir(tmp_path, dynamic_registration=True)
    monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
    application = create_app(str(config_dir))
    application.config["TESTING"] = True
    assert get_runtime_store().shared
    return application.test_client(), config_dir


class TestTheSurface:
    def test_the_guarded_group_is_the_modules_own_table(self):
        """Derived, not listed again: a tool added to the module is inside
        the guard and, unless it only reads, a mutating tool."""
        from nanoidp.mcp_server.handlers_runtime import (
            RUNTIME_STATE_HANDLERS,
            RUNTIME_STATE_READERS,
        )

        assert RUNTIME_STATE_TOOLS == frozenset(RUNTIME_STATE_HANDLERS)
        assert RUNTIME_STATE_READERS == _READING
        assert {name: mcp._TOOL_HANDLERS[name] for name in RUNTIME_STATE_HANDLERS} == RUNTIME_STATE_HANDLERS

    def test_eleven_tools_about_the_runtime_state(self):
        names = {tool.name for tool in _TOOLS}

        assert RUNTIME_STATE_TOOLS == _WRITING | _READING
        assert RUNTIME_STATE_TOOLS <= names
        assert {name for name in names if "runtime" in name} == set(RUNTIME_STATE_TOOLS)
        assert len(names) == 37

    def test_the_ones_that_write_are_gated_like_every_mutating_tool(self):
        assert _WRITING <= MUTATING_TOOLS
        assert not (_READING & MUTATING_TOOLS)

    def test_every_one_says_what_store_it_needs(self):
        for tool in _TOOLS:
            if tool.name in RUNTIME_STATE_TOOLS:
                assert "runtime.store: sqlite" in tool.description
                assert "MCP_RUNTIME_STORE_NOT_SHARED" in tool.description


class TestUsers:
    async def test_one_created_through_mcp_is_served_and_authenticated_over_http(self, idp, mcp_call_tool):
        client, _ = idp

        result = await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw", "roles": ["QA"]})

        created = _payload(result)
        assert result.is_error is not True
        assert created["success"] is True
        served = client.get("/api/runtime/users/rt-user")
        assert served.status_code == 200
        assert created["user"] == served.get_json()
        assert created["user"]["origin"] == "runtime"
        assert "password" not in created["user"]
        token = client.post(
            "/token", data={"grant_type": "password", "username": "rt-user", "password": "pw"}, headers=_BASIC
        )
        assert token.status_code == 200

    async def test_one_created_over_http_is_served_by_the_tools(self, idp, mcp_call_tool):
        client, _ = idp
        made = client.post("/api/runtime/users", json={"username": "rt-http", "password": "pw"}).get_json()

        got = _payload(await mcp_call_tool("get_runtime_user", {"username": "rt-http"}))
        listed = _payload(await mcp_call_tool("list_runtime_users", {}))

        assert got == {"found": True, "user": made}
        assert listed == {"users": [made], "count": 1}

    async def test_one_deleted_through_mcp_is_gone_over_http(self, idp, mcp_call_tool):
        client, _ = idp
        client.post("/api/runtime/users", json={"username": "rt-http", "password": "pw"})

        deleted = _payload(await mcp_call_tool("delete_runtime_user", {"username": "rt-http"}))

        assert deleted == {"success": True, "deleted": "rt-http"}
        assert client.get("/api/runtime/users/rt-http").status_code == 404

    async def test_one_promoted_through_mcp_is_declared_and_said_once(self, idp, mcp_call_tool):
        client, config_dir = idp
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        promoted = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-user"}))

        assert promoted == {"success": True, "promoted": "rt-user", "file": "users.yaml"}
        assert "rt-user" in yaml.safe_load((config_dir / "users.yaml").read_text())["users"]
        assert client.get("/api/runtime/users/rt-user").status_code == 404
        assert client.get("/api/users/rt-user").status_code == 200
        said = _events("runtime_identity_promoted")
        assert [(entry["endpoint"], entry["method"]) for entry in said] == [("mcp", "promote_runtime_user")]
        assert _events("runtime_identity_removed_on_reload") == []


class TestClients:
    async def test_the_same_lifecycle(self, idp, mcp_call_tool):
        client, config_dir = idp

        created = _payload(
            await mcp_call_tool(
                "create_runtime_client",
                {"client_id": "rt-client", "client_secret": "s3cret", "redirect_uris": ["http://localhost:3000/cb"]},
            )
        )

        served = client.get("/api/runtime/clients/rt-client")
        assert created == {"success": True, "client": served.get_json()}
        assert "client_secret" not in created["client"]
        got = _payload(await mcp_call_tool("get_runtime_client", {"client_id": "rt-client"}))
        assert got == {"found": True, "client": served.get_json()}
        assert _payload(await mcp_call_tool("list_runtime_clients", {})) == client.get("/api/runtime/clients").get_json()

        promoted = _payload(await mcp_call_tool("promote_runtime_client", {"client_id": "rt-client"}))

        assert promoted == {"success": True, "promoted": "rt-client", "file": "settings.yaml"}
        declared = yaml.safe_load((config_dir / "settings.yaml").read_text())["oauth"]["clients"]
        assert "rt-client" in [entry["client_id"] for entry in declared]
        assert client.get("/api/runtime/clients/rt-client").status_code == 404
        said = _events("runtime_identity_promoted")
        assert [(entry["endpoint"], entry["method"]) for entry in said] == [("mcp", "promote_runtime_client")]

    async def test_a_registered_client_is_listed_as_such_and_deleted_with_its_record(self, idp, mcp_call_tool):
        client, _ = idp
        registered = client.post("/register", json={"redirect_uris": ["http://localhost:3000/cb"]}).get_json()
        client_id = registered["client_id"]

        listed = _payload(await mcp_call_tool("list_runtime_clients", {}))
        got = _payload(await mcp_call_tool("get_runtime_client", {"client_id": client_id}))

        assert [entry.get("source") for entry in listed["clients"]] == ["dcr"]
        assert got["client"]["source"] == "dcr"

        deleted = _payload(await mcp_call_tool("delete_runtime_client", {"client_id": client_id}))

        assert deleted == {"success": True, "deleted": client_id}
        assert registrations().list() == []


class TestReset:
    async def test_it_removes_what_the_server_holds_and_says_how_much(self, idp, mcp_call_tool):
        client, _ = idp
        client.post("/api/runtime/users", json={"username": "rt-one", "password": "pw"})
        client.post("/api/runtime/users", json={"username": "rt-two", "password": "pw"})
        client.post("/api/runtime/clients", json={"client_id": "rt-client", "client_secret": "s3cret"})

        reset = _payload(await mcp_call_tool("reset_runtime_identities", {}))

        assert reset == {"success": True, "users_deleted": 2, "clients_deleted": 1, "sessions_ended": 0}
        assert client.get("/api/runtime/users").get_json()["count"] == 0
        assert client.get("/api/runtime/clients").get_json()["count"] == 0
        assert reset == {"success": True, **client.delete("/api/runtime").get_json(), "users_deleted": 2, "clients_deleted": 1}

    async def test_it_ends_the_browser_sessions_too(self, idp, mcp_call_tool, monkeypatch):
        from nanoidp.services.authenticated_sessions import get_authenticated_session_store

        ended = []
        monkeypatch.setattr(type(get_authenticated_session_store()), "delete_all", lambda self: ended.append(1) or 3)

        reset = _payload(await mcp_call_tool("reset_runtime_identities", {}))

        assert ended == [1]
        assert reset["sessions_ended"] == 3


class TestRefusalsAreTheOnesOfTheHttpSurface:
    """Each refusal by its ``kind``, and the message the HTTP route gives."""

    async def _both(self, client, mcp_call_tool, tool, arguments, method, path, body=None):
        result = await mcp_call_tool(tool, arguments)
        answered = client.open(path, method=method, json=body)
        return result, _payload(result), answered

    @pytest.mark.parametrize(
        "tool, arguments, method, path, body, kind",
        [
            ("create_runtime_user", {"username": "admin", "password": "pw"}, "POST", "/api/runtime/users",
             {"username": "admin", "password": "pw"}, "declared"),
            ("create_runtime_user", {"username": "taken", "password": "pw"}, "POST", "/api/runtime/users",
             {"username": "taken", "password": "pw"}, "exists"),
            ("create_runtime_user", {"username": "rt-x", "totp_secret": "not base32!"}, "POST", "/api/runtime/users",
             {"username": "rt-x", "totp_secret": "not base32!"}, "invalid"),
            ("delete_runtime_user", {"username": "nobody"}, "DELETE", "/api/runtime/users/nobody", None, "not_found"),
            ("promote_runtime_user", {"username": "nobody"}, "POST", "/api/runtime/users/nobody/promote", None, "not_found"),
            ("create_runtime_client", {"client_id": "demo-client", "client_secret": "s"}, "POST", "/api/runtime/clients",
             {"client_id": "demo-client", "client_secret": "s"}, "declared"),
            ("create_runtime_client", {"client_id": "rt-c"}, "POST", "/api/runtime/clients",
             {"client_id": "rt-c"}, "invalid"),
            ("delete_runtime_client", {"client_id": "nobody"}, "DELETE", "/api/runtime/clients/nobody", None, "not_found"),
            ("promote_runtime_client", {"client_id": "nobody"}, "POST", "/api/runtime/clients/nobody/promote", None, "not_found"),
        ],
        ids=lambda value: value if isinstance(value, str) and "_" in value and "/" not in value else None,
    )
    async def test_the_same_kind_and_the_same_words(self, idp, mcp_call_tool, tool, arguments, method, path, body, kind):
        client, _ = idp
        client.post("/api/runtime/users", json={"username": "taken", "password": "pw"})

        result, refused, answered = await self._both(client, mcp_call_tool, tool, arguments, method, path, body)

        assert result.is_error is True
        assert refused["success"] is False
        assert refused["kind"] == kind == answered.get_json()["kind"]
        # An invalid entry names where it came from, which differs: the
        # tool here, the request there. The rest is the parser's sentence.
        said_over_http = answered.get_json()["error"].replace(f"{method} {path}: ", f"{tool}: ")
        assert refused["error"] == said_over_http
        assert "retryable" not in refused

    async def test_an_invalid_entry_says_what_is_wrong_with_it(self, idp, mcp_call_tool):
        refused = _payload(await mcp_call_tool("create_runtime_user", {"username": "rt-x", "totp_secret": "not base32!"}))

        assert refused == {
            "success": False,
            "error": "create_runtime_user: totp_secret: totp_secret is not valid Base32",
            "kind": "invalid",
        }

    async def test_a_lock_another_write_holds_is_worth_a_retry(self, idp, mcp_call_tool, monkeypatch):
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        def held(self, username, context):
            raise LockUnavailableError("held by a peer", kind="lock_timeout")

        monkeypatch.setattr(IdentityResolver, "promote_runtime_user", held)

        refused = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-user"}))

        assert (refused["success"], refused["kind"], refused["retryable"]) == (False, "lock_unavailable", True)
        assert refused["error"] == "users.yaml is locked by another write; try again"

    async def test_a_lock_this_filesystem_cannot_give_is_not(self, idp, mcp_call_tool, monkeypatch):
        """Whether coming back helps is the lock's own answer (#477), not
        the same for every lock."""
        client, _ = idp
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        def unsupported(self, username, context):
            raise LockUnavailableError("no advisory locks on /mnt/share", kind="lock_unsupported")

        monkeypatch.setattr(IdentityResolver, "promote_runtime_user", unsupported)

        refused = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-user"}))
        over_http = client.post("/api/runtime/users/rt-user/promote")

        assert (refused["kind"], refused["retryable"]) == ("lock_unavailable", False)
        assert refused["error"] == "the lock of users.yaml cannot be taken; nothing was written"
        assert "try again" not in refused["error"]
        assert (over_http.status_code, over_http.get_json()["error"]) == (503, refused["error"])

    async def test_what_stopped_a_write_stays_in_the_log(self, idp, mcp_call_tool, monkeypatch, caplog):
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        def failing(self, username, context):
            raise OSError(5, "the disk said /secret/path")

        monkeypatch.setattr(IdentityResolver, "promote_runtime_user", failing)

        refused = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-user"}))

        assert refused == {"success": False, "error": "'rt-user' could not be written to users.yaml", "kind": "write_failed"}
        assert "/secret/path" in caplog.text


class TestALookupThatFindsNothingIsAnAnswer:
    async def test_it_is_not_a_failed_call(self, idp, mcp_call_tool):
        """As get_user answers: ``found: false``, no ``error``, not flagged."""
        for tool, arguments in (
            ("get_runtime_user", {"username": "nobody"}),
            ("get_runtime_client", {"client_id": "nobody"}),
        ):
            result = await mcp_call_tool(tool, arguments)

            assert result.is_error is not True
            assert _payload(result) == {"found": False, **arguments}


class TestAnEntryIsTheParsersToJudge:
    """The schema of a creation constrains the name. Every other field is
    accepted in every form the YAML file accepts, as over HTTP."""

    async def test_a_scalar_where_a_list_is_usual(self, idp, mcp_call_tool):
        client, _ = idp
        entry = {"client_id": "rt-client", "client_secret": "s3cret", "redirect_uris": "http://localhost:3000/cb"}

        created = _payload(await mcp_call_tool("create_runtime_client", entry))

        assert created["success"] is True
        assert created["client"]["redirect_uris"] == ["http://localhost:3000/cb"]
        assert client.post("/api/runtime/clients", json={**entry, "client_id": "rt-http"}).status_code == 201

    async def test_a_persona_only_user_has_no_password(self, idp, mcp_call_tool):
        created = _payload(await mcp_call_tool("create_runtime_user", {"username": "rt-persona", "password": None}))

        assert created["success"] is True

    async def test_the_name_is_still_the_schemas(self, idp, mcp_call_tool):
        for tool, arguments in (("create_runtime_user", {"password": "pw"}), ("create_runtime_client", {"client_id": ""})):
            refused = _payload(await mcp_call_tool(tool, arguments))

            assert refused["code"] == "MCP_INVALID_ARGUMENTS"


class TestTheAdminSecretIsNeverPartOfAnEntry:
    async def test_given_where_none_is_configured_it_is_not_stored(self, idp, mcp_call_tool):
        """A caller that always sends the secret, to a process that has
        none configured: nothing checks it, and nothing keeps it."""
        client, _ = idp

        created = _payload(
            await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw", "admin_secret": "hunter2"})
        )
        made = _payload(
            await mcp_call_tool(
                "create_runtime_client", {"client_id": "rt-client", "client_secret": "s3cret", "admin_secret": "hunter2"}
            )
        )

        assert created["success"] is True
        assert made["success"] is True
        stored = get_runtime_store().users.get("rt-user")
        assert "admin_secret" not in stored.attributes
        assert "hunter2" not in stored.model_dump_json()
        token = client.post(
            "/token", data={"grant_type": "password", "username": "rt-user", "password": "pw"}, headers=_BASIC
        )
        assert "hunter2" not in base64.urlsafe_b64decode(token.get_json()["access_token"].split(".")[1] + "==").decode()


class TestWhatIsNotTheOperationsToAnswerFor:
    async def test_a_directory_lock_held_while_a_name_is_checked(self, idp, mcp_call_tool, monkeypatch):
        """Creating a runtime identity over a shared store checks the name
        against the files under the directory's lock. One held by a peer
        is the configuration's answer, with the lock's own retryability,
        not an internal error with the lock's path in it."""

        def held(self, user):
            raise LockUnavailableError("could not lock /srv/config/.nanoidp.lock", kind="lock_timeout")

        monkeypatch.setattr(IdentityResolver, "create_runtime_user", held)

        result = await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        refused = _payload(result)
        assert result.is_error is True
        assert (refused["code"], refused["retryable"]) == ("MCP_CONFIGURATION_UNAVAILABLE", True)
        assert "/srv/config" not in refused["error"]

    async def test_a_store_held_during_a_promotion_is_said_as_the_store(self, idp, mcp_call_tool, monkeypatch):
        """Not as a write that failed: the store's answer is the same
        wherever it is met, and it is worth a retry."""
        from nanoidp.services.runtime_repository import RuntimeStoreUnavailable

        client, _ = idp
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        def held(self, username, context):
            raise RuntimeStoreUnavailable("database is locked")

        monkeypatch.setattr(IdentityResolver, "promote_runtime_user", held)

        refused = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-user"}))
        over_http = client.post("/api/runtime/users/rt-user/promote")

        assert (refused["code"], refused["retryable"]) == ("MCP_RUNTIME_STORE_UNAVAILABLE", True)
        assert over_http.status_code == 503
        assert over_http.get_json().get("kind") != "write_failed"


class TestEachRefusalOfAPromotionOnBothSurfaces:
    """What a promotion can be refused for, raised where the writer raises
    it: one ``kind`` for both surfaces, and the status HTTP gives it."""

    @pytest.mark.parametrize(
        "raised, kind, status, retryable",
        [
            (lambda: DocumentRejected("users.yaml: invalid value at users.rt-user"), "unloadable", 422, False),
            (lambda: ConflictError("moved", kind="conflict"), "conflict", 409, False),
            (lambda: LockUnavailableError("held by a peer", kind="lock_timeout"), "lock_unavailable", 503, True),
            (lambda: PromotionInProgress("already"), "promotion_in_progress", 409, False),
            (lambda: DeclaredNameCollision("declared"), "declared", 409, False),
            (lambda: PostWriteError("after the write"), "reload_failed", 500, False),
            (lambda: ConfigurationRejected("does not load", kind="invalid"), "reload_failed", 500, False),
            (lambda: OSError(5, "the disk"), "write_failed", 500, False),
        ],
        ids=["unloadable", "conflict", "lock", "in-progress", "declared", "post-write", "rejected", "write-failed"],
    )
    async def test_one_kind_and_its_http_status(self, idp, mcp_call_tool, monkeypatch, raised, kind, status, retryable):
        client, _ = idp
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        def refusing(self, username, context):
            raise raised()

        monkeypatch.setattr(IdentityResolver, "promote_runtime_user", refusing)

        by_tool = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-user"}))
        over_http = client.post("/api/runtime/users/rt-user/promote")

        assert over_http.status_code == status
        assert over_http.get_json()["kind"] == kind == by_tool["kind"]
        assert over_http.get_json()["error"] == by_tool["error"]
        assert by_tool.get("retryable", False) is retryable


class TestTheAuditOfTheToolsThatWrite:
    async def test_the_events_of_the_http_surface_said_by_mcp(self, idp, mcp_call_tool):
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})
        await mcp_call_tool("create_runtime_client", {"client_id": "rt-client", "client_secret": "s3cret"})
        await mcp_call_tool("delete_runtime_user", {"username": "rt-user"})
        await mcp_call_tool("reset_runtime_identities", {})

        def said(kind):
            return [(e["endpoint"], e["method"], e["details"].get("name")) for e in _events(kind)]

        assert sorted(said("runtime_identity_created")) == [
            ("mcp", "create_runtime_client", "rt-client"),
            ("mcp", "create_runtime_user", "rt-user"),
        ]
        assert said("runtime_identity_deleted") == [("mcp", "delete_runtime_user", "rt-user")]
        reset = _events("runtime_identities_reset")
        assert [(e["endpoint"], e["method"]) for e in reset] == [("mcp", "reset_runtime_identities")]
        assert reset[0]["details"] == {"users_deleted": 0, "clients_deleted": 1, "sessions_ended": 0}

    async def test_a_refusal_records_no_lifecycle_event(self, idp, mcp_call_tool):
        await mcp_call_tool("create_runtime_user", {"username": "admin", "password": "pw"})
        await mcp_call_tool("delete_runtime_user", {"username": "nobody"})

        assert _events("runtime_identity_created") == []
        assert _events("runtime_identity_deleted") == []


class TestTheToolsOfTheDeclaredConfigurationStayOnIt:
    async def test_a_runtime_user_is_not_theirs(self, idp, mcp_call_tool):
        """Stated in the reference: list_users, get_user and generate_token
        answer from the declared configuration, with either store."""
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})

        listed = _payload(await mcp_call_tool("list_users", {}))
        got = _payload(await mcp_call_tool("get_user", {"username": "rt-user"}))
        token = _payload(await mcp_call_tool("generate_token", {"username": "rt-user"}))

        assert "rt-user" not in [user["username"] for user in listed["users"]]
        assert got["found"] is False
        assert token["success"] is False


class TestAStoreOfThisProcessAlone:
    @pytest.fixture
    def alone(self, tmp_path, monkeypatch, mcp_process):
        config_dir = _config_dir(tmp_path, store="memory")
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
        return config_dir

    @pytest.mark.parametrize("tool", sorted(_VALID_ARGUMENTS))
    async def test_every_tool_of_the_group_refuses_and_says_why(self, alone, mcp_call_tool, monkeypatch, tool):
        ran = []

        async def must_not_run(*args, **kwargs):
            ran.append(args[0])
            return {}

        monkeypatch.setattr(mcp, "_execute_tool", must_not_run)

        result = await mcp_call_tool(tool, _VALID_ARGUMENTS[tool])

        refused = _payload(result)
        assert result.is_error is True
        assert refused == {
            "error": RUNTIME_STORE_NOT_SHARED_TEXT,
            "code": "MCP_RUNTIME_STORE_NOT_SHARED",
            "tool": tool,
            "retryable": False,
        }
        assert "runtime.store: sqlite" in refused["error"]
        assert ran == []

    async def test_nothing_is_created_in_the_store_nobody_else_sees(self, alone, mcp_call_tool):
        await mcp_call_tool("create_runtime_user", {"username": "rt-user", "password": "pw"})
        await mcp_call_tool("create_runtime_client", {"client_id": "rt-client", "client_secret": "s3cret"})

        store = get_runtime_store()
        assert not store.shared
        assert store.users.list() == []
        assert store.clients.entries() == []

    async def test_the_other_tools_are_not_touched_by_the_guard(self, alone, mcp_call_tool):
        listed = await mcp_call_tool("list_users", {})

        assert listed.is_error is not True
        assert _payload(listed)["count"] > 0


class TestTheGatesComeFirst:
    @pytest.mark.parametrize("tool", sorted(_WRITING))
    async def test_read_only_mode_disables_the_ones_that_write(self, idp, mcp_call_tool, monkeypatch, tool):
        monkeypatch.setattr(mcp, "_readonly_mode", True)

        refused = _payload(await mcp_call_tool(tool, _VALID_ARGUMENTS[tool]))

        assert refused["code"] == "MCP_READONLY_MODE"

    @pytest.mark.parametrize("tool", sorted(_READING))
    async def test_read_only_mode_leaves_the_ones_that_read(self, idp, mcp_call_tool, monkeypatch, tool):
        monkeypatch.setattr(mcp, "_readonly_mode", True)

        answered = _payload(await mcp_call_tool(tool, _VALID_ARGUMENTS[tool]))

        assert answered.get("code") != "MCP_READONLY_MODE"

    @pytest.mark.parametrize("tool", sorted(_WRITING))
    async def test_a_management_secret_is_asked_of_the_ones_that_write(self, tmp_path, monkeypatch, mcp_process, mcp_call_tool, tool):
        config_dir = _config_dir(tmp_path)
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document.setdefault("session", {})["management_secret"] = "the-secret"
        settings.write_text(yaml.safe_dump(document))
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))

        without = _payload(await mcp_call_tool(tool, _VALID_ARGUMENTS[tool]))
        with_it = _payload(await mcp_call_tool(tool, {**_VALID_ARGUMENTS[tool], "admin_secret": "the-secret"}))

        assert without["code"] == "MCP_ADMIN_SECRET_REQUIRED"
        assert with_it.get("code") != "MCP_ADMIN_SECRET_REQUIRED"


# ---- two processes -----------------------------------------------------------


def _free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _http(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    request = urllib.request.Request(url, method=method, data=data, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status, json.loads(answer.read() or b"{}")
    except urllib.error.HTTPError as refused:
        return refused.code, json.loads(refused.read() or b"{}")


@pytest.fixture
def server(tmp_path, monkeypatch, mcp_process):
    """A real NanoIDP in a process of its own, and this process composed as
    ``nanoidp-mcp`` over the same configuration directory and store."""
    config_dir = _config_dir(tmp_path)
    port = _free_port()
    log = open(tmp_path / "server.log", "w")
    process = subprocess.Popen(
        [sys.executable, "-m", "nanoidp", "--config", str(config_dir), "--port", str(port)],
        env=dict(os.environ, PYTHONPATH=str(_REPO / "src")),
        stdout=log,
        stderr=log,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                urllib.request.urlopen(f"{base}/api/health", timeout=1)
                break
            except OSError:
                assert process.poll() is None and time.monotonic() < deadline, "the server did not start"
                time.sleep(0.1)
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
        yield base, config_dir
    finally:
        process.terminate()
        process.wait(30)
        log.close()


class TestAServerAndAnMcpServerOverOneStore:
    """The acceptance of #432, each check both ways round."""

    async def test_what_one_creates_the_other_serves(self, server, mcp_call_tool):
        base, _ = server
        assert _http("POST", f"{base}/api/runtime/users", {"username": "rt-rest", "password": "pw"})[0] == 201

        by_tool = _payload(await mcp_call_tool("get_runtime_user", {"username": "rt-rest"}))
        created = _payload(await mcp_call_tool("create_runtime_user", {"username": "rt-mcp", "password": "pw"}))

        assert by_tool["user"]["username"] == "rt-rest"
        status, served = _http("GET", f"{base}/api/runtime/users/rt-mcp")
        assert (status, served) == (200, created["user"])
        token = urllib.request.Request(
            f"{base}/token", data=b"grant_type=password&username=rt-mcp&password=pw", headers=_BASIC
        )
        with urllib.request.urlopen(token, timeout=10) as issued:
            assert "access_token" in json.loads(issued.read())

    async def test_what_one_deletes_is_gone_for_the_other(self, server, mcp_call_tool):
        base, _ = server
        _http("POST", f"{base}/api/runtime/users", {"username": "rt-rest", "password": "pw"})
        await mcp_call_tool("create_runtime_user", {"username": "rt-mcp", "password": "pw"})

        deleted = _payload(await mcp_call_tool("delete_runtime_user", {"username": "rt-rest"}))
        assert _http("DELETE", f"{base}/api/runtime/users/rt-mcp")[0] == 200

        assert deleted["success"] is True
        assert _http("GET", f"{base}/api/runtime/users/rt-rest")[0] == 404
        assert _payload(await mcp_call_tool("get_runtime_user", {"username": "rt-mcp"}))["found"] is False

    async def test_a_promotion_through_mcp_is_declared_for_the_server_and_said_once(self, server, mcp_call_tool):
        base, _ = server
        await mcp_call_tool("create_runtime_user", {"username": "rt-mcp", "password": "pw"})

        promoted = _payload(await mcp_call_tool("promote_runtime_user", {"username": "rt-mcp"}))

        assert promoted["success"] is True
        assert _http("GET", f"{base}/api/runtime/users/rt-mcp")[0] == 404
        assert _http("GET", f"{base}/api/users/rt-mcp")[0] == 200
        entries = _http("GET", f"{base}/api/audit?limit=200")[1]["entries"]
        said = [(e["endpoint"], e["method"]) for e in entries if e["event_type"] == "runtime_identity_promoted"]
        assert said == [("mcp", "promote_runtime_user")]
        assert [e for e in entries if e["event_type"] == "runtime_identity_removed_on_reload"] == []

    async def test_a_promotion_over_http_is_declared_for_the_tools(self, server, mcp_call_tool):
        base, _ = server
        _http("POST", f"{base}/api/runtime/users", {"username": "rt-rest", "password": "pw"})

        assert _http("POST", f"{base}/api/runtime/users/rt-rest/promote")[0] == 200

        assert _payload(await mcp_call_tool("get_runtime_user", {"username": "rt-rest"}))["found"] is False
        assert _payload(await mcp_call_tool("get_user", {"username": "rt-rest"}))["found"] is True

    async def test_a_reset_by_one_is_seen_by_the_other(self, server, mcp_call_tool):
        base, _ = server
        _http("POST", f"{base}/api/runtime/users", {"username": "rt-rest", "password": "pw"})

        reset = _payload(await mcp_call_tool("reset_runtime_identities", {}))

        assert reset["users_deleted"] == 1
        assert _http("GET", f"{base}/api/runtime/users")[1]["count"] == 0

        await mcp_call_tool("create_runtime_user", {"username": "rt-mcp", "password": "pw"})
        assert _http("DELETE", f"{base}/api/runtime")[1]["users_deleted"] == 1
        assert _payload(await mcp_call_tool("list_runtime_users", {})) == {"users": [], "count": 0}


class TestASaveWhoseReloadDidNotComplete:
    """``save_config`` writes the files and reloads them. The reload
    reconciles the runtime identities, so a save that declares a name a
    runtime identity has needs the store; held by another writer past its
    wait, the reload fails after the files are written (#426, point 7).
    Measured before: ``reload_after_save`` with the configuration
    directory and SQLite's own words in the error, and no ``retryable``."""

    @pytest.fixture
    def a_short_wait(self, monkeypatch):
        """Before the store is opened: a connection is given its wait
        when it is made."""
        from nanoidp.services import sqlite_runtime_store

        monkeypatch.setattr(sqlite_runtime_store, "_BUSY_TIMEOUT_MS", 300)

    @pytest.fixture
    def held(self, a_short_wait, idp, tmp_path):
        import sqlite3

        _, config_dir = idp
        other = sqlite3.connect(str(tmp_path / "state" / "runtime.db"), isolation_level=None)

        def hold():
            other.execute("BEGIN IMMEDIATE")

        def release():
            other.execute("ROLLBACK")

        yield config_dir, hold, release
        other.close()

    async def test_the_answer_is_fixed_and_says_what_to_do_next(self, held, mcp_call_tool, caplog):
        from nanoidp.refusal_texts import SAVE_RELOAD_INCOMPLETE_TEXT

        config_dir, hold, release = held
        assert _payload(await mcp_call_tool("create_runtime_user", {"username": "collide", "password": "pw"}))["success"]
        assert _payload(await mcp_call_tool("create_user", {"username": "collide", "password": "pw"}))["success"]
        hold()
        try:
            with caplog.at_level(logging.ERROR):
                result = await mcp_call_tool("save_config", {})
            answer = _payload(result)

            assert result.is_error is True
            assert answer == {
                "success": False,
                "error": SAVE_RELOAD_INCOMPLETE_TEXT,
                "kind": "reload_after_save",
                "retryable": False,
            }
            assert "reload_config" in answer["error"]
            text = result.content[0].text
            assert str(config_dir) not in text and "database is locked" not in text
            # The files are written, which is what retryable false is about.
            declared = yaml.safe_load((config_dir / "users.yaml").read_text())["users"]
            assert "collide" in declared
            # What stood in the way is in the log.
            assert "the runtime failed to reload it" in caplog.text and "held by another" in caplog.text

            # The step the answer names, while the store is still held: its
            # own refusal, which does invite a retry.
            still = _payload(await mcp_call_tool("reload_config", {}))
            assert still["code"] == "MCP_RUNTIME_STORE_UNAVAILABLE" and still["retryable"] is True
            assert [user["username"] for user in _payload(await mcp_call_tool("list_runtime_users", {}))["users"]] == ["collide"]
        finally:
            release()

        # And once it is free, it completes the operation: the runtime
        # identity gives way to the declared one.
        reloaded = _payload(await mcp_call_tool("reload_config", {}))

        assert reloaded["success"] is True
        assert _payload(await mcp_call_tool("list_runtime_users", {}))["users"] == []
        declared = _payload(await mcp_call_tool("get_user", {"username": "collide"}))
        assert declared["found"] is True and declared["user"]["username"] == "collide"
        assert len(_events("runtime_identity_removed_on_reload")) == 1

    async def test_a_save_with_nothing_to_reconcile_does_not_need_the_store(self, held, mcp_call_tool):
        _, hold, release = held
        hold()
        try:
            answer = _payload(await mcp_call_tool("save_config", {}))
        finally:
            release()

        assert answer["success"] is True
