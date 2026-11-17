"""The step after a load belongs to the process composition, the server's
and the MCP server's alike (#432).

After every successful load the runtime identities are reconciled with what
the configuration now declares, and the registration records of the clients
that went are swept. That step was wired in ``create_app`` only. A process
built as ``nanoidp-mcp`` builds itself loaded without it: over a store
shared with a server, an object it promoted was not retired by its own
reload, and the server's next load removed it as a collision, so the audit
said ``runtime_identity_removed_on_reload`` where a promotion had happened.
"""

import multiprocessing
import shutil
import time
from pathlib import Path

import pytest
import yaml

import nanoidp.mcp_server as mcp
from nanoidp.app import create_app
from nanoidp.config import User, get_config
from nanoidp.services.activation import after_load_services
from nanoidp.services.audit import get_audit_log
from nanoidp.services.dynamic_registration import registrations
from nanoidp.services.identities import identities_for
from nanoidp.services.runtime_store import fresh_configuration, get_runtime_store

_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"
_SPAWN = multiprocessing.get_context("spawn")
_BOUND = 30
MCP_CONTEXT = {"endpoint": "mcp", "method": "promote_runtime_user", "ip_address": "mcp", "user_agent": "mcp"}


def _config_dir(tmp_path, shared_store=False):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    if shared_store:
        document["runtime"] = {"store": "sqlite", "path": "../state/runtime.db"}
    settings.write_text(yaml.safe_dump(document))
    return config_dir


def _events(kind):
    return [entry for entry in get_audit_log().get_entries(limit=500) if entry["event_type"] == kind]


@pytest.fixture
def as_nanoidp_mcp(tmp_path, monkeypatch):
    """This process, composed as ``nanoidp-mcp`` composes itself: nothing
    loaded yet, the configuration directory in the environment."""

    def compose(shared_store=False):
        config_dir = _config_dir(tmp_path, shared_store)
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
        return config_dir

    return compose


class TestBothCompositionsPassTheSameStep:
    def test_the_server(self, tmp_path):
        create_app(str(_config_dir(tmp_path)))

        assert get_config()._after_load is after_load_services

    def test_the_mcp_server(self, as_nanoidp_mcp):
        as_nanoidp_mcp()

        assert mcp._ensure_config()._after_load is after_load_services


class TestALoadInTheMcpProcessReconciles:
    async def test_reload_config_retires_the_runtime_object_a_file_now_declares(self, as_nanoidp_mcp, mcp_call_tool):
        """Through the protocol, on the configuration the first tool call
        builds: the name is declared by hand, and the tool's reload removes
        the runtime object under it, said once."""
        config_dir = as_nanoidp_mcp()
        await mcp_call_tool("list_users", {})
        config = get_config()
        identities_for(config, config.snapshot).create_runtime_user(User(username="rt-user", password="pw"))
        users = config_dir / "users.yaml"
        document = yaml.safe_load(users.read_text())
        document["users"]["rt-user"] = {"password": "declared"}
        users.write_text(yaml.safe_dump(document))

        result = await mcp_call_tool("reload_config", {})

        assert result.is_error is not True
        assert get_runtime_store().users.get("rt-user") is None
        assert get_config().get_user("rt-user").password == "declared"
        assert len(_events("runtime_identity_removed_on_reload")) == 1


class TestTheSweepFollowsTheReconciliation:
    def test_a_load_that_declares_a_registered_client_drops_its_record(self, tmp_path):
        """The record of a dynamically registered client goes with the
        runtime client the load retires, in the same step: nobody has to
        ask about that registration first."""
        config_dir = _config_dir(tmp_path)
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["oauth"]["dynamic_registration"] = {"enabled": True}
        settings.write_text(yaml.safe_dump(document))
        application = create_app(str(config_dir))
        client = application.test_client()
        registered = client.post("/register", json={"redirect_uris": ["http://localhost:3000/cb"]}).get_json()
        assert [record.client_id for record in registrations().list()] == [registered["client_id"]]
        document["oauth"]["clients"].append(
            {"client_id": registered["client_id"], "client_secret": "declared", "redirect_uris": ["http://localhost:3000/cb"]}
        )
        settings.write_text(yaml.safe_dump(document))

        assert client.post("/api/config/reload").status_code == 200

        assert registrations().list() == []


def _the_server(config_dir, reloads, stop, declared):
    """A server over the same directory and store, adopting the files
    whenever they change, as it does at the start of every request."""
    import logging

    logging.disable(logging.CRITICAL)
    from nanoidp.app import create_app
    from nanoidp.config import get_config
    from nanoidp.services.runtime_store import fresh_configuration

    create_app(config_dir)
    reloads.value = 0
    while not stop.is_set():
        if get_config().refresh_if_changed():
            with reloads.get_lock():
                reloads.value += 1
        time.sleep(0.001)
    fresh_configuration()
    declared.put(sorted(name for name in get_config().users if name.startswith("rt-")))


class TestAPromotionFromTheMcpProcessWhileTheServerReloads:
    PROMOTIONS = 5

    def test_it_is_recorded_once_as_a_promotion_by_mcp(self, as_nanoidp_mcp):
        """The server adopts the file the promotion wrote BEFORE the MCP
        process reloads it: it finds the name declared and the object
        claimed by a writer that is alive, and leaves it. The MCP process's
        own reload retires it, as its promotion."""
        config_dir = as_nanoidp_mcp(shared_store=True)
        reloads = _SPAWN.Value("i", -1)
        stop = _SPAWN.Event()
        declared = _SPAWN.Queue()
        server = _SPAWN.Process(target=_the_server, args=(str(config_dir), reloads, stop, declared))
        server.start()
        try:
            deadline = time.monotonic() + _BOUND
            while reloads.value < 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert reloads.value == 0, "the server did not start"

            config = mcp._ensure_config()
            assert get_runtime_store().shared
            own_reload = config.reload_local
            server_went_first = []

            def after_the_server(*args, **kwargs):
                before = reloads.value
                deadline = time.monotonic() + 5
                while reloads.value == before and time.monotonic() < deadline:
                    time.sleep(0.002)
                server_went_first.append(reloads.value > before)
                return own_reload(*args, **kwargs)

            config.reload_local = after_the_server
            for number in range(self.PROMOTIONS):
                name = f"rt-{number}"
                fresh_configuration()
                resolver = identities_for(config, config.snapshot)
                resolver.create_runtime_user(User(username=name, password="pw"))
                resolver.promote_runtime_user(name, MCP_CONTEXT)
        finally:
            stop.set()
            server.join(_BOUND)
            if server.is_alive():
                server.kill()

        names = [f"rt-{number}" for number in range(self.PROMOTIONS)]
        assert declared.get(timeout=_BOUND) == names
        assert server_went_first and all(server_went_first), "the server did not reload before the MCP process did"
        assert get_runtime_store().users.list() == []
        promoted = _events("runtime_identity_promoted")
        assert sorted(entry["details"]["name"] for entry in promoted) == names
        assert {entry["endpoint"] for entry in promoted} == {"mcp"}
        assert _events("runtime_identity_removed_on_reload") == []
