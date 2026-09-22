"""The SQLite runtime store, chosen by settings.yaml (#354, step 4c).

``runtime.store: sqlite`` with ``runtime.path``: the path relative to the
configuration directory (the identity of a store several processes share
must not depend on where each was started), or absolute; its files outside
the configuration directory; chosen when the process starts, a reload that
asks for another store or another file refused; what the provisional store
held before the activation said to be lost; and a store held by another
process past its wait a retryable MCP error.
"""

import logging
import multiprocessing
import os
import shutil
import time
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigManager, ConfigurationRejected
from nanoidp.services import activate_services, runtime_store
from nanoidp.services.runtime_store import (
    get_runtime_store,
    resolved_runtime_path,
    runtime_store_inputs,
)
from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"
_SPAWN = multiprocessing.get_context("spawn")
_BOUND = 60


def _config_dir(tmp_path, runtime=None, name="config"):
    config_dir = tmp_path / name
    config_dir.mkdir(parents=True)
    for file in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG / file, config_dir / file)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    if runtime is not None:
        document["runtime"] = runtime
    settings.write_text(yaml.safe_dump(document))
    for file in ("settings.yaml", "users.yaml"):
        then = time.time() - 60
        os.utime(config_dir / file, (then, then))
    return config_dir


def _set_runtime(config_dir, runtime):
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["runtime"] = runtime
    settings.write_text(yaml.safe_dump(document))


def _loaded(config_dir):
    return ConfigManager(str(config_dir), activate=activate_services)


class TestTheDocument:
    @pytest.mark.parametrize(
        "runtime",
        [{"store": "memory"}, {"store": "sqlite", "path": "../state/runtime.db"}, {"store": "sqlite", "path": "/abs/x.db"}],
    )
    def test_a_path_goes_with_sqlite(self, tmp_path, runtime):
        from nanoidp.config_documents import SettingsDocument

        document = SettingsDocument.model_validate({"runtime": runtime})

        assert document.runtime.store == runtime["store"]
        assert document.runtime.path == runtime.get("path")

    @pytest.mark.parametrize(
        "runtime, why",
        [
            ({"store": "memory", "path": "../x.db"}, "is for runtime.store: sqlite"),
            ({"store": "memory", "path": None}, "is for runtime.store: sqlite"),
            ({"store": "memory", "path": ""}, "is for runtime.store: sqlite"),
            ({"store": "sqlite"}, "required"),
            ({"store": "sqlite", "path": ""}, "may not be empty"),
            ({"store": "sqlite", "path": "   "}, "may not be empty"),
            ({"store": "sqlite", "path": 5}, "string"),
            ({"store": "sqlite", "path": "~/nanoidp/runtime.db"}, "HOME"),
            ({"store": "sqlite", "path": "~"}, "HOME"),
        ],
    )
    def test_a_path_without_its_store_or_a_store_without_its_path_is_an_invalid_file(self, tmp_path, runtime, why):
        config_dir = _config_dir(tmp_path, runtime)

        with pytest.raises(ConfigurationRejected) as refused:
            _loaded(config_dir)

        assert refused.value.kind == "invalid"
        assert why in refused.value.message


class TestThePath:
    def test_a_relative_path_is_the_configuration_directorys_whatever_the_working_directory(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        seen = []
        for cwd in (tmp_path, tmp_path / "keys", Path("/")):
            cwd.mkdir(exist_ok=True)
            monkeypatch.chdir(cwd)
            settings = ConfigManager(str(config_dir)).settings
            seen.append(resolved_runtime_path(settings, config_dir))

        assert seen == [(tmp_path / "state" / "runtime.db").resolve()] * 3

    def test_an_absolute_path_is_itself(self, tmp_path):
        target = tmp_path / "elsewhere" / "runtime.db"
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": str(target)})
        settings = ConfigManager(str(config_dir)).settings

        assert resolved_runtime_path(settings, config_dir) == target.resolve()
        assert runtime_store_inputs(settings, config_dir) == ("sqlite", str(target.resolve()))

    def test_memory_has_no_path(self, tmp_path):
        config_dir = _config_dir(tmp_path)
        settings = ConfigManager(str(config_dir)).settings

        assert resolved_runtime_path(settings, config_dir) is None
        assert runtime_store_inputs(settings, config_dir) == ("memory",)

    @pytest.mark.parametrize(
        "layout",
        [
            "the database in it",
            "a symlink to it",
            "the owners' leases as it",
            "the owners' leases a symlink into it",
            "the audit a symlink into it",
        ],
    )
    def test_no_file_of_the_store_lies_in_the_configuration_directory(self, tmp_path, layout):
        if layout == "the database in it":
            config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "runtime.db"})
        elif layout == "a symlink to it":
            config_dir = _config_dir(tmp_path)
            (tmp_path / "looks-elsewhere").symlink_to(config_dir, target_is_directory=True)
            _set_runtime(config_dir, {"store": "sqlite", "path": "../looks-elsewhere/runtime.db"})
        elif layout == "the owners' leases as it":
            # runtime.db next to a configuration directory named as its
            # owners' directory would be.
            config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../runtime.db"}, name="runtime-owners")
        elif layout == "the owners' leases a symlink into it":
            # The database outside, its owners' directory a symlink into it.
            config_dir = _config_dir(tmp_path)
            (tmp_path / "runtime-owners").symlink_to(config_dir, target_is_directory=True)
            _set_runtime(config_dir, {"store": "sqlite", "path": "../runtime.db"})
        else:
            # The database outside, its audit a symlink to a file inside.
            config_dir = _config_dir(tmp_path)
            (tmp_path / "runtime-audit.db").symlink_to(config_dir / "audit.db")
            _set_runtime(config_dir, {"store": "sqlite", "path": "../runtime.db"})

        with pytest.raises(ConfigurationRejected) as refused:
            _loaded(config_dir)

        assert refused.value.kind == "activation"
        assert "inside the configuration directory" in refused.value.message
        assert not (tmp_path / "runtime.db").exists()


class TestTheActivation:
    def test_settings_yaml_chooses_the_sqlite_store(self, tmp_path):
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})

        _loaded(config_dir)

        store = get_runtime_store()
        assert isinstance(store, SqliteRuntimeStore)
        assert store.path == (tmp_path / "state" / "runtime.db").resolve()
        assert store.shared is True
        assert runtime_store._runtime_store_inputs == ("sqlite", str(store.path))

    @pytest.mark.parametrize(
        "then",
        [{"store": "sqlite", "path": "../state/other.db"}, {"store": "memory"}],
        ids=["another file", "another store"],
    )
    def test_a_reload_that_asks_for_another_file_or_store_is_refused(self, tmp_path, then):
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        config = _loaded(config_dir)
        store = get_runtime_store()
        _set_runtime(config_dir, then)

        with pytest.raises(ConfigurationRejected) as refused:
            config.reload()

        assert refused.value.kind == "activation"
        assert "restart" in refused.value.message
        assert get_runtime_store() is store

    def test_the_same_file_named_otherwise_is_no_restart(self, tmp_path):
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        config = _loaded(config_dir)
        store = get_runtime_store()
        _set_runtime(config_dir, {"store": "sqlite", "path": str(tmp_path / "state" / "runtime.db")})

        config.reload()

        assert get_runtime_store() is store

    def test_a_sqlite_this_python_cannot_use_refuses_the_configuration(self, tmp_path, monkeypatch):
        import sqlite3

        monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 23, 1))
        monkeypatch.setattr(sqlite3, "sqlite_version", "3.23.1")
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})

        with pytest.raises(ConfigurationRejected) as refused:
            _loaded(config_dir)

        assert refused.value.kind == "activation"
        assert "3.24" in refused.value.message


class TestTheProvisionalAudit:
    def _record_before_activation(self):
        from nanoidp.services.audit import get_audit_log

        get_audit_log().log("early", "/e", "GET", "success")

    def test_what_it_held_is_said_to_be_lost_when_sqlite_replaces_it(self, tmp_path, caplog):
        self._record_before_activation()
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})

        with caplog.at_level(logging.WARNING):
            _loaded(config_dir)

        said = [record.getMessage() for record in caplog.records if "not kept" in record.getMessage()]
        assert said and said[0].startswith("1 audit event(s)")

    def test_memory_adopts_it_and_loses_nothing(self, tmp_path, caplog):
        self._record_before_activation()
        config_dir = _config_dir(tmp_path)

        with caplog.at_level(logging.WARNING):
            _loaded(config_dir)

        assert not any("not kept" in record.getMessage() for record in caplog.records)
        assert [entry.event_type for entry in get_runtime_store().audit.entries(10)] == ["early"]

    def test_a_load_that_fails_says_nothing_is_lost(self, tmp_path, caplog, monkeypatch):
        """Said at the publication, never at a preparation a failure undoes."""
        from nanoidp.services import crypto

        self._record_before_activation()
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})

        def signing_fails(settings, config_dir=None):
            raise ValueError("no signing service")

        monkeypatch.setattr("nanoidp.services.activation.activate_crypto_service", signing_fails)
        with caplog.at_level(logging.WARNING), pytest.raises(ConfigurationRejected):
            _loaded(config_dir)

        assert not any("not kept" in record.getMessage() for record in caplog.records)
        assert crypto is not None


class TestTheSurfaces:
    def test_api_config_says_which_store_and_which_file(self, tmp_path):
        from nanoidp.app import create_app

        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        application = create_app(str(config_dir))
        application.config["TESTING"] = True

        runtime = application.test_client().get("/api/config").get_json()["runtime"]

        assert runtime == {"store": "sqlite", "path": str((tmp_path / "state" / "runtime.db").resolve())}

    def test_memory_is_said_without_a_path(self, tmp_path):
        from nanoidp.app import create_app

        application = create_app(str(_config_dir(tmp_path)))
        application.config["TESTING"] = True

        assert application.test_client().get("/api/config").get_json()["runtime"] == {"store": "memory"}

    async def test_mcp_says_the_same(self, tmp_path, mcp_call_tool):
        import json

        from nanoidp.config import init_config

        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        init_config(str(config_dir), activate=activate_services)

        result = json.loads((await mcp_call_tool("get_settings", {})).content[0].text)

        assert result["runtime"] == {"store": "sqlite", "path": str((tmp_path / "state" / "runtime.db").resolve())}

    async def test_a_store_held_past_its_wait_is_a_retryable_mcp_error(self, tmp_path, monkeypatch, mcp_call_tool):
        import json

        from nanoidp import mcp_server
        from nanoidp.config import init_config
        from nanoidp.services.runtime_repository import RuntimeStoreUnavailable

        init_config(str(_config_dir(tmp_path)), activate=activate_services)

        async def held(name, arguments, config):
            raise RuntimeStoreUnavailable("the runtime store is held by another process for longer than 5000 ms")

        monkeypatch.setattr(mcp_server, "_execute_tool", held)
        result = json.loads((await mcp_call_tool("list_users", {})).content[0].text)

        assert result["code"] == "MCP_RUNTIME_STORE_UNAVAILABLE"
        assert result["retryable"] is True


class TestTwoProcessesFromOneSettingsYaml:
    def test_they_share_the_store_whatever_they_were_started_from(self, tmp_path):
        """No store published by hand: settings.yaml, the activation, the
        path resolved against the configuration directory, one store. The
        two start from different working directories."""
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        for name in ("a", "b"):
            (tmp_path / name).mkdir()
        out = _SPAWN.Queue()
        first = _SPAWN.Process(target=_serve, args=(str(config_dir), str(tmp_path / "a"), "create", out), daemon=True)
        first.start()
        assert out.get(timeout=_BOUND) == ("a", 201)
        first.join(_BOUND)
        second = _SPAWN.Process(target=_serve, args=(str(config_dir), str(tmp_path / "b"), "read", out), daemon=True)
        second.start()
        assert out.get(timeout=_BOUND) == ("b", ["shared"])
        second.join(_BOUND)
        assert not (tmp_path / "a" / "state").exists() and not (tmp_path / "b" / "state").exists()


def _serve(config_dir, cwd, what, out):
    import logging

    logging.disable(logging.CRITICAL)
    os.chdir(cwd)
    from nanoidp.app import create_app

    application = create_app(config_dir)
    application.config["TESTING"] = True
    client = application.test_client()
    if what == "create":
        response = client.post("/api/runtime/users", json={"username": "shared", "password": "pw"})
        out.put(("a", response.status_code))
    else:
        users = client.get("/api/runtime/users").get_json()["users"]
        out.put(("b", [user["username"] for user in users]))


class TestTheReviewOf4c:
    async def test_a_store_held_while_the_first_tool_opens_it_is_retryable_too(self, tmp_path, monkeypatch, mcp_call_tool):
        """The first MCP tool call loads the configuration, and the load
        opens the store: a store held by another process then is the same
        contention as later, and is said as such."""
        import json

        from nanoidp.services.runtime_repository import RuntimeStoreUnavailable

        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))

        def held(inputs):
            raise RuntimeStoreUnavailable("the runtime store is held by another process for longer than 5000 ms")

        monkeypatch.setitem(runtime_store._RUNTIME_STORE_FACTORIES, "sqlite", held)
        result = json.loads((await mcp_call_tool("get_settings", {})).content[0].text)

        assert result["code"] == "MCP_RUNTIME_STORE_UNAVAILABLE"
        assert result["retryable"] is True

    async def test_a_configuration_that_is_rejected_otherwise_is_no_store_contention(self, tmp_path, monkeypatch, mcp_call_tool):
        import json

        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "runtime.db"})
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))

        result = json.loads((await mcp_call_tool("get_settings", {})).content[0].text)

        assert result["code"] != "MCP_RUNTIME_STORE_UNAVAILABLE"
        assert "retryable" not in result

    def test_the_report_is_of_the_file_in_use_not_of_where_the_path_points_now(self, tmp_path):
        """A path through a symlink retargeted after the start: the process
        still uses the file it opened, and says that one."""
        from nanoidp.app import create_app

        (tmp_path / "first").mkdir()
        (tmp_path / "second").mkdir()
        (tmp_path / "state").symlink_to(tmp_path / "first", target_is_directory=True)
        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        application = create_app(str(config_dir))
        application.config["TESTING"] = True
        (tmp_path / "state").unlink()
        (tmp_path / "state").symlink_to(tmp_path / "second", target_is_directory=True)

        runtime = application.test_client().get("/api/config").get_json()["runtime"]

        assert runtime["path"] == str((tmp_path / "first" / "runtime.db").resolve())

    def test_a_configuration_that_activated_nothing_reports_the_file_it_names(self, tmp_path):
        """No store published yet (a manager built without the activation):
        the report says the file the settings name, resolved as an
        activation would."""
        from nanoidp.services.runtime_store import runtime_store_report

        config_dir = _config_dir(tmp_path, {"store": "sqlite", "path": "../state/runtime.db"})
        settings = ConfigManager(str(config_dir)).settings

        assert runtime_store_report(settings, config_dir) == {
            "store": "sqlite",
            "path": str((tmp_path / "state" / "runtime.db").resolve()),
        }

    def test_settings_made_in_code_with_sqlite_and_no_path_are_said_so(self, tmp_path):
        """The document cannot say it; settings built in code can, and the
        store's layer does not take it for memory."""
        from nanoidp.config import Settings

        settings = Settings(runtime_store="sqlite", runtime_path=None)

        with pytest.raises(ValueError, match="runtime.path"):
            resolved_runtime_path(settings, tmp_path)
