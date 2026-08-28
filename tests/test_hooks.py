"""
Hooks and plugins v1 (#185): the three extension points, the bootstrap
surface, the per-hook error policy, plugin loading and introspection.
"""

import importlib.util
import logging
import pathlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

import nanoidp.hooks as hooks_module
from nanoidp.config import ConfigManager, init_config
from nanoidp.config_documents import BootstrapDocument
from nanoidp.hooks import (
    HOOK_API_VERSION,
    SOURCE_BOOTSTRAP_ENV,
    SOURCE_BOOTSTRAP_FILE,
    SOURCE_SETTINGS,
    HookError,
    HookRegistry,
    plugin_settings_from_env,
)
from nanoidp.services.audit import get_audit_log

REPO = Path(__file__).resolve().parent.parent
ECHO_SRC = REPO / "examples" / "plugins" / "nanoidp-echo" / "src" / "nanoidp_echo" / "__init__.py"


def _echo_plugin_class():
    """Import the reference plugin from examples/ without installing it."""
    spec = importlib.util.spec_from_file_location("nanoidp_echo", ECHO_SRC)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("nanoidp_echo", module)
    spec.loader.exec_module(module)
    return module.EchoPlugin


def _write(tmp_path, settings=None, users=None):
    doc = {"server": {"host": "127.0.0.1", "port": 8000}}
    doc.update(settings or {})
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
    (tmp_path / "users.yaml").write_text(yaml.safe_dump(users or {"users": {"alice": {"password": "x"}}}))
    return str(tmp_path)


def _record_cmd(log: Path, text: str) -> str:
    return f"echo '{text}' >> {log}"


def _lines(log: Path):
    return log.read_text().splitlines() if log.exists() else []


@pytest.fixture
def fake_entry_points(monkeypatch):
    """Register plugin classes under the nanoidp.plugins group in-process."""
    registry = {}

    def entry_points(group=None):
        if group != hooks_module.ENTRY_POINT_GROUP:
            return []
        return [SimpleNamespace(name=name, load=lambda cls=cls: cls) for name, cls in registry.items()]

    monkeypatch.setattr(hooks_module.metadata, "entry_points", entry_points)
    return registry


class TestShellHooksReceivePlaceholders:
    def test_before_load_and_config_saved(self, tmp_path):
        log = tmp_path / "hooks.log"
        cfg = _write(tmp_path, {"hooks": {
            "on_before_load": _record_cmd(log, "load {config_dir}"),
            "on_config_saved": _record_cmd(log, "saved {kind} {path}"),
        }})
        config = ConfigManager(cfg)
        # settings.yaml's on_before_load cannot run before the file that
        # declares it is read: first load has no settings-sourced hook yet.
        assert _lines(log) == []
        config.reload()
        assert _lines(log) == [f"load {tmp_path}"]
        config.save()
        lines = _lines(log)
        assert f"saved users {tmp_path / 'users.yaml'}" in lines
        assert f"saved settings {tmp_path / 'settings.yaml'}" in lines

    def test_yaml_writer_saves_dispatch_too(self, tmp_path):
        from nanoidp.services.yaml_writer import YamlWriter

        log = tmp_path / "hooks.log"
        init_config(_write(tmp_path, {"hooks": {"on_config_saved": _record_cmd(log, "{kind}")}}))
        YamlWriter(str(tmp_path)).update_login_settings(mode="persona")
        assert "settings" in _lines(log)

    def test_audit_event_gets_event_type_and_json_stdin(self, tmp_path):
        log = tmp_path / "hooks.log"
        init_config(_write(tmp_path, {"hooks": {
            "on_audit_event": f"cat >> {log}; echo ' {{event_type}}' >> {log}",
        }}))
        get_audit_log().log("token_request", "/token", "POST", "success", username="alice")
        text = log.read_text()
        assert '"event_type": "token_request"' in text
        assert text.rstrip().endswith("token_request")

    def test_braces_in_commands_are_not_placeholders(self, tmp_path):
        log = tmp_path / "hooks.log"
        init_config(_write(tmp_path, {"hooks": {"on_config_saved": f"echo '${{HOME:-x}} {{kind}}' >> {log}"}}))
        ConfigManager(str(tmp_path)).save()
        assert _lines(log)[-1].endswith(" settings")


class TestBootstrapSurface:
    def test_env_hook_runs_once_before_first_load_not_on_reload(self, tmp_path, monkeypatch):
        log = tmp_path / "hooks.log"
        cfg = _write(tmp_path)
        monkeypatch.setenv("NANOIDP_BOOTSTRAP_HOOK", _record_cmd(log, "bootstrap {config_dir}"))
        config = ConfigManager(cfg)
        assert _lines(log) == [f"bootstrap {tmp_path}"]
        config.reload()
        config.reload()
        assert _lines(log) == [f"bootstrap {tmp_path}"]
        hook = config.hooks.describe()["shell_hooks"][0]
        assert hook["source"] == SOURCE_BOOTSTRAP_ENV and hook["once"] is True

    def test_bootstrap_hook_can_render_the_settings_file(self, tmp_path, monkeypatch):
        """The main use case: the file that declares everything else does not
        exist until the bootstrap hook has run."""
        rendered = tmp_path / "rendered.yaml"
        rendered.write_text(yaml.safe_dump({"oauth": {"issuer": "http://rendered:1"}}))
        (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {}}))
        monkeypatch.setenv("NANOIDP_BOOTSTRAP_HOOK", f"cp {rendered} {{config_dir}}/settings.yaml")
        assert not (tmp_path / "settings.yaml").exists()
        config = ConfigManager(str(tmp_path))
        assert config.settings.issuer == "http://rendered:1"

    def test_bootstrap_yaml_hooks_and_unknown_key_warned(self, tmp_path, caplog):
        log = tmp_path / "hooks.log"
        cfg = _write(tmp_path)
        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"hooks": {
            "on_before_load": _record_cmd(log, "file-bootstrap"),
            "on_config_saved": _record_cmd(log, "file-saved"),
        }}))
        config = ConfigManager(cfg)
        assert _lines(log) == ["file-bootstrap"]
        config.reload()
        assert _lines(log) == ["file-bootstrap"]  # before_load from bootstrap.yaml runs once
        config.save()
        assert _lines(log).count("file-saved") == 2  # users + settings, every save
        assert {h["source"] for h in config.hooks.describe()["shell_hooks"]} == {SOURCE_BOOTSTRAP_FILE}

        # Same reporting as settings.yaml: an unknown key is warned with its
        # path and ignored, not a raw pydantic error (review before 2.7.0rc4).
        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"hooks": {}, "oauth": {"issuer": "x"}}))
        with caplog.at_level(logging.WARNING):
            ConfigManager(cfg)
        assert any("bootstrap.yaml: unknown key oauth (ignored)" in r.getMessage() for r in caplog.records)

    def test_bootstrap_yaml_only_hooks_and_plugins(self):
        doc = BootstrapDocument.model_validate({"hooks": None, "plugins": None})
        assert doc.hooks.on_before_load is None and doc.plugins == {}
        with pytest.raises(ValidationError, match="server"):
            BootstrapDocument.model_validate({"server": {}})

    def test_plugin_settings_from_env(self):
        env = {"NANOIDP_PLUGIN_MY_STORE_BUCKET": "b", "NANOIDP_PLUGIN_MY_STORE_PREFIX": "p", "NANOIDP_PLUGIN_OTHER_X": "1", "NANOIDP_PLUGIN_MY_STORE_": "ignored"}
        assert plugin_settings_from_env("my-store", env) == {"bucket": "b", "prefix": "p"}

    def test_bootstrap_plugin_from_env(self, tmp_path, monkeypatch, fake_entry_points):
        fake_entry_points["echo"] = _echo_plugin_class()
        record = tmp_path / "record.jsonl"
        monkeypatch.setenv("NANOIDP_BOOTSTRAP_PLUGIN", "echo")
        monkeypatch.setenv("NANOIDP_PLUGIN_ECHO_RECORD", str(record))
        config = ConfigManager(_write(tmp_path))
        plugin = config.hooks.plugins[0]
        assert plugin.source == SOURCE_BOOTSTRAP_ENV and plugin.config == {"record": str(record)}
        # a bootstrap plugin takes part in every hook for the life of the process
        config.reload()
        hooks_seen = [line for line in record.read_text().splitlines() if "on_before_load" in line]
        assert len(hooks_seen) == 2


class TestErrorPolicy:
    def test_before_load_failure_is_logged_by_default(self, tmp_path, caplog):
        cfg = _write(tmp_path, {"hooks": {"on_before_load": "false"}})
        config = ConfigManager(cfg)
        with caplog.at_level("WARNING"):
            config.reload()
        assert "on_before_load shell hook (settings.yaml) exited 1" in caplog.text
        assert config.hooks.describe()["shell_hooks"][0]["failures"] == 1

    def test_before_load_failure_blocks_under_strict(self, tmp_path):
        cfg = _write(tmp_path, {"hooks": {"on_before_load": "false", "strict": True}})
        config = ConfigManager(cfg)  # first load: the file's strict is not known yet
        with pytest.raises(HookError, match="on_before_load"):
            config.reload()

    def test_bootstrap_strict_blocks_the_first_load(self, tmp_path):
        cfg = _write(tmp_path)
        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"hooks": {"on_before_load": "exit 3", "strict": True}}))
        with pytest.raises(HookError, match=r"on_before_load shell hook \(bootstrap.yaml\) failed \(exit 3\)"):
            ConfigManager(cfg)

    def test_config_saved_failure_default_logs_and_file_is_written(self, tmp_path, caplog):
        config = ConfigManager(_write(tmp_path, {"hooks": {"on_config_saved": "echo boom >&2; false"}}))
        config.settings.audience = "changed"
        with caplog.at_level("WARNING"):
            config.save()
        assert "on_config_saved shell hook (settings.yaml) exited 1" in caplog.text
        assert "[stderr: boom]" in caplog.text
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["oauth"]["audience"] == "changed"

    def test_config_saved_failure_propagates_under_strict_after_the_write(self, tmp_path):
        config = ConfigManager(_write(tmp_path, {"hooks": {"on_config_saved": "false", "strict": True}}))
        config.settings.audience = "changed"
        with pytest.raises(HookError, match="on_config_saved"):
            config._save_settings()
        # the local save is committed regardless
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "changed"

    def test_strict_save_writes_both_files_before_any_hook_runs(self, tmp_path):
        """ConfigManager.save() writes users.yaml and settings.yaml as one
        transaction (#229): both are committed to disk before either
        file's on_config_saved hook runs. Under strict, a hook failure
        still raises HookError - but by then both files are already
        written, unlike the pre-#229 behaviour where a first-file hook
        failure meant the second file was never even attempted."""
        config = ConfigManager(_write(tmp_path, {"hooks": {"on_config_saved": "false", "strict": True}}))
        config.settings.audience = "changed"
        with pytest.raises(HookError):
            config.save()
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "changed"

    def test_config_saved_strict_reaches_yaml_writer_callers(self, tmp_path):
        from nanoidp.services.yaml_writer import YamlWriter

        init_config(_write(tmp_path, {"hooks": {"on_config_saved": "false", "strict": True}}))
        with pytest.raises(HookError):
            YamlWriter(str(tmp_path)).update_login_settings(mode="persona")
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["login"]["mode"] == "persona"

    def test_audit_event_failure_never_propagates_even_under_strict(self, tmp_path):
        config = init_config(_write(tmp_path, {"hooks": {"on_audit_event": "false", "strict": True}}))
        get_audit_log().log("token_request", "/token", "POST", "success")
        get_audit_log().log("token_request", "/token", "POST", "success")
        assert config.hooks.describe()["shell_hooks"][0]["failures"] == 2

    def test_timeout_is_a_failure(self, tmp_path, caplog):
        config = ConfigManager(_write(tmp_path, {"hooks": {"on_config_saved": "sleep 5", "timeout_seconds": 0.2}}))
        with caplog.at_level("WARNING"):
            config.save()
        assert "timed out after 0.2s" in caplog.text
        assert config.hooks.timeout_seconds == 0.2

    def test_plugin_failure_follows_the_same_policy(self, tmp_path):
        class Broken:
            hook_api_version = HOOK_API_VERSION

            def on_config_saved(self, path, kind):
                raise RuntimeError("store down")

            def on_audit_event(self, event):
                raise RuntimeError("audit down")

        config = init_config(_write(tmp_path))
        config.hooks.register_plugin_object("broken", Broken(), SOURCE_SETTINGS)
        config.save()  # default: logged
        assert config.hooks.plugins[0].failures["on_config_saved"] == 2  # users + settings
        config.hooks.set_policy(SOURCE_SETTINGS, strict=True)
        with pytest.raises(HookError, match="plugin 'broken' on_config_saved failed$"):
            config.save()
        get_audit_log().log("x", "/x", "GET", "success")  # never raises
        assert config.hooks.plugins[0].failures["on_audit_event"] == 1


class TestPlugins:
    def test_entry_point_plugin_discovered_configured_and_called(self, tmp_path, fake_entry_points):
        fake_entry_points["echo"] = _echo_plugin_class()
        record = tmp_path / "record.jsonl"
        config = init_config(_write(tmp_path, {"plugins": {"echo": {"record": str(record)}}}))
        plugin = config.hooks.plugins[0]
        assert plugin.name == "echo" and plugin.source == SOURCE_SETTINGS
        assert plugin.hooks == ["on_before_load", "on_config_saved", "on_audit_event"]
        assert plugin.obj.record == record  # configure() received plugins.echo
        config.save()
        get_audit_log().log("login", "/login", "POST", "success")
        hooks_recorded = [yaml.safe_load(line)["hook"] for line in record.read_text().splitlines()]
        assert hooks_recorded == ["on_config_saved", "on_config_saved", "on_audit_event"]
        config.reload()
        assert yaml.safe_load(record.read_text().splitlines()[-1])["hook"] == "on_before_load"
        # reload re-reads settings.yaml: the plugin is re-registered, not duplicated
        assert [p.name for p in config.hooks.plugins] == ["echo"]

    def test_bare_plugin_entry_means_no_settings(self, tmp_path, fake_entry_points):
        fake_entry_points["echo"] = _echo_plugin_class()
        config = ConfigManager(_write(tmp_path, {"plugins": {"echo": None}}))
        assert config.hooks.plugins[0].config == {}

    def test_unknown_plugin_is_reported_not_fatal(self, tmp_path, fake_entry_points, caplog):
        """Registration follows the error policy (review before 2.7.0rc4): a
        missing package must not abort the load or a post-write refresh."""
        with caplog.at_level(logging.ERROR):
            config = ConfigManager(_write(tmp_path, {"plugins": {"nope": {}}}))
        failed = config.hooks.describe()["plugins_failed"]
        assert failed == [{"name": "nope", "source": SOURCE_SETTINGS, "reason": failed[0]["reason"]}]
        assert failed[0]["reason"] == "not installed"
        assert any("plugin 'nope'" in r.getMessage() for r in caplog.records)
        assert "NOT LOADED" in config.hooks.format_report()

    def test_unknown_plugin_blocks_the_load_under_strict(self, tmp_path, fake_entry_points):
        with pytest.raises(HookError, match="plugin\\(s\\) 'nope' from settings.yaml could not be loaded"):
            ConfigManager(_write(tmp_path, {"plugins": {"nope": {}}, "hooks": {"strict": True}}))

    def test_api_version_mismatch_reported(self, tmp_path, fake_entry_points):
        class Old:
            hook_api_version = 0

        fake_entry_points["old"] = Old
        config = ConfigManager(_write(tmp_path, {"plugins": {"old": {}}}))
        assert config.hooks.plugins == []
        reason = config.hooks.describe()["plugins_failed"][0]["reason"]
        assert reason == "incompatible hook_api_version=0 (expected 1)"

    def test_shell_hook_runs_before_plugins(self, tmp_path):
        order = []

        class P:
            name = "p"
            hook_api_version = 1

            def on_config_saved(self, path, kind):
                order.append(f"plugin:{kind}")

        log = tmp_path / "hooks.log"
        config = init_config(_write(tmp_path, {"hooks": {"on_config_saved": _record_cmd(log, "shell")}}))
        config.hooks.register_plugin_object("p", P(), SOURCE_SETTINGS)
        config._save_settings()
        assert _lines(log) == ["shell"] and order == ["plugin:settings"]

    def test_plugins_section_shape_is_validated_but_keys_are_not(self, tmp_path):
        with pytest.raises(ValueError, match="plugins.echo must be a mapping"):
            ConfigManager(_write(tmp_path, {"plugins": {"echo": "x"}}))
        with pytest.raises(ValueError, match="plugins must be a mapping"):
            ConfigManager(_write(tmp_path, {"plugins": ["echo"]}))


class TestIntrospection:
    def test_api_config_and_mcp_report_the_same_block(self, tmp_path, mcp_call_tool):
        import asyncio

        from nanoidp.app import create_app

        log = tmp_path / "hooks.log"
        app = create_app(config_dir=_write(tmp_path, {"hooks": {"on_config_saved": _record_cmd(log, "x"), "timeout_seconds": 3}}))
        app.config["TESTING"] = True
        with app.test_client() as client:
            block = client.get("/api/config").get_json()["hooks"]
        assert block["hook_api_version"] == HOOK_API_VERSION
        assert block["strict"] is False and block["timeout_seconds"] == 3.0
        assert block["shell_hooks"][0]["hook"] == "on_config_saved"
        assert block["shell_hooks"][0]["source"] == SOURCE_SETTINGS
        assert block["plugins"] == []

        import nanoidp.mcp_server as mcp
        mcp._config = ConfigManager(str(tmp_path))
        result = asyncio.run(mcp_call_tool("get_settings", {}))
        payload = yaml.safe_load(result.content[0].text)
        assert payload["hooks"] == block

    def test_update_settings_schema_says_hooks_are_yaml_only(self, mcp_list_tools):
        import asyncio

        tools = asyncio.run(mcp_list_tools())
        update = next(t for t in tools if t.name == "update_settings")
        assert "YAML-only" in update.description
        assert "hooks" not in update.input_schema["properties"]
        assert "plugins" not in update.input_schema["properties"]

    def test_cli_plugins_subcommand(self, tmp_path, capsys, monkeypatch):
        from nanoidp.__main__ import main

        log = tmp_path / "hooks.log"
        cfg = _write(tmp_path, {"hooks": {"on_before_load": _record_cmd(log, "l")}})
        monkeypatch.setattr(sys, "argv", ["nanoidp", "plugins", "--config", cfg])
        main()
        out = capsys.readouterr().out
        assert "hook API version: 1" in out
        assert "on_before_load   settings.yaml  failures=0" in out
        assert "plugins:\n  (none)" in out

    def test_cli_bootstrap_hook_flag_maps_to_env(self, monkeypatch, tmp_path):
        from nanoidp import __main__ as main_mod

        called = {}
        monkeypatch.setattr(sys, "argv", ["nanoidp", "--bootstrap-hook", "echo hi", "--config", _write(tmp_path)])
        # setenv (not delenv) so monkeypatch restores the variable to absent
        # after main() has overwritten it; otherwise it leaks into later tests.
        monkeypatch.setenv("NANOIDP_BOOTSTRAP_HOOK", "overwritten-by-main")
        import nanoidp.app as app_mod
        monkeypatch.setattr(app_mod, "run_app", lambda **kw: called.update(kw))
        main_mod.main()
        import os
        assert os.environ["NANOIDP_BOOTSTRAP_HOOK"] == "echo hi"
        assert called["config_dir"] == _write(tmp_path)

    def test_shipped_config_declares_no_hooks(self):
        config = ConfigManager(str(REPO / "config"))
        info = config.hooks.describe()
        assert info["shell_hooks"] == [] and info["plugins"] == [] and info["plugins_failed"] == []

    def test_hooks_survive_a_settings_save_untouched(self, tmp_path):
        """The writer manages its own keys only; hooks:/plugins: are preserved
        verbatim (read-modify-write, #87) and never materialized."""
        cfg = _write(tmp_path, {"hooks": {"on_config_saved": "true", "strict": True}, "plugins": {}})
        config = ConfigManager(cfg)
        config.settings.audience = "a"
        config.save()
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert on_disk["hooks"] == {"on_config_saved": "true", "strict": True}
        cfg2 = _write(tmp_path)
        ConfigManager(cfg2).save()
        assert "hooks" not in yaml.safe_load((tmp_path / "settings.yaml").read_text())


class TestRegistryUnit:
    def test_unknown_hook_name_refused(self):
        with pytest.raises(ValueError, match="Unknown hook"):
            HookRegistry().add_shell_hook("on_login", "true", SOURCE_SETTINGS)

    def test_drop_source_keeps_other_sources(self):
        r = HookRegistry()
        r.add_shell_hook("on_before_load", "a", SOURCE_BOOTSTRAP_ENV, once=True)
        r.add_shell_hook("on_before_load", "b", SOURCE_SETTINGS)
        r.drop_source(SOURCE_SETTINGS)
        assert [h.command for h in r.shell_hooks] == ["a"]


class TestSecretsNeverLeaveTheProcess:
    """#185 review, blocker: commands are stored after ${VAR} expansion and
    /api/* is unauthenticated, so neither describe() nor a propagated
    HookError may carry a command or a hook's stderr."""

    SECRET = "s3cr3t-value"

    def _app(self, tmp_path, monkeypatch, strict=True):
        from nanoidp.app import create_app

        monkeypatch.setenv("MIRROR_TOKEN", self.SECRET)
        cfg = _write(tmp_path, {"hooks": {
            "on_config_saved": 'echo "leaking ${MIRROR_TOKEN}" >&2; curl -s -H "Authorization: Bearer ${MIRROR_TOKEN}" http://127.0.0.1:9/ >/dev/null 2>&1; exit 1',
            "strict": strict,
        }})
        app = create_app(config_dir=cfg)
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        return app

    def test_api_config_and_mcp_expose_no_command(self, tmp_path, monkeypatch, mcp_call_tool):
        import asyncio

        import nanoidp.mcp_server as mcp

        app = self._app(tmp_path, monkeypatch)
        with app.test_client() as client:
            body = client.get("/api/config").get_data(as_text=True)
            block = client.get("/api/config").get_json()["hooks"]
        assert self.SECRET not in body
        assert all("command" not in h for h in block["shell_hooks"])
        assert set(block["shell_hooks"][0]) == {"hook", "source", "failures", "once"}
        mcp._config = ConfigManager(str(tmp_path))
        result = asyncio.run(mcp_call_tool("get_settings", {}))
        assert self.SECRET not in result.content[0].text
        assert "command" not in result.content[0].text

    def test_propagated_error_and_ui_flash_carry_no_command_or_stderr(self, tmp_path, monkeypatch, caplog):
        from nanoidp.config import get_config

        app = self._app(tmp_path, monkeypatch)
        get_config().settings.audience = "changed"
        with caplog.at_level("WARNING"):
            with pytest.raises(HookError) as exc_info:
                get_config()._save_settings()
        message = str(exc_info.value)
        assert message == "on_config_saved shell hook (settings.yaml) failed (exit 1)"
        assert self.SECRET not in message and "curl" not in message
        # the local log is the one place that has the command and stderr
        assert self.SECRET in caplog.text and "[stderr: leaking" in caplog.text
        # the UI flash under strict
        with app.test_client() as client:
            resp = client.post("/settings", data={"issuer": "http://localhost:8000", "audience": "x"}, follow_redirects=True)
            page = resp.get_data(as_text=True)
        assert self.SECRET not in page and "curl" not in page
        assert "Settings saved locally; mirror hook failed" in page

    def test_plugin_exception_text_is_not_propagated(self, tmp_path):
        class Leaky:
            hook_api_version = HOOK_API_VERSION

            def on_config_saved(self, path, kind):
                raise RuntimeError("https://store/?token=" + TestSecretsNeverLeaveTheProcess.SECRET)

        config = init_config(_write(tmp_path, {"hooks": {"strict": True}}))
        config.hooks.register_plugin_object("leaky", Leaky(), SOURCE_SETTINGS)
        with pytest.raises(HookError) as exc_info:
            config._save_settings()
        assert str(exc_info.value) == "plugin 'leaky' on_config_saved failed"

    def test_cli_report_is_the_only_place_with_commands(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MIRROR_TOKEN", self.SECRET)
        config = ConfigManager(_write(tmp_path, {"hooks": {"on_config_saved": "echo ${MIRROR_TOKEN}"}}))
        assert "command" not in str(config.hooks.describe())
        report = config.hooks.format_report()
        assert "command (local only, may embed secrets): echo " + self.SECRET in report


class TestSourcePrecedenceAndLifecycle:
    """#185 review, blocker: bootstrap policy is the baseline, settings.yaml
    overrides only what it declares, and a vanished settings.yaml takes its
    entries and policy with it."""

    def _bootstrap(self, tmp_path, **hooks):
        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"hooks": hooks}))

    def test_bootstrap_strict_survives_a_settings_file_without_hooks(self, tmp_path):
        self._bootstrap(tmp_path, on_config_saved="false", strict=True, timeout_seconds=2)
        config = ConfigManager(_write(tmp_path))  # no hooks: in settings.yaml
        assert config.hooks.strict is True and config.hooks.timeout_seconds == 2.0
        config.settings.audience = "changed"
        with pytest.raises(HookError, match=r"\(bootstrap.yaml\) failed"):
            config._save_settings()
        config.reload()
        assert config.hooks.strict is True and config.hooks.timeout_seconds == 2.0

    def test_settings_overrides_only_what_it_declares(self, tmp_path):
        self._bootstrap(tmp_path, on_config_saved="false", strict=True, timeout_seconds=2)
        config = ConfigManager(_write(tmp_path, {"hooks": {"strict": False}}))
        assert config.hooks.strict is False
        assert config.hooks.timeout_seconds == 2.0  # not declared: bootstrap value stays
        config.settings.audience = "changed"
        config._save_settings()  # not strict any more: logged, not raised

    def test_vanished_settings_file_drops_its_hooks_plugins_and_policy(self, tmp_path, fake_entry_points):
        class Tracker:
            hook_api_version = HOOK_API_VERSION

        fake_entry_points["tracker"] = Tracker
        self._bootstrap(tmp_path, on_config_saved="true", timeout_seconds=3)
        cfg = _write(tmp_path, {"hooks": {"on_config_saved": "true", "strict": True, "timeout_seconds": 1}, "plugins": {"tracker": {}}})
        config = ConfigManager(cfg)
        assert {h.source for h in config.hooks.shell_hooks} == {SOURCE_BOOTSTRAP_FILE, SOURCE_SETTINGS}
        assert [p.name for p in config.hooks.plugins] == ["tracker"]
        assert config.hooks.strict is True and config.hooks.timeout_seconds == 1.0
        (tmp_path / "settings.yaml").unlink()
        config.reload()
        assert {h.source for h in config.hooks.shell_hooks} == {SOURCE_BOOTSTRAP_FILE}
        assert config.hooks.plugins == []
        assert config.hooks.strict is False and config.hooks.timeout_seconds == 3.0

    def test_bootstrap_yaml_rejects_non_positive_timeout(self, tmp_path):
        for value in (0, -1):
            self._bootstrap(tmp_path, timeout_seconds=value)
            with pytest.raises(ValueError, match="bootstrap.yaml: invalid value at hooks.timeout_seconds"):
                ConfigManager(_write(tmp_path))


class TestConfigDirPlaceholderOnSave:
    def test_config_dir_is_available_to_on_config_saved_and_audit(self, tmp_path):
        log = tmp_path / "hooks.log"
        cfg = _write(tmp_path, {"hooks": {
            "on_config_saved": f"echo 'saved {{config_dir}} {{kind}}' >> {log}",
            "on_audit_event": f"echo 'audit {{config_dir}} {{event_type}}' >> {log}",
        }})
        config = init_config(cfg)
        config._save_settings()
        get_audit_log().log("token_request", "/token", "POST", "success")
        assert f"saved {tmp_path} settings" in _lines(log)
        assert f"audit {tmp_path} token_request" in _lines(log)

    def test_git_worked_example_runs(self, tmp_path):
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git not installed")
        cfg = _write(tmp_path, {"hooks": {
            "on_config_saved": "git -C {config_dir} add {path} && git -C {config_dir} commit -q -m 'nanoidp: {kind} saved'",
            "strict": True,
        }})
        subprocess.run(["git", "-C", cfg, "init", "-q"], check=True)
        subprocess.run(["git", "-C", cfg, "config", "user.email", "t@example.org"], check=True)
        subprocess.run(["git", "-C", cfg, "config", "user.name", "t"], check=True)
        config = ConfigManager(cfg)
        config.settings.audience = "versioned"
        config._save_settings()  # strict: a failing git command would raise
        log = subprocess.run(["git", "-C", cfg, "log", "--oneline"], capture_output=True, text=True, check=True).stdout
        assert "nanoidp: settings saved" in log


class TestStrictSaveKeepsDiskAndRuntimeAligned:
    def test_yaml_writer_reloads_before_propagating(self, tmp_path):
        from nanoidp.config import get_config
        from nanoidp.services.yaml_writer import YamlWriter

        init_config(_write(tmp_path, {"hooks": {"on_config_saved": "false", "strict": True}}))
        assert get_config().settings.login_mode == "password"
        with pytest.raises(HookError):
            YamlWriter(str(tmp_path)).update_login_settings(mode="persona")
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["login"]["mode"] == "persona"
        assert get_config().settings.login_mode == "persona"  # runtime == disk

    def test_ui_settings_save_under_strict_shows_new_value(self, tmp_path):
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        app = create_app(config_dir=_write(tmp_path, {"hooks": {"on_config_saved": "false", "strict": True}}))
        app.config["TESTING"] = True
        with app.test_client() as client:
            page = client.post("/settings", data={"issuer": "http://localhost:8000", "audience": "aligned"}, follow_redirects=True).get_data(as_text=True)
        assert "Settings saved locally; mirror hook failed" in page
        assert get_config().settings.audience == "aligned"
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["oauth"]["audience"] == "aligned"


class TestPostWriteRefreshNeverConsultsTheMirror:
    """#185 review: the refresh after a local write must read the LOCAL files
    only. If it ran on_before_load, a mirror that has not caught up (or whose
    push just failed) would be copied back over the file just written: a
    silent rollback, with the UI still reporting success."""

    def _mirror_setup(self, tmp_path, strict):
        remote = tmp_path / "remote"
        remote.mkdir()
        cfg = _write(tmp_path)
        # the mirror holds the OLD configuration
        (remote / "settings.yaml").write_text((tmp_path / "settings.yaml").read_text())
        (tmp_path / "settings.yaml").write_text(
            (tmp_path / "settings.yaml").read_text()
            + yaml.safe_dump({"hooks": {
                "on_before_load": f"cp {remote}/settings.yaml {{config_dir}}/settings.yaml",
                "on_config_saved": "false",
                "strict": strict,
            }})
        )
        (remote / "settings.yaml").write_text((tmp_path / "settings.yaml").read_text())
        return cfg, remote

    @pytest.mark.parametrize("strict", [True, False])
    def test_failed_push_does_not_roll_the_write_back(self, tmp_path, strict):
        from nanoidp.config import get_config
        from nanoidp.services.yaml_writer import YamlWriter

        cfg, remote = self._mirror_setup(tmp_path, strict)
        init_config(cfg)
        assert get_config().settings.login_mode == "password"
        writer = YamlWriter(cfg)
        if strict:
            with pytest.raises(HookError):
                writer.update_login_settings(mode="persona")
        else:
            writer.update_login_settings(mode="persona")
        local = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert local["login"]["mode"] == "persona", "local write must survive"
        assert get_config().settings.login_mode == "persona", "runtime must follow the local disk"
        assert "login" not in yaml.safe_load((remote / "settings.yaml").read_text()), "mirror untouched (push failed)"

    def test_explicit_reload_still_pulls_from_the_mirror(self, tmp_path):
        """The mirror is consulted by the EXTERNAL reload only."""
        from nanoidp.config import get_config
        from nanoidp.services.yaml_writer import YamlWriter

        cfg, remote = self._mirror_setup(tmp_path, strict=False)
        init_config(cfg)
        YamlWriter(cfg).update_login_settings(mode="persona")
        assert get_config().settings.login_mode == "persona"
        get_config().reload()  # on_before_load copies the old mirror back
        assert get_config().settings.login_mode == "password"

    def test_reload_local_does_not_run_before_load(self, tmp_path):
        from nanoidp.config import get_config

        log = tmp_path / "hooks.log"
        init_config(_write(tmp_path, {"hooks": {"on_before_load": _record_cmd(log, "before")}}))
        n = len(_lines(log))
        get_config().reload_local()
        assert len(_lines(log)) == n
        get_config().reload()
        assert len(_lines(log)) == n + 1


class TestReviewBeforeRc4:
    """Findings of the code review on v2.7.0-rc3..main, each pinned."""

    def test_failed_plugin_does_not_break_saves_and_is_reported_by_the_api(self, tmp_path, fake_entry_points):
        from nanoidp.app import create_app
        from nanoidp.config import get_config
        from nanoidp.services.yaml_writer import YamlWriter

        app = create_app(config_dir=_write(tmp_path, {"plugins": {"store": {}}}))
        app.config["TESTING"] = True
        YamlWriter(str(tmp_path)).update_login_settings(mode="persona")  # post-write refresh must not raise
        assert get_config().settings.login_mode == "persona"
        with app.test_client() as client:
            block = client.get("/api/config").get_json()["hooks"]
        assert block["plugins_failed"][0]["name"] == "store"

    def test_reload_endpoint_returns_json_on_hook_error(self, tmp_path):
        from nanoidp.app import create_app

        cfg = _write(tmp_path)
        app = create_app(config_dir=cfg)
        app.config["TESTING"] = True
        # declare the failing strict hook AFTER the first load so startup passes
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["hooks"] = {"on_before_load": "false", "strict": True}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        with app.test_client() as client:
            client.post("/api/config/reload")  # picks the declaration up (hook not yet registered)
            resp = client.post("/api/config/reload")
        assert resp.status_code == 503
        assert resp.is_json
        assert resp.get_json()["status"] == "error"
        assert "on_before_load shell hook (settings.yaml) failed (exit 1)" in resp.get_json()["error"]

    def test_mcp_reload_returns_error_result_on_hook_error(self, tmp_path, mcp_call_tool):
        import asyncio

        import nanoidp.mcp_server as mcp

        cfg = _write(tmp_path)
        mcp._config = ConfigManager(cfg)
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["hooks"] = {"on_before_load": "false", "strict": True}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        mcp._config.reload()
        result = asyncio.run(mcp_call_tool("reload_config", {}))
        payload = yaml.safe_load(result.content[0].text)
        assert payload["success"] is False
        assert "Reload failed: on_before_load shell hook (settings.yaml) failed (exit 1)" in payload["error"]

    def test_audit_from_a_plugin_before_load_completes_and_is_not_dispatched(self, tmp_path, fake_entry_points):
        from nanoidp.config import init_config
        from nanoidp.services.audit import get_audit_log

        seen = []

        class Chatty:
            hook_api_version = 1

            def on_before_load(self, config_dir):
                get_audit_log().log(event_type="plugin_boot", endpoint="/plugin", method="HOOK", status="success")

            def on_audit_event(self, event):
                seen.append(event["event_type"])

        fake_entry_points["chatty"] = Chatty
        cfg = _write(tmp_path, {"plugins": {"chatty": {}}})
        config = init_config(cfg)
        config.reload()  # plugin registered now: its on_before_load logs an audit event
        assert "plugin_boot" not in seen  # not dispatched while loading: no recursion
        get_audit_log().log(event_type="after", endpoint="/x", method="GET", status="success")
        assert "after" in seen

    def test_audit_logging_never_constructs_the_config(self, monkeypatch):
        import nanoidp.config as config_module
        from nanoidp.services.audit import get_audit_log

        assert config_module._config is None

        def boom(*a, **k):
            raise AssertionError("ConfigManager constructed from an audit log call")

        monkeypatch.setattr(config_module, "ConfigManager", boom)
        get_audit_log().log(event_type="x", endpoint="/x", method="GET", status="success")
        assert config_module._config is None

    def test_bootstrap_yaml_expands_placeholders_and_reports_errors_like_settings(self, tmp_path, monkeypatch, caplog, fake_entry_points):
        monkeypatch.setenv("STORE_URL", "s3://bucket")
        fake_entry_points["echo"] = _echo_plugin_class()
        cfg = _write(tmp_path)
        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"plugins": {"echo": {"url": "${STORE_URL}"}}}))
        config = ConfigManager(cfg)
        assert config.hooks.plugins[0].config == {"url": "s3://bucket"}

        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"hooks": {"timeout_seconds": "x"}}))
        with pytest.raises(ValueError, match="bootstrap.yaml: invalid value at hooks.timeout_seconds"):
            ConfigManager(cfg)

        (tmp_path / "bootstrap.yaml").write_text(yaml.safe_dump({"hooks": {"on_before_laod": "true"}}))
        with caplog.at_level(logging.WARNING):
            ConfigManager(cfg)
        assert any("bootstrap.yaml: unknown key hooks.on_before_laod (ignored)" in r.getMessage() for r in caplog.records)

    def test_mcp_get_settings_carries_the_profile_keys_of_api_config(self, tmp_path, mcp_call_tool):
        import asyncio

        import nanoidp.mcp_server as mcp
        from nanoidp.app import create_app

        app = create_app(config_dir=_write(tmp_path), profile="stricter-dev")
        app.config["TESTING"] = True
        with app.test_client() as client:
            api = client.get("/api/config").get_json()
        mcp._config = ConfigManager(str(tmp_path), profile_override="stricter-dev")
        result = asyncio.run(mcp_call_tool("get_settings", {}))
        payload = yaml.safe_load(result.content[0].text)
        for key in ("security_profile", "profile_override", "effective", "config_version", "config_validation", "hooks"):
            assert payload[key] == api[key], key
        assert payload["effective"]["require_pkce"] is True

    def test_plugins_are_not_reinstantiated_on_a_post_write_refresh(self, tmp_path, fake_entry_points):
        from nanoidp.config import init_config
        from nanoidp.services.yaml_writer import YamlWriter

        instances = []

        class Counting:
            hook_api_version = 1

            def __init__(self):
                instances.append(self)

            def configure(self, settings):
                self.settings = settings

        fake_entry_points["counting"] = Counting
        cfg = _write(tmp_path, {"plugins": {"counting": {"v": 1}}})
        init_config(cfg)
        writer = YamlWriter(cfg)
        for mode in ("persona", "password", "persona"):
            writer.update_login_settings(mode=mode)
        assert len(instances) == 1
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["plugins"] = {"counting": {"v": 2}}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        writer.update_login_settings(mode="password")
        assert len(instances) == 2 and instances[-1].settings == {"v": 2}

    def test_settings_model_has_no_hook_fields(self):
        from nanoidp.models import Settings

        s = Settings()
        for name in ("hooks_on_before_load", "hooks_on_config_saved", "hooks_on_audit_event",
                     "hooks_strict", "hooks_timeout_seconds", "plugins"):
            assert not hasattr(s, name), name

    def test_dispatch_is_skipped_when_nothing_is_registered(self, monkeypatch):
        registry = HookRegistry()

        def boom(*a, **k):
            raise AssertionError("_dispatch called with nothing registered")

        monkeypatch.setattr(registry, "_dispatch", boom)
        registry.run_audit_event({"event_type": "x"})  # the hot path: no copies, no dispatch
        # the other hooks reach _dispatch, which returns before iterating
        monkeypatch.undo()
        monkeypatch.setattr(registry, "_run_shell", boom)
        registry.run_config_saved(pathlib.Path("/tmp/x.yaml"), "settings")
        registry.run_before_load(pathlib.Path("/tmp"))



class TestPluginFailureReasonsNeverExposeExceptionText:
    """#200 review: plugins_failed.reason must be one of nanoidp's own short
    diagnoses; a configure() exception that embeds plugin settings (tokens)
    stays in the local log."""

    def test_configure_exception_is_redacted_everywhere(self, tmp_path, monkeypatch, caplog, fake_entry_points):
        monkeypatch.setenv("PLUGIN_TOKEN", "s3cr3t-plugin-token")

        class Leaky:
            hook_api_version = 1

            def configure(self, settings):
                raise RuntimeError(f"cannot connect to {settings['url']} with token {settings['token']}")

        fake_entry_points["leaky"] = Leaky
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        with caplog.at_level(logging.ERROR):
            app = create_app(config_dir=_write(tmp_path, {"plugins": {"leaky": {"url": "https://store", "token": "${PLUGIN_TOKEN}"}}}))
        app.config["TESTING"] = True
        failed = get_config().hooks.describe()["plugins_failed"]
        assert failed == [{"name": "leaky", "source": SOURCE_SETTINGS, "reason": "initialization failed"}]
        with app.test_client() as client:
            body = client.get("/api/config").get_data(as_text=True)
        assert "s3cr3t-plugin-token" not in body and "cannot connect" not in body
        # the detail is in the local log
        assert any("s3cr3t-plugin-token" in r.getMessage() for r in caplog.records)
        # strict: the propagated message names the plugin only
        get_config().hooks.drop_source(SOURCE_SETTINGS)
        cfg = _write(tmp_path, {"hooks": {"strict": True}, "plugins": {"leaky": {"url": "u", "token": "${PLUGIN_TOKEN}"}}})
        with pytest.raises(HookError) as info:
            ConfigManager(cfg)
        assert info.value.kind == "plugin_load"
        assert "s3cr3t-plugin-token" not in str(info.value) and "leaky" in str(info.value)


class TestPluginDeclarationOrderIsHonouredOnReload:
    def test_reordering_plugins_reapplies_them(self, tmp_path, fake_entry_points):
        from nanoidp.config import get_config
        from nanoidp.services.yaml_writer import YamlWriter

        calls = []

        def make(tag):
            class P:
                hook_api_version = 1

                def on_config_saved(self, path, kind):
                    calls.append(tag)
            return P

        fake_entry_points["pa"] = make("a")
        fake_entry_points["pb"] = make("b")
        cfg = _write(tmp_path, {"plugins": {"pa": {}, "pb": {}}})
        init_config(cfg)
        assert [p.name for p in get_config().hooks.plugins] == ["pa", "pb"]
        YamlWriter(cfg).update_login_settings(mode="persona")
        assert calls == ["a", "b"]
        # rewrite the file with the plugins reordered, same configs
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["plugins"] = {"pb": {}, "pa": {}}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
        get_config().reload_local()
        assert [p.name for p in get_config().hooks.plugins] == ["pb", "pa"]
        calls.clear()
        YamlWriter(cfg).update_login_settings(mode="password")
        assert calls[:2] == ["b", "a"]


class TestReloadErrorNamesThePhase:
    def test_plugin_load_failure_is_reported_as_plugin_load(self, tmp_path):
        from nanoidp.app import create_app

        app = create_app(config_dir=_write(tmp_path))
        app.config["TESTING"] = True
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["hooks"] = {"strict": True}
        doc["plugins"] = {"missing": {}}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        with app.test_client() as client:
            resp = client.post("/api/config/reload")
        assert resp.status_code == 503
        body = resp.get_json()
        assert body["kind"] == "plugin_load" and "missing" in body["error"]

    def test_before_load_failure_is_reported_as_on_before_load(self, tmp_path):
        from nanoidp.app import create_app

        app = create_app(config_dir=_write(tmp_path))
        app.config["TESTING"] = True
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["hooks"] = {"on_before_load": "false", "strict": True}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        with app.test_client() as client:
            client.post("/api/config/reload")  # registers the hook (first reload reads the file)
            resp = client.post("/api/config/reload")
        assert resp.status_code == 503 and resp.get_json()["kind"] == "on_before_load"



class TestStrictReloadFailsWithoutCommit:
    """#200 review: a live process whose reload fails under strict must keep
    its previous settings, profile hardening and registry untouched."""

    def test_plugin_load_failure_leaves_runtime_and_registry_intact(self, tmp_path, fake_entry_points):
        from nanoidp.app import create_app
        from nanoidp.config import get_config

        class Keep:
            hook_api_version = 1

        fake_entry_points["keep"] = Keep
        app = create_app(config_dir=_write(tmp_path, {"plugins": {"keep": {}}}), profile="stricter-dev")
        app.config["TESTING"] = True
        config = get_config()
        assert config.settings.security_profile == "stricter-dev" and config.settings.require_pkce is True
        old_settings = config.settings
        old_plugins = list(config.hooks.plugins)
        old_snapshot = config.hooks.snapshot()
        doc = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        doc["hooks"] = {"strict": True}
        doc["plugins"] = {"keep": {}, "missing": {}}
        doc.setdefault("oauth", {})["audience"] = "changed-on-disk"
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        with app.test_client() as client:
            resp = client.post("/api/config/reload")
        assert resp.status_code == 503 and resp.get_json()["kind"] == "plugin_load"
        # runtime: the previous Settings object, still hardened, audience unchanged
        assert config.settings is old_settings
        assert config.settings.security_profile == "stricter-dev"
        assert config.settings.require_pkce is True
        assert config.settings.password_hashing is True
        assert config.settings.rate_limit_enabled is True
        assert config.settings.debug is False
        assert config.settings.audience != "changed-on-disk"
        # registry: same plugin instances, same policy, nothing half-applied
        assert config.hooks.plugins == old_plugins
        assert config.hooks.snapshot() == old_snapshot
        assert config.hooks.strict is False
        # fixing the file makes the next reload succeed and commit
        doc["plugins"] = {"keep": {}}
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(doc))
        with app.test_client() as client:
            assert client.post("/api/config/reload").status_code == 200
        assert config.settings.audience == "changed-on-disk"
        assert config.settings.security_profile == "stricter-dev" and config.settings.require_pkce is True
        assert config.hooks.strict is True
