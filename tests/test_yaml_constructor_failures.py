"""A document the YAML parser refuses outside its own error type (#494).

``yaml.safe_load`` answers some documents with an exception that is not a
``yaml.YAMLError``: a tag whose constructor refuses the value, or nesting
deeper than the interpreter's stack. These left the contract of a refused
configuration at every entry point (a traceback at startup, a 500 on reload,
an internal error on the MCP surface) and the freshness check took them for
temporary. They are documents that are not valid YAML, decided by the bytes.
"""

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from nanoidp import config as config_module
from nanoidp import config_writer
from nanoidp.app import create_app
from nanoidp.config import ConfigManager, ConfigurationRejected, a_retry_may_load, init_config
from nanoidp.config_writer import DocumentUnreadable, compare_and_replace_many
from nanoidp.serialization import INVALID_TAG_VALUE, NESTING_TOO_DEEP, NotValidYaml, parse_yaml
from nanoidp.services import runtime_store
from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

_REPO = Path(__file__).resolve().parent.parent
_FILES = ("settings.yaml", "users.yaml")

# What the census of #494 found, by the exception PyYAML answers with.
_REFUSED = {
    "bool-KeyError": ("zz_probe: !!bool maybe\n", KeyError),
    "int-IndexError": ("zz_probe: !!int ''\n", IndexError),
    "timestamp-AttributeError": ("zz_probe: !!timestamp x\n", AttributeError),
    "nesting-RecursionError": ("zz_probe: " + "[" * 5000 + "]" * 5000 + "\n", RecursionError),
    "int-ValueError": ("zz_probe: !!int x\n", ValueError),
}
_DOCUMENTS = pytest.mark.parametrize("text", [text for text, _ in _REFUSED.values()], ids=list(_REFUSED))
_EACH_FILE = pytest.mark.parametrize("name", _FILES)


def _config_dir(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in _FILES:
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(document))
    _age(config_dir)
    return config_dir


def _age(config_dir, seconds=60):
    """Written a while before they are read, so that their stat is trusted."""
    for name in _FILES:
        then = time.time() - seconds
        os.utime(config_dir / name, (then, then))


def _append(config_dir, name, text):
    path = config_dir / name
    path.write_text(path.read_text() + text)
    _age(config_dir, seconds=30)


class TestTheParse:
    @pytest.mark.parametrize("text, raised", list(_REFUSED.values()), ids=list(_REFUSED))
    def test_what_the_parser_refuses_outside_its_own_error_is_not_valid_yaml(self, text, raised):
        with pytest.raises(NotValidYaml) as refused:
            parse_yaml(text.encode(), "settings.yaml")

        reason = NESTING_TOO_DEEP if raised is RecursionError else INVALID_TAG_VALUE
        assert str(refused.value) == f"settings.yaml: not valid YAML: {reason}"
        assert refused.value.reason == reason

    def test_the_two_reasons_are_the_texts_a_caller_reads(self):
        assert INVALID_TAG_VALUE == "invalid value for an explicit YAML tag"
        assert NESTING_TOO_DEEP == "nesting exceeds the parser's recursion limit"

    @pytest.mark.parametrize(
        "text, raised",
        [
            ("password: !!int hunter2-the-secret\n", "ValueError"),
            ("password: !!bool HUNTER2-the-secret\n", "KeyError"),
            ("key: !!bool |\n  -----BEGIN KEY-----\n" + "  hunter2-the-secret\n" * 40, "KeyError"),
            ("password: !!timestamp hunter2-the-secret\n", "AttributeError"),
        ],
        ids=["int", "bool", "bool-block", "timestamp"],
    )
    def test_the_value_the_parser_refused_is_said_nowhere(self, caplog, text, raised):
        """The constructor's message quotes the value, whole: neither the
        answer, nor the log, nor a traceback of the refusal repeats it."""
        import traceback

        with caplog.at_level(logging.DEBUG):
            with pytest.raises(NotValidYaml) as refused:
                parse_yaml(text, "users.yaml")

        said = str(refused.value) + caplog.text + "".join(traceback.format_exception(refused.value))
        assert "hunter2" not in said.lower()
        assert refused.value.__cause__ is None
        assert refused.value.__context__ is None
        assert f"users.yaml: the YAML parser refused the document with a {raised}" in caplog.text

    def test_it_is_a_value_error_as_every_refused_document_is(self):
        assert issubclass(NotValidYaml, ValueError)

    def test_the_parsers_own_error_passes_as_it_is(self):
        with pytest.raises(yaml.YAMLError) as refused:
            parse_yaml(b"zz: [broken\n", "settings.yaml")

        assert not isinstance(refused.value, NotValidYaml)

    def test_a_document_that_parses_is_returned(self):
        assert parse_yaml(b"a: !!int 3\n", "settings.yaml") == {"a": 3}
        assert parse_yaml(b"", "settings.yaml") is None

    @pytest.mark.parametrize("unexpected", [TypeError, RuntimeError, AssertionError, LookupError, ArithmeticError])
    def test_any_other_failure_of_the_parser_stays_what_it_is(self, monkeypatch, unexpected):
        """The list is the census's, not ``Exception``: a failure nobody has
        seen a document cause is not reported as an invalid document. The
        base classes of the listed ones included."""

        def failing(raw):
            raise unexpected("not a document's doing")

        monkeypatch.setattr(yaml, "safe_load", failing)

        with pytest.raises(unexpected) as raised:
            parse_yaml(b"a: 1\n", "settings.yaml")

        assert type(raised.value) is unexpected


class TestTheLoad:
    @_DOCUMENTS
    @_EACH_FILE
    def test_it_is_a_refused_configuration_that_names_the_file(self, tmp_path, text, name):
        config_dir = _config_dir(tmp_path)
        _append(config_dir, name, text)

        with pytest.raises(ConfigurationRejected) as rejected:
            ConfigManager(str(config_dir))

        assert rejected.value.kind == "invalid"
        assert rejected.value.message.startswith(f"{name}: not valid YAML: ")
        assert str(config_dir) not in rejected.value.message
        assert rejected.value.message.endswith((INVALID_TAG_VALUE, NESTING_TOO_DEEP))
        assert a_retry_may_load(rejected.value) is False

    @_EACH_FILE
    def test_a_refused_secret_reaches_neither_the_answer_nor_the_log(self, tmp_path, caplog, name):
        import traceback

        config_dir = _config_dir(tmp_path)
        _append(config_dir, name, "zz_probe: !!bool hunter2-the-secret\n")

        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ConfigurationRejected) as rejected:
                ConfigManager(str(config_dir))

        said = rejected.value.message + caplog.text + "".join(traceback.format_exception(rejected.value))
        assert "hunter2" not in said

    @pytest.mark.parametrize("unexpected", [RuntimeError, TypeError, LookupError])
    def test_a_failure_of_the_parser_nobody_listed_is_not_a_refused_configuration(
        self, tmp_path, monkeypatch, unexpected
    ):
        """At the load itself, first and again: the read of the declared
        mode before the first load reports nothing, by design."""
        config_dir = _config_dir(tmp_path)
        config = ConfigManager(str(config_dir))

        def failing(raw):
            raise unexpected("not a document's doing")

        monkeypatch.setattr(yaml, "safe_load", failing)

        with pytest.raises(unexpected) as raised:
            config.reload()
        assert type(raised.value) is unexpected
        with pytest.raises(unexpected) as raised:
            ConfigManager(str(config_dir))
        assert type(raised.value) is unexpected


class TestStartup:
    def _start(self, module, config_dir):
        env = dict(os.environ, PYTHONPATH=str(_REPO / "src"), PORT="8398", NANOIDP_CONFIG_DIR=str(config_dir))
        return subprocess.run(
            [sys.executable, "-m", module, *(["--config", str(config_dir)] if module == "nanoidp" else [])],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )

    @_DOCUMENTS
    def test_the_server_says_a_configuration_error_not_a_traceback(self, tmp_path, text):
        config_dir = _config_dir(tmp_path)
        _append(config_dir, "settings.yaml", text)

        result = self._start("nanoidp", config_dir)

        assert result.returncode == 1
        assert "error: configuration rejected: settings.yaml: not valid YAML: " in result.stderr
        assert "Traceback" not in result.stderr

    @_EACH_FILE
    def test_the_mcp_server_says_a_configuration_error_not_a_traceback(self, tmp_path, name):
        config_dir = _config_dir(tmp_path)
        _append(config_dir, name, _REFUSED["bool-KeyError"][0])

        result = self._start("nanoidp.mcp_server", config_dir)

        assert result.returncode == 1
        assert f"error: configuration rejected: {name}: not valid YAML: " in result.stderr
        assert "Traceback" not in result.stderr


class TestReloadOverHttp:
    @_DOCUMENTS
    @_EACH_FILE
    def test_it_is_a_422_of_kind_invalid(self, tmp_path, text, name):
        config_dir = _config_dir(tmp_path)
        app = create_app(str(config_dir))
        app.config["TESTING"] = True
        app.config["PROPAGATE_EXCEPTIONS"] = False
        _append(config_dir, name, text)

        response = app.test_client().post("/api/config/reload")

        assert response.status_code == 422
        assert response.get_json()["kind"] == "invalid"
        assert response.get_json()["error"] in (
            f"{name}: not valid YAML: {INVALID_TAG_VALUE}",
            f"{name}: not valid YAML: {NESTING_TOO_DEEP}",
        )


@pytest.fixture
def loaded(tmp_path, monkeypatch):
    import nanoidp.mcp_server as mcp

    config_dir = _config_dir(tmp_path)
    monkeypatch.setattr(mcp, "_readonly_mode", False)
    monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
    monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
    init_config(str(config_dir))
    return config_dir


def _payload(result):
    import json

    return json.loads(result.content[0].text)


class TestTheMcpSurface:
    @_DOCUMENTS
    @_EACH_FILE
    async def test_reload_config_answers_kind_invalid(self, loaded, mcp_call_tool, text, name):
        _append(loaded, name, text)

        payload = _payload(await mcp_call_tool("reload_config", {}))

        assert payload.get("code") != "MCP_INTERNAL_ERROR"
        assert payload["success"] is False
        assert payload["kind"] == "invalid"
        assert f"{name}: not valid YAML: " in payload["error"]

    @_DOCUMENTS
    @_EACH_FILE
    async def test_validate_config_reports_a_finding(self, loaded, mcp_call_tool, text, name):
        _append(loaded, name, text)

        payload = _payload(await mcp_call_tool("validate_config", {}))

        assert payload.get("code") != "MCP_INTERNAL_ERROR"
        assert payload["valid"] is False
        findings = [finding for finding in payload["findings"] if finding["level"] == "error"]
        assert [finding["file"] for finding in findings] == [name]
        assert "not valid YAML" in findings[0]["message"]


class TestValidateConfig:
    @_DOCUMENTS
    @pytest.mark.parametrize("name", [*_FILES, "bootstrap.yaml"])
    def test_the_command_reports_a_finding_and_exits_1(self, tmp_path, capsys, text, name):
        from nanoidp.__main__ import validate_config_command

        config_dir = _config_dir(tmp_path)
        if name == "bootstrap.yaml":
            (config_dir / name).write_text(text)
        else:
            _append(config_dir, name, text)

        code = validate_config_command(str(config_dir), False)

        out = capsys.readouterr().out
        assert code == 1
        assert f"{config_dir / name}: not valid YAML: " in out
        assert "1 error(s)" in out


class TestFreshness:
    @pytest.fixture
    def shared(self, tmp_path):
        config_dir = _config_dir(tmp_path)
        store = SqliteRuntimeStore(tmp_path / "state" / "runtime.db")
        runtime_store.publish_runtime_store(store, ("memory",))
        return config_dir, ConfigManager(str(config_dir))

    @_DOCUMENTS
    @_EACH_FILE
    def test_the_files_are_refused_until_their_bytes_change(self, shared, monkeypatch, text, name):
        config_dir, config = shared
        # No wait between two tries of a temporary failure: one that is
        # taken for temporary is loaded again at the next look.
        monkeypatch.setattr(config_module, "_TRANSIENT_RETRY_SECONDS", 0.0)
        loads = []
        real = config.reload_local
        monkeypatch.setattr(config, "reload_local", lambda: (loads.append(1), real())[1])
        good = (config_dir / name).read_text()
        _append(config_dir, name, text)

        assert config.refresh_if_changed() is False
        assert config.refresh_if_changed() is False
        # Touched, same bytes: looked at again, and still not loaded.
        _age(config_dir, seconds=20)
        assert config.refresh_if_changed() is False

        assert len(loads) == 1

        (config_dir / name).write_text(good + "\n# fixed\n")
        _age(config_dir, seconds=10)
        assert config.refresh_if_changed() is True
        assert len(loads) == 2


class TestTheWritersPrecondition:
    """Phase 1 reads bytes and parses nothing (#477 review): only the OS
    refusing the read is the document's to answer for."""

    def _touch(self, document):
        document["touched"] = True

    def test_a_read_the_os_refuses_is_a_document_unreadable_for_now(self, tmp_path, monkeypatch):
        on_disk = tmp_path / "settings.yaml"
        on_disk.write_text("a: 1\n")

        def refusing(file_path):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(config_writer, "current_revision", refusing)

        with pytest.raises(DocumentUnreadable) as refused:
            compare_and_replace_many([(on_disk, None, self._touch)])

        assert refused.value.temporary is True
        assert "settings.yaml" in refused.value.message
        assert on_disk.read_text() == "a: 1\n"

    @pytest.mark.parametrize("unexpected", [RuntimeError, ValueError, KeyError])
    def test_any_other_failure_there_is_not_the_documents(self, tmp_path, monkeypatch, unexpected):
        on_disk = tmp_path / "settings.yaml"
        on_disk.write_text("a: 1\n")

        def failing(file_path):
            raise unexpected("ours")

        monkeypatch.setattr(config_writer, "current_revision", failing)

        with pytest.raises(unexpected) as raised:
            compare_and_replace_many([(on_disk, None, self._touch)])

        assert type(raised.value) is unexpected
        assert on_disk.read_text() == "a: 1\n"
