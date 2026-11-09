"""One answer per configuration condition on the MCP surface (#477).

The MCP dispatcher and save_config answered a configuration that does not
load, and a lock that could not be taken, with the parser's or the lock's
own text, and filed a first load that failed as an internal error with a
traceback. The HTTP app answers the same conditions with fixed texts and
keeps the detail in the log. Retryability of a lock refusal is decided on
the exception, once.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigurationRejected, DeclaredConfigurationUnloadable, a_retry_may_load
from nanoidp.config_writer import (
    DocumentNotEditable,
    DocumentUnreadable,
    LockNamespaceUnavailable,
    LockUnavailableError,
    compare_and_replace_many,
)
from nanoidp.refusal_texts import (
    CONFIGURATION_UNAVAILABLE_TEXT,
    CONFIGURATION_UNLOADABLE_TEXT,
    NO_CONFIGURATION_TEXT,
    SAVE_FILES_NOT_EDITABLE_TEXT,
    SAVE_FILES_UNAVAILABLE_TEXT,
    SAVE_FILES_UNLOADABLE_TEXT,
)

_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"
_BROKEN = "oauth: [broken\n"
# What the parser says about _BROKEN; never part of an answer.
_PARSER_WORDS = ("parsing", "flow sequence", "line 1")
_NOT_ROOT = pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0, reason="mode bits do not refuse here"
)


def _config_dir(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for file in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO_CONFIG / file, config_dir / file)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(document))
    return config_dir


def _payload(result):
    return json.loads(result.content[0].text)


def _no_parser_text(text):
    return not any(word in text for word in _PARSER_WORDS)


@pytest.fixture
def unloaded(monkeypatch):
    """No configuration loaded yet: the first tool call loads it."""
    import nanoidp.mcp_server as mcp

    monkeypatch.setattr("nanoidp.config._config", None)
    monkeypatch.setattr(mcp, "_readonly_mode", False)
    monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)


class TestRetryableIsDecidedOnTheLockRefusal:
    @pytest.mark.parametrize(
        "kind, retryable",
        [
            ("lock_timeout", True),
            ("freshness_in_progress", True),
            ("lock_unsupported", False),
            ("lock_unavailable", False),
        ],
    )
    def test_a_lock_refusal_says_whether_coming_back_helps(self, kind, retryable):
        assert LockUnavailableError("detail", kind=kind).retryable is retryable

    def test_a_directory_with_no_lock_namespace_is_not_retryable(self):
        refused = LockNamespaceUnavailable("detail", kind="lock_namespace_unavailable")
        assert refused.retryable is False


class TestARetryMayLoad:
    def test_files_that_do_not_parse_are_not_worth_a_retry(self):
        rejected = ConfigurationRejected("bad yaml", kind="invalid")
        assert a_retry_may_load(rejected) is False

    def test_an_io_error_on_the_way_is(self):
        try:
            try:
                raise OSError("EIO")
            except OSError as exc:
                raise ConfigurationRejected("EIO", kind="invalid") from exc
        except ConfigurationRejected as rejected:
            assert a_retry_may_load(rejected) is True

    def test_an_activation_is(self):
        assert a_retry_may_load(ConfigurationRejected("keys", kind="activation")) is True

    def test_a_directory_this_process_cannot_write_is_not(self):
        try:
            try:
                try:
                    raise LockNamespaceUnavailable("/keys", kind="lock_namespace_unavailable")
                except LockNamespaceUnavailable as exc:
                    raise ValueError("JWT signing configuration cannot be activated") from exc
            except ValueError as exc:
                raise ConfigurationRejected(str(exc), kind="activation") from exc
        except ConfigurationRejected as rejected:
            assert a_retry_may_load(rejected) is False

    @pytest.mark.parametrize("kind, retryable", [("lock_timeout", True), ("lock_unsupported", False)])
    def test_a_lock_behind_the_load_decides_by_its_kind(self, kind, retryable):
        try:
            try:
                raise LockUnavailableError("held", kind=kind)
            except LockUnavailableError as exc:
                raise ConfigurationRejected(str(exc), kind=exc.kind) from exc
        except ConfigurationRejected as rejected:
            assert a_retry_may_load(rejected) is retryable


@pytest.mark.asyncio
class TestTheFirstLoad:
    async def test_files_that_do_not_parse_answer_the_fixed_text(
        self, tmp_path, monkeypatch, unloaded, mcp_call_tool, caplog
    ):
        config_dir = _config_dir(tmp_path)
        (config_dir / "settings.yaml").write_text(_BROKEN)
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))

        with caplog.at_level(logging.WARNING):
            result = await mcp_call_tool("get_oidc_discovery", {})

        assert result.is_error is True
        assert _payload(result) == {
            "error": NO_CONFIGURATION_TEXT,
            "code": "MCP_CONFIGURATION_UNAVAILABLE",
            "tool": "get_oidc_discovery",
            "retryable": False,
        }
        # The detail is the operator's, in the log, and no traceback: a
        # configuration they wrote wrong is no fault of the server.
        assert any("flow sequence" in record.getMessage() for record in caplog.records)
        assert all(record.exc_info is None for record in caplog.records)

    @pytest.mark.parametrize(
        "rejected, retryable",
        [
            (ConfigurationRejected("the signing service: /keys", kind="activation"), True),
            (ConfigurationRejected("/config/settings.yaml: bad", kind="invalid"), False),
        ],
    )
    async def test_retryable_says_whether_coming_back_may_load(
        self, monkeypatch, unloaded, mcp_call_tool, rejected, retryable
    ):
        import nanoidp.mcp_server as mcp

        def refuse(*args, **kwargs):
            raise rejected

        monkeypatch.setattr(mcp, "init_config", refuse)
        payload = _payload(await mcp_call_tool("list_users", {}))

        assert payload["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert payload["error"] == NO_CONFIGURATION_TEXT
        assert payload["retryable"] is retryable

    async def test_a_lock_behind_the_first_load_decides_retryable_by_its_kind(
        self, monkeypatch, unloaded, mcp_call_tool
    ):
        import nanoidp.mcp_server as mcp

        def refuse(*args, **kwargs):
            try:
                raise LockUnavailableError("on /config/.lock", kind="lock_unsupported")
            except LockUnavailableError as exc:
                raise ConfigurationRejected(str(exc), kind=exc.kind) from exc

        monkeypatch.setattr(mcp, "init_config", refuse)
        payload = _payload(await mcp_call_tool("list_users", {}))

        assert payload["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert payload["error"] == NO_CONFIGURATION_TEXT
        assert payload["retryable"] is False

    async def test_a_plugin_that_refuses_the_first_load_is_no_internal_error(
        self, monkeypatch, unloaded, mcp_call_tool
    ):
        import nanoidp.mcp_server as mcp
        from nanoidp.hooks import HookError

        def refuse(*args, **kwargs):
            raise HookError("before_load hook exited 1", kind="before_load")

        monkeypatch.setattr(mcp, "init_config", refuse)
        payload = _payload(await mcp_call_tool("list_users", {}))

        assert payload["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert payload["error"] == NO_CONFIGURATION_TEXT
        # Outside the two files: coming back may load.
        assert payload["retryable"] is True

    @_NOT_ROOT
    @pytest.mark.parametrize("keys", [".", "keys"], ids=["present-read-only", "absent-cannot-be-created"])
    async def test_a_keys_directory_this_process_cannot_write_is_not_retryable(
        self, tmp_path, monkeypatch, unloaded, mcp_call_tool, keys
    ):
        config_dir = _config_dir(tmp_path)
        read_only = tmp_path / "read-only-keys"
        read_only.mkdir()
        settings = config_dir / "settings.yaml"
        document = yaml.safe_load(settings.read_text())
        document["jwt"]["keys_dir"] = str((read_only / keys).resolve())
        settings.write_text(yaml.safe_dump(document))
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
        read_only.chmod(0o555)
        try:
            payload = _payload(await mcp_call_tool("list_users", {}))
        finally:
            read_only.chmod(0o755)

        assert payload["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert payload["error"] == NO_CONFIGURATION_TEXT
        assert payload["retryable"] is False

    async def test_any_other_failure_stays_an_internal_error(self, monkeypatch, unloaded, mcp_call_tool):
        import nanoidp.mcp_server as mcp

        def boom(*args, **kwargs):
            raise RuntimeError("a defect")

        monkeypatch.setattr(mcp, "init_config", boom)
        payload = _payload(await mcp_call_tool("list_users", {}))

        assert payload["code"] == "MCP_INTERNAL_ERROR"


@pytest.mark.asyncio
class TestAToolCheckedAgainstFilesThatDoNotLoad:
    @pytest.mark.parametrize(
        "temporary, text",
        [(True, CONFIGURATION_UNAVAILABLE_TEXT), (False, CONFIGURATION_UNLOADABLE_TEXT)],
    )
    async def test_answers_the_texts_of_the_http_app(
        self, tmp_path, monkeypatch, unloaded, mcp_call_tool, caplog, temporary, text
    ):
        import nanoidp.mcp_server as mcp

        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(_config_dir(tmp_path)))

        async def refuse(*args, **kwargs):
            raise DeclaredConfigurationUnloadable(
                "the configuration files in /config do not load: while parsing", temporary=temporary
            )

        monkeypatch.setattr(mcp, "_execute_tool", refuse)
        with caplog.at_level(logging.WARNING):
            result = await mcp_call_tool("list_users", {})

        assert result.is_error is True
        assert _payload(result) == {
            "error": text,
            "code": "MCP_CONFIGURATION_UNAVAILABLE",
            "tool": "list_users",
            "retryable": temporary,
        }
        assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.asyncio
class TestTheFreshnessLock:
    async def test_the_lock_text_stays_in_the_log(self, tmp_path, monkeypatch, mcp_call_tool, caplog):
        from nanoidp.config import init_config
        from nanoidp.services import runtime_store
        from nanoidp.services.sqlite_runtime_store import SqliteRuntimeStore

        config_dir = _config_dir(tmp_path)
        runtime_store.publish_runtime_store(SqliteRuntimeStore(tmp_path / "runtime.db"), ("memory",))
        config = init_config(str(config_dir))

        def unavailable():
            raise LockUnavailableError(f"waiting for the write lock on {config_dir}", kind="lock_timeout")

        monkeypatch.setattr(config, "refresh_if_changed", unavailable)
        with caplog.at_level(logging.WARNING):
            payload = _payload(await mcp_call_tool("list_users", {}))

        assert payload["code"] == "MCP_CONFIGURATION_UNAVAILABLE"
        assert str(config_dir) not in payload["error"]
        assert payload["retryable"] is True
        assert any(str(config_dir) in record.getMessage() for record in caplog.records)


@pytest.fixture
def loaded(tmp_path, monkeypatch, unloaded):
    from nanoidp.config import init_config

    config_dir = _config_dir(tmp_path)
    monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(config_dir))
    init_config(str(config_dir))
    return config_dir


@pytest.mark.asyncio
class TestSaveConfig:
    async def test_a_file_on_disk_that_does_not_parse_is_configuration_unloadable(
        self, loaded, mcp_call_tool, caplog
    ):
        (loaded / "settings.yaml").write_text(_BROKEN)

        with caplog.at_level(logging.WARNING):
            result = await mcp_call_tool("save_config", {})

        payload = _payload(result)
        assert result.is_error is True
        assert payload["success"] is False
        assert payload["kind"] == "configuration_unloadable"
        assert payload["error"] == SAVE_FILES_UNLOADABLE_TEXT
        assert payload["retryable"] is False
        assert _no_parser_text(payload["error"])
        # Nothing was written, the users file included.
        assert (loaded / "settings.yaml").read_text() == _BROKEN
        assert any("flow sequence" in record.getMessage() for record in caplog.records)

    async def test_a_file_on_disk_that_is_not_utf_8_is_not_retryable(self, loaded, mcp_call_tool):
        (loaded / "users.yaml").write_bytes(b"users: caf\xe9\n")

        payload = _payload(await mcp_call_tool("save_config", {}))

        assert payload["kind"] == "configuration_unloadable"
        assert payload["error"] == SAVE_FILES_UNLOADABLE_TEXT
        assert payload["retryable"] is False

    async def test_a_tag_whose_value_does_not_construct_is_not_retryable(self, loaded, mcp_call_tool):
        (loaded / "settings.yaml").write_text("config_version: !!int invalid-demo-value\n")

        payload = _payload(await mcp_call_tool("save_config", {}))

        assert payload["kind"] == "configuration_unloadable"
        assert payload["error"] == SAVE_FILES_UNLOADABLE_TEXT
        assert payload["retryable"] is False

    @_NOT_ROOT
    async def test_a_file_on_disk_the_os_refuses_is_retryable(self, loaded, mcp_call_tool):
        users = loaded / "users.yaml"
        before = users.read_bytes()
        users.chmod(0)
        try:
            payload = _payload(await mcp_call_tool("save_config", {}))
        finally:
            users.chmod(0o644)

        # The kind of the failed read; whether coming back helps is the OS's,
        # as a load classifies an OSError.
        assert payload["kind"] == "configuration_unloadable"
        assert payload["error"] == SAVE_FILES_UNAVAILABLE_TEXT
        assert payload["retryable"] is True
        assert users.read_bytes() == before

    async def test_a_file_that_repeats_a_key_loads_and_is_not_editable(self, loaded, mcp_call_tool, caplog):
        users = loaded / "users.yaml"
        repeated = users.read_text() + "default_user: admin\ndefault_user: admin\n"
        users.write_text(repeated)

        reloaded = _payload(await mcp_call_tool("reload_config", {}))
        with caplog.at_level(logging.WARNING):
            payload = _payload(await mcp_call_tool("save_config", {}))

        assert reloaded["success"] is True
        assert payload == {
            "success": False,
            "error": SAVE_FILES_NOT_EDITABLE_TEXT,
            "kind": "configuration_not_editable",
            "retryable": False,
        }
        assert users.read_text() == repeated
        assert any("duplicate" in record.getMessage() for record in caplog.records)

    @pytest.mark.parametrize("kind, retryable", [("lock_timeout", True), ("lock_unsupported", False)])
    async def test_a_lock_refusal_answers_a_fixed_text(
        self, loaded, mcp_call_tool, monkeypatch, caplog, kind, retryable
    ):
        from nanoidp.config import get_config

        def refuse(**kwargs):
            raise LockUnavailableError(f"waiting for the write lock on {loaded}", kind=kind)

        monkeypatch.setattr(get_config(), "save", refuse)
        with caplog.at_level(logging.WARNING):
            payload = _payload(await mcp_call_tool("save_config", {}))

        assert payload["success"] is False
        assert payload["kind"] == kind
        assert payload["retryable"] is retryable
        assert str(loaded) not in payload["error"]
        assert any(str(loaded) in record.getMessage() for record in caplog.records)


class TestTheWriterNamesAnUnreadableDocument:
    def test_a_document_that_repeats_a_key_is_not_editable(self, tmp_path):
        on_disk = tmp_path / "users.yaml"
        on_disk.write_text("a: 1\na: 2\n")

        with pytest.raises(DocumentNotEditable):
            compare_and_replace_many([(on_disk, None, lambda document: None)])

        assert on_disk.read_text() == "a: 1\na: 2\n"

    @pytest.mark.parametrize(
        "content",
        [
            b"users: caf\xe9\n",
            b"- a\n",
            b"just a string\n",
            # Tags whose constructor refuses the value: a ValueError, an
            # IndexError and a KeyError out of ruamel, none a YAMLError.
            b"config_version: !!int invalid-demo-value\n",
            b"config_version: !!float nope\n",
            b"config_version: !!bool maybe\n",
        ],
        ids=["not-utf-8", "a-list", "a-scalar", "bad-int", "bad-float", "bad-bool"],
    )
    def test_what_the_loader_refuses_is_refused_before_anything_is_written(self, tmp_path, content):
        on_disk = tmp_path / "settings.yaml"
        on_disk.write_bytes(content)

        def touch(document):
            document["touched"] = True

        with pytest.raises(DocumentUnreadable):
            compare_and_replace_many([(on_disk, None, touch)])

        assert on_disk.read_bytes() == content

    def test_a_document_that_does_not_parse_is_refused_before_anything_is_written(self, tmp_path):
        good = tmp_path / "users.yaml"
        good.write_text("users: {}\n")
        broken = tmp_path / "settings.yaml"
        broken.write_text(_BROKEN)

        def touch(document):
            document["touched"] = True

        with pytest.raises(DocumentUnreadable) as refused:
            compare_and_replace_many([(good, None, touch), (broken, None, touch)])

        assert "settings.yaml" in refused.value.message
        assert good.read_text() == "users: {}\n"
        assert broken.read_text() == _BROKEN


# UTF-8 whatever the locale: the loader reads the bytes as UTF-8, so the
# writer must too (#477 review). Under the C locale with coercion and UTF-8
# mode off, Python's default text encoding is ASCII.
_ASCII_LOCALE = {**os.environ, "LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}


@pytest.mark.skipif(os.name == "nt", reason="the C locale is a POSIX thing")
class TestTheConfigurationFilesAreUtf8WhateverTheLocale:
    def _run(self, script, tmp_path):
        src = Path(__file__).resolve().parent.parent / "src"
        env = {**_ASCII_LOCALE, "PYTHONPATH": str(src)}
        check = subprocess.run(
            [sys.executable, "-c", "import locale; print(locale.getpreferredencoding(False))"],
            env=env, capture_output=True, text=True,
        )
        if "UTF" in check.stdout.upper():
            pytest.skip("this interpreter reads the C locale as UTF-8")
        return subprocess.run(
            [sys.executable, "-c", textwrap.dedent(script), str(tmp_path)],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def test_a_valid_utf_8_file_is_edited_under_an_ascii_locale(self, tmp_path):
        on_disk = tmp_path / "users.yaml"
        on_disk.write_bytes("users:\n  jose:\n    name: Jos\u00e9\n".encode("utf-8"))

        result = self._run(
            """
            import sys
            from pathlib import Path
            from nanoidp.config_writer import compare_and_replace_many

            def rename(document):
                # chr(): the command line itself stays ASCII under this locale.
                document["users"]["jose"]["name"] = "Jos" + chr(0xE9) + " Mar" + chr(0xED) + "a"

            compare_and_replace_many([(Path(sys.argv[1]) / "users.yaml", None, rename)])
            """,
            tmp_path,
        )

        assert result.returncode == 0, result.stderr
        # Written as UTF-8 too, which is what the loader reads.
        assert yaml.safe_load(on_disk.read_bytes())["users"]["jose"]["name"] == "Jos\u00e9 Mar\u00eda"

    def test_a_literal_template_is_written_as_utf_8_under_an_ascii_locale(self, tmp_path):
        """The wizard's and init's writer: the same files, the same encoding."""
        result = self._run(
            """
            import sys
            from pathlib import Path
            from nanoidp.serialization import atomic_write_text

            atomic_write_text(Path(sys.argv[1]) / "users.yaml", "users: {}  # Jos" + chr(0xE9) + "\\n")
            """,
            tmp_path,
        )

        assert result.returncode == 0, result.stderr
        assert (tmp_path / "users.yaml").read_bytes() == "users: {}  # Jos\u00e9\n".encode("utf-8")
