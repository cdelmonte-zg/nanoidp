"""
Tests for the MCP audit log and key management tools (issue #48).

They mirror the HTTP API (/api/audit*, /api/keys*) so agent-driven test
workflows can inspect what the IdP recorded and rotate keys to exercise a
client's JWKS refresh handling.
"""

import logging
from pathlib import Path

import pytest

from nanoidp.config import get_config
from nanoidp.config_writer import LockNamespaceUnavailable, LockUnavailableError
from nanoidp.mcp_server import MUTATING_TOOLS, _execute_tool
from nanoidp.services import get_audit_log
from nanoidp.services.crypto import (
    EXTERNAL_KEYS_NOT_ROTATABLE,
    EXTERNAL_KEYS_NOT_ROTATABLE_KIND,
    KEYS_DIRECTORY_LOCK_UNAVAILABLE,
    KEYS_DIRECTORY_NOT_WRITABLE,
)
from nanoidp.services.key_directory import KeysDirectoryNotWritable


class TestAuditTools:
    @pytest.mark.asyncio
    async def test_get_audit_log_returns_logged_entries(self, app):
        with app.app_context():
            get_audit_log().log(
                event_type="token_request",
                endpoint="/token",
                method="POST",
                status="success",
                username="admin",
            )
            result = await _execute_tool("get_audit_log", {}, get_config())
        assert result["count"] >= 1
        assert any(e["event_type"] == "token_request" for e in result["entries"])

    @pytest.mark.asyncio
    async def test_get_audit_log_filters(self, app):
        with app.app_context():
            audit = get_audit_log()
            audit.log(event_type="a_event", endpoint="/a", method="GET", status="success")
            audit.log(event_type="b_event", endpoint="/b", method="GET", status="success")
            result = await _execute_tool(
                "get_audit_log", {"event_type": "a_event"}, get_config()
            )
        assert result["count"] == 1
        assert result["entries"][0]["event_type"] == "a_event"

    @pytest.mark.asyncio
    async def test_stats_and_clear(self, app):
        with app.app_context():
            config = get_config()
            get_audit_log().log(
                event_type="x", endpoint="/x", method="GET", status="success"
            )
            stats = await _execute_tool("get_audit_stats", {}, config)
            assert stats  # non-empty after logging

            cleared = await _execute_tool("clear_audit_log", {}, config)
            assert cleared["success"] is True
            after = await _execute_tool("get_audit_log", {}, config)
        assert after["count"] == 0


class TestKeyTools:
    @pytest.mark.asyncio
    async def test_get_keys_info(self, app):
        with app.app_context():
            info = await _execute_tool("get_keys_info", {}, get_config())
        assert info["active_kid"]
        assert "previous_kids" in info

    @pytest.mark.asyncio
    async def test_rotate_keys_changes_active_and_preserves_old(self, app):
        with app.app_context():
            config = get_config()
            before = await _execute_tool("get_keys_info", {}, config)
            result = await _execute_tool("rotate_keys", {}, config)
            after = await _execute_tool("get_keys_info", {}, config)

        assert result["success"] is True
        assert after["active_kid"] != before["active_kid"]
        # The old key remains available for verification (JWKS keeps it)
        assert before["active_kid"] in after["previous_kids"]


    @pytest.mark.asyncio
    async def test_rotate_keys_says_so_when_the_keys_directory_lock_cannot_be_had(self, app, monkeypatch):
        """The keys directory is shared between processes (#420). A lock
        that cannot be had in time is an answer of the tool, not an error
        out of it, and nothing is rotated."""
        from nanoidp import config_writer
        from nanoidp.services import key_directory

        monkeypatch.setattr(config_writer, "_LOCK_TIMEOUT_SECONDS", 0.2)
        with app.app_context():
            config = get_config()
            before = await _execute_tool("get_keys_info", {}, config)
            with key_directory._thread_lock:
                result = await _execute_tool("rotate_keys", {}, config)
            after = await _execute_tool("get_keys_info", {}, config)

        assert result == {"success": False, "error": KEYS_DIRECTORY_LOCK_UNAVAILABLE, "kind": "lock_timeout"}
        assert after["active_kid"] == before["active_kid"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "raised, kind, message",
        [
            (
                lambda d: KeysDirectoryNotWritable(Path(d), PermissionError(13, "Permission denied")),
                "keys_directory_not_writable",
                KEYS_DIRECTORY_NOT_WRITABLE,
            ),
            (
                lambda d: LockNamespaceUnavailable(f"{d} is not writable and holds no usable lock file"),
                "lock_namespace_unavailable",
                KEYS_DIRECTORY_NOT_WRITABLE,
            ),
            (
                lambda d: LockUnavailableError(
                    f"Timed out after 10.0s waiting for the write lock on {d}", kind="lock_timeout"
                ),
                "lock_timeout",
                KEYS_DIRECTORY_LOCK_UNAVAILABLE,
            ),
            (
                lambda d: LockUnavailableError(
                    f"Advisory locking is not supported on {d}/.nanoidp-write.lock", kind="lock_unsupported"
                ),
                "lock_unsupported",
                KEYS_DIRECTORY_LOCK_UNAVAILABLE,
            ),
        ],
    )
    async def test_a_refusal_of_the_keys_directory_is_said_without_naming_it(
        self, app, monkeypatch, caplog, raised, kind, message
    ):
        """The same refusal as /api/keys/rotate: the fixed message and the
        exception's kind, and the directory it names only in the log."""
        from nanoidp.services import crypto as crypto_module

        directory = "/srv/nanoidp/secret-keys-9f3a"
        service = crypto_module.get_crypto_service()
        monkeypatch.setattr(service, "rotate_keys", lambda: (_ for _ in ()).throw(raised(directory)))
        with app.app_context(), caplog.at_level(logging.WARNING, logger="nanoidp.services.crypto"):
            result = await _execute_tool("rotate_keys", {}, get_config())

        assert result == {"success": False, "error": message, "kind": kind}
        assert directory not in str(result)
        assert any(directory in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_external_keys_are_refused_with_the_kind_beside_the_fixed_message(self, app, monkeypatch):
        from nanoidp.services import crypto as crypto_module
        from nanoidp.services.crypto import ExternalKeysNotRotatable

        service = crypto_module.get_crypto_service()
        monkeypatch.setattr(service, "rotate_keys", lambda: (_ for _ in ()).throw(ExternalKeysNotRotatable()))
        with app.app_context():
            result = await _execute_tool("rotate_keys", {}, get_config())

        assert result == {
            "success": False,
            "error": EXTERNAL_KEYS_NOT_ROTATABLE,
            "kind": EXTERNAL_KEYS_NOT_ROTATABLE_KIND,
        }


class TestToolClassification:
    def test_mutating_tools_membership(self):
        assert "clear_audit_log" in MUTATING_TOOLS
        assert "rotate_keys" in MUTATING_TOOLS
        assert "get_audit_log" not in MUTATING_TOOLS
        assert "get_audit_stats" not in MUTATING_TOOLS
        assert "get_keys_info" not in MUTATING_TOOLS
