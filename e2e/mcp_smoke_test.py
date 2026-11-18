#!/usr/bin/env python3
"""MCP stdio smoke test: drive the real `nanoidp-mcp` server end-to-end.

The unit tests call ``_execute_tool`` directly, which is why the stdio
entrypoint could crash at startup for years without a test noticing (#56).
This script exercises the actual transport: it launches ``nanoidp-mcp`` as a
subprocess, performs the MCP handshake, lists the tools and calls a couple of
read-only ones, asserting on the results. A last leg breaks a COPY of the
configuration under a running server (#477); the directory given is never
written.

Usage:
    python e2e/mcp_smoke_test.py [--config ./config]

Exit code 0 on success, 1 on any failure.
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Deliberately a hard number: the docs advertise the tool count, so growing or
# shrinking the MCP surface must consciously update both (metadata never lies).
EXPECTED_TOOLS = 41


# What the parser says about _BROKEN; never part of an answer (#477).
_BROKEN = "oauth: [broken\n"
_PARSER_WORDS = ("parsing", "flow sequence", "line 1")


def _server(config_dir: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "nanoidp.mcp_server"],
        env={**os.environ, "NANOIDP_CONFIG_DIR": config_dir},
    )


def _copy_of(config_dir: str, into: Path) -> Path:
    """The configuration in a directory of its own, keys included, so a leg
    that breaks a file never touches the one this script was given."""
    copy = into / "config"
    copy.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(Path(config_dir) / name, copy / name)
    settings = yaml.safe_load((copy / "settings.yaml").read_text())
    settings.setdefault("jwt", {})["keys_dir"] = str(into / "keys")
    (copy / "settings.yaml").write_text(yaml.safe_dump(settings))
    return copy


async def run_with_files_that_do_not_load(config_dir: str) -> int:
    """#477, through the real entry point: a server started on a good
    configuration, whose settings.yaml is broken afterwards, answers
    save_config with the fixed text and writes nothing; a server started
    on the broken file refuses to start."""
    with tempfile.TemporaryDirectory() as scratch:
        copy = _copy_of(config_dir, Path(scratch))
        settings = copy / "settings.yaml"
        async with stdio_client(_server(str(copy))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                settings.write_text(_BROKEN)
                result = await session.call_tool("save_config", {})
                refused = json.loads(result.content[0].text)
                from nanoidp.refusal_texts import SAVE_FILES_UNLOADABLE_TEXT

                if (
                    refused.get("success") is not False
                    or refused.get("kind") != "configuration_unloadable"
                    or refused.get("error") != SAVE_FILES_UNLOADABLE_TEXT
                    or refused.get("retryable") is not False
                    or any(word in refused.get("error", "") for word in _PARSER_WORDS)
                ):
                    print(f"[FAIL] save_config over a broken file: {refused!r}")
                    return 1
                if settings.read_text() != _BROKEN:
                    print("[FAIL] save_config wrote over the broken file")
                    return 1
        print("[OK] save_config over a file that does not parse: configuration_unloadable, fixed text, nothing written")

        started = subprocess.run(
            [sys.executable, "-m", "nanoidp.mcp_server"],
            env={**os.environ, "NANOIDP_CONFIG_DIR": str(copy)},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if started.returncode != 1 or "error: configuration rejected:" not in started.stderr:
            print(f"[FAIL] a server on a broken file started or failed otherwise: {started.returncode} {started.stderr!r}")
            return 1
        print("[OK] a server on a file that does not parse refuses to start")
    return 0


async def run_with_a_tag_the_parser_refuses(config_dir: str) -> int:
    """#494, through the real entry point: a tagged value PyYAML refuses
    with a KeyError, not with its own error, is a refused configuration on
    reload and a finding on validate, never an internal error; and a
    server started on it refuses to start without a traceback."""
    with tempfile.TemporaryDirectory() as scratch:
        copy = _copy_of(config_dir, Path(scratch))
        users = copy / "users.yaml"
        async with stdio_client(_server(str(copy))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                users.write_text(users.read_text() + "zz_probe: !!bool maybe\n")
                refused = json.loads((await session.call_tool("reload_config", {})).content[0].text)
                if (
                    refused.get("success") is not False
                    or refused.get("kind") != "invalid"
                    or "users.yaml: not valid YAML: " not in refused.get("error", "")
                ):
                    print(f"[FAIL] reload_config over a tag the parser refuses: {refused!r}")
                    return 1
                validation = json.loads((await session.call_tool("validate_config", {})).content[0].text)
                errors = [f for f in validation.get("findings", []) if f.get("level") == "error"]
                if validation.get("valid") is not False or [f.get("file") for f in errors] != ["users.yaml"]:
                    print(f"[FAIL] validate_config over a tag the parser refuses: {validation!r}")
                    return 1
        print("[OK] a tag the parser refuses: reload_config kind invalid, validate_config one finding")

        started = subprocess.run(
            [sys.executable, "-m", "nanoidp.mcp_server"],
            env={**os.environ, "NANOIDP_CONFIG_DIR": str(copy)},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if (
            started.returncode != 1
            or "error: configuration rejected: users.yaml: not valid YAML: " not in started.stderr
            or "Traceback" in started.stderr
        ):
            print(f"[FAIL] a server on a tag the parser refuses: {started.returncode} {started.stderr!r}")
            return 1
        print("[OK] a server on a tag the parser refuses does not start, and says which file")
    return 0


async def run_with_a_file_where_a_rotation_writes(config_dir: str) -> int:
    """#492, through the real entry point: a file at ``previous`` in the
    keys directory refuses rotate_keys with the fixed text and the kind,
    the path stays off the wire, the active key is the same, and with the
    file gone the next rotation succeeds."""
    with tempfile.TemporaryDirectory() as scratch:
        copy = _copy_of(config_dir, Path(scratch))
        keys_dir = Path(scratch) / "keys"
        async with stdio_client(_server(str(copy))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                before = json.loads((await session.call_tool("get_keys_info", {})).content[0].text)
                (keys_dir / "previous").write_text("not a directory")
                result = await session.call_tool("rotate_keys", {})
                text = result.content[0].text
                from nanoidp.services.crypto import KEYS_DIRECTORY_NOT_WRITABLE

                if json.loads(text) != {
                    "success": False,
                    "error": KEYS_DIRECTORY_NOT_WRITABLE,
                    "kind": "keys_directory_not_writable",
                } or str(keys_dir) in text:
                    print(f"[FAIL] rotate_keys with a file at previous: {text!r}")
                    return 1
                after = json.loads((await session.call_tool("get_keys_info", {})).content[0].text)
                journal = keys_dir / ".rotation" / "journal.json"
                if after.get("active_kid") != before.get("active_kid") or journal.exists():
                    print(f"[FAIL] the refusal changed something: {before!r} -> {after!r}")
                    return 1
                print("[OK] a file where a rotation writes: rotate_keys refused, kind keys_directory_not_writable")

                (keys_dir / "previous").unlink()
                rotated = json.loads((await session.call_tool("rotate_keys", {})).content[0].text)
                if rotated.get("success") is not True or rotated.get("old_kid") != before.get("active_kid"):
                    print(f"[FAIL] rotate_keys with the file gone: {rotated!r}")
                    return 1
                print("[OK] with the file gone the rotation succeeds")
    return 0


def _set_runtime(copy: Path, runtime: dict) -> None:
    settings = yaml.safe_load((copy / "settings.yaml").read_text())
    settings["runtime"] = runtime
    (copy / "settings.yaml").write_text(yaml.safe_dump(settings))


async def run_with_a_store_inside_the_configuration(config_dir: str) -> int:
    """#426, point 10: the check and the start agree. A runtime.path that
    puts the SQLite store inside the configuration directory is an error
    for validate_config and for ``nanoidp validate-config``, as it is a
    refusal for a server started on it."""
    with tempfile.TemporaryDirectory() as scratch:
        copy = _copy_of(config_dir, Path(scratch))
        async with stdio_client(_server(str(copy))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                _set_runtime(copy, {"store": "sqlite", "path": "runtime.db"})
                validation = json.loads((await session.call_tool("validate_config", {})).content[0].text)
                errors = [f for f in validation.get("findings", []) if f.get("level") == "error"]
                if (
                    validation.get("valid") is not False
                    or [f.get("file") for f in errors] != ["settings.yaml"]
                    or "inside the configuration directory" not in errors[0].get("message", "")
                ):
                    print(f"[FAIL] validate_config over a store inside the configuration: {validation!r}")
                    return 1
        environment = {**os.environ, "NANOIDP_CONFIG_DIR": str(copy)}
        checked = subprocess.run(
            [sys.executable, "-m", "nanoidp", "validate-config", "--config", str(copy)],
            env=environment, capture_output=True, text=True, timeout=60,
        )
        started = subprocess.run(
            [sys.executable, "-m", "nanoidp.mcp_server"],
            env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
        )
        if checked.returncode != 1 or "inside the configuration directory" not in checked.stdout:
            print(f"[FAIL] validate-config over a store inside the configuration: {checked.returncode} {checked.stdout!r}")
            return 1
        if started.returncode != 1 or "inside the configuration directory" not in started.stderr:
            print(f"[FAIL] a server on a store inside the configuration: {started.returncode} {started.stderr!r}")
            return 1
        if (copy / "runtime.db").exists():
            print("[FAIL] a store was made inside the configuration directory")
            return 1
        print("[OK] a store inside the configuration: an error for validate_config and validate-config, as for the start")
    return 0


async def run_with_a_reload_after_the_save_that_cannot_end(config_dir: str) -> int:
    """#426, point 7: a save that declares a name a runtime identity has,
    while another writer holds the runtime store. The files are written
    and the reload is not made: the fixed text, reload_after_save,
    retryable false, nothing of the directory or of SQLite on the wire.
    For this cause, with the store free, reload_config completes it."""
    import sqlite3

    from nanoidp.refusal_texts import SAVE_RELOAD_INCOMPLETE_TEXT

    with tempfile.TemporaryDirectory() as scratch:
        copy = _copy_of(config_dir, Path(scratch))
        store = Path(scratch) / "state" / "runtime.db"
        _set_runtime(copy, {"store": "sqlite", "path": str(store)})
        async with stdio_client(_server(str(copy))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                identity = {"username": "smoke-collide", "password": "pw"}
                for tool in ("create_runtime_user", "create_user"):
                    made = json.loads((await session.call_tool(tool, identity)).content[0].text)
                    if made.get("success") is not True:
                        print(f"[FAIL] {tool}: {made!r}")
                        return 1
                other = sqlite3.connect(str(store), isolation_level=None)
                other.execute("BEGIN IMMEDIATE")
                try:
                    text = (await session.call_tool("save_config", {})).content[0].text
                finally:
                    other.execute("ROLLBACK")
                    other.close()
                if json.loads(text) != {
                    "success": False,
                    "error": SAVE_RELOAD_INCOMPLETE_TEXT,
                    "kind": "reload_after_save",
                    "retryable": False,
                } or scratch in text or "locked" in text:
                    print(f"[FAIL] save_config with the store held: {text!r}")
                    return 1
                if "smoke-collide" not in (copy / "users.yaml").read_text():
                    print("[FAIL] the save that answered reload_after_save wrote no file")
                    return 1
                reloaded = json.loads((await session.call_tool("reload_config", {})).content[0].text)
                left = json.loads((await session.call_tool("list_runtime_users", {})).content[0].text)
                if reloaded.get("success") is not True or left.get("users") != []:
                    print(f"[FAIL] reload_config after the store was freed: {reloaded!r} {left!r}")
                    return 1
        print("[OK] save_config with the store held: reload_after_save, fixed text; reload_config completes it")
    return 0


async def run_with_a_scenario(config_dir: str) -> int:
    """#402: the scenario tools over stdio. With the store of this process
    alone they refuse; with a shared one a scenario is armed against the
    schema the tool publishes, listed, read and removed with its user."""
    declaration = {
        "name": "smoke-scenario",
        "given": {"user": {"username": "smoke-scn-user", "password": "pw", "roles": ["USER"]}},
        "steps": [
            {"after": {"event": "token_issued", "grant_type": "refresh_token"}, "update_user": {"roles": ["ADMIN"]}}
        ],
    }
    async with stdio_client(_server(config_dir)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            alone = json.loads((await session.call_tool("arm_scenario", declaration)).content[0].text)
            if alone.get("code") != "MCP_RUNTIME_STORE_NOT_SHARED":
                print(f"[FAIL] arm_scenario with a store of this process alone: {alone!r}")
                return 1
    with tempfile.TemporaryDirectory() as scratch:
        copy = _copy_of(config_dir, Path(scratch))
        _set_runtime(copy, {"store": "sqlite", "path": str(Path(scratch) / "state" / "runtime.db")})
        async with stdio_client(_server(str(copy))) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def call(tool: str, arguments: dict) -> dict:
                    return json.loads((await session.call_tool(tool, arguments)).content[0].text)

                schema = {tool.name: tool.input_schema for tool in (await session.list_tools()).tools}["arm_scenario"]
                after = schema["$defs"]["Trigger"]["properties"]
                if after["event"].get("enum") != ["token_issued", "authorization_completed"] or (
                    "roles" not in schema["$defs"]["StepDeclaration"]["properties"]["update_user"]["properties"]
                ):
                    print(f"[FAIL] the schema of arm_scenario does not say its events and fields: {schema!r}")
                    return 1
                refused = await call("arm_scenario", {**declaration, "steps": [{"after": {"event": "nope"}, "update_user": {"roles": []}}]})
                armed = await call("arm_scenario", declaration)
                listed = await call("list_scenarios", {})
                read_back = await call("get_scenario", {"name": "smoke-scenario"})
                user = await call("get_runtime_user", {"username": "smoke-scn-user"})
                removed = await call("remove_scenario", {"name": "smoke-scenario"})
                after_it = await call("get_scenario", {"name": "smoke-scenario"})
                gone = await call("get_runtime_user", {"username": "smoke-scn-user"})
                if (
                    refused.get("code") != "MCP_INVALID_ARGUMENTS"
                    or armed.get("success") is not True
                    or armed["scenario"].get("state") != "armed"
                    or listed != {"scenarios": [armed["scenario"]], "count": 1}
                    or read_back != {"found": True, "scenario": armed["scenario"]}
                    or user.get("found") is not True
                    or removed != {"success": True, "deleted": "smoke-scenario", "user": "smoke-scn-user", "user_removed": True}
                    or after_it != {"found": False, "name": "smoke-scenario"}
                    or gone.get("found") is not False
                ):
                    print(
                        f"[FAIL] the scenario tools: refused={refused!r} armed={armed!r} listed={listed!r} "
                        f"read={read_back!r} user={user!r} removed={removed!r} after={after_it!r} gone={gone!r}"
                    )
                    return 1
        print("[OK] scenario tools: refused without a shared store; armed, listed, read and removed with one")
    return 0


async def run(config_dir: str) -> int:
    params = _server(config_dir)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[OK] MCP handshake (initialize)")

            tools = (await session.list_tools()).tools
            names = sorted(t.name for t in tools)
            if len(names) != EXPECTED_TOOLS:
                print(
                    f"[FAIL] expected {EXPECTED_TOOLS} tools, got {len(names)}: {names}"
                )
                return 1
            print(f"[OK] list_tools: {len(names)} tools")

            # Read-only calls through the real dispatch path
            result = await session.call_tool("list_users", {})
            payload = json.loads(result.content[0].text)
            users = payload.get("users", payload) if isinstance(payload, dict) else payload
            if not users:
                print(f"[FAIL] list_users returned no users: {payload!r}")
                return 1
            print(f"[OK] list_users: {len(users)} user(s)")

            # The runtime identity tools (#432) act on a store shared with a
            # running NanoIDP. With a store of this process's alone, which
            # is what the default configuration gives, they refuse and say
            # what to configure; nothing is created. Skipped on a directory
            # that does declare a shared store.
            result = await session.call_tool("list_runtime_users", {})
            runtime = json.loads(result.content[0].text)
            if runtime.get("code") == "MCP_RUNTIME_STORE_NOT_SHARED":
                if runtime.get("retryable") is not False or "runtime.store: sqlite" not in runtime.get("error", ""):
                    print(f"[FAIL] the refusal over a store that is not shared: {runtime!r}")
                    return 1
                print("[OK] list_runtime_users over a store of this process's alone: refused, and says why")
            elif "users" not in runtime:
                print(f"[FAIL] list_runtime_users: {runtime!r}")
                return 1
            else:
                print(f"[OK] list_runtime_users over a shared store: {runtime.get('count')} runtime user(s)")

            result = await session.call_tool("get_oidc_discovery", {})
            discovery = json.loads(result.content[0].text)
            if "issuer" not in discovery or "token_endpoint" not in discovery:
                print(f"[FAIL] discovery document incomplete: {discovery!r}")
                return 1
            print(f"[OK] get_oidc_discovery: issuer={discovery['issuer']}")

            # validate_config (#175 piece 4): the config the server is running
            # on must lint clean through the same loaders, and the call must
            # be inert (no hook, no plugin, no reload).
            result = await session.call_tool("validate_config", {})
            validation = json.loads(result.content[0].text)
            if not validation.get("valid"):
                print(f"[FAIL] validate_config reported the config invalid: {validation!r}")
                return 1
            print(
                f"[OK] validate_config: valid, {len(validation.get('findings', []))} finding(s)"
            )

            result = await session.call_tool("get_keys_info", {})
            keys_info = json.loads(result.content[0].text)
            if "active_kid" not in keys_info and "kid" not in keys_info:
                print(f"[FAIL] get_keys_info missing kid: {keys_info!r}")
                return 1
            print("[OK] get_keys_info")

            # Revision preconditions (#229 phase 5). Read tools hand out the
            # revision of the file the runtime was loaded from; save_config
            # with a deliberately WRONG revision must be refused with kind
            # 'conflict' before anything is written. Deliberately no
            # positive save here: this script may run against a checked-in
            # config directory, and the conflict branch is the one leg
            # guaranteed to leave every file byte-identical.
            result = await session.call_tool("list_users", {})
            users_payload = json.loads(result.content[0].text)
            users_revision = users_payload.get("users_revision", "")
            if len(users_revision) != 64:
                print(f"[FAIL] list_users users_revision not a sha256 hex: {users_revision!r}")
                return 1
            # extra_claims adds, never changes (#451): the tool refuses a
            # claim the grant or the user store decides, with the names.
            users = users_payload.get("users") or []
            first_user = users[0]["username"] if isinstance(users, list) else next(iter(users))
            result = await session.call_tool(
                "generate_token",
                {"username": first_user, "extra_claims": {"client_id": "x", "sub": "root"}},
            )
            refused = json.loads(result.content[0].text)
            if refused.get("success") is not False or refused.get("error") != (
                "'extra_claims' cannot set: client_id, sub"
            ):
                print(f"[FAIL] generate_token did not refuse a forged extra_claims: {refused!r}")
                return 1
            print("[OK] generate_token refuses forged extra_claims")
            result = await session.call_tool("get_settings", {})
            settings_payload = json.loads(result.content[0].text)
            if len(settings_payload.get("settings_revision", "")) != 64:
                print(
                    f"[FAIL] get_settings settings_revision not a sha256 hex: "
                    f"{settings_payload.get('settings_revision')!r}"
                )
                return 1
            # The four #441 settings reach an agent over stdio as the config
            # directory declares them, whichever directory this runs on
            from nanoidp.config import ConfigManager

            declared = ConfigManager(config_dir).settings
            expected = {
                "refresh_token_expiry_minutes": declared.refresh_token_expiry_minutes,
                "device_code_expiry_seconds": declared.device_code_expiry_seconds,
                "device_polling_interval": declared.device_polling_interval,
                "cors_allowed_origins": declared.cors_allowed_origins,
            }
            seen = {key: settings_payload.get(key, "missing") for key in expected}
            if seen != expected:
                print(f"[FAIL] get_settings timing/CORS fields: {seen!r}")
                return 1
            result = await session.call_tool(
                "save_config", {"expected_users_revision": "0" * 64}
            )
            conflict = json.loads(result.content[0].text)
            if conflict.get("success") is not False or conflict.get("kind") != "conflict":
                print(f"[FAIL] stale save_config not refused as a conflict: {conflict!r}")
                return 1
            result = await session.call_tool("list_users", {})
            after = json.loads(result.content[0].text).get("users_revision")
            if after != users_revision:
                print(
                    f"[FAIL] users.yaml moved despite the refused save: "
                    f"{users_revision} -> {after}"
                )
                return 1
            print("[OK] revision preconditions: read tools expose them, stale save refused")

            # NANOIDP_E2E_PLUGIN: the installed reference plugin, bootstrapped
            # through NANOIDP_BOOTSTRAP_PLUGIN, must be visible to an agent
            # through get_settings (#185 parity with /api/config).
            expected_plugin = os.environ.get("NANOIDP_E2E_PLUGIN")
            if expected_plugin:
                result = await session.call_tool("get_settings", {})
                settings = json.loads(result.content[0].text)
                block = settings.get("hooks") or {}
                names = [p.get("name") for p in block.get("plugins", [])]
                failed = [f.get("name") for f in block.get("plugins_failed", [])]
                if expected_plugin not in names:
                    print(f"[FAIL] plugin {expected_plugin!r} not in get_settings hooks: {names}, failed={failed}")
                    return 1
                print(f"[OK] get_settings lists plugin {expected_plugin!r} (hook API {block.get('hook_api_version')})")

    if await run_with_files_that_do_not_load(config_dir):
        return 1

    if await run_with_a_tag_the_parser_refuses(config_dir):
        return 1

    if await run_with_a_file_where_a_rotation_writes(config_dir):
        return 1

    if await run_with_a_store_inside_the_configuration(config_dir):
        return 1

    if await run_with_a_reload_after_the_save_that_cannot_end(config_dir):
        return 1

    if await run_with_a_scenario(config_dir):
        return 1

    print("\n[SUCCESS] MCP stdio smoke test passed")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", default="./config", help="Config directory (default: ./config)"
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.config)))


if __name__ == "__main__":
    main()
