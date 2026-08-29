#!/usr/bin/env python3
"""MCP stdio smoke test: drive the real `nanoidp-mcp` server end-to-end.

The unit tests call ``_execute_tool`` directly, which is why the stdio
entrypoint could crash at startup for years without a test noticing (#56).
This script exercises the actual transport: it launches ``nanoidp-mcp`` as a
subprocess, performs the MCP handshake, lists the tools and calls a couple of
read-only ones, asserting on the results.

Usage:
    python e2e/mcp_smoke_test.py [--config ./config]

Exit code 0 on success, 1 on any failure.
"""

import argparse
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Deliberately a hard number: the docs advertise the tool count, so growing or
# shrinking the MCP surface must consciously update both (metadata never lies).
EXPECTED_TOOLS = 26


async def run(config_dir: str) -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "nanoidp.mcp_server"],
        env={**os.environ, "NANOIDP_CONFIG_DIR": config_dir},
    )

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
            result = await session.call_tool("get_settings", {})
            settings_payload = json.loads(result.content[0].text)
            if len(settings_payload.get("settings_revision", "")) != 64:
                print(
                    f"[FAIL] get_settings settings_revision not a sha256 hex: "
                    f"{settings_payload.get('settings_revision')!r}"
                )
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
