#!/usr/bin/env python3
"""MCP stdio smoke test: drive the real `nanoidp-mcp` server end-to-end.

The unit tests call ``_execute_tool`` directly, which is why the stdio
entrypoint could crash at startup for years without a test noticing (#56).
This script exercises the actual transport: it launches ``nanoidp-mcp`` as a
subprocess, performs the MCP handshake, lists the tools and calls a couple of
read-only ones, asserting on the results.

Usage:
    python examples/mcp_smoke_test.py [--config ./config]

Exit code 0 on success, 1 on any failure.
"""

import argparse
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = 24


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

            result = await session.call_tool("get_keys_info", {})
            keys_info = json.loads(result.content[0].text)
            if "active_kid" not in keys_info and "kid" not in keys_info:
                print(f"[FAIL] get_keys_info missing kid: {keys_info!r}")
                return 1
            print("[OK] get_keys_info")

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
