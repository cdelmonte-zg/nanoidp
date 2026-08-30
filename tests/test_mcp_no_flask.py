"""
The stdio MCP process must not import Flask (#286).

Before the decomposition, mcp_server did `from .routes._auth import
verify_secret`, and routes/_auth.py imports Flask at module top - so every
`nanoidp-mcp` process carried the whole web framework to reach a three-line
compare_digest wrapper. verify_secret now lives in the framework-free
nanoidp.security; this pins the boundary in a clean subprocess (this test
process itself has Flask loaded via conftest, so the check must not run
in-process).
"""

import subprocess
import sys


def test_importing_mcp_server_does_not_import_flask():
    code = (
        "import sys; import nanoidp.mcp_server; "
        "sys.exit(1 if 'flask' in sys.modules else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"nanoidp.mcp_server pulled Flask into the process\n{result.stderr}"
    )
