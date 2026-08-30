"""`python -m nanoidp.mcp_server` entry (#286).

The pre-split module ran its own `if __name__ == "__main__"` guard; a
package needs this file for the same invocation (e2e/mcp_smoke_test.py and
any operator using -m). The console script `nanoidp-mcp` targets
nanoidp.mcp_server:main directly and never passes through here.
"""

from . import main

if __name__ == "__main__":
    main()
