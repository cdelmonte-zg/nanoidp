"""
Framework-free secret comparison, shared by the Flask routes and the MCP
server (#286).

This used to live in routes/_auth.py, which imports Flask at module top - so
the stdio MCP process transitively imported Flask just to reach a
compare_digest wrapper. routes/_auth.py re-exports it for its own callers;
the MCP package imports it from here.
"""

import secrets


def verify_secret(candidate: object, secret: str | None) -> bool:
    """Constant-time compare of an arbitrary candidate against a secret.

    False (never raises) when secret is missing/empty, or candidate isn't a
    non-empty str - covers a non-str MCP argument (e.g. admin_secret: 123)
    and the fact that secrets.compare_digest requires same-type ASCII-only
    str, or bytes, operands; comparing as UTF-8 bytes here sidesteps both the
    type mismatch and the non-ASCII TypeError it otherwise raises (#163
    review).
    """
    if not secret or not isinstance(candidate, str) or not candidate:
        return False
    return secrets.compare_digest(candidate.encode("utf-8"), secret.encode("utf-8"))
