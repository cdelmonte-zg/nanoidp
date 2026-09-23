"""The configuration this request reads (#406).

One published configuration is chosen when the request begins, right after
freshness has been established, and every read of the declared state in that
request comes from it. The choice is made in one place, ``app.py``'s
before_request hook, so nothing depends on the order two hooks were
registered in.

It lives here, and not in ``services/``, because it is Flask's request
globals: a service never reaches for the request, it is given what to read.
The MCP server does the same thing at the start of a tool call and passes
what it took (``mcp_server.call_tool``).

Fail closed on purpose: a handler that reaches for the request's
configuration where none was chosen is a handler outside the boundary, and
answering it with the current configuration would make the invariant
optional again.
"""

from flask import g

from ..config import ConfigSnapshot

_ATTRIBUTE = "config_snapshot"


def remember_for_this_request(loaded: ConfigSnapshot) -> None:
    """Called once per request, by the hook that established freshness.

    Forgotten when that request ends (``forget_after_this_request``): ``g``
    belongs to the application context, which outlives the request when a
    caller pushed one around it (tests, ``flask shell``, a script), and a
    later request or an endpoint outside the boundary would otherwise read
    what the previous one chose.
    """
    setattr(g, _ATTRIBUTE, loaded)


def forget_after_this_request(_: object = None) -> None:
    """The teardown of the request that chose it."""
    if hasattr(g, _ATTRIBUTE):
        delattr(g, _ATTRIBUTE)


def request_config() -> ConfigSnapshot:
    """The configuration this request began with."""
    loaded = getattr(g, _ATTRIBUTE, None)
    if loaded is None:
        raise RuntimeError(
            "no configuration was chosen for this request: the endpoint is outside the "
            "boundary (see app.py's before_request), and reading the current configuration "
            "here would pair it with whatever the rest of the request read"
        )
    return loaded
