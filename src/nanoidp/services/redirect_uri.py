"""
Redirect URI validation and registration matching (issues #67, #81).

Single home for the two questions /authorize asks about a ``redirect_uri``,
so the GET and POST legs of the authorization endpoint (and any future
surface) cannot drift:

1. Is it syntactically acceptable at all? RFC 6749 §3.1.2: an absolute URI
   without a fragment component. "Absolute" means a scheme is present;
   an authority is NOT required, because native apps use private-use
   scheme URIs such as ``com.example.app:/oauth2redirect`` (RFC 8252 §7.1)
   that have a path but no host.

2. Does it match one of the client's registered URIs? RFC 6749 §3.1.2.3 /
   OAuth 2.1 draft §4.1.1: simple string comparison, with exactly one
   RFC-mandated exception. RFC 8252 §7.3 requires the authorization server
   to allow any port on loopback redirect URIs (``http://127.0.0.1:{port}/``
   and ``http://[::1]:{port}/``), because a native app binds an ephemeral
   port at runtime and cannot register it in advance. The OAuth 2.1 draft
   keeps that carve-out (§4.1.1: "except for port numbers in localhost
   redirection URIs of native apps", referring to RFC 8252 §7.3), so the
   ``oauth21`` profile does not tighten it. Only the port component is
   variable: scheme, host, path and query stay exact.

``localhost`` is deliberately NOT a loopback host here: RFC 8252 §7.3 and
§8.3 recommend the literal IP addresses because ``localhost`` can be
remapped by the resolver, so a registered ``http://localhost:3000/cb`` keeps
exact matching, port included.
"""

from typing import Iterable
from urllib.parse import urlparse

# RFC 8252 §7.3: loopback interface redirection is defined for the IPv4 and
# IPv6 loopback literals only. urlparse().hostname strips the brackets from
# an IPv6 literal, so "[::1]" is seen as "::1".
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})


def is_absolute_redirect_uri(uri: str) -> bool:
    """True when ``uri`` is an absolute URI without a fragment (RFC 6749 §3.1.2).

    Accepts web URIs (``https://host/path``), private-use scheme URIs with a
    path and no authority (``com.example.app:/oauth2redirect``, RFC 8252
    §7.1) and loopback URIs. Rejects relative references, scheme-only
    strings and anything carrying a fragment.
    """
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if not parsed.scheme:
        return False
    if not parsed.netloc and not parsed.path:
        return False
    if parsed.fragment or uri.endswith("#"):
        return False
    return True


def is_loopback_redirect_uri(uri: str) -> bool:
    """True for ``http://127.0.0.1[:port]/...`` and ``http://[::1][:port]/...``.

    RFC 8252 §7.3: only the ``http`` scheme on a loopback IP literal gets the
    variable-port exception. ``https`` on loopback and ``localhost`` do not.
    """
    try:
        parsed = urlparse(uri)
        hostname = parsed.hostname
    except ValueError:
        return False
    return parsed.scheme == "http" and hostname in _LOOPBACK_HOSTS


def _without_port(uri: str) -> str:
    """The URI with its port component removed, for loopback comparison."""
    parsed = urlparse(uri)
    hostname = parsed.hostname or ""
    if ":" in hostname:  # IPv6 literal: restore the brackets
        hostname = f"[{hostname}]"
    netloc = hostname
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"
    return parsed._replace(netloc=netloc).geturl()


def redirect_uri_matches(requested: str, registered: str) -> bool:
    """Compare a requested redirect_uri against one registered value.

    Simple string comparison (RFC 6749 §3.1.2.3), except that when the
    REGISTERED value is a loopback URI the port of the requested one is
    ignored (RFC 8252 §7.3). The exception is keyed on the registered side
    on purpose: a client registered with ``http://localhost:3000/cb`` or
    ``https://app.example.com/cb`` never gains port flexibility, and a
    requested loopback URI cannot match a non-loopback registration.
    """
    if requested == registered:
        return True
    if not is_loopback_redirect_uri(registered):
        return False
    if not is_loopback_redirect_uri(requested):
        return False
    return _without_port(requested) == _without_port(registered)


def redirect_uri_is_registered(requested: str, registered_uris: Iterable[str]) -> bool:
    """True when ``requested`` matches any of ``registered_uris``."""
    return any(redirect_uri_matches(requested, registered) for registered in registered_uris)
