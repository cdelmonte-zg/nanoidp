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


_WEB_SCHEMES = frozenset({"http", "https"})

PRIVATE_SCHEME_REASON = (
    "Invalid redirect_uri: private-use scheme must be reverse-domain based, "
    "e.g. com.example.app:/callback (RFC 8252 section 7.1)"
)


def has_acceptable_scheme(uri: str) -> bool:
    """True when the scheme is ``http``/``https`` or a reverse-domain private-use
    scheme (RFC 8252 §7.1).

    §7.1 requires private-use schemes to be based on a domain name under the
    app's control, in reverse order (``com.example.app``), names ``myapp`` as
    an example that does NOT qualify, and says the authorization server
    SHOULD enforce it and at a minimum SHOULD reject schemes without a
    period. This applies exactly that minimum rule: nanoidp cannot know which
    domains an app controls, so full reverse-domain ownership is not
    verified, only the presence of a period in the scheme.
    """
    try:
        scheme = urlparse(uri).scheme
    except ValueError:
        return False
    return scheme in _WEB_SCHEMES or "." in scheme


def redirect_uri_rejection_reason(uri: str) -> str | None:
    """The single syntactic gate /authorize applies to a ``redirect_uri``.

    Returns ``None`` when the URI is acceptable, otherwise the
    ``error_description`` to answer with: the generic "Invalid redirect_uri"
    for non-absolute URIs and fragments (RFC 6749 §3.1.2), or a message that
    names the RFC 8252 §7.1 rule for a private-use scheme without a period,
    so a client developer learns why ``myapp://`` is not enough.
    """
    if not is_absolute_redirect_uri(uri):
        return "Invalid redirect_uri"
    if not has_acceptable_scheme(uri):
        return PRIVATE_SCHEME_REASON
    return None


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


def _strip_loopback_port(uri: str) -> str | None:
    """``uri`` with only its port substring removed, or None if unusable.

    The port exception (RFC 8252 §7.3) must not relax anything but the
    port, so this never re-serializes the URI: ``urlparse`` is used only to
    locate the authority and to validate the port (``.port`` raises on a
    non-numeric or out-of-range value such as ``:evil``), and the original
    string is then sliced so that scheme case, an empty query, trailing
    characters and everything else stay byte-identical for the comparison
    (#81 review). Returns None when the authority cannot be located or the
    port is invalid, which callers treat as "no match".
    """
    try:
        parsed = urlparse(uri)
        port = parsed.port  # ValueError on ":evil", ":99999", ...
    except ValueError:
        return None
    if not parsed.netloc:
        return None
    authority_start = uri.find("//")
    if authority_start == -1:
        return None
    authority_start += 2
    authority_end = authority_start + len(parsed.netloc)
    if uri[authority_start:authority_end] != parsed.netloc:
        return None
    if port is None:
        return uri
    # Remove the port component as WRITTEN, not str(port): RFC 3986 3.2.3
    # defines port as *DIGIT, so ":0080" is a valid port component that
    # differs from ":80" only in the component RFC 8252 8.4 tells us to
    # ignore (#81 review). parsed.port above already validated it; for an
    # IPv6 literal the last ":" in the authority is the one after "]".
    raw_port = parsed.netloc.rsplit(":", 1)[1]
    suffix = f":{raw_port}"
    return uri[:authority_end - len(suffix)] + uri[authority_end:]


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
    requested_stripped = _strip_loopback_port(requested)
    registered_stripped = _strip_loopback_port(registered)
    if requested_stripped is None or registered_stripped is None:
        return False
    return requested_stripped == registered_stripped


def redirect_uri_is_registered(requested: str, registered_uris: Iterable[str]) -> bool:
    """True when ``requested`` matches any of ``registered_uris``."""
    return any(redirect_uri_matches(requested, registered) for registered in registered_uris)
