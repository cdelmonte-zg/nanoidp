"""
RFC 8707 Resource Indicators: validate a requested ``resource`` and bind the
access token audience to it (issue #187).

An MCP client sends ``resource=<MCP server URL>`` on /authorize and /token so
the token it gets back is audience-restricted to that server and useless at
another. This module answers, once for every call site in ``routes/oauth.py``,
the two questions those sites share: is each requested ``resource`` a
syntactically valid resource indicator (RFC 8707 section 2: an absolute URI
with no fragment), and is it one this client may target? A failure is
``invalid_target`` (RFC 8707 section 2), for both the authorization and the
token endpoint.

Like per-client scopes (#186), the per-client allow-list is opt-in: a client
with an empty ``allowed_resources`` may target any syntactically valid
resource (the dev-friendly default, same "empty = unrestricted" convention as
``allowed_scopes`` and ``redirect_uris``). Sending no ``resource`` at all is
always allowed and leaves the audience at ``oauth.audience``, so existing
clients are unaffected - RFC 8707 makes the parameter optional, and the MCP
requirement to send it is an obligation on the client, not the AS.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit

from ..models import OAuthClient

# The characters RFC 3986 permits anywhere in a URI: unreserved, gen-delims,
# sub-delims and the percent sign. This is a pre-parse guard, NOT the whole
# check: urlsplit is a permissive parser (it accepts a raw space) AND it
# silently strips ASCII tab/newline before parsing (WHATWG behaviour), so a
# value carrying a control character would otherwise reach the token aud with
# the control character removed. Rejecting anything outside this set first
# catches the space, tab, newline, control and non-ASCII bytes the
# per-component grammar below never sees (#254/#256 review).
# \Z, not $: in Python '$' also matches just before a trailing newline.
_RFC3986_CHARS = re.compile(r"\A[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*\Z")

# RFC 3986 per-component ABNF (#257). A single global whitelist accepts '[' and
# ']' anywhere and leans on urlsplit's numeric-range port check; the grammar is
# per component: brackets are legal only inside an IP-literal host, a port is
# *DIGIT, and path/query pchar excludes the gen-delims a whitelist would admit.
_UNRESERVED = r"A-Za-z0-9\-._~"
_SUB_DELIMS = r"!$&'()*+,;="
_PCT = r"%[0-9A-Fa-f]{2}"
# pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
_PCHAR = rf"(?:[{_UNRESERVED}{_SUB_DELIMS}:@]|{_PCT})"
_SCHEME_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9+\-.]*\Z")
# userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
_USERINFO_RE = re.compile(rf"\A(?:[{_UNRESERVED}{_SUB_DELIMS}:]|{_PCT})*\Z")
# reg-name = *( unreserved / pct-encoded / sub-delims ) - also matches IPv4address
_REG_NAME_RE = re.compile(rf"\A(?:[{_UNRESERVED}{_SUB_DELIMS}]|{_PCT})*\Z")
_PORT_RE = re.compile(r"\A[0-9]*\Z")  # port = *DIGIT
# path = *( pchar / "/" ); query = *( pchar / "/" / "?" )
_PATH_RE = re.compile(rf"\A(?:{_PCHAR}|/)*\Z")
_QUERY_RE = re.compile(rf"\A(?:{_PCHAR}|[/?])*\Z")
# IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
_IPVFUTURE_RE = re.compile(rf"\A[vV][0-9A-Fa-f]+\.[{_UNRESERVED}{_SUB_DELIMS}:]+\Z")


def _is_valid_host(host: str) -> bool:
    """RFC 3986 §3.2.2 host = IP-literal / IPv4address / reg-name."""
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        if inner[:1] in ("v", "V"):
            return bool(_IPVFUTURE_RE.match(inner))
        try:
            ipaddress.IPv6Address(inner)
            return True
        except ValueError:
            return False
    # reg-name / IPv4address: brackets are legal ONLY in an IP-literal, so a
    # reg-name carrying '[' or ']' is rejected here (the gap a whitelist missed).
    return bool(_REG_NAME_RE.match(host))


def _is_valid_authority(authority: str) -> bool:
    """RFC 3986 §3.2 authority = [ userinfo '@' ] host [ ':' port ]."""
    rest = authority
    if "@" in rest:
        userinfo, rest = rest.rsplit("@", 1)
        if not _USERINFO_RE.match(userinfo):
            return False
    # Split host from port, honouring an IP-literal's own colons.
    if rest.startswith("["):
        end = rest.find("]")
        if end == -1:
            return False
        host, after = rest[: end + 1], rest[end + 1 :]
        if after == "":
            port = ""
        elif after.startswith(":"):
            port = after[1:]
        else:
            return False
    elif ":" in rest:
        host, port = rest.rsplit(":", 1)
    else:
        host, port = rest, ""
    return bool(_PORT_RE.match(port)) and _is_valid_host(host)


@dataclass
class ResourceResult:
    """The outcome of validating requested resource indicators against a client.

    ``granted`` is the list of resources to bind the token to (empty when the
    request carried none, which leaves the audience at ``oauth.audience``);
    ``error_description`` is set, and ``granted`` is None, exactly when the
    request must be rejected as ``invalid_target``.
    """

    granted: Optional[List[str]]
    error_description: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error_description is None


def is_valid_resource_indicator(value: str) -> bool:
    """RFC 8707 section 2: a resource is an absolute URI without a fragment
    (RFC 3986 section 4.3, "absolute-URI = scheme ':' hier-part [ '?' query ]").

    A query component is allowed; a fragment component is NOT - and that
    means no ``#`` at all, since an absolute-URI has no ``fragment``
    production, so even an empty fragment (``https://x/#``) is rejected. A
    value ``urlparse`` cannot parse (e.g. ``https://[bad`` raises
    ``ValueError: Invalid IPv6 URL``) is a rejected indicator, never a 500.
    An empty or relative value (no scheme, or no authority/path) is rejected.
    """
    if not value:
        return False
    # Pre-parse guard for the characters urlsplit permits or silently strips
    # (raw space, control, tab/newline, non-ASCII) - see _RFC3986_CHARS.
    if not _RFC3986_CHARS.match(value):
        return False
    # A fragment component is forbidden outright: reject any '#', not just a
    # non-empty fragment - urlsplit treats a trailing '#' as an empty fragment,
    # which is still a fragment component RFC 8707 disallows (#254 review).
    if "#" in value:
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        # A malformed value (e.g. a bad IPv6 literal urlsplit rejects) is an
        # invalid indicator handled as invalid_target, never a crash.
        return False
    # scheme ":" hier-part [ "?" query ], no fragment (absolute-URI, RFC 3986
    # §4.3). Validate each component against its own ABNF (#257).
    if not _SCHEME_RE.match(parts.scheme):
        return False
    if parts.query and not _QUERY_RE.match(parts.query):
        return False
    if parts.netloc:
        # hier-part with an authority: path is path-abempty (empty or "/"...).
        if not _is_valid_authority(parts.netloc):
            return False
        if parts.path and not parts.path.startswith("/"):
            return False
    if parts.path and not _PATH_RE.match(parts.path):
        return False
    # absolute-URI needs a hier-part: an authority (https://host/...) or, for a
    # non-hierarchical scheme, an opaque path (urn:example:resource).
    return bool(parts.netloc or parts.path)


def resolve_resources(
    requested: List[str],
    client: OAuthClient,
    *,
    allowed_subset: Optional[List[str]] = None,
) -> ResourceResult:
    """Validate requested resource indicators for one client.

    ``requested`` is the raw list from ``resource`` parameters (repeatable per
    RFC 8707). Each must be a valid indicator, and - when the client declares a
    non-empty ``allowed_resources`` - one of that set. ``allowed_subset``, when
    given, is a second gate the request must also fall within: the resources a
    prior step already bound (an authorization code or refresh token), so a
    /token request may narrow the set but never widen it (RFC 8707 section 2,
    "the requested resource ... a subset").

    Returns the de-duplicated granted list (order preserving first appearance),
    or an ``invalid_target`` error. An empty ``requested`` is ``ok`` with an
    empty granted list - no resource was asked for.
    """
    granted: List[str] = []
    for value in requested:
        if not is_valid_resource_indicator(value):
            return ResourceResult(
                None,
                f"resource {value!r} is not a valid resource indicator "
                "(RFC 8707: an absolute URI without a fragment)",
            )
        if client.allowed_resources and value not in client.allowed_resources:
            return ResourceResult(
                None, f"resource {value!r} is not allowed for this client"
            )
        if allowed_subset is not None and value not in allowed_subset:
            return ResourceResult(
                None,
                f"resource {value!r} was not part of the original grant "
                "and cannot be added on refresh",
            )
        if value not in granted:
            granted.append(value)
    return ResourceResult(granted)
