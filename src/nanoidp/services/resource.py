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

import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

from ..models import OAuthClient

# The characters RFC 3986 permits in a URI: unreserved, gen-delims,
# sub-delims and the percent sign for percent-encoding. urlparse is a
# permissive parser, not an RFC 3986 validator - it happily accepts a raw
# space in the authority - so a resource indicator is charset-checked
# against this set first (#254 review).
_RFC3986_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")


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
    # Reject anything outside the RFC 3986 character set (a raw space, a
    # control character, a non-ASCII byte) before parsing (#254 review).
    if not _RFC3986_CHARS.match(value):
        return False
    # A fragment component is forbidden outright: reject any '#', not just a
    # non-empty fragment (#254 review) - urlparse treats a trailing '#' as an
    # empty fragment, which is still a fragment component RFC 8707 disallows.
    if "#" in value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        # urlparse raises on a malformed authority (bad IPv6 literal); that is
        # an invalid indicator, handled as invalid_target, not a crash.
        return False
    if not parsed.scheme:
        return False
    # An absolute URI has either an authority (https://host/...) or, for a
    # non-hierarchical scheme, an opaque path (urn:example:resource).
    return bool(parsed.netloc or parsed.path)


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
