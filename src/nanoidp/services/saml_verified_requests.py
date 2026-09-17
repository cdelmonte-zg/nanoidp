"""The Redirect AuthnRequests a browser has had verified (#375).

With ``saml.want_authn_requests_signed``, a Redirect-binding AuthnRequest is
signed over its query string, and that signature cannot survive the login
form's round trip. So a verified ``GET /saml/sso`` is remembered, and the
login leg that continues it is admitted only for a request that was. Before
this the session held one such request, so a second signed request in the
same browser made the first one non-continuable.

What is remembered is local to one browser - "this browser presented this
Redirect AuthnRequest and had it verified" - so it lives in that browser's
own signed session, not in a store shared by every browser. A shared store
was tried first and rejected: its per-browser budget is keyed on a value the
client carries, so a client that discards its cookie never trips it, and
replaying one already-signed URL would fill the global cap and refuse signed
Redirect SSO for everyone. Keeping the proof where the browser keeps it has
no such coupling, and it survives a restart or several workers, as long as
they share the Flask secret - which is what sharing a signed session already
requires.

This module is framework-free: it owns the digest and the bounded, expiring
set, and the route owns the session it is kept in. The POST binding is not
here at all: its signature travels inside the XML and is verified again on
every leg, with nothing to remember.
"""

import base64
import hashlib
import hmac
import json
import time
from enum import Enum
from typing import Any, List, Optional, Sequence, Tuple

# "This signature authorizes the browser continuation of this AuthnRequest
# for ten minutes of inactivity", rather than for as long as the session
# happens to last. Continuing the flow refreshes it, so a login that takes
# several screens does not expire underneath the user.
VERIFIED_REQUEST_LIFETIME_SECONDS = 600

# How many requests one browser may have in flight. The entry is the proof
# that a signed GET was verified, not work the user has done, so at the
# limit the newest request wins and the oldest becomes non-continuable. Ten
# full digests are small next to what a cookie holds.
MAX_VERIFIED_REQUESTS = 10

# One entry: the digest and when it was last verified or continued.
Entry = List[Any]


class VerificationState(str, Enum):
    """What this browser's remembered requests say about one request."""

    VERIFIED = "verified"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


def request_digest(saml_request: str, relay_state: str) -> str:
    """SHA-256 over exactly the values a login leg must present unchanged,
    serialized canonically, base64url so the cookie stays small.

    ``saml_original_verb`` is not among them: it is not part of the signed
    request, and it is what selects this lookup in the first place.
    """
    serialized = json.dumps(
        {"SAMLRequest": saml_request, "RelayState": relay_state},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(serialized.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _parsed(remembered: object) -> List[Entry]:
    """The well-formed entries of a remembered set, whatever the session
    holds, of any age.

    A session cookie is client-supplied data: it is signed, so it cannot be
    forged, but an older build (or a hand-edited test session) may have put
    something else under this key, and anything this function does not
    recognise reads as "nothing remembered" rather than raising - or, worse,
    being reported as an expired verification.
    """
    if not isinstance(remembered, list):
        return []
    return [
        [entry[0], float(entry[1])]
        for entry in remembered
        if isinstance(entry, (list, tuple))
        and len(entry) == 2
        and isinstance(entry[0], str)
        and isinstance(entry[1], (int, float))
        and not isinstance(entry[1], bool)
    ]


def _entries(remembered: object, now: float) -> List[Entry]:
    """The entries that have not expired."""
    return [
        entry
        for entry in _parsed(remembered)
        if now - entry[1] < VERIFIED_REQUEST_LIFETIME_SECONDS
    ]


def remember_verified(
    remembered: object, digest: str, now: Optional[float] = None
) -> List[Entry]:
    """The remembered set with this request verified now: the expired
    entries dropped, this one refreshed or appended, and the oldest dropped
    past the cap."""
    now = time.time() if now is None else now
    live = [entry for entry in _entries(remembered, now) if not _matches(entry, digest)]
    live.append([digest, now])
    live.sort(key=lambda entry: entry[1])
    return live[-MAX_VERIFIED_REQUESTS:]


def state_of(
    remembered: object, digest: str, now: Optional[float] = None
) -> Tuple[VerificationState, List[Entry]]:
    """What this browser's set says about this request, and the set with its
    expired entries dropped.

    ``EXPIRED`` is distinguished from ``UNKNOWN`` while the expired entry is
    still there, so the refusal does not suggest the signature was invalid.
    """
    now = time.time() if now is None else now
    live = _entries(remembered, now)
    if any(_matches(entry, digest) for entry in live):
        return VerificationState.VERIFIED, live
    if any(_matches(entry, digest) for entry in _parsed(remembered)):
        return VerificationState.EXPIRED, live
    return VerificationState.UNKNOWN, live


def _matches(entry: Sequence[Any], digest: str) -> bool:
    return isinstance(entry[0], str) and hmac.compare_digest(entry[0], digest)
