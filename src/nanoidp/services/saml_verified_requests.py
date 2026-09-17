"""Verified SAML Redirect AuthnRequests, one per flow (#375).

With ``saml.want_authn_requests_signed``, a Redirect-binding AuthnRequest is
signed over its query string, and that signature cannot survive the login
form's round trip. So a verified ``GET /saml/sso`` records that this browser
had this request verified, and the login leg that continues it asks whether
it did. Before this the session held one such request, so a second signed
request in the same browser made the first one non-continuable.

The POST binding is not here: its signature travels inside the XML and is
verified again on every leg, with nothing to remember.

A record is only that proof: no request content beyond a digest of it, and
no user. It is looked up by ``(browser_binding, request_digest)``, which is
also its key, because a request digest alone would not identify one - two
browsers can be sent the same signed AuthnRequest. The browser never names
a record: it re-presents the request and the server answers whether it
verified it.

The login POST does not consume the record. What the tests fix is "this
request was verified", not "usable once"; making a verification single-use
is a separate change.
"""

import hashlib
import hmac
import json
import threading
import time
from typing import Optional

from pydantic import BaseModel

from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store

# "This signature authorizes the browser continuation of this AuthnRequest
# for ten minutes", rather than for as long as the session happens to last.
VERIFIED_REQUEST_LIFETIME_SECONDS = 600

# How many verified requests one browser may continue at once. A record is
# the proof that a signed GET was verified, not work the user has done, so
# at the limit the newest request wins and that browser's oldest becomes
# non-continuable.
MAX_VERIFIED_REQUESTS_PER_BROWSER = 10

# A belt, not the bound that matters: a validly signed Redirect URL can be
# replayed as often as anyone likes, since nothing here is a signature
# replay cache. At the cap a new verification is refused rather than another
# browser's record dropped.
MAX_VERIFIED_REQUESTS = 1000


class VerifiedRequestStoreFull(Exception):
    """The store holds as many verified requests as it will."""


def request_digest(saml_request: str, relay_state: str) -> str:
    """SHA-256 over exactly the values a login leg must present unchanged,
    serialized canonically. ``saml_original_verb`` is not among them: it is
    not part of the signed request, and it is what selects this lookup."""
    serialized = json.dumps(
        {"SAMLRequest": saml_request, "RelayState": relay_state},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _key(browser_binding: str, digest: str) -> str:
    return hashlib.sha256(f"{browser_binding}\0{digest}".encode("utf-8")).hexdigest()


class VerifiedRedirectAuthnRequest(BaseModel):
    key: str
    browser_binding: str
    request_digest: str
    verified_at: float
    expires_at: float

    def is_live(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at

    def is_for(self, browser_binding: Optional[str]) -> bool:
        return browser_binding is not None and hmac.compare_digest(
            self.browser_binding, browser_binding
        )


_store_lock = threading.RLock()


class VerifiedRequestStore:
    """Remember and answer for verified Redirect requests, one operation at
    a time so a read never lands inside a write."""

    def __init__(self) -> None:
        self._lock = _store_lock

    @property
    def _repository(self) -> MemoryRuntimeRepository[VerifiedRedirectAuthnRequest]:
        return get_runtime_identity_store().repository(
            "saml_verified_requests", lambda record: record.key
        )

    def remember_verified(
        self, browser_binding: str, saml_request: str, relay_state: str
    ) -> VerifiedRedirectAuthnRequest:
        """Record that this browser had this request verified. Re-verifying
        the same request refreshes it. Raises VerifiedRequestStoreFull."""
        now = time.time()
        digest = request_digest(saml_request, relay_state)
        record = VerifiedRedirectAuthnRequest(
            key=_key(browser_binding, digest),
            browser_binding=browser_binding,
            request_digest=digest,
            verified_at=now,
            expires_at=now + VERIFIED_REQUEST_LIFETIME_SECONDS,
        )
        with self._lock:
            # Everything listed below is live: the sweep runs first.
            self._prune_expired(now)
            if self._repository.get(record.key) is not None:
                # The same request verified again: refresh it, and leave the
                # room this browser has for other flows as it was.
                self._repository.delete(record.key)
                return self._repository.create(record)
            mine = sorted(
                (
                    existing
                    for existing in self._repository.list()
                    if existing.is_for(browser_binding)
                ),
                key=lambda existing: existing.verified_at,
            )
            for oldest in mine[: max(0, len(mine) + 1 - MAX_VERIFIED_REQUESTS_PER_BROWSER)]:
                self._repository.delete(oldest.key)
            if len(self._repository.list()) >= MAX_VERIFIED_REQUESTS:
                raise VerifiedRequestStoreFull(
                    f"{MAX_VERIFIED_REQUESTS} verified AuthnRequests are already held"
                )
            return self._repository.create(record)

    def is_verified(
        self, browser_binding: Optional[str], saml_request: str, relay_state: str
    ) -> bool:
        """Whether this browser had exactly this request verified, and the
        verification is still live."""
        if browser_binding is None:
            return False
        digest = request_digest(saml_request, relay_state)
        with self._lock:
            record = self._repository.get(_key(browser_binding, digest))
        return (
            record is not None
            and record.is_for(browser_binding)
            and hmac.compare_digest(record.request_digest, digest)
            and record.is_live()
        )

    def prune_expired(self) -> int:
        with self._lock:
            return self._prune_expired(time.time())

    def _prune_expired(self, now: float) -> int:
        dropped = 0
        for record in self._repository.list():
            if not record.is_live(now) and self._repository.delete(record.key):
                dropped += 1
        return dropped


def get_verified_request_store() -> VerifiedRequestStore:
    """The verified Redirect AuthnRequests of this process."""
    return VerifiedRequestStore()
