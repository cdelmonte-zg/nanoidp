"""Client ID Metadata Documents: the client source, without the network (#196).

A CIMD client identifies itself with an ``https`` URL and publishes its own
metadata there. This module owns what that means locally: which URLs are
Client Identifier URLs at all, what a fetched document has to say to become
an ``OAuthClient``, and the cache the resolver reads as a third origin.

It performs no I/O. Fetching the document, and every rule about how that
fetch may be made, is its own piece of work: keeping the two apart is what
lets "``/token`` never performs network I/O" be a property of the shape
rather than a promise to re-check at seventeen call sites.

The rules below come from draft-ietf-oauth-client-id-metadata-document-02,
the draft MCP 2026-07-28 references.
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel

from ..config_documents import EntryInvalid, parse_client_entry
from ..models import OAuthClient
from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store

logger = logging.getLogger(__name__)

# The document says the client authenticates with none of the shared-secret
# methods. nanoidp supports client_secret_basic, client_secret_post and
# none, so two of its three are forbidden here and the third is the answer.
# private_key_jwt, which the draft does allow, nanoidp does not implement.
ONLY_AUTH_METHOD = "none"

# How long a cached document may be kept when the response says nothing, and
# the bounds an operator's own answer is clamped to. Lifetimes come from the
# fetch, which is not here; these are what this module enforces about them.
DEFAULT_LIFETIME_SECONDS = 3600
MIN_LIFETIME_SECONDS = 60
MAX_LIFETIME_SECONDS = 86400

# How many documents this server will hold at once. The entries are filled
# by an unauthenticated endpoint from client-chosen URLs, so a bound per
# entry is not a bound: without this, distinct URLs pin memory for as long
# as their lifetimes allow. At the cap the oldest fetch is evicted rather
# than the newest refused, because this is a cache and a client that is
# actually being used will simply be fetched again.
MAX_CACHED_DOCUMENTS = 100

# The cache is read and written by concurrent requests, and a write is
# several visits to the repository (sweep, evict, replace). One at a time.
cache_lock = threading.Lock()

# The scheme, spelled once, so "is this worth fetching" and "is this a legal
# identifier" cannot disagree about the same string.
_SCHEME = "https://"


class ClientIdUrlInvalid(ValueError):
    """The ``client_id`` is not a Client Identifier URL.

    Not the same as "this is not a CIMD client": a ``client_id`` that is not
    a URL at all is simply someone else's, and ``looks_like_client_id_url``
    answers that. This is raised for one that means to be and is not.
    """


class DocumentInvalid(ValueError):
    """The document at a Client Identifier URL cannot become a client."""


class CachedClient(BaseModel):
    """A client learned from a metadata document, and when to forget it."""

    client_id: str
    client: OAuthClient
    fetched_at: float
    expires_at: float

    def is_fresh(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at


def looks_like_client_id_url(client_id: str) -> bool:
    """Whether this ``client_id`` is meant to be fetched at all.

    Deliberately shallow: an ``https`` URL is a candidate, and everything
    else is a name. Whether the candidate is a *valid* Client Identifier URL
    is ``reject_invalid_client_id_url``'s answer, which says why.
    """
    return client_id.startswith(_SCHEME)


def reject_invalid_client_id_url(client_id: str) -> None:
    """Every rule the draft puts on the URL itself, before any fetch.

    Checked here, in one place, so the fetcher cannot be handed a URL the
    specification never allowed and so each rule has somewhere to be tested
    without a socket.
    """
    # urlsplit strips surrounding whitespace, drops embedded tab/CR/LF and
    # lowercases the scheme, so validating what it returns would approve a
    # string that is not the identifier. The identifier is what becomes the
    # cache key, the fetch target, and the value the document must equal by
    # simple string comparison, so it is checked as given.
    if client_id != client_id.strip() or any(ch.isspace() for ch in client_id):
        raise ClientIdUrlInvalid("a client identifier URL must contain no whitespace")
    if not client_id.startswith(_SCHEME):
        raise ClientIdUrlInvalid("a client identifier URL must use https")
    parts = urlsplit(client_id)
    if parts.scheme != "https":
        raise ClientIdUrlInvalid("a client identifier URL must use https")
    if parts.username or parts.password:
        raise ClientIdUrlInvalid("a client identifier URL must carry no userinfo")
    if parts.fragment:
        raise ClientIdUrlInvalid("a client identifier URL must carry no fragment")
    if not parts.hostname:
        raise ClientIdUrlInvalid("a client identifier URL must name a host")
    if not parts.path or parts.path == "/":
        raise ClientIdUrlInvalid("a client identifier URL must have a path")
    # Percent-decoded first: %2e is '.' (RFC 3986), and the rule exists so
    # that nothing between here and the origin can normalise the request
    # target into a different resource than the identifier names.
    if any(unquote(segment) in (".", "..") for segment in parts.path.split("/")):
        raise ClientIdUrlInvalid(
            "a client identifier URL must have no '.' or '..' path segments"
        )
    if parts.query:
        # SHOULD NOT, not MUST NOT. A conforming client may still carry one
        # (a multi-tenant host, say), and refusing would lock it out of this
        # IdP entirely, so it is accepted and said out loud instead.
        logger.warning(
            "Client identifier URL carries a query, which the specification "
            "discourages: %s", client_id
        )


def client_from_document(
    client_id: str, document: Any, vocabulary: List[str]
) -> OAuthClient:
    """The document as an ``OAuthClient``, or an explanation.

    The subset nanoidp understands is read and everything else ignored, the
    same treatment #190 gives registration metadata, and the result goes
    through ``parse_client_entry`` so a CIMD client is validated by the
    rules a declared client is.
    """
    if not isinstance(document, dict):
        raise DocumentInvalid("the metadata document must be a JSON object")

    declared_id = document.get("client_id")
    if declared_id != client_id:
        # The document has to claim the URL it was found at. Simple string
        # comparison, as the draft specifies: no normalisation that could
        # make two different URLs look like one.
        raise DocumentInvalid("the document's client_id is not the URL it was fetched from")

    method = document.get("token_endpoint_auth_method", ONLY_AUTH_METHOD)
    if method != ONLY_AUTH_METHOD:
        raise DocumentInvalid(
            "a client identified by a metadata document authenticates with "
            f"{ONLY_AUTH_METHOD!r}"
        )

    redirect_uris = document.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise DocumentInvalid("the document must list at least one redirect_uri")
    if not all(isinstance(uri, str) and uri for uri in redirect_uris):
        raise DocumentInvalid("redirect_uris must be a list of strings")
    for uri in redirect_uris:
        # The same answer #190 gives a registration: a value /authorize
        # could never match is named here, rather than found later as an
        # opaque refusal.
        parsed = urlsplit(uri)
        if not parsed.scheme or not (parsed.netloc or parsed.path):
            raise DocumentInvalid("redirect_uris must be absolute URIs")

    entry: Dict[str, Any] = {
        "client_id": client_id,
        "token_endpoint_auth_method": ONLY_AUTH_METHOD,
        "redirect_uris": redirect_uris,
    }

    scope = document.get("scope")
    if scope is not None:
        if not isinstance(scope, str):
            raise DocumentInvalid("scope must be a string")
        granted = [name for name in scope.split() if name in vocabulary]
        if scope.split() and not granted:
            # An empty allowed_scopes means every scope (#186), so narrowing
            # to nothing would widen the client instead.
            raise DocumentInvalid("scope names none of the scopes this server supports")
        entry["allowed_scopes"] = granted or list(vocabulary)
    else:
        entry["allowed_scopes"] = list(vocabulary)

    name = document.get("client_name")
    if name is not None:
        if not isinstance(name, str):
            raise DocumentInvalid("client_name must be a string")
        entry["description"] = name

    try:
        return parse_client_entry(entry, f"the metadata document at {client_id}")
    except EntryInvalid as invalid:
        raise DocumentInvalid(invalid.message) from invalid


def bounded_lifetime(seconds: Optional[float]) -> float:
    """What the response asked for, within what this server will keep.

    A document with no lifetime of its own gets the default; one asking for
    a day and a half is kept for a day. The bounds are the server's, so a
    client cannot pin its own metadata in this cache indefinitely.
    """
    if seconds is None:
        return float(DEFAULT_LIFETIME_SECONDS)
    return float(min(max(seconds, MIN_LIFETIME_SECONDS), MAX_LIFETIME_SECONDS))


def cache() -> MemoryRuntimeRepository[CachedClient]:
    """The repository the runtime store keeps for this module.

    Process memory, like every other runtime repository: two nanoidp
    processes do not share it, and a durable backend is #354's.
    """
    return get_runtime_identity_store().repository(
        "cimd_documents", lambda cached: cached.client_id
    )


def prune_expired() -> int:
    """Drop every entry past its lifetime, and say how many.

    A read only expires the entry it was asked for, so without this a URL
    nobody asks for again is held until the process ends. Called on the way
    into a write, which is the only moment anything grows.
    """
    now = time.time()
    dropped = 0
    for entry in cache().list():
        if not entry.is_fresh(now) and cache().delete(entry.client_id):
            dropped += 1
    return dropped


def _evict_oldest(room_for: int) -> int:
    """Make room at the cap by dropping the least recently fetched."""
    entries = sorted(cache().list(), key=lambda entry: entry.fetched_at)
    dropped = 0
    while len(entries) - dropped > MAX_CACHED_DOCUMENTS - room_for:
        if cache().delete(entries[dropped].client_id):
            logger.info(
                "Dropped the oldest cached client metadata document to stay "
                "within %d entries", MAX_CACHED_DOCUMENTS
            )
        dropped += 1
    return dropped


def remember(client_id: str, client: OAuthClient, lifetime: Optional[float]) -> CachedClient:
    """Cache a document that was fetched and accepted.

    Only successes are cached. The draft says an error response or an
    invalid document MUST NOT be, and there is deliberately no negative
    cache here: a bad answer must not be able to stick. Protecting the
    server from a client that keeps failing is rate limiting, elsewhere.

    The identifier is checked here rather than trusted from the caller, so
    the rules this module states are the rules the cache actually holds to:
    nothing can be remembered under a URL the specification does not allow.

    Sweep, evict and replace are one critical section. They are three visits
    to the repository, and two requests for the same uncached URL would
    otherwise both fetch and collide on the create.
    """
    reject_invalid_client_id_url(client_id)
    now = time.time()
    with cache_lock:
        prune_expired()
        forget(client_id)
        _evict_oldest(room_for=1)
        return cache().create(
            CachedClient(
                client_id=client_id,
                client=client,
                fetched_at=now,
                expires_at=now + bounded_lifetime(lifetime),
            )
        )


def cached_client(client_id: str) -> Optional[OAuthClient]:
    """The cached client for this URL, if one is there and still fresh.

    An expired entry is dropped on the way past rather than left for a
    sweep: this is the only read, so it is the only place that would.
    """
    entry = cache().get(client_id)
    if entry is None:
        return None
    if entry.is_fresh():
        return entry.client
    with cache_lock:
        # Re-read under the lock: a concurrent remember may have replaced
        # the expired entry with a fresh one between the check and here.
        current = cache().get(client_id)
        if current is not None and not current.is_fresh():
            cache().delete(client_id)
        return current.client if current is not None and current.is_fresh() else None


def forget(client_id: str) -> bool:
    """Drop one entry: an operator action, and how a developer re-fetches a
    document they have just changed."""
    return cache().delete(client_id)


def forget_all() -> int:
    return cache().delete_all()


def cached_entries() -> List[CachedClient]:
    """Everything currently cached, for a read surface. Expired entries are
    filtered rather than returned with a note: a read surface showing an
    entry nothing would use is a lie about what is in effect."""
    return [entry for entry in cache().list() if entry.is_fresh()]
