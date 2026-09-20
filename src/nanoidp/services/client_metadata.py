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
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, model_validator

from ..config_documents import EntryInvalid, parse_client_entry
from ..models import OAuthClient
from .redirect_uri import redirect_uri_rejection_reason
from .runtime_identities import (
    MemoryRuntimeRepository,
    PydanticCodec,
    get_runtime_identity_store,
)
from .runtime_repository import (
    RepositoryTransaction,
    delete_where,
    replace,
    transact_refusing,
)

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


class DocumentNotUsable(ValueError):
    """The document is valid and cannot be used for this flow.

    A document the response says must not be cached (#196): the cache is
    the only place a CIMD client exists between ``/authorize`` and
    ``/token``, so issuing an authorization code for one would produce a
    code no token request could ever redeem. Refusing at the authorization
    request says so at the moment a developer can act on it.
    """


class CacheIsFull(DocumentNotUsable):
    """Every cached client is holding up an authorization code that is
    still alive, so there is no room to learn another.

    Refusing the new authorization request is the lesser harm. The
    alternative is evicting an entry to make room, which breaks a flow
    already under way for a client that did nothing wrong and would see
    only a code that stopped working.
    """


class CachedClient(BaseModel):
    """A client learned from a metadata document, and when to forget it.

    The client carries its own id and the repository is keyed on it, so a
    cache entry cannot end up filed under a URL other than the one the
    client answers to. There is nothing here to keep in step.

    Two clocks, because they answer different questions. ``expires_at`` is
    how long this document may be used, which the response decides.
    ``protected_until`` is how long something else depends on this entry
    existing, which this server decides: an authorization code names a
    client, and the cache is the only place a CIMD client is. The cap reads
    the second one, so a document nobody is mid-flow with is a fine thing
    to evict and one holding up a live code is not.
    """

    client: OAuthClient
    fetched_at: float
    expires_at: float
    protected_until: float = 0.0

    @model_validator(mode="after")
    def _outlive_what_depends_on_this_entry(self) -> "CachedClient":
        """An entry cannot expire while something still depends on it.

        Stated once, here, rather than at each write: a lifetime shorter
        than the promise would let the sweep drop an entry the cap was
        told to keep, which is the same defect one step further along.
        """
        if self.expires_at < self.protected_until:
            self.expires_at = self.protected_until
        return self

    @property
    def client_id(self) -> str:
        return self.client.client_id

    def is_fresh(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at

    def is_protected(self, now: Optional[float] = None) -> bool:
        """Whether something still depends on this entry being here."""
        return (now if now is not None else time.time()) < self.protected_until


def looks_like_client_id_url(client_id: str) -> bool:
    """Whether this ``client_id`` is meant to be fetched at all.

    Deliberately shallow: an ``https`` URL is a candidate, and everything
    else is a name. Whether the candidate is a *valid* Client Identifier URL
    is ``reject_invalid_client_id_url``'s answer, which says why.
    """
    return client_id[: len(_SCHEME)].lower() == _SCHEME


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
    if client_id[: len(_SCHEME)].lower() != _SCHEME:
        # Case-insensitive, per RFC 3986: scheme names are, and an
        # implementation is asked to accept an uppercase one. Everything
        # after it is compared as given, because the draft matches the
        # document's client_id against this string literally.
        raise ClientIdUrlInvalid("a client identifier URL must use https")
    try:
        parts = urlsplit(client_id)
    except ValueError as exc:
        # urlsplit raises a bare ValueError for an unbalanced bracket
        # ("Invalid IPv6 URL"), which is not a subclass of the errors a
        # caller catches. Everything this function refuses is its own.
        raise ClientIdUrlInvalid("a client identifier URL cannot be parsed") from exc
    if parts.scheme != "https":
        raise ClientIdUrlInvalid("a client identifier URL must use https")
    if parts.username or parts.password:
        raise ClientIdUrlInvalid("a client identifier URL must carry no userinfo")
    if parts.fragment:
        raise ClientIdUrlInvalid("a client identifier URL must carry no fragment")
    if not parts.hostname:
        raise ClientIdUrlInvalid("a client identifier URL must name a host")
    if not parts.path:
        raise ClientIdUrlInvalid("a client identifier URL must have a path")
    if parts.path == "/":
        # NOT RECOMMENDED in the draft, not forbidden - the same treatment
        # the query gets, for the same reason.
        logger.warning(
            "Client identifier URL uses the root path, which the "
            "specification discourages: %s", client_id
        )
    # Percent-decoded first: %2e is '.' (RFC 3986), and the rule exists so
    # that nothing between here and the origin can normalise the request
    # target into a different resource than the identifier names.
    if any(unquote(segment) in (".", "..") for segment in parts.path.split("/")):
        raise ClientIdUrlInvalid(
            "a client identifier URL must have no '.' or '..' path segments"
        )
    if not client_id.isascii():
        # http.client builds the request line from this and cannot encode a
        # non-ASCII one. A client that wants those characters percent-encodes
        # them; the encoded form is what the document must then claim, since
        # the draft compares the two literally.
        raise ClientIdUrlInvalid("a client identifier URL must be ASCII")
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
        # Through the gate /authorize itself applies, not a second reading
        # of the same rule: that module exists to be the only one, and it
        # knows things this would have missed, such as RFC 6749's ban on a
        # fragment and RFC 8252's rule for private-use schemes.
        rejection = redirect_uri_rejection_reason(uri)
        if rejection is not None:
            raise DocumentInvalid(f"redirect_uris: {rejection}")

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
        "cimd_documents", lambda cached: cached.client.client_id, PydanticCodec(CachedClient)
    )


def prune_expired() -> int:
    """Drop every entry past its lifetime, and say how many.

    A read only expires the entry it was asked for, so without this a URL
    nobody asks for again is held until the process ends. Called on the way
    into a write, which is the only moment anything grows.
    """
    return delete_where(cache(), lambda entry: not entry.is_fresh())


def _oldest_to_evict(live: List[CachedClient], room_for: int, now: float) -> List[str]:
    """Which entries to drop to make room at the cap: the least recently
    fetched ones that nothing depends on. Raises ``CacheIsFull``.

    An entry holding up a live authorization code is not a candidate, and
    it would otherwise be among the first: it was fetched before the login
    that produced the code, so by then it is one of the oldest things here.
    The cap is 100 and a code lives ten minutes, so this is reached by
    ordinary traffic, with no attacker and nobody at fault.

    If every entry is protected there is no room to make, and the caller is
    refused rather than served at the cost of a flow already under way.
    """
    room_needed = len(live) + room_for - MAX_CACHED_DOCUMENTS
    if room_needed <= 0:
        return []
    candidates = sorted(
        (entry for entry in live if not entry.is_protected(now)),
        key=lambda entry: entry.fetched_at,
    )
    if len(candidates) < room_needed:
        raise CacheIsFull(
            "every cached metadata document is holding up an authorization "
            "code that is still valid"
        )
    return [entry.client_id for entry in candidates[:room_needed]]


def remember(client: OAuthClient, lifetime: Optional[float]) -> CachedClient:
    """Cache a document that was fetched and accepted.

    Only successes are cached. The draft says an error response or an
    invalid document MUST NOT be, and there is deliberately no negative
    cache here: a bad answer must not be able to stick. Protecting the
    server from a client that keeps failing is rate limiting, elsewhere.

    The key is the client's own id, and the identifier is checked here
    rather than trusted from the caller, so the rules this module states are
    the rules the cache actually holds to: nothing can be remembered under a
    URL the specification does not allow, and nothing can be filed under a
    URL other than the one it answers to.

    Sweep, evict and replace are one decision of the repository's (#404):
    two requests for the same uncached URL would otherwise both fetch and
    collide on the create, and a second process sharing the store would see
    the cache over its cap or a document missing in between. A refusal is
    returned by the decision and raised after it, so what the sweep dropped
    stays dropped, as it always did.
    """
    client_id = client.client_id
    reject_invalid_client_id_url(client_id)
    lifetime_seconds = bounded_lifetime(lifetime)

    def decide(
        view: RepositoryTransaction[CachedClient],
    ) -> Union[Tuple[CachedClient, List[str]], Exception]:
        # The document was fetched before any wait for the store, but what
        # is fresh, what is protected and when this entry expires are
        # questions about the moment it is remembered.
        now = time.time()
        replaced: Optional[CachedClient] = None
        others: List[CachedClient] = []
        for entry in view.entries():
            if not entry.value.is_fresh(now):
                view.delete(entry.name)
            elif entry.name == client_id:
                replaced = entry.value
            else:
                others.append(entry.value)
        try:
            evicted = _oldest_to_evict(others, room_for=1, now=now)
        except CacheIsFull as full:
            return full
        for name in evicted:
            view.delete(name)
        remembered = CachedClient(
            client=client,
            fetched_at=now,
            expires_at=now + lifetime_seconds,
            # Re-fetching a document does not release what depends on the
            # entry it replaces: the promise was made about the client, not
            # about this copy of its document.
            protected_until=replaced.protected_until if replaced else 0.0,
        )
        stored = (
            view.replace(client_id, remembered) if replaced else view.create(remembered)
        )
        return stored.value, evicted

    remembered, evicted = transact_refusing(cache(), decide)
    if evicted:
        # Logged here and not where they are dropped: a decision may be run
        # again, and has no effect outside its view.
        logger.info(
            "Dropped the oldest cached client metadata document(s) to stay within %d entries: %s",
            MAX_CACHED_DOCUMENTS,
            ", ".join(evicted),
        )
    return remembered


def retain_until(client_id: str, moment: float) -> bool:
    """Keep a cached client resolvable at least until ``moment``.

    The cache is the only place a CIMD client exists between ``/authorize``
    and ``/token``, so an entry must outlive any authorization code issued
    against it. A lifetime floor cannot promise that: the document is
    cached when it is fetched, and the code is minted later, when the login
    finishes. A document with a short ``max-age`` fetched at 06:00 and a
    code issued at 06:05 leaves five minutes where the code is valid and
    the client is not, with nobody doing anything wrong.

    So the moment the code exists, the entry is extended to cover it. A
    client that is not in the cache - declared, runtime, gone - is not
    this function's business, and it says so by answering ``False``.

    This marks the entry as depended upon, not merely long-lived: the cap
    drops the least recently fetched entry, and one a code was issued
    against is by then one of the oldest. Extending only the lifetime would
    leave it first in line for eviction, which is the same broken flow by
    another route.
    """
    entry = cache().get(client_id)
    if entry is None:
        return False
    if entry.protected_until >= moment:
        return True

    def retained(current: CachedClient) -> CachedClient:
        if current.protected_until >= moment:
            return current  # someone else got there first, and further
        return CachedClient(
            client=current.client,
            fetched_at=current.fetched_at,
            expires_at=current.expires_at,
            protected_until=moment,
        )

    return replace(cache(), client_id, retained) is not None


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
    def decide(view: RepositoryTransaction[CachedClient]) -> Optional[OAuthClient]:
        # Looked at again, in one step with the drop: a concurrent remember
        # may have replaced the expired entry with a fresh document between
        # the check above and here.
        current = view.entry(client_id)
        if current is None:
            return None
        if current.value.is_fresh():
            return current.value.client
        view.delete(client_id)
        return None

    return cache().transact(decide)


def forget(client_id: str) -> bool:
    """Drop one entry: an operator action, and how a developer re-fetches a
    document they have just changed."""
    return cache().delete(client_id)


def forget_all() -> int:
    return cache().delete_all()


def learn_client(client_id: str, settings: Any) -> OAuthClient:
    """Fetch a metadata document, validate it, cache it, return the client.

    The one composition of the two halves, and the reason the halves exist:
    the fetcher performs I/O and knows nothing about the cache, this module
    owns the rules and the cache and knows nothing about sockets, and only
    a caller that is allowed to reach the network calls this. That caller
    is ``/authorize``; the resolver never does, which is what keeps network
    I/O out of the other sixteen places a client is resolved.

    Raises ``ClientIdUrlInvalid``, ``FetchRefused``, ``DocumentInvalid`` or
    ``DocumentNotUsable``. A caller that cannot use any of them has one
    answer for all four.
    """
    from .client_metadata_fetch import DO_NOT_CACHE, fetch_document

    reject_invalid_client_id_url(client_id)
    document, lifetime = fetch_document(client_id, settings)
    client = client_from_document(client_id, document, list(settings.scopes_supported))
    if lifetime is DO_NOT_CACHE or lifetime == DO_NOT_CACHE:
        raise DocumentNotUsable(
            "the document must not be cached, and a client that is not cached "
            "cannot be resolved at the token endpoint"
        )
    remember(client, lifetime)
    return client


def cached_entries() -> List[CachedClient]:
    """Everything currently cached, for a read surface. Expired entries are
    filtered rather than returned with a note: a read surface showing an
    entry nothing would use is a lie about what is in effect."""
    return [entry for entry in cache().list() if entry.is_fresh()]
