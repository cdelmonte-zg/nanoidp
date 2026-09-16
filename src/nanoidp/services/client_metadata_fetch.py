"""Fetching a Client ID Metadata Document (#196, PR B).

The one place nanoidp makes an outbound request, and the only one it ever
should: a URL a client chose, fetched by the server. Every rule here exists
because of that, and the shape of the module is the argument. It knows
nothing about ``/authorize``, which is what calls it (PR C), and nothing
about the cache, which is ``services.client_metadata``'s.

Built on ``http.client`` rather than on an HTTP library, so that nothing is
a flag someone can flip later:

- The connection goes to an address this module resolved and checked, with
  the hostname kept for TLS and for ``Host``. Resolving, approving an
  address and then asking a library to connect by name would be a DNS
  time-of-check-to-time-of-use: the second resolution can differ.
- Redirects are not followed because ``http.client`` cannot follow one.
  The draft says the server MUST NOT.
- The body is bounded while it is read. A ``Content-Length`` is the sender's
  claim, not a limit.
- There is exactly one request. No retry, no second address after a failed
  connection, no redirect: a failure is a failure, and the peer that
  answered is the peer that was checked.

The rules come from draft-ietf-oauth-client-id-metadata-document-02.
"""

import concurrent.futures
import io
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
from typing import Any, List, Optional, Tuple
from urllib.parse import urlsplit

from ..models import Settings

logger = logging.getLogger(__name__)

# A budget for the whole fetch, not a timeout per operation: a server that
# sends one byte at a time would otherwise hold a worker for as long as it
# liked, each read finishing well inside its own limit. Fixed rather than
# configurable, because it is a bound on what a client can cost this
# server, and a setting here would mostly be a way to raise it.
TIMEOUT_SECONDS = 5.0

# The size the draft recommends. Enforced against what is read, so a
# response with no Content-Length, or a dishonest one, is bounded too.
MAX_BODY_BYTES = 5 * 1024
_READ_CHUNK = 1024

ACCEPTED_MEDIA_TYPES = ("application/json",)
_JSON_SUFFIX = "+json"


class FetchRefused(Exception):
    """The document was not fetched, and why.

    One exception for every outcome: a rule refused the URL, the host was
    not allowed, an address was, the connection failed, the answer was not
    a document. The caller has one thing to do about all of them - not
    honour this client_id - and the reason is for the log, not for a
    decision.
    """


def _deadline_remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FetchRefused("the metadata document took longer than the fetch budget")
    return remaining


class _DeadlineSocket:
    """A socket whose read timeout is re-derived from one deadline.

    ``settimeout`` is per operation, so setting it once bounds nothing: a
    peer that sends a byte just inside the limit, forever, is never idle.
    Every read through here re-arms from the deadline, so the timeout
    shrinks to nothing and the whole exchange is bounded - the status line
    and the headers included, which ``http.client`` reads on its own.
    """

    def __init__(self, sock: Any, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline

    def _arm(self) -> None:
        self._sock.settimeout(_deadline_remaining(self._deadline))

    def recv(self, *args: Any, **kwargs: Any) -> bytes:
        self._arm()
        return self._sock.recv(*args, **kwargs)

    def recv_into(self, *args: Any, **kwargs: Any) -> int:
        self._arm()
        return self._sock.recv_into(*args, **kwargs)

    def sendall(self, *args: Any, **kwargs: Any) -> None:
        self._arm()
        self._sock.sendall(*args, **kwargs)

    def send(self, *args: Any, **kwargs: Any) -> int:
        self._arm()
        return self._sock.send(*args, **kwargs)

    def makefile(self, mode: str = "rb", buffering: Optional[int] = None,
                 **kwargs: Any) -> Any:
        """A reader over this wrapper, not over the socket underneath.

        ``http.client`` reads the status line and the headers through the
        object this returns, which is the phase a body-only deadline
        misses.
        """
        raw = socket.SocketIO(self, "r")  # type: ignore[arg-type]
        return io.BufferedReader(raw, buffering or io.DEFAULT_BUFFER_SIZE)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)


class _PinnedConnection:
    """One HTTPS request to one address, with the name kept for TLS.

    Not a connection pool and not reusable: a fetch is a single request to a
    single peer, and everything about this class is arranged so that stays
    true.
    """

    def __init__(self, hostname: str, address: str, port: int, deadline: float) -> None:
        self.hostname = hostname
        self.address = address
        self.port = port
        self.deadline = deadline
        self._sock: Optional[Any] = None
        self._watchdog: Optional[threading.Timer] = None

    def __enter__(self) -> "_PinnedConnection":
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(_deadline_remaining(self.deadline))
            raw.connect((self.address, self.port))
            context = ssl.create_default_context()
            # The certificate is checked against the name the client gave,
            # never against the address dialled: pinning the address must
            # not weaken what the name has to prove.
            raw.settimeout(_deadline_remaining(self.deadline))
            # The handshake is many reads, so the same per-operation problem
            # applies to it. A watchdog closes the socket at the deadline,
            # which no amount of dribbling can outlast.
            self._watchdog = threading.Timer(
                _deadline_remaining(self.deadline), self._abort, args=(raw,)
            )
            self._watchdog.daemon = True
            self._watchdog.start()
            self._sock = _DeadlineSocket(
                context.wrap_socket(raw, server_hostname=self.hostname), self.deadline
            )
        except FetchRefused:
            self._stop_watchdog()
            raw.close()
            raise
        except ssl.SSLError as exc:
            self._stop_watchdog()
            raw.close()
            raise FetchRefused(f"the TLS connection was refused: {exc.__class__.__name__}") from exc
        except OSError as exc:
            self._stop_watchdog()
            raw.close()
            if time.monotonic() >= self.deadline:
                raise FetchRefused(
                    "the metadata document took longer than the fetch budget"
                ) from exc
            raise FetchRefused("the metadata document could not be reached") from exc
        except Exception as exc:
            # Anything else, so nothing but a FetchRefused ever leaves this
            # module and the socket is never left open: ssl encodes the
            # hostname with the idna codec, which raises a UnicodeError for
            # a name it cannot encode.
            self._stop_watchdog()
            raw.close()
            raise FetchRefused("the metadata document could not be reached") from exc
        return self

    @staticmethod
    def _abort(raw: socket.socket) -> None:
        """Close the socket from under a read that will not end."""
        try:
            raw.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _stop_watchdog(self) -> None:
        if self._watchdog is not None:
            self._watchdog.cancel()
            self._watchdog = None

    def __exit__(self, *exc_info: Any) -> None:
        self._stop_watchdog()
        if self._sock is not None:
            self._sock.close()

    def get(self, path: str) -> Tuple[int, Optional[str], bytes, Optional[str]]:
        """Send the one request and read a bounded answer."""
        import http.client

        assert self._sock is not None
        connection = http.client.HTTPConnection(self.hostname, self.port)
        connection.sock = self._sock
        # The socket was handed over, so nothing may dial one: auto_open
        # would reconnect by name, in the clear, to whatever the name
        # resolves to then - the one thing this module exists to prevent.
        connection.auto_open = 0
        try:
            self._sock.settimeout(_deadline_remaining(self.deadline))
            connection.request(
                "GET",
                path,
                headers={
                    # With the port when it is not the scheme's default
                    # (RFC 7230): a name-based virtual host on another port
                    # would otherwise be asked for the wrong resource.
                    "Host": self.hostname if self.port == 443
                    else f"{self.hostname}:{self.port}",
                    "Accept": ", ".join(ACCEPTED_MEDIA_TYPES),
                    "User-Agent": "nanoidp",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            return (
                response.status,
                response.getheader("Content-Type"),
                self._read_bounded(response),
                response.getheader("Cache-Control"),
            )
        except FetchRefused:
            raise
        except (OSError, http.client.HTTPException) as exc:
            # A socket timeout here is the budget running out, because the
            # timeout was set from what was left of it. Saying so names the
            # thing an operator can act on.
            if time.monotonic() >= self.deadline:
                raise FetchRefused(
                    "the metadata document took longer than the fetch budget"
                ) from exc
            raise FetchRefused("the metadata document could not be read") from exc

    def _read_bounded(self, response: Any) -> bytes:
        """At most MAX_BODY_BYTES, within what is left of the budget.

        ``read1`` rather than ``read``: ``read(n)`` waits for n bytes, so a
        server sending eight at a time keeps one call blocked for as long
        as it likes while the deadline check between calls never runs. A
        socket timeout does not save that, because the connection is never
        idle - each byte arrives well inside it. ``read1`` returns what has
        arrived, so the deadline is tested at every turn of the loop, and
        the timeout is reset from it so a genuinely idle peer is caught too.

        Reading one byte past the limit is enough to know the document is
        too big; nothing larger is ever held.
        """
        body = bytearray()
        while len(body) <= MAX_BODY_BYTES:
            assert self._sock is not None
            self._sock.settimeout(_deadline_remaining(self.deadline))
            chunk = response.read1(min(_READ_CHUNK, MAX_BODY_BYTES + 1 - len(body)))
            if not chunk:
                return bytes(body)
            body.extend(chunk)
        raise FetchRefused(
            f"the metadata document is larger than {MAX_BODY_BYTES} bytes"
        )


def allowed_hosts(settings: Settings) -> List[str]:
    """The hostnames an operator has opted in, compared as DNS names.

    Lower-cased and with a trailing dot removed, because those are the same
    name. The ``client_id`` itself is never normalised: the draft matches it
    against the document by simple string comparison.
    """
    return [_dns_name(host) for host in settings.client_id_metadata_documents_allowed_hosts]


def _dns_name(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _resolve(hostname: str, port: int, deadline: float) -> List[str]:
    """The addresses a name answers with, inside the budget.

    ``getaddrinfo`` blocks with no timeout of its own, so a host whose
    nameserver black-holes queries would spend the resolver's own retries -
    tens of seconds - before the budget was ever consulted. It runs on a
    worker so the wait can be given up on. The worker is not killed, because
    nothing can kill it; it ends when the resolver does, and answers nobody.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            socket.getaddrinfo, hostname, port, type=socket.SOCK_STREAM
        )
        try:
            infos = future.result(timeout=_deadline_remaining(deadline))
        except concurrent.futures.TimeoutError as exc:
            raise FetchRefused(
                "the metadata document's host took longer than the budget to resolve"
            ) from exc
        except socket.gaierror as exc:
            raise FetchRefused("the metadata document's host does not resolve") from exc
        except UnicodeError as exc:
            raise FetchRefused("the metadata document's host is not a usable name") from exc
    addresses: List[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FetchRefused("the metadata document's host does not resolve")
    return addresses


def _server_is_on_loopback(settings: Settings) -> bool:
    """Whether nanoidp itself is bound to a loopback address.

    Half of the draft's development exception: it applies when the
    authorization server is on loopback too, so an instance reachable from
    a network cannot be talked into fetching from its own host.
    """
    try:
        return ipaddress.ip_address(settings.host).is_loopback
    except ValueError:
        # A name, or 0.0.0.0. Neither is "this server is on loopback": a
        # wildcard bind is reachable from everywhere it has an address.
        return False


# The one range Python still calls globally routable that an operator has
# no business being sent to: 6to4 relay anycast, deprecated by RFC 7526.
_EXTRA_FORBIDDEN = (ipaddress.ip_network("192.88.99.0/24"),)
# IPv6 forms that carry an IPv4 address inside them. Judging the wrapper
# instead of what it wraps is how ::ffff:169.254.169.254 gets fetched.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(parsed: Any) -> Optional[Any]:
    """The IPv4 address an IPv6 one carries, if it carries one."""
    if parsed.version != 6:
        return None
    if parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    if parsed in _NAT64:
        return ipaddress.ip_address(int(parsed) & 0xFFFFFFFF)
    return None


def _is_routable(parsed: Any) -> bool:
    """Whether this address is one the public internet routes to.

    Allowed means globally routable, rather than "not on a list of bad
    ranges": a list is a thing to keep up to date, and the ranges added
    over the years - RFC 6598 carrier-grade NAT among them, which is also
    what several Kubernetes networks use - are exactly the ones an SSRF
    wants. Multicast counts as global to ``ipaddress`` and is never an
    answer to a request for one document over TCP.
    """
    forbidden_extra = any(
        parsed in network for network in _EXTRA_FORBIDDEN
        if network.version == parsed.version
    )
    return bool(parsed.is_global) and not forbidden_extra and not parsed.is_multicast


def _address_refusal(address: str, settings: Settings) -> Optional[str]:
    """Why this address may not be connected to, or ``None``.

    The development exception is loopback only, and only when the server is
    itself on loopback, and only for the same family it is bound to. RFC
    1918, link-local and unique-local addresses are not in it.
    """
    parsed = ipaddress.ip_address(address)

    embedded = _embedded_ipv4(parsed)
    if embedded is not None:
        # Judged by what it reaches, not by what it looks like:
        # ::ffff:169.254.169.254 is the metadata service. The loopback
        # exception is deliberately not extended to these - such an address
        # is not loopback, it is a global address that translates to one,
        # and the connection would leave this machine.
        if not _is_routable(embedded):
            return "a metadata document may not be fetched from a special-use address"
        return None

    if _is_routable(parsed):
        return None
    if not parsed.is_loopback:
        return "a metadata document may not be fetched from a special-use address"
    if not settings.client_id_metadata_documents_allow_loopback:
        return "a metadata document may not be fetched from a loopback address"
    if not _server_is_on_loopback(settings):
        return (
            "a loopback metadata document is only fetched by a server that is "
            "itself on loopback"
        )
    if ipaddress.ip_address(settings.host).version != parsed.version:
        return "a loopback metadata document must be on the interface this server is bound to"
    return None


def _acceptable_address(
    hostname: str, port: int, settings: Settings, deadline: float
) -> str:
    """One address to connect to, once every address the name has is allowed.

    Every one, not the first acceptable one: a name that answers with a
    public address and a loopback address is a name that can hand out
    either, so it is refused entirely rather than raced.
    """
    addresses = _resolve(hostname, port, deadline)
    for address in addresses:
        refusal = _address_refusal(address, settings)
        if refusal is not None:
            raise FetchRefused(refusal)
    return addresses[0]


# What a document may be kept for, when the answer is "not at all". The
# caller passes the lifetime to client_metadata.remember, which clamps a
# number upwards to a minute; a separate value says do not call it.
DO_NOT_CACHE = "do-not-cache"


def cache_lifetime(cache_control: Optional[str]) -> Any:
    """What the response says it may be kept for, or ``None`` for a default.

    A narrow reading of the header rather than an HTTP cache: ``no-store``
    and ``no-cache`` answer ``DO_NOT_CACHE``, ``max-age`` gives a number
    that ``client_metadata.bounded_lifetime`` will clamp, and ``None``
    means the response said nothing. Anything else is ignored, because
    revalidation is not implemented and pretending otherwise would be the
    part that goes wrong.
    """
    if not cache_control:
        return None
    directives = [directive.strip().lower() for directive in cache_control.split(",")]
    if "no-store" in directives or "no-cache" in directives:
        # Usable, not cacheable. Discarding the document would lock out any
        # client whose host sets no-store globally, which most frameworks
        # and CDNs do for anything that is not a static file, and the rule
        # is about keeping a copy rather than about honouring the answer.
        # no-cache means "not without revalidating", which is not
        # implemented, so it reads the same way.
        return DO_NOT_CACHE
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                return float(directive.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _is_json(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type in ACCEPTED_MEDIA_TYPES or (
        media_type.startswith("application/") and media_type.endswith(_JSON_SUFFIX)
    )


def fetch_document(client_id: str, settings: Settings) -> Tuple[Any, Any]:
    """The document at this client identifier URL, and how long it may be kept.

    The second value is what ``Cache-Control`` said: a number of seconds,
    ``None`` for "it said nothing", or ``DO_NOT_CACHE``. A document that may
    not be cached is still a document.

    Raises ``FetchRefused`` for everything else. The caller's only decision
    is whether it has a document; the reason is for the operator.
    """
    try:
        parts = urlsplit(client_id)
        hostname = _dns_name(parts.hostname or "")
        port = parts.port or 443
    except ValueError as exc:
        # urlsplit and .port both raise on input PR A's URL rules do not
        # look at - a port out of range, an unbalanced bracket. Everything
        # this module refuses is a FetchRefused, including this.
        raise FetchRefused("the client identifier URL cannot be parsed") from exc
    if parts.scheme != "https":
        # Checked here too, not only by the URL rules: this module dials
        # TLS, and a caller that skipped them must not get a TLS handshake
        # on port 80 out of it.
        raise FetchRefused("a metadata document is only fetched over https")
    if not settings.client_id_metadata_documents_enabled:
        raise FetchRefused("client ID metadata documents are not enabled")
    if not hostname:
        raise FetchRefused("the client identifier URL names no host")
    if hostname not in allowed_hosts(settings):
        # Default empty: nothing is fetched until an operator names a host.
        raise FetchRefused("the metadata document's host is not in allowed_hosts")

    deadline = time.monotonic() + TIMEOUT_SECONDS
    address = _acceptable_address(hostname, port, settings, deadline)
    path = parts.path + (f"?{parts.query}" if parts.query else "")

    with _PinnedConnection(hostname, address, port, deadline) as connection:
        status, content_type, body, cache_control = connection.get(path)

    if status != 200:
        # Including a redirect: it is an answer that is not a document, and
        # the draft says it must not be followed.
        raise FetchRefused(f"the metadata document answered {status}")
    if not _is_json(content_type):
        raise FetchRefused("the metadata document is not JSON")
    try:
        document = json.loads(body)
    except ValueError as exc:
        raise FetchRefused("the metadata document is not valid JSON") from exc
    return document, cache_lifetime(cache_control)
