"""Fetching a client's metadata document (#196, PR B).

The first outbound request nanoidp makes, against a URL a client chose, so
every rule here has a negative and the negatives are the deliverable.

The origin is a real HTTPS server with a private CA, serving a certificate
for a name that does not exist in DNS. That is deliberate: the fetcher is
told which address to connect to and has to prove the name anyway, which is
the whole point of pinning the address. Resolution is the seam the tests
drive, because it is the seam an attacker would.
"""

import ipaddress
import socket
import ssl
import time
from pathlib import Path

import pytest

from nanoidp.models import Settings
from nanoidp.services import client_metadata_fetch as fetcher
from nanoidp.services.client_metadata_fetch import (
    DO_NOT_CACHE,
    MAX_BODY_BYTES,
    TIMEOUT_SECONDS,
    FetchRefused,
    cache_lifetime,
    fetch_document,
)
from tests.cimd_harness import HOSTNAME, Origin, issue_certificates, metadata_document


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    return issue_certificates(tmp_path_factory.mktemp("cimd-ca"))


@pytest.fixture
def trust_the_test_ca(certificates, monkeypatch):
    """The default context reads SSL_CERT_FILE, so the production code is
    not given a test-only way to trust something."""
    ca_path, _ = certificates
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    return ca_path


@pytest.fixture
def origin(certificates, trust_the_test_ca):
    _, server_pem = certificates
    with Origin(server_pem) as running:
        yield running


def _settings(port=None, **overrides):
    """``port`` is the harness's, because an allowlist entry names a host
    and a port: opting a host in must not open every port on it."""
    values = {
        "host": "127.0.0.1",
        "client_id_metadata_documents_enabled": True,
        "client_id_metadata_documents_allowed_hosts": [
            f"{HOSTNAME}:{port}" if port else HOSTNAME
        ],
        "client_id_metadata_documents_allow_loopback": True,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def resolves_to_loopback(monkeypatch):
    """The name the certificate is for does not exist in DNS. The tests say
    where it lives, which is also how they say where an attacker would."""

    def resolve(addresses):
        def getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET6 if ":" in address else socket.AF_INET,
                 socket.SOCK_STREAM, 6, "", (address, port))
                for address in addresses
            ]

        monkeypatch.setattr(fetcher.socket, "getaddrinfo", getaddrinfo)

    resolve(["127.0.0.1"])
    return resolve


def _client_id(origin, path="/metadata.json"):
    return f"https://{HOSTNAME}:{origin.port}{path}"


class TestTheHappyPath:
    def test_a_document_is_fetched_and_parsed(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        document, lifetime = fetch_document(client_id, _settings(origin.port))

        assert document["client_id"] == client_id
        assert lifetime is None

    def test_the_request_carries_the_name_not_the_address(self, origin, resolves_to_loopback):
        """TLS proved the name, and Host says it: the address is a routing
        decision this module made, not something the origin is told."""
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        fetch_document(client_id, _settings(origin.port))

        path, headers = origin.requests[-1]
        assert path == "/metadata.json"
        # With the port, because it is not the scheme's default: a
        # name-based virtual host would otherwise serve another resource.
        assert headers["Host"] == f"{HOSTNAME}:{origin.port}"
        assert "application/json" in headers["Accept"]

    def test_a_json_suffix_media_type_is_accepted(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        origin.content_type = "application/client-metadata+json; charset=utf-8"

        assert fetch_document(client_id, _settings(origin.port))[0]["client_id"] == client_id


class TestTheAnswerMustBeADocument:
    @pytest.mark.parametrize("status", [201, 204, 400, 404, 500])
    def test_only_200_is_a_document(self, origin, resolves_to_loopback, status):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        origin.status = status

        with pytest.raises(FetchRefused, match="answered"):
            fetch_document(client_id, _settings(origin.port))

    @pytest.mark.parametrize("status", [301, 302, 307, 308])
    def test_a_redirect_is_an_answer_not_a_hop(self, origin, resolves_to_loopback, status):
        """The draft says the server must not follow one. Nothing here can:
        the refusal is the status, and there is no second request."""
        client_id = _client_id(origin)
        origin.status = status
        origin.location = "/elsewhere.json"

        with pytest.raises(FetchRefused, match="answered"):
            fetch_document(client_id, _settings(origin.port))

        assert len(origin.requests) == 1

    @pytest.mark.parametrize(
        "content_type", [None, "text/html", "text/plain", "application/xml", "json"]
    )
    def test_a_body_that_does_not_claim_to_be_json_is_refused(
        self, origin, resolves_to_loopback, content_type
    ):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        origin.content_type = content_type

        with pytest.raises(FetchRefused, match="not JSON"):
            fetch_document(client_id, _settings(origin.port))

    def test_a_body_that_is_not_json_is_refused(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.body = b"{not json at all"

        with pytest.raises(FetchRefused, match="not valid JSON"):
            fetch_document(client_id, _settings(origin.port))


class TestTheBodyIsBounded:
    def test_an_oversize_body_is_refused(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.body = b'{"padding": "' + b"x" * (MAX_BODY_BYTES * 2) + b'"}'

        with pytest.raises(FetchRefused, match="larger than"):
            fetch_document(client_id, _settings(origin.port))

    def test_the_limit_does_not_depend_on_content_length(self, origin, resolves_to_loopback):
        """Chunked, so the sender declares no size at all. A limit that
        trusted Content-Length would not be a limit."""
        client_id = _client_id(origin)
        origin.body = b'{"padding": "' + b"x" * (MAX_BODY_BYTES * 2) + b'"}'
        origin.chunk_size = 512

        with pytest.raises(FetchRefused, match="larger than"):
            fetch_document(client_id, _settings(origin.port))

    def test_a_document_just_under_the_limit_is_read(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        document = metadata_document(client_id)
        padding = MAX_BODY_BYTES - len(str(document)) - 40
        document["client_name"] = "x" * padding
        origin.serve_document(document)

        assert len(origin.body) < MAX_BODY_BYTES
        assert fetch_document(client_id, _settings(origin.port))[0]["client_name"] == "x" * padding


class TestTheBudgetIsForTheWholeFetch:
    def test_a_server_that_drips_cannot_outlast_the_budget(
        self, origin, resolves_to_loopback, monkeypatch
    ):
        """The subtlety a per-operation timeout misses: every read finishes
        well inside its own limit while the fetch as a whole never ends.
        The timeout is recomputed from one deadline, so it shrinks."""
        monkeypatch.setattr(fetcher, "TIMEOUT_SECONDS", 1.0)
        client_id = _client_id(origin)
        document = metadata_document(client_id)
        document["client_name"] = "x" * 3000
        origin.serve_document(document)
        origin.chunk_size = 8
        origin.chunk_delay = 0.2  # each chunk is far inside the budget

        started = time.monotonic()
        with pytest.raises(FetchRefused, match="budget"):
            fetch_document(client_id, _settings(origin.port))
        elapsed = time.monotonic() - started

        assert elapsed < 3.0, f"the fetch ran for {elapsed:.1f}s on a 1s budget"

    def test_a_server_that_drips_headers_cannot_outlast_it_either(
        self, origin, resolves_to_loopback, monkeypatch
    ):
        """The same trick one phase earlier. http.client reads the status
        line and the headers itself, so a deadline that only governs the
        body governs the half an origin controls."""
        monkeypatch.setattr(fetcher, "TIMEOUT_SECONDS", 1.0)
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        origin.header_lines = 60
        origin.header_delay = 0.3

        started = time.monotonic()
        with pytest.raises(FetchRefused):
            fetch_document(client_id, _settings(origin.port))
        elapsed = time.monotonic() - started

        assert elapsed < 3.0, f"the header phase ran for {elapsed:.1f}s on a 1s budget"

    def test_a_server_that_drips_the_handshake_cannot_outlast_it(
        self, monkeypatch, resolves_to_loopback
    ):
        """The one place the per-operation rule does not bite: ssl applies
        the socket timeout to the handshake as a whole, not to each read.
        The rest of this module works around the opposite, so the exception
        is pinned rather than assumed - if it ever stopped being true, the
        handshake would be the unbounded phase."""
        import threading

        monkeypatch.setattr(fetcher, "TIMEOUT_SECONDS", 1.0)
        ready, port = threading.Event(), []

        def dribble():
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port.append(listener.getsockname()[1])
            ready.set()
            try:
                connection, _ = listener.accept()
                connection.recv(4096)
                # A well formed record header announcing a long record, so
                # the peer waits for the rest rather than rejecting a
                # malformed one - the refusal has to be the budget, not a
                # protocol error arriving sooner.
                connection.sendall(b"\x16\x03\x03\x40\x00")
                for _ in range(200):
                    connection.sendall(b"\x00")
                    time.sleep(0.3)
            except OSError:
                pass
            finally:
                listener.close()

        threading.Thread(target=dribble, daemon=True).start()
        ready.wait(5)
        # Without this the name does not resolve and the test would pass
        # long before any handshake, which is how it first passed.
        resolves_to_loopback(["127.0.0.1"])

        started = time.monotonic()
        with pytest.raises(FetchRefused):
            fetch_document(f"https://{HOSTNAME}:{port[0]}/metadata.json", _settings(port[0]))
        elapsed = time.monotonic() - started

        assert elapsed < 3.0, f"the handshake ran for {elapsed:.1f}s on a 1s budget"

    def test_a_slow_resolver_cannot_outlast_it_either(self, monkeypatch):
        """A pool created per fetch cannot work: leaving its context manager
        waits for the task it was given, so the request waits for the
        resolver anyway. Measured at 2.0s on a 0.1s budget before this."""
        monkeypatch.setattr(fetcher, "TIMEOUT_SECONDS", 0.2)

        def slow(*args, **kwargs):
            time.sleep(3)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        monkeypatch.setattr(fetcher.socket, "getaddrinfo", slow)

        started = time.monotonic()
        with pytest.raises(FetchRefused, match="resolve"):
            fetch_document(f"https://{HOSTNAME}/metadata.json", _settings())
        elapsed = time.monotonic() - started

        assert elapsed < 1.0, f"the fetch waited {elapsed:.1f}s for a resolver it gave up on"

    def test_the_resolver_pool_is_bounded_and_shared(self):
        """Not a pool per request: under a run of slow names that would be a
        thread per request. Two workers for the process, so the third fetch
        waits for its own budget and then fails."""
        assert fetcher._RESOLVER_WORKERS == 2
        assert fetcher._resolver() is fetcher._resolver()

    def test_the_budget_is_not_configurable(self):
        """A bound on what a client can cost this server, not a preference.
        A setting here would mostly be a way to raise it."""
        assert TIMEOUT_SECONDS == 5.0
        assert not any(
            "timeout" in name for name in Settings.model_fields
            if "client_id_metadata" in name
        )


class TestNothingEscapesAsSomethingElse:
    """Every refusal is a FetchRefused. Once PR C calls this from
    /authorize, anything else is an unhandled exception on an
    unauthenticated endpoint."""

    @pytest.mark.parametrize(
        "client_id",
        [
            # PR A's URL rules never look at the port, and urlsplit raises
            # when asked for one it cannot parse.
            f"https://{HOSTNAME}:99999/metadata.json",
            f"https://{HOSTNAME}:abc/metadata.json",
            f"https://{HOSTNAME}:-1/metadata.json",
            "https://[unbalanced/metadata.json",
        ],
    )
    def test_a_url_that_cannot_be_parsed_is_refused_not_raised(self, client_id):
        with pytest.raises(FetchRefused):
            fetch_document(client_id, _settings())

    def test_nothing_is_fetched_when_the_feature_is_off(self, origin, resolves_to_loopback):
        """Checked here as well as by the caller: an operator who filled in
        allowed_hosts with the feature off is not protected by a call site
        alone."""
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        with pytest.raises(FetchRefused, match="not enabled"):
            fetch_document(
                client_id, _settings(client_id_metadata_documents_enabled=False)
            )

        assert origin.requests == []


class TestTheDeadlineSocket:
    """The wrapper on its own.

    The budget is held in two places, for two reasons: ``ssl`` applies the
    socket timeout to the handshake as a whole, so that phase needs nothing
    but the remaining deadline, while ``http.client`` reads the status line,
    the headers and the body itself, and a timeout set once bounds none of
    that against a peer that is never idle. This wrapper is the second half,
    and it is exercised directly as well as through a fetch.
    """

    def test_every_read_re_arms_the_timeout_from_the_deadline(self):
        armed = []

        class FakeSocket:
            def settimeout(self, value):
                armed.append(value)

            def recv_into(self, buffer, *args):
                buffer[:1] = b"x"
                return 1

        wrapped = fetcher._DeadlineSocket(FakeSocket(), time.monotonic() + 5)
        buffer = bytearray(1)
        wrapped.recv_into(buffer)
        wrapped.recv_into(buffer)

        assert len(armed) == 2
        assert armed[1] < armed[0], "the budget did not shrink between reads"

    def test_a_read_past_the_deadline_is_refused(self):
        class FakeSocket:
            def settimeout(self, value):
                pass

            def recv_into(self, buffer, *args):
                return 0

        wrapped = fetcher._DeadlineSocket(FakeSocket(), time.monotonic() - 1)

        with pytest.raises(FetchRefused, match="budget"):
            wrapped.recv_into(bytearray(1))

    def test_the_reader_it_hands_out_goes_through_it(self):
        """http.client reads the status line and headers through makefile,
        so a reader over the socket underneath would skip the re-arming."""
        armed = []

        class FakeSocket:
            def settimeout(self, value):
                armed.append(value)

            def recv_into(self, buffer, *args):
                return 0

        wrapped = fetcher._DeadlineSocket(FakeSocket(), time.monotonic() + 5)
        wrapped.makefile("rb").read()

        assert armed, "the reader did not re-arm the timeout"


class TestWhichHostsMayBeFetched:
    def test_nothing_is_fetched_until_a_host_is_opted_in(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        with pytest.raises(FetchRefused, match="allowed_hosts"):
            fetch_document(
                client_id, _settings(client_id_metadata_documents_allowed_hosts=[])
            )

        assert origin.requests == [], "a refused host must not be contacted"

    def test_a_host_is_matched_exactly(self, origin, resolves_to_loopback):
        """No wildcards: a wildcard turns a list of hosts into a list of
        zones, which is rarely what the person writing it meant."""
        client_id = _client_id(origin)

        for allowed in (["other.example"], ["*.example"], ["example"], ["ient.example"]):
            with pytest.raises(FetchRefused, match="allowed_hosts"):
                fetch_document(
                    client_id,
                    _settings(client_id_metadata_documents_allowed_hosts=allowed),
                )

    def test_a_host_is_allowed_on_one_port_not_on_every_port(
        self, origin, resolves_to_loopback
    ):
        """Naming a host must not turn this server into a way to reach
        :22 or :6379 on it, at a path of the caller's choosing."""
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        with pytest.raises(FetchRefused, match="allowed_hosts"):
            fetch_document(
                client_id,
                _settings(client_id_metadata_documents_allowed_hosts=[
                    f"{HOSTNAME}:{origin.port + 1}"
                ]),
            )

        assert origin.requests == []

    def test_an_entry_with_no_port_means_443(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        with pytest.raises(FetchRefused, match="allowed_hosts"):
            fetch_document(
                client_id,
                _settings(client_id_metadata_documents_allowed_hosts=[HOSTNAME]),
            )

    def test_the_comparison_is_a_dns_one(self, origin, resolves_to_loopback):
        """Case and a trailing dot are the same name; the client_id itself
        is never normalised, since the draft compares it literally."""
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        allowed = [f"{HOSTNAME.upper()}."]
        assert fetch_document(
            client_id, _settings(client_id_metadata_documents_allowed_hosts=[f'{a}:{origin.port}' for a in allowed])
        )[0]["client_id"] == client_id


class TestWhichAddressesMayBeConnectedTo:
    def _fetch(self, origin, addresses, resolves_to_loopback, **settings):
        resolves_to_loopback(addresses)
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        return fetch_document(client_id, _settings(origin.port, **settings))

    @pytest.mark.parametrize(
        "address",
        [
            "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254",
            "fd00::1", "fe80::1", "224.0.0.1", "0.0.0.0",
            # RFC 6598 carrier-grade NAT, which several Kubernetes networks
            # use for pods: ipaddress calls it neither private nor reserved.
            "100.64.0.1",
            # 6to4 relay anycast, which ipaddress still calls globally
            # routable.
            "192.88.99.1",
            # An IPv4 address inside an IPv6 one. Judging the wrapper rather
            # than what it reaches is how the metadata service gets fetched.
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
        ],
    )
    def test_a_special_use_address_is_refused(self, origin, resolves_to_loopback, address):
        with pytest.raises(FetchRefused, match="special-use|loopback"):
            self._fetch(origin, [address], resolves_to_loopback)

    def test_every_resolved_address_must_be_acceptable(self, origin, resolves_to_loopback):
        """Not "find one that is allowed": a name that answers with a public
        address and a loopback one can hand out either, so it is refused
        entirely rather than raced."""
        with pytest.raises(FetchRefused):
            self._fetch(origin, ["127.0.0.1", "10.0.0.5"], resolves_to_loopback)

    def test_a_name_that_does_not_resolve_is_refused(self, origin, monkeypatch):
        def fails(*args, **kwargs):
            raise socket.gaierror("no such host")

        monkeypatch.setattr(fetcher.socket, "getaddrinfo", fails)

        with pytest.raises(FetchRefused, match="does not resolve"):
            fetch_document(_client_id(origin), _settings(origin.port))


class TestTheInterpreterDoesNotDecide:
    """CVE-2024-4032: supported CPython patch releases older than 3.10.15 /
    3.11.10 / 3.12.4 call these special-purpose addresses globally
    reachable. Raising requires-python would not settle it - >=3.10.15
    still admits 3.11.0 to 3.11.9 - so the ranges are named in the module
    and asserted here, on whatever interpreter happens to run the suite.
    """

    @pytest.mark.parametrize(
        "address",
        [
            "192.0.0.1",        # IETF protocol assignments
            "192.0.0.171",
            "64:ff9b:1::1",     # local-use NAT64
            "2002::1",          # 6to4
            "2001::1",          # Teredo
            "2001:2::1",        # benchmarking
        ],
    )
    def test_an_address_an_old_interpreter_calls_global_is_refused(self, address):
        assert not fetcher._is_routable(ipaddress.ip_address(address))

    @pytest.mark.parametrize(
        "address",
        [
            # The exceptions are the point: these sit inside the ranges
            # above and the registry does call them globally reachable, so
            # a simpler rule would refuse what is allowed.
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
        ],
    )
    def test_the_exceptions_inside_those_ranges_stay_routable(self, address):
        assert fetcher._is_routable(ipaddress.ip_address(address))

    @pytest.mark.parametrize(
        "address", ["192.0.0.1", "64:ff9b:1::1", "2002::1", "2001::1"]
    )
    def test_they_are_refused_even_when_the_interpreter_says_global(
        self, address, monkeypatch
    ):
        """The condition the table exists for, reproduced rather than
        waited for: on an interpreter with the CVE, is_global answers True
        for these. On a corrected one the table is redundant, which is why
        nothing else here can tell whether it is consulted at all.
        """
        monkeypatch.setattr(
            ipaddress.IPv4Address, "is_global", property(lambda self: True)
        )
        monkeypatch.setattr(
            ipaddress.IPv6Address, "is_global", property(lambda self: True)
        )

        assert not fetcher._is_routable(ipaddress.ip_address(address))

    @pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700::1111"])
    def test_an_ordinary_public_address_is_still_routable(self, address):
        """The correction must not become a deny-list that swallows the
        internet."""
        assert fetcher._is_routable(ipaddress.ip_address(address))


class TestTheLoopbackException:
    def _attempt(self, origin, resolves_to_loopback, addresses, **settings):
        resolves_to_loopback(addresses)
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        return fetch_document(client_id, _settings(origin.port, **settings))

    def test_loopback_is_refused_unless_it_is_opted_in(self, origin, resolves_to_loopback):
        with pytest.raises(FetchRefused, match="loopback"):
            self._attempt(
                origin, resolves_to_loopback, ["127.0.0.1"],
                client_id_metadata_documents_allow_loopback=False,
            )

    def test_a_server_not_on_loopback_does_not_get_the_exception(
        self, origin, resolves_to_loopback
    ):
        """Half the rule: an instance reachable from a network must not be
        talked into fetching from its own host."""
        with pytest.raises(FetchRefused, match="itself on loopback"):
            self._attempt(origin, resolves_to_loopback, ["127.0.0.1"], host="0.0.0.0")

    def test_the_family_must_be_the_one_the_server_is_bound_to(
        self, origin, resolves_to_loopback
    ):
        with pytest.raises(FetchRefused, match="interface"):
            self._attempt(origin, resolves_to_loopback, ["::1"], host="127.0.0.1")

    def test_a_private_address_is_refused_even_with_the_exception_on(
        self, origin, resolves_to_loopback
    ):
        with pytest.raises(FetchRefused, match="special-use"):
            self._attempt(origin, resolves_to_loopback, ["10.0.0.5"])


class TestTls:
    def test_the_floor_is_tls_1_2_and_it_is_said_here(self):
        """Not left to whatever policy the machine carries:
        create_default_context leaves minimum_version at MINIMUM_SUPPORTED,
        and this connects to a host a client chose."""
        context = fetcher.tls_context()

        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_an_untrusted_certificate_is_refused(self, origin, resolves_to_loopback, monkeypatch):
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        with pytest.raises(FetchRefused, match="TLS"):
            fetch_document(client_id, _settings(origin.port))

    def test_the_certificate_must_name_the_host_that_was_asked_for(
        self, origin, resolves_to_loopback, monkeypatch
    ):
        """Pinning the address must not weaken what the name has to prove."""
        client_id = f"https://other.example:{origin.port}/metadata.json"
        origin.serve_document(metadata_document(client_id))

        with pytest.raises(FetchRefused, match="TLS"):
            fetch_document(
                client_id,
                _settings(
                    client_id_metadata_documents_allowed_hosts=[
                        f"other.example:{origin.port}"
                    ]
                ),
            )

    def test_an_http_url_is_refused_rather_than_dialled_with_tls(
        self, origin, resolves_to_loopback
    ):
        """The URL rules refuse the scheme first, but this module dials TLS,
        so it refuses it too rather than trusting the caller to have."""
        with pytest.raises(FetchRefused, match="https"):
            fetch_document(f"http://{HOSTNAME}:{origin.port}/metadata.json", _settings())

        assert origin.requests == []


class TestTheCacheLifetime:
    @pytest.mark.parametrize(
        "header, expected",
        [
            (None, None),
            ("", None),
            ("max-age=120", 120.0),
            ("public, max-age=600", 600.0),
            ("max-age=notanumber", None),
            ("public", None),
        ],
    )
    def test_max_age_is_read_and_nothing_else_is(self, header, expected):
        assert cache_lifetime(header) == expected

    @pytest.mark.parametrize("header", ["no-store", "no-cache", "private, no-store"])
    def test_a_document_that_says_not_to_keep_it_says_so(self, header):
        """no-cache means "not without revalidating", which is not
        implemented, so the conservative reading is the honest one."""
        assert cache_lifetime(header) == DO_NOT_CACHE

    def test_a_valid_document_is_returned_with_the_do_not_cache_answer(
        self, origin, resolves_to_loopback
    ):
        """Refusing here would discard a good document, which is a different
        thing from not caching it. What a caller can do with one it may not
        keep is the caller's decision: with the cache the only place a CIMD
        client exists between /authorize and /token, PR C will refuse the
        authorization request rather than issue a code for a client /token
        cannot resolve."""
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        origin.cache_control = "no-store"

        document, lifetime = fetch_document(client_id, _settings(origin.port))

        assert document["client_id"] == client_id
        assert lifetime == DO_NOT_CACHE

    def test_the_lifetime_reaches_the_caller(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))
        origin.cache_control = "max-age=300"

        assert fetch_document(client_id, _settings(origin.port))[1] == 300.0


class TestExactlyOneRequest:
    def test_a_refused_connection_is_not_retried(self, origin, resolves_to_loopback, monkeypatch):
        """No retry and no second address: the peer that answered is the
        peer that was checked, and a failure is a failure."""
        attempts = []
        real_connect = socket.socket.connect

        def counting_connect(self, address):
            attempts.append(address)
            raise OSError("refused")

        monkeypatch.setattr(socket.socket, "connect", counting_connect)
        try:
            with pytest.raises(FetchRefused, match="could not be reached"):
                fetch_document(_client_id(origin), _settings(origin.port))
        finally:
            monkeypatch.setattr(socket.socket, "connect", real_connect)

        assert len(attempts) == 1

    def test_a_successful_fetch_makes_one_request(self, origin, resolves_to_loopback):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id))

        fetch_document(client_id, _settings(origin.port))

        assert len(origin.requests) == 1


class TestNothingIsCachedHere:
    def test_the_fetcher_imports_nothing_from_the_cache(self):
        """Two modules, two questions. A fetcher that remembered would make
        "only successes are cached" a property of this file too, and the
        draft's rule about not caching failures would live in two places."""
        import ast

        tree = ast.parse(Path(fetcher.__file__).read_text())
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        } | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }

        assert not any("client_metadata" in name for name in imported), imported
