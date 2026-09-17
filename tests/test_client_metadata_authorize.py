"""A metadata-document client through a real authorization flow (#196, PR C).

PR A made the resolver read a third origin and PR B made the fetch safe.
This is where they meet, and the properties worth holding are about which
surface may fetch and what happens when one may not:

- ``/authorize`` is the only place that fetches, and only on a miss.
- ``/token`` never fetches, so a document that is not cached is an unknown
  client there - asserted with the origin shut down and the cache emptied,
  which is the state a second nanoidp process would be in.
"""

import base64
import hashlib
import os
import shutil
import time as clock
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.routes import oauth as oauth_routes
from nanoidp.services import client_metadata, client_metadata_fetch
from nanoidp.services.client_metadata import cached_client, cached_entries
from nanoidp.services.identities import get_identities
from tests.cimd_harness import HOSTNAME, Origin, issue_certificates, metadata_document

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:3000/callback"


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    return issue_certificates(tmp_path_factory.mktemp("cimd-authorize-ca"))


@pytest.fixture
def origin(certificates, monkeypatch):
    ca_path, server_pem = certificates
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    with Origin(server_pem) as running:
        yield running


@pytest.fixture
def resolves_to_loopback(monkeypatch):
    import socket

    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(client_metadata_fetch.socket, "getaddrinfo", getaddrinfo)


@pytest.fixture
def app(tmp_path, origin):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document["oauth"]["client_id_metadata_documents"] = {
        "enabled": True,
        # With the port: naming a host opts in one port on it, not every
        # port, and the harness listens on an ephemeral one.
        "allowed_hosts": [f"{HOSTNAME}:{origin.port}"],
        "allow_loopback": True,
    }
    settings.write_text(yaml.safe_dump(document))
    application = create_app(str(config_dir))
    application.config["TESTING"] = True
    return application


def _client_id(origin, path="/metadata.json"):
    return f"https://{HOSTNAME}:{origin.port}{path}"


def _authorize_query(client_id, **overrides):
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "scope": "openid profile",
        "state": "s1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    query.update(overrides)
    return query, verifier


class TestAuthorizeLearnsTheClient:
    def test_a_published_document_completes_an_authorization_code_flow(
        self, app, origin, resolves_to_loopback
    ):
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        query, verifier = _authorize_query(client_id)

        client.get("/authorize", query_string=query)
        authorized = client.post(
            "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
        )
        code = parse_qs(urlparse(authorized.headers["Location"]).query)["code"][0]
        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )

        assert token.status_code == 200
        assert token.get_json()["access_token"]

    def test_the_document_is_fetched_once_and_then_read_from_the_cache(
        self, app, origin, resolves_to_loopback
    ):
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        query, _ = _authorize_query(client_id)

        client.get("/authorize", query_string=query)
        client.get("/authorize", query_string=query)

        assert len(origin.requests) == 1

    def test_it_is_listed_as_a_client_with_its_origin(self, app, origin, resolves_to_loopback):
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        query, _ = _authorize_query(client_id)
        client.get("/authorize", query_string=query)

        with app.app_context():
            listed = {
                entry.client.client_id: entry.origin
                for entry in get_identities().list_clients()
            }

        assert listed[client_id] == "cimd"
        assert listed["demo-client"] == "declared"


class TestOnlyAuthorizeFetches:
    def test_a_declared_client_whose_id_is_a_url_is_never_fetched(
        self, app, origin, resolves_to_loopback
    ):
        """An operator must not cause an outbound request by naming a client
        that way. The draft contemplates pre-registered identifier URLs."""
        client = app.test_client()
        client_id = _client_id(origin)
        with app.app_context():
            from nanoidp.config import OAuthClient

            get_config().settings.clients.append(
                OAuthClient(client_id=client_id, client_secret="declared",
                            redirect_uris=[REDIRECT])
            )
        query, _ = _authorize_query(client_id)

        client.get("/authorize", query_string=query)

        assert origin.requests == []

    def test_token_does_not_fetch_and_an_uncached_client_is_unknown(
        self, app, origin, resolves_to_loopback
    ):
        """The invariant the whole shape exists for, in the state a second
        nanoidp process would be in: the document was never fetched here,
        and the token endpoint must not go and get it."""
        client = app.test_client()
        client_id = _client_id(origin)

        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "not-a-real-code",
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": "x" * 43,
            },
        )

        assert response.status_code in (400, 401)
        assert origin.requests == [], "/token reached the network"

    def test_token_still_answers_with_the_origin_gone(
        self, app, origin, resolves_to_loopback
    ):
        """Authorize once so the client is cached, then take the origin
        away: /token reads the cache and never notices."""
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        query, verifier = _authorize_query(client_id)
        client.get("/authorize", query_string=query)
        authorized = client.post(
            "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
        )
        code = parse_qs(urlparse(authorized.headers["Location"]).query)["code"][0]

        origin.__exit__()  # the client's server is gone

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )

        assert token.status_code == 200


class TestWhatIsRefused:
    def _authorize(self, app, client_id):
        query, _ = _authorize_query(client_id)
        return app.test_client().get("/authorize", query_string=query)

    def test_every_refusal_answers_the_same_unknown_client(
        self, app, origin, resolves_to_loopback
    ):
        """Saying which rule refused would tell whoever chose the URL
        whether a host is allowed, whether it resolved, what it answered.
        The reason is in the audit, where an operator reads it."""
        origin.status = 404
        refused = self._authorize(app, _client_id(origin))

        origin.status = 200
        origin.serve_document(metadata_document("https://elsewhere.example/m.json"))
        mismatched = self._authorize(app, _client_id(origin))

        not_allowed = self._authorize(app, "https://other.example/m.json")

        for response in (refused, mismatched, not_allowed):
            assert response.status_code == 400
            assert response.get_json()["error"] == "invalid_client"
            assert response.get_json()["error_description"] == "Unknown client_id"

    def test_a_document_that_may_not_be_cached_is_refused_at_authorize(
        self, app, origin, resolves_to_loopback
    ):
        """Issuing a code for it would produce one /token could never
        redeem, since the cache is where a CIMD client lives between the
        two."""
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        origin.cache_control = "no-store"

        response = self._authorize(app, client_id)

        assert response.status_code == 400
        with app.app_context():
            assert cached_client(client_id) is None

    def test_nothing_happens_at_all_when_the_feature_is_off(self, app, origin, resolves_to_loopback):
        """Not merely refused: not attempted. The fetcher checks the flag
        too, so a route that did not would still make no request - and
        would record a refusal for something nobody asked it to do."""
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        with app.app_context():
            get_config().settings.client_id_metadata_documents_enabled = False

        response = self._authorize(app, client_id)

        assert response.status_code == 400
        assert origin.requests == []
        entries = client.get("/api/audit").get_data(as_text=True)
        assert "client_metadata_document_refused" not in entries

    def test_a_refusal_is_audited_without_its_reason(self, app, origin, resolves_to_loopback):
        """GET /api/audit is readable by anyone who can reach it, so a
        reason in the entry would hand back through one surface exactly
        what the uniform error withholds on the other. The event is
        recorded; the why is in the server log."""
        client = app.test_client()
        origin.status = 500
        self._authorize(app, _client_id(origin))

        entries = client.get("/api/audit").get_data(as_text=True)

        assert "client_metadata_document_refused" in entries
        for leak in ("allowed_hosts", "does not resolve", "answered", "larger than"):
            assert leak not in entries, f"the audit says why: {leak}"

    @pytest.mark.parametrize(
        "client_id",
        [
            # urlsplit raises a bare ValueError for these, which is not one
            # of the errors the route catches: it left /authorize as a 500
            # from an unauthenticated request.
            "https://[::1",
            "https://[abc]x/p",
            "https://user@[::1/p",
        ],
    )
    def test_a_malformed_url_is_refused_not_raised(self, app, client_id):
        response = self._authorize(app, client_id)

        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_client"

    def test_a_url_that_is_not_ascii_is_refused_not_raised(
        self, app, origin, resolves_to_loopback
    ):
        """A request target is ASCII. Without the rule the URL passed
        validation and http.client raised UnicodeEncodeError building the
        request line: a 500 from an unauthenticated endpoint."""
        response = self._authorize(app, f"https://{HOSTNAME}:{origin.port}/caf\u00e9.json")

        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_client"
        assert origin.requests == []

    def test_this_server_will_not_be_made_to_fetch_without_end(
        self, app, origin, resolves_to_loopback, monkeypatch
    ):
        """Only successes are cached, so a URL that fails validation is
        fetched again every time it is asked for, and /authorize is
        unauthenticated. The limit is on the fetch, not on the endpoint:
        that is where the cost is, and the endpoint is where people log
        in."""
        monkeypatch.setattr(client_metadata_fetch, "MAX_FETCHES_PER_MINUTE", 3)
        monkeypatch.setattr(client_metadata_fetch, "_fetch_times", [])
        origin.status = 404

        for _ in range(6):
            self._authorize(app, _client_id(origin))

        assert len(origin.requests) == 3

    def test_a_refused_host_does_not_spend_the_budget(
        self, app, origin, resolves_to_loopback, monkeypatch
    ):
        """The limit is on the fetch, so what is refused locally must cost
        nothing: otherwise a caller naming a host nobody allowed, thirty
        times, denies the allowance to a client on a host that is."""
        monkeypatch.setattr(client_metadata_fetch, "MAX_FETCHES_PER_MINUTE", 3)
        monkeypatch.setattr(client_metadata_fetch, "_fetch_times", [])
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))

        for _ in range(10):
            self._authorize(app, "https://not-allowed.example/x.json")

        query, _ = _authorize_query(client_id)
        assert app.test_client().get("/authorize", query_string=query).status_code == 200
        assert len(origin.requests) == 1

    def test_an_ordinary_login_is_not_rate_limited_by_it(
        self, app, origin, resolves_to_loopback, monkeypatch
    ):
        """The budget must not become a limit on /authorize itself."""
        monkeypatch.setattr(client_metadata_fetch, "MAX_FETCHES_PER_MINUTE", 1)
        monkeypatch.setattr(client_metadata_fetch, "_fetch_times", [])
        client = app.test_client()
        query, _ = _authorize_query("demo-client")

        for _ in range(5):
            assert client.get("/authorize", query_string=query).status_code == 200


class TestTheReadSurface:
    def _learn(self, app, origin):
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        query, _ = _authorize_query(client_id)
        app.test_client().get("/authorize", query_string=query)
        return client_id

    def test_a_cached_client_is_shown_read_only(self, app, origin, resolves_to_loopback):
        """It is not the operator's client to edit: nothing here writes
        settings.yaml, and an Edit button would offer a page that cannot
        save."""
        from flask import url_for

        client_id = self._learn(app, origin)

        page = app.test_client().get("/clients").get_data(as_text=True)

        assert client_id in page
        assert ">cimd<" in page
        # Built the way the template would build it, since url_for encodes
        # the URL in the path and a literal comparison would pass whatever
        # the page said.
        with app.test_request_context():
            edit = url_for("ui.client_edit", client_id=client_id)
            regenerate = url_for("ui.client_regenerate_secret", client_id=client_id)
        assert edit not in page
        assert regenerate not in page
        # And the declared client's actions are still there, so this is not
        # passing because the page lost its buttons.
        with app.test_request_context():
            assert url_for("ui.client_edit", client_id="demo-client") in page
            # The one action a cached client does have, so "read-only" is
            # not being satisfied by an empty cell.
            assert url_for("ui.client_forget") in page

    def test_an_operator_can_forget_one(self, app, origin, resolves_to_loopback):
        """How a developer re-fetches a document they have just changed."""
        client = app.test_client()
        client_id = self._learn(app, origin)
        assert len(origin.requests) == 1

        client.post("/clients/forget", data={"client_id": client_id})

        with app.app_context():
            assert cached_client(client_id) is None
        query, _ = _authorize_query(client_id)
        client.get("/authorize", query_string=query)
        assert len(origin.requests) == 2, "the document was not fetched again"

    def test_forgetting_something_that_is_not_cached_says_so(self, app, origin):
        page = app.test_client().post(
            "/clients/forget",
            data={"client_id": "https://nobody.example/m.json"},
            follow_redirects=True,
        ).get_data(as_text=True)

        assert "No cached metadata document" in page

    def test_a_declared_client_cannot_be_forgotten_through_it(self, app, origin):
        """The cache is the only thing this reaches."""
        client = app.test_client()

        client.post("/clients/forget", data={"client_id": "demo-client"})

        with app.app_context():
            assert get_identities().resolve_client("demo-client") is not None


def _expiry(client_id: str) -> float:
    """When the cache would stop answering for this client."""
    return next(
        entry.expires_at for entry in cached_entries() if entry.client_id == client_id
    )


class TestACodeOutlivesTheClientItWasIssuedFor:
    """The cache is the only place a CIMD client exists between /authorize
    and /token, so an entry must cover any code minted against it.

    A lifetime floor cannot promise this: the document is cached when it is
    fetched and the code is minted later, when the login finishes. A
    document with a short max-age fetched at 06:00 and a code issued at
    06:05 leaves five minutes where the code is valid and the client is
    not, with nobody doing anything wrong.
    """

    def test_issuing_a_code_extends_the_cached_entry(
        self, app, origin, resolves_to_loopback
    ):
        from nanoidp.services.auth_code import CODE_LIFETIME_SECONDS

        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        origin.cache_control = "max-age=60"
        query, _ = _authorize_query(client_id)

        client.get("/authorize", query_string=query)
        with app.app_context():
            before = _expiry(client_id)
        client.post(
            "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
        )
        with app.app_context():
            after = _expiry(client_id)

        assert before < clock.time() + CODE_LIFETIME_SECONDS
        assert after >= clock.time() + CODE_LIFETIME_SECONDS - 5

    def test_a_short_lived_document_still_redeems_its_code(
        self, app, origin, resolves_to_loopback, monkeypatch
    ):
        """End to end, with the floor shortened so the document's own
        lifetime runs out while the code is still valid. Without the
        extension this is the /token failure a developer would have to
        explain: nothing expired that they set, and nobody did anything
        wrong. The wait is the point of the test, so it is a real one."""
        monkeypatch.setattr(client_metadata, "MIN_LIFETIME_SECONDS", 3)
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        origin.cache_control = "max-age=0"
        query, verifier = _authorize_query(client_id)

        client.get("/authorize", query_string=query)
        authorized = client.post(
            "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
        )
        code = parse_qs(urlparse(authorized.headers["Location"]).query)["code"][0]
        origin.__exit__()
        clock.sleep(3.2)

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )

        assert token.status_code == 200

    def test_a_cache_full_of_live_codes_refuses_a_new_client(
        self, app, origin, resolves_to_loopback, monkeypatch
    ):
        """At the cap the oldest entry goes, and the one a code was issued
        against is by then among the oldest. The new authorization request
        is refused instead, because breaking a flow already under way is
        the worse of the two."""
        monkeypatch.setattr(client_metadata, "MAX_CACHED_DOCUMENTS", 1)
        client = app.test_client()
        first = _client_id(origin)
        origin.serve_document(metadata_document(first, redirect_uris=[REDIRECT]))
        query, _ = _authorize_query(first)
        client.get("/authorize", query_string=query)
        client.post(
            "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
        )

        second = _client_id(origin, "/other.json")
        origin.serve_document(metadata_document(second, redirect_uris=[REDIRECT]))
        other_query, _ = _authorize_query(second)
        refused = client.get("/authorize", query_string=other_query)

        assert refused.status_code == 400
        assert refused.get_json()["error"] == "invalid_client"
        with app.app_context():
            assert cached_client(first) is not None

    def test_no_code_is_issued_when_the_client_cannot_be_held(
        self, app, origin, resolves_to_loopback, monkeypatch
    ):
        """The window between the login being accepted and the code being
        minted is one instruction wide, so the seam is where the race lands
        and the seam is what is driven here. A code handed over for a
        client that is already gone is one nobody can redeem or explain."""
        client = app.test_client()
        client_id = _client_id(origin)
        origin.serve_document(metadata_document(client_id, redirect_uris=[REDIRECT]))
        query, _ = _authorize_query(client_id)
        client.get("/authorize", query_string=query)
        monkeypatch.setattr(oauth_routes, "retain_cached_client_until", lambda *a: False)

        authorized = client.post(
            "/authorize", query_string=query, data={"username": "admin", "password": "admin"}
        )

        params = parse_qs(urlparse(authorized.headers["Location"]).query)
        assert "code" not in params
        assert params["error"] == ["temporarily_unavailable"]

    def test_it_does_nothing_for_a_client_that_is_not_cached(self, app):
        """Declared and runtime clients are not this function's business,
        and it says so rather than pretending to have done something."""
        from nanoidp.services.client_metadata import retain_until

        with app.app_context():
            assert retain_until("demo-client", 1e12) is False


class TestDiscovery:
    @pytest.mark.parametrize(
        "path", ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]
    )
    def test_it_is_advertised_while_it_is_on(self, app, path):
        document = app.test_client().get(path).get_json()

        assert document["client_id_metadata_document_supported"] is True

    def test_it_is_not_advertised_when_no_host_is_allowed(self, app):
        """Enabled with an empty allowed_hosts refuses every client, so
        advertising it would promise a capability with no way to tell it is
        inert. The registration endpoint needs no second setting to work,
        which is why it has no such state."""
        with app.app_context():
            get_config().settings.client_id_metadata_documents_allowed_hosts = []

        document = app.test_client().get("/.well-known/openid-configuration").get_json()

        assert "client_id_metadata_document_supported" not in document

    def test_it_is_not_advertised_when_it_is_off(self, app):
        with app.app_context():
            get_config().settings.client_id_metadata_documents_enabled = False

        document = app.test_client().get("/.well-known/openid-configuration").get_json()

        assert "client_id_metadata_document_supported" not in document


class TestTheResolverStillCannotFetch:
    def test_identities_does_not_import_the_fetcher(self):
        """The property PR A and PR B were split to get. One caller composes
        the two halves, and it is not the module every protocol path goes
        through."""
        import ast

        tree = ast.parse((_REPO / "src/nanoidp/services/identities.py").read_text())
        imported = {
            node.module for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }

        assert not any("client_metadata_fetch" in name for name in imported), imported

    def test_resolving_an_uncached_url_reaches_no_network(self, app, origin):
        import socket

        with app.app_context():
            original = socket.getaddrinfo
            socket.getaddrinfo = lambda *a, **k: pytest.fail("the resolver resolved a name")
            try:
                assert get_identities().resolve_client(_client_id(origin)) is None
            finally:
                socket.getaddrinfo = original
