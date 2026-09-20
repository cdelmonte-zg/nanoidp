"""A client from a metadata document, as a third origin (#196, PR A).

Everything here is deterministic: the rules about what a client identifier
URL is, what a document must say to become a client, what the cache keeps
and for how long, and where the resolver puts that answer among the others.
Nothing opens a socket. The fetch, and every rule about how it may be made,
is PR B; wiring it to ``/authorize`` is PR C.

The point of the split is the property the resolver must have: it reads, it
never fetches. Sixteen of the seventeen places that resolve a client are not
``/authorize``, and none of them may acquire network I/O by accident.
"""

import shutil
import time
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import OAuthClient, get_config
from nanoidp.services import client_metadata
from nanoidp.services.client_metadata import (
    DEFAULT_LIFETIME_SECONDS,
    MAX_CACHED_DOCUMENTS,
    MAX_LIFETIME_SECONDS,
    MIN_LIFETIME_SECONDS,
    CachedClient,
    CacheIsFull,
    ClientIdUrlInvalid,
    DocumentInvalid,
    bounded_lifetime,
    cache,
    cached_client,
    cached_entries,
    client_from_document,
    forget,
    looks_like_client_id_url,
    reject_invalid_client_id_url,
    remember,
    retain_until,
)
from nanoidp.services.identities import get_identities

_REPO = Path(__file__).resolve().parent.parent
URL = "https://client.example/metadata.json"
REDIRECT = "http://localhost:3000/callback"


def _expire(client_id):
    """Put a cached entry's lifetime in the past, keeping everything else."""
    entry = cache().get(client_id)
    cache().delete(client_id)
    cache().create(
        CachedClient(
            client=entry.client,
            fetched_at=entry.fetched_at,
            expires_at=time.time() - 1,
        )
    )


def _document(**overrides):
    document = {
        "client_id": URL,
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "none",
    }
    document.update(overrides)
    return document


@pytest.fixture
def app(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document["oauth"]["client_id_metadata_documents"] = {"enabled": True}
    settings.write_text(yaml.safe_dump(document))
    application = create_app(str(config_dir))
    application.config["TESTING"] = True
    return application


class TestTheClientIdentifierUrl:
    def test_only_an_https_url_is_a_candidate(self):
        assert looks_like_client_id_url(URL) is True
        assert looks_like_client_id_url("demo-client") is False
        assert looks_like_client_id_url("http://client.example/m.json") is False

    @pytest.mark.parametrize(
        "client_id, reason",
        [
            ("http://client.example/m.json", "https"),
            ("https://user:pw@client.example/m.json", "userinfo"),
            ("https://client.example/m.json#frag", "fragment"),
            ("https://client.example", "path"),
            ("https://client.example/./m.json", "path segments"),
            ("https://client.example/a/../m.json", "path segments"),
            # %2e is '.' (RFC 3986), so the rule has to look past the
            # encoding or nothing stops an intermediary normalising the
            # request target into another resource.
            ("https://client.example/a/%2e%2e/m.json", "path segments"),
            ("https://client.example/.%2E/m.json", "path segments"),
            # urlsplit strips these before parsing, so validating what it
            # returns would approve a string that is not the identifier.
            (" https://client.example/m.json", "whitespace"),
            ("https://client.example/m.json\n", "whitespace"),
            ("https://client.ex\tample/m.json", "whitespace"),
            # A request target is ASCII, so a URL that is not can never be
            # fetched: http.client raises UnicodeEncodeError while building
            # the request line, which is a 500 from /authorize rather than
            # a refusal. The draft says nothing about IDNs, and refusing
            # here keeps the answer to "can this be fetched" in one place.
            ("https://client.example/caf\u00e9.json", "ASCII"),
            ("https://cl\u00efent.example/m.json", "ASCII"),
            ("https://client.example/m.json?q=\u00e9", "ASCII"),
        ],
    )
    def test_every_rule_has_its_own_refusal(self, client_id, reason):
        with pytest.raises(ClientIdUrlInvalid, match=reason):
            reject_invalid_client_id_url(client_id)

    def test_a_well_formed_url_passes(self):
        reject_invalid_client_id_url(URL)

    @pytest.mark.parametrize(
        "client_id",
        [
            # SHOULD NOT and NOT RECOMMENDED, not MUST NOT: refusing either
            # would lock a conforming client out of this IdP entirely.
            "https://client.example/m.json?tenant=a",
            "https://client.example/",
        ],
    )
    def test_what_the_draft_discourages_is_not_refused(self, client_id):
        reject_invalid_client_id_url(client_id)

    def test_an_uppercase_scheme_is_accepted(self):
        """RFC 3986: scheme names are case-insensitive, and an
        implementation is asked to accept an uppercase one. Both gates say
        so, or a URL one accepts could never resolve through the other."""
        upper = "HTTPS://client.example/m.json"

        reject_invalid_client_id_url(upper)
        assert looks_like_client_id_url(upper) is True

    def test_the_two_gates_agree_about_the_same_string(self):
        """One says whether a client_id is worth looking at, the other
        whether it is legal. A string the second accepts and the first
        rejects could never resolve, and would be a rule with no effect."""
        for candidate in (URL, "https://client.example/a/b/m.json"):
            assert looks_like_client_id_url(candidate)
            reject_invalid_client_id_url(candidate)


class TestTheDocument:
    def test_a_well_formed_document_becomes_a_client(self):
        client = client_from_document(URL, _document(client_name="An MCP host"), ["openid"])

        assert client.client_id == URL
        assert client.token_endpoint_auth_method == "none"
        assert client.is_public is True
        assert client.redirect_uris == [REDIRECT]
        assert client.description == "An MCP host"

    def test_the_document_must_claim_the_url_it_was_found_at(self):
        with pytest.raises(DocumentInvalid, match="not the URL"):
            client_from_document(URL, _document(client_id="https://other.example/m.json"), [])

    @pytest.mark.parametrize(
        "method", ["client_secret_basic", "client_secret_post", "client_secret_jwt"]
    )
    def test_a_shared_secret_method_is_refused(self, method):
        """The draft forbids every shared-symmetric-secret method. Of the
        three nanoidp advertises, two are those and the third is none, so
        this is the only method a CIMD client can have."""
        with pytest.raises(DocumentInvalid, match="authenticates with"):
            client_from_document(URL, _document(token_endpoint_auth_method=method), [])

    @pytest.mark.parametrize(
        "uri",
        [
            "/cb",
            # RFC 6749 forbids a fragment in a redirect endpoint, and
            # RFC 8252 wants a period in a private-use scheme. Neither rule
            # is restated here: this goes through the gate /authorize uses.
            "https://app.example/cb#fragment",
            "myapp:/oauth2redirect",
        ],
    )
    def test_a_redirect_uri_authorize_would_refuse_is_refused_here(self, uri):
        with pytest.raises(DocumentInvalid, match="redirect_uris"):
            client_from_document(URL, _document(redirect_uris=[uri]), [])

    @pytest.mark.parametrize("value", [None, [], "not-a-list", [""], [1]])
    def test_redirect_uris_must_be_a_non_empty_list_of_strings(self, value):
        document = _document()
        if value is None:
            document.pop("redirect_uris")
        else:
            document["redirect_uris"] = value

        with pytest.raises(DocumentInvalid, match="redirect_uri"):
            client_from_document(URL, document, [])

    def test_scope_is_narrowed_to_the_vocabulary(self):
        client = client_from_document(
            URL, _document(scope="openid profile not-a-scope"), ["openid", "profile"]
        )

        assert client.allowed_scopes == ["openid", "profile"]

    def test_a_scope_naming_nothing_supported_is_refused(self):
        """An empty allowed_scopes means every scope (#186), so narrowing to
        nothing would widen the client instead."""
        with pytest.raises(DocumentInvalid, match="none of the scopes"):
            client_from_document(URL, _document(scope="nothing-known"), ["openid"])

    def test_no_scope_grants_the_vocabulary_written_out(self):
        client = client_from_document(URL, _document(), ["openid", "profile"])

        assert client.allowed_scopes == ["openid", "profile"]

    def test_metadata_this_server_does_not_understand_is_ignored(self):
        client = client_from_document(
            URL,
            _document(logo_uri="https://client.example/logo.png", contacts=["a@b.c"]),
            [],
        )

        assert client.client_id == URL

    @pytest.mark.parametrize("document", ["not an object", ["a", "list"], 7, None])
    def test_a_document_that_is_not_an_object_is_refused(self, document):
        with pytest.raises(DocumentInvalid, match="JSON object"):
            client_from_document(URL, document, [])


class TestTheCache:
    def test_a_remembered_client_reads_back(self, app):
        with app.app_context():
            client = client_from_document(URL, _document(), ["openid"])
            remember(client, None)

            assert cached_client(URL).client_id == URL

    def test_an_expired_entry_is_gone_and_dropped(self, app):
        with app.app_context():
            remember(client_from_document(URL, _document(), ["openid"]), None)
            _expire(URL)

            assert cached_client(URL) is None
            assert cache().get(URL) is None, "the expired entry was not dropped"

    def test_expired_entries_nobody_asks_about_are_swept_on_a_write(self, app):
        """A read expires only the entry it was asked for, so without a
        sweep a URL nobody requests again is held until the process ends."""
        with app.app_context():
            for index in range(3):
                url = f"https://client.example/{index}.json"
                remember(client_from_document(url, _document(client_id=url), []), None)
                _expire(url)

            remember(client_from_document(URL, _document(), []), None)

            assert [entry.client_id for entry in cache().list()] == [URL]

    def test_the_cache_does_not_grow_past_its_cap(self, app):
        """The entries come from client-chosen URLs on an unauthenticated
        endpoint, so a bound per entry is not a bound. At the cap the oldest
        fetch goes, not the newest client."""
        with app.app_context():
            for index in range(MAX_CACHED_DOCUMENTS + 5):
                url = f"https://client.example/{index}.json"
                remember(client_from_document(url, _document(client_id=url), []), None)

            entries = cache().list()
            assert len(entries) == MAX_CACHED_DOCUMENTS
            newest = f"https://client.example/{MAX_CACHED_DOCUMENTS + 4}.json"
            assert cached_client(newest) is not None
            assert cached_client("https://client.example/0.json") is None

    def test_an_entry_a_live_code_depends_on_is_not_evicted(self, app):
        """The cap drops the least recently fetched, and an entry a code was
        issued against is by then one of the oldest. Evicting it breaks a
        flow already under way, with nobody doing anything wrong: the cap is
        100, the fetch budget 30 a minute, and a code lives ten."""
        with app.app_context():
            remember(client_from_document(URL, _document(), []), None)
            retain_until(URL, time.time() + 600)

            for index in range(MAX_CACHED_DOCUMENTS + 5):
                url = f"https://client.example/{index}.json"
                remember(client_from_document(url, _document(client_id=url), []), None)

            assert cached_client(URL) is not None

    def test_a_cache_full_of_live_codes_refuses_the_newcomer(self, app, monkeypatch):
        """When every entry is holding up a code, there is no room to make.
        Refusing a new authorization request is the lesser harm: the
        alternative breaks a flow already under way, for a client that did
        nothing wrong and would see only a code that stopped working."""
        monkeypatch.setattr(client_metadata, "MAX_CACHED_DOCUMENTS", 2)
        with app.app_context():
            for index in range(2):
                url = f"https://client.example/{index}.json"
                remember(client_from_document(url, _document(client_id=url), []), None)
                retain_until(url, time.time() + 600)

            with pytest.raises(CacheIsFull):
                remember(client_from_document(URL, _document(), []), None)

            assert cached_client("https://client.example/0.json") is not None

    def test_an_unprotected_entry_still_goes_at_the_cap(self, app, monkeypatch):
        """The protection is for entries a code depends on, not a way for
        any cached document to outstay the cap."""
        monkeypatch.setattr(client_metadata, "MAX_CACHED_DOCUMENTS", 2)
        with app.app_context():
            for index in range(2):
                url = f"https://client.example/{index}.json"
                remember(client_from_document(url, _document(client_id=url), []), None)
            retain_until("https://client.example/1.json", time.time() + 600)

            remember(client_from_document(URL, _document(), []), None)

            assert cached_client("https://client.example/0.json") is None
            assert cached_client("https://client.example/1.json") is not None

    def test_an_entry_cannot_expire_while_something_depends_on_it(self):
        """Said once, in the model: a lifetime shorter than the promise
        would let the sweep drop what the cap was told to keep."""
        now = time.time()

        entry = CachedClient(
            client=client_from_document(URL, _document(), []),
            fetched_at=now,
            expires_at=now + 1,
            protected_until=now + 600,
        )

        assert entry.expires_at == entry.protected_until
        assert entry.is_fresh(now + 60)

    def test_re_fetching_a_document_keeps_what_depends_on_the_entry(self, app):
        """The promise was made about the client, not about this copy of
        its document."""
        with app.app_context():
            remember(client_from_document(URL, _document(), []), None)
            retain_until(URL, time.time() + 600)

            remember(client_from_document(URL, _document(), []), 1)

            assert cache().get(URL).is_fresh(time.time() + 300)

    def test_concurrent_writes_for_one_url_do_not_collide(self, app):
        """remember() is a sweep, an evict and a create: two requests for
        the same uncached URL would otherwise both get there and the second
        would raise the repository's "that name is taken" out of a request."""
        import threading

        with app.app_context():
            client = client_from_document(URL, _document(), [])
            barrier = threading.Barrier(8)
            failures = []

            def write():
                barrier.wait()
                try:
                    remember(client, None)
                except Exception as exc:  # noqa: BLE001 - the point of the test
                    failures.append(exc)

            threads = [threading.Thread(target=write) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            assert failures == []
            assert len(cache().list()) == 1

    def test_a_url_the_rules_refuse_cannot_be_remembered(self, app):
        """The rules are this module's, so the cache holds to them rather
        than trusting whoever calls it. The client is built around a legal
        URL and then given an illegal one, which is the only way to get a
        client the rules would refuse: client_from_document applies them
        too."""
        with app.app_context():
            client = client_from_document(URL, _document(), [])
            client.client_id = "https://client.example/m.json#frag"

            with pytest.raises(ClientIdUrlInvalid):
                remember(client, None)

            assert cache().list() == []

    def test_forgetting_says_whether_there_was_an_entry(self, app):
        with app.app_context():
            remember(client_from_document(URL, _document(), []), None)

            assert forget(URL) is True
            assert forget(URL) is False

    def test_remembering_again_replaces_rather_than_collides(self, app):
        """A re-fetch of a document that changed must not hit the
        repository's "a name is taken" rule."""
        with app.app_context():
            remember(client_from_document(URL, _document(), []), None)
            remember(client_from_document(URL, _document(client_name="renamed"), []), None)

            assert cached_client(URL).description == "renamed"

    def test_only_fresh_entries_are_listed(self, app):
        """Expiry, not deletion: a read surface showing an entry nothing
        would use would be a lie about what is in effect."""
        with app.app_context():
            remember(client_from_document(URL, _document(), []), None)
            assert [entry.client_id for entry in cached_entries()] == [URL]

            _expire(URL)

            assert cached_entries() == []

    @pytest.mark.parametrize(
        "asked, kept",
        [
            (None, DEFAULT_LIFETIME_SECONDS),
            (1, MIN_LIFETIME_SECONDS),
            (10 * MAX_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS),
            (600, 600),
        ],
    )
    def test_the_lifetime_is_the_response_within_this_server_s_bounds(self, asked, kept):
        """A client must not be able to pin its own metadata here forever,
        and a one-second lifetime must not turn the cache into a fetch per
        request."""
        assert bounded_lifetime(asked) == kept


class TestPrecedence:
    """declared > runtime > cimd, and the cache is not even consulted for
    the first two."""

    def _cache_a_client(self, client_id=URL):
        remember(client_from_document(client_id, _document(client_id=client_id), []), None)

    def test_a_cached_document_resolves_as_cimd(self, app):
        with app.app_context():
            self._cache_a_client()

            resolved = get_identities().resolve_client(URL)

            assert resolved is not None
            assert resolved.origin == "cimd"
            assert resolved.client.client_id == URL

    def test_a_declared_client_of_that_name_wins(self, app):
        with app.app_context():
            self._cache_a_client()
            config = get_config()
            config.settings.clients.append(
                OAuthClient(client_id=URL, client_secret="declared", redirect_uris=[REDIRECT])
            )

            resolved = get_identities().resolve_client(URL)

            assert resolved.origin == "declared"
            assert resolved.client.client_secret == "declared"

    def test_a_runtime_client_of_that_name_wins(self, app):
        with app.app_context():
            self._cache_a_client()
            get_identities().create_runtime_client(
                OAuthClient(client_id=URL, client_secret="runtime", redirect_uris=[REDIRECT])
            )

            resolved = get_identities().resolve_client(URL)

            assert resolved.origin == "runtime"

    def test_an_ordinary_client_never_touches_the_cimd_cache(self, app, monkeypatch):
        """Not only answered first: not looked up at all. The cache is for
        client_ids that are URLs, and a declared client's resolution must
        not depend on anything this feature owns."""
        with app.app_context():
            monkeypatch.setattr(
                "nanoidp.services.client_metadata.cache",
                lambda: pytest.fail("an ordinary resolution consulted the CIMD cache"),
            )

            assert get_identities().resolve_client("demo-client") is not None
            assert get_identities().resolve_client("no-such-client") is None

    def test_an_unknown_url_resolves_to_nothing(self, app):
        with app.app_context():
            assert get_identities().resolve_client("https://nobody.example/m.json") is None


class TestTheSwitch:
    def test_a_cached_document_is_not_honoured_when_the_feature_is_off(self, app):
        """Unlike a registered client (#190), which keeps working when
        dynamic registration is switched off, this is a cached copy of
        someone else's document: the switch says whether such documents
        count at all."""
        with app.app_context():
            remember(client_from_document(URL, _document(), []), None)
            get_config().settings.client_id_metadata_documents_enabled = False

            assert get_identities().resolve_client(URL) is None

    def test_it_is_off_in_the_shipped_configuration(self):
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(_REPO / "config"))
        assert config.settings.client_id_metadata_documents_enabled is False


class TestTheResolverNeverFetches:
    def test_resolving_an_uncached_url_does_no_io_and_answers_nothing(self, app, monkeypatch):
        """The whole reason the fetch is not in here. Sixteen of the
        seventeen callers are not /authorize, and /token is one of them:
        an uncached document is an unknown client, immediately."""
        import socket

        with app.app_context():
            monkeypatch.setattr(
                socket,
                "getaddrinfo",
                lambda *a, **k: pytest.fail("the resolver must not reach the network"),
            )

            assert get_identities().resolve_client(URL) is None
            assert get_identities().get_client(URL) is None


class TestTheDcrInvariantStillHolds:
    """#190's registration record survives only while its name resolves to
    the runtime client it manages. A third origin does not change that rule,
    it is a new way for the rule to fire."""

    def test_a_name_that_now_resolves_to_cimd_makes_a_record_stale(self, app):
        from nanoidp.services.dynamic_registration import (
            live_registration_and_client,
            new_registration_token,
            record_registration,
        )

        def live_registration(client_id, identities):
            return live_registration_and_client(client_id, identities)

        with app.app_context():
            identities = get_identities()
            created = identities.create_runtime_client_entry(
                OAuthClient(client_id=URL, token_endpoint_auth_method="none",
                            redirect_uris=[REDIRECT])
            )
            record_registration(created, ["authorization_code"], new_registration_token(), limit=100)
            assert live_registration(URL, identities) is not None

            identities.delete_runtime_client(URL)
            remember(client_from_document(URL, _document(), []), None)

            assert identities.resolve_client(URL).origin == "cimd"
            assert live_registration(URL, identities) is None
