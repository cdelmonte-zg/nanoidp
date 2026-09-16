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
from nanoidp.services.client_metadata import (
    DEFAULT_LIFETIME_SECONDS,
    MAX_LIFETIME_SECONDS,
    MIN_LIFETIME_SECONDS,
    CachedClient,
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
)
from nanoidp.services.identities import get_identities

_REPO = Path(__file__).resolve().parent.parent
URL = "https://client.example/metadata.json"
REDIRECT = "http://localhost:3000/callback"


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
            ("https://client.example/", "path"),
            ("https://client.example/./m.json", "path segments"),
            ("https://client.example/a/../m.json", "path segments"),
            ("https://client.example/m.json?x=1", "query"),
        ],
    )
    def test_every_rule_has_its_own_refusal(self, client_id, reason):
        with pytest.raises(ClientIdUrlInvalid, match=reason):
            reject_invalid_client_id_url(client_id)

    def test_a_well_formed_url_passes(self):
        reject_invalid_client_id_url(URL)


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
            remember(URL, client, None)

            assert cached_client(URL).client_id == URL

    def test_an_expired_entry_is_gone_and_dropped(self, app):
        with app.app_context():
            client = client_from_document(URL, _document(), ["openid"])
            remember(URL, client, None)
            entry = cache().get(URL)
            cache().delete(URL)
            cache().create(
                CachedClient(
                    client_id=URL,
                    client=entry.client,
                    fetched_at=entry.fetched_at,
                    expires_at=time.time() - 1,
                    document_url=URL,
                )
            )

            assert cached_client(URL) is None
            assert cache().get(URL) is None, "the expired entry was not dropped"

    def test_forgetting_says_whether_there_was_an_entry(self, app):
        with app.app_context():
            remember(URL, client_from_document(URL, _document(), []), None)

            assert forget(URL) is True
            assert forget(URL) is False

    def test_remembering_again_replaces_rather_than_collides(self, app):
        """A re-fetch of a document that changed must not hit the
        repository's "a name is taken" rule."""
        with app.app_context():
            remember(URL, client_from_document(URL, _document(), []), None)
            remember(URL, client_from_document(URL, _document(client_name="renamed"), []), None)

            assert cached_client(URL).description == "renamed"

    def test_only_fresh_entries_are_listed(self, app):
        with app.app_context():
            remember(URL, client_from_document(URL, _document(), []), None)
            assert [entry.client_id for entry in cached_entries()] == [URL]

            cache().delete(URL)
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
        remember(client_id, client_from_document(client_id, _document(client_id=client_id), []), None)

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
            remember(URL, client_from_document(URL, _document(), []), None)
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
            live_registration,
            new_registration_token,
            record_registration,
        )

        with app.app_context():
            identities = get_identities()
            identities.create_runtime_client(
                OAuthClient(client_id=URL, token_endpoint_auth_method="none",
                            redirect_uris=[REDIRECT])
            )
            record_registration(URL, ["authorization_code"], new_registration_token())
            assert live_registration(URL, identities) is not None

            identities.delete_runtime_client(URL)
            remember(URL, client_from_document(URL, _document(), []), None)

            assert identities.resolve_client(URL).origin == "cimd"
            assert live_registration(URL, identities) is None
