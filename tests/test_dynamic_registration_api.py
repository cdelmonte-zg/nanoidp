"""``/register``: RFC 7591 registration and RFC 7592 management (#190).

The HTTP contract of an endpoint that is open on purpose. What a client may
ask for, what it gets back, what it is refused, and what stops working when
the registration it was issued no longer manages anything.

The record lifecycle itself is pinned one layer down, in
tests/test_dynamic_registration_records.py.
"""

import base64
import hashlib
import json
import os
import shutil
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.services.identities import get_identities

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:9000/cb"


def _app(tmp_path, enabled=True, max_clients=100):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document["oauth"]["dynamic_registration"] = {
        "enabled": enabled,
        "max_clients": max_clients,
    }
    settings.write_text(yaml.safe_dump(document))
    application = create_app(str(config_dir))
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(tmp_path):
    return _app(tmp_path).test_client()


def _register(client, **metadata):
    body = {"redirect_uris": [REDIRECT]}
    body.update(metadata)
    return client.post("/register", json=body)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


class TestTheFlagDecides:
    def test_every_operation_is_absent_when_off(self, tmp_path):
        """Not a 403: with the flag off the capability is not offered, and
        discovery does not advertise it."""
        off = _app(tmp_path, enabled=False).test_client()

        assert off.post("/register", json={"redirect_uris": [REDIRECT]}).status_code == 404
        assert off.get("/register/anything", headers=_bearer("t")).status_code == 404
        assert off.delete("/register/anything", headers=_bearer("t")).status_code == 404

    # One application per test: there is one ConfigManager per process
    # (#230), so a second create_app in the same test would answer for both.
    @pytest.mark.parametrize(
        "path", ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]
    )
    def test_the_endpoint_is_not_advertised_when_off(self, tmp_path, path):
        off = _app(tmp_path, enabled=False).test_client()

        assert "registration_endpoint" not in json.loads(off.get(path).data)

    @pytest.mark.parametrize(
        "path", ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]
    )
    def test_the_endpoint_is_advertised_when_on(self, tmp_path, path):
        """Both discovery names carry it, since both are one document."""
        on = _app(tmp_path).test_client()

        assert json.loads(on.get(path).data)["registration_endpoint"].endswith("/register")

    def test_turning_it_off_does_not_unmake_a_registered_client(self, tmp_path):
        """The flag governs the capability, not the state it created: a
        client registered while it was on keeps working as an OAuth client,
        it only stops being manageable through RFC 7592."""
        application = _app(tmp_path)
        client = application.test_client()
        registered = _register(client, token_endpoint_auth_method="none").get_json()

        with application.app_context():
            get_config().settings.dynamic_registration_enabled = False

        assert client.get(
            f"/register/{registered['client_id']}",
            headers=_bearer(registered["registration_access_token"]),
        ).status_code == 404
        with application.app_context():
            resolved = get_identities().resolve_client(registered["client_id"])
        assert resolved is not None and resolved.origin == "runtime"


class TestWhatComesBack:
    def test_a_public_registration_gets_no_secret(self, client):
        response = _register(client, token_endpoint_auth_method="none")
        body = response.get_json()

        assert response.status_code == 201
        assert body["token_endpoint_auth_method"] == "none"
        assert "client_secret" not in body
        assert body["redirect_uris"] == [REDIRECT]
        assert body["grant_types"] == ["authorization_code"]
        assert body["client_id_issued_at"] > 0
        assert body["registration_client_uri"].endswith(f"/register/{body['client_id']}")
        assert body["registration_access_token"]

    def test_a_confidential_registration_gets_a_secret_that_does_not_expire(self, client):
        """RFC 7591: absent token_endpoint_auth_method means
        client_secret_basic, so a secret is issued; 0 means it never
        expires, which is true of every nanoidp client secret."""
        body = _register(client).get_json()

        assert body["token_endpoint_auth_method"] == "client_secret_basic"
        assert body["client_secret"]
        assert body["client_secret_expires_at"] == 0

    def test_a_requested_name_becomes_the_description(self, client):
        body = _register(client, client_name="An MCP host").get_json()

        assert body["client_name"] == "An MCP host"

    def test_scopes_are_narrowed_to_the_vocabulary_and_echoed(self, client):
        """RFC 7591 lets a server register a subset. What it must not do is
        say nothing: an empty allowed_scopes means "any scope" here (#186)."""
        body = _register(client, scope="openid profile not-a-scope").get_json()

        assert body["scope"] == "openid profile"

    def test_a_long_name_is_accepted_exactly_as_a_declared_one_would_be(self, client):
        """A registered client is validated by the rules a declared client
        is, no more: OAuthClient.description has no length limit, so
        /register does not invent one either."""
        assert _register(client, client_name="x" * 500).status_code == 201

    def test_metadata_this_server_does_not_understand_is_ignored(self, client):
        """RFC 7591 asks a server to ignore what it does not understand,
        rather than refuse a client for sending more than nanoidp models."""
        response = _register(
            client,
            software_statement="ignored",
            logo_uri="https://example.org/logo.png",
            contacts=["ops@example.org"],
            response_types=["code"],
        )

        assert response.status_code == 201
        assert "logo_uri" not in response.get_json()


class TestWhatIsRefused:
    @pytest.mark.parametrize(
        "metadata, error",
        [
            ({"redirect_uris": []}, "invalid_redirect_uri"),
            ({}, "invalid_redirect_uri"),
            ({"redirect_uris": [REDIRECT], "grant_types": ["implicit"]}, "invalid_client_metadata"),
            (
                {"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "private_key_jwt"},
                "invalid_client_metadata",
            ),
            ({"redirect_uris": [REDIRECT], "scope": "nothing-known"}, "invalid_client_metadata"),
            ({"redirect_uris": "not-a-list"}, "invalid_client_metadata"),
            ({"redirect_uris": [REDIRECT], "client_name": 7}, "invalid_client_metadata"),
        ],
    )
    def test_the_metadata_is_refused_with_its_own_error(self, client, metadata, error):
        response = client.post("/register", json=metadata)

        assert response.status_code == 400
        assert response.get_json()["error"] == error

    def test_a_body_that_is_not_an_object_is_refused(self, client):
        assert client.post("/register", json=["not", "an", "object"]).status_code == 400
        assert client.post("/register", data="not json").status_code == 400

    def test_nothing_is_created_when_the_metadata_is_refused(self, tmp_path):
        application = _app(tmp_path)
        application.test_client().post("/register", json={})

        with application.app_context():
            assert get_identities().store.clients.list() == []


class TestCapacity:
    def test_the_limit_answers_429_with_its_own_name(self, tmp_path):
        """RFC 7591's error codes are about metadata, so none of them says
        "no more room"; this one is nanoidp's, documented as an extension."""
        client = _app(tmp_path, max_clients=1).test_client()
        assert _register(client).status_code == 201

        response = _register(client)

        assert response.status_code == 429
        assert response.get_json()["error"] == "registration_limit_reached"

    def test_a_deleted_registration_frees_its_slot(self, tmp_path):
        client = _app(tmp_path, max_clients=1).test_client()
        first = _register(client).get_json()
        assert _register(client).status_code == 429

        client.delete(
            f"/register/{first['client_id']}",
            headers=_bearer(first["registration_access_token"]),
        )

        assert _register(client).status_code == 201

    def test_a_promoted_registration_frees_its_slot(self, tmp_path):
        """The pruning sweep, not a callback in the identity code: the
        record of a promoted client stops counting on the next registration."""
        application = _app(tmp_path, max_clients=1)
        client = application.test_client()
        first = _register(client).get_json()

        with application.app_context():
            get_identities().promote_runtime_client(first["client_id"], {"source": "test"})

        assert _register(client).status_code == 201


class TestManagingARegistration:
    def test_a_read_returns_the_registration_and_the_presented_token(self, client):
        registered = _register(client, client_name="Readable").get_json()

        response = client.get(
            f"/register/{registered['client_id']}",
            headers=_bearer(registered["registration_access_token"]),
        )
        body = response.get_json()

        assert response.status_code == 200
        assert body["client_id"] == registered["client_id"]
        assert body["client_name"] == "Readable"
        assert body["registration_access_token"] == registered["registration_access_token"]

    @pytest.mark.parametrize("headers", [None, {"Authorization": "Bearer wrong"}])
    def test_a_read_without_the_right_credential_is_refused(self, client, headers):
        registered = _register(client).get_json()

        response = client.get(f"/register/{registered['client_id']}", headers=headers or {})

        assert response.status_code == 401
        assert "Bearer" in response.headers["WWW-Authenticate"]

    def test_an_unknown_registration_answers_like_a_wrong_credential(self, client):
        """Telling the two apart would let anyone walk the client ids."""
        registered = _register(client).get_json()

        unknown = client.get(
            "/register/dcr-nothing-here",
            headers=_bearer(registered["registration_access_token"]),
        )
        wrong = client.get(
            f"/register/{registered['client_id']}", headers=_bearer("wrong")
        )

        assert unknown.status_code == wrong.status_code == 401
        assert unknown.get_json() == wrong.get_json()

    def test_a_delete_removes_the_client_too(self, tmp_path):
        application = _app(tmp_path)
        client = application.test_client()
        registered = _register(client).get_json()

        response = client.delete(
            f"/register/{registered['client_id']}",
            headers=_bearer(registered["registration_access_token"]),
        )

        assert response.status_code == 204
        with application.app_context():
            assert get_identities().resolve_client(registered["client_id"]) is None

    def test_a_delete_without_the_right_credential_changes_nothing(self, tmp_path):
        application = _app(tmp_path)
        client = application.test_client()
        registered = _register(client).get_json()

        assert client.delete(f"/register/{registered['client_id']}").status_code == 401

        with application.app_context():
            assert get_identities().resolve_client(registered["client_id"]) is not None

    def test_management_ends_when_the_client_is_promoted(self, tmp_path):
        """The operator owns a declared client; a credential handed to
        whoever registered it must not still delete it."""
        application = _app(tmp_path)
        client = application.test_client()
        registered = _register(client).get_json()

        with application.app_context():
            get_identities().promote_runtime_client(registered["client_id"], {"source": "test"})

        token = _bearer(registered["registration_access_token"])
        assert client.get(f"/register/{registered['client_id']}", headers=token).status_code == 401
        assert client.delete(f"/register/{registered['client_id']}", headers=token).status_code == 401
        with application.app_context():
            assert get_identities().resolve_client(registered["client_id"]).origin == "declared"


class TestTheRegisteredClientIsAnOrdinaryClient:
    def test_it_completes_an_authorization_code_flow(self, tmp_path):
        client = _app(tmp_path).test_client()
        registered = _register(client, token_endpoint_auth_method="none").get_json()
        verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        query = {
            "response_type": "code",
            "client_id": registered["client_id"],
            "redirect_uri": REDIRECT,
            "scope": "openid profile",
            "state": "s1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

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
                "client_id": registered["client_id"],
                "code_verifier": verifier,
            },
        )

        assert token.status_code == 200
        assert token.get_json()["access_token"]

    def test_a_redirect_uri_it_did_not_register_is_refused(self, client):
        registered = _register(client, token_endpoint_auth_method="none").get_json()

        response = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered["client_id"],
                "redirect_uri": "http://localhost:9999/evil",
            },
        )

        assert response.status_code == 400
        assert "Location" not in response.headers

    def test_it_is_listed_as_a_runtime_client_with_its_source(self, tmp_path):
        client = _app(tmp_path).test_client()
        registered = _register(client).get_json()

        listed = client.get("/api/runtime/clients").get_json()["clients"]

        entry = next(c for c in listed if c["client_id"] == registered["client_id"])
        assert entry["origin"] == "runtime"
        assert entry["source"] == "dcr"
        assert "client_secret" not in entry


class TestTheCredentialsStayOut:
    def test_no_read_surface_repeats_the_registration_token(self, tmp_path):
        client = _app(tmp_path).test_client()
        registered = _register(client).get_json()
        token = registered["registration_access_token"]

        for path in (
            f"/api/runtime/clients/{registered['client_id']}",
            "/api/runtime/clients",
            "/api/config",
            "/api/audit",
        ):
            assert token not in client.get(path).get_data(as_text=True), path

    def test_the_audit_records_the_registration_without_its_secrets(self, tmp_path):
        client = _app(tmp_path).test_client()
        registered = _register(client).get_json()

        entries = client.get("/api/audit").get_data(as_text=True)

        assert "client_registered" in entries
        assert registered["client_id"] in entries
        assert registered["registration_access_token"] not in entries
        assert registered["client_secret"] not in entries
