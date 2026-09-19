"""Runtime identities (#235): the in-memory store, the resolver that composes
it with the declared configuration, and the reconciliation on reload.

No surface creates runtime objects yet (#192); these tests create them
through the resolver, the way #192's routes will.
"""

import asyncio
import base64
import json
import logging
import re
import shutil
import threading
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import OAuthClient, User, get_config
from nanoidp.services.identities import (
    DeclaredNameCollision,
    ResolvedClient,
    ResolvedUser,
    get_identities,
)
from nanoidp.services.runtime_identities import (
    RuntimeObjectExists,
    get_runtime_identity_store,
)
from tests.runtime_store_contract import REPOSITORIES, STORE_FACTORIES, registration

_REPO = Path(__file__).resolve().parent.parent
REDIRECT = "http://localhost:3000/callback"


def _user(name: str, password: str = "pw") -> User:
    return User(username=name, password=password, email=f"{name}@runtime.test")


def _client(client_id: str, secret: str = "runtime-secret") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_secret=secret,
        redirect_uris=[REDIRECT],
        allowed_scopes=["openid", "profile", "email"],
    )


def _basic(client_id: str, secret: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


# ---------------------------------------------------------------------------
# Repository contract: written against the interface, so a later backend
# (#354) runs the same tests by adding its factory here.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("factory", STORE_FACTORIES)
@pytest.mark.parametrize("repository", REPOSITORIES)
class TestRepositoryContract:
    def test_create_get_list_delete(self, factory, repository):
        get_repo, make, name_of, _ = repository
        repo = get_repo(factory())

        first, second = make("first"), make("second")
        repo.create(first)
        repo.create(second)

        assert name_of(repo.get("first")) == "first"
        assert repo.get("missing") is None
        assert [name_of(obj) for obj in repo.list()] == ["first", "second"]
        assert repo.delete("first") is True
        assert repo.delete("first") is False
        assert [name_of(obj) for obj in repo.list()] == ["second"]

    def test_a_taken_name_is_refused(self, factory, repository):
        get_repo, make, _, _field = repository
        repo = get_repo(factory())
        repo.create(make("taken"))

        with pytest.raises(RuntimeObjectExists):
            repo.create(make("taken"))
        assert len(repo.list()) == 1

    def test_delete_all_returns_the_count(self, factory, repository):
        get_repo, make, _, _field = repository
        repo = get_repo(factory())
        for name in ("a", "b", "c"):
            repo.create(make(name))

        assert repo.delete_all() == 3
        assert repo.list() == []
        assert repo.delete_all() == 0

    @staticmethod
    def _mutate(field, obj):
        """Change one of the object's list fields in place."""
        field(obj).append("MUTATED")

    @staticmethod
    def _mutated(field, obj):
        return "MUTATED" in field(obj)

    def test_changing_the_instance_handed_to_create_does_not_change_the_repository(
        self, factory, repository
    ):
        get_repo, make, _, field = repository
        repo = get_repo(factory())
        obj = make("isolated")
        repo.create(obj)

        self._mutate(field, obj)

        assert not self._mutated(field, repo.get("isolated"))

    @pytest.mark.parametrize("returned_by", ["create", "get", "list"])
    def test_changing_a_returned_object_does_not_change_the_repository(
        self, factory, repository, returned_by
    ):
        """By value, as a backend that serializes would be (#354)."""
        get_repo, make, _, field = repository
        repo = get_repo(factory())
        created = repo.create(make("isolated"))
        returned = {
            "create": lambda: created,
            "get": lambda: repo.get("isolated"),
            "list": lambda: repo.list()[0],
        }[returned_by]()

        self._mutate(field, returned)

        assert not self._mutated(field, repo.get("isolated"))
        assert not self._mutated(field, repo.list()[0])

    def test_concurrent_creates_of_one_name_let_exactly_one_through(self, factory, repository):
        get_repo, make, _, _field = repository
        repo = get_repo(factory())
        barrier = threading.Barrier(8)
        outcomes = []

        def create():
            barrier.wait()
            try:
                repo.create(make("contended"))
                outcomes.append("created")
            except RuntimeObjectExists:
                outcomes.append("refused")

        threads = [threading.Thread(target=create) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert outcomes.count("created") == 1
        assert len(repo.list()) == 1

    def test_the_repositories_are_separate(self, factory, repository):
        store = factory()
        lent = store.repository("dynamic_registrations", lambda r: r.client_id)
        store.users.create(_user("same-name"))
        store.clients.create(_client("same-name"))
        lent.create(registration("same-name"))

        assert store.users.delete_all() == 1
        assert [c.client_id for c in store.clients.list()] == ["same-name"]
        assert [r.client_id for r in lent.list()] == ["same-name"]

    def test_a_lent_repository_is_the_same_one_every_time(self, factory, repository):
        """Asked for twice, it is one repository, not two views (#190)."""
        store = factory()
        store.repository("dynamic_registrations", lambda r: r.client_id).create(
            registration("once")
        )

        again = store.repository("dynamic_registrations", lambda r: r.client_id)
        assert [r.client_id for r in again.list()] == ["once"]


# ---------------------------------------------------------------------------
# Resolver rules
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    doc = yaml.safe_load(settings.read_text())
    doc["jwt"]["keys_dir"] = str(tmp_path / "keys")
    settings.write_text(yaml.safe_dump(doc))
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app.test_client(), config_dir


class TestResolverRules:
    def test_a_runtime_user_resolves_with_its_origin(self, app_client):
        identities = get_identities()
        identities.create_runtime_user(_user("ci-alice"))

        resolved = identities.resolve_user("ci-alice")
        assert resolved == ResolvedUser(get_runtime_identity_store().users.get("ci-alice"), "runtime")
        assert identities.resolve_user("admin").origin == "declared"
        assert identities.resolve_user("nobody") is None

    def test_a_declared_name_cannot_be_created_at_runtime(self, app_client):
        identities = get_identities()

        with pytest.raises(DeclaredNameCollision):
            identities.create_runtime_user(_user("admin"))
        with pytest.raises(DeclaredNameCollision):
            identities.create_runtime_client(_client("demo-client"))
        assert get_runtime_identity_store().users.list() == []
        assert get_runtime_identity_store().clients.list() == []

    def test_the_declared_object_wins_when_both_exist(self, app_client):
        # Only possible between a reload that declares the name and the
        # reconciliation that follows it; the store accepts it directly.
        get_runtime_identity_store().users.create(_user("admin", password="runtime-pw"))
        get_runtime_identity_store().clients.create(_client("demo-client", secret="runtime"))
        identities = get_identities()

        assert identities.resolve_user("admin").origin == "declared"
        assert identities.authenticate("admin", "runtime-pw") is None
        assert identities.resolve_client("demo-client").origin == "declared"
        assert identities.check_client("demo-client", "runtime") is False

    def test_listings_carry_the_origin_and_hide_shadowed_runtime_objects(self, app_client):
        identities = get_identities()
        identities.create_runtime_user(_user("ci-alice"))
        identities.create_runtime_client(_client("ci-app"))
        get_runtime_identity_store().users.create(_user("admin"))

        users = identities.list_users()
        assert [u.user.username for u in users if u.origin == "runtime"] == ["ci-alice"]
        assert {u.user.username for u in users if u.origin == "declared"} == set(get_config().users)
        clients = identities.list_clients()
        assert [c.client.client_id for c in clients if c.origin == "runtime"] == ["ci-app"]
        assert all(isinstance(c, ResolvedClient) for c in clients)

    def test_a_settings_snapshot_still_finds_runtime_clients(self, app_client):
        identities = get_identities()
        identities.create_runtime_client(_client("ci-app"))
        snapshot = get_config().settings

        assert identities.get_client("ci-app", snapshot).client_id == "ci-app"
        assert identities.get_client("demo-client", snapshot).client_id == "demo-client"


# ---------------------------------------------------------------------------
# Every protocol surface resolves through the resolver
# ---------------------------------------------------------------------------


class TestProtocolSurfacesResolveRuntimeIdentities:
    @pytest.fixture(autouse=True)
    def runtime_identities(self, app_client):
        identities = get_identities()
        identities.create_runtime_user(_user("ci-alice", password="alice-pw"))
        identities.create_runtime_client(_client("ci-app", secret="app-secret"))

    def test_password_grant_with_a_runtime_client_and_user(self, app_client):
        client, _ = app_client
        response = client.post(
            "/token",
            data={"grant_type": "password", "username": "ci-alice", "password": "alice-pw"},
            headers=_basic("ci-app", "app-secret"),
        )
        assert response.status_code == 200, response.get_data(as_text=True)
        token = response.get_json()["access_token"]

        userinfo = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert userinfo.status_code == 200
        assert userinfo.get_json()["sub"] == "ci-alice"
        introspection = client.post(
            "/introspect", data={"token": token}, headers=_basic("ci-app", "app-secret")
        )
        assert introspection.get_json()["active"] is True

    def test_wrong_runtime_credentials_are_refused(self, app_client):
        client, _ = app_client
        wrong_secret = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers=_basic("ci-app", "not-the-secret"),
        )
        wrong_password = client.post(
            "/token",
            data={"grant_type": "password", "username": "ci-alice", "password": "nope"},
            headers=_basic("ci-app", "app-secret"),
        )
        assert wrong_secret.status_code == 401
        assert wrong_password.status_code == 400
        assert wrong_password.get_json()["error"] == "invalid_grant"

    def test_client_credentials_grant_for_a_runtime_client(self, app_client):
        client, _ = app_client
        response = client.post(
            "/token", data={"grant_type": "client_credentials"}, headers=_basic("ci-app", "app-secret")
        )
        assert response.status_code == 200, response.get_data(as_text=True)

    def test_authorization_code_flow_for_a_runtime_client_and_user(self, app_client):
        client, _ = app_client
        params = {
            "response_type": "code",
            "client_id": "ci-app",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "state": "s1",
            "nonce": "n1",
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        assert client.get("/authorize?" + query).status_code == 200
        login = client.post(
            "/authorize", data={"username": "ci-alice", "password": "alice-pw"}, follow_redirects=False
        )
        assert login.status_code == 302, login.get_data(as_text=True)
        code = re.search(r"code=([^&]+)", login.headers["Location"]).group(1)

        tokens = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT},
            headers=_basic("ci-app", "app-secret"),
        )
        assert tokens.status_code == 200, tokens.get_data(as_text=True)
        id_token = tokens.get_json()["id_token"]
        claims = json.loads(base64.urlsafe_b64decode(id_token.split(".")[1] + "=="))
        # The ID Token audience resolves the runtime client from the
        # response's settings snapshot (#359) through the resolver.
        assert claims["aud"] == "ci-app"
        assert claims["sub"] == "ci-alice"

    def test_ui_login_for_a_runtime_user(self, app_client):
        client, _ = app_client
        response = client.post("/login", data={"username": "ci-alice", "password": "alice-pw"})
        assert response.status_code == 302
        with client.session_transaction() as session:
            assert session.get("user") == "ci-alice"

    def test_saml_sso_for_a_runtime_user(self, app_client):
        client, _ = app_client
        request = base64.b64encode(
            b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'ID="_rt1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" '
            b'AssertionConsumerServiceURL="http://sp.example.com/acs"/>'
        ).decode()
        response = client.post(
            "/saml/sso",
            data={
                "SAMLRequest": request,
                "saml_original_verb": "POST",
                "username": "ci-alice",
                "password": "alice-pw",
            },
        )
        assert response.status_code == 200
        encoded = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', response.get_data(as_text=True))
        assert encoded is not None
        assert b"ci-alice" in base64.b64decode(encoded.group(1))

    def test_persona_mode_selects_a_runtime_user(self, app_client):
        get_config().settings.login_mode = "persona"
        assert get_identities().interactive_authenticate("ci-alice", "").username == "ci-alice"


PKCE_VERIFIER = "runtime-verifier-0123456789-0123456789-0123456789"
PKCE_CHALLENGE = (
    base64.urlsafe_b64encode(__import__("hashlib").sha256(PKCE_VERIFIER.encode()).digest())
    .rstrip(b"=")
    .decode()
)
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _runtime_client(client_id: str, **fields) -> OAuthClient:
    return OAuthClient(client_id=client_id, redirect_uris=[REDIRECT], **fields)


def _replace_runtime_client(client_id: str, **policy) -> None:
    """Change a runtime client's policy the way #192 can: the repository is
    by value, so a change is a delete and a create of the replacement."""
    store = get_runtime_identity_store()
    current = store.clients.get(client_id)
    assert store.clients.delete(client_id)
    get_identities().create_runtime_client(
        OAuthClient.model_validate({**current.model_dump(), **policy})
    )


def _authorization_code(client, client_id: str, scope: str = "openid", **extra) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "scope": scope,
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
        **extra,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    assert client.get("/authorize?" + query).status_code == 200
    login = client.post(
        "/authorize", data={"username": "ci-alice", "password": "alice-pw"}, follow_redirects=False
    )
    assert login.status_code == 302, login.get_data(as_text=True)
    return re.search(r"code=([^&]+)", login.headers["Location"]).group(1)


class TestEveryResolutionSite:
    """One observable behaviour per resolution site: with the runtime object
    invisible (a declared-only lookup), each of these tests fails."""

    @pytest.fixture(autouse=True)
    def runtime_identities(self, app_client):
        identities = get_identities()
        identities.create_runtime_user(_user("ci-alice", password="alice-pw"))
        identities.create_runtime_client(_client("ci-app", secret="app-secret"))

    def _password_tokens(self, client, client_id="ci-app", secret="app-secret", **data):
        return client.post(
            "/token",
            data={"grant_type": "password", "username": "ci-alice", "password": "alice-pw", **data},
            headers=_basic(client_id, secret),
        )

    def test_userinfo_returns_the_runtime_users_claims(self, app_client):
        client, _ = app_client
        token = self._password_tokens(client, scope="openid email").get_json()["access_token"]
        body = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"}).get_json()
        assert body["email"] == "ci-alice@runtime.test"

    def test_the_id_token_takes_the_runtime_clients_additional_audiences(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _client("ci-multi", secret="multi-secret").model_copy(
                update={"additional_audiences": ["api://extra"]}
            )
        )
        tokens = self._password_tokens(client, "ci-multi", "multi-secret", scope="openid").get_json()
        claims = json.loads(base64.urlsafe_b64decode(tokens["id_token"].split(".")[1] + "=="))
        assert claims["aud"] == ["ci-multi", "api://extra"]

    def test_password_grant_applies_the_runtime_clients_scope_ceiling(self, app_client):
        client, _ = app_client
        _replace_runtime_client("ci-app", allowed_scopes=["openid"])
        response = self._password_tokens(client, scope="openid email")
        assert response.status_code == 400 and response.get_json()["error"] == "invalid_scope"

    def test_client_credentials_applies_the_runtime_clients_scope_ceiling(self, app_client):
        client, _ = app_client
        _replace_runtime_client("ci-app", allowed_scopes=["openid"])
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "scope": "email"},
            headers=_basic("ci-app", "app-secret"),
        )
        assert response.status_code == 400 and response.get_json()["error"] == "invalid_scope"

    def test_code_redemption_rechecks_the_runtime_clients_scope_ceiling(self, app_client):
        client, _ = app_client
        code = _authorization_code(client, "ci-app", scope="openid email")
        _replace_runtime_client("ci-app", allowed_scopes=["openid"])
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": PKCE_VERIFIER,
            },
            headers=_basic("ci-app", "app-secret"),
        )
        assert response.status_code == 400 and response.get_json()["error"] == "invalid_scope"

    def test_refresh_resolves_the_runtime_user_and_rechecks_the_ceiling(self, app_client):
        client, _ = app_client
        refresh_token = self._password_tokens(client, scope="openid email").get_json()["refresh_token"]
        refreshed = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers=_basic("ci-app", "app-secret"),
        )
        assert refreshed.status_code == 200, refreshed.get_data(as_text=True)

        _replace_runtime_client("ci-app", allowed_scopes=["openid"])
        narrowed = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refreshed.get_json()["refresh_token"]},
            headers=_basic("ci-app", "app-secret"),
        )
        assert narrowed.status_code == 400 and narrowed.get_json()["error"] == "invalid_scope"

    def test_a_runtime_public_client_redeems_a_code_without_a_secret(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client("ci-spa", token_endpoint_auth_method="none")
        )
        code = _authorization_code(client, "ci-spa")
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": "ci-spa",
                "code_verifier": PKCE_VERIFIER,
            },
        )
        assert response.status_code == 200, response.get_data(as_text=True)

    def test_a_runtime_client_secret_post_client_authenticates_in_the_body(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client(
                "ci-post", client_secret="post-secret", token_endpoint_auth_method="client_secret_post"
            )
        )
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials", "client_id": "ci-post", "client_secret": "post-secret"},
        )
        assert response.status_code == 200, response.get_data(as_text=True)

    def test_a_runtime_public_client_is_refused_at_introspection_as_public(self, app_client):
        from nanoidp.services import get_audit_log

        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client("ci-spa", token_endpoint_auth_method="none")
        )
        response = client.post("/introspect", data={"token": "x", "client_id": "ci-spa"})
        assert response.status_code == 401
        reasons = [
            entry.get("details", {}).get("reason", "")
            for entry in get_audit_log().get_entries(event_type="introspection_request")
        ]
        assert any("public clients cannot authenticate" in reason for reason in reasons)

    def test_a_runtime_public_client_revokes_its_own_token(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client("ci-spa", token_endpoint_auth_method="none")
        )
        code = _authorization_code(client, "ci-spa")
        tokens = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": "ci-spa",
                "code_verifier": PKCE_VERIFIER,
            },
        ).get_json()

        revoke = client.post("/revoke", data={"token": tokens["access_token"], "client_id": "ci-spa"})

        assert revoke.status_code == 200
        introspection = client.post(
            "/introspect", data={"token": tokens["access_token"]}, headers=_basic("ci-app", "app-secret")
        )
        assert introspection.get_json()["active"] is False

    def test_device_flow_for_a_runtime_public_client_and_user(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client("ci-tv", token_endpoint_auth_method="none", allowed_scopes=["openid", "email"])
        )
        refused = client.post("/device_authorization", data={"client_id": "ci-tv", "scope": "profile"})
        assert refused.status_code == 400 and refused.get_json()["error"] == "invalid_scope"

        started = client.post("/device_authorization", data={"client_id": "ci-tv", "scope": "openid email"})
        assert started.status_code == 200, started.get_data(as_text=True)
        codes = started.get_json()
        approved = client.post(
            "/device",
            data={"user_code": codes["user_code"], "username": "ci-alice", "password": "alice-pw", "action": "authorize"},
        )
        assert approved.status_code == 200
        tokens = client.post(
            "/token",
            data={"grant_type": DEVICE_GRANT, "device_code": codes["device_code"], "client_id": "ci-tv"},
        )
        assert tokens.status_code == 200, tokens.get_data(as_text=True)

    def test_device_redemption_rechecks_the_runtime_clients_ceilings(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client(
                "ci-tv",
                token_endpoint_auth_method="none",
                allowed_scopes=["openid", "email"],
                allowed_resources=["https://api.runtime.test"],
            )
        )
        codes = client.post(
            "/device_authorization",
            data={"client_id": "ci-tv", "scope": "openid email", "resource": "https://api.runtime.test"},
        ).get_json()
        client.post(
            "/device",
            data={"user_code": codes["user_code"], "username": "ci-alice", "password": "alice-pw", "action": "authorize"},
        )
        _replace_runtime_client("ci-tv", allowed_resources=["https://other.runtime.test"])

        response = client.post(
            "/token",
            data={"grant_type": DEVICE_GRANT, "device_code": codes["device_code"], "client_id": "ci-tv"},
        )

        assert response.status_code == 400 and response.get_json()["error"] == "invalid_target"

    def test_device_scope_is_rechecked_at_redemption(self, app_client):
        client, _ = app_client
        get_identities().create_runtime_client(
            _runtime_client("ci-tv", token_endpoint_auth_method="none", allowed_scopes=["openid", "email"])
        )
        codes = client.post(
            "/device_authorization", data={"client_id": "ci-tv", "scope": "openid email"}
        ).get_json()
        client.post(
            "/device",
            data={"user_code": codes["user_code"], "username": "ci-alice", "password": "alice-pw", "action": "authorize"},
        )
        _replace_runtime_client("ci-tv", allowed_scopes=["openid"])

        response = client.post(
            "/token",
            data={"grant_type": DEVICE_GRANT, "device_code": codes["device_code"], "client_id": "ci-tv"},
        )

        assert response.status_code == 400 and response.get_json()["error"] == "invalid_scope"

    def test_client_credentials_uses_a_runtime_user_named_as_the_default_user(self, app_client):
        client, config_dir = app_client
        users = config_dir / "users.yaml"
        doc = yaml.safe_load(users.read_text())
        doc["default_user"] = "ci-service"
        users.write_text(yaml.safe_dump(doc))
        assert client.post("/api/config/reload").status_code == 200
        get_identities().create_runtime_user(
            User(username="ci-service", password=None, roles=["RUNTIME_SERVICE"])
        )

        token = client.post(
            "/token", data={"grant_type": "client_credentials"}, headers=_basic("ci-app", "app-secret")
        ).get_json()["access_token"]

        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        assert claims["sub"] == "ci-service"

    def test_saml_attribute_query_for_a_runtime_user(self, app_client):
        client, _ = app_client
        query = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            '<samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' ID="_aq" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">'
            "<saml:Issuer>sp</saml:Issuer>"
            "<saml:Subject><saml:NameID>ci-alice</saml:NameID></saml:Subject>"
            "</samlp:AttributeQuery></soap:Body></soap:Envelope>"
        )
        response = client.post("/saml/attribute-query", data=query, content_type="text/xml")
        assert response.status_code == 200
        assert b"ci-alice@runtime.test" in response.data

    def test_auto_login_selects_a_runtime_persona(self, app_client):
        client, _ = app_client
        settings = get_config().settings
        settings.login_mode = "persona"
        settings.auto_login = True
        response = client.get(
            "/authorize",
            query_string={
                "response_type": "code",
                "client_id": "ci-app",
                "redirect_uri": REDIRECT,
                "scope": "openid",
                "login_hint": "persona-auto-login:ci-alice",
            },
        )
        assert response.status_code == 302
        assert "code=" in response.headers["Location"]


class TestEffectiveViews:
    """#192: the observation surfaces show declared and runtime identities
    with their origin; the declared-configuration views and MCP do not."""

    @pytest.fixture(autouse=True)
    def runtime_user(self, app_client):
        get_identities().create_runtime_user(_user("ci-alice", password="alice-pw"))
        get_identities().create_runtime_client(_client("ci-app", secret="app-secret"))

    def test_api_users_lists_effective_users_with_their_origin(self, app_client):
        client, _ = app_client
        listed = {user["username"]: user["origin"] for user in client.get("/api/users").get_json()["users"]}
        assert listed["ci-alice"] == "runtime"
        assert listed["admin"] == "declared"
        detail = client.get("/api/users/ci-alice").get_json()
        assert detail["origin"] == "runtime"
        assert "password" not in detail

    def test_the_token_endpoint_resolves_runtime_users_and_clients(self, app_client):
        client, _ = app_client
        response = client.post("/api/users/ci-alice/token", json={"client_id": "ci-app"})
        assert response.status_code == 200, response.get_data(as_text=True)
        claims = json.loads(base64.urlsafe_b64decode(response.get_json()["access_token"].split(".")[1] + "=="))
        assert claims["sub"] == "ci-alice" and claims["client_id"] == "ci-app"
        assert client.post("/api/users/nobody/token", json={}).status_code == 404
        assert client.post("/api/users/ci-alice/token", json={"client_id": "nope"}).status_code == 400

    def test_the_persona_picker_lists_runtime_users(self, app_client):
        assert "ci-alice" in [name for name, _ in get_identities().persona_picker_entries()]

    def test_the_config_view_counts_only_declared_objects(self, app_client):
        client, _ = app_client
        body = client.get("/api/config").get_json()
        assert body["users_count"] == len(get_config().users)
        assert body["oauth"]["clients_count"] == len(get_config().settings.clients)

    def test_mcp_list_users_sees_only_declared_users(self, app_client, mcp_call_tool):
        result = json.loads(asyncio.run(mcp_call_tool("list_users", {})).content[0].text)
        assert "ci-alice" not in [user["username"] for user in result["users"]]

    def test_ui_lists_runtime_objects_read_only(self, app_client):
        client, _ = app_client
        users_page = client.get("/users").get_data(as_text=True)
        clients_page = client.get("/clients").get_data(as_text=True)
        dashboard = client.get("/").get_data(as_text=True)

        assert "ci-alice" in users_page and "managed through /api/runtime" in users_page
        assert "/users/ci-alice" not in users_page  # no Details / edit link
        assert "ci-app" in clients_page and "/clients/ci-app/edit" not in clients_page
        assert f"{len(get_config().users)} declared, 1 runtime" in dashboard


# ---------------------------------------------------------------------------
# Reconciliation on reload
# ---------------------------------------------------------------------------


class TestReloadReconciliation:
    def _declare(self, config_dir: Path, username: str, client_id: str) -> None:
        users = config_dir / "users.yaml"
        doc = yaml.safe_load(users.read_text())
        doc["users"][username] = {"password": "declared-pw"}
        users.write_text(yaml.safe_dump(doc))
        settings = config_dir / "settings.yaml"
        sdoc = yaml.safe_load(settings.read_text())
        sdoc["oauth"]["clients"].append(
            {"client_id": client_id, "client_secret": "declared-secret", "redirect_uris": [REDIRECT]}
        )
        settings.write_text(yaml.safe_dump(sdoc))

    def test_a_reload_that_declares_a_runtime_name_removes_the_runtime_object(
        self, app_client, caplog
    ):
        client, config_dir = app_client
        identities = get_identities()
        identities.create_runtime_user(_user("ci-alice", password="runtime-pw"))
        identities.create_runtime_client(_client("ci-app"))
        identities.create_runtime_user(_user("ci-bob"))

        self._declare(config_dir, "ci-alice", "ci-app")
        with caplog.at_level(logging.WARNING, logger="nanoidp.services.identities"):
            assert client.post("/api/config/reload").status_code == 200

        store = get_runtime_identity_store()
        assert store.users.get("ci-alice") is None
        assert store.clients.get("ci-app") is None
        assert store.users.get("ci-bob") is not None
        assert get_identities().resolve_user("ci-alice").origin == "declared"
        assert get_identities().authenticate("ci-alice", "declared-pw") is not None
        messages = [record.getMessage() for record in caplog.records]
        assert "Runtime user 'ci-alice' removed: the configuration now declares that name" in messages
        assert "Runtime client 'ci-app' removed: the configuration now declares that name" in messages

    def test_a_create_racing_a_reload_that_declares_the_name_leaves_no_runtime_object(
        self, app_client, monkeypatch
    ):
        import time

        _, config_dir = app_client
        manager = get_config()
        real_get_user = manager.get_user
        checked = threading.Event()

        def get_user_then_pause(name):
            found = real_get_user(name)
            if threading.current_thread().name == "creator":
                checked.set()
                time.sleep(0.3)  # between the declared-name check and the insert
            return found

        monkeypatch.setattr(manager, "get_user", get_user_then_pause)

        def create():
            get_identities().create_runtime_user(_user("ci-bob", password="runtime-pw"))

        def reload():
            checked.wait()
            self._declare(config_dir, "ci-bob", "ci-bob-app")
            manager.reload()

        threads = [threading.Thread(target=create, name="creator"), threading.Thread(target=reload)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        monkeypatch.setattr(manager, "get_user", real_get_user)

        assert get_runtime_identity_store().users.get("ci-bob") is None
        assert get_identities().resolve_user("ci-bob").origin == "declared"

    def test_a_lookup_spanning_a_reload_that_declares_the_name_finds_one_of_the_two(
        self, app_client, monkeypatch
    ):
        _, config_dir = app_client
        manager = get_config()
        get_identities().create_runtime_user(_user("ci-alice"))
        real_get_user = manager.get_user
        reloaded = []

        def get_user_then_reload(name):
            found = real_get_user(name)
            if not reloaded:
                # The reload lands right after this read, from another thread.
                reloaded.append(True)
                self._declare(config_dir, "ci-alice", "ci-alice-app")
                worker = threading.Thread(target=manager.reload)
                worker.start()
                worker.join()
            return found

        monkeypatch.setattr(manager, "get_user", get_user_then_reload)
        resolved = get_identities().resolve_user("ci-alice")
        monkeypatch.setattr(manager, "get_user", real_get_user)

        assert reloaded
        assert resolved is not None
        assert get_runtime_identity_store().users.get("ci-alice") is None

    def test_a_listing_spanning_a_reload_that_declares_the_name_shows_one_of_the_two(
        self, app_client, monkeypatch
    ):
        _, config_dir = app_client
        manager = get_config()
        get_identities().create_runtime_user(_user("ci-alice"))
        repository = get_runtime_identity_store().users
        real_list = repository.list
        reloaded = []

        def reload_then_list():
            if not reloaded:
                reloaded.append(True)
                self._declare(config_dir, "ci-alice", "ci-alice-app")
                manager.reload()
            return real_list()

        monkeypatch.setattr(repository, "list", reload_then_list)
        names = [entry.user.username for entry in get_identities().list_users()]

        assert reloaded
        assert names.count("ci-alice") == 1

    def test_a_settings_snapshot_older_than_the_reload_still_finds_the_client(self, app_client):
        client, config_dir = app_client
        get_identities().create_runtime_client(_client("ci-app"))
        snapshot = get_config().settings

        self._declare(config_dir, "ci-carol", "ci-app")
        assert client.post("/api/config/reload").status_code == 200

        resolved = get_identities().resolve_client("ci-app", snapshot)
        assert resolved is not None and resolved.origin == "declared"

    def test_runtime_objects_survive_an_unrelated_reload_and_a_ui_write(self, app_client):
        from nanoidp.services.yaml_writer import get_yaml_writer

        client, _ = app_client
        get_identities().create_runtime_user(_user("ci-alice"))

        assert client.post("/api/config/reload").status_code == 200
        get_yaml_writer().update_login_settings(mode="password")

        assert get_identities().resolve_user("ci-alice").origin == "runtime"

    def test_a_rejected_reload_leaves_the_runtime_objects_alone(self, app_client):
        client, config_dir = app_client
        get_identities().create_runtime_user(_user("ci-alice"))
        self._declare(config_dir, "ci-alice", "ci-app")
        (config_dir / "settings.yaml").write_text("oauth: [broken\n")

        assert client.post("/api/config/reload").status_code == 422

        assert get_identities().resolve_user("ci-alice").origin == "runtime"
