"""
A client_credentials token's subject is the client (#445).

It used to be issued for ``default_user``, as if that user had logged in:
``sub`` was the user's name and the token carried the user's roles and
attributes, so with the shipped configuration every service's token said
``sub: admin`` with ``ROLE_ADMIN``, and ``/userinfo`` handed a service the
admin's profile. RFC 9068 §2.2: with no resource owner, ``sub`` is an
identifier of the client.

The tests read the tokens a client receives and what the endpoints that take
those tokens answer, not the objects in between.
"""

import base64
import json
import logging

import jwt
import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import ConfigManager
from nanoidp.services.audit import get_audit_log


def _basic(client_id, secret):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


DEMO = _basic("demo-client", "demo-secret")

# What a user grant puts in a token about the user; none of it is the client's
USER_CLAIMS = (
    "roles", "authorities", "tenant", "identity_class", "entitlements",
    "groups", "source_acl", "attributes",
)


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def _client_credentials(client, headers=DEMO, **data):
    response = client.post("/token", headers=headers, data={"grant_type": "client_credentials", **data})
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _password_token(client):
    return client.post("/token", headers=DEMO, data={
        "grant_type": "password", "username": "admin", "password": "admin",
    }).get_json()["access_token"]


def _edit(config_dir, name, change):
    path = config_dir / name
    document = yaml.safe_load(path.read_text())
    change(document)
    path.write_text(yaml.safe_dump(document))


class TestTheTokenIsTheClients:
    def test_the_subject_is_the_client_id(self, client):
        claims = _claims(_client_credentials(client)["access_token"])
        assert claims["sub"] == "demo-client"
        assert claims["client_id"] == "demo-client"

    def test_no_user_claims_whoever_default_user_names(self, client):
        # The shipped configuration names admin, who has ADMIN roles
        claims = _claims(_client_credentials(client)["access_token"])
        assert [claim for claim in USER_CLAIMS if claim in claims] == []

    def test_exactly_the_claims_the_grant_owns(self, client):
        claims = _claims(_client_credentials(client, scope="profile")["access_token"])
        assert set(claims) == {
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id", "scope", "token_use",
        }
        assert claims["token_use"] == "access"
        assert claims["scope"] == "profile"

    def test_no_scope_no_scope_claim(self, client):
        assert "scope" not in _claims(_client_credentials(client)["access_token"])

    def test_the_audience_is_the_resource_when_one_is_asked_for(self, client):
        claims = _claims(_client_credentials(client, resource="https://api.example")["access_token"])
        assert claims["aud"] == "https://api.example"

    def test_still_no_refresh_token_and_no_id_token(self, client):
        answer = _client_credentials(client, scope="openid profile")
        assert "refresh_token" not in answer and "id_token" not in answer

    def test_a_runtime_client_is_its_own_subject(self, client):
        from nanoidp.config import OAuthClient
        from nanoidp.services.identities import get_identities

        get_identities().create_runtime_client(
            OAuthClient(client_id="ci-app", client_secret="app-secret")
        )
        claims = _claims(_client_credentials(client, headers=_basic("ci-app", "app-secret"))["access_token"])
        assert claims["sub"] == "ci-app"


class TestExtraCannotMakeItSomeoneElse:
    """`extra` is applied after the claims the server sets; on this path it
    may add claims of its own, never change who or what the token is for,
    nor give it a user's identity (#445; the other grants are #451)."""

    def test_the_owned_claims_and_the_user_claims_are_not_taken_from_extra(self, client):
        forged = {
            "sub": "root", "iss": "http://evil", "aud": "other-api", "exp": 4102444800,
            "iat": 1, "nbf": 1, "jti": "fixed", "client_id": "someone-else",
            "scope": "admin", "token_use": "id",
            **{claim: ["FORGED"] for claim in USER_CLAIMS},
        }
        claims = _claims(_client_credentials(client, extra=json.dumps(forged))["access_token"])
        assert claims["sub"] == "demo-client"
        assert claims["client_id"] == "demo-client"
        assert claims["iss"] == "http://localhost:8000"
        assert claims["aud"] != "other-api"
        assert claims["exp"] != 4102444800 and claims["jti"] != "fixed"
        assert claims["token_use"] == "access"
        assert "scope" not in claims
        assert [claim for claim in USER_CLAIMS if claim in claims] == []

    def test_nor_a_standard_identity_claim_or_one_the_server_reads_back(self, client):
        forged = {
            "email": "admin@example.org", "email_verified": True, "preferred_username": "admin",
            "name": "Admin", "username": "admin",
            "token_type": "refresh", "rt_family": "f", "resource": ["https://x"],
        }
        claims = _claims(_client_credentials(client, extra=json.dumps(forged))["access_token"])
        assert [claim for claim in forged if claim in claims] == []

    def test_a_custom_claim_passes(self, client):
        claims = _claims(_client_credentials(client, extra=json.dumps({"x-test-run": "42"}))["access_token"])
        assert claims["x-test-run"] == "42"


class TestAnAccessTokenIsNeverARefreshToken:
    """`extra` could stamp token_type=refresh on an access token, and the
    refresh grant read that claim alone: any access token, a client
    credentials one included, could then be spent for a new access token and
    a refresh token, a same-named user's with #445 and default_user's before
    it (measured on main). The refresh grant now also requires the
    token_use the server sets last, which no extra can change."""

    @pytest.mark.parametrize("grant", [
        {"grant_type": "client_credentials"},
        {"grant_type": "password", "username": "user1", "password": "password"},
    ])
    def test_refused_whatever_extra_stamped_on_it(self, isolated_repo_config, grant):
        # A user named like the client: what the refresh grant would have
        # resolved the client credentials token's sub to
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc["users"].__setitem__(
            "demo-client", {"password": "pw", "roles": ["ADMIN"]},
        ))
        client = create_app().test_client()
        issued = client.post("/token", headers=DEMO, data={
            **grant, "extra": json.dumps({"token_type": "refresh", "rt_family": "f"}),
        }).get_json()
        spent = client.post("/token", headers=DEMO, data={
            "grant_type": "refresh_token", "refresh_token": issued["access_token"],
        })
        assert spent.status_code == 400
        assert spent.get_json()["error"] == "invalid_grant"

    def test_a_real_refresh_token_still_works(self, client):
        issued = client.post("/token", headers=DEMO, data={
            "grant_type": "password", "username": "user1", "password": "password",
            "scope": "openid offline_access",
        }).get_json()
        spent = client.post("/token", headers=DEMO, data={
            "grant_type": "refresh_token", "refresh_token": issued["refresh_token"],
        })
        assert spent.status_code == 200, spent.get_data(as_text=True)


class TestNoEndUserBehindIt:
    def test_userinfo_answers_the_subject_alone(self, client):
        token = _client_credentials(client)["access_token"]
        answer = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert answer.status_code == 200
        assert answer.get_json() == {"sub": "demo-client"}

    def test_userinfo_never_resolves_it_as_a_user_of_the_same_name(self, isolated_repo_config):
        """A user named like the client: the token is still the client's,
        so UserInfo discloses nobody's profile, only the subject."""
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc["users"].__setitem__(
            "demo-client", {"password": "pw", "email": "person@example.org", "roles": ["ADMIN"]},
        ))
        client = create_app().test_client()
        token = _client_credentials(client)["access_token"]
        answer = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"}).get_json()
        assert answer == {"sub": "demo-client"}

    def test_introspection_names_no_resource_owner(self, client):
        token = _client_credentials(client)["access_token"]
        answer = client.post("/introspect", headers=DEMO, data={"token": token}).get_json()
        assert answer["active"] is True
        assert answer["sub"] == "demo-client"
        assert "username" not in answer

    def test_introspection_reports_no_scope_the_token_does_not_have(self, client):
        """RFC 7662: scope, when present, is the token's. A client's token
        requested without scope has none, and is not reported with the
        openid default a user token issued before scopes were recorded
        gets (#452 review)."""
        token = _client_credentials(client)["access_token"]
        answer = client.post("/introspect", headers=DEMO, data={"token": token}).get_json()
        assert "scope" not in answer

    def test_introspection_reports_the_scope_a_client_token_has(self, client):
        token = _client_credentials(client, scope="profile")["access_token"]
        answer = client.post("/introspect", headers=DEMO, data={"token": token}).get_json()
        assert answer["scope"] == "profile"

    def test_a_user_token_without_scope_keeps_the_openid_default(self, client):
        answer = client.post("/introspect", headers=DEMO, data={"token": _password_token(client)}).get_json()
        assert answer["scope"] == "openid"

    def test_a_user_token_keeps_its_username(self, client):
        answer = client.post("/introspect", headers=DEMO, data={"token": _password_token(client)}).get_json()
        assert answer["username"] == "admin"

    def test_no_audit_names_the_client_as_a_user(self, client):
        """userinfo, introspection and revocation of a client's token record
        the client, not a user named like it (#445 review)."""
        token = _client_credentials(client)["access_token"]
        client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        client.post("/introspect", headers=DEMO, data={"token": token})
        client.post("/revoke", headers=DEMO, data={"token": token})
        for event in ("userinfo_request", "introspection_request", "revocation_request"):
            entry = get_audit_log().get_entries(limit=5, event_type=event)[0]
            assert not entry.get("username"), (event, entry)

    def test_the_audit_names_the_client_and_no_user(self, client):
        _client_credentials(client)
        entry = get_audit_log().get_entries(limit=5, event_type="token_request")[0]
        assert entry["client_id"] == "demo-client"
        assert not entry.get("username")
        assert "authorities_count" not in (entry.get("details") or {})


class TestAUserNamedLikeAClient:
    def test_is_warned_about_at_load(self, isolated_repo_config, caplog):
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc["users"].__setitem__(
            "demo-client", {"password": "pw"},
        ))
        with caplog.at_level(logging.WARNING):
            ConfigManager(str(isolated_repo_config))
        assert "demo-client" in caplog.text and "both a user and a client" in caplog.text

    def test_is_warned_about_on_the_runtime_api(self, client, caplog):
        with caplog.at_level(logging.WARNING):
            created = client.post("/api/runtime/users", json={"username": "demo-client", "password": "pw"})
        assert created.status_code == 201
        assert "both a user and a client" in caplog.text

    def test_is_warned_about_for_a_runtime_client_named_like_a_user(self, client, caplog):
        with caplog.at_level(logging.WARNING):
            created = client.post("/api/runtime/clients", json={"client_id": "admin", "client_secret": "s"})
        assert created.status_code == 201
        assert "both a user and a client" in caplog.text

    def test_no_warning_without_a_collision(self, isolated_repo_config, caplog):
        with caplog.at_level(logging.WARNING):
            ConfigManager(str(isolated_repo_config))
        assert "both a user and a client" not in caplog.text


class TestDefaultUserIsDeprecated:
    def test_a_file_that_carries_it_is_warned_about(self, isolated_repo_config, caplog):
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "admin"))
        with caplog.at_level(logging.WARNING):
            ConfigManager(str(isolated_repo_config))
        assert "default_user" in caplog.text and "no effect" in caplog.text

    def test_validate_reports_it(self, isolated_repo_config):
        """What #441 set out to report: a key that is accepted and does
        nothing. Not an error, in either mode."""
        from nanoidp.config_validation import validate_config_dir

        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "admin"))
        findings = validate_config_dir(str(isolated_repo_config))
        default_user = [f for f in findings if "default_user" in f.message]
        assert [f.level for f in default_user] == ["info"]

    def test_validate_strict_agrees_with_a_strict_server(self, isolated_repo_config):
        """A strict server starts with default_user in the file; a strict
        validation must not fail the same directory (#452 review): the
        finding is a note, never fatal."""
        from nanoidp.config_validation import report, validate_config_dir, validate_config_result

        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "admin"))
        ConfigManager(str(isolated_repo_config), strict_config=True)
        assert validate_config_result(str(isolated_repo_config), True)["valid"] is True
        lines, code = report(validate_config_dir(str(isolated_repo_config)), strict=True)
        assert code == 0
        assert any("default_user" in line for line in lines)

    def test_warned_once_per_file_not_on_every_load(self, isolated_repo_config, caplog):
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "admin"))
        with caplog.at_level(logging.WARNING):
            config = ConfigManager(str(isolated_repo_config))
            config.reload_local()
            config.reload_local()
        assert caplog.text.count("default_user has no effect") == 1

    def test_a_file_without_it_is_not(self, isolated_repo_config, caplog):
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.pop("default_user", None))
        with caplog.at_level(logging.WARNING):
            ConfigManager(str(isolated_repo_config))
        assert "default_user" not in caplog.text

    def test_it_never_refuses_to_load_even_strict(self, isolated_repo_config):
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "admin"))
        ConfigManager(str(isolated_repo_config), strict_config=True)

    def test_init_does_not_write_it(self, tmp_path):
        from nanoidp.__main__ import init_config

        init_config(str(tmp_path / "fresh"))
        assert "default_user" not in yaml.safe_load((tmp_path / "fresh" / "users.yaml").read_text())

    def test_a_save_keeps_it_without_managing_it(self, isolated_repo_config):
        """The writer leaves the key where it is: removing it is the
        operator's edit, and deleting the user it names does not rewrite it."""
        from nanoidp.services.yaml_writer import YamlWriter

        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "user1"))
        YamlWriter(str(isolated_repo_config)).delete_user("user1")
        assert yaml.safe_load((isolated_repo_config / "users.yaml").read_text())["default_user"] == "user1"

    def test_a_config_save_neither_adds_it_nor_rewrites_it(self, isolated_repo_config):
        """The path of ConfigManager.save() and MCP save_config."""
        path = isolated_repo_config / "users.yaml"
        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.pop("default_user", None))
        ConfigManager(str(isolated_repo_config)).save()
        assert "default_user" not in yaml.safe_load(path.read_text())

        _edit(isolated_repo_config, "users.yaml", lambda doc: doc.__setitem__("default_user", "user1"))
        ConfigManager(str(isolated_repo_config)).save()
        assert yaml.safe_load(path.read_text())["default_user"] == "user1"

    @pytest.mark.asyncio
    async def test_mcp_list_users_does_not_report_it(self, isolated_repo_config, mcp_call_tool, monkeypatch):
        monkeypatch.setattr("nanoidp.config._config", ConfigManager(str(isolated_repo_config)))
        result = await mcp_call_tool("list_users", {})
        assert "default_user" not in json.loads(result.content[0].text)
