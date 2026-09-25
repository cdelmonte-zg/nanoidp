"""
``extra`` adds claims; it never changes what the grant or the user store
decided (#451).

Up to #451 the ``extra`` parameter of ``/token`` (and ``extra_claims`` of the
MCP ``generate_token`` tool) was merged into the access token after the
registered claims: ``sub``, ``iss``, ``aud``, ``exp``, ``jti``, ``roles`` and
the rest came from the request when the request named them. The client
credentials path filtered them since #445; the user grants did not.

Two barriers, both pinned here: the boundaries refuse a request that names
a forbidden claim, before any code or refresh token is consumed, and the
token service strips the same set for any caller that gets past them.
"""

import base64
import hashlib
import json

import jwt
import pytest

from nanoidp.models import User
from nanoidp.services.audit import get_audit_log
from nanoidp.services.token import (
    EXTRA_FORBIDDEN_CLAIMS,
    forbidden_extra_claims,
    get_token_service,
    resolve_user_claim,
)


def _basic(client_id, secret):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


DEMO = _basic("demo-client", "demo-secret")
REDIRECT = "http://localhost:3000/callback"
VERIFIER = "extra-claims-verifier-0123456789-0123456789-0123456789"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()

# One name from each group the rule covers, and one that passes
FORGED = {"sub": "root", "aud": "other-api", "exp": 4102444800, "custom": "ok"}
REFUSAL = "'extra' cannot set: aud, exp, sub"


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def _token(client, headers=DEMO, **form):
    return client.post("/token", headers=headers, data=form)


def _password_form():
    return {"grant_type": "password", "username": "admin", "password": "admin", "scope": "openid"}


def _authorization_code_form(client):
    params = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    assert client.get("/authorize", query_string=params).status_code == 200
    login = client.post(
        "/authorize", data={"username": "admin", "password": "admin"}, follow_redirects=False
    )
    assert login.status_code == 302, login.get_data(as_text=True)
    code = login.headers["Location"].split("code=")[1].split("&")[0]
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
    }


def _refresh_form(client):
    first = _token(client, **_password_form())
    assert first.status_code == 200, first.get_data(as_text=True)
    return {"grant_type": "refresh_token", "refresh_token": first.get_json()["refresh_token"]}


def _device_code_form(client):
    started = client.post("/device_authorization", data={"scope": "openid"}, headers=DEMO)
    assert started.status_code == 200, started.get_data(as_text=True)
    data = started.get_json()
    approved = client.post("/device", data={
        "user_code": data["user_code"], "username": "admin", "password": "admin",
        "action": "authorize",
    })
    assert approved.status_code == 200
    return {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": data["device_code"],
    }


GRANTS = {
    "password": lambda client: _password_form(),
    "client_credentials": lambda client: {"grant_type": "client_credentials"},
    "authorization_code": _authorization_code_form,
    "refresh_token": _refresh_form,
    "device_code": _device_code_form,
}


class TestEveryGrantRefusesIt:
    """One request per grant naming a registered claim, refused before the
    grant runs: the same code, refresh token or device code is then spent
    successfully with a permitted ``extra``, which shows nothing was
    consumed by the refusal."""

    @pytest.mark.parametrize("grant", sorted(GRANTS))
    def test_refused_and_nothing_consumed(self, client, grant):
        form = GRANTS[grant](client)

        refused = _token(client, **form, extra=json.dumps(FORGED))
        assert refused.status_code == 400, refused.get_data(as_text=True)
        body = refused.get_json()
        assert body["error"] == "invalid_request"
        assert body["error_description"] == REFUSAL

        allowed = _token(client, **form, extra=json.dumps({"custom": "ok"}))
        assert allowed.status_code == 200, allowed.get_data(as_text=True)
        claims = _claims(allowed.get_json()["access_token"])
        assert claims["custom"] == "ok"
        assert claims["sub"] == ("demo-client" if grant == "client_credentials" else "admin")
        assert claims["aud"] != "other-api"
        assert claims["exp"] < 4102444800

    def test_the_refusal_is_audited(self, client):
        _token(client, **_password_form(), extra=json.dumps(FORGED))
        entry = get_audit_log().get_entries(limit=5, event_type="token_request")[0]
        assert entry["client_id"] == "demo-client"
        assert entry["details"]["reason"] == REFUSAL
        assert entry["details"]["grant_type"] == "password"

    @pytest.mark.parametrize("name", [
        # registered (RFC 7519)
        "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
        # protocol
        "client_id", "token_use", "scope", "azp", "nonce", "auth_time", "amr", "at_hash",
        "req_userinfo_claims", "req_id_token_claims",
        # read back by the server
        "token_type", "rt_family", "resource",
        # the user store's
        "roles", "authorities", "tenant", "groups", "entitlements", "identity_class",
        "source_acl", "attributes", "username", "email", "name", "preferred_username",
    ])
    def test_each_group_is_refused_on_a_user_grant(self, client, name):
        refused = _token(client, **_password_form(), extra=json.dumps({name: "x"}))
        assert refused.status_code == 400, name
        assert refused.get_json()["error_description"] == f"'extra' cannot set: {name}"

    def test_the_names_are_listed_sorted(self, client):
        refused = _token(client, **_password_form(), extra=json.dumps(
            {"sub": "root", "aud": "x", "roles": ["SUPERUSER"], "custom": 1}
        ))
        assert refused.get_json()["error_description"] == "'extra' cannot set: aud, roles, sub"

    def test_a_forbidden_name_with_the_true_value_is_still_refused(self, client):
        """No value comparison: the rule is about who decides, not about
        whether the request guessed right."""
        refused = _token(client, **_password_form(), extra=json.dumps({"sub": "admin"}))
        assert refused.status_code == 400


class TestMcpGenerateToken:
    async def _generate(self, arguments):
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        return await _execute_tool("generate_token", arguments, get_config())

    @pytest.mark.asyncio
    async def test_an_unbound_token_cannot_be_given_a_client_id(self, app):
        """The case that is not an overwrite: unbound, ``create_token`` set no
        ``client_id``, so a forged one used to survive (#451)."""
        result = await self._generate({"username": "admin", "extra_claims": {"client_id": "demo-client"}})
        assert result["success"] is False
        assert result["error"] == "'extra_claims' cannot set: client_id"

    @pytest.mark.asyncio
    async def test_identity_and_registered_claims_are_refused(self, app):
        result = await self._generate({
            "username": "admin", "client_id": "demo-client",
            "extra_claims": {"sub": "root", "roles": ["SUPERUSER"], "exp": 1},
        })
        assert result["success"] is False
        assert result["error"] == "'extra_claims' cannot set: exp, roles, sub"

    @pytest.mark.asyncio
    async def test_a_custom_claim_still_passes(self, app):
        result = await self._generate({
            "username": "admin", "client_id": "demo-client", "extra_claims": {"custom": "ok"},
        })
        assert result["success"] is True, result
        claims = _claims(result["access_token"])
        assert claims["custom"] == "ok"
        assert claims["sub"] == "admin"
        assert claims["client_id"] == "demo-client"

    @pytest.mark.asyncio
    async def test_extra_claims_must_be_an_object(self, app):
        """``_execute_tool`` is reachable without the schema validation of
        ``call_tool`` (see the id_token_claims precedent): a list is refused
        here instead of failing inside the token service."""
        result = await self._generate({"username": "admin", "extra_claims": ["sub"]})
        assert result["success"] is False
        assert "object" in result["error"]


class TestTheServiceStripsItToo:
    """The second barrier: a caller that reaches the token service directly,
    whatever the boundary did, cannot mint a forged token."""

    @pytest.fixture
    def token_service(self, app):
        from nanoidp.config import get_config

        with app.app_context():
            return get_token_service(get_config().snapshot)

    def test_create_token_keeps_only_what_extra_may_add(self, token_service, app):
        user = User(username="alice", password="pw", email="alice@example.org", roles=["USER"])
        with app.app_context():
            response = token_service.create_token(
                user=user,
                extra_claims={"sub": "root", "roles": ["SUPERUSER"], "client_id": "demo-client",
                              "exp": 1, "token_type": "refresh", "custom": "ok"},
            )
        claims = _claims(response["access_token"])
        assert claims["sub"] == "alice"
        assert claims["roles"] == ["USER"]
        assert "client_id" not in claims
        assert claims["exp"] > 1
        assert "token_type" not in claims
        assert claims["custom"] == "ok"

    def test_client_credentials_token_keeps_only_what_extra_may_add(self, token_service, app):
        with app.app_context():
            response = token_service.create_client_credentials_token(
                client_id="demo-client", exp_minutes=5,
                extra_claims={"sub": "root", "roles": ["SUPERUSER"], "email": "x", "custom": "ok"},
                scope=None,
            )
        claims = _claims(response["access_token"])
        assert claims["sub"] == "demo-client"
        assert "roles" not in claims and "email" not in claims
        assert claims["custom"] == "ok"

    def test_forbidden_extra_claims_names_them_sorted(self):
        assert forbidden_extra_claims(None) == []
        assert forbidden_extra_claims({"custom": 1, "department": "x"}) == []
        assert forbidden_extra_claims({"sub": 1, "aud": 2, "roles": 3, "custom": 4}) == ["aud", "roles", "sub"]

    def test_the_set_is_the_union_of_the_three(self):
        from nanoidp.services.token import (
            _RESERVED_CLAIMS,
            _SERVER_READ_CLAIMS,
            USER_IDENTITY_CLAIMS,
        )

        assert EXTRA_FORBIDDEN_CLAIMS == _RESERVED_CLAIMS | _SERVER_READ_CLAIMS | USER_IDENTITY_CLAIMS
        assert "client_id" in _RESERVED_CLAIMS

    def test_client_id_is_not_requestable_through_the_claims_parameter_either(self):
        """``client_id`` joined ``_RESERVED_CLAIMS``, which the OIDC ``claims``
        resolver consults (#110): a user attribute named ``client_id`` can
        no longer be requested into an ID Token."""
        user = User(username="u", password="p", attributes={"client_id": "spoof", "department": "eng"})
        assert resolve_user_claim(user, "client_id") == (False, None)
        assert resolve_user_claim(user, "department") == (True, "eng")
