"""
Tests for the OIDC ``claims`` request parameter (OIDC Core §5.5, issue #104).

A client can ask for specific claims to be delivered in the ID Token (via the
``id_token`` member) or from UserInfo (via the ``userinfo`` member). nanoidp
parses the parameter at /authorize, carries it through the authorization code,
and resolves the requested claims from the user.
"""

import json
from urllib.parse import urlencode

import jwt as pyjwt

from nanoidp.app import create_app
from nanoidp.config import User
from nanoidp.routes.oauth import _parse_claims_parameter
from nanoidp.services.token import resolve_user_claim


# --------------------------------------------------------------------------
# Unit: parameter parsing
# --------------------------------------------------------------------------
class TestParseClaimsParameter:
    def test_none_and_empty(self):
        assert _parse_claims_parameter(None) is None
        assert _parse_claims_parameter("") is None

    def test_voluntary_null_form(self):
        raw = json.dumps({"id_token": {"email": None, "email_verified": None}})
        assert _parse_claims_parameter(raw) == {"id_token": ["email", "email_verified"]}

    def test_both_members(self):
        raw = json.dumps({"id_token": {"email": None}, "userinfo": {"name": None}})
        assert _parse_claims_parameter(raw) == {"id_token": ["email"], "userinfo": ["name"]}

    def test_essential_and_value_forms_extract_names(self):
        raw = json.dumps({"id_token": {"email": {"essential": True}, "tenant": {"value": "x"}}})
        parsed = _parse_claims_parameter(raw)
        assert set(parsed["id_token"]) == {"email", "tenant"}

    def test_unknown_members_ignored(self):
        raw = json.dumps({"id_token": {"email": None}, "bogus": {"x": None}})
        assert _parse_claims_parameter(raw) == {"id_token": ["email"]}

    def test_empty_members_collapse_to_none(self):
        assert _parse_claims_parameter(json.dumps({"id_token": {}})) is None
        assert _parse_claims_parameter(json.dumps({})) is None

    def test_malformed_json_is_ignored(self):
        assert _parse_claims_parameter("not json at all") is None

    def test_non_object_top_level_is_ignored(self):
        assert _parse_claims_parameter(json.dumps(["email"])) is None


# --------------------------------------------------------------------------
# Unit: claim resolution
# --------------------------------------------------------------------------
class TestResolveUserClaim:
    def _user(self, **kw):
        base = {"username": "u", "password": "p", "email": "u@example.org"}
        base.update(kw)
        return User(**base)

    def test_standard_claims(self):
        u = self._user(roles=["USER"], tenant="acme")
        assert resolve_user_claim(u, "email") == (True, "u@example.org")
        assert resolve_user_claim(u, "email_verified") == (True, True)
        assert resolve_user_claim(u, "preferred_username") == (True, "u")
        assert resolve_user_claim(u, "roles") == (True, ["USER"])
        assert resolve_user_claim(u, "tenant") == (True, "acme")

    def test_optional_claims_present_and_absent(self):
        assert resolve_user_claim(self._user(identity_class="INTERNAL"), "identity_class") == (True, "INTERNAL")
        assert resolve_user_claim(self._user(identity_class=None), "identity_class") == (False, None)

    def test_custom_attribute(self):
        u = self._user(attributes={"department": "eng"})
        assert resolve_user_claim(u, "department") == (True, "eng")

    def test_unknown_claim(self):
        assert resolve_user_claim(self._user(), "does_not_exist") == (False, None)


# --------------------------------------------------------------------------
# Integration helpers (default dev profile, full authorization code flow)
# --------------------------------------------------------------------------
def _dev_client():
    app = create_app(profile="dev")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test"
    return app.test_client()


def _basic_auth():
    import base64
    return {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def _id_token_via_authcode(client, claims=None):
    """Drive the full authorization code flow and return the decoded ID Token."""
    query = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "openid",
    }
    if claims is not None:
        query["claims"] = claims
    client.get("/authorize?" + urlencode(query))
    resp = client.post(
        "/authorize", data={"username": "admin", "password": "admin"}, follow_redirects=False
    )
    code = resp.headers["Location"].split("code=")[1].split("&")[0]
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
        },
        headers=_basic_auth(),
    )
    assert token_resp.status_code == 200, token_resp.data
    id_token = json.loads(token_resp.data)["id_token"]
    return pyjwt.decode(id_token, options={"verify_signature": False})


class TestIdTokenMember:
    def test_email_absent_by_default(self):
        payload = _id_token_via_authcode(_dev_client())
        assert "email" not in payload

    def test_requested_email_lands_in_id_token(self):
        claims = json.dumps({"id_token": {"email": None, "email_verified": None}})
        payload = _id_token_via_authcode(_dev_client(), claims=claims)
        assert payload["email"] == "admin@example.org"
        assert payload["email_verified"] is True

    def test_requested_custom_claim_lands_in_id_token(self):
        claims = json.dumps({"id_token": {"preferred_username": None, "tenant": None}})
        payload = _id_token_via_authcode(_dev_client(), claims=claims)
        assert payload["preferred_username"] == "admin"
        assert "tenant" in payload

    def test_unresolvable_claim_is_skipped(self):
        claims = json.dumps({"id_token": {"no_such_claim": None}})
        payload = _id_token_via_authcode(_dev_client(), claims=claims)
        assert "no_such_claim" not in payload

    def test_protocol_claims_not_overwritten(self):
        # A client asking for auth_time must not clobber the real value.
        payload = _id_token_via_authcode(
            _dev_client(), claims=json.dumps({"id_token": {"auth_time": None}})
        )
        assert isinstance(payload["auth_time"], int)

    def test_malformed_claims_does_not_break_the_flow(self):
        payload = _id_token_via_authcode(_dev_client(), claims="}{ not json")
        assert payload["sub"] == "admin"
        assert "email" not in payload


# --------------------------------------------------------------------------
# Integration: UserInfo member (composes with #102 scope gating)
# --------------------------------------------------------------------------
def _mint_and_userinfo(profile, scope, userinfo_claims):
    from nanoidp.config import get_config
    from nanoidp.services.token import get_token_service

    app = create_app(profile=profile)
    app.config["TESTING"] = True
    token = get_token_service().create_token(
        get_config().get_user("admin"),
        scope=scope,
        client_id="demo-client",
        userinfo_claims=userinfo_claims,
    )["access_token"]
    resp = app.test_client().get(
        "/userinfo", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200, resp.data
    return json.loads(resp.data)


class TestUserinfoMember:
    def test_requested_claim_returned_despite_scope_gating(self):
        # stricter-dev would drop email without the email scope (#102); the
        # UserInfo claims member forces it back in.
        data = _mint_and_userinfo("stricter-dev", scope="openid", userinfo_claims=["email"])
        assert data["email"] == "admin@example.org"

    def test_without_member_scope_gating_still_applies(self):
        data = _mint_and_userinfo("stricter-dev", scope="openid", userinfo_claims=None)
        assert "email" not in data


# --------------------------------------------------------------------------
# Discovery advertisement
# --------------------------------------------------------------------------
def test_discovery_advertises_claims_parameter_supported():
    client = _dev_client()
    doc = json.loads(client.get("/.well-known/openid-configuration").data)
    assert doc["claims_parameter_supported"] is True
