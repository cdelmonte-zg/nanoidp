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


def _tokens_via_authcode(client, claims=None):
    """Drive the full authorization code flow and return the token response."""
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
    return json.loads(token_resp.data)


def _id_token_via_authcode(client, claims=None):
    """Drive the full authorization code flow and return the decoded ID Token."""
    id_token = _tokens_via_authcode(client, claims=claims)["id_token"]
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

    def test_custom_user_attribute_lands_in_id_token(self):
        # admin carries department/cost_center in users.yaml attributes; a
        # requested attribute name resolves like any standard claim (#113).
        claims = json.dumps({"id_token": {"department": None}})
        payload = _id_token_via_authcode(_dev_client(), claims=claims)
        assert payload["department"] == "IT"

    def test_essential_and_value_refinements_accepted_but_ignored(self):
        # §5.5.1 refinements are parsed for the claim NAME only: essential
        # claims are delivered as if voluntary, and a `value` constraint never
        # overrides the user's real value.
        claims = json.dumps(
            {"id_token": {"email": {"essential": True}, "tenant": {"value": "spoofed"}}}
        )
        payload = _id_token_via_authcode(_dev_client(), claims=claims)
        assert payload["email"] == "admin@example.org"
        assert payload["tenant"] == "default"  # real value, not the requested one


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

    def test_requesting_already_present_claims_is_invariant_under_dev(self):
        # Under the permissive dev profile email/preferred_username are already
        # in the response; the no-overwrite branch must leave the response
        # exactly as it would be without the request (#113).
        with_claims = _mint_and_userinfo(
            "dev", scope="openid", userinfo_claims=["email", "email_verified", "roles"]
        )
        without_claims = _mint_and_userinfo("dev", scope="openid", userinfo_claims=None)
        assert with_claims == without_claims
        assert with_claims["email"] == "admin@example.org"

    def test_no_overwrite_keeps_scope_gated_value(self, monkeypatch):
        # White-box check of the `claim_name not in response` guard. /userinfo
        # resolves every claim through resolve_user_claim (defaults and the
        # req_userinfo_claims loop alike, #113), so a resolver wrapper that
        # records each resolved name proves the guard: a requested claim that
        # is already present must be resolved exactly once (by the defaults),
        # never re-resolved by the requested-claims loop.
        import nanoidp.routes.oauth as oauth_module
        from nanoidp.services.token import resolve_user_claim as real_resolver

        resolved_names = []

        def recording_resolver(user, name):
            found, value = real_resolver(user, name)
            if found:
                resolved_names.append(name)
            return found, value

        from nanoidp.config import get_config
        from nanoidp.services.token import get_token_service

        client = _dev_client()
        token = get_token_service().create_token(
            get_config().get_user("admin"),
            scope="openid",
            client_id="demo-client",
            userinfo_claims=["email", "department"],
        )["access_token"]

        # Patch AFTER minting, and only where /userinfo resolves claims.
        monkeypatch.setattr(oauth_module, "resolve_user_claim", recording_resolver)
        resp = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.data
        data = json.loads(resp.data)
        # email was already placed by the permissive dev defaults: the
        # requested duplicate must not have re-resolved it.
        assert resolved_names.count("email") == 1
        assert data["email"] == "admin@example.org"
        # department was not among the defaults -> added by the requested loop
        assert data["department"] == "IT"


# --------------------------------------------------------------------------
# Integration: requested claims persist across token refresh (#112)
# --------------------------------------------------------------------------
class TestClaimsPersistAcrossRefresh:
    def _refresh(self, client, refresh_token, extra_form=None):
        form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if extra_form:
            form.update(extra_form)
        resp = client.post("/token", data=form, headers=_basic_auth())
        assert resp.status_code == 200, resp.data
        return json.loads(resp.data)

    def test_refresh_token_carries_requested_claim_names(self):
        client = _dev_client()
        claims = json.dumps({"id_token": {"email": None}, "userinfo": {"department": None}})
        tokens = _tokens_via_authcode(client, claims=claims)
        rt = pyjwt.decode(tokens["refresh_token"], options={"verify_signature": False})
        assert rt["req_id_token_claims"] == ["email"]
        assert rt["req_userinfo_claims"] == ["department"]

    def test_refreshed_id_token_keeps_requested_claims(self):
        client = _dev_client()
        claims = json.dumps({"id_token": {"email": None, "department": None}})
        tokens = _tokens_via_authcode(client, claims=claims)

        refreshed = self._refresh(client, tokens["refresh_token"])
        payload = pyjwt.decode(refreshed["id_token"], options={"verify_signature": False})
        assert payload["email"] == "admin@example.org"
        assert payload["department"] == "IT"

        # ...and across a SECOND refresh (rotation re-persists the names).
        refreshed2 = self._refresh(client, refreshed["refresh_token"])
        payload2 = pyjwt.decode(refreshed2["id_token"], options={"verify_signature": False})
        assert payload2["email"] == "admin@example.org"

    def test_refreshed_access_token_keeps_userinfo_claims(self):
        # Under stricter-dev, /userinfo would gate email out without the email
        # scope (#102); the persisted userinfo member must keep forcing it back
        # in after a refresh. The refresh leg is driven over HTTP; the original
        # grant is minted directly (the stricter-dev authorize leg would need
        # PKCE, which is orthogonal here).
        from nanoidp.config import get_config
        from nanoidp.services.token import get_token_service

        app = create_app(profile="stricter-dev")
        app.config["TESTING"] = True
        client = app.test_client()
        original = get_token_service().create_token(
            get_config().get_user("admin"),
            scope="openid",
            client_id="demo-client",
            userinfo_claims=["email"],
        )

        refreshed = self._refresh(client, original["refresh_token"])
        access_payload = pyjwt.decode(
            refreshed["access_token"], options={"verify_signature": False}
        )
        assert access_payload["req_userinfo_claims"] == ["email"]

        resp = client.get(
            "/userinfo",
            headers={"Authorization": "Bearer " + refreshed["access_token"]},
        )
        assert resp.status_code == 200, resp.data
        assert json.loads(resp.data)["email"] == "admin@example.org"

    def test_legacy_refresh_token_without_claims_still_works(self):
        # Refresh tokens minted before #112 carry neither claim: the refresh
        # succeeds and simply issues tokens without the requested-claims extras.
        client = _dev_client()
        tokens = _tokens_via_authcode(client)  # no claims parameter
        rt = pyjwt.decode(tokens["refresh_token"], options={"verify_signature": False})
        assert "req_id_token_claims" not in rt
        assert "req_userinfo_claims" not in rt

        refreshed = self._refresh(client, tokens["refresh_token"])
        id_payload = pyjwt.decode(refreshed["id_token"], options={"verify_signature": False})
        assert "email" not in id_payload
        access_payload = pyjwt.decode(
            refreshed["access_token"], options={"verify_signature": False}
        )
        assert "req_userinfo_claims" not in access_payload

    def test_forged_refresh_token_with_malformed_claims_refreshes_cleanly(self):
        # Hand-crafting tokens with the IdP key is a first-class dev workflow:
        # a refresh token carrying garbage requested-claims values (an int, the
        # raw §5.5 object instead of names, a bare string) must not 500 after
        # the token has been consumed — sanitize_claim_names drops the garbage
        # and the refresh succeeds without it.
        from nanoidp.config import get_config
        from nanoidp.services.crypto import get_crypto_service

        client = _dev_client()
        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)
        forged = crypto.create_jwt(
            sub="admin",
            issuer=config.settings.issuer,
            audience=config.settings.audience,
            exp_minutes=60,
            extra={
                "token_type": "refresh",
                "token_use": "refresh",
                "scope": "openid",
                "rt_family": "forged-family",
                "req_id_token_claims": 42,  # non-iterable
                "req_userinfo_claims": "email",  # bare string, not a list
            },
        )

        refreshed = self._refresh(client, forged)
        id_payload = pyjwt.decode(refreshed["id_token"], options={"verify_signature": False})
        assert "email" not in id_payload  # the garbage resolved nothing
        access_payload = pyjwt.decode(
            refreshed["access_token"], options={"verify_signature": False}
        )
        assert "req_userinfo_claims" not in access_payload
        # ...and a list with mixed entries keeps only the string names
        forged_mixed = crypto.create_jwt(
            sub="admin",
            issuer=config.settings.issuer,
            audience=config.settings.audience,
            exp_minutes=60,
            extra={
                "token_type": "refresh",
                "token_use": "refresh",
                "scope": "openid",
                "rt_family": "forged-family-2",
                "req_id_token_claims": ["email", {"essential": True}],
            },
        )
        refreshed = self._refresh(client, forged_mixed)
        id_payload = pyjwt.decode(refreshed["id_token"], options={"verify_signature": False})
        assert id_payload["email"] == "admin@example.org"

    def test_userinfo_tolerates_malformed_req_claims_on_access_token(self):
        # A hand-crafted ACCESS token with a non-list req_userinfo_claims must
        # not 500 /userinfo (nor leak single-character attribute lookups from
        # iterating a string).
        from nanoidp.config import get_config
        from nanoidp.services.crypto import get_crypto_service

        client = _dev_client()
        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)
        for bad in (5, "email", {"email": None}):
            token = crypto.create_jwt(
                sub="admin",
                issuer=config.settings.issuer,
                audience=config.settings.audience,
                exp_minutes=5,
                extra={"req_userinfo_claims": bad},
            )
            resp = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200, (bad, resp.data)


# --------------------------------------------------------------------------
# Security: authoritative claims cannot be spoofed via `extra`
# --------------------------------------------------------------------------
class TestReservedClaimsCannotBeSpoofed:
    """`scope`/`req_userinfo_claims` must reflect the grant, not `extra_claims`.

    The /token endpoint accepts an arbitrary `extra` JSON object, so a caller
    must not be able to smuggle these authoritative claims into the access token
    and have /userinfo honour them past the #102 scope gating.
    """

    def _mint(self, profile, scope, extra_claims):
        from nanoidp.config import get_config
        from nanoidp.services.token import get_token_service

        app = create_app(profile=profile)
        app.config["TESTING"] = True
        token = get_token_service().create_token(
            get_config().get_user("admin"),
            scope=scope,
            client_id="demo-client",
            extra_claims=extra_claims,
        )["access_token"]
        payload = pyjwt.decode(token, options={"verify_signature": False})
        resp = app.test_client().get(
            "/userinfo", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200, resp.data
        return payload, json.loads(resp.data)

    def test_req_userinfo_claims_via_extra_is_dropped(self):
        payload, data = self._mint(
            "stricter-dev", scope="openid", extra_claims={"req_userinfo_claims": ["email"]}
        )
        assert "req_userinfo_claims" not in payload
        assert "email" not in data

    def test_scope_via_extra_is_dropped(self):
        payload, data = self._mint(
            "stricter-dev", scope=None, extra_claims={"scope": "openid email"}
        )
        assert "scope" not in payload
        assert "email" not in data


# --------------------------------------------------------------------------
# Security: reserved claim names cannot be requested/overwritten (#110)
# --------------------------------------------------------------------------
_RESERVED = [
    "iss", "sub", "aud", "exp", "iat", "nbf", "jti",
    "token_use", "auth_time", "at_hash", "azp", "nonce", "scope",
    "req_userinfo_claims", "req_id_token_claims",
]


class TestReservedClaimNames:
    def test_resolver_refuses_reserved_names_even_with_colliding_attribute(self):
        user = User(
            username="u", password="p", email="u@example.org",
            attributes={"exp": 111, "aud": "evil", "sub": "spoof", "department": "eng"},
        )
        for name in _RESERVED:
            assert resolve_user_claim(user, name) == (False, None), name
        # a non-reserved attribute still resolves normally
        assert resolve_user_claim(user, "department") == (True, "eng")

    def test_id_token_registered_claims_not_overwritable(self):
        """A requested claim colliding with a user attribute must not hijack the
        registered ID Token claims (create_jwt applies `extra` last)."""
        from nanoidp.services.token import get_token_service

        app = create_app(profile="dev")
        app.config["TESTING"] = True
        user = User(
            username="attacker", password="p", email="a@example.org",
            attributes={"exp": 111, "aud": "https://evil.example", "iss": "https://evil"},
        )
        resp = get_token_service().create_token(
            user, scope="openid", client_id="demo-client",
            id_token_claims=["exp", "aud", "iss", "email"],
        )
        payload = pyjwt.decode(resp["id_token"], options={"verify_signature": False})
        assert payload["exp"] > 111  # real future expiry, not the attribute
        assert "evil" not in str(payload["aud"])  # real audience, not attacker value
        assert "evil" not in payload["iss"]
        # a legitimate requested claim still lands
        assert payload["email"] == "a@example.org"


# --------------------------------------------------------------------------
# Discovery advertisement
# --------------------------------------------------------------------------
def test_discovery_advertises_claims_parameter_supported():
    client = _dev_client()
    doc = json.loads(client.get("/.well-known/openid-configuration").data)
    assert doc["claims_parameter_supported"] is True
