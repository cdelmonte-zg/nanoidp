"""The user-fact contract across the OIDC and SAML surfaces (#316).

The census behind this file replaced the original plan. The two assemblers,
``TokenService.create_token`` and ``resolve_saml_attributes``, share almost
no code to extract: one produces JWT claims, the other SAML attributes
under names the service provider configures. What they do share is a set of
DIFFERENCES that nobody had written down, so a change to either side could
silently change what nanoidp says about a principal on the other.

These are characterization tests, deliberately not parity tests. Nothing
here asserts that the two protocols carry the same facts; they do not, and
several of the differences are the point. What each test asserts is that a
difference is the one that was decided. A test failing here means an
observable difference appeared or disappeared, which is a decision to make,
not a number to update.

The matrix they fix (#316 carries it in full):

- ``tenant`` is OIDC-only and reaches no SAML surface.
- ``authorities`` exists only on the access token.
- ``source_acl`` is on the access token and the SAML attribute query, and
  on no identity surface.
- ``entitlements`` is on the access token and both SAML surfaces, absent
  from the default UserInfo response, and obtainable on request.
- ``attributes`` is a map on the OIDC surfaces and one flattened attribute
  per key on the SAML ones.
- ``roles``/``groups`` are unconditional on OIDC and opt-in, under
  configurable names, on SAML.
"""

import jwt as pyjwt
import pytest

from nanoidp.config import get_config
from nanoidp.models import Settings, User
from nanoidp.services.discovery import build_discovery_document
from nanoidp.services.saml_attributes import resolve_saml_attributes
from nanoidp.services.token import TokenService, resolve_user_claim
from nanoidp.services.userinfo import build_userinfo_response

#: One principal carrying every fact, so a surface that omits one omits it
#: because of its own rule and not for want of data.
FULL_USER = {
    "username": "alice",
    "password": "pw",
    "email": "alice@example.org",
    "identity_class": "human",
    "entitlements": ["ent-a"],
    "roles": ["DEV"],
    "groups": ["team"],
    "tenant": "acme",
    "source_acl": ["/docs/*"],
    "attributes": {"department": "IT"},
}

#: Claims the protocol machinery mints, not facts about the user. They are
#: the claims_supported entries this file does not expect a user resolver to
#: produce.
PROTOCOL_CLAIMS = frozenset(
    {"sub", "iss", "aud", "azp", "exp", "iat", "nbf", "auth_time", "nonce", "at_hash", "amr"}
)

#: The one advertised claim that is not a claim NAME: UserInfo supplies the
#: map, and the `claims` request parameter cannot ask for it. Declared here
#: rather than silently tolerated (#316 decision 2).
USERINFO_ONLY_EXTENSIONS = frozenset({"attributes"})


@pytest.fixture
def user():
    return User(**FULL_USER)


def _userinfo(user, **overrides):
    arguments = {
        "subject": user.username,
        "granted_scope": "openid email profile",
        "scope_gating_active": False,
        "requested_claims": None,
    }
    arguments.update(overrides)
    return build_userinfo_response(user, **arguments)


def _access_token(app, user):
    with app.app_context():
        config = get_config()
        config.users[user.username] = user
        response = TokenService(config).create_token(
            user, scope="openid email profile", client_id="demo-client"
        )
    return pyjwt.decode(response["access_token"], options={"verify_signature": False}), response


class TestDiscoveryAdvertisesOnlyWhatAnIdentitySurfaceCanSupply:
    """The #41 principle, applied to `claims_supported` (#316).

    OIDC Core 3 §3 defines the field as the claims the provider may be able
    to supply VALUES for. A claim that exists only on the access token is
    not one of them: no ID Token and no UserInfo response can carry it, and
    a client that reads the document and asks for it gets nothing back.
    """

    def test_every_advertised_user_claim_resolves(self, app, user):
        with app.app_context():
            document = build_discovery_document(get_config().settings, issuer="http://localhost")

        unsupplied = [
            claim
            for claim in document["claims_supported"]
            if claim not in PROTOCOL_CLAIMS
            and claim not in USERINFO_ONLY_EXTENSIONS
            and not resolve_user_claim(user, claim)[0]
        ]

        assert not unsupplied, (
            "claims_supported advertises claims no identity surface can supply: "
            f"{sorted(unsupplied)}. Either they are obtainable through the ID Token "
            "or UserInfo, or the document must not promise them (#41, #316)."
        )

    def test_the_declared_extension_really_is_supplied_by_userinfo(self, app, user):
        """An exemption that stops being true must fail too: `attributes` is
        excused from the resolver only because UserInfo returns it."""
        for claim in USERINFO_ONLY_EXTENSIONS:
            assert claim in _userinfo(user)

    def test_the_access_token_only_facts_are_not_advertised(self, app):
        """The two the census found, named so the reason survives: they are
        authorization facts for a resource server, not identity claims."""
        with app.app_context():
            document = build_discovery_document(get_config().settings, issuer="http://localhost")

        assert "source_acl" not in document["claims_supported"]
        assert "authorities" not in document["claims_supported"]


class TestWhatEachSurfaceCarries:
    def test_tenant_is_oidc_only(self, app, user):
        """Historical absence turned into a decision (#316): no commit ever
        exported tenant over SAML, and adding it now would change the
        assertions every service provider under test receives."""
        token, _ = _access_token(app, user)
        with app.app_context():
            settings = get_config().settings
            sso = resolve_saml_attributes(settings, user, include_source_acl=False)
            query = resolve_saml_attributes(settings, user, include_source_acl=True)

        assert token["tenant"] == "acme"
        assert _userinfo(user)["tenant"] == "acme"
        assert "tenant" not in sso
        assert "tenant" not in query

    def test_authorities_is_access_token_only(self, app, user):
        token, _ = _access_token(app, user)
        with app.app_context():
            settings = get_config().settings
            saml = resolve_saml_attributes(settings, user, include_source_acl=True)

        assert token["authorities"]
        assert "authorities" not in _userinfo(user)
        assert "authorities" not in saml

    def test_source_acl_reaches_the_access_token_and_the_saml_query_only(self, app, user):
        """The attribute query exists for backend authorization lookups; a
        login assertion carries no document-level ACLs (#302)."""
        token, _ = _access_token(app, user)
        with app.app_context():
            settings = get_config().settings
            sso = resolve_saml_attributes(settings, user, include_source_acl=False)
            query = resolve_saml_attributes(settings, user, include_source_acl=True)

        assert token["source_acl"] == ["/docs/*"]
        assert query["source_acl"] == ["/docs/*"]
        assert "source_acl" not in sso
        assert "source_acl" not in _userinfo(user)

    def test_entitlements_is_absent_from_userinfo_but_obtainable_on_request(self, app, user):
        """Contract already, from the ungated list in tokens.md: not
        returned by default, and never unreachable (#316 decision 4)."""
        token, _ = _access_token(app, user)
        with app.app_context():
            saml = resolve_saml_attributes(get_config().settings, user, include_source_acl=False)

        assert token["entitlements"] == ["ent-a"]
        assert saml["entitlements"] == ["ent-a"]
        assert "entitlements" not in _userinfo(user)
        assert _userinfo(user, requested_claims=["entitlements"])["entitlements"] == ["ent-a"]

    def test_email_is_on_no_oauth_token(self, app, user):
        """It is served from UserInfo, which is what tokens.md tells clients
        to expect, and asserted over SAML."""
        token, response = _access_token(app, user)
        id_token = pyjwt.decode(response["id_token"], options={"verify_signature": False})
        with app.app_context():
            saml = resolve_saml_attributes(get_config().settings, user, include_source_acl=False)

        assert "email" not in token
        assert "email" not in id_token
        assert _userinfo(user)["email"] == "alice@example.org"
        assert saml["email"] == "alice@example.org"

    def test_the_id_token_carries_no_user_fact_unless_asked(self, app, user):
        """Every fact in the matrix is absent from an ID Token issued
        without a `claims` request."""
        _, response = _access_token(app, user)
        id_token = pyjwt.decode(response["id_token"], options={"verify_signature": False})

        for fact in FULL_USER:
            if fact != "username":
                assert fact not in id_token


class TestTheTwoShapesOfACustomAttribute:
    def test_oidc_carries_the_map_and_saml_carries_one_attribute_per_key(self, app, user):
        token, _ = _access_token(app, user)
        with app.app_context():
            saml = resolve_saml_attributes(get_config().settings, user, include_source_acl=False)

        assert token["attributes"] == {"department": "IT"}
        assert _userinfo(user)["attributes"] == {"department": "IT"}
        assert saml["department"] == "IT"
        assert "attributes" not in saml

    def test_an_individual_attribute_is_a_claim_name_and_the_map_is_not(self, user):
        """Reads as a contradiction until it is written down (#316 decision
        2): a custom attribute is requestable, the container that holds them
        is not."""
        assert resolve_user_claim(user, "department") == (True, "IT")
        assert resolve_user_claim(user, "attributes") == (False, None)

    def test_the_map_resolves_only_by_name_collision(self):
        """And then it is that custom claim, not the UserInfo map."""
        owner = User(**{**FULL_USER, "attributes": {"attributes": "a custom value"}})

        assert resolve_user_claim(owner, "attributes") == (True, "a custom value")


class TestRolesAndGroupsAreUnconditionalOnOidcAndOptInOnSaml:
    def test_saml_exports_neither_by_default(self, app, user):
        token, _ = _access_token(app, user)
        with app.app_context():
            settings = get_config().settings
            saml = resolve_saml_attributes(settings, user, include_source_acl=False)

        assert settings.saml_export_roles is False
        assert settings.saml_export_groups is False
        assert token["roles"] == ["DEV"]
        assert _userinfo(user)["groups"] == ["team"]
        assert "roles" not in saml
        assert "groups" not in saml

    def test_when_exported_they_carry_the_service_provider_s_own_names(self, app, user):
        with app.app_context():
            base = get_config().settings.model_dump()
        settings = Settings(
            **{
                **base,
                "saml_export_roles": True,
                "saml_export_groups": True,
                "saml_roles_attr_name": "memberOf",
                "saml_groups_attr_name": "memberOf",
            }
        )

        saml = resolve_saml_attributes(settings, user, include_source_acl=False)

        # One configured name for both exports merges the lists, roles
        # first, rather than letting the second replace the first (#134).
        assert saml["memberOf"] == ["DEV", "team"]
        assert "roles" not in saml
