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

#: Advertised Claim Names that UserInfo supplies as a COMPOSITE member
#: rather than through the claim resolver. `attributes` is a Claim Name
#: (Core §5.6.1: for Normal Claims the member name is the Claim Name); what
#: it is not is resolver-addressable. Declared here rather than silently
#: tolerated (#316 decision 2).
COMPOSITE_USERINFO_CLAIMS = frozenset({"attributes"})


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


def _with_exports(app, **overrides):
    """The settings with both SAML exports on, which is what makes the
    roles/groups cells of the matrix observable at all."""
    with app.app_context():
        base = get_config().settings.model_dump()
    return Settings(
        **{**base, "saml_export_roles": True, "saml_export_groups": True, **overrides}
    )


def _access_token(app, user):
    with app.app_context():
        config = get_config()
        config.users[user.username] = user
        response = TokenService(config, config.snapshot).create_token(
            user, scope="openid email profile", client_id="demo-client"
        )
    return pyjwt.decode(response["access_token"], options={"verify_signature": False}), response


class TestDiscoveryAdvertisesOnlyWhatAnIdentitySurfaceCanSupply:
    """The #41 principle, applied to `claims_supported` (#316).

    OpenID Connect Discovery 1.0 §3 defines the field as the Claim Names the
    provider may be able to supply VALUES for. On top of that, nanoidp holds
    its own invariant: only a claim that can appear in an ID Token or a
    UserInfo response is advertised. That is a choice rather than a
    normative consequence - Core §5.5 does not require a requested claim to
    be returned, and this field is not the list of names the `claims`
    parameter accepts - and it is what this suite enforces.
    """

    def test_every_advertised_user_claim_resolves(self, app, user):
        with app.app_context():
            document = build_discovery_document(get_config().settings, issuer="http://localhost")

        unsupplied = [
            claim
            for claim in document["claims_supported"]
            if claim not in PROTOCOL_CLAIMS
            and claim not in COMPOSITE_USERINFO_CLAIMS
            and not resolve_user_claim(user, claim)[0]
        ]

        assert not unsupplied, (
            "claims_supported advertises claims no identity surface can supply: "
            f"{sorted(unsupplied)}. Either they are obtainable through the ID Token "
            "or UserInfo, or the document must not promise them (#41, #316)."
        )

    def test_the_composite_claims_really_are_supplied_by_userinfo(self, app, user):
        """An exemption that stops being true must fail too: `attributes` is
        excused from the resolver only because UserInfo supplies it as a
        composite member."""
        for claim in COMPOSITE_USERINFO_CLAIMS:
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

    def test_the_gated_userinfo_column_is_exercised_too(self, app, user):
        """The column exists in the matrix, so it is asserted here rather
        than left to the scope-gating tests elsewhere (#316 review): a
        regression in the gating branch must fail the contract suite."""
        gated = _userinfo(user, granted_scope="openid", scope_gating_active=True)
        with_email = _userinfo(user, granted_scope="openid email", scope_gating_active=True)

        assert "email" not in gated
        assert "preferred_username" not in gated
        assert with_email["email"] == "alice@example.org"
        # The ungated ones are unchanged by gating, which is the row above.
        assert gated["tenant"] == "acme"
        assert gated["roles"] == ["DEV"]
        assert "entitlements" not in gated
        assert "source_acl" not in gated

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


class TestWhatAuthoritiesFlattens:
    def test_a_custom_attribute_with_a_configured_prefix_becomes_an_authority(self, app, user):
        """The contract page listed the five stored fields and stopped there
        (#316 review): a custom attribute whose name has a prefix configured
        is flattened alongside them."""
        with app.app_context():
            config = get_config()
            config.settings.authority_prefixes["department"] = "DEPT_"
            authorities = TokenService(config, config.snapshot).build_authorities(user)

        assert "DEPT_IT" in authorities
        assert "ROLE_DEV" in authorities

    def test_a_custom_attribute_without_a_prefix_is_not_one(self, app, user):
        with app.app_context():
            config = get_config()
            config.settings.authority_prefixes.pop("department", None)
            authorities = TokenService(config, config.snapshot).build_authorities(user)

        assert not [a for a in authorities if a.endswith("IT")]


class TestTheTwoShapesOfACustomAttribute:
    def test_oidc_carries_the_map_and_saml_carries_one_attribute_per_key(self, app, user):
        token, _ = _access_token(app, user)
        with app.app_context():
            saml = resolve_saml_attributes(get_config().settings, user, include_source_acl=False)

        assert token["attributes"] == {"department": "IT"}
        assert _userinfo(user)["attributes"] == {"department": "IT"}
        assert saml["department"] == "IT"
        assert "attributes" not in saml

    def test_individual_custom_claim_is_resolver_addressable_but_composite_map_is_not(
        self, user
    ):
        """Both are Claim Names (Core §5.6.1). Only one is addressed by the
        resolver that answers a `claims` request (#316 decision 2)."""
        assert resolve_user_claim(user, "department") == (True, "IT")
        assert resolve_user_claim(user, "attributes") == (False, None)

    def test_one_name_gets_two_answers_when_a_user_owns_an_attribute_called_attributes(
        self, app
    ):
        """The consequence, characterized rather than described loosely
        (#316 review). The resolver answers a request for `attributes` from
        the user's own map, so an ID Token carries the scalar; UserInfo sets
        the composite member first and a requested claim never overwrites one
        already present, so the map wins there."""
        owner = User(**{**FULL_USER, "attributes": {"attributes": "a custom value"}})
        with app.app_context():
            config = get_config()
            config.users[owner.username] = owner
            response = TokenService(config, config.snapshot).create_token(
                owner, scope="openid", client_id="demo-client", id_token_claims=["attributes"]
            )
        id_token = pyjwt.decode(response["id_token"], options={"verify_signature": False})

        assert id_token["attributes"] == "a custom value"
        assert _userinfo(owner, requested_claims=["attributes"])["attributes"] == {
            "attributes": "a custom value"
        }


#: The four shapes an empty custom attribute can take. `_is_absent` names
#: all four explicitly and `attributes` is a Dict[str, Any], so testing only
#: one of them would leave three quarters of the policy implicit (#388).
EMPTY_SHAPES = {"e_str": "", "e_list": [], "e_dict": {}, "e_none": None}


class TestAnEmptyValueIsKeptByCompositesAndDroppedByProjections:
    """The #388 rule, which changed no behaviour and wrote three down.

    Composite and raw representations preserve explicitly configured empty
    values; derived projections may omit them when their representation
    cannot preserve the distinction usefully, or when the surface has an
    established omission policy. The disagreement between `authorities` and
    `attributes` inside one access token is therefore not a contradiction:
    they are two projections with different representational capacity.

    Deliberately not unified behind a shared `is_fact_present()`: the answer
    depends on the projection, so each of the three call sites would have to
    override it anyway.
    """

    @pytest.fixture
    def user_with_empties(self):
        return User(**{**FULL_USER, "attributes": {**EMPTY_SHAPES, "real": "IT"}})

    def test_the_attributes_map_keeps_every_empty_shape(self, app, user_with_empties):
        """The map is lossless about this distinction: `{}`, `{"x": ""}` and
        `{"x": []}` are three different documents, and an operator can
        deliberately simulate an upstream that supplies an empty claim."""
        token, _ = _access_token(app, user_with_empties)

        assert token["attributes"] == {**EMPTY_SHAPES, "real": "IT"}
        assert _userinfo(user_with_empties)["attributes"] == {**EMPTY_SHAPES, "real": "IT"}

    def test_a_user_with_no_attributes_carries_no_attributes_claim(self, app):
        """The composite is emitted only when it holds something, so the
        rule is about values under its keys and not about the map itself
        (#388 review): an empty map is absent, not an empty claim."""
        bare = User(**{**FULL_USER, "attributes": {}})
        token, _ = _access_token(app, bare)

        assert "attributes" not in token
        assert "attributes" not in _userinfo(bare)

    def test_a_value_that_is_itself_an_empty_map_is_still_kept(self, app):
        """The distinction the row above could be confused with: `{}` as a
        VALUE is preserved like any other empty shape."""
        owner = User(**{**FULL_USER, "attributes": {"x": {}}})
        token, _ = _access_token(app, owner)

        assert token["attributes"] == {"x": {}}

    def test_authorities_drops_every_empty_shape(self, app, user_with_empties):
        """A flat list of strings cannot say "present but empty": keeping
        `e_str` under the prefix `E_STR_` would emit the bare string
        `"E_STR_"`, which reads like an ordinary authority and loses the very
        distinction it was meant to carry."""
        with app.app_context():
            config = get_config()
            for name in {**EMPTY_SHAPES, "real": None}:
                config.settings.authority_prefixes[name] = name.upper() + "_"
            authorities = TokenService(config, config.snapshot).build_authorities(user_with_empties)

        assert "REAL_IT" in authorities
        for name in EMPTY_SHAPES:
            assert not [a for a in authorities if a.startswith(name.upper() + "_")]

    def test_saml_drops_every_empty_shape_by_policy(self, app, user_with_empties):
        """Not a limitation of the format: SAML 2.0 Core allows
        `<Attribute Name="x"/>`, an attribute that exists with no values, and
        that is distinct from the attribute being absent. #315 chose the
        other contract, an empty fact is an absent attribute, and #388 keeps
        it."""
        with app.app_context():
            settings = get_config().settings
            sso = resolve_saml_attributes(settings, user_with_empties, include_source_acl=False)
            query = resolve_saml_attributes(settings, user_with_empties, include_source_acl=True)

        for attributes in (sso, query):
            assert attributes["real"] == "IT"
            for name in EMPTY_SHAPES:
                assert name not in attributes


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

    def test_the_exports_govern_both_saml_surfaces(self, app, user):
        """One resolver serves the login assertion and the attribute query,
        and the route hands it the same settings, so an export reaches both.
        The contract page said "no" for the query column until a review read
        it against the resolver (#316 review): source_acl is the only
        attribute-level difference between those two surfaces."""
        settings = _with_exports(app)

        sso = resolve_saml_attributes(settings, user, include_source_acl=False)
        query = resolve_saml_attributes(settings, user, include_source_acl=True)

        assert sso["roles"] == ["DEV"] and sso["groups"] == ["team"]
        assert query["roles"] == ["DEV"] and query["groups"] == ["team"]
        assert set(query) - set(sso) == {"source_acl"}

    def test_when_exported_they_carry_the_service_provider_s_own_names(self, app, user):
        settings = _with_exports(app, saml_roles_attr_name="memberOf", saml_groups_attr_name="memberOf")

        saml = resolve_saml_attributes(settings, user, include_source_acl=False)

        # One configured name for both exports merges the lists, roles
        # first, rather than letting the second replace the first (#134).
        assert saml["memberOf"] == ["DEV", "team"]
        assert "roles" not in saml
