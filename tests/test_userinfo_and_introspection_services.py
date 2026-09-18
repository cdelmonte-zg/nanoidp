"""What a token's bearer is told, without a request to ask it (#303).

The UserInfo claim assembly and the RFC 7662 introspection response used to
be built inside the routes, so these rules could only be exercised through
HTTP. They are services now, and this is what they promise.
"""

import pytest

from nanoidp.models import Settings, User
from nanoidp.services.introspection import build_introspection_response
from nanoidp.services.userinfo import build_userinfo_response


def _user(**overrides):
    values = {
        "username": "alice",
        "password": "secret",
        "email": "alice@example.org",
        "roles": ["dev"],
        "groups": ["team"],
        "tenant": "acme",
        "identity_class": "human",
    }
    values.update(overrides)
    return User(**values)


def _userinfo(user=None, subject="alice", scope="openid", gating=False, requested=None):
    return build_userinfo_response(
        user,
        subject=subject,
        granted_scope=scope,
        scope_gating_active=gating,
        requested_claims=requested,
    )


class TestTheCallCannotBeMadeWrongly:
    def test_the_subject_and_the_scope_cannot_be_swapped_silently(self):
        """Two adjacent optional strings next to each other are a swap
        waiting to happen, and a swap would answer with the scope as the
        subject (#303 review): they are keyword-only."""
        with pytest.raises(TypeError):
            build_userinfo_response(_user(), "alice", "openid", False, None)


class TestWhatTheBearerSees:
    def test_a_subject_with_no_user_gets_its_subject_and_nothing_else(self):
        assert _userinfo(user=None) == {"sub": "alice"}

    def test_without_gating_the_standard_claims_are_returned_whatever_the_scope(self):
        """The permissive `dev` default, unchanged since #102."""
        response = _userinfo(_user(), scope="openid")

        assert response["email"] == "alice@example.org"
        assert response["email_verified"] is True
        assert response["preferred_username"] == "alice"

    @pytest.mark.parametrize(
        ("scope", "expected"),
        [
            ("openid", set()),
            ("openid email", {"email", "email_verified"}),
            ("openid profile", {"preferred_username"}),
            ("openid email profile", {"email", "email_verified", "preferred_username"}),
        ],
    )
    def test_with_gating_each_standard_claim_waits_for_its_scope(self, scope, expected):
        response = _userinfo(_user(), scope=scope, gating=True)

        standard = {"email", "email_verified", "preferred_username"}
        assert standard & set(response) == expected

    @pytest.mark.parametrize("gating", [False, True])
    def test_the_claims_with_no_standard_scope_are_always_returned(self, gating):
        """Gating them would be arbitrary: no scope governs them (#102)."""
        response = _userinfo(_user(), scope="openid", gating=gating)

        assert response["roles"] == ["dev"]
        assert response["groups"] == ["team"]
        assert response["tenant"] == "acme"
        assert response["identity_class"] == "human"

    def test_the_raw_attributes_dict_is_passed_through(self):
        response = _userinfo(_user(attributes={"department": "IT"}))

        assert response["attributes"] == {"department": "IT"}

    def test_a_user_without_attributes_carries_no_attributes_key(self):
        assert "attributes" not in _userinfo(_user(attributes={}))

    def test_a_claim_the_resolver_cannot_supply_is_omitted(self):
        response = _userinfo(_user(roles=[], groups=[], tenant="", identity_class=None))

        assert "identity_class" not in response

    def test_a_requested_claim_arrives_even_when_gating_would_omit_it(self):
        """§5.5: what the client asked for is added, gating or not."""
        response = _userinfo(_user(), scope="openid", gating=True, requested=["email"])

        assert response["email"] == "alice@example.org"

    def test_a_requested_claim_never_overwrites_one_already_set(self):
        response = _userinfo(
            _user(attributes={"department": "IT"}), requested=["preferred_username", "department"]
        )

        assert response["preferred_username"] == "alice"
        assert response["department"] == "IT"

    @pytest.mark.parametrize(
        "requested", [None, "email", 42, {"email": None}, ["email", 7], []]
    )
    def test_a_malformed_requested_claims_value_is_ignored_not_raised(self, requested):
        """It reaches here from a token payload, which may be hand-crafted."""
        response = _userinfo(_user(), scope="openid", gating=True, requested=requested)

        assert response["sub"] == "alice"

    def test_a_reserved_claim_cannot_be_requested(self):
        response = _userinfo(_user(), requested=["sub", "iss"])

        assert response["sub"] == "alice"
        assert "iss" not in response


class TestTheProfileDecidesTheGating:
    @pytest.mark.parametrize(
        ("profile", "gating"),
        [("dev", False), ("stricter-dev", True), ("oauth21", True)],
    )
    def test_which_profiles_gate(self, profile, gating):
        assert Settings(security_profile=profile).userinfo_scope_gating_active is gating

    def test_scope_enforcement_alone_does_not_gate_userinfo(self):
        """The two predicates read alike and are not the same question: under
        dev with enforcement on, UserInfo still answers ungated."""
        settings = Settings(security_profile="dev", scope_enforcement=True)

        assert settings.scope_enforcement_active is True
        assert settings.userinfo_scope_gating_active is False


class TestWhatAnIntrospectionReports:
    PAYLOAD = {
        "sub": "alice",
        "client_id": "demo-client",
        "aud": "my-app",
        "iss": "http://localhost:8000",
        "exp": 2000,
        "iat": 1000,
        "nbf": 1000,
        "scope": "openid email",
    }

    def test_a_full_payload_is_reported_claim_for_claim(self):
        response = build_introspection_response(self.PAYLOAD, "caller")

        assert response == {
            "active": True,
            "token_type": "Bearer",
            "client_id": "demo-client",
            "username": "alice",
            "sub": "alice",
            "aud": "my-app",
            "iss": "http://localhost:8000",
            "exp": 2000,
            "iat": 1000,
            "nbf": 1000,
            "scope": "openid email",
        }

    def test_the_caller_is_the_fallback_only_when_the_token_names_no_client(self):
        """RFC 7662 §2.2 reports the client the TOKEN was issued to."""
        without = {key: value for key, value in self.PAYLOAD.items() if key != "client_id"}

        assert build_introspection_response(without, "caller")["client_id"] == "caller"

    def test_a_token_naming_a_null_client_reports_null_not_the_caller(self):
        """Presence, not truthiness: the key is there, so it is what is
        reported - flattening this to `or` would change what the response
        says about the token."""
        payload = {**self.PAYLOAD, "client_id": None}

        assert build_introspection_response(payload, "caller")["client_id"] is None

    def test_a_token_without_a_scope_is_reported_with_the_default(self):
        without = {key: value for key, value in self.PAYLOAD.items() if key != "scope"}

        assert build_introspection_response(without, "caller")["scope"] == "openid"

    def test_an_empty_scope_is_reported_as_empty(self):
        payload = {**self.PAYLOAD, "scope": ""}

        assert build_introspection_response(payload, "caller")["scope"] == ""

    def test_missing_time_and_audience_claims_are_reported_as_null(self):
        response = build_introspection_response({"sub": "alice"}, "caller")

        for claim in ("aud", "iss", "exp", "iat", "nbf"):
            assert response[claim] is None
        assert response["active"] is True
