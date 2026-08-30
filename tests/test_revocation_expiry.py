"""
RevocationStore entry expiry and opportunistic sweep (#288).

Before this, revoked jtis and rotation-family markers lived in two sets that
were never swept: every revocation and every rotation on a long-lived
instance was a permanent memory increment. A revoked jti only needs
remembering until the token it names expires - after ``exp`` the signature
check rejects it anyway.

Time is driven by monkeypatching ``time.time`` inside the module - no sleeps.
"""

import time

import pytest

from nanoidp.services import revocation
from nanoidp.services.revocation import _DEFAULT_RETENTION_SECONDS, RevocationStore


@pytest.fixture
def store():
    return RevocationStore()


def _advance(monkeypatch, seconds):
    real_now = time.time()
    monkeypatch.setattr(revocation.time, "time", lambda: real_now + seconds)


class TestEntryExpiry:
    def test_revoked_until_exp_then_swept(self, store, monkeypatch):
        store.revoke("jti-a", expires_at=time.time() + 100)
        assert store.is_revoked("jti-a")

        _advance(monkeypatch, 200)
        # Sweep runs on the next mutating call.
        store.revoke("jti-b", expires_at=revocation.time.time() + 100)
        assert not store.is_revoked("jti-a")
        assert store.is_revoked("jti-b")

    def test_no_exp_falls_back_to_bounded_retention(self, store, monkeypatch):
        store.revoke("jti-noexp")
        assert store.is_revoked("jti-noexp")

        _advance(monkeypatch, _DEFAULT_RETENTION_SECONDS + 60)
        store.revoke("other")
        assert not store.is_revoked("jti-noexp")

    def test_logout_forged_exp_never_reaches_the_store(self, client):
        """/logout decodes id_token_hint UNVERIFIED, so no claim from it -
        exp included - reaches the store (#293 review round 1): the entry
        gets the bounded default, not the forged 10-year exp. Route-level
        because the trust decision lives at the call site now, not in a
        store-side cap (which would break trusted long expiries, blocker 1)."""
        import jwt as pyjwt

        from nanoidp.services.revocation import get_revocation_store

        forged = pyjwt.encode(
            {"jti": "forged-jti", "exp": time.time() + 10 * 365 * 24 * 3600, "sub": "x"},
            "attacker-key",
            algorithm="HS256",
        )
        get_revocation_store().clear()
        try:
            resp = client.get("/logout", query_string={"id_token_hint": forged})
            assert resp.status_code in (200, 302)
            store = get_revocation_store()
            assert store.is_revoked("forged-jti")
            assert (
                store._revoked_tokens["forged-jti"]
                <= time.time() + _DEFAULT_RETENTION_SECONDS + 1
            )
        finally:
            get_revocation_store().clear()

    def test_already_expired_token_keeps_a_short_memory(self, store):
        """A just-revoked, just-expired token must not flicker back as
        unrevoked before the caller's own exp check catches it."""
        store.revoke("jti-old", expires_at=time.time() - 1000)
        assert store.is_revoked("jti-old")


class TestRefreshClaimExpiry:
    def test_claimed_jti_expires_with_its_token(self, store, monkeypatch):
        exp = time.time() + 100
        reused = store.check_and_claim_refresh("rt-1", "fam-1", True, expires_at=exp)
        assert reused is False
        # Reuse before exp is detected.
        assert store.check_and_claim_refresh("rt-1", "fam-1", True, expires_at=exp) is True

        _advance(monkeypatch, 200)
        # After the token's own exp the claim may be forgotten: the JWT is
        # rejected on exp long before this store is consulted.
        store.revoke("unrelated")
        assert not store.is_revoked("rt-1")

    def test_family_marker_outlives_the_presented_token(self, store, monkeypatch):
        """Descendants minted before reuse detection can outlive the
        presented ancestor: the family marker gets the retention bound, not
        the ancestor's exp."""
        near_exp = time.time() + 5
        store.check_and_claim_refresh("rt-a", "fam-x", True, expires_at=near_exp)
        assert store.check_and_claim_refresh("rt-a", "fam-x", True, expires_at=near_exp) is True

        _advance(monkeypatch, 3600)
        # Well past the ancestor's exp, the family is still revoked for a
        # descendant presenting a longer-lived token.
        assert (
            store.check_and_claim_refresh(
                "rt-descendant", "fam-x", True, expires_at=revocation.time.time() + 1000
            )
            is True
        )

    def test_rotation_semantics_unchanged(self, store):
        """The pre-#288 contract: first claim passes, family revocation on
        reuse hits every member."""
        assert store.check_and_claim_refresh("r1", "famZ", True) is False
        assert store.check_and_claim_refresh("r1", "famZ", True) is True
        assert store.check_and_claim_refresh("r2", "famZ", True) is True
        store.clear()
        assert store.check_and_claim_refresh("r1", "famZ", True) is False


class TestReviewRound1Blockers:
    """#293 review round 1: two retention-semantics blockers."""

    def test_trusted_exp_beyond_the_bound_survives_the_sweep(self, store, monkeypatch):
        """B1: /api/users/<u>/token accepts arbitrary exp_minutes, so a
        VERIFIED token can outlive the 8-day bound - capping a trusted exp
        let a revoked 14-day token flicker back after the day-8 sweep."""
        fourteen_days = time.time() + 14 * 24 * 3600
        store.revoke("jti-long", expires_at=fourteen_days)

        _advance(monkeypatch, 9 * 24 * 3600)
        store.revoke("trigger-sweep")
        assert store.is_revoked("jti-long"), (
            "a verified 14-day token must stay revoked past day 8"
        )

        _advance(monkeypatch, 15 * 24 * 3600)
        store.revoke("trigger-sweep-2")
        assert not store.is_revoked("jti-long")

    def test_re_revoking_never_shortens_retention(self, store, monkeypatch):
        """B2: writes are monotonic - a second revoke of the same jti with a
        shorter expiry must not shorten the existing retention (the old
        set.add() was naturally idempotent; the dict assignment was not)."""
        store.revoke("jti-twice", expires_at=time.time() + 3600)
        store.revoke("jti-twice", expires_at=time.time() + 60)

        _advance(monkeypatch, 600)
        store.revoke("trigger-sweep")
        assert store.is_revoked("jti-twice"), (
            "the 1-hour revocation must survive a later 60-second re-revoke"
        )


class TestReviewRound2TrustedNoExp:
    """#293 review round 2: verify_jwt does not require the exp claim, so a
    SIGNED token without exp verifies - and such a token never expires. Its
    revocation (or refresh consumption) must never be forgotten; None from a
    verified payload means 'no expiry', not 'use the default'."""

    def test_verified_no_exp_revocation_is_indefinite(self, store, monkeypatch):
        store.revoke("jti-eternal", expires_at=None)

        _advance(monkeypatch, 9 * 24 * 3600)
        store.revoke("trigger-sweep")
        assert store.is_revoked("jti-eternal"), (
            "a verified token without exp never expires - its revocation "
            "must survive any sweep"
        )

        _advance(monkeypatch, 10 * 365 * 24 * 3600)
        store.revoke("trigger-sweep-2")
        assert store.is_revoked("jti-eternal")

    def test_verified_no_exp_refresh_claim_is_indefinite(self, store, monkeypatch):
        assert store.check_and_claim_refresh("rt-eternal", "fam-e", True, expires_at=None) is False

        _advance(monkeypatch, 9 * 24 * 3600)
        store.revoke("trigger-sweep")
        assert (
            store.check_and_claim_refresh("rt-eternal", "fam-e", True, expires_at=None) is True
        ), "a consumed no-exp refresh token must stay consumed forever"

    def test_trusted_exp_is_normalized_to_a_number(self, store):
        """PyJWT can hand back an exp it merely coerced for its own check;
        the store normalizes at the boundary so retention math never
        compares mixed types."""
        store.revoke("jti-strexp", expires_at="4102444800")
        assert isinstance(store._revoked_tokens["jti-strexp"], float)
        assert store._revoked_tokens["jti-strexp"] == 4102444800.0
