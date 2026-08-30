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
from nanoidp.services.revocation import _MAX_RETENTION_SECONDS, RevocationStore


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

        _advance(monkeypatch, _MAX_RETENTION_SECONDS + 60)
        store.revoke("other")
        assert not store.is_revoked("jti-noexp")

    def test_attacker_supplied_far_future_exp_is_capped(self, store):
        """/logout decodes id_token_hint UNVERIFIED: a forged exp must not
        pin memory forever."""
        store.revoke("jti-forged", expires_at=time.time() + 10 * 365 * 24 * 3600)
        assert store._revoked_tokens["jti-forged"] <= time.time() + _MAX_RETENTION_SECONDS + 1

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
