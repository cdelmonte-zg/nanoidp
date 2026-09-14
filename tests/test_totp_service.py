"""
Tests for the stdlib TOTP verification service (#348).

RFC 6238 Appendix B publishes SHA-1 test vectors for the 20-byte ASCII
secret "12345678901234567890" (encoded here as Base32, since that is the
form ``totp_secret`` takes). Appendix B's codes are 8 digits; this project
uses 6-digit codes (the authenticator-app default), so the vectors are
compared on their last 6 digits, which is what the same HOTP truncation
yields at 6 digits.
"""

import base64

import pytest

from nanoidp.services.totp import generate_totp, verify_totp
from nanoidp.totp_secret import canonical_secret, normalize_secret

# RFC 6238 Appendix B secret, Base32-encoded so it round-trips through
# normalize_secret exactly as a users.yaml totp_secret would.
_RFC_SECRET_B32 = base64.b32encode(b"12345678901234567890").decode("ascii")

# (unix time, expected 8-digit code) from RFC 6238 Appendix B, SHA-1 column.
_RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
]


class TestCanonicalSecret:
    def test_upper_case_unpadded_is_the_one_spelling(self):
        assert canonical_secret("jbsw y3dp ehpk 3pxp") == "JBSWY3DPEHPK3PXP"
        assert canonical_secret("JBSWY3D=") == "JBSWY3D"

    def test_invalid_base32_is_rejected_without_echoing_the_value(self):
        with pytest.raises(ValueError) as excinfo:
            canonical_secret("not-valid-base32!!!")
        assert "not-valid-base32" not in str(excinfo.value)

    def test_empty_is_rejected(self):
        with pytest.raises(ValueError):
            canonical_secret("   ")


class TestNormalizeSecret:
    def test_upper_case_round_trips(self):
        assert normalize_secret("JBSWY3DPEHPK3PXP") == normalize_secret("jbswy3dpehpk3pxp")

    def test_spaces_are_tolerated(self):
        assert normalize_secret("JBSW Y3DP EHPK 3PXP") == normalize_secret("JBSWY3DPEHPK3PXP")

    def test_missing_padding_is_tolerated(self):
        assert normalize_secret("JBSWY3D") == normalize_secret("JBSWY3D=")

    def test_invalid_base32_is_rejected(self):
        with pytest.raises(ValueError):
            normalize_secret("not-valid-base32!!!")


class TestRfc6238Vectors:
    @pytest.mark.parametrize("unix_time,expected_8digit", _RFC_VECTORS)
    def test_known_vector_last_six_digits(self, unix_time, expected_8digit):
        assert generate_totp(_RFC_SECRET_B32, at=unix_time) == expected_8digit[-6:]

    @pytest.mark.parametrize("unix_time,expected_8digit", _RFC_VECTORS)
    def test_verify_accepts_known_vector(self, unix_time, expected_8digit):
        assert verify_totp(_RFC_SECRET_B32, expected_8digit[-6:], at=unix_time)


class TestSkewBoundary:
    def test_one_step_before_is_accepted(self):
        at = 1_700_000_000
        assert verify_totp(_RFC_SECRET_B32, generate_totp(_RFC_SECRET_B32, at=at - 30), at=at)

    def test_one_step_after_is_accepted(self):
        at = 1_700_000_000
        assert verify_totp(_RFC_SECRET_B32, generate_totp(_RFC_SECRET_B32, at=at + 30), at=at)

    def test_two_steps_before_is_rejected(self):
        at = 1_700_000_000
        assert not verify_totp(_RFC_SECRET_B32, generate_totp(_RFC_SECRET_B32, at=at - 60), at=at)

    def test_two_steps_after_is_rejected(self):
        at = 1_700_000_000
        assert not verify_totp(_RFC_SECRET_B32, generate_totp(_RFC_SECRET_B32, at=at + 60), at=at)

    def test_same_step_replays_without_a_replay_guard(self):
        # Documented out-of-scope behavior (#348): no replay memory.
        at = 1_700_000_000
        code = generate_totp(_RFC_SECRET_B32, at=at)
        assert verify_totp(_RFC_SECRET_B32, code, at=at)
        assert verify_totp(_RFC_SECRET_B32, code, at=at)

    def test_first_step_of_the_epoch_does_not_raise(self):
        # counter - 1 would be negative here; the step is skipped, not
        # packed into struct.pack(">Q") (review of #348).
        code = generate_totp(_RFC_SECRET_B32, at=5)
        assert verify_totp(_RFC_SECRET_B32, code, at=5)
        verify_totp(_RFC_SECRET_B32, "000000", at=5)  # must return, not raise


class TestRejectedCodes:
    def test_wrong_code_is_rejected(self):
        at = 1_700_000_000
        code = generate_totp(_RFC_SECRET_B32, at=at)
        wrong = "000000" if code != "000000" else "111111"
        assert not verify_totp(_RFC_SECRET_B32, wrong, at=at)

    def test_blank_code_is_rejected(self):
        assert not verify_totp(_RFC_SECRET_B32, "", at=1_700_000_000)

    def test_letters_are_rejected(self):
        assert not verify_totp(_RFC_SECRET_B32, "abcdef", at=1_700_000_000)

    def test_seven_digits_is_rejected(self):
        at = 1_700_000_000
        assert not verify_totp(_RFC_SECRET_B32, generate_totp(_RFC_SECRET_B32, at=at) + "1", at=at)

    def test_invalid_secret_is_rejected_not_raised(self):
        assert not verify_totp("not-valid-base32!!!", "123456", at=1_700_000_000)

    def test_fullwidth_digits_are_rejected_not_raised(self):
        # str.isdigit() is True for fullwidth digits too, but they are not
        # ASCII, and hmac.compare_digest raises TypeError on a non-ASCII
        # str - the code screen must return False here, not 500 (#348
        # review, blocking 1).
        at = 1_700_000_000
        code = generate_totp(_RFC_SECRET_B32, at=at)
        fullwidth = code.translate(str.maketrans("0123456789", "０１２３４５６７８９"))
        assert fullwidth.isdigit()
        assert not fullwidth.isascii()
        assert not verify_totp(_RFC_SECRET_B32, fullwidth, at=at)


class TestSecretSpellingEquivalence:
    def test_lower_case_and_spaced_secrets_produce_the_same_code(self):
        at = 1_700_000_000
        spaced = " ".join(_RFC_SECRET_B32[i : i + 4] for i in range(0, len(_RFC_SECRET_B32), 4))
        assert (
            generate_totp(_RFC_SECRET_B32, at=at)
            == generate_totp(_RFC_SECRET_B32.lower(), at=at)
            == generate_totp(spaced, at=at)
        )
