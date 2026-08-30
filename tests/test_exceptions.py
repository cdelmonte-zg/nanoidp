"""
Tests for the one exception nanoidp actually raises (#287).

The 20-class hierarchy this file used to exercise was removed: only
SAMLSignatureError was ever raised or caught in the codebase (the tests here
were the hierarchy's sole consumer). Errors are shaped per surface instead -
see CONTRIBUTING, "Error surfaces".
"""

import pytest

from nanoidp.exceptions import SAMLSignatureError


class TestSAMLSignatureError:
    def test_default_message(self):
        exc = SAMLSignatureError()
        assert str(exc) == "SAML signature validation failed"
        assert exc.message == "SAML signature validation failed"

    def test_custom_message(self):
        exc = SAMLSignatureError("bad digest")
        assert str(exc) == "bad digest"

    def test_is_a_plain_exception(self):
        """No hidden hierarchy: catching Exception is enough, and there is
        no removed base class to accidentally depend on."""
        assert SAMLSignatureError.__mro__[1] is Exception

    def test_raisable_and_catchable(self):
        with pytest.raises(SAMLSignatureError, match="bad digest"):
            raise SAMLSignatureError("bad digest")
