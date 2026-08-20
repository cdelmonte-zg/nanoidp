"""Tests for per-client color validation."""

import pytest
from pydantic import ValidationError

from nanoidp.models import OAuthClient


class TestClientColorValidation:
    """Test color field validation in OAuthClient."""

    def test_valid_hex_color_background(self):
        """OAuthClient accepts valid hex background_color."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
            background_color="#123456",
        )
        assert client.background_color == "#123456"

    def test_valid_hex_color_header(self):
        """OAuthClient accepts valid hex header_color."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
            header_color="#abcdef",
        )
        assert client.header_color == "#abcdef"

    def test_valid_hex_color_footer(self):
        """OAuthClient accepts valid hex footer_color."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
            footer_color="#AABBCC",
        )
        assert client.footer_color == "#AABBCC"

    def test_color_none_is_valid(self):
        """OAuthClient accepts None for color fields (optional)."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
            background_color=None,
            header_color=None,
            footer_color=None,
        )
        assert client.background_color is None
        assert client.header_color is None
        assert client.footer_color is None

    def test_color_defaults_to_none(self):
        """OAuthClient color fields default to None."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
        )
        assert client.background_color is None
        assert client.header_color is None
        assert client.footer_color is None

    def test_invalid_hex_color_missing_hash(self):
        """OAuthClient rejects hex color without # prefix."""
        with pytest.raises(ValidationError):
            OAuthClient(
                client_id="test-client",
                client_secret="secret",
                background_color="123456",
            )

    def test_invalid_hex_color_wrong_length(self):
        """OAuthClient rejects hex color with wrong length."""
        with pytest.raises(ValidationError):
            OAuthClient(
                client_id="test-client",
                client_secret="secret",
                header_color="#12345",
            )

    def test_invalid_hex_color_non_hex_chars(self):
        """OAuthClient rejects hex color with non-hex characters."""
        with pytest.raises(ValidationError):
            OAuthClient(
                client_id="test-client",
                client_secret="secret",
                footer_color="#GGGGGG",
            )

    def test_color_validation_enforced_on_assignment(self):
        """OAuthClient enforces color validation on attribute assignment."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
        )

        with pytest.raises(ValidationError):
            client.background_color = "#invalid"

    def test_valid_color_assignment(self):
        """OAuthClient accepts valid color on attribute assignment."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
        )

        client.background_color = "#ff0000"
        assert client.background_color == "#ff0000"

    def test_show_client_id_defaults_true(self):
        """OAuthClient.show_client_id defaults to True."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
        )
        assert client.show_client_id is True

    def test_show_description_defaults_false(self):
        """OAuthClient.show_description defaults to False."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
        )
        assert client.show_description is False

    def test_show_client_id_explicit_false(self):
        """OAuthClient accepts show_client_id=False."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
            show_client_id=False,
        )
        assert client.show_client_id is False

    def test_show_description_explicit_true(self):
        """OAuthClient accepts show_description=True."""
        client = OAuthClient(
            client_id="test-client",
            client_secret="secret",
            show_description=True,
        )
        assert client.show_description is True
