"""How a client's method and secret go together (#300).

One rule that four surfaces used to write for themselves - the UI create and
edit forms, MCP create_client and update_client - plus the assignment order
an existing client has to be moved through, which exists because the model
validates on assignment.

What is deliberately absent: the rest of what `is_public` decides. Those are
ten endpoint-specific rules sharing a predicate, and they stay where they
are applied (#300 has the table).
"""

import pytest

from nanoidp.models import OAuthClient
from nanoidp.services.client_policy import (
    UNSET,
    ClientAuthState,
    ClientSecretRequired,
    apply_client_auth,
    resolve_client_auth,
)


class TestWhatGetsPersisted:
    def test_a_public_client_has_no_secret_even_when_one_is_supplied(self):
        """The create form pre-generates one and the browser sends it: a
        dead, ignored value must not reach the file (#188, #254 review)."""
        auth = resolve_client_auth(method="none", secret="generated-by-the-form")

        assert auth == ClientAuthState("none", None)
        assert auth.is_public

    def test_a_public_client_drops_the_secret_it_already_had(self):
        auth = resolve_client_auth(
            method="none", secret=UNSET, current_method="client_secret_basic", current_secret="old"
        )

        assert auth.secret is None

    def test_a_confidential_client_keeps_the_secret_it_is_given(self):
        auth = resolve_client_auth(method="client_secret_post", secret="s3cret")

        assert auth == ClientAuthState("client_secret_post", "s3cret")
        assert not auth.is_public

    @pytest.mark.parametrize("secret", [None, "", UNSET])
    def test_a_confidential_client_without_a_secret_is_refused(self, secret):
        with pytest.raises(ClientSecretRequired):
            resolve_client_auth(method="client_secret_basic", secret=secret)

    def test_an_omitted_method_keeps_the_current_one(self):
        auth = resolve_client_auth(
            secret=UNSET, current_method="client_secret_post", current_secret="kept"
        )

        assert auth == ClientAuthState("client_secret_post", "kept")

    def test_an_omitted_method_on_a_new_client_is_the_default(self):
        auth = resolve_client_auth(secret="s3cret")

        assert auth.method == "client_secret_basic"


class TestNotProvidedIsNotProvidedEmpty:
    """The four callers do not answer this alike, so the service is told
    which question it is being asked."""

    def test_an_omitted_secret_keeps_the_stored_one(self):
        auth = resolve_client_auth(
            method="client_secret_basic",
            secret=UNSET,
            current_method="client_secret_basic",
            current_secret="stored",
        )

        assert auth.secret == "stored"

    def test_an_empty_secret_is_an_attempt_to_clear_it_and_is_refused(self):
        """MCP's `client_secret: ""` on a confidential client."""
        with pytest.raises(ClientSecretRequired):
            resolve_client_auth(
                method="client_secret_basic",
                secret=None,
                current_method="client_secret_basic",
                current_secret="stored",
            )

    def test_an_empty_secret_on_a_public_target_is_simply_none(self):
        auth = resolve_client_auth(
            method="none",
            secret=None,
            current_method="client_secret_basic",
            current_secret="stored",
        )

        assert auth.secret is None


class TestMovingAnExistingClient:
    """``OAuthClient`` validates on assignment, so the order is the rule."""

    def _confidential(self):
        return OAuthClient(client_id="c", client_secret="old", token_endpoint_auth_method="client_secret_basic")

    def _public(self):
        return OAuthClient(client_id="c", token_endpoint_auth_method="none")

    def test_confidential_to_public_ends_with_no_secret(self):
        client = self._confidential()

        apply_client_auth(client, ClientAuthState("none", None))

        assert client.token_endpoint_auth_method == "none"
        assert client.client_secret is None

    def test_public_to_confidential_ends_with_the_new_secret(self):
        client = self._public()

        apply_client_auth(client, ClientAuthState("client_secret_basic", "fresh"))

        assert client.token_endpoint_auth_method == "client_secret_basic"
        assert client.client_secret == "fresh"

    def test_a_confidential_client_can_change_its_secret(self):
        client = self._confidential()

        apply_client_auth(client, ClientAuthState("client_secret_post", "rotated"))

        assert client.token_endpoint_auth_method == "client_secret_post"
        assert client.client_secret == "rotated"

    def test_the_wrong_order_is_what_the_model_refuses(self):
        """Why the helper exists: flipping a public client to confidential
        by setting the method first is refused while it has no secret."""
        client = self._public()

        with pytest.raises(ValueError):
            client.token_endpoint_auth_method = "client_secret_basic"

    def test_nothing_is_half_applied_when_the_state_was_refused(self):
        """The state is resolved before any assignment, so a refusal leaves
        the live client untouched."""
        client = self._confidential()

        with pytest.raises(ClientSecretRequired):
            resolve_client_auth(
                method="client_secret_post",
                secret=None,
                current_method=client.token_endpoint_auth_method,
                current_secret=None,
            )

        assert client.token_endpoint_auth_method == "client_secret_basic"
        assert client.client_secret == "old"
