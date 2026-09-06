"""Direct unit coverage for the shared two-step step-detection rule
(#323 review round 2, before-merge 5) - the single home every password-form
surface (/authorize, /login, /saml/sso, /device) now calls into, instead of
each hand-writing its own copy of the same logic."""

from nanoidp.routes._auth import TwoStepPhase, two_step_phase


class TestTwoStepPhase:
    def test_inactive_is_always_attempt(self):
        """Two-step off (or a surface-specific carve-out like device's
        'deny') always authenticates directly - the combined form's
        behavior, unaffected by this function's existence."""
        assert (
            two_step_phase(
                two_step_active=False, username="", password="", password_submitted=False
            )
            is TwoStepPhase.ATTEMPT
        )
        assert (
            two_step_phase(
                two_step_active=False, username="admin", password="admin", password_submitted=True
            )
            is TwoStepPhase.ATTEMPT
        )

    def test_password_present_is_always_attempt(self):
        """#323 review round 1, blocking 1: a request carrying a password
        authenticates directly, whether it's the two-step password screen
        or a combined-form POST skipping straight past the username-only
        step."""
        assert (
            two_step_phase(
                two_step_active=True, username="admin", password="admin", password_submitted=True
            )
            is TwoStepPhase.ATTEMPT
        )

    def test_blank_username_is_required(self):
        assert (
            two_step_phase(
                two_step_active=True, username="", password="", password_submitted=False
            )
            is TwoStepPhase.USERNAME_REQUIRED
        )

    def test_blank_password_resubmission_is_required(self):
        """The password screen (hidden username, empty password field)
        resubmitted with nothing typed - distinct from the silent first
        arrival at that screen."""
        assert (
            two_step_phase(
                two_step_active=True,
                username="admin",
                password="",
                password_submitted=True,
            )
            is TwoStepPhase.PASSWORD_REQUIRED
        )

    def test_username_only_is_the_username_step(self):
        assert (
            two_step_phase(
                two_step_active=True,
                username="admin",
                password="",
                password_submitted=False,
            )
            is TwoStepPhase.USERNAME_STEP
        )

    def test_username_submitted_false_treats_blank_username_as_fresh(self):
        """SAML's exception (#323 review round 2): a request that carries no
        username field at all - a fresh SAMLRequest via GET redirect or POST
        binding - is not the same as one that carries a blank one. Only the
        latter is USERNAME_REQUIRED."""
        assert (
            two_step_phase(
                two_step_active=True,
                username="",
                password="",
                password_submitted=False,
                username_submitted=False,
            )
            is TwoStepPhase.USERNAME_STEP
        )
        assert (
            two_step_phase(
                two_step_active=True,
                username="",
                password="",
                password_submitted=False,
                username_submitted=True,
            )
            is TwoStepPhase.USERNAME_REQUIRED
        )
