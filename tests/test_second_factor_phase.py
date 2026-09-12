"""Direct unit coverage for the declarative TOTP second-factor phase
(#348) - the single home every interactive-login surface (/login,
/authorize, /saml/sso, /device) calls into after a successful password
check, exactly the way test_two_step_phase.py covers two_step_phase."""

import base64

from nanoidp.models import User
from nanoidp.routes._auth import (
    AuthMethod,
    SecondFactorPhase,
    authenticate_interactively,
    second_factor_phase,
)
from nanoidp.services.totp import generate_totp

_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


def _user_with_secret(secret=_SECRET) -> User:
    return User(username="alice", password="alice-pw", totp_secret=secret)


def _user_without_secret() -> User:
    return User(username="bob", password="bob-pw")


class TestSecondFactorPhase:
    def test_totp_inactive_is_always_not_required(self):
        assert (
            second_factor_phase(
                totp_active=False, user=_user_with_secret(), code_submitted=False, code=""
            )
            is SecondFactorPhase.NOT_REQUIRED
        )

    def test_no_user_is_not_required(self):
        """A failed password check never reaches here in practice
        (authenticate_interactively short-circuits first), but the
        function itself must not explode on a None user."""
        assert (
            second_factor_phase(totp_active=True, user=None, code_submitted=False, code="")
            is SecondFactorPhase.NOT_REQUIRED
        )

    def test_user_without_secret_is_not_required(self):
        assert (
            second_factor_phase(
                totp_active=True, user=_user_without_secret(), code_submitted=False, code=""
            )
            is SecondFactorPhase.NOT_REQUIRED
        )

    def test_user_with_secret_and_nothing_submitted_is_code_step(self):
        assert (
            second_factor_phase(
                totp_active=True, user=_user_with_secret(), code_submitted=False, code=""
            )
            is SecondFactorPhase.CODE_STEP
        )

    def test_blank_code_resubmission_is_code_required(self):
        assert (
            second_factor_phase(
                totp_active=True, user=_user_with_secret(), code_submitted=True, code=""
            )
            is SecondFactorPhase.CODE_REQUIRED
        )

    def test_wrong_code_is_code_invalid(self):
        assert (
            second_factor_phase(
                totp_active=True, user=_user_with_secret(), code_submitted=True, code="000000"
            )
            is SecondFactorPhase.CODE_INVALID
        )

    def test_valid_code_is_verified(self):
        code = generate_totp(_SECRET)
        assert (
            second_factor_phase(
                totp_active=True, user=_user_with_secret(), code_submitted=True, code=code
            )
            is SecondFactorPhase.VERIFIED
        )


class TestAuthenticateInteractively:
    """authenticate_interactively reads ``totp_code`` from the request form
    itself, so each case runs inside a test request context carrying the
    form it would see."""

    def _config(self, tmp_path, *, totp=False, mode="password", two_step=False):
        from nanoidp.config import ConfigManager

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "settings.yaml").write_text(
            'oauth:\n  issuer: "http://localhost:8000"\n'
            "login:\n"
            f"  mode: {mode}\n"
            f"  totp: {str(totp).lower()}\n"
            f"  two_step: {str(two_step).lower()}\n"
        )
        (config_dir / "users.yaml").write_text(
            "users:\n"
            "  alice:\n"
            '    password: "alice-pw"\n'
            f'    totp_secret: "{_SECRET}"\n'
            "  bob:\n"
            '    password: "bob-pw"\n'
            "default_user: alice\n"
        )
        return ConfigManager(str(config_dir))

    def _login(self, app, config, username, password, form=None):
        with app.test_request_context("/login", method="POST", data=form or {}):
            return authenticate_interactively(config, username=username, password=password)

    def test_wrong_password_returns_no_user(self, app, tmp_path):
        config = self._config(tmp_path, totp=True)
        login = self._login(app, config, "alice", "wrong")
        assert login.user is None
        assert login.phase is SecondFactorPhase.NOT_REQUIRED
        assert not login.phase.pending
        assert login.amr is None

    def test_totp_inactive_completes_without_a_code_and_claims_no_amr(self, app, tmp_path):
        """Off by default means off on the wire too: no amr claim appears
        in a deployment that never turned login.totp on (review of #348)."""
        config = self._config(tmp_path, totp=False)
        login = self._login(app, config, "alice", "alice-pw")
        assert login.user is not None
        assert login.phase is SecondFactorPhase.NOT_REQUIRED
        assert login.method is AuthMethod.PASSWORD
        assert login.amr is None

    def test_user_without_secret_completes_with_pwd_amr(self, app, tmp_path):
        config = self._config(tmp_path, totp=True)
        login = self._login(app, config, "bob", "bob-pw")
        assert login.user is not None
        assert login.phase is SecondFactorPhase.NOT_REQUIRED
        assert login.method is AuthMethod.PASSWORD
        assert login.amr == ("pwd",)

    def test_user_with_secret_is_pending_with_no_user(self, app, tmp_path):
        """Fail closed: while the code screen is pending, ``user`` is None,
        so a surface that only checks ``if login.user`` cannot complete the
        login without a code (review of #348)."""
        config = self._config(tmp_path, totp=True)
        login = self._login(app, config, "alice", "alice-pw")
        assert login.user is None
        assert login.phase is SecondFactorPhase.CODE_STEP
        assert login.phase.pending
        assert login.phase.error is None

    def test_blank_and_wrong_codes_carry_their_messages(self, app, tmp_path):
        config = self._config(tmp_path, totp=True)
        blank = self._login(app, config, "alice", "alice-pw", {"totp_code": ""})
        wrong = self._login(app, config, "alice", "alice-pw", {"totp_code": "000000"})
        assert blank.phase is SecondFactorPhase.CODE_REQUIRED
        assert blank.phase.error == "Code is required"
        assert wrong.phase is SecondFactorPhase.CODE_INVALID
        assert wrong.phase.error == "Invalid code"
        assert blank.user is None and wrong.user is None

    def test_valid_code_completes_as_password_otp(self, app, tmp_path):
        config = self._config(tmp_path, totp=True)
        login = self._login(app, config, "alice", "alice-pw", {"totp_code": generate_totp(_SECRET)})
        assert login.user is not None
        assert login.phase is SecondFactorPhase.VERIFIED
        assert login.method is AuthMethod.PASSWORD_OTP
        assert login.amr == ("pwd", "otp")

    def test_persona_mode_is_inert_even_with_a_secret(self, app, tmp_path):
        """#348: persona login checks no password at all, so the second
        factor never engages - inert, same composition as two_step - and
        no amr is claimed for a check that never happened."""
        config = self._config(tmp_path, totp=True, mode="persona")
        login = self._login(app, config, "alice", "")
        assert login.user is not None
        assert login.phase is SecondFactorPhase.NOT_REQUIRED
        assert login.method is AuthMethod.PERSONA
        assert login.amr is None
