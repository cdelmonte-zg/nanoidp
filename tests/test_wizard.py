"""
Tests for the interactive configuration wizard (issue #72 - it was the only
module with zero coverage, capping the CI threshold).

The wizard is driven by monkeypatching ``builtins.input`` (and
``getpass.getpass`` for the password helper); the acceptance criterion is
that a wizard-generated configuration round-trips through ``ConfigManager``.
"""

import pytest

from nanoidp import wizard
from nanoidp.config import ConfigManager


@pytest.fixture
def feed(monkeypatch):
    """Feed scripted answers to input(); fails loudly if the wizard asks more
    questions than the script expects."""

    def _feed(answers):
        it = iter(answers)

        def fake_input(prompt: str = "") -> str:
            try:
                return next(it)
            except StopIteration:  # pragma: no cover - test authoring error
                raise AssertionError(f"unexpected extra prompt: {prompt!r}") from None

        monkeypatch.setattr("builtins.input", fake_input)

    return _feed


def _default_answers(config_path: str) -> list:
    """One answer per wizard prompt, accepting every default."""
    return [
        "",  # Continue with setup? -> yes
        "",  # Host
        "",  # Port
        "",  # Issuer
        "",  # Audience
        "",  # Client ID
        "",  # Client Secret
        "",  # Description
        "",  # Username
        "",  # Password
        "",  # Email
        "",  # Token expiry
        config_path,  # Config directory
        "",  # Create this configuration? -> yes
    ]


class TestWizardHappyPath:
    def test_defaults_produce_a_loadable_config(self, tmp_path, feed):
        config_dir = str(tmp_path / "wizard-config")
        feed(_default_answers(config_dir))

        assert wizard.run_wizard() is True

        # Round-trip: everything the wizard wrote loads through ConfigManager
        manager = ConfigManager(config_dir)
        assert manager.settings.issuer == "http://localhost:8000"
        assert manager.settings.audience == "my-app"
        assert manager.settings.token_expiry_minutes == 60
        client = manager.get_client("demo-client")
        assert client is not None and client.client_secret == "demo-secret"
        assert manager.authenticate("admin", "admin") is not None
        assert manager.default_user == "admin"
        assert (tmp_path / "wizard-config" / "keys").is_dir()

    def test_custom_answers_land_in_the_config(self, tmp_path, feed):
        config_dir = str(tmp_path / "custom")
        feed([
            "y",  # continue
            "127.0.0.1",  # host
            "9000",  # port
            "",  # issuer -> default derived from port
            "custom-app",  # audience
            "my-client",  # client id
            "s3cret",  # client secret
            "My client",  # description
            "alice",  # username
            "wonder",  # password
            "",  # email -> default alice@example.org
            "120",  # token expiry
            config_dir,
            "yes",  # create
        ])

        assert wizard.run_wizard() is True

        manager = ConfigManager(config_dir)
        assert manager.settings.host == "127.0.0.1"
        assert manager.settings.port == 9000
        assert manager.settings.issuer == "http://localhost:9000"
        assert manager.settings.audience == "custom-app"
        assert manager.settings.token_expiry_minutes == 120
        assert manager.get_client("my-client").description == "My client"
        assert manager.authenticate("alice", "wonder") is not None
        user = manager.get_user("alice")
        assert user.email == "alice@example.org"


class TestWizardCancellation:
    def test_cancel_at_welcome(self, tmp_path, feed):
        feed(["n"])
        assert wizard.run_wizard(str(tmp_path / "never")) is False
        assert not (tmp_path / "never").exists()

    def test_cancel_at_summary(self, tmp_path, feed):
        config_dir = str(tmp_path / "never")
        answers = _default_answers(config_dir)
        answers[-1] = "no"  # refuse the summary confirmation
        feed(answers)
        assert wizard.run_wizard() is False
        assert not (tmp_path / "never").exists()

    def test_create_failure_reports_false(self, tmp_path, feed, monkeypatch):
        feed(_default_answers(str(tmp_path / "boom")))
        monkeypatch.setattr(
            wizard, "_create_config", lambda **kw: (_ for _ in ()).throw(OSError("disk full"))
        )
        assert wizard.run_wizard() is False


class TestPromptHelpers:
    def test_confirm_reprompts_until_valid(self, feed):
        feed(["maybe", "definitely", "Y"])
        assert wizard._confirm("Proceed?") is True

    def test_confirm_accepts_no(self, feed):
        feed(["N"])
        assert wizard._confirm("Proceed?") is False

    def test_prompt_returns_default_on_empty(self, feed):
        feed([""])
        assert wizard._prompt("Value", "fallback") == "fallback"

    def test_prompt_strips_and_overrides_default(self, feed):
        feed(["  chosen  "])
        assert wizard._prompt("Value", "fallback") == "chosen"

    def test_prompt_password_uses_getpass(self, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "hidden")
        assert wizard._prompt_password("Password") == "hidden"

    def test_prompt_password_default_on_empty(self, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
        assert wizard._prompt_password("Password", "dflt") == "dflt"

    def test_prompt_password_falls_back_when_getpass_unavailable(
        self, monkeypatch, feed
    ):
        def broken(prompt: str = ""):
            raise OSError("no tty")

        monkeypatch.setattr("getpass.getpass", broken)
        feed(["visible"])
        assert wizard._prompt_password("Password") == "visible"


class TestValidateAndWrite:
    """#282: the wizard used to write raw f-strings with open() - no
    validation, no atomicity. _validate_and_write validates through the
    document models BEFORE anything touches disk and then writes through
    the shared temp-then-replace primitive."""

    def test_valid_settings_template_lands_and_loads(self, tmp_path):
        from nanoidp.wizard import _validate_and_write

        text = 'config_version: 1\noauth:\n  issuer: "http://localhost:1234"\n'
        target = tmp_path / "settings.yaml"
        _validate_and_write(str(target), text, kind="settings")
        # Byte-exact: no re-serialization of the template.
        assert target.read_text() == text

    def test_invalid_template_raises_and_writes_nothing(self, tmp_path):
        import pydantic
        import pytest as _pytest

        from nanoidp.wizard import _validate_and_write

        target = tmp_path / "settings.yaml"
        with _pytest.raises(pydantic.ValidationError):
            _validate_and_write(
                str(target), "config_version: 1\noauth: not-a-mapping\n", kind="settings"
            )
        assert not target.exists()

    def test_invalid_users_template_raises(self, tmp_path):
        import pydantic
        import pytest as _pytest

        from nanoidp.wizard import _validate_and_write

        target = tmp_path / "users.yaml"
        with _pytest.raises(pydantic.ValidationError):
            _validate_and_write(
                str(target), "config_version: 1\nusers: not-a-mapping\n", kind="users"
            )
        assert not target.exists()
