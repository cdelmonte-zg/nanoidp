"""
A rejected configuration value never echoes a secret (#352).

pydantic renders ``input_value=<the value>`` into a ValidationError unless
the model that runs the validation sets ``hide_input_in_errors``. The loader
raises its own message ``from`` that error, so the value reaches every place
that prints the chained traceback: the startup output, the server log on
``POST /api/config/reload`` and the MCP server log on ``reload_config``. A
validator that rejects a secret on its content (the printable-ASCII rule on
``management_secret``) also puts it into the message that
``nanoidp validate-config`` and the MCP ``validate_config`` tool report.

The flag is honoured on the outermost model of a validation, so it sits on
the three document roots and on the domain models built from them
(``Settings``, ``OAuthClient``, ``User``); these tests pin the value's
absence on every rendering, not the flag itself.
"""

import json
import traceback
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from nanoidp.config import ConfigManager
from nanoidp.config_validation import validate_config_dir, validate_config_result
from nanoidp.models import OAuthClient, Settings, User

GOOD_SETTINGS = {
    "oauth": {
        "issuer": "http://localhost:8000",
        "clients": [{"client_id": "demo", "client_secret": "demo-secret"}],
    },
}
GOOD_USERS = {"users": {"alice": {"password": "x"}}}


def _write(directory: Path, settings, users, bootstrap=None) -> str:
    (directory / "settings.yaml").write_text(yaml.safe_dump(settings))
    (directory / "users.yaml").write_text(yaml.safe_dump(users))
    if bootstrap is not None:
        (directory / "bootstrap.yaml").write_text(yaml.safe_dump(bootstrap))
    return str(directory)


def _rendered(exc: BaseException) -> str:
    """Everything a traceback printer shows, the chained causes included."""
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def _leaks(secret: str, text: str) -> bool:
    """pydantic shortens a long input to ``'tok-...CRET-123'``, so the whole
    secret can be absent while most of it is printed: check its tail too."""
    return secret in text or secret[-8:] in text


# (id, settings document, users document, the secret that must not appear)
CASES = [
    (
        "numeric client_secret",
        {"oauth": {**GOOD_SETTINGS["oauth"], "clients": [{"client_id": "demo", "client_secret": 55512345678}]}},
        GOOD_USERS,
        "55512345678",
    ),
    (
        "numeric session.secret_key",
        {**GOOD_SETTINGS, "session": {"secret_key": 44412345678}},
        GOOD_USERS,
        "44412345678",
    ),
    (
        "numeric session.management_secret",
        {**GOOD_SETTINGS, "session": {"management_secret": 33312345678}},
        GOOD_USERS,
        "33312345678",
    ),
    (
        "non-ASCII session.management_secret",
        {**GOOD_SETTINGS, "session": {"management_secret": "pässwörd-geheim-42"}},
        GOOD_USERS,
        "pässwörd-geheim-42",
    ),
    (
        "plugin settings next to a malformed plugin entry",
        {**GOOD_SETTINGS, "plugins": {"vault": {"token": "tok-SECRET-123"}, "broken": 5}},
        GOOD_USERS,
        "tok-SECRET-123",
    ),
    # users.yaml, closed by #350; kept here so the two files share one guard.
    (
        "numeric users[].password",
        GOOD_SETTINGS,
        {"users": {"alice": {"password": 98765432123}}},
        "98765432123",
    ),
    (
        "numeric users[].totp_secret",
        GOOD_SETTINGS,
        {"users": {"alice": {"password": "x", "totp_secret": 2345672345672345}}},
        "2345672345672345",
    ),
    (
        "invalid users[].totp_secret",
        GOOD_SETTINGS,
        {"users": {"alice": {"password": "x", "totp_secret": "JBSWY3DPEHPK3PX1"}}},
        "JBSWY3DPEHPK3PX1",
    ),
]


@pytest.mark.parametrize(
    "settings, users, secret", [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
class TestLoaderNeverEchoesASecret:
    def test_startup(self, tmp_path, settings, users, secret):
        config_dir = _write(tmp_path, settings, users)
        with pytest.raises((ValueError, ValidationError)) as exc:
            ConfigManager(config_dir)
        assert not _leaks(secret, _rendered(exc.value))

    def test_reload(self, tmp_path, settings, users, secret):
        config_dir = _write(tmp_path, GOOD_SETTINGS, GOOD_USERS)
        manager = ConfigManager(config_dir)
        _write(tmp_path, settings, users)
        with pytest.raises((ValueError, ValidationError)) as exc:
            manager.reload()
        assert not _leaks(secret, _rendered(exc.value))
        # The previous configuration stays in service.
        assert manager.get_user("alice") is not None

    def test_validate_config(self, tmp_path, settings, users, secret):
        config_dir = _write(tmp_path, settings, users)
        findings = validate_config_dir(config_dir)
        assert any(f.level == "error" for f in findings)
        assert not _leaks(secret, json.dumps(validate_config_result(config_dir), ensure_ascii=False))
        assert not any(_leaks(secret, f.message) for f in findings)


class TestDomainModelsNeverEchoASecret:
    """The models the UI and the MCP tools build directly, outside the loader."""

    def test_oauth_client(self):
        with pytest.raises(ValidationError) as exc:
            OAuthClient(client_id="c", client_secret=55512345678)
        assert not _leaks("55512345678", str(exc.value))

    def test_settings_management_secret(self):
        with pytest.raises(ValidationError) as exc:
            Settings(management_secret="pässwörd-geheim-42")
        assert not _leaks("pässwörd-geheim-42", str(exc.value))

    def test_user_password(self):
        with pytest.raises(ValidationError) as exc:
            User(username="u", password=98765432123)
        assert not _leaks("98765432123", str(exc.value))

    def test_the_error_still_names_the_field(self):
        """Hiding the input must not hide where the problem is."""
        with pytest.raises(ValidationError) as exc:
            OAuthClient(client_id="c", client_secret=55512345678)
        assert "client_secret" in str(exc.value)


def test_bootstrap_plugin_settings_are_not_echoed(tmp_path):
    """bootstrap.yaml carries the same plugins mapping; its root hides input too."""
    bootstrap = {"plugins": {"vault": {"token": "tok-SECRET-123"}, "broken": 5}}
    config_dir = _write(tmp_path, GOOD_SETTINGS, GOOD_USERS, bootstrap)
    findings = validate_config_dir(config_dir)
    assert any(f.level == "error" for f in findings)
    assert not _leaks("tok-SECRET-123", json.dumps(validate_config_result(config_dir), ensure_ascii=False))
    with pytest.raises(Exception) as exc:
        ConfigManager(config_dir)
    assert not _leaks("tok-SECRET-123", _rendered(exc.value))
