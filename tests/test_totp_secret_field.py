"""
Tests for the per-user 'totp_secret' field (#348).

The presence of a secret is the enrolment - there is no separate 'enabled'
flag. Validation ("Base32 or rejected", "a factor has to follow a
password") lives on the ``User`` model, the one home every constructor -
YAML load, the users form, MCP create_user/update_user - shares. The
secret is YAML-only: written directly in users.yaml, never accepted or
returned by any other surface (structural parity is
tests/test_user_field_parity.py; this file covers the behavior).
"""

import base64

import pytest
import yaml
from pydantic import ValidationError

from nanoidp.config import ConfigManager
from nanoidp.models import User


def _write_config(tmp_path, users_yaml: str):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "settings.yaml").write_text(
        'oauth:\n  issuer: "http://localhost:8000"\n'
    )
    (config_dir / "users.yaml").write_text(users_yaml)
    return config_dir


_VALID_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


class TestModelValidation:
    def test_valid_base32_secret_is_normalized(self):
        user = User(username="alice", password="pw", totp_secret=_VALID_SECRET.lower())
        assert user.totp_secret == _VALID_SECRET

    def test_invalid_base32_secret_is_rejected(self):
        with pytest.raises(ValidationError, match="not valid Base32"):
            User(username="alice", password="pw", totp_secret="not-base32!!!")

    def test_secret_without_password_is_rejected(self):
        with pytest.raises(ValidationError, match="requires a password"):
            User(username="alice", totp_secret=_VALID_SECRET)

    def test_no_secret_and_no_password_is_fine(self):
        # A persona-only user with no second factor - unaffected by #348.
        user = User(username="alice")
        assert user.totp_secret is None

    def test_empty_string_secret_is_rejected(self):
        # Not treated as absent (#348 review, blocking 2): an unset
        # ${VAR} placeholder expands to "", and silently mapping that to
        # None would disable the factor with no error - see
        # TestYamlLoadAndEnvVarExpansion.test_unset_env_var_secret_fails_to_load
        # for the placeholder form of this same case.
        with pytest.raises(ValidationError, match="must not be empty"):
            User(username="alice", password="pw", totp_secret="")


class TestYamlLoadAndEnvVarExpansion:
    def test_secret_loads_from_users_yaml(self, tmp_path):
        config_dir = _write_config(
            tmp_path,
            "users:\n"
            "  alice:\n"
            '    password: "alice-pw"\n'
            f'    totp_secret: "{_VALID_SECRET}"\n'
            "default_user: alice\n",
        )
        config = ConfigManager(str(config_dir))
        assert config.get_user("alice").totp_secret == _VALID_SECRET

    def test_secret_expands_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALICE_TOTP_SECRET", _VALID_SECRET)
        config_dir = _write_config(
            tmp_path,
            "users:\n"
            "  alice:\n"
            '    password: "alice-pw"\n'
            '    totp_secret: "${ALICE_TOTP_SECRET}"\n'
            "default_user: alice\n",
        )
        config = ConfigManager(str(config_dir))
        assert config.get_user("alice").totp_secret == _VALID_SECRET

    def test_unset_env_var_secret_fails_to_load(self, tmp_path, monkeypatch):
        """An unset ${VAR} placeholder expands to "" (serialization.
        expand_env_vars), which must fail to load exactly like the same
        mistake on 'password' already does (#348 review, blocking 2) - not
        silently disable the factor with alice logging in on the password
        alone."""
        monkeypatch.delenv("ALICE_TOTP_SECRET", raising=False)
        config_dir = _write_config(
            tmp_path,
            "users:\n"
            "  alice:\n"
            '    password: "alice-pw"\n'
            '    totp_secret: "${ALICE_TOTP_SECRET}"\n'
            "default_user: alice\n",
        )
        with pytest.raises(Exception, match="must not be empty"):
            ConfigManager(str(config_dir))

    def test_user_without_secret_is_unaffected(self, tmp_path):
        config_dir = _write_config(
            tmp_path,
            "users:\n"
            "  bob:\n"
            '    password: "bob-pw"\n'
            "default_user: bob\n",
        )
        config = ConfigManager(str(config_dir))
        assert config.get_user("bob").totp_secret is None

    def test_invalid_secret_in_yaml_fails_to_load(self, tmp_path):
        config_dir = _write_config(
            tmp_path,
            "users:\n"
            "  alice:\n"
            '    password: "alice-pw"\n'
            '    totp_secret: "not-base32!!!"\n'
            "default_user: alice\n",
        )
        with pytest.raises(Exception, match="not valid Base32"):
            ConfigManager(str(config_dir))


class TestYamlRoundTrip:
    def test_user_to_yaml_writes_secret_when_set(self):
        from nanoidp.serialization import user_to_yaml

        user = User(username="alice", password="pw", totp_secret=_VALID_SECRET)
        entry = user_to_yaml(user)
        assert entry["totp_secret"].strip('"') == _VALID_SECRET

    def test_user_to_yaml_omits_secret_when_absent(self):
        from nanoidp.serialization import user_to_yaml

        user = User(username="alice", password="pw")
        entry = user_to_yaml(user)
        assert "totp_secret" not in entry

    def test_save_user_round_trips_through_yaml_writer(self, tmp_path):
        config_dir = _write_config(
            tmp_path,
            "users:\n"
            "  bob:\n"
            '    password: "bob-pw"\n'
            "default_user: bob\n",
        )
        from nanoidp.services.yaml_writer import YamlWriter

        writer = YamlWriter(str(config_dir))
        writer.save_user(
            User(username="alice", password="alice-pw", totp_secret=_VALID_SECRET),
            is_new=True,
        )
        with open(config_dir / "users.yaml") as f:
            doc = yaml.safe_load(f)
        assert doc["users"]["alice"]["totp_secret"] == _VALID_SECRET


class TestExclusionFromReadSurfaces:
    def test_to_dict_omits_secret(self):
        user = User(username="alice", password="pw", totp_secret=_VALID_SECRET)
        assert "totp_secret" not in user.to_dict()

    def test_api_users_detail_omits_secret(self, client, app):
        with app.app_context():
            from nanoidp.config import get_config

            config = get_config()
            config.users["alice"] = User(
                username="alice", password="pw", totp_secret=_VALID_SECRET
            )

        resp = client.get("/api/users/alice")
        assert resp.status_code == 200
        assert "totp_secret" not in resp.get_json()

    @pytest.mark.asyncio
    async def test_mcp_get_user_omits_secret(self, app):
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        with app.app_context():
            config = get_config()
            config.users["alice"] = User(
                username="alice", password="pw", totp_secret=_VALID_SECRET
            )
            result = await _execute_tool("get_user", {"username": "alice"}, config)

        assert "totp_secret" not in result["user"]


class TestPreservedOnEdit:
    @pytest.mark.asyncio
    async def test_mcp_update_user_leaves_secret_in_place(self, app):
        """update_user's schema doesn't accept totp_secret at all (#348) -
        the candidate is a deep copy of the live user, so a field never
        touched by the handler survives unless the handler explicitly
        clears it, which it does not."""
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        with app.app_context():
            config = get_config()
            config.users["alice"] = User(
                username="alice", password="pw", totp_secret=_VALID_SECRET
            )
            result = await _execute_tool(
                "update_user", {"username": "alice", "description": "updated"}, config
            )
            assert result["success"] is True
            assert config.users["alice"].totp_secret == _VALID_SECRET

    def test_users_form_edit_leaves_secret_in_place(self, client, app):
        with app.app_context():
            from nanoidp.config import get_config

            config = get_config()
            config.users["alice"] = User(
                username="alice", password="pw", totp_secret=_VALID_SECRET
            )
            from nanoidp.services.yaml_writer import get_yaml_writer

            get_yaml_writer().save_user(config.users["alice"], is_new=True)

        response = client.post(
            "/users/alice/edit",
            data={
                "password": "",
                "description": "edited via the form",
                "email": "",
                "roles": "",
                "groups": "",
                "entitlements": "",
                "source_acl": "",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

        from nanoidp.config import get_config

        with app.app_context():
            get_config().reload()
            assert get_config().get_user("alice").totp_secret == _VALID_SECRET


class TestEnrolledUserPasswordClearance:
    @pytest.mark.asyncio
    async def test_mcp_update_user_cannot_clear_the_password(self, app):
        """Clearing the password of a user whose users.yaml entry carries a
        totp_secret trips the model rule (a factor has to follow a
        password). update_user validates a scratch copy and raises, the
        contract tests/test_mcp.py already pins for every invalid field
        (#244), so the live user is untouched; the secret is YAML-only, so
        the operator's fix is to edit the file."""
        from nanoidp.config import get_config
        from nanoidp.mcp_server import _execute_tool

        with app.app_context():
            config = get_config()
            config.users["alice"] = User(
                username="alice", password="pw", totp_secret=_VALID_SECRET
            )
            with pytest.raises(ValueError, match="totp_secret requires a password"):
                await _execute_tool(
                    "update_user", {"username": "alice", "password": None}, config
                )
            assert config.users["alice"].password == "pw"
