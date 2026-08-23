"""
#172: the CLI --profile override wins over settings.yaml for every value
(including an explicit "dev"), survives reload(), is never persisted, and the
stricter-dev runtime hardening is re-derived on every reload instead of being
applied once in create_app().
"""

import pytest
import yaml

from nanoidp.config import ConfigManager, get_config, init_config
from nanoidp.models import SECURITY_PROFILES


def _write_config(tmp_path, security_profile=None):
    settings = {"server": {"host": "127.0.0.1", "port": 8000}}
    if security_profile is not None:
        settings["security_profile"] = security_profile
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {}}))
    return str(tmp_path)


class TestProfileOverrideWinsOverYaml:
    @pytest.mark.parametrize("cli_profile", SECURITY_PROFILES)
    @pytest.mark.parametrize("yaml_profile", SECURITY_PROFILES)
    def test_explicit_cli_profile_overrides_any_yaml_value(self, tmp_path, cli_profile, yaml_profile):
        config = ConfigManager(_write_config(tmp_path, yaml_profile), profile_override=cli_profile)
        assert config.settings.security_profile == cli_profile

    def test_explicit_dev_overrides_stricter_yaml(self, tmp_path):
        """The original report: --profile dev could not bring oauth21 back to dev."""
        config = ConfigManager(_write_config(tmp_path, "oauth21"), profile_override="dev")
        assert config.settings.security_profile == "dev"

    @pytest.mark.parametrize("yaml_profile", SECURITY_PROFILES)
    def test_omitted_flag_leaves_yaml_value(self, tmp_path, yaml_profile):
        config = ConfigManager(_write_config(tmp_path, yaml_profile))
        assert config.profile_override is None
        assert config.settings.security_profile == yaml_profile

    def test_invalid_override_rejected_at_construction(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid profile override"):
            ConfigManager(_write_config(tmp_path), profile_override="prod")

    def test_create_app_passes_override_through(self, tmp_path):
        from nanoidp.app import create_app

        create_app(config_dir=_write_config(tmp_path, "oauth21"), profile="dev")
        assert get_config().profile_override == "dev"
        assert get_config().settings.security_profile == "dev"


class TestOverrideSurvivesReload:
    def test_reload_keeps_cli_profile(self, tmp_path):
        config = init_config(_write_config(tmp_path), profile_override="stricter-dev")
        config.reload()
        assert config.settings.security_profile == "stricter-dev"

    def test_yaml_writer_save_keeps_cli_profile(self, tmp_path):
        """dshvedchenko's repro: stricter-dev -> switch login mode in UI -> back to dev."""
        from nanoidp.services.yaml_writer import YamlWriter

        init_config(_write_config(tmp_path), profile_override="stricter-dev")
        YamlWriter(str(tmp_path)).update_login_settings(mode="persona")
        assert get_config().settings.security_profile == "stricter-dev"
        assert get_config().settings.login_mode == "persona"

    def test_override_is_never_persisted(self, tmp_path):
        config = init_config(_write_config(tmp_path), profile_override="oauth21")
        config.save()
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert "security_profile" not in on_disk

    def test_override_preserves_explicit_yaml_profile_on_save(self, tmp_path):
        config = init_config(_write_config(tmp_path, "stricter-dev"), profile_override="dev")
        config.save()
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert on_disk["security_profile"] == "stricter-dev"
        # and the in-memory override still stands after the save's reload
        assert config.settings.security_profile == "dev"

    def test_yaml_profile_is_persisted_normally_without_override(self, tmp_path):
        config = init_config(_write_config(tmp_path))
        config.settings.security_profile = "oauth21"
        config.save()
        on_disk = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert on_disk["security_profile"] == "oauth21"


class TestDerivedHardeningIsNeverPersisted:
    """#172 review: the override's EFFECTS must stay out of the file too.

    Before the fix, --profile stricter-dev never wrote "stricter-dev" but
    save() wrote `oauth.require_pkce: true` (and the other forced fields),
    so the next start without the flag kept PKCE enforced.
    """

    FORCED = ("require_pkce", "password_hashing", "rate_limit_enabled")

    def _on_disk(self, tmp_path):
        return yaml.safe_load((tmp_path / "settings.yaml").read_text())

    def test_cli_stricter_dev_save_writes_neither_profile_nor_effects(self, tmp_path):
        config = init_config(_write_config(tmp_path), profile_override="stricter-dev")
        config.save()
        on_disk = self._on_disk(tmp_path)
        assert "security_profile" not in on_disk
        # The writer materializes managed keys at their DECLARED value (false,
        # the model default here); what must never appear is the forced true.
        flat = yaml.safe_dump(on_disk)
        for field in self.FORCED:
            assert f"{field}: true" not in flat, flat
        assert (on_disk.get("oauth") or {}).get("require_pkce") is not True
        # the effective state is untouched by the save
        assert config.settings.require_pkce is True
        assert config.settings.security_profile == "stricter-dev"

    def test_cli_stricter_dev_save_keeps_explicit_declared_values(self, tmp_path):
        """File says require_pkce: false explicitly; the flag forces True at
        runtime; the save must keep the declared false."""
        settings = {
            "server": {"host": "127.0.0.1", "port": 8000},
            "oauth": {"require_pkce": False},
        }
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
        (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {}}))
        config = init_config(str(tmp_path), profile_override="stricter-dev")
        assert config.settings.require_pkce is True
        config.save()
        assert self._on_disk(tmp_path)["oauth"]["require_pkce"] is False

    def test_yaml_stricter_dev_save_does_not_materialize_effects(self, tmp_path):
        """Profile declared in YAML: the hardening is implied by the profile
        line and must not be spelled out by a save either."""
        config = init_config(_write_config(tmp_path, "stricter-dev"))
        config.save()
        on_disk = self._on_disk(tmp_path)
        assert on_disk["security_profile"] == "stricter-dev"
        assert "require_pkce: true" not in yaml.safe_dump(on_disk)
        assert (on_disk.get("oauth") or {}).get("require_pkce") is not True

    def test_persistable_settings_is_effective_settings_without_profile(self, tmp_path):
        config = ConfigManager(_write_config(tmp_path))
        assert config.persistable_settings() is config.settings

    def test_next_start_without_flag_is_not_hardened(self, tmp_path):
        """End to end: run with the flag, save, restart without it."""
        init_config(_write_config(tmp_path), profile_override="stricter-dev").save()
        fresh = ConfigManager(str(tmp_path))
        assert fresh.settings.security_profile == "dev"
        assert fresh.settings.require_pkce is False
        assert fresh.settings.password_hashing is False
        assert fresh.settings.rate_limit_enabled is False


class TestStricterDevHardeningSurvivesReload:
    EXPECTED = {"require_pkce": True, "password_hashing": True, "rate_limit_enabled": True, "debug": False}

    def _assert_hardened(self, settings):
        for field, value in self.EXPECTED.items():
            assert getattr(settings, field) is value, field

    def test_yaml_stricter_dev_hardening_after_reload(self, tmp_path):
        """Before #172 every reload silently dropped require_pkce & co. even
        with security_profile: stricter-dev in the YAML itself."""
        config = ConfigManager(_write_config(tmp_path, "stricter-dev"))
        self._assert_hardened(config.settings)
        config.reload()
        assert config.settings.security_profile == "stricter-dev"
        self._assert_hardened(config.settings)

    def test_cli_stricter_dev_hardening_after_reload(self, tmp_path):
        config = ConfigManager(_write_config(tmp_path), profile_override="stricter-dev")
        config.reload()
        self._assert_hardened(config.settings)

    def test_dev_profile_does_not_harden(self, tmp_path):
        config = ConfigManager(_write_config(tmp_path))
        assert config.settings.require_pkce is False
        assert config.settings.password_hashing is False
        assert config.settings.rate_limit_enabled is False

    def test_explicit_dev_override_undoes_yaml_stricter_hardening(self, tmp_path):
        config = ConfigManager(_write_config(tmp_path, "stricter-dev"), profile_override="dev")
        assert config.settings.require_pkce is False
        assert config.settings.rate_limit_enabled is False


class TestCliDefault:
    def test_profile_flag_defaults_to_none(self):
        import inspect

        import nanoidp.__main__ as main_mod

        src = inspect.getsource(main_mod)
        assert 'default=None' in src.split('"--profile"')[1].split("help=")[0]
        assert 'choices=list(SECURITY_PROFILES)' in src


class TestApiConfigExposesEffectiveProfile:
    def test_api_config_reports_override_and_hardening(self, tmp_path):
        from nanoidp.app import create_app

        app = create_app(config_dir=_write_config(tmp_path, "oauth21"), profile="stricter-dev")
        app.config["TESTING"] = True
        with app.test_client() as client:
            doc = client.get("/api/config").get_json()
        assert doc["security_profile"] == "stricter-dev"
        assert doc["profile_override"] == "stricter-dev"
        assert doc["effective"] == {
            "require_pkce": True,
            "password_hashing": True,
            "rate_limit_enabled": True,
            "debug": False,
        }

    def test_api_config_without_override(self, tmp_path):
        from nanoidp.app import create_app

        app = create_app(config_dir=_write_config(tmp_path))
        app.config["TESTING"] = True
        with app.test_client() as client:
            doc = client.get("/api/config").get_json()
        assert doc["security_profile"] == "dev"
        assert doc["profile_override"] is None
        assert doc["effective"]["require_pkce"] is False
