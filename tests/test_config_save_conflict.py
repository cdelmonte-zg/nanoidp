"""
Tests for issue #229 phase 2: ConfigManager.save() (and the underlying
_save_users/_save_settings) now route through the shared
compare_and_replace primitive (services/config_writer.py) and accept an
optional expected_*_revision, refusing a stale write with ConflictError
instead of silently overwriting it.
"""

import pytest
import yaml

from nanoidp.config import ConfigManager
from nanoidp.services.config_writer import ConflictError, current_revision


def _seed(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.yaml").write_text(
        "oauth:\n  issuer: 'http://localhost:8000'\n  audience: 'default'\n"
    )
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


class TestSaveSettingsConflictDetection:
    def test_matching_revision_succeeds(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        base = current_revision(config_dir / "settings.yaml")

        config.settings.audience = "changed"
        config.save(expected_settings_revision=base)

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "changed"

    def test_stale_revision_raises_conflict_and_leaves_file_untouched(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        base = current_revision(config_dir / "settings.yaml")

        # someone else writes settings.yaml first
        settings_file = config_dir / "settings.yaml"
        settings_file.write_text(settings_file.read_text() + "\nlogging:\n  verbose_logging: false\n")

        config.settings.audience = "changed"
        with pytest.raises(ConflictError):
            config.save(expected_settings_revision=base)

        on_disk = yaml.safe_load(settings_file.read_text())
        assert (on_disk.get("oauth") or {}).get("audience") != "changed"

    def test_unconditional_save_is_unaffected_by_a_stale_precondition_never_supplied(self, tmp_path):
        """expected_settings_revision=None (the default) is today's
        last-write-wins - it keeps working for every caller not yet
        migrated to pass a revision."""
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        settings_file = config_dir / "settings.yaml"
        settings_file.write_text(settings_file.read_text() + "\nlogging:\n  verbose_logging: false\n")

        config.settings.audience = "changed"
        config.save()

        on_disk = yaml.safe_load(settings_file.read_text())
        assert on_disk["oauth"]["audience"] == "changed"


class TestSaveUsersConflictDetection:
    def test_matching_revision_succeeds(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        base = current_revision(config_dir / "users.yaml")

        config.users["admin"].email = "changed@example.org"
        config.save(expected_users_revision=base)

        on_disk = yaml.safe_load((config_dir / "users.yaml").read_text())
        assert on_disk["users"]["admin"]["email"] == "changed@example.org"

    def test_stale_revision_raises_conflict(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        base = current_revision(config_dir / "users.yaml")

        users_file = config_dir / "users.yaml"
        users_file.write_text(users_file.read_text() + "\n# a comment someone else added\n")

        config.users["admin"].email = "changed@example.org"
        with pytest.raises(ConflictError):
            config.save(expected_users_revision=base)


class TestSaveRefreshesRuntimeOnceAfterBothFiles:
    """Regression pin: save() used to call reload_local() after each
    individual file (_save_users then _save_settings), so the users.yaml
    reload's freshly-loaded Settings discarded the in-memory
    settings.yaml change before it was ever written. save() must refresh
    exactly once, after both files are written."""

    def test_settings_change_survives_a_save_that_also_touches_users(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))

        config.settings.security_profile = "oauth21"
        config.users["admin"].email = "changed@example.org"
        config.save()

        on_disk_settings = yaml.safe_load((config_dir / "settings.yaml").read_text())
        on_disk_users = yaml.safe_load((config_dir / "users.yaml").read_text())
        assert on_disk_settings["security_profile"] == "oauth21"
        assert on_disk_users["users"]["admin"]["email"] == "changed@example.org"
        # the runtime reflects what was just written, not the pre-save state
        assert config.settings.security_profile == "oauth21"
