"""
Tests for issue #229 phase 2: ConfigManager.save() now writes users.yaml
and settings.yaml as one transaction through compare_and_replace_many
(config_writer.py), and accepts an optional expected_*_revision per file,
refusing the whole save with ConflictError - before either file is
written - instead of silently overwriting one.
"""

import pytest
import yaml

from nanoidp.config import ConfigManager, ReloadAfterSaveError
from nanoidp.config_documents import DocumentRejected
from nanoidp.config_writer import ConflictError, current_revision
from nanoidp.hooks import HookError


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


class TestSaveIsTransactionalAcrossBothFiles:
    """Regression pin for the #229 review finding on phase 2: save() used
    to write users.yaml, then check settings.yaml's revision - a stale
    settings revision left a fresh users.yaml on disk with the in-memory
    settings change silently dropped. Both revisions must be checked
    before either file is written."""

    def test_stale_settings_revision_leaves_users_untouched_too(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        stale_settings_revision = current_revision(config_dir / "settings.yaml")

        # someone else writes settings.yaml first
        settings_file = config_dir / "settings.yaml"
        settings_file.write_text(settings_file.read_text() + "\nlogging:\n  verbose_logging: false\n")

        config.users["admin"].email = "changed@example.org"
        config.settings.audience = "changed"
        with pytest.raises(ConflictError):
            config.save(expected_settings_revision=stale_settings_revision)

        on_disk_users = yaml.safe_load((config_dir / "users.yaml").read_text())
        on_disk_settings = yaml.safe_load(settings_file.read_text())
        assert on_disk_users["users"]["admin"].get("email", "") != "changed@example.org"
        assert (on_disk_settings.get("oauth") or {}).get("audience") != "changed"


class TestASaveThatWouldNotLoadIsRefused:
    """What used to be pinned here as damage control is now prevented.

    Settings has no validate_assignment, so an in-memory
    token_expiry_minutes = -5 (the model declares gt=0) reached
    settings.yaml just fine and only failed on the way back in. These
    tests asserted that the -5 was on disk afterwards, because at the
    time the alternative was a durable write reported as if nothing had
    happened. Since #366 the document is parsed before the file is
    replaced, so the write never happens at all - which is the outcome
    those assertions were the least bad substitute for.

    The reload-failure contract itself is still pinned, one class down.
    """

    def test_the_file_is_left_alone(self, tmp_path):
        config_dir = _seed(tmp_path)
        settings_file = config_dir / "settings.yaml"
        config = ConfigManager(str(config_dir))
        before = settings_file.read_text()

        config.settings.token_expiry_minutes = -5

        with pytest.raises(DocumentRejected):
            config.save()

        assert settings_file.read_text() == before

    def test_the_refusal_names_the_file_and_the_field(self, tmp_path):
        config = ConfigManager(str(_seed(tmp_path)))
        config.settings.token_expiry_minutes = -5

        with pytest.raises(DocumentRejected) as refused:
            config.save()

        assert "settings.yaml" in refused.value.message
        assert "token_expiry_minutes" in refused.value.message

    def test_a_refusal_does_not_reach_the_mirror_hook(self, tmp_path):
        """Nothing was written, so there is nothing to mirror. The hook
        would otherwise announce a save that did not happen."""
        config_dir = _seed(tmp_path)
        settings_file = config_dir / "settings.yaml"
        marker = tmp_path / "hook-ran"
        settings_file.write_text(
            settings_file.read_text()
            + f"\nhooks:\n  on_config_saved: 'touch {marker}'\n  strict: true\n"
        )
        config = ConfigManager(str(config_dir))

        config.settings.token_expiry_minutes = -5

        with pytest.raises(DocumentRejected):
            config.save()
        assert not marker.exists()


class TestReloadFailureAfterASuccessfulWrite:
    """The #229 review blocking 3 contract, still true.

    reload_local() runs unconditionally at the end of save(), so it can
    raise on its own. Since #366 the writer no longer produces a document
    that fails to parse, so the causes left are the ones it cannot see -
    another process writing in between, an environment that changed under
    it, a strictness the file does not declare. The failure is injected
    here rather than provoked, because the contract being pinned is what
    save() does about it, not which cause produced it: a durable write
    must never be reported as if nothing happened, and a reload failure
    must never replace a pending HookError. A caller needs to tell "the
    write itself failed" apart from "written, but the runtime couldn't
    adopt it" apart from "written, only the mirror push failed".
    """

    @staticmethod
    def _reload_always_fails(config, monkeypatch):
        def fail() -> None:
            raise ValueError("the runtime could not adopt it")

        monkeypatch.setattr(config, "reload_local", fail)

    def test_reload_failure_is_not_reported_as_a_silent_success(self, tmp_path, monkeypatch):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        config.settings.audience = "written-anyway"
        self._reload_always_fails(config, monkeypatch)

        with pytest.raises(ReloadAfterSaveError):
            config.save()

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "written-anyway"

    def test_reload_failure_does_not_swallow_a_pending_hook_error(self, tmp_path, monkeypatch):
        config_dir = _seed(tmp_path)
        settings_file = config_dir / "settings.yaml"
        settings_file.write_text(
            settings_file.read_text() + "\nhooks:\n  on_config_saved: 'false'\n  strict: true\n"
        )
        config = ConfigManager(str(config_dir))
        config.settings.audience = "written-anyway"
        self._reload_always_fails(config, monkeypatch)

        with pytest.raises(HookError):
            config.save()

        on_disk = yaml.safe_load(settings_file.read_text())
        assert on_disk["oauth"]["audience"] == "written-anyway"


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
