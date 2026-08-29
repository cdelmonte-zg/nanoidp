"""
Tests for issue #229 phase 5 (ConfigManager side): the manager tracks the
revision of the bytes each YAML file was LOADED from, so a caller (the MCP
save_config tool) can build a save precondition on the state its change
was actually based on.

The tracked revision is deliberately not the file's revision at ask time:
on a runtime that is stale against the directory (another process wrote),
a fresh disk hash would satisfy save()'s precondition exactly when the
lost update is real. That distinction is what the two-manager tests pin.
"""

import pytest
import yaml

from nanoidp.config import ConfigManager
from nanoidp.config_writer import ConflictError, current_revision, revision_of_bytes


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


class TestLoadedRevisionsTrackTheParsedBytes:
    def test_after_load_the_revisions_match_the_files(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))

        assert config.users_revision == current_revision(config_dir / "users.yaml")
        assert config.settings_revision == current_revision(config_dir / "settings.yaml")

    def test_a_missing_file_has_the_empty_bytes_revision(self, tmp_path):
        config_dir = _seed(tmp_path)
        (config_dir / "users.yaml").unlink()
        config = ConfigManager(str(config_dir))

        # Same value current_revision() reports for a missing path - and
        # for an existing zero-byte file, which shares sha256(b""): the
        # precondition this enables means "the file still has the
        # missing/empty revision", not literally "the file is still
        # absent" (semantics from phase 2, kept as is).
        assert config.users_revision == revision_of_bytes(b"")
        assert config.users_revision == current_revision(config_dir / "users.yaml")

    def test_an_external_write_does_not_move_the_tracked_revision(self, tmp_path):
        """The tracked revision describes what THIS runtime loaded, not
        the directory's current state - that staleness is exactly what a
        save precondition needs to carry."""
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        loaded = config.settings_revision

        settings_file = config_dir / "settings.yaml"
        settings_file.write_text(settings_file.read_text() + "\n# another writer\n")

        assert config.settings_revision == loaded
        assert config.settings_revision != current_revision(settings_file)

    def test_reload_local_refreshes_the_revisions(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))
        settings_file = config_dir / "settings.yaml"
        settings_file.write_text(settings_file.read_text() + "\n# another writer\n")

        config.reload_local()

        assert config.settings_revision == current_revision(settings_file)

    def test_save_refreshes_the_revisions_to_what_was_written(self, tmp_path):
        config_dir = _seed(tmp_path)
        config = ConfigManager(str(config_dir))

        config.settings.audience = "changed"
        config.save()

        assert config.settings_revision == current_revision(config_dir / "settings.yaml")
        assert config.users_revision == current_revision(config_dir / "users.yaml")


class TestTwoRuntimesOnOneDirectory:
    """The scenario phase 5 exists for: a Flask process and a nanoidp-mcp
    companion (here: two ConfigManagers) writing the same directory."""

    def test_the_stale_runtime_is_refused_not_silently_clobbering(self, tmp_path):
        config_dir = _seed(tmp_path)
        a = ConfigManager(str(config_dir))
        b = ConfigManager(str(config_dir))

        b.settings.audience = "written-by-b"
        b.save()

        a.settings.audience = "written-by-a"
        with pytest.raises(ConflictError):
            a.save(expected_settings_revision=a.settings_revision)

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "written-by-b"

    def test_reload_then_save_with_fresh_revisions_succeeds(self, tmp_path):
        config_dir = _seed(tmp_path)
        a = ConfigManager(str(config_dir))
        b = ConfigManager(str(config_dir))

        b.settings.audience = "written-by-b"
        b.save()

        a.reload_local()
        a.settings.audience = "written-by-a"
        a.save(
            expected_users_revision=a.users_revision,
            expected_settings_revision=a.settings_revision,
        )

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "written-by-a"

    def test_without_a_precondition_the_stale_runtime_still_wins(self, tmp_path):
        """Unchanged contract: no revision supplied = last-write-wins,
        stated as such - the two-process lost update phase 5 lets a
        caller catch is still the default behaviour when nobody asks."""
        config_dir = _seed(tmp_path)
        a = ConfigManager(str(config_dir))
        b = ConfigManager(str(config_dir))

        b.settings.audience = "written-by-b"
        b.save()

        a.settings.audience = "written-by-a"
        a.save()

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "written-by-a"
