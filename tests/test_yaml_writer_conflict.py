"""
Tests for issue #229 phase 3: YamlWriter's write methods now route through
the shared compare_and_replace primitive (config_writer.py) via
YamlWriter._atomic_write, and each accepts an optional expected_revision,
refusing a stale write with ConflictError instead of silently overwriting
it - the same guarantee ConfigManager.save() already got in phase 2.

Also pins that moving each method's already-exists/not-found validation
INSIDE its mutate closure (so it runs against the same freshly loaded
document that gets written, under the same lock) didn't change any of
those checks' outward behavior.
"""

import threading

import pytest
import yaml

from nanoidp.config import ConfigManager, OAuthClient, User
from nanoidp.config_writer import ConflictError, current_revision
from nanoidp.services.yaml_writer import YamlWriter


def _seed(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.yaml").write_text(
        "oauth:\n  issuer: 'http://localhost:8000'\n  clients:\n"
        "    - client_id: 'c1'\n      client_secret: 's1'\n"
    )
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


def _writer(config_dir):
    ConfigManager(str(config_dir))  # installs the active config singleton
    return YamlWriter(str(config_dir))


class TestUsersYamlSkeletonFidelity:
    """Regression pin for #229 phase 3 review, blocking 1: the old
    _load_users_yaml() injected {"users": {}, "default_user": "admin"}
    only when users.yaml did not exist at all - not whenever the
    default_user key happened to be absent. save_user/delete_user's
    mutate closures must reproduce exactly that condition, or an
    existing file that simply never declared default_user (or an
    existing-but-empty file) silently gains a key the operator never
    wrote, naming a user ("admin") that may not even exist in the file -
    the opposite of the #127 line of work, where an untouched file
    survives a save unchanged."""

    def test_save_user_does_not_inject_default_user_into_an_existing_file_missing_it(
        self, tmp_path
    ):
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "settings.yaml").write_text("oauth:\n  issuer: 'http://localhost:8000'\n")
        (config_dir / "users.yaml").write_text('users:\n  alice:\n    password: "x"\n')
        writer = _writer(config_dir)

        writer.save_user(User(username="bob", password="y"))

        on_disk = yaml.safe_load((config_dir / "users.yaml").read_text())
        assert "default_user" not in on_disk
        assert set(on_disk["users"]) == {"alice", "bob"}

    def test_delete_user_does_not_inject_default_user_into_an_existing_file_missing_it(
        self, tmp_path
    ):
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "settings.yaml").write_text("oauth:\n  issuer: 'http://localhost:8000'\n")
        (config_dir / "users.yaml").write_text(
            'users:\n  alice:\n    password: "x"\n  bob:\n    password: "y"\n'
        )
        writer = _writer(config_dir)

        writer.delete_user("bob")

        on_disk = yaml.safe_load((config_dir / "users.yaml").read_text())
        assert "default_user" not in on_disk
        assert set(on_disk["users"]) == {"alice"}

    def test_save_user_still_applies_the_old_skeleton_for_a_genuinely_missing_file(
        self, tmp_path
    ):
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "settings.yaml").write_text("oauth:\n  issuer: 'http://localhost:8000'\n")
        # no users.yaml at all
        ConfigManager(str(config_dir))
        writer = YamlWriter(str(config_dir))

        writer.save_user(User(username="bob", password="y"))

        on_disk = yaml.safe_load((config_dir / "users.yaml").read_text())
        assert on_disk["default_user"] == "admin"
        assert set(on_disk["users"]) == {"bob"}


class TestSaveUserConflictDetection:
    def test_matching_revision_succeeds(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        base = current_revision(config_dir / "users.yaml")

        writer.save_user(User(username="bob", password="x"), expected_revision=base)

        on_disk = yaml.safe_load((config_dir / "users.yaml").read_text())
        assert "bob" in on_disk["users"]

    def test_stale_revision_raises_conflict_and_leaves_file_untouched(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        users_file = config_dir / "users.yaml"
        base = current_revision(users_file)
        users_file.write_text(users_file.read_text() + "\n# someone else wrote this\n")

        with pytest.raises(ConflictError):
            writer.save_user(User(username="bob", password="x"), expected_revision=base)

        on_disk = yaml.safe_load(users_file.read_text())
        assert "bob" not in on_disk["users"]

    def test_unconditional_write_is_unaffected_by_no_precondition(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        users_file = config_dir / "users.yaml"
        users_file.write_text(users_file.read_text() + "\n# someone else wrote this\n")

        writer.save_user(User(username="bob", password="x"))

        on_disk = yaml.safe_load(users_file.read_text())
        assert "bob" in on_disk["users"]

    def test_already_exists_check_still_works_from_inside_mutate(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)

        with pytest.raises(ValueError, match="already exists"):
            writer.save_user(User(username="admin", password="x"), is_new=True)


class TestSaveUserConcurrentCreateDoesNotLoseAnUpdate:
    """Regression pin for the actual race #229 phase 3 closes: before this
    migration, save_user's already-exists check ran on a document loaded
    before _atomic_write was even called, so two near-simultaneous
    is_new=True creates of the same username could both pass the check
    (each loaded independently before either wrote) and the second
    silently overwrote the first - reproduced by the reviewer 20/20 on
    the pre-migration code with this exact shape.

    A single Barrier(2)-synchronized trial is not, on its own, a
    provably deterministic pin - it makes the race very likely, not
    certain, since it does not force both threads' load to complete
    before either write. Repeating it many times, and asserting the
    invariant on every trial, is the robust version: on a
    lock-protected write path, it must hold every single time; on a
    regression that reintroduces the old load-before-the-write-call
    pattern, 20 trials reproduces the loss with overwhelming
    probability (matching the reviewer's own 20/20 empirical check),
    rather than depending on exactly where a monkeypatched
    synchronization point sits in the current call graph."""

    @staticmethod
    def _race_one_trial(writer, barrier, results, password):
        barrier.wait()
        try:
            writer.save_user(User(username="bob", password=password), is_new=True)
            results.append("ok")
        except ValueError:
            results.append("value_error")

    def test_two_concurrent_creates_of_the_same_user_never_both_succeed(self, tmp_path):
        for trial in range(20):
            config_dir = _seed(tmp_path / f"trial-{trial}")
            writer = _writer(config_dir)

            barrier = threading.Barrier(2)
            results = []

            threads = [
                threading.Thread(
                    target=self._race_one_trial, args=(writer, barrier, results, password)
                )
                for password in ("first", "second")
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert sorted(results) == ["ok", "value_error"], f"trial {trial}: {results}"


class TestDeleteUserConflictDetection:
    def test_stale_revision_raises_conflict(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        users_file = config_dir / "users.yaml"
        base = current_revision(users_file)
        users_file.write_text(users_file.read_text() + "\n# someone else wrote this\n")

        with pytest.raises(ConflictError):
            writer.delete_user("admin", expected_revision=base)

        on_disk = yaml.safe_load(users_file.read_text())
        assert "admin" in on_disk["users"]

    def test_not_found_check_still_works_from_inside_mutate(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)

        with pytest.raises(ValueError, match="not found"):
            writer.delete_user("nobody")


class TestSaveClientConflictDetection:
    def test_matching_revision_succeeds(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        base = current_revision(config_dir / "settings.yaml")

        writer.save_client(
            OAuthClient(client_id="c2", client_secret="s2", description="d"),
            is_new=True,
            expected_revision=base,
        )

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        client_ids = [c["client_id"] for c in on_disk["oauth"]["clients"]]
        assert "c2" in client_ids

    def test_stale_revision_raises_conflict_and_leaves_file_untouched(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        settings_file = config_dir / "settings.yaml"
        base = current_revision(settings_file)
        settings_file.write_text(settings_file.read_text() + "\nlogging:\n  verbose_logging: false\n")

        with pytest.raises(ConflictError):
            writer.save_client(
                OAuthClient(client_id="c2", client_secret="s2", description="d"),
                is_new=True,
                expected_revision=base,
            )

        on_disk = yaml.safe_load(settings_file.read_text())
        client_ids = [c["client_id"] for c in on_disk["oauth"]["clients"]]
        assert "c2" not in client_ids

    def test_already_exists_check_still_works_from_inside_mutate(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)

        with pytest.raises(ValueError, match="already exists"):
            writer.save_client(
                OAuthClient(client_id="c1", client_secret="s1", description="d"),
                is_new=True,
            )


class TestUpdateOauthSettingsConflictDetection:
    def test_stale_revision_raises_conflict(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        settings_file = config_dir / "settings.yaml"
        base = current_revision(settings_file)
        settings_file.write_text(settings_file.read_text() + "\nlogging:\n  verbose_logging: false\n")

        with pytest.raises(ConflictError):
            writer.update_oauth_settings(audience="changed", expected_revision=base)

        on_disk = yaml.safe_load(settings_file.read_text())
        assert on_disk["oauth"].get("audience") != "changed"

    def test_matching_revision_succeeds(self, tmp_path):
        config_dir = _seed(tmp_path)
        writer = _writer(config_dir)
        base = current_revision(config_dir / "settings.yaml")

        writer.update_oauth_settings(audience="changed", expected_revision=base)

        on_disk = yaml.safe_load((config_dir / "settings.yaml").read_text())
        assert on_disk["oauth"]["audience"] == "changed"
