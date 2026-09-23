"""The declared configuration is published as one value (#406, step A).

``tests/test_config_consistency_boundary.py`` pins the same invariant one
level down: a directory is observed once, so a reader never pairs one
file's content with another's. This file is the analogue inside the
process. A load was transactional on the way in and not on the way out:
``_commit_directory()`` assigned eleven fields one after the other, and a
reader that read two of them across a reload got a configuration that never
existed.

Step A makes the publication one assignment of one frozen carrier. It fixes
nothing measurable by itself, and it is what step B (one snapshot per
request) is built on, so what is pinned here is the shape: one assignment,
the attributes read through to it, and a holder of the carrier unaffected
by a later load.

The carrier holds references, not deep copies: a load publishes new objects
instead of mutating the old ones. The objects themselves are still mutable,
and the MCP write tools do mutate them in place before saving; where the
boundary for such an edit lies belongs to step B, not here.
"""

import ast
import inspect
import shutil
import textwrap
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigManager

_PUBLISHED = (
    "settings",
    "users",
    "default_user",
    "strict_config",
    "config_version",
    "users_revision",
    "settings_revision",
    "observed_at",
)


_REPO_CONFIG = Path(__file__).resolve().parent.parent / "config"


@pytest.fixture
def config_dir(tmp_path):
    # Resolved from this file, not from the working directory, and copied:
    # the repository's own config/ is written to during development.
    directory = tmp_path / "config"
    shutil.copytree(_REPO_CONFIG, directory)
    return directory


def _declare(directory: Path, username: str) -> None:
    users = yaml.safe_load((directory / "users.yaml").read_text())
    users["users"] = {username: {"password": "pw", "roles": ["user"]}}
    users["default_user"] = username
    (directory / "users.yaml").write_text(yaml.safe_dump(users, sort_keys=False))


class TestOnePublication:
    def test_the_published_state_is_assigned_once(self):
        """Not eleven assignments whose order is the contract: one."""
        source = textwrap.dedent(inspect.getsource(ConfigManager._commit_directory))
        assigned = []
        for node in ast.walk(ast.parse(source)):
            # An annotated assignment is one too: `self.observed_at: float =`
            # is how one of these fields used to be published.
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                    assigned.append(target.attr)
            # setattr(self, "settings", ...) would be a publication too.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr":
                first = node.args[0] if node.args else None
                if isinstance(first, ast.Name) and first.id == "self" and len(node.args) > 1:
                    named = node.args[1]
                    assigned.append(named.value if isinstance(named, ast.Constant) else "setattr")

        published = [name for name in assigned if name in _PUBLISHED or name == "setattr"]
        assert published == [], f"still published field by field: {published}"
        assert assigned.count("_snapshot") == 1, f"the snapshot is not assigned exactly once: {assigned}"

    def test_the_attributes_read_through_to_it(self, config_dir):
        config = ConfigManager(str(config_dir))

        snapshot = config.snapshot

        for name in _PUBLISHED:
            assert getattr(config, name) is getattr(snapshot, name), name

    def test_a_load_replaces_the_whole_carrier(self, config_dir):
        config = ConfigManager(str(config_dir))
        before = config.snapshot

        _declare(config_dir, "bob")
        config.reload_local()

        assert config.snapshot is not before
        assert config.default_user == "bob"

    def test_a_holder_of_one_carrier_is_not_moved_by_a_load(self, config_dir):
        """What step B rests on: a request that took the carrier reads the
        configuration it took, whatever lands afterwards."""
        config = ConfigManager(str(config_dir))
        held = config.snapshot
        held_users = dict(held.users)

        _declare(config_dir, "bob")
        config.reload_local()

        assert held.default_user != "bob"
        assert held.users == held_users
        assert "bob" not in held.users
        assert config.snapshot.users.keys() != held.users.keys()

    def test_the_carrier_refuses_to_be_changed(self, config_dir):
        config = ConfigManager(str(config_dir))

        with pytest.raises(FrozenInstanceError):
            config.snapshot.default_user = "someone-else"

    def test_the_manager_refuses_to_publish_a_field_on_its_own(self, config_dir):
        """The way a load used to change one field is gone: what a reader
        may hold is a whole configuration."""
        config = ConfigManager(str(config_dir))

        with pytest.raises(AttributeError):
            config.default_user = "someone-else"


class TestOneObservationPerAnswer:
    @staticmethod
    def _counting(config, monkeypatch):
        taken = []
        real = type(config).snapshot.fget
        monkeypatch.setattr(
            type(config), "snapshot", property(lambda self: (taken.append(1), real(self))[1])
        )
        return taken

    def test_a_save_writes_both_files_from_one_carrier(self, config_dir, monkeypatch):
        """The two documents are written under the directory's lock, but a
        load commits outside it, so composing the save from two reads wrote
        users.yaml from one load and settings.yaml from another."""
        config = ConfigManager(str(config_dir))
        taken = self._counting(config, monkeypatch)

        config.save()

        assert len(taken) == 1, f"the carrier was observed {len(taken)} times"

    def test_saving_the_users_alone_reads_the_carrier_once(self, config_dir, monkeypatch):
        """The user map and the default user are one pair, or the file gets
        one load's users under another's default."""
        config = ConfigManager(str(config_dir))
        taken = self._counting(config, monkeypatch)

        config._save_users()

        assert len(taken) == 1, f"the carrier was observed {len(taken)} times"

    def test_persistable_settings_reads_the_carrier_once(self, config_dir, monkeypatch):
        """It composed `settings` with `_declared` from two reads, so a load
        between them wrote a file pairing one load's values with another's
        declarations. Counted rather than timed: the invariant is the number
        of observations."""
        config = ConfigManager(str(config_dir))
        taken = []
        real = type(config).snapshot.fget

        monkeypatch.setattr(
            type(config), "snapshot", property(lambda self: (taken.append(1), real(self))[1])
        )

        config.persistable_settings()

        assert len(taken) == 1, f"the carrier was observed {len(taken)} times"
