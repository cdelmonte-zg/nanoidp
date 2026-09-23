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
instead of mutating the old ones, and this is not a promise against a
caller that mutates ``settings`` in place.
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


@pytest.fixture
def config_dir(tmp_path):
    directory = tmp_path / "config"
    shutil.copytree("config", directory)
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
        assigned = [
            target.attr
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self"
        ]

        published = [name for name in assigned if name in _PUBLISHED]
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
        assert held.settings is not config.snapshot.settings or held.settings == config.snapshot.settings

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
