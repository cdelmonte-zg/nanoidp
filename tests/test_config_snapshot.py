"""The declared configuration is published as one value, and an operation
reads one (#406, steps A and B).

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
import json
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


class TestAnMcpCallIsAnOperationToo:
    """An MCP tool call is the other implementation of the same invariant
    as an HTTP request: one published configuration, chosen after freshness
    is established, carried through the call."""

    def test_the_settings_it_reports_are_the_ones_the_call_began_with(self, config_dir, monkeypatch):
        """The handler read the settings, then the version, the strictness
        and the revision, so a load landing between the first and the rest
        reported settings of one load with the revision of another: the
        revision a caller passes back as expected_settings_revision.

        Counted, because after the fix the window is not there to force: a
        load is triggered by any read of the manager's published state, and
        the call must neither make such a read nor report the later load.
        """
        import asyncio

        from mcp.types import CallToolRequestParams

        from nanoidp import mcp_server
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(config_dir))
        began_with = (config.settings.audience, config.settings_revision)
        monkeypatch.setattr(mcp_server, "_ensure_config", lambda: config)
        monkeypatch.setattr(mcp_server, "fresh_configuration", lambda: None)
        reads = []

        def load_on_any_read(manager):
            reads.append(1)
            if len(reads) == 1:
                document = yaml.safe_load((config_dir / "settings.yaml").read_text())
                document["oauth"]["audience"] = "an-audience-of-the-next-load"
                (config_dir / "settings.yaml").write_text(yaml.safe_dump(document, sort_keys=False))
                config.reload_local()
            return manager._snapshot.settings

        monkeypatch.setattr(type(config), "settings", property(load_on_any_read))
        answer = asyncio.run(
            mcp_server.call_tool(None, CallToolRequestParams(name="get_settings", arguments={}))
        )

        reported = json.loads(answer.content[0].text)
        assert (reported["audience"], reported["settings_revision"]) == began_with, (
            "the report is of a load the call did not begin with"
        )
        assert reads == [], f"the call read the manager {len(reads)} times instead of the configuration it took"

    def test_a_load_between_the_choice_and_the_dispatch_is_not_read(self, config_dir, monkeypatch):
        """The call chooses its configuration right after freshness, and the
        handler is given that one: everything between, the argument check and
        the management gate, is inside the call, not before it."""
        import asyncio

        from mcp.types import CallToolRequestParams

        from nanoidp import mcp_server
        from nanoidp.config import ConfigManager

        config = ConfigManager(str(config_dir))
        began_with = config.settings.audience
        monkeypatch.setattr(mcp_server, "_ensure_config", lambda: config)
        monkeypatch.setattr(mcp_server, "fresh_configuration", lambda: None)
        in_the_window = []
        validate = mcp_server.best_match

        def load_before_the_dispatch(errors):
            if not in_the_window:
                in_the_window.append(True)
                document = yaml.safe_load((config_dir / "settings.yaml").read_text())
                document["oauth"]["audience"] = "an-audience-of-the-next-load"
                (config_dir / "settings.yaml").write_text(yaml.safe_dump(document, sort_keys=False))
                config.reload_local()
            return validate(errors)

        monkeypatch.setattr(mcp_server, "best_match", load_before_the_dispatch)
        answer = asyncio.run(
            mcp_server.call_tool(None, CallToolRequestParams(name="get_settings", arguments={}))
        )

        assert in_the_window, "the load was never placed in the window"
        assert json.loads(answer.content[0].text)["audience"] == began_with

    def test_every_tool_handler_is_synchronous(self):
        """The census measured that two tool calls in one process do not
        interleave, because a handler runs to completion between awaits. One
        carrier per call rests on that. An `async` handler, or an `await`
        inside one, reopens the question of what a consistent call means
        while another editor interleaves, and must be decided before it is
        written, not after.
        """
        import inspect as inspection

        from nanoidp import mcp_server

        for name, handler in mcp_server._TOOL_HANDLERS.items():
            assert not inspection.iscoroutinefunction(handler), name
            source = textwrap.dedent(inspection.getsource(handler))
            awaits = [node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Await, ast.AsyncFor))]
            assert awaits == [], f"{name} can yield to the event loop"


class TestWhatStaysTheServersDecision:
    """Five reads are the server's, not the operation's, and each says so
    where it is (#406). A later tidy-up that replaced them with the
    operation's configuration would change semantics quietly, so they are
    pinned here."""

    @staticmethod
    def _resolver(config, loaded=None):
        from nanoidp.services.identities import IdentityResolver
        from nanoidp.services.runtime_store import get_runtime_store

        return IdentityResolver(config, loaded or config.snapshot, get_runtime_store())

    def test_the_metadata_switch_is_the_servers(self, config_dir, monkeypatch):
        """Turning the capability off takes effect at once on every path,
        including an operation that began while it was on. A snapshot keeps
        a response consistent with the values it was built from; whether a
        capability is offered at all is not such a value."""
        from nanoidp.config import ConfigManager

        def switch(on):
            document = yaml.safe_load((config_dir / "settings.yaml").read_text())
            document.setdefault("oauth", {})["client_id_metadata_documents"] = {
                "enabled": on,
                "allowed_hosts": ["a-client.example"],
            }
            (config_dir / "settings.yaml").write_text(yaml.safe_dump(document, sort_keys=False))

        switch(True)
        config = ConfigManager(str(config_dir))
        began_with = config.snapshot
        assert began_with.settings.client_id_metadata_documents_enabled is True

        switch(False)
        config.reload_local()

        resolver = self._resolver(config, began_with)
        assert resolver.resolve_client("https://a-client.example/metadata.json") is None
        assert began_with.settings.client_id_metadata_documents_enabled is True, (
            "the operation still holds the configuration it began with"
        )

    def test_a_name_declared_after_the_operation_began_is_still_found(self, config_dir):
        """The store is live and the declaration is the operation's, so a
        load that declares a name and reconciles the runtime object away
        would otherwise be observed as neither."""
        from nanoidp.config import ConfigManager
        from nanoidp.services.runtime_store import get_runtime_store

        config = ConfigManager(str(config_dir))
        began_with = config.snapshot
        _declare(config_dir, "later")
        config.reload_local()
        get_runtime_store().users.delete("later")

        resolved = self._resolver(config, began_with).resolve_user("later")

        assert resolved is not None and resolved.origin == "declared"

    def test_the_route_reads_the_capability_switch_live_too(self, config_dir):
        """The one outbound fetch this server makes is behind the switch, and
        the resolver reads it live: the route that falls back to learning a
        client must not disagree, or a request that began while it was on
        would fetch after it was turned off."""
        from flask import Flask

        from nanoidp.config import ConfigManager
        from nanoidp.routes._config import remember_for_this_request
        from nanoidp.routes.oauth import _client_from_metadata_document

        def switch(on):
            document = yaml.safe_load((config_dir / "settings.yaml").read_text())
            document.setdefault("oauth", {})["client_id_metadata_documents"] = {
                "enabled": on,
                "allowed_hosts": ["a-client.example"],
            }
            (config_dir / "settings.yaml").write_text(yaml.safe_dump(document, sort_keys=False))

        switch(True)
        config = ConfigManager(str(config_dir))
        began_with = config.snapshot
        switch(False)
        config.reload_local()

        import nanoidp.routes.oauth as oauth_module

        attempts = []
        learn = oauth_module.learn_client

        with Flask(__name__).test_request_context("/authorize"):
            remember_for_this_request(began_with)
            oauth_module.learn_client = lambda *arguments, **named: attempts.append(1)
            try:
                assert _client_from_metadata_document(config, "https://a-client.example/m.json") is None
            finally:
                oauth_module.learn_client = learn

        assert attempts == [], "a document was fetched under a capability that is off"

    def test_a_declared_client_is_the_one_the_operation_began_with(self, config_dir):
        """Users were the measured case, clients are the same rule: a record
        that changed under the operation must not be half of its answer."""
        from nanoidp.config import ConfigManager

        def declare(secret):
            document = yaml.safe_load((config_dir / "settings.yaml").read_text())
            document["oauth"]["clients"] = [
                {"client_id": "a-client", "client_secret": secret, "description": "one"}
            ]
            (config_dir / "settings.yaml").write_text(yaml.safe_dump(document, sort_keys=False))

        declare("the-secret-it-began-with")
        config = ConfigManager(str(config_dir))
        began_with = config.snapshot

        declare("the-secret-of-the-next-load")
        config.reload_local()

        resolved = self._resolver(config, began_with).resolve_client("a-client")
        assert resolved is not None
        assert resolved.client.client_secret == "the-secret-it-began-with"

    def test_a_runtime_creation_checks_the_declaration_as_it_is_now(self, config_dir):
        """The check exists to refuse a runtime name the files declare, and
        the files are read under their lock: an operation's older view would
        let the collision through."""
        from nanoidp.config import ConfigManager, User
        from nanoidp.services.identities import DeclaredNameCollision

        config = ConfigManager(str(config_dir))
        began_with = config.snapshot
        _declare(config_dir, "declared-later")
        config.reload_local()

        with pytest.raises(DeclaredNameCollision):
            self._resolver(config, began_with).create_runtime_user(
                User(username="declared-later", password="pw")
            )


class TestTheBoundaryOfTheRequest:
    def test_one_request_does_not_read_what_another_chose(self, config_dir):
        """`g` belongs to the application context, which outlives a request
        when a caller pushed one around it, so the choice is kept with the
        request that made it and forgotten when that request ends."""
        from nanoidp.app import create_app
        from nanoidp.routes._config import request_config

        app = create_app(str(config_dir))

        with app.app_context():
            client = app.test_client()
            assert client.get("/api/config").status_code == 200

            with pytest.raises(RuntimeError, match="outside the boundary"):
                request_config()

            assert client.get("/api/health").status_code == 200

    def test_a_probe_that_reads_no_configuration_chooses_none(self, config_dir):
        """Health and static are exempt from freshness (#354, step 4a), so
        they choose no configuration either, and must not need one."""
        from nanoidp.app import create_app

        app = create_app(str(config_dir))

        with app.test_client() as client:
            assert client.get("/api/health").status_code == 200
            from nanoidp.routes._config import request_config

            with pytest.raises(RuntimeError, match="outside the boundary"):
                request_config()
