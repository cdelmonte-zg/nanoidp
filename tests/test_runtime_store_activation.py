"""The runtime store is chosen by the configuration and activated with it
(#354, first step).

Before this, ``get_runtime_store()`` built an in-memory store on first use,
took no settings and was published by nobody, so no backend could ever be
chosen and nothing said which store a process was using. Now:

- ``runtime.store`` is read from ``settings.yaml``. In this step the one value
  is ``memory``, the default: the schema offers no backend that nanoidp does
  not have (``sqlite`` and its path arrive with the backend, in the next step);
- the store is **activated** in the configuration's activation step, next to
  the signing service (#359): prepared from the candidate settings before
  anything is committed, and published once nothing can fail. Preparing does
  not activate: only the publication records the inputs a store was chosen
  with. (For memory, preparing may bring the provisional store into
  existence, as any reader of it would; that is no configured choice);
- **restart required**: a reload whose runtime store inputs differ from the
  ones in force is refused, and nothing is built for it;
- before the first activation there is a **provisional** memory store for
  whoever asks (the audit, a plugin's load hook), and the first activation
  that asks for memory adopts that very instance; ``get_runtime_store()``
  never reads the configuration itself;
- the services know the store and its repositories by their contracts only.

The machinery is generic. The tests that need a second backend register a
private factory for a kind no configuration file can name, and hand the
activation candidate settings carrying it.
"""

import ast
import shutil
from pathlib import Path

import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import ConfigManager, ConfigurationRejected, get_config
from nanoidp.services import runtime_store as runtime_store_module
from nanoidp.services.audit import get_audit_log
from nanoidp.services.runtime_store import (
    MemoryRuntimeStore,
    RuntimeStore,
    RuntimeStoreRestartRequired,
    activate_runtime_store,
    get_runtime_store,
    prepare_runtime_store,
)

_REPO = Path(__file__).resolve().parent.parent


def _config_dir(tmp_path, runtime=None):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    _set(config_dir, lambda doc: doc["jwt"].update(keys_dir=str(tmp_path / "keys")))
    if runtime is not None:
        _set(config_dir, lambda doc: doc.update(runtime=runtime))
    return config_dir


def _set(config_dir, mutate):
    settings = config_dir / "settings.yaml"
    doc = yaml.safe_load(settings.read_text())
    mutate(doc)
    settings.write_text(yaml.safe_dump(doc))


def _app(config_dir):
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app, app.test_client()


def _activated():
    return runtime_store_module._runtime_store, runtime_store_module._runtime_store_inputs


@pytest.fixture
def another_backend(monkeypatch):
    """A second kind of store, private to the tests: a memory store
    underneath, counted, so that which one a process is using can be told
    apart. No configuration file can name it; candidate settings that carry
    it are made with ``model_copy``, which does not validate."""
    made = []

    def make(settings):
        store = MemoryRuntimeStore()
        made.append(store)
        return store

    monkeypatch.setitem(runtime_store_module._RUNTIME_STORE_FACTORIES, "another", make)
    return made


def _asking_for(settings, kind):
    return settings.model_copy(update={"runtime_store": kind})


class TestTheStoreIsChosenByTheConfiguration:
    def test_by_default_it_is_the_memory_store_and_it_says_so(self, tmp_path):
        _, client = _app(_config_dir(tmp_path))

        assert isinstance(get_runtime_store(), MemoryRuntimeStore)
        assert client.get("/api/config").get_json()["runtime"] == {"store": "memory"}

    def test_saying_so_in_the_file_is_the_same(self, tmp_path):
        _app(_config_dir(tmp_path, {"store": "memory"}))

        assert _activated()[1] == ("memory",)

    def test_the_mcp_settings_tool_says_it_too(self, tmp_path):
        from nanoidp.mcp_server.handlers_config import _tool_get_settings

        _app(_config_dir(tmp_path))

        assert _tool_get_settings({}, get_config())["runtime"] == {"store": "memory"}

    def test_the_store_that_is_used_is_the_one_that_was_activated(self, tmp_path):
        _app(_config_dir(tmp_path))

        store, inputs = _activated()

        assert get_runtime_store() is store and inputs == ("memory",)

    @pytest.mark.parametrize("runtime", [{"store": "sqlite"}, {"store": "redis"}, {"store": ""}, "memory"])
    def test_a_store_the_schema_does_not_offer_is_an_invalid_file(self, tmp_path, runtime):
        """No backend nanoidp does not have: sqlite is refused like any
        value that is not one, until the backend is there."""
        with pytest.raises(ConfigurationRejected) as refused:
            create_app(str(_config_dir(tmp_path, runtime)))

        assert refused.value.kind == "invalid"

    @pytest.mark.parametrize("runtime", [{"store": "memory", "sqlite_path": "./x.db"}, {"shared": True}])
    def test_a_key_the_schema_does_not_offer_is_what_any_unknown_key_is(self, tmp_path, runtime, caplog):
        """The configuration's contract for unknown keys (#175): a warning,
        and the key ignored; refused under strict validation. sqlite_path
        included: it arrives with the backend."""
        with caplog.at_level("WARNING", logger="nanoidp.config_documents"):
            create_app(str(_config_dir(tmp_path, runtime)))
        assert "unknown key runtime." in caplog.text
        assert _activated()[1] == ("memory",)

        with pytest.raises(ConfigurationRejected) as refused:
            create_app(str(tmp_path / "config"), strict_config=True)
        assert refused.value.kind == "invalid"

    def test_a_backend_named_by_the_settings_is_the_one_built_and_published(self, tmp_path, another_backend):
        _app(_config_dir(tmp_path))
        settings = get_config().settings
        runtime_store_module._runtime_store = runtime_store_module._runtime_store_inputs = None

        activate_runtime_store(_asking_for(settings, "another"))()

        assert get_runtime_store() is another_backend[0]
        assert _activated()[1] == ("another",)


    def test_a_kind_nanoidp_has_no_store_for_is_refused_not_taken_for_memory(self, tmp_path):
        """Out of reach of a file (the schema names only what there is), and
        refused all the same if it ever gets there: never a memory store in
        its place, which would be state a peer does not share."""
        settings = ConfigManager(str(_config_dir(tmp_path))).settings
        provisional = get_runtime_store()

        with pytest.raises(ValueError, match="not a runtime store nanoidp has"):
            prepare_runtime_store(_asking_for(settings, "nothing-like-it"))

        assert _activated() == (provisional, None)


class TestPreparingDoesNotActivate:
    def test_a_prepared_store_is_not_published(self, tmp_path, another_backend):
        _app(_config_dir(tmp_path))
        settings = get_config().settings
        runtime_store_module._runtime_store = runtime_store_module._runtime_store_inputs = None
        provisional = get_runtime_store()

        prepare_runtime_store(_asking_for(settings, "another"))

        assert _activated() == (provisional, None), "still provisional, still that one"
        assert len(another_backend) == 1

    def test_an_activation_that_fails_after_the_store_was_prepared_leaves_it_provisional(self, tmp_path, monkeypatch):
        """The signing service is prepared after the store; if that fails,
        the configuration is refused and the store was never activated."""
        from nanoidp.services import crypto as crypto_module

        provisional = get_runtime_store()

        def cannot(settings):
            raise RuntimeError("no signing service for you")

        monkeypatch.setattr(crypto_module, "prepare_crypto_service", cannot)
        with pytest.raises(ConfigurationRejected) as refused:
            create_app(str(_config_dir(tmp_path)))

        assert refused.value.kind == "activation"
        assert _activated() == (provisional, None)


class TestARestartIsRequiredToChangeIt:
    def test_an_unrelated_reload_keeps_the_store_and_what_is_in_it(self, tmp_path):
        config_dir = _config_dir(tmp_path)
        _, client = _app(config_dir)
        client.post(
            "/api/runtime/clients",
            json={"client_id": "rt", "client_secret": "s" * 20, "redirect_uris": ["http://localhost:1/cb"]},
        )
        store = get_runtime_store()

        _set(config_dir, lambda doc: doc["oauth"].update(token_expiry_minutes=17))
        assert client.post("/api/config/reload").status_code == 200

        assert get_runtime_store() is store
        assert store.clients.get("rt") is not None

    def test_other_inputs_are_refused_before_anything_is_built(self, tmp_path, another_backend):
        _app(_config_dir(tmp_path))
        store = get_runtime_store()

        with pytest.raises(RuntimeStoreRestartRequired, match="restart"):
            prepare_runtime_store(_asking_for(get_config().settings, "another"))

        assert another_backend == []
        assert _activated() == (store, ("memory",))

    def test_a_reload_that_changes_them_is_refused_and_changes_nothing(self, tmp_path, another_backend, monkeypatch):
        """End to end, through the endpoint: the candidate asks for another
        store (the inputs of the file are read as another kind), and the
        reload is a 422 of kind activation, with nothing applied."""
        config_dir = _config_dir(tmp_path)
        _, client = _app(config_dir)
        store = get_runtime_store()
        expiry = get_config().settings.token_expiry_minutes
        monkeypatch.setattr(runtime_store_module, "runtime_store_inputs", lambda settings: ("another",))

        _set(config_dir, lambda doc: doc["oauth"].update(token_expiry_minutes=expiry + 1))
        response = client.post("/api/config/reload")

        assert response.status_code == 422
        body = response.get_json()
        assert body["kind"] == "activation" and "restart" in body["error"]
        assert get_runtime_store() is store and _activated()[1] == ("memory",)
        assert another_backend == []
        assert get_config().settings.token_expiry_minutes == expiry, "and none of it took effect"

    def test_a_restart_that_is_required_is_said_before_a_signing_service_is_built(self, tmp_path, monkeypatch):
        """The store is prepared first in the activation: the cheaper of the
        two, and the one that can refuse outright."""
        from nanoidp.services import crypto as crypto_module
        from nanoidp.services.activation import activate_services

        _app(_config_dir(tmp_path))
        monkeypatch.setattr(runtime_store_module, "runtime_store_inputs", lambda settings: ("another",))
        monkeypatch.setattr(
            crypto_module, "prepare_crypto_service", lambda settings: pytest.fail("a signing service was prepared")
        )

        with pytest.raises(RuntimeStoreRestartRequired):
            activate_services(get_config().settings)

    def test_what_the_activation_returns_publishes_the_store_and_the_signing_service(self, tmp_path, another_backend):
        from nanoidp.services import crypto as crypto_module
        from nanoidp.services.activation import activate_services

        settings = ConfigManager(str(_config_dir(tmp_path))).settings
        publish = activate_services(_asking_for(settings, "another"))
        assert _activated()[1] is None and crypto_module._crypto_service is None, "nothing before the publication"

        publish()

        assert _activated() == (another_backend[0], ("another",))
        assert crypto_module._crypto_service is not None

    def test_the_same_inputs_are_the_same_store(self, tmp_path):
        _app(_config_dir(tmp_path))
        store = get_runtime_store()

        prepared = prepare_runtime_store(get_config().settings)

        assert prepared[0] is store


class TestBeforeTheFirstActivation:
    def test_a_store_is_there_for_whoever_asks_before_any_configuration(self):
        store = get_runtime_store()

        assert isinstance(store, MemoryRuntimeStore)
        assert _activated() == (store, None)
        assert get_runtime_store() is store

    def test_the_first_activation_adopts_it_when_it_asks_for_memory(self, tmp_path):
        """What was recorded before the configuration was read (a plugin's
        load hook logging an event) is not thrown away."""
        early = get_runtime_store()
        get_audit_log().log("before the load", "/boot", "INTERNAL", "success")

        _app(_config_dir(tmp_path))

        assert _activated() == (early, ("memory",))
        assert get_audit_log().get_entries(event_type="before the load")

    def test_what_is_recorded_between_preparing_and_publishing_is_kept(self, tmp_path):
        """Nobody had asked for a store when the first load began. Between
        preparing it and publishing it the load configures the hooks, and a
        plugin's configure() may record an event: it lands in the store that
        is then published, not in one the publication throws away."""
        settings = ConfigManager(str(_config_dir(tmp_path))).settings
        runtime_store_module._runtime_store = runtime_store_module._runtime_store_inputs = None

        publish = activate_runtime_store(settings)
        get_audit_log().log("while the hooks are configured", "/boot", "INTERNAL", "success")
        publish()

        assert get_audit_log().get_entries(event_type="while the hooks are configured")

    def test_the_first_activation_of_another_backend_replaces_it_and_is_no_restart(self, tmp_path, another_backend):
        early = get_runtime_store()
        settings = ConfigManager(str(_config_dir(tmp_path))).settings

        activate_runtime_store(_asking_for(settings, "another"))()

        assert _activated() == (another_backend[0], ("another",))
        assert another_backend[0] is not early

    def test_the_getter_never_reads_the_configuration(self, monkeypatch):
        """It is called while the configuration is being built (the audit of
        a plugin's load hook), so it must not ask for it."""
        import nanoidp.config as config_module

        def no(*args, **kwargs):
            raise AssertionError("get_runtime_store() read the configuration")

        monkeypatch.setattr(config_module, "get_config", no)
        monkeypatch.setattr(config_module, "get_config_if_loaded", no)

        assert isinstance(get_runtime_store(), MemoryRuntimeStore)

    def test_a_configuration_manager_without_the_activation_step_governs_nothing(self, tmp_path):
        """Built by hand, as tests and tools do: it is not the process's
        configuration, and the store stays provisional."""
        early = get_runtime_store()

        ConfigManager(str(_config_dir(tmp_path)))

        assert _activated() == (early, None)

    def test_both_compositions_activate_the_store(self, tmp_path, monkeypatch):
        from nanoidp import mcp_server

        monkeypatch.setenv("NANOIDP_CONFIG_DIR", str(_config_dir(tmp_path)))
        mcp_server._ensure_config()

        assert _activated()[1] == ("memory",)


class TestTheServicesKnowTheContractsOnly:
    _BACKENDS = {"runtime_repository.py", "runtime_store.py", "audit_store.py"}

    def test_no_consumer_names_a_backend(self):
        """A second backend changes nothing in a service: they are written
        against RuntimeStore, RuntimeRepository and AuditStore. The backend
        modules themselves are, of course, where the backends are."""
        services = _REPO / "src" / "nanoidp" / "services"
        named = []
        for path in sorted(services.glob("*.py")):
            if path.name in self._BACKENDS:
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Name) and node.id.startswith("Memory"):
                    named.append(f"{path.name}:{node.lineno} {node.id}")
                elif isinstance(node, ast.alias) and node.name.startswith("Memory"):
                    named.append(f"{path.name} imports {node.name}")

        assert named == []

    def test_the_activation_state_is_no_part_of_a_store(self):
        store: RuntimeStore = MemoryRuntimeStore()

        assert not hasattr(store, "activated_inputs")
        assert store.users is not None and store.clients is not None and store.audit is not None
