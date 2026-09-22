"""The runtime store: the state of a running IdP that is not declared in the
YAML files. It began as the runtime identity store (#235), users and clients
created while the IdP runs, and since #363 holds the protocol state and the
audit as well.

Runtime objects are execution state: disposable test identities that live in
process memory and never touch the declared configuration unless one is
explicitly promoted (#192). The store holds ``users`` and ``clients`` as
named attributes, and lends the same machinery to a service that owns a
record type of its own through ``repository()`` (#190's dynamic client
registrations, #196's CIMD cache): same lock, same by-value contract,
without this module importing that type. Authorization codes are kept that
way too, device codes with the index of their user codes, and the
revocations of tokens and rotation families (#363).

The audit is here too, as ``audit``, and is not a repository: it has a
contract of its own (``audit_store.AuditStore``) and, in memory, a lock of its
own. The repository state shares one lock; the audit is owned by the same
runtime store and is a concurrency domain of its own, because no operation
has to be atomic across the two. Resetting the store resets both; ``DELETE
/api/runtime`` removes runtime users and clients and nothing else.

The store knows nothing about declared configuration. The precedence rule
(declared first), the collision rule on creation and the reconciliation on
reload live in ``services.identities``, the one place that composes the two.

Which store a process uses is the configuration's to say (``runtime.store``,
#354), and it is said once. The store is activated with the configuration,
next to the signing service: prepared from the candidate settings before
anything is committed, published once nothing can fail. A reload that asks for
another store is refused: the processes that share one would otherwise be
split between two runtime universes. Before the first activation there is a
provisional memory store for whoever asks (the audit of a plugin's load hook),
which the first activation adopts when it asks for memory.
"""

import threading
from typing import Any, Callable, Dict, Optional, Protocol, Tuple, cast

from ..config import OAuthClient, Settings, User, get_config_if_loaded
from .audit_store import AuditStore, MemoryAuditStore
from .runtime_repository import (
    Codec,
    MemoryRuntimeRepository,
    PydanticCodec,
    RuntimeObjectExists,
    RuntimeRepository,
    T,
    refuse_inside_a_decision,
)

# The repository itself, its contract and its in-memory backend live in
# ``runtime_repository`` (#404); they are named here because this is where
# callers have always found them.
__all__ = [
    "MemoryRuntimeStore",
    "MemoryRuntimeRepository",
    "PydanticCodec",
    "RuntimeObjectExists",
    "RuntimeRepository",
    "RuntimeStore",
    "RuntimeStoreRestartRequired",
    "activate_runtime_store",
    "get_runtime_store",
]


class RuntimeStore(Protocol):
    """What the services know of the runtime store: its repositories and its
    audit, by their contracts. No backend is named outside the backend
    modules, and nothing here says how a store came to be the process's:
    that is the activation's business (see below)."""

    # Read-only to a consumer: a service uses the store's repositories and
    # never replaces them (and a backend keeps its own kind of repository).
    @property
    def users(self) -> RuntimeRepository[User]: ...

    @property
    def clients(self) -> RuntimeRepository[OAuthClient]: ...

    @property
    def audit(self) -> AuditStore: ...

    @property
    def shared(self) -> bool:
        """Whether other processes use this store too (#354, step 4a). They
        then share the declared configuration's consequences, and each has
        to see the files as they are, at the start of every operation."""
        ...

    def repository(self, name: str, key_of: Callable[[T], str], codec: Codec[T]) -> RuntimeRepository[T]:
        """The repository a service keeps under ``name``, created once."""


class MemoryRuntimeStore:
    """The runtime state of this process, in memory: two concurrency domains
    under one owner. The repository state (users, clients and every
    repository lent to a service) shares one lock; the audit is owned by the
    same store and has a lock of its own (``audit_store``), because nothing
    has to be atomic across the two and every request appends to it."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.audit: AuditStore = MemoryAuditStore()
        self.users: MemoryRuntimeRepository[User] = MemoryRuntimeRepository(
            self._lock, lambda user: user.username, PydanticCodec(User)
        )
        self.clients: MemoryRuntimeRepository[OAuthClient] = MemoryRuntimeRepository(
            self._lock, lambda client: client.client_id, PydanticCodec(OAuthClient)
        )
        self._lent: Dict[str, MemoryRuntimeRepository[Any]] = {}

    @property
    def shared(self) -> bool:
        # This process's alone.
        return False

    def repository(
        self, name: str, key_of: Callable[[T], str], codec: Codec[T]
    ) -> MemoryRuntimeRepository[T]:
        """The repository a service keeps here under ``name``, created once.

        For runtime state that belongs to one service rather than to the
        identity model: #190 keeps its registration records this way. The
        store holds the state and the lock, the service owns the type and
        the rules, and this module stays free of both. ``codec`` is how
        that type is copied, written down and read back (#404): the service
        says it, so that no backend has to guess what it is keeping.

        Not from inside a decision: the first call creates the repository,
        which is an effect outside the decision's view like any other.
        """
        refuse_inside_a_decision()
        with self._lock:
            existing = self._lent.get(name)
            if existing is None:
                existing = MemoryRuntimeRepository(self._lock, key_of, codec)
                self._lent[name] = existing
            return cast(MemoryRuntimeRepository[T], existing)


# What a store is built from: the kind first, then whatever else that kind
# needs to be the same store (a path, for a backend that has one). Two
# configurations with equal inputs share one store.
RuntimeStoreInputs = Tuple[str, ...]

# How each kind is built, from the settings. Internal, not a plugin API: a
# kind is added with its backend, and a kind is named in the schema
# (models.RuntimeStoreKind) only once it is here.
_RUNTIME_STORE_FACTORIES: Dict[str, Callable[[Settings], RuntimeStore]] = {
    "memory": lambda settings: MemoryRuntimeStore(),
}

# The store of this process, and the inputs it was activated with. Kept apart:
# being the activated store is the lifecycle's business and no property of a
# store. Inputs of None mean that no configuration has chosen yet, and the
# store there is provisional.
_runtime_store: Optional[RuntimeStore] = None
_runtime_store_inputs: Optional[RuntimeStoreInputs] = None
_runtime_store_lock = threading.Lock()


class RuntimeStoreRestartRequired(ValueError):
    """A configuration asked for another runtime store than the one in use."""


def runtime_store_inputs(settings: Settings) -> RuntimeStoreInputs:
    """What the store these settings ask for is built from."""
    return (settings.runtime_store,)


def prepare_runtime_store(settings: Settings) -> Tuple[RuntimeStore, RuntimeStoreInputs]:
    """The store the candidate settings need, and its inputs, prepared
    and not activated: only ``publish_runtime_store`` makes a store the
    process's configured choice, by recording the inputs it was chosen
    with. Until then they stay None, whatever happens here.

    The store in use when the inputs are the ones in force. A refusal when
    they are not, before anything is built for them. Before the first
    activation, and asking for memory: the provisional store, which this
    may bring into existence if nobody has asked for one yet (so that what
    is recorded between preparing and publishing lands in the store that
    is published); that is the one global effect, and the same one any
    ``get_runtime_store()`` has. Asking for another kind: a new store of
    that kind, built aside and published by nobody.

    So a load that fails after this leaves no configured choice behind: at
    most a provisional store, which is what there was before or what the
    next reader would have made.
    """
    wanted = runtime_store_inputs(settings)
    with _runtime_store_lock:
        store, inputs = _runtime_store, _runtime_store_inputs
    if store is not None and inputs is not None:
        if wanted != inputs:
            raise RuntimeStoreRestartRequired(
                f"runtime.store asks for {_described(wanted)} while this process uses {_described(inputs)}: "
                "the runtime store is chosen when the process starts, so restart it to change it"
            )
        return store, inputs
    if wanted == ("memory",):
        # The provisional store, made now if nobody has asked for one yet:
        # between preparing and publishing, the load configures the hooks,
        # and whatever a plugin records then must land in the store that is
        # published, not in one the publication would replace. Making it
        # activates nothing: the inputs stay None until the publication.
        provisional = get_runtime_store()
        if isinstance(provisional, MemoryRuntimeStore):
            return provisional, wanted
    factory = _RUNTIME_STORE_FACTORIES.get(wanted[0])
    if factory is None:
        raise ValueError(f"runtime.store: {wanted[0]} is not a runtime store nanoidp has")
    return factory(settings), wanted


def publish_runtime_store(store: RuntimeStore, inputs: RuntimeStoreInputs) -> None:
    """Make ``store`` the one every reader gets from get_runtime_store(),
    chosen by a configuration."""
    global _runtime_store, _runtime_store_inputs
    with _runtime_store_lock:
        _runtime_store, _runtime_store_inputs = store, inputs


def activate_runtime_store(settings: Settings) -> Callable[[], None]:
    """The configuration activation step for the runtime store (#354): the
    store is prepared now, and the returned function publishes it once the
    load can no longer fail."""
    store, inputs = prepare_runtime_store(settings)
    return lambda: publish_runtime_store(store, inputs)


def _described(inputs: RuntimeStoreInputs) -> str:
    return " at ".join(inputs)


def get_runtime_store() -> RuntimeStore:
    """The runtime store of this process: the one a configuration activated,
    or, before any did, a provisional memory store (thread-safe lazy init).

    It never reads the configuration: it is called while the configuration
    is being built (the audit of a plugin's load hook), and a configuration
    manager built without the activation step is not the process's to
    govern the store by.
    """
    global _runtime_store
    store = _runtime_store
    if store is not None:
        return store
    with _runtime_store_lock:
        if _runtime_store is None:
            _runtime_store = MemoryRuntimeStore()
        return _runtime_store


def fresh_configuration() -> None:
    """At the start of an operation: when the store is shared with other
    processes, adopt the configuration files if one of them changed them
    (#354, step 4a). Nothing with a store of this process's alone, nor before
    a configuration is loaded. May raise LockUnavailableError, which is
    temporary."""
    if not get_runtime_store().shared:
        return
    config = get_config_if_loaded()
    if config is not None:
        config.refresh_if_changed()
