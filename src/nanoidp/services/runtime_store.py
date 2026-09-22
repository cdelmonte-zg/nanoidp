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

import logging
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, Iterator, Optional, Protocol, Tuple, cast

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

logger = logging.getLogger(__name__)

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

    def claim_owner(self) -> Optional[str]:
        """Who a claim made now belongs to, when others may have to prove it
        dead (#354, step 4b): this process, in a store it shares. None in a
        store that dies with the process, where nobody ever has to."""

    def prove_owner_dead(self, owner: Optional[str]) -> ContextManager[bool]:
        """Whether the owner of a claim is proved dead, and, when it is by a
        lock, held so until the block is done. Never by a timeout."""

    def owner_may_be_dead(self, owner: Optional[str]) -> bool:
        """Whether the owner of a claim could be proved dead now; nothing is
        held or removed. False means nothing about the claim is recoverable
        now, whatever the configuration says."""


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

    def claim_owner(self) -> Optional[str]:
        # A claim here dies with the process that made it and the store.
        return None

    @contextmanager
    def prove_owner_dead(self, owner: Optional[str]) -> Iterator[bool]:
        yield False

    def owner_may_be_dead(self, owner: Optional[str]) -> bool:
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

def _sqlite_store(inputs: RuntimeStoreInputs) -> RuntimeStore:
    from .sqlite_runtime_store import SqliteRuntimeStore

    return SqliteRuntimeStore(Path(inputs[1]))


# How each kind is built, from its inputs (already resolved: a factory never
# looks at a path of its own). Internal, not a plugin API: a kind is added
# with its backend, and a kind is named in the schema (models.RuntimeStoreKind)
# only once it is here.
_RUNTIME_STORE_FACTORIES: Dict[str, Callable[[RuntimeStoreInputs], RuntimeStore]] = {
    "memory": lambda inputs: MemoryRuntimeStore(),
    "sqlite": _sqlite_store,
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


def resolved_runtime_path(settings: Settings, config_dir: Optional[Path] = None) -> Optional[Path]:
    """The file of the SQLite runtime store these settings name, as the
    process uses it; None for a store that has no file (#354, step 4c).

    The one place it is resolved: the inputs, the check against the
    configuration directory and what /api/config and MCP report all go
    through here. A relative ``runtime.path`` is relative to the
    configuration directory, not to the process's working directory: it is
    the identity of a store several processes share, and the same
    settings.yaml in the same directory must name the same store however the
    processes were started."""
    if settings.runtime_store != "sqlite":
        return None
    if settings.runtime_path is None:
        # The document cannot say it; settings made in code can, and this is
        # no store without a file.
        raise ValueError("runtime.store: sqlite needs runtime.path, and these settings have none")
    path = Path(settings.runtime_path)
    if not path.is_absolute():
        if config_dir is None:
            raise ValueError(
                f"runtime.path {settings.runtime_path!r} is relative to the configuration directory, "
                "and none was given"
            )
        path = Path(config_dir) / path
    return path.resolve()


def runtime_store_inputs(settings: Settings, config_dir: Optional[Path] = None) -> RuntimeStoreInputs:
    """What the store these settings ask for is built from: the kind, and
    for SQLite the file, resolved."""
    path = resolved_runtime_path(settings, config_dir)
    return (settings.runtime_store,) if path is None else (settings.runtime_store, str(path))


def runtime_store_report(settings: Settings, config_dir: Optional[Path] = None) -> Dict[str, str]:
    """What /api/config and MCP say about the runtime store: its kind, and
    for SQLite the file this process uses, resolved as the activation
    resolves it (the declared value is the settings')."""
    report: Dict[str, str] = {"store": settings.runtime_store}
    with _runtime_store_lock:
        inputs = _runtime_store_inputs
    if inputs is not None and inputs[0] == settings.runtime_store == "sqlite":
        # The file this process opened, not where the path points now (a
        # symlink retargeted since would say another).
        report["path"] = inputs[1]
        return report
    path = resolved_runtime_path(settings, config_dir)
    if path is not None:
        report["path"] = str(path)
    return report


def _outside_the_configuration(path: Path, config_dir: Optional[Path]) -> None:
    """The store's files are a secret of the processes that share it: none
    of them (the database, its audit, its owners' leases) may lie in the
    configuration directory, which is read, copied and committed as
    configuration. Resolved, so that a symlink does not hide it."""
    from .sqlite_runtime_store import audit_path_of, owners_path_of

    if config_dir is None:
        raise ValueError("the SQLite runtime store is activated with its configuration directory")
    configuration = Path(config_dir).resolve()
    for part in (path, audit_path_of(path), owners_path_of(path)):
        resolved = part.resolve()
        if resolved == configuration or configuration in resolved.parents:
            raise ValueError(
                f"runtime.path: {resolved} is inside the configuration directory {configuration}; "
                "the runtime store's files are a secret, and must lie outside it"
            )


def prepare_runtime_store(
    settings: Settings, config_dir: Optional[Path] = None
) -> Tuple[RuntimeStore, RuntimeStoreInputs]:
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
    wanted = runtime_store_inputs(settings, config_dir)
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
    if wanted[0] == "sqlite":
        _outside_the_configuration(Path(wanted[1]), config_dir)
    return factory(wanted), wanted


def publish_runtime_store(store: RuntimeStore, inputs: RuntimeStoreInputs) -> None:
    """Make ``store`` the one every reader gets from get_runtime_store(),
    chosen by a configuration."""
    global _runtime_store, _runtime_store_inputs
    with _runtime_store_lock:
        replaced, replaced_inputs = _runtime_store, _runtime_store_inputs
        _runtime_store, _runtime_store_inputs = store, inputs
    if replaced is not None and replaced is not store and replaced_inputs is None:
        _say_what_the_provisional_store_loses(replaced)


def _say_what_the_provisional_store_loses(provisional: RuntimeStore) -> None:
    """Before the first activation the audit is kept in a provisional store
    in memory; a configuration that asks for another store replaces it, and
    what was recorded there is not carried over (#354, step 2). Said, once,
    here where it happens: at the publication, when nothing can fail any
    more. Never raises."""
    try:
        lost = len(provisional.audit.entries(sys.maxsize))
    except Exception:  # pragma: no cover - a publication must not fail
        return
    if lost:
        logger.warning(
            "%d audit event(s) recorded before the runtime store was activated are not kept: "
            "they were in the provisional store in memory, which the configured store replaces",
            lost,
        )


def activate_runtime_store(settings: Settings, config_dir: Optional[Path] = None) -> Callable[[], None]:
    """The configuration activation step for the runtime store (#354): the
    store is prepared now, and the returned function publishes it once the
    load can no longer fail."""
    store, inputs = prepare_runtime_store(settings, config_dir)
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
