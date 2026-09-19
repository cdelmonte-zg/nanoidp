"""The runtime identity store (#235): users and clients created while the
IdP runs, as opposed to the ones declared in the YAML files.

Runtime objects are execution state: disposable test identities that live in
process memory and never touch the declared configuration unless one is
explicitly promoted (#192). The store holds ``users`` and ``clients`` as
named attributes, and lends the same machinery to a service that owns a
record type of its own through ``repository()`` (#190's dynamic client
registrations, #196's CIMD cache): same lock, same by-value contract,
without this module importing that type. Authorization codes, device codes,
revocations and the audit keep their own stores.

The store knows nothing about declared configuration. The precedence rule
(declared first), the collision rule on creation and the reconciliation on
reload live in ``services.identities``, the one place that composes the two.
"""

import threading
from typing import Any, Callable, Dict, Optional, cast

from ..config import OAuthClient, User
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
    "MemoryRuntimeIdentityStore",
    "MemoryRuntimeRepository",
    "PydanticCodec",
    "RuntimeObjectExists",
    "RuntimeRepository",
    "get_runtime_identity_store",
]


class MemoryRuntimeIdentityStore:
    """Runtime users and clients in process memory, behind one lock."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users: MemoryRuntimeRepository[User] = MemoryRuntimeRepository(
            self._lock, lambda user: user.username, PydanticCodec(User)
        )
        self.clients: MemoryRuntimeRepository[OAuthClient] = MemoryRuntimeRepository(
            self._lock, lambda client: client.client_id, PydanticCodec(OAuthClient)
        )
        self._lent: Dict[str, MemoryRuntimeRepository[Any]] = {}

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


_runtime_identity_store: Optional[MemoryRuntimeIdentityStore] = None
_runtime_identity_store_lock = threading.Lock()


def get_runtime_identity_store() -> MemoryRuntimeIdentityStore:
    """The runtime identity store of this process (thread-safe lazy init)."""
    global _runtime_identity_store
    if _runtime_identity_store is None:
        with _runtime_identity_store_lock:
            if _runtime_identity_store is None:
                _runtime_identity_store = MemoryRuntimeIdentityStore()
    return _runtime_identity_store
