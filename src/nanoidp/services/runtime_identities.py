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
from typing import Any, Callable, Dict, Generic, List, Optional, Protocol, TypeVar, cast

from pydantic import BaseModel

from ..config import OAuthClient, User

# Any pydantic model: the repository needs a deep copy and a name, nothing
# else, so naming the two types that happened to exist first would only
# describe the day it was written (#190).
T = TypeVar("T", bound=BaseModel)


class RuntimeObjectExists(ValueError):
    """A runtime object with that name is already in the repository."""


class RuntimeRepository(Protocol[T]):
    """The operations a runtime repository offers; a later durable backend
    (#354) implements the same contract (tests/test_runtime_identities.py).

    By value: every object handed in or out is a copy, so changing one never
    changes the repository. A change is a delete and a create.
    """

    def create(self, obj: T) -> T:
        """Store ``obj``; raises RuntimeObjectExists when its name is taken."""

    def get(self, name: str) -> Optional[T]:
        """The object with that name, or None."""

    def list(self) -> List[T]:
        """Every object, in creation order."""

    def delete(self, name: str) -> bool:
        """Remove the object with that name; False when there was none."""

    def delete_all(self) -> int:
        """Remove every object and return how many there were."""


class MemoryRuntimeRepository(Generic[T]):
    """A runtime repository in process memory, keyed by the object's name."""

    def __init__(self, lock: threading.RLock, name_of: Callable[[T], str]) -> None:
        self._lock = lock
        self._name_of: Callable[[T], str] = name_of
        self._objects: Dict[str, T] = {}

    def create(self, obj: T) -> T:
        name = self._name_of(obj)
        with self._lock:
            if name in self._objects:
                raise RuntimeObjectExists(f"runtime object {name!r} already exists")
            # By value, both ways: neither the caller's instance nor the one
            # returned is the stored one, as with a backend that serializes.
            stored = obj.model_copy(deep=True)
            self._objects[name] = stored
            return stored.model_copy(deep=True)

    def get(self, name: str) -> Optional[T]:
        with self._lock:
            stored = self._objects.get(name)
            return stored.model_copy(deep=True) if stored is not None else None

    def list(self) -> List[T]:
        with self._lock:
            return [obj.model_copy(deep=True) for obj in self._objects.values()]

    def delete(self, name: str) -> bool:
        with self._lock:
            return self._objects.pop(name, None) is not None

    def delete_all(self) -> int:
        with self._lock:
            count = len(self._objects)
            self._objects.clear()
            return count


class MemoryRuntimeIdentityStore:
    """Runtime users and clients in process memory, behind one lock."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users: MemoryRuntimeRepository[User] = MemoryRuntimeRepository(
            self._lock, lambda user: user.username
        )
        self.clients: MemoryRuntimeRepository[OAuthClient] = MemoryRuntimeRepository(
            self._lock, lambda client: client.client_id
        )
        self._lent: Dict[str, MemoryRuntimeRepository[Any]] = {}

    def repository(
        self, name: str, key_of: Callable[[T], str]
    ) -> MemoryRuntimeRepository[T]:
        """The repository a service keeps here under ``name``, created once.

        For runtime state that belongs to one service rather than to the
        identity model: #190 keeps its registration records this way. The
        store holds the state and the lock, the service owns the type and
        the rules, and this module stays free of both.
        """
        with self._lock:
            existing = self._lent.get(name)
            if existing is None:
                existing = MemoryRuntimeRepository(self._lock, key_of)
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
