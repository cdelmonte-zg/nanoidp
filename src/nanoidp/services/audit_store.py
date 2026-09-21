"""
The audit behind the runtime boundary (#363): its event, its contract and the
in-memory backend.

"Behind the runtime boundary" does not mean "inside ``RuntimeRepository``".
An audit is not a collection of named objects somebody decides about: it is a
bounded sequence that is appended to on every request, read with filters, and
counted. So it has a small contract of its own, ``AuditStore``, and the
runtime store owns one next to its repositories.

What the contract says, for every backend:

- **The event and its counters are one step.** A reader never finds an event
  that has not been counted.
- **The order is the order of the appends**, not the order of the
  timestamps: events of one timestamp, and a clock that steps back, read
  newest append first like everything else. What keeps that order is the
  backend's business and not a field of the event: here the deque is the
  sequence, and a backend with rows assigns a number in the transaction of
  the append (#354).
- **The bound belongs to the backend.** Past it the oldest event goes, and no
  counter goes with it.
- **The backend knows no counter by name.** Which ones an event increments is
  the service's rule; the store keeps the ones that were ever incremented.
- **The details of an event are a JSON object**: text keys, and values that
  are text, numbers (finite), booleans, null, lists and objects of the same.
  That is the domain of the contract, and every call site stays inside it
  (the suite's ``verify_codecs`` holds them to it). What is outside it is not
  a capability of an ``AuditStore``: a backend that writes the event down
  refuses it before any event or counter changes (#354, third step). That the
  in-memory backend copies a set or a tuple all the same is its own extra
  behaviour, which no caller may ask of another backend.
- **By value**, for every event in the domain: what is appended is copied in,
  what is read is copied out.
- **Not from inside a repository decision**, reads included (#404): a decision
  depends on its view and on what it captured, may be run again, and has no
  effect outside the view.

And one thing it deliberately does not say: that it shares the repositories'
lock. One runtime boundary is not one mutex. No operation has to be atomic
across the audit and a repository, and every request appends here, so the
in-memory backend has a lock of its own and does not wait for a decision (or
for a repository's sweep, #417).
"""

import copy
import json
import math
import sys
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Protocol, Sequence

from .runtime_repository import RepositorySwitches, refuse_inside_a_decision

# How many events the in-memory backend keeps. Read when a store is made.
MAX_AUDIT_ENTRIES = 1000


@dataclass
class AuditEntry:
    """Represents a single audit log entry."""

    timestamp: datetime
    event_type: str
    username: Optional[str]
    client_id: Optional[str]
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    status: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "username": self.username,
            "client_id": self.client_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "endpoint": self.endpoint,
            "method": self.method,
            "status": self.status,
            "details": self.details,
        }


_ATOMS = (str, int, float, bool, type(None))


def _plain_copy(value: Any) -> Any:
    """A copy of the details. What JSON can hold, which is all the details
    ever held (#363's census), is copied by hand, without the cost of
    ``copy.deepcopy`` on every request; anything else (a set, a tuple with a
    dict in it, a subclass) is still copied, by ``deepcopy``: by value holds
    for whatever is there, and whether it may be there is the codec's to
    say, not the copy's."""
    kind = type(value)
    if kind in _ATOMS:
        return value
    if kind is dict:
        return {key: _plain_copy(item) for key, item in value.items()}
    if kind is list:
        return [_plain_copy(item) for item in value]
    return copy.deepcopy(value)


def outside_the_domain(details: Any) -> Optional[str]:
    """What in ``details`` is outside the contract's domain (a JSON object),
    or None when nothing is. What JSON would change is outside it too, not
    only what it cannot write: a tuple read back as a list, a key that is a
    number read back as text, is no longer by value."""
    if not isinstance(details, dict):
        return f"the details are a {type(details).__name__}, not a JSON object"
    return _outside(details, "details")


def _outside(value: Any, where: str) -> Optional[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                return f"{where} has a key that is a {type(key).__name__}, not text"
            found = _outside(item, f"{where}[{key!r}]")
            if found is not None:
                return found
        return None
    if isinstance(value, list):
        for index, item in enumerate(value):
            found = _outside(item, f"{where}[{index}]")
            if found is not None:
                return found
        return None
    if isinstance(value, float):
        return None if math.isfinite(value) else f"{where} is {value!r}, which JSON has no number for"
    if value is None or isinstance(value, (str, int)):
        return None
    return f"{where} is a {type(value).__name__}"


def checked_increments(increments: Sequence[str]) -> List[str]:
    """The names of the counters an append adds one to, each as often as it
    is named."""
    if isinstance(increments, str) or not all(isinstance(name, str) for name in increments):
        raise TypeError("the counters to increment are a sequence of names")
    return list(increments)


def checked_bound(max_entries: Optional[int]) -> int:
    """How many events a backend keeps: ``MAX_AUDIT_ENTRIES`` unless it is
    given, and then a whole number, not below zero, that a count of events
    can reach (``sys.maxsize``)."""
    if max_entries is None:
        return MAX_AUDIT_ENTRIES
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 0 <= max_entries <= sys.maxsize:
        raise ValueError(f"a bound is a whole number from 0 to {sys.maxsize}, not {max_entries!r}")
    return max_entries


def checked_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"a limit is a whole number, not below zero, not {limit!r}")
    return limit


class AuditEntryCodec:
    """How an event is copied, written down and read back: the timestamp as
    ISO 8601, the details as the JSON they already are."""

    def copy(self, value: AuditEntry) -> AuditEntry:
        # Spelled out: ``dataclasses.replace`` costs several times as much,
        # and this runs for every event appended and every event read.
        return AuditEntry(
            timestamp=value.timestamp,
            event_type=value.event_type,
            username=value.username,
            client_id=value.client_id,
            ip_address=value.ip_address,
            user_agent=value.user_agent,
            endpoint=value.endpoint,
            method=value.method,
            status=value.status,
            details=_plain_copy(value.details),
        )

    def dump(self, value: AuditEntry) -> Any:
        return value.to_dict()

    def load(self, data: Any) -> AuditEntry:
        return AuditEntry(**{**data, "timestamp": datetime.fromisoformat(data["timestamp"])})


class AuditStore(Protocol):
    """Where the audit is kept. See the module docstring for what every
    backend promises."""

    def append(self, entry: AuditEntry, increments: Sequence[str]) -> None:
        """Keep the event and add one to each counter named, as one step."""

    def entries(
        self,
        limit: int,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> List[AuditEntry]:
        """At most ``limit`` events, newest append first, of those that match
        every filter given. ``limit`` is a whole number, not below zero:
        ValueError otherwise, so that no backend gives "-1" a meaning."""

    def client_ids(self) -> List[str]:
        """The distinct client ids of the events kept, sorted."""

    def counters(self) -> Dict[str, int]:
        """Every counter ever incremented since the last ``clear``."""

    def clear(self) -> None:
        """Forget the events and the counters."""


class MemoryAuditStore:
    """The audit in process memory, behind a lock of its own."""

    # This backend copies and never writes an event down, so details outside
    # the domain would go unnoticed here. With the switch every store shares
    # (``RepositorySwitches.verify_codecs``, on in the suite), every event
    # appended is first taken through dump, JSON and load, and must come back
    # equal.

    def __init__(self, max_entries: Optional[int] = None) -> None:
        self._lock = threading.Lock()
        self._codec = AuditEntryCodec()
        # In the order of the appends, newest last: the deque is the sequence.
        self._events: Deque[AuditEntry] = deque(maxlen=checked_bound(max_entries))
        self._counters: Dict[str, int] = {}

    def _stored(self, entry: AuditEntry) -> AuditEntry:
        """The copy of ``entry`` the store keeps."""
        if not isinstance(entry, AuditEntry):
            raise TypeError(f"an audit event is an AuditEntry, not {type(entry).__name__}")
        if RepositorySwitches.verify_codecs:
            try:
                written = json.dumps(self._codec.dump(entry), allow_nan=False)
                read_back = self._codec.load(json.loads(written))
            except Exception as failure:
                raise ValueError(f"the audit event does not survive its codec: {failure}") from failure
            if read_back != entry:
                raise ValueError("the audit event does not survive its codec: it comes back changed")
        return self._codec.copy(entry)

    def append(self, entry: AuditEntry, increments: Sequence[str]) -> None:
        refuse_inside_a_decision()
        names = checked_increments(increments)
        stored = self._stored(entry)
        with self._lock:
            self._events.append(stored)
            for name in names:
                self._counters[name] = self._counters.get(name, 0) + 1

    def entries(
        self,
        limit: int,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> List[AuditEntry]:
        refuse_inside_a_decision()
        checked_limit(limit)
        # The lock is held for the snapshot and nothing else: every request
        # appends, and must not wait for a reader's filters. An event that
        # is kept is never changed, only dropped, so what was there stays
        # what it was while it is looked through and copied.
        with self._lock:
            kept = list(self._events)
        found: List[AuditEntry] = []
        for stored in reversed(kept):
            if len(found) == limit:
                break
            if event_type is not None and stored.event_type != event_type:
                continue
            if username is not None and stored.username != username:
                continue
            if client_id is not None and stored.client_id != client_id:
                continue
            found.append(self._codec.copy(stored))
        return found

    def client_ids(self) -> List[str]:
        refuse_inside_a_decision()
        with self._lock:
            kept = list(self._events)
        return sorted({stored.client_id for stored in kept if stored.client_id})

    def counters(self) -> Dict[str, int]:
        refuse_inside_a_decision()
        with self._lock:
            return dict(self._counters)

    def clear(self) -> None:
        refuse_inside_a_decision()
        with self._lock:
            self._events.clear()
            self._counters = {}
