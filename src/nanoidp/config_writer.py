"""
Single write pipeline with optimistic conflict detection (issue #229).

A root-level module, a peer of ``config.py`` and ``serialization.py`` -
not under ``services/`` - because both ``config.py`` (phase 2) and
``services/yaml_writer.py`` (phase 3) call into it, and the
``[tool.importlinter]`` "layers: routes -> services -> config" contract
in ``pyproject.toml`` puts ``config`` below ``services``: ``config``
importing anything under ``nanoidp.services`` breaks that contract even
as a late/deferred import, since import-linter's static analysis does
not care where in a function the import statement sits (#229 review: a
late import here was exactly this mistake, caught by ``lint-imports`` in
CI, not by pytest or mypy). It cannot live inside ``serialization.py``
either: that module has its own "no runtime package imports" contract
and is meant to stay a stateless pile of pure functions, and a lock plus
``fcntl`` is state.

``ConfigManager.save()`` and ``YamlWriter`` each run their own independent
load -> mutate -> ``atomic_write_yaml`` -> replace cycle against the same
files. Content-shape drift between them is already solved (``OWNED_SETTINGS``,
#226), but neither cycle has any way to notice that the file it is about to
overwrite changed since it was last read - two writers racing (a UI form
submit and a concurrent MCP ``save_config``, say) can silently clobber one
another with no error either side would see.

``compare_and_replace`` is the one place both write paths funnel through
(phases 2-3 migrate them; this module only introduces the primitive). A
caller reads a file, remembers its ``current_revision``, does whatever
in-memory mutation it needs, then calls ``compare_and_replace`` with that
revision as ``expected_revision``. If the file's revision has moved on,
the write is refused with ``ConflictError`` and the file is left untouched;
otherwise the mutation is applied to a freshly loaded document and written
atomically, exactly like the two write paths already do today.

``compare_and_replace_many`` is the same guarantee across several files at
once: every ``expected_revision`` is checked before any file is written, so
a conflict on the second file never leaves the first one already written.
``ConfigManager.save()`` needs this because it writes ``users.yaml`` and
``settings.yaml`` as one coordinated save (#229 review on phase 2,
reproduced: a stale ``settings.yaml`` revision left a fresh ``users.yaml``
on disk and the in-memory settings change silently unsaved). This is a
write-side guarantee only, not the same boundary ``ConfigManager._load_config``
gives reads (#204): ``_stage_directory`` opens both files unlocked, so a
concurrent save() in another process can still pair an old settings.yaml
with a new users.yaml on the read side (#229 review round 4).
``compare_and_replace`` is the ``len(items) == 1`` case of the same
function.

``expected_revision=None`` means unconditional - today's last-write-wins -
so a caller that hasn't been migrated to pass a revision yet keeps its
current behaviour exactly.

A revision is the sha256 of the file's raw on-disk bytes, not a hash of the
parsed document: hashing what's actually on disk means any two readers of
the same file always compute the same revision, with no dependence on
ruamel's dump formatting.

The check-load-mutate-write sequence runs under two locks, both held for
the whole section (single file or many) and both deliberately one lock
for every file in a directory rather than one per path (``save()``
writes two files back to back, ``reload_local()`` stages the whole
directory (#204), and #192 will need a cross-file check that only works
under one lock each). ``compare_and_replace_many`` locks every distinct
parent directory among its items, in sorted order, so two concurrent
multi-file calls can never deadlock on each other by acquiring the same
two directory locks in opposite order:

- ``_write_lock``, a ``threading.Lock`` (same pattern as ``config.py``'s
  ``_config_lock``), serializing threads within this process.
- an advisory lock on a lock file in the config directory
  (``.nanoidp-write.lock``), serializing separate OS processes - the
  actual case #229 was opened for (a UI worker and an MCP process, or
  two MCP processes, sharing one config directory). The thread lock
  alone does not cover this: two processes each get their own
  ``_write_lock`` and race exactly as before without the file lock
  (#229 review round 2, reproduced with ``multiprocessing`` and a
  ``Barrier`` - both writers saw "ok", one update silently lost, 10/10
  trials). Both locks are kept, not just the file lock, because a
  second lock acquisition from the same process is not guaranteed to
  exclude the first the way it does across processes (true of both
  ``fcntl.flock``, scoped to the open file description, and
  ``msvcrt.locking``), so cross-thread safety within one process still
  needs the plain thread lock. The backend is ``fcntl.flock`` on POSIX
  and ``msvcrt.locking`` on Windows (``_try_lock_exclusive``/``_unlock``
  below dispatch by ``sys.platform``, #229 review round 8 - a top-level
  unconditional ``import fcntl`` used to break ``import nanoidp.config``
  outright on Windows, a platform ``pyproject.toml`` declares as
  supported). Acquisition is a bounded, polled non-blocking wait, not a
  plain blocking acquisition - it is taken while holding the process-wide
  ``_write_lock``, so an indefinite wait on one stuck peer process would
  otherwise block every writer thread in this process, including ones
  targeting an unrelated directory, with nothing in the logs to explain
  why. A wait past ``_LOCK_TIMEOUT_SECONDS``, or an ``OSError`` that
  means the filesystem does not support advisory locks at all (NFS
  without ``lockd``, some 9p/FUSE bind mounts), raises
  ``LockUnavailableError`` instead of hanging forever or leaking a bare
  ``OSError`` from deep inside a write helper.

Readers do not take the file lock: the atomic replace (``os.replace``)
already guarantees a reader sees a complete file, one revision or the
next, never a partial one - the lock's job is only to make the
check-then-replace section atomic against another writer, not to gate
reads.

Concurrent YAML parsing/dumping is a separate hazard the lock above does
not touch, because reads never take it: ``reload_local()``, every
``YamlWriter`` loader and every other read path call
``serialization.load_yaml_document`` outside this module entirely, so a
lock here could never cover them without every reader taking it too
(which would serialize the whole app's reads against every write, not
just writes against each other). That hazard is closed at the source
instead: ``serialization._new_yaml_rt()`` builds a fresh ``ruamel.yaml``
``YAML`` instance per call rather than sharing one at module scope, since
a shared instance's parser/composer/emitter state is not safe under
concurrent use (#229 review: a shared instance produced 35 errors across
six exception types under a read/write race probe; a fresh instance per
call, zero). ``compare_and_replace`` only needs to be safe against other
callers of itself, which ``_write_lock`` already guarantees; it relies on
the loader/dumper being independently safe against concurrent reads.

Two edge cases worth knowing about, both accepted for a bytes-based
revision: a merely-cosmetic rewrite (e.g. a hand-written file using
4-space sequence indent, where ``_new_yaml_rt()`` always dumps at
``offset=0``) changes the revision on its first save even though nothing
semantic changed - there is no phantom writer, just a formatting
normalization; and a missing file and a zero-byte file share the same
revision (the hash of empty bytes), so ``expected_revision ==
current_revision(missing_path)`` guards "create if still absent" but does
not distinguish "absent" from "present but empty".
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .serialization import atomic_write_yaml, load_yaml_document

# Platform-specific advisory-lock backend (#229 review round 8): fcntl
# does not exist on Windows at all - importing it unconditionally made
# `import nanoidp.config` fail outright on a platform pyproject.toml
# declares as supported. msvcrt.locking is Windows' analogue, dispatched
# by _try_lock_exclusive/_unlock below; both platforms share the same
# bounded-poll retry loop in _cross_process_lock.
if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

logger = logging.getLogger(__name__)

Revision = str

_LOCK_FILENAME = ".nanoidp-write.lock"

# Bounded, visible wait instead of an indefinite LOCK_EX (#229 review,
# non-blocking - applied): _cross_process_lock is taken while holding
# the process-global _write_lock, so an indefinite wait on one stuck
# peer process would block every writer thread in this process, even
# ones targeting an unrelated directory, with no log line to explain why.
_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_POLL_INTERVAL_SECONDS = 0.05

_write_lock = threading.Lock()


class LockUnavailableError(RuntimeError):
    """Raised by ``_cross_process_lock`` when the advisory cross-process
    lock could not be acquired (#229 review, non-blocking - applied):
    either the filesystem does not support advisory locks at all (NFS
    without ``lockd``, some 9p/FUSE bind mounts - a bare ``OSError`` from
    ``flock()`` used to surface directly here, on a path that worked
    before ``compare_and_replace`` existed), or the lock stayed held
    longer than ``_LOCK_TIMEOUT_SECONDS``, typically because a peer
    process is stuck inside its own locked section. Same shape as
    ``ConflictError``/``HookError`` (``message``, ``kind``).
    """

    def __init__(self, message: str, kind: str = "lock_unavailable") -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


def _try_lock_exclusive(fd: int) -> bool:
    """Attempt to acquire the advisory lock on ``fd`` without blocking.

    Dispatches by platform (#229 review round 8): ``fcntl.flock`` on
    POSIX, ``msvcrt.locking`` on Windows - the latter locks a byte range
    at the file's current position rather than the whole file, so every
    caller here always operates from position 0 on a lock file that is
    never otherwise written to, which is equivalent in practice. Returns
    ``True`` if acquired, ``False`` if another holder has it right now
    (POSIX: ``EACCES``/``EAGAIN``; Windows: ``EACCES`` is what
    ``msvcrt.locking`` raises for "would block" too, plus ``EDEADLK`` for
    the case ``msvcrt`` detects as a self-deadlock). Any other
    ``OSError`` - the filesystem does not support advisory locks at all -
    propagates to the caller, which turns it into
    ``LockUnavailableError(kind="lock_unsupported")``.
    """
    if sys.platform == "win32":
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EDEADLK):
                return False
            raise
    else:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise


def _unlock(fd: int) -> None:
    """Release the lock ``_try_lock_exclusive`` acquired on ``fd``."""
    if sys.platform == "win32":
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def _cross_process_lock(directory: Path) -> Iterator[None]:
    """Advisory, cross-process exclusive lock for one config directory.

    One lock file per directory (not per target file, same reasoning as
    ``_write_lock``), opened fresh and locked for the duration of the
    caller's section, released in ``finally`` even if the caller raises
    (a stale lock file left over from a partial write is harmless - it
    is never read for content, only locked).

    Acquisition polls ``_try_lock_exclusive`` rather than blocking
    indefinitely, so a stuck peer is a bounded, logged wait
    (``LockUnavailableError`` after ``_LOCK_TIMEOUT_SECONDS``) instead of
    an indefinite hang with no explanation. An ``OSError`` that isn't
    "someone else holds it" means the filesystem itself does not support
    advisory locks here, and is reported as ``LockUnavailableError``
    immediately rather than as a bare ``OSError`` from deep inside a
    write helper.
    """
    lock_path = directory / _LOCK_FILENAME
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        warned = False
        while True:
            try:
                if _try_lock_exclusive(fd):
                    break
            except OSError as exc:
                raise LockUnavailableError(
                    f"Advisory locking is not supported on {lock_path} "
                    f"({exc}) - {directory} may be on a filesystem "
                    "without advisory-lock support (e.g. NFS without lockd)",
                    kind="lock_unsupported",
                ) from exc
            if time.monotonic() >= deadline:
                raise LockUnavailableError(
                    f"Timed out after {_LOCK_TIMEOUT_SECONDS}s waiting for "
                    f"the write lock on {directory} - another process may "
                    "be stuck holding it",
                    kind="lock_timeout",
                )
            if not warned:
                logger.warning(f"Waiting for the write lock on {directory}...")
                warned = True
            time.sleep(_LOCK_POLL_INTERVAL_SECONDS)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


class ConflictError(RuntimeError):
    """Raised by ``compare_and_replace`` when ``expected_revision`` no longer
    matches the file's on-disk revision - someone else wrote it first.

    Same shape as ``hooks.HookError`` (``message``, ``kind``) so each
    surface's existing except-clause pattern (UI flash, MCP ``is_error``)
    extends to a conflict without new branching logic.
    """

    def __init__(self, message: str, kind: str = "conflict") -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


def _read_bytes(file_path: Path) -> bytes:
    if not file_path.exists():
        return b""
    return file_path.read_bytes()


def revision_of_bytes(raw: bytes) -> Revision:
    """The revision of content a caller has already read.

    One recipe for the whole codebase: a reader that parses raw bytes
    itself (ConfigManager._stage_directory, #229 phase 5) must hash the
    bytes it actually parsed, not re-read the file - a second read could
    hash different content than what its parse saw.
    """
    return hashlib.sha256(raw).hexdigest()


def current_revision(file_path: Path) -> Revision:
    """The revision a reader hands back later as ``expected_revision``.

    A missing file has a well-defined revision (the hash of empty bytes),
    so a caller can request "only create this if it still doesn't exist".
    """
    return revision_of_bytes(_read_bytes(file_path))


WriteItem = Tuple[Path, Optional[Revision], Callable[[Dict[str, Any]], Any]]


def compare_and_replace(
    file_path: Path,
    expected_revision: Optional[Revision],
    mutate: Callable[[Dict[str, Any]], Any],
) -> Revision:
    """Load, optionally check, mutate, atomically replace; return the new revision.

    ``mutate`` receives the freshly loaded document (a ruamel
    ``CommentedMap``, via ``load_yaml_document``) and edits it in place;
    its return value is ignored. It only runs, and the file is only
    written, after the revision check passes - a conflict never leaves a
    partial write or a half-applied mutation. The single-item case of
    ``compare_and_replace_many``.
    """
    return compare_and_replace_many([(file_path, expected_revision, mutate)])[0]


def compare_and_replace_many(items: Sequence[WriteItem]) -> List[Revision]:
    """``compare_and_replace`` across several files as one coordinated,
    conflict-checked batch - not a filesystem transaction (see below).

    Every item's ``expected_revision`` is checked - against every file's
    on-disk revision - before any file is loaded, and every ``mutate``
    runs, against its own freshly loaded document, before any file is
    written: a conflict, or a ``mutate`` that raises, leaves every file
    in the batch untouched, the same way a single ``compare_and_replace``
    call never leaves a partial write within one file. Only an I/O
    failure on an individual ``atomic_write_yaml`` call can still leave
    an earlier item in the batch written while a later one is not - there
    is no single filesystem operation spanning multiple files, just
    three passes ordered to keep every failure mode except that one from
    reaching disk at all. Items are otherwise independent: different
    files, different ``mutate`` callables, processed in the order given.
    Returns each item's new revision, in that same order.

    Raises ``ValueError`` if ``items`` repeats a path: two items on the
    same file would each load and mutate their own independent copy of
    that document, and whichever writes second would silently discard
    the first's mutation - there is no caller of this today, but nothing
    else here would catch the mistake.
    """
    paths = [file_path for file_path, _, _ in items]
    if len(paths) != len(set(paths)):
        raise ValueError(f"compare_and_replace_many got a repeated path: {paths}")

    directories = sorted({file_path.parent for file_path, _, _ in items}, key=str)
    with _write_lock, contextlib.ExitStack() as stack:
        for directory in directories:
            stack.enter_context(_cross_process_lock(directory))

        # Phase 1: every precondition checked before anything is loaded.
        for file_path, expected_revision, _mutate in items:
            actual = current_revision(file_path)
            if expected_revision is not None and expected_revision != actual:
                raise ConflictError(
                    f"{file_path.name} changed since it was last read "
                    f"(expected revision {expected_revision[:12]}, found {actual[:12]})"
                )

        # Phase 2: every document loaded and mutated - nothing written
        # yet, so a mutate that raises leaves every file untouched too.
        loaded = []
        for file_path, _expected_revision, mutate in items:
            document = load_yaml_document(file_path)
            mutate(document)
            loaded.append((file_path, document))

        # Phase 3: every mutated document written.
        new_revisions = []
        for file_path, document in loaded:
            atomic_write_yaml(file_path, document)
            new_revisions.append(current_revision(file_path))
        return new_revisions
