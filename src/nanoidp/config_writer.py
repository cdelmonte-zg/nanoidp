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
write-side guarantee, and since #246 the read side has the matching one:
``ConfigManager._load_config`` observes both files through
``config_store.ConfigFileStore`` under this same lock, so a concurrent
save() in another process can no longer pair an old settings.yaml with a
new users.yaml (it used to, #229 review round 4).
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
  plain blocking acquisition: a stuck peer process must become a bounded,
  logged failure rather than a hang with nothing in the logs to explain
  it. Since #246 the wait no longer holds ``_write_lock`` - the ordering
  is the file lock first, the thread lock second - so a stuck peer stalls
  only callers of the SAME directory instead of every thread in the
  process. A wait past ``_LOCK_TIMEOUT_SECONDS``, or an ``OSError`` that
  means the filesystem does not support advisory locks at all (NFS
  without ``lockd``, some 9p/FUSE bind mounts), raises
  ``LockUnavailableError`` instead of hanging forever or leaking a bare
  ``OSError`` from deep inside a write helper.

Readers took no file lock until #246. The atomic replace (``os.replace``)
already guarantees a reader sees a complete FILE, one revision or the
next, never a partial one, and that was taken to be enough. It is not the
same property as a reader seeing one consistent observation of the
DIRECTORY, which is why ``config_store.ConfigFileStore`` now acquires this
lock for reads too, through ``directory_lock`` below.

Concurrent YAML parsing/dumping is a separate hazard this lock does not
touch, and it survives #246: ``serialization.load_yaml_document`` is still
called directly from outside this module, and a loader has to be safe for
whoever calls it rather than only for callers that happen to hold a lock
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
# non-blocking - applied): a stuck peer must fail with an explanation
# rather than hang silently. The wait is no longer taken while holding
# _write_lock (#246 review): the order is the directory's file lock
# first, the process-global thread lock second, so waiting on another
# process never monopolizes this one.
_LOCK_TIMEOUT_SECONDS = 10.0
# The pause between two tries of the file lock: 1 ms, doubled at every miss,
# 50 ms at most (#426 point 3, measured). A fixed 50 ms made every collision
# cost 50 ms whatever the hold: a freshness read holds the lock for 0.1 ms
# and an ordinary write for 7 ms, so a reader that met a writer, or a writer
# a reader, paid the poll and not the section (p99 31 ms at rest, 82 ms
# under two writes a second). Doubling reaches the cap after 63 ms, so a
# long section (a write of users.yaml with five hundred users holds it for a
# third of a second) and a stuck peer are polled as before.
_LOCK_POLL_INITIAL_SECONDS = 0.001
_LOCK_POLL_MAX_SECONDS = 0.05

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


class LockNamespaceUnavailable(LockUnavailableError):
    """The lock file cannot EXIST through this view of the directory (#246).

    A narrower thing than "the lock could not be acquired": there is nowhere
    to put the lock at all, because this process cannot open or create the
    lock file through this view. Such a view cannot write configuration
    either - ``atomic_write_yaml`` needs the same capability - so no writer
    participating through it can exist, and a reader has nobody to be
    inconsistent with.

    NOT raised for a directory that does not exist: that stays a plain
    ``FileNotFoundError``, the exception the write path has always raised
    for it (#246 review round 3). The read side handles the absent
    directory before it ever reaches the lock, where "every file is
    missing" is the answer rather than an error.

    Deliberately NOT raised for a lock that exists but cannot be opened, for
    a filesystem without advisory locking, or for a timeout. Those mean the
    protocol is available and this process could not join it, which is
    failing to coordinate rather than having nothing to coordinate with, and
    they stay ``LockUnavailableError``. A subclass, so every existing
    handler on the write paths keeps catching it.
    """

    def __init__(self, message: str, kind: str = "lock_namespace_unavailable") -> None:
        super().__init__(message, kind=kind)


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


def _poll_pauses() -> Iterator[float]:
    """The pauses between two tries of the file lock, in order: doubling
    from the initial one up to the cap, then the cap for as long as it
    takes. The deadline, not this, ends the wait."""
    pause = _LOCK_POLL_INITIAL_SECONDS
    while True:
        yield pause
        pause = min(pause * 2, _LOCK_POLL_MAX_SECONDS)


def _unlock(fd: int) -> None:
    """Release the lock ``_try_lock_exclusive`` acquired on ``fd``."""
    if sys.platform == "win32":
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def _write_lock_within(
    deadline: float, lock: Optional[threading.Lock] = None, of: str = "configuration"
) -> Iterator[None]:
    """The process-global thread lock, acquired within the budget the whole
    acquisition shares (#246 review round 2).

    An unbounded ``acquire()`` here would mean holding somebody's file lock
    indefinitely while waiting on a lock of our own, which is the mirror of
    the hazard the ordering fixed: a slow writer on one directory could
    push a peer process writing ANOTHER directory into its timeout. The
    coupling between directories is not removed by this - that needs
    per-directory thread locks, which this finding does not justify - but
    it becomes bounded and explainable rather than open-ended.
    """
    thread_lock = _write_lock if lock is None else lock
    remaining = max(0.0, deadline - time.monotonic())
    if not thread_lock.acquire(timeout=remaining):
        raise LockUnavailableError(
            f"Timed out after {_LOCK_TIMEOUT_SECONDS}s waiting for this "
            f"process's own {of} lock",
            kind="lock_timeout",
        )
    try:
        yield
    finally:
        thread_lock.release()


@contextlib.contextmanager
def _cross_process_lock(directory: Path, deadline: Optional[float] = None) -> Iterator[None]:
    """Advisory, cross-process exclusive lock for one config directory.

    One lock file per directory (not per target file, same reasoning as
    ``_write_lock``), opened fresh and locked for the duration of the
    caller's section, released in ``finally`` even if the caller raises
    (a stale lock file left over from a partial write is harmless - it
    is never read for content, only locked).

    Acquisition polls ``_try_lock_exclusive`` rather than blocking
    indefinitely, pausing 1 ms after the first miss and twice as long
    after each next one up to 50 ms (``_poll_pauses``), so a stuck peer is
    a bounded wait, logged once the pauses have reached the cap
    (``LockUnavailableError`` after ``_LOCK_TIMEOUT_SECONDS``) instead of
    an indefinite hang with no explanation. An ``OSError`` that isn't
    "someone else holds it" means the filesystem itself does not support
    advisory locks here, and is reported as ``LockUnavailableError``
    immediately rather than as a bare ``OSError`` from deep inside a
    write helper.
    """
    lock_path = directory / _LOCK_FILENAME
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError as exc:
        if exc.errno not in (errno.EROFS, errno.EACCES, errno.EPERM):
            raise
        # A read-only view of the directory. The lock file may still be
        # THERE - it usually is, since it is part of whatever content was
        # mounted, and this repository's own config/ has one after any
        # local save - and flock works perfectly well on a descriptor
        # opened read-only, so the protocol is still available and this
        # process still joins it (#246 review round 2; the first fix
        # checked `not lock_path.exists()` and so skipped the concession
        # in exactly the common case, breaking `docker compose up` on any
        # machine that had ever saved configuration).
        if sys.platform == "win32":
            # No read-only fallback here (#246 review round 3):
            # ``msvcrt.locking`` needs a WRITABLE descriptor and answers
            # EACCES on a read-only one, which _try_lock_exclusive reads as
            # "someone else holds it" - so the fallback would poll out the
            # whole timeout and then blame a peer that does not exist. A
            # descriptor this process cannot open for writing means it
            # cannot write configuration through this view either, which is
            # the same conclusion, reached without the wait. ``os.access``
            # is unreliable on Windows, so it is not consulted.
            raise LockNamespaceUnavailable(
                f"{directory} cannot be opened for writing ({exc.strerror}), "
                "so no writer can participate through this view"
            ) from exc
        try:
            fd = os.open(str(lock_path), os.O_RDONLY)
        except OSError:
            # No usable lock file either. Whether that is a view with
            # nothing to coordinate in, or a namespace that is simply
            # broken, is decided by the DIRECTORY, not by the lock file: a
            # writable directory can be written through atomic_write_yaml
            # whatever state the lock file is in, so there really is a
            # writer to be inconsistent with and this must fail closed
            # (#246 review).
            if os.access(directory, os.W_OK):
                raise
            raise LockNamespaceUnavailable(
                f"{directory} is not writable and holds no usable lock file "
                f"({exc.strerror}), so no writer can participate through this view"
            ) from exc
    try:
        if deadline is None:
            deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        warned = False
        pauses = _poll_pauses()
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
            # One reading of the clock for the check and the pause: read
            # twice, the deadline could pass in between and the pause go
            # negative, which time.sleep refuses.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LockUnavailableError(
                    f"Timed out after {_LOCK_TIMEOUT_SECONDS}s waiting for "
                    f"the write lock on {directory} - another process may "
                    "be stuck holding it",
                    kind="lock_timeout",
                )
            pause = next(pauses)
            if not warned and pause >= _LOCK_POLL_MAX_SECONDS:
                # Once the pauses have reached the cap (63 ms in): a peer
                # holding the lock for longer than a section takes, not the
                # collision with a read or a write that the short pauses
                # absorb, which under a shared store is routine.
                logger.warning(f"Waiting for the write lock on {directory}...")
                warned = True
            # Never past the deadline: the last pause is what is left of it.
            time.sleep(min(pause, remaining))
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


@contextlib.contextmanager
def directory_lock(
    directory: Path, thread_lock: Optional[threading.Lock] = None, of: str = "configuration"
) -> Iterator[None]:
    """The exclusive section for one configuration directory: the
    directory's advisory file lock and then the process-global thread
    lock, in that order (#246 - it is the reverse of the order writers
    used before, see the comment on the acquisition below).

    ``thread_lock`` is for a directory that is not a configuration
    directory: the keys directory (#420). It shares the mechanism and not
    the lock, so that reading or rotating keys neither waits for a
    configuration save in this process nor makes one wait, and so that the
    keys can be reached from anywhere, whatever the caller already holds.
    (Nothing enters the keys' section while holding the configuration's
    lock today; with one shared, non-reentrant lock the first caller that
    did would wait for itself.) ``of`` names the lock in a timeout's
    message, which otherwise sends the operator to the wrong directory.

    Published so that READS can join the protocol through
    ``config_store.ConfigFileStore``. It is NOT reentrant, by design and by
    the primitives: ``_write_lock`` is a plain ``threading.Lock``, and
    ``_cross_process_lock`` opens a fresh descriptor whose ``flock`` the
    same process conflicts with. A caller already inside the section uses
    the unlocked form of what it needs rather than acquiring again.
    """
    # ORDER: the cross-process lock FIRST, the thread lock second, and
    # never the other way round (#246 review). Taking the global thread
    # lock first meant polling a peer process while holding it, so one
    # stuck peer on one directory stalled every thread in this process,
    # including readers of a completely different directory: measured at
    # 1.8s of unrelated stall against a 2s timeout. Waiting for another
    # process is not a reason to own this one.
    #
    # This is about the WAIT, not the held section (#246 review round 3):
    # _write_lock is still process-global, so one directory's critical
    # section does exclude another's for as long as it runs. That is the
    # length of a validation and two atomic writes rather than the length
    # of somebody else's timeout, and making the thread lock per-directory
    # is a separate refactor with no measured case behind it yet.
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    with _cross_process_lock(directory, deadline), _write_lock_within(deadline, thread_lock, of):
        yield


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
# Given every (path, mutated document) in a batch, raise to refuse the write.
Validate = Callable[[Sequence[Tuple[Path, Dict[str, Any]]]], None]


def compare_and_replace(
    file_path: Path,
    expected_revision: Optional[Revision],
    mutate: Callable[[Dict[str, Any]], Any],
    validate: Optional[Validate] = None,
) -> Revision:
    """Load, optionally check, mutate, atomically replace; return the new revision.

    ``mutate`` receives the freshly loaded document (a ruamel
    ``CommentedMap``, via ``load_yaml_document``) and edits it in place;
    its return value is ignored. It only runs, and the file is only
    written, after the revision check passes - a conflict never leaves a
    partial write or a half-applied mutation. The single-item case of
    ``compare_and_replace_many``.
    """
    return compare_and_replace_many([(file_path, expected_revision, mutate)], validate)[0]


def compare_and_replace_many(
    items: Sequence[WriteItem], validate: Optional[Validate] = None
) -> List[Revision]:
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
    # Same ordering as directory_lock, and the directories in a stable
    # sorted order so two batches over the same set cannot deadlock each
    # other: every cross-process lock first, the process-global thread lock
    # last (#246 review).
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    with contextlib.ExitStack() as stack:
        for directory in directories:
            stack.enter_context(_cross_process_lock(directory, deadline))
        stack.enter_context(_write_lock_within(deadline))

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

        # Phase 2b: the caller inspects what phase 2 produced, before any
        # of it reaches disk (#366). It sees every document in the batch at
        # once, which is the only place that view exists: a rule spanning
        # users.yaml and settings.yaml has nowhere else to run. Raising here
        # leaves every file untouched, exactly like a mutate that raises.
        # This module stays ignorant of what makes a document acceptable -
        # the caller owns that, as it owns mutate.
        if validate is not None:
            validate(loaded)

        # Phase 3: every mutated document written.
        new_revisions = []
        for file_path, document in loaded:
            atomic_write_yaml(file_path, document)
            new_revisions.append(current_revision(file_path))
        return new_revisions
