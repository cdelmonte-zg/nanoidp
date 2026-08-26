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
``settings.yaml`` as one logical save (#229 review on phase 2, reproduced:
a stale ``settings.yaml`` revision left a fresh ``users.yaml`` on disk and
the in-memory settings change silently unsaved) - the same directory-wide
transactional boundary ``ConfigManager._load_config`` already gives reads
(#204), now for this write. ``compare_and_replace`` is the ``len(items) ==
1`` case of the same function.

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
- an advisory ``fcntl.flock`` on a lock file in the config directory
  (``.nanoidp-write.lock``), serializing separate OS processes - the
  actual case #229 was opened for (a UI worker and an MCP process, or
  two MCP processes, sharing one config directory). The thread lock
  alone does not cover this: two processes each get their own
  ``_write_lock`` and race exactly as before without the file lock
  (#229 review round 2, reproduced with ``multiprocessing`` and a
  ``Barrier`` - both writers saw "ok", one update silently lost, 10/10
  trials). Both locks are kept, not just the file lock, because
  ``fcntl.flock`` is scoped to the open file description: a second
  ``flock()`` from the same process is not guaranteed to exclude the
  first the way it does across processes, so cross-thread safety within
  one process still needs the plain thread lock. POSIX only
  (``fcntl``) - the platforms this project runs on in CI (Linux/macOS).
  A Windows deployment would need ``msvcrt.locking`` behind the same
  helper; not implemented, so this is a hard requirement, not a silent
  degradation, on a platform where ``fcntl`` cannot even be imported.

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
import fcntl
import hashlib
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .serialization import atomic_write_yaml, load_yaml_document

logger = logging.getLogger(__name__)

Revision = str

_LOCK_FILENAME = ".nanoidp-write.lock"

_write_lock = threading.Lock()


@contextlib.contextmanager
def _cross_process_lock(directory: Path) -> Iterator[None]:
    """Advisory, cross-process exclusive lock for one config directory.

    One lock file per directory (not per target file, same reasoning as
    ``_write_lock``), opened fresh and ``flock``-ed for the duration of
    the caller's section, released in ``finally`` even if the caller
    raises (a stale lock file left over from a partial write is harmless -
    it is never read for content, only locked).
    """
    lock_path = directory / _LOCK_FILENAME
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
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


def current_revision(file_path: Path) -> Revision:
    """The revision a reader hands back later as ``expected_revision``.

    A missing file has a well-defined revision (the hash of empty bytes),
    so a caller can request "only create this if it still doesn't exist".
    """
    return hashlib.sha256(_read_bytes(file_path)).hexdigest()


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
    """``compare_and_replace`` across several files as one transaction.

    Every item's ``expected_revision`` is checked - against every file's
    on-disk revision - before any file in the batch is written: a
    conflict on the second item never leaves the first one already
    written, the same way a single ``compare_and_replace`` call never
    leaves a partial write within one file. Items are otherwise
    independent: different files, different ``mutate`` callables,
    checked and written in the order given. Returns each item's new
    revision, in that same order.
    """
    directories = sorted({file_path.parent for file_path, _, _ in items}, key=str)
    with _write_lock, contextlib.ExitStack() as stack:
        for directory in directories:
            stack.enter_context(_cross_process_lock(directory))

        # Phase 1: every precondition checked before anything is written,
        # so a conflict on item N leaves items before it untouched too.
        for file_path, expected_revision, _mutate in items:
            actual = current_revision(file_path)
            if expected_revision is not None and expected_revision != actual:
                raise ConflictError(
                    f"{file_path.name} changed since it was last read "
                    f"(expected revision {expected_revision[:12]}, found {actual[:12]})"
                )

        # Phase 2: every mutation applied and written.
        new_revisions = []
        for file_path, _expected_revision, mutate in items:
            document = load_yaml_document(file_path)
            mutate(document)
            atomic_write_yaml(file_path, document)
            new_revisions.append(current_revision(file_path))
        return new_revisions
