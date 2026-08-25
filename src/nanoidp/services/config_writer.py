"""
Single write pipeline with optimistic conflict detection (issue #229, phase 1).

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

``expected_revision=None`` means unconditional - today's last-write-wins -
so a caller that hasn't been migrated to pass a revision yet keeps its
current behaviour exactly.

A revision is the sha256 of the file's raw on-disk bytes, not a hash of the
parsed document: hashing what's actually on disk means any two readers of
the same file always compute the same revision, with no dependence on
ruamel's dump formatting.

The check-load-mutate-write sequence runs under a single process-local lock
(``_write_lock``, same pattern as ``config.py``'s ``_config_lock``): without
it, two in-process threads can both read the same "actual" revision before
either has written and both pass the check, which both defeats the
conflict guarantee and corrupts the shared ruamel dumper (it isn't
reentrant across threads). The lock only serializes callers within this
process - there is no cross-process file lock anywhere in this codebase,
so it narrows rather than eliminates the race between a caller reading a
revision and calling ``compare_and_replace`` with it. That window is
still cut from "however long an HTTP request or an MCP tool call takes
between a read and a write" down to "however long one write takes" - the
actual lost-update scenario #229 is closing.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from ..serialization import atomic_write_yaml, load_yaml_document

logger = logging.getLogger(__name__)

Revision = str

_write_lock = threading.Lock()


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


def compare_and_replace(
    file_path: Path,
    expected_revision: Optional[Revision],
    mutate: Callable[[Dict[str, Any]], None],
) -> Revision:
    """Load, optionally check, mutate, atomically replace; return the new revision.

    ``mutate`` receives the freshly loaded document (a ruamel
    ``CommentedMap``, via ``load_yaml_document``) and edits it in place;
    its return value is ignored. It only runs, and the file is only
    written, after the revision check passes - a conflict never leaves a
    partial write or a half-applied mutation.
    """
    with _write_lock:
        actual = current_revision(file_path)
        if expected_revision is not None and expected_revision != actual:
            raise ConflictError(
                f"{file_path.name} changed since it was last read "
                f"(expected revision {expected_revision[:12]}, found {actual[:12]})"
            )
        document = load_yaml_document(file_path)
        mutate(document)
        atomic_write_yaml(file_path, document)
        return current_revision(file_path)
