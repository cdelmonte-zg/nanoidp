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
(``_write_lock``, same pattern as ``config.py``'s ``_config_lock``, and
deliberately one lock for every file rather than one per path: ``save()``
writes two files back to back, ``reload_local()`` stages the whole
directory (#204), and #192 will need a cross-file check that only works
under one lock). Without it, two in-process threads can both read the
same "actual" revision before either has written and both pass the
check - that part is purely about the check-then-write race (TOCTOU); it
is not what makes concurrent YAML parsing safe (see below). The lock only
serializes callers within this process - there is no cross-process file
lock anywhere in this codebase, so it narrows rather than eliminates the
race between a caller reading a revision and calling
``compare_and_replace`` with it. That window is still cut from "however
long an HTTP request or an MCP tool call takes between a read and a
write" down to "however long one write takes" - the actual lost-update
scenario #229 is closing.

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
    mutate: Callable[[Dict[str, Any]], Any],
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
