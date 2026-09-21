"""
The keys directory as state that several processes share (#420).

The signing keys nanoidp generates for itself live in a directory, under
documented names:

    rsa_private.pem  rsa_public.pem  idp-cert.pem  keys.json  kid.txt
    previous/<kid>_public.pem

Each of those is one file, and a bundle is all of them. What this module
guarantees is that a process only ever loads a bundle that is whole and is
the one ``kid.txt`` names, whatever other processes are doing and wherever
one of them died.

- **One lock for the directory, across processes** (``config_writer``'s
  advisory file lock, with a thread lock of this module's own), held for a
  cold start, a rotation and a load, and for nothing else. Key material is
  generated before it is taken: an RSA key is a tenth of a second or more.
- **A process that cannot write the directory can still read it.** A keys
  volume mounted read-only, or owned by somebody else, has no lock this
  process could take, and nothing it could repair: it loads what is
  published without the lock, checking that the marker did not move and
  that no rotation is under way while it read. The same concession, for the
  same reason, as ``config_store`` makes for a read-only configuration.
- **``kid.txt`` is the marker, and replacing it is the commit point.** While
  there is no marker, whatever files are there were never published: a cold
  start ignores them, writes the whole bundle and the marker last.
- **A rotation is a small transaction.** "Files first, marker last" is not
  enough: the live names are fixed, so replacing the first of them already
  destroys the old bundle, and a process killed right there leaves a marker
  that says OLD over a private key that is NEW. So a rotation first writes
  down a complete rollback of OLD and a journal that says so, then replaces
  the live files, then the marker, and only then removes what is no longer
  referred to. Whoever next takes the lock recovers: a journal with the
  marker still OLD means not committed, and OLD is restored; with the marker
  NEW it means committed, and the leftovers go.
- **The rollback is reusable.** A restore copies and replaces and never
  consumes its source, so a second death during a recovery is recovered
  again.

Nothing here knows about JWT, SAML or the configuration: bytes in, bytes
out. ``crypto`` decides what a bundle contains.
"""

import json
import logging
import os
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ..config_writer import LockNamespaceUnavailable, directory_lock
from ..serialization import _replace_with_retry

logger = logging.getLogger(__name__)

PRIVATE = "rsa_private.pem"
PUBLIC = "rsa_public.pem"
CERTIFICATE = "idp-cert.pem"
METADATA = "keys.json"
MARKER = "kid.txt"
PREVIOUS = "previous"

# The live files of a bundle, in the order a rotation replaces them. The
# marker is not one of them: it goes last, and alone.
_LIVE = (PRIVATE, PUBLIC, CERTIFICATE, METADATA)
_MODES = {PRIVATE: 0o600, PUBLIC: 0o644, CERTIFICATE: 0o644, METADATA: 0o644, MARKER: 0o644}

# Where a rotation keeps what it needs to be undone or finished.
_TEMPORARY = ".writing-"
_WORK = ".rotation"
_JOURNAL = "journal.json"
_ROLLBACK = "rollback"

# A lock of this directory's own, not the configuration's: see ``thread_lock``
# on ``config_writer.directory_lock``.
_thread_lock = threading.Lock()

# How long a reader that cannot take the lock waits for a rotation it found
# under way to end, before it says so.
_READ_ONLY_PATIENCE_SECONDS = 2.0


def _checkpoint(step: str) -> None:
    """A seam and nothing else: the tests put a death here, at each step in
    turn."""


@dataclass(frozen=True)
class PreviousKey:
    kid: str
    public_pem: bytes
    created_at: str = ""


@dataclass(frozen=True)
class Bundle:
    """Everything a process signs and verifies with, as one thing."""

    kid: str
    private_pem: bytes
    public_pem: bytes
    certificate_pem: bytes
    previous: Tuple[PreviousKey, ...] = ()

    def metadata(self) -> bytes:
        document = {
            "active_kid": self.kid,
            "previous_keys": [{"kid": key.kid, "created_at": key.created_at} for key in self.previous],
        }
        return json.dumps(document, indent=2).encode("utf-8")

    def live_files(self) -> Dict[str, bytes]:
        return {
            PRIVATE: self.private_pem,
            PUBLIC: self.public_pem,
            CERTIFICATE: self.certificate_pem,
            METADATA: self.metadata(),
        }


@contextmanager
def locked(keys_dir: Path) -> Iterator[None]:
    """The exclusive section of one keys directory, across processes. Any
    rotation that died on the way is settled before the caller sees the
    directory. Not reentrant."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    with directory_lock(keys_dir, _thread_lock, of="keys directory"):
        _sweep_temporaries(keys_dir)
        _recover(keys_dir)
        yield


def load_published(keys_dir: Path) -> Optional[Bundle]:
    """The published bundle, for a process that is starting: under the lock
    when it can take it, without it when the directory is not this process's
    to write (``LockNamespaceUnavailable``, and only that: a lock that is
    there and cannot be had in time is still an error)."""
    try:
        with locked(keys_dir):
            return load(keys_dir)
    except (LockNamespaceUnavailable, PermissionError):
        return _load_without_the_lock(keys_dir)


def _load_without_the_lock(keys_dir: Path) -> Optional[Bundle]:
    """What a read-only view can do: read, and check that nothing moved
    while it did. It cannot recover a rotation that died, so one it keeps
    finding under way is an error that says what to do."""
    deadline = time.monotonic() + _READ_ONLY_PATIENCE_SECONDS
    while True:
        before = active_kid(keys_dir)
        bundle = load(keys_dir)
        rotating = (keys_dir / _WORK / _JOURNAL).exists()
        if not rotating and active_kid(keys_dir) == before:
            return bundle
        if time.monotonic() >= deadline:
            raise ValueError(
                f"{keys_dir} holds a key rotation that was not finished, and this process cannot "
                "write there to settle it: start a NanoIDP process that can, once"
            )
        time.sleep(0.05)


def active_kid(keys_dir: Path) -> Optional[str]:
    """What the marker says, read without the lock: one small file, replaced
    atomically, so either the kid before a commit or the one after it. None
    when nothing was ever published."""
    try:
        kid = (keys_dir / MARKER).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return kid or None


def load(keys_dir: Path) -> Optional[Bundle]:
    """The published bundle, or None when there is none. Caller holds the
    lock, so what the marker names is whole."""
    kid = active_kid(keys_dir)
    if kid is None:
        return None
    try:
        return Bundle(
            kid=kid,
            private_pem=(keys_dir / PRIVATE).read_bytes(),
            public_pem=(keys_dir / PUBLIC).read_bytes(),
            certificate_pem=_read_or_empty(keys_dir / CERTIFICATE),
            previous=_previous_keys(keys_dir),
        )
    except OSError:
        # A marker with no key behind it is a directory from before this
        # protocol, or one somebody edited: not a bundle.
        return None


def publish_first(keys_dir: Path, bundle: Bundle) -> None:
    """A cold start's bundle. Caller holds the lock and found no bundle, so
    whatever files are there were never published: they are replaced one by
    one, and the marker last makes the bundle exist.

    A marker may be there all the same, with no key behind it (``load`` does
    not call that a bundle). It goes first: left in place, a death half way
    would leave it naming the NEW key pair under the OLD kid, which the next
    start would load as if it were whole."""
    (keys_dir / MARKER).unlink(missing_ok=True)
    _checkpoint("first:unpublished")
    for name, data in bundle.live_files().items():
        _checkpoint(f"first:{name}")
        _replace(keys_dir / name, data, _MODES[name])
    _checkpoint("first:marker")
    _replace(keys_dir / MARKER, bundle.kid.encode("utf-8"), _MODES[MARKER])


def replace_certificate(keys_dir: Path, certificate_pem: bytes) -> None:
    """Repair the one file a bundle can be loaded without. Caller holds the
    lock."""
    _replace(keys_dir / CERTIFICATE, certificate_pem, _MODES[CERTIFICATE])


def rotate(keys_dir: Path, new: Bundle) -> None:
    """Make ``new`` the published bundle in place of the one that is. Caller
    holds the lock and built ``new`` from what it loaded under it.

    No cleanup on the way out of a failure, on purpose: a process that is
    killed runs none, so there must be nothing here that only a handler
    would put right. What is left behind is settled by the next ``locked``.
    """
    old_kid = active_kid(keys_dir)
    work = keys_dir / _WORK
    rollback = work / _ROLLBACK
    # OLD written down, whole, before anything live is touched: the bytes of
    # the live files as they are, not a reconstruction of them. The journal
    # goes last: until it is there the live files are untouched, and the
    # work directory is just litter.
    shutil.rmtree(work, ignore_errors=True)
    rollback.mkdir(parents=True)
    kept = []
    for name in _LIVE:
        try:
            data = (keys_dir / name).read_bytes()
        except OSError:
            continue  # it was not there, and a restore takes it away again
        _replace(rollback / name, data, _MODES[name])
        kept.append(name)
    _checkpoint("rollback:written")
    journal = {"old_kid": old_kid, "new_kid": new.kid, "rollback": kept}
    _replace(work / _JOURNAL, json.dumps(journal).encode("utf-8"), 0o600)
    _checkpoint("journal:published")

    # The previous keys NEW refers to. None is deleted yet: OLD still refers
    # to the ones it has.
    previous = keys_dir / PREVIOUS
    previous.mkdir(parents=True, exist_ok=True)
    for key in new.previous:
        _replace(previous / f"{key.kid}_public.pem", key.public_pem, 0o644)
    _checkpoint("previous:added")

    # The live files. From the first of these on the directory is neither
    # bundle, and only the journal says which way to go.
    for name, data in new.live_files().items():
        _replace(keys_dir / name, data, _MODES[name])
        _checkpoint(f"live:{name}")

    # The commit point.
    _replace(keys_dir / MARKER, new.kid.encode("utf-8"), _MODES[MARKER])
    _checkpoint("marker:committed")

    # What nothing refers to any more.
    _finish(keys_dir)


def _recover(keys_dir: Path) -> None:
    """Settle a rotation that did not reach its end. Caller holds the lock."""
    work = keys_dir / _WORK
    if not work.exists():
        return
    try:
        journal = json.loads((work / _JOURNAL).read_text(encoding="utf-8"))
        old_kid, new_kid, kept = journal["old_kid"], journal["new_kid"], list(journal["rollback"])
    except (OSError, ValueError, KeyError, TypeError):
        # No journal: the rotation died before it touched anything live, or
        # it was settled and died while its leftovers were being removed.
        shutil.rmtree(work, ignore_errors=True)
        return
    if active_kid(keys_dir) == new_kid:
        logger.warning("A key rotation to %s was committed and not finished: finishing it", new_kid)
        _finish(keys_dir)
        return
    logger.warning("A key rotation from %s was interrupted before its commit: restoring it", old_kid)
    rollback = work / _ROLLBACK
    for name in _LIVE:
        _checkpoint(f"restore:{name}")
        if name in kept:
            # Copied, never moved: died here, the next recovery finds the
            # rollback as whole as this one did.
            _replace(keys_dir / name, (rollback / name).read_bytes(), _MODES[name])
        else:
            (keys_dir / name).unlink(missing_ok=True)
    if old_kid:
        _replace(keys_dir / MARKER, str(old_kid).encode("utf-8"), _MODES[MARKER])
    _checkpoint("restore:done")
    # The previous key the rotation had added for NEW is nobody's now.
    _finish(keys_dir)


def _sweep_temporaries(keys_dir: Path) -> None:
    """What a writer that was killed inside ``_replace`` left beside its
    target. Every writer here holds the lock, so under it a temporary file
    is nobody's, and one of them may hold a private key."""
    for directory in (keys_dir, keys_dir / PREVIOUS, keys_dir / _WORK, keys_dir / _WORK / _ROLLBACK):
        if not directory.is_dir():
            continue
        for file in directory.iterdir():
            if file.is_file() and file.name.startswith(_TEMPORARY):
                file.unlink(missing_ok=True)


def _finish(keys_dir: Path) -> None:
    """Once the directory holds one bundle again, the new one after a commit
    or the old one after a restore: drop the previous keys its metadata does
    not refer to, then the work directory, whose absence is what says there
    is nothing to settle."""
    referred = {
        f"{entry.get('kid')}_public.pem"
        for entry in _metadata(keys_dir).get("previous_keys", [])
        if isinstance(entry, dict) and entry.get("kid")
    }
    previous = keys_dir / PREVIOUS
    if previous.is_dir():
        for file in previous.iterdir():
            if file.name.endswith("_public.pem") and file.name not in referred:
                file.unlink(missing_ok=True)
    _checkpoint("finish:pruned")
    # The journal first, and alone: it is what says there is something to
    # settle. Removed with the rest, in whatever order the directory is
    # walked, a death in between could leave it pointing at a rollback that
    # is gone, and every later start would fail on it.
    (keys_dir / _WORK / _JOURNAL).unlink(missing_ok=True)
    _checkpoint("finish:journal-removed")
    shutil.rmtree(keys_dir / _WORK, ignore_errors=True)


def _metadata(keys_dir: Path) -> Dict[str, List[Dict[str, str]]]:
    try:
        document = json.loads((keys_dir / METADATA).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return document if isinstance(document, dict) else {}


def _previous_keys(keys_dir: Path) -> Tuple[PreviousKey, ...]:
    """The previous keys the metadata lists, newest first, whose public key
    is there."""
    found = []
    for entry in _metadata(keys_dir).get("previous_keys", []):
        kid = entry.get("kid") if isinstance(entry, dict) else None
        if not kid:
            continue
        try:
            public_pem = (keys_dir / PREVIOUS / f"{kid}_public.pem").read_bytes()
        except OSError:
            continue
        found.append(PreviousKey(kid=kid, public_pem=public_pem, created_at=entry.get("created_at", "")))
    return tuple(found)


def _read_or_empty(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def write_beside_and_replace(path: Path, data: bytes, mode: int) -> None:
    """For the one file in the keys directory that is no part of a bundle:
    the certificate of external keys (#358), which has a name of its own and
    no marker. Atomic, and nothing more is claimed for it."""
    _replace(path, data, mode)


def _replace(path: Path, data: bytes, mode: int) -> None:
    """Written beside the target and moved into place, so that a reader finds
    the file as it was or as it is, never part of it. A write that fails
    takes its temporary file with it: what it holds may be a private key.
    The move is the configuration writers', with their patience for a reader
    that has the target open on Windows (the marker is read without the
    lock)."""
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=_TEMPORARY)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        _replace_with_retry(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
