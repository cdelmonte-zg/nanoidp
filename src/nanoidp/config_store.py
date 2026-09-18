"""One home for filesystem access to a configuration directory (#246).

Until this module existed there was no single entry point for reading the
configuration at all, which is why the same hole was found three times:
``_stage_directory`` opened ``settings.yaml`` and ``users.yaml`` with two
separate unlocked reads, ``config_validation`` opened ``settings.yaml``
again, and the bootstrap read went its own way. The last two are still
outside this module: they are the second part of #246, and until then
``validate-config`` and the bootstrap read keep observing the directory on
their own. A write landing between two
of those reads is observed as a pair that never existed on disk.

The store owns **observations of the filesystem, not configuration
semantics**. Bytes and their revisions come from here; YAML parsing,
environment expansion, the document models, strictness and hooks all stay
outside, and deliberately outside the lock: the atomic unit being acquired
is the directory snapshot, not the whole reload.

Scoped to one directory, like the lock it uses. A store never knows about
arbitrary directories: ``compare_and_replace_many`` can technically span
several, but the case that matters is ``ConfigManager.save()`` over two
files of one directory, and coordinating several directories belongs to a
coordinator ordering several stores rather than inside one.

**Reentrancy is by explicit pairing, not machinery.** Every read exists as a
private ``_..._unlocked`` and a public method that takes the lock; a caller
that is already inside the critical section, which is every write, uses the
unlocked one. There is no reentrant lock and no depth counting: the
cross-process lock opens a fresh descriptor per acquisition and ``flock`` is
per open file description, so a nested acquisition waits out the whole
timeout and then fails, and ``_write_lock`` is a plain, non-reentrant
``threading.Lock`` (its wait is bounded by the acquisition's shared
deadline, but a thread still cannot hold it twice).
Writing the two forms out makes "this caller already holds the lock" a fact
in the code rather than something compensated for at runtime.

**A read never abandons an AVAILABLE protocol.** Contention is never a
reason to read unlocked: a timeout fails, and a filesystem that cannot do
advisory locking fails, because both mean the protocol exists and this
process could not join it. A caller that must degrade decides how to
PRESENT that failure, not whether to keep the guarantee.

The one concession is for a view where the protocol cannot exist at all
(#246 review). A read-only configuration mount is a supported, documented
deployment here - ``docker-compose.yml`` and the Helm chart both mount the
directory read-only, and the chart's README states that SAVES fail while
reads work - and a directory with no lock file that this process cannot
create an entry in has no writer to be inconsistent with: writing
configuration needs that same capability. Such a view keeps its historical
read semantics, and so does a directory that does not exist. That is
``LockNamespaceUnavailable``, which is narrower than "the lock could not be
acquired" on purpose, and the concession lives HERE, on the read side,
never in ``_cross_process_lock`` itself: a writer still always requires the
lock and still fails without it.

The limit, stated rather than hidden: a read-only view read without the
lock cannot be coordinated with a writer reaching the same storage through
some other, writable view. No advisory protocol can fix that for a reader
with no access to the lock namespace. Strong consistency holds between
participants able to use the same lock.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .config_writer import (
    LockNamespaceUnavailable,
    Revision,
    Validate,
    compare_and_replace_many,
    directory_lock,
    revision_of_bytes,
)

#: A write item named the way a store addresses its own directory: by file
#: NAME, not by path. Otherwise identical to ``config_writer.WriteItem``.
StoreWriteItem = Tuple[str, Optional[Revision], Callable[[Dict[str, Any]], Any]]


@dataclass(frozen=True)
class FileSnapshot:
    """What one file looked like at one moment, with the revision of exactly
    those bytes.

    Content and revision are one observation. Returning bytes and leaving
    the caller to ask for the revision separately is the pattern this type
    exists to make unavailable: the second call can describe content the
    caller never saw, and the precondition built from it would then be a
    promise about a file state nobody read.
    """

    data: bytes
    revision: Revision
    #: Whether the file was there at all. Part of the same observation on
    #: purpose: asking ``path.exists()`` afterwards would be a second look
    #: at the directory, and an absent file and an empty one are not the
    #: same thing to a loader even when both parse to nothing.
    exists: bool


#: What every file of a directory that is not there looks like. A constant,
#: because the answer must not depend on a second look at the filesystem.
_MISSING = FileSnapshot(data=b"", revision=revision_of_bytes(b""), exists=False)


class ConfigFileStore:
    """Consistent observations of one configuration directory."""

    def __init__(self, directory: Path | str) -> None:
        self._directory = Path(directory)

    @property
    def directory(self) -> Path:
        return self._directory

    def path_of(self, name: str) -> Path:
        """The absolute path of a file in this directory.

        For callers that must name a file in a message or hand it to a
        surface outside this boundary; reading it is the store's job.
        """
        return self._directory / name

    # -- reads -------------------------------------------------------

    def read(self, name: str) -> FileSnapshot:
        """One file, observed under the directory lock."""
        return self._observe((name,))[name]

    def read_snapshot(self, names: Sequence[str]) -> Dict[str, FileSnapshot]:
        """Several files, observed under ONE acquisition of the directory
        lock, so the result is a pair (or a triple) that really existed on
        disk at one moment.

        This is the whole point of the store: two separate ``read`` calls
        would each be consistent on their own and could still compose into a
        snapshot that never existed.
        """
        return self._observe(names)

    def current_revision(self, name: str) -> Revision:
        """The revision a caller hands back later as ``expected_revision``."""
        return self._observe((name,))[name].revision

    def _observe(self, names: Sequence[str]) -> Dict[str, FileSnapshot]:
        """The one read path, so the three public forms cannot drift on
        when the lock applies (#246).

        Three cases, and only the third gives anything up:

        - the ordinary one, where the lock is taken and held for the whole
          acquisition;
        - a directory that is not there, which holds no lock and no files -
          every snapshot is simply missing, and raising here would take
          away the "no settings.yaml, use the defaults" first run;
        - a view where the lock namespace cannot exist, which has no writer
          to be inconsistent with.

        Contention and a filesystem without advisory locking are NOT among
        them: those raise, because the protocol is there and this process
        could not join it.
        """
        if not self._directory.is_dir():
            # ONE decision, then no further look at the filesystem in this
            # call (#246 review round 4). Reading the files here would be a
            # fresh observation each: another process creating the directory
            # in between would hand back a snapshot composed of different
            # moments, which is the very class of bug this module exists to
            # remove.
            return dict.fromkeys(names, _MISSING)
        try:
            with directory_lock(self._directory):
                return {name: self._read_unlocked(name) for name in names}
        except LockNamespaceUnavailable:
            return {name: self._read_unlocked(name) for name in names}

    def _read_unlocked(self, name: str) -> FileSnapshot:
        """The one place bytes are read. Callers already inside the critical
        section use this; everyone else goes through the public methods.

        ``open`` rather than ``Path.read_bytes``: the tests put their seam on
        the builtin to stop a reader exactly between two acquisitions, and
        ``Path.read_bytes`` resolves ``io.open`` instead, which would leave
        the seam silently disarmed. The consistency test asserts that its
        seam fired, so this cannot rot unnoticed.
        """
        path = self._directory / name
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            # A missing file has a well-defined revision, the hash of empty
            # bytes, so "create this only if it still does not exist" keeps
            # working (#229 phase 5).
            return FileSnapshot(data=b"", revision=revision_of_bytes(b""), exists=False)
        return FileSnapshot(data=data, revision=revision_of_bytes(data), exists=True)

    # -- writes ------------------------------------------------------

    def compare_and_replace_many(
        self,
        items: Sequence[StoreWriteItem],
        validate: Optional[Validate] = None,
    ) -> List[Revision]:
        """Replace several files of this directory as one transaction.

        Named by file NAME rather than by path: a store writes its own
        directory and nothing else.
        """
        return compare_and_replace_many(
            [(self._directory / name, revision, mutate) for name, revision, mutate in items],
            validate=validate,
        )
