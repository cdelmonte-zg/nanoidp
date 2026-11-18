"""
Where the files of a SQLite runtime store lie (#354 step 4c, #426).

What the settings name, resolved as the process uses it, the two files
named after it, and the rule that none of them lies in the configuration
directory. Paths and nothing else: no store is opened and no file is made.

A module of its own, outside ``services``, because two callers need it and
one of them may import nothing that runs: the activation of a load applies
the rule before it builds a store, and ``config_validation`` applies it to
a directory it only looks at, so that what the start refuses the check
reports, in the same words.
"""

from pathlib import Path
from typing import Optional

from .models import Settings


def audit_path_of(path: Path) -> Path:
    """The audit's file, named after the store's: ``runtime.db`` has its
    audit in ``runtime-audit.db``. The two are the store."""
    return path.with_name(f"{path.stem}-audit{path.suffix}")


def owners_path_of(path: Path) -> Path:
    """The directory of the owner leases, named after the store's file:
    ``runtime.db`` has them in ``runtime-owners`` (#354, step 4b)."""
    return path.with_name(f"{path.stem}-owners")


def resolved_runtime_path(settings: Settings, config_dir: Optional[Path] = None) -> Optional[Path]:
    """The file of the SQLite runtime store these settings name, as the
    process uses it; None for a store that has no file (#354, step 4c).

    The one place it is resolved: the inputs, the check against the
    configuration directory and what /api/config and MCP report all go
    through here. A relative ``runtime.path`` is relative to the
    configuration directory, not to the process's working directory: it is
    the identity of a store several processes share, and the same
    settings.yaml in the same directory must name the same store however the
    processes were started."""
    if settings.runtime_store != "sqlite":
        return None
    if settings.runtime_path is None:
        # The document cannot say it; settings made in code can, and this is
        # no store without a file.
        raise ValueError("runtime.store: sqlite needs runtime.path, and these settings have none")
    path = Path(settings.runtime_path)
    if not path.is_absolute():
        if config_dir is None:
            raise ValueError(
                f"runtime.path {settings.runtime_path!r} is relative to the configuration directory, "
                "and none was given"
            )
        path = Path(config_dir) / path
    return path.resolve()


def require_store_outside_the_configuration(settings: Settings, config_dir: Optional[Path] = None) -> None:
    """The rule about where a SQLite store's files may lie, for these
    settings: nothing to ask of a store that has no file. A ValueError
    that says which file and why.

    The activation applies it before it builds a store, and the
    validation of a configuration directory applies it too (#426): what
    one refuses the other reports, in the same words. Only paths are
    looked at: no store is opened and no file is made."""
    path = resolved_runtime_path(settings, config_dir)
    if path is not None:
        outside_the_configuration(path, config_dir)


def outside_the_configuration(path: Path, config_dir: Optional[Path]) -> None:
    """The store's files are a secret of the processes that share it: none
    of them (the database, its audit, its owners' leases) may lie in the
    configuration directory, which is read, copied and committed as
    configuration. Resolved, so that a symlink does not hide it."""
    if config_dir is None:
        raise ValueError("the SQLite runtime store is activated with its configuration directory")
    configuration = Path(config_dir).resolve()
    for part in (path, audit_path_of(path), owners_path_of(path)):
        resolved = part.resolve()
        if resolved == configuration or configuration in resolved.parents:
            raise ValueError(
                f"runtime.path: {resolved} is inside the configuration directory {configuration}; "
                "the runtime store's files are a secret, and must lie outside it"
            )
