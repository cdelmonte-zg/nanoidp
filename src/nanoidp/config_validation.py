"""
Validating a configuration directory without starting anything (#175 piece 4).

``nanoidp validate-config`` and the MCP ``validate_config`` tool both call
``validate_config_dir()``. It reads ``settings.yaml``, ``users.yaml`` and
``bootstrap.yaml`` through the very loaders the server uses, so a finding
here is a finding there, and it deliberately does NOT:

- construct a ``ConfigManager`` or touch the global config singleton,
- build a ``HookRegistry``, dispatch ``on_before_load`` or any other hook,
- import an entry point or instantiate a plugin.

``bootstrap.yaml`` is validated for its SHAPE only (``BootstrapDocument``):
the file's whole purpose is to name commands and plugins, and a lint step
that ran them would be a remote-execution primitive triggered by looking at
a directory. That is why this module imports ``config_documents`` and
``serialization`` but never ``config`` or ``hooks``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .config_documents import (
    SettingsDocument,
    UsersDocument,
    declared_validation_mode,
    load_bootstrap_document,
    load_settings_document,
    load_users_document,
)
from .serialization import check_config_version
from .serialization import expand_env_vars as _expand_env_vars

ERROR = "error"
WARNING = "warning"

# The three files of a configuration directory. bootstrap.yaml is optional
# and absent by default; the other two fall back to built-in defaults, which
# is worth saying out loud in a lint step.
SETTINGS_FILE = "settings.yaml"
USERS_FILE = "users.yaml"
BOOTSTRAP_FILE = "bootstrap.yaml"


@dataclass(frozen=True)
class Finding:
    """One line of a validation report."""

    level: str
    message: str
    file: Optional[str] = None

    def format(self) -> str:
        return f"{self.level}: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "message": self.message, "file": self.file}


def _read_yaml(path: Path, findings: List[Finding]) -> Optional[Dict[str, Any]]:
    """Parse one YAML file into a mapping, recording what went wrong."""
    try:
        with open(path, "r") as handle:
            data = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        findings.append(Finding(ERROR, f"{path}: not valid YAML: {exc}", path.name))
        return None
    except OSError as exc:
        findings.append(Finding(ERROR, f"{path}: cannot be read: {exc}", path.name))
        return None
    if not isinstance(data, dict):
        findings.append(
            Finding(ERROR, f"{path}: top level must be a mapping, found {type(data).__name__}", path.name)
        )
        return None
    return data


def _validate_file(
    path: Path,
    model_loader: Any,
    findings: List[Finding],
    expected_version: Optional[int] = None,
    check_version: bool = True,
) -> Tuple[Optional[Any], Optional[int]]:
    """Run one file through the real loader, collecting instead of raising.

    Returns the built document (or None) and the file's effective
    ``config_version``. Unknown keys always arrive as warnings: ``--strict``
    is a decision about the exit code, made once over the whole report, not
    a second code path (and it is what lets the report list every finding
    instead of stopping at the first).
    """
    data = _read_yaml(path, findings)
    if data is None:
        return None, None

    version: Optional[int] = None
    if check_version:
        try:
            version = check_config_version(data, path)
        except ValueError as exc:
            findings.append(Finding(ERROR, str(exc), path.name))
            return None, None

    if expected_version is not None and version != expected_version:
        findings.append(
            Finding(
                ERROR,
                f"{path}: config_version {version} does not match settings.yaml's "
                f"config_version {expected_version}; the configuration directory "
                f"follows one contract version",
                path.name,
            )
        )

    expanded = _expand_env_vars(data)
    unknown: List[str] = []
    document = None
    try:
        document = model_loader(expanded, path, on_unknown=unknown.append)
    except ValueError as exc:
        findings.append(Finding(ERROR, str(exc), path.name))
    findings.extend(Finding(WARNING, message, path.name) for message in unknown)
    return document, version


def validate_config_dir(config_dir: Path | str) -> List[Finding]:
    """Validate a configuration directory; never starts or runs anything.

    Every finding carries its own file, so the report reads the same whether
    it is printed by the CLI or returned to an MCP agent.
    """
    directory = Path(config_dir)
    findings: List[Finding] = []

    if not directory.is_dir():
        return [Finding(ERROR, f"{directory}: not a configuration directory", None)]

    settings_path = directory / SETTINGS_FILE
    users_path = directory / USERS_FILE
    bootstrap_path = directory / BOOTSTRAP_FILE

    settings_version: Optional[int] = None
    settings_document: Optional[SettingsDocument] = None
    if settings_path.exists():
        settings_document, settings_version = _validate_file(
            settings_path, load_settings_document, findings
        )
        if settings_document is not None:
            try:
                settings_document.to_settings()
            except (ValueError, TypeError) as exc:
                # Domain-model validators and the duplicate-client_id rule:
                # a file whose shape is fine can still be refused at startup.
                findings.append(Finding(ERROR, f"{settings_path}: {exc}", SETTINGS_FILE))
    else:
        findings.append(
            Finding(WARNING, f"{settings_path}: not found, built-in defaults would be used", SETTINGS_FILE)
        )

    if users_path.exists():
        users_document, _ = _validate_file(
            users_path, load_users_document, findings, expected_version=settings_version
        )
        if isinstance(users_document, UsersDocument):
            try:
                users_document.to_users()
            except (ValueError, TypeError) as exc:
                findings.append(Finding(ERROR, f"{users_path}: {exc}", USERS_FILE))
    else:
        findings.append(
            Finding(WARNING, f"{users_path}: not found, the default admin user would be used", USERS_FILE)
        )

    if bootstrap_path.exists():
        # Shape only: hooks and plugins declared here are never dispatched
        # or imported by a validation run (see the module docstring).
        # bootstrap.yaml has no config_version in its schema and the real
        # startup path (bootstrap_registry) never version-checks it: a
        # config_version key there is an unknown key, same as at startup
        # (#204 review: same semantics as the loader, not stricter ones).
        _validate_file(bootstrap_path, load_bootstrap_document, findings, check_version=False)

    return findings


def declared_mode(config_dir: Path | str) -> str:
    """``config_validation`` as settings.yaml declares it, for the report
    header. Unreadable files return the default; validate_config_dir reports
    what is actually wrong with them."""
    settings_path = Path(config_dir) / SETTINGS_FILE
    if not settings_path.exists():
        return "warn"
    try:
        with open(settings_path, "r") as handle:
            data = yaml.safe_load(handle) or {}
    except (yaml.YAMLError, OSError):
        return "warn"
    return declared_validation_mode(data) if isinstance(data, dict) else "warn"


def effective_strict(config_dir: Path | str, strict_flag: bool = False) -> bool:
    """``--strict`` on the command line, or the directory declaring it.

    A directory whose settings.yaml says ``config_validation: strict`` is one
    the server refuses to start on: a lint step that returned 0 for it would
    be lying, so the declaration counts here too. The flag can only add
    strictness, never remove it, exactly as it does for the server.
    """
    return bool(strict_flag) or declared_mode(config_dir) == "strict"


def report(findings: List[Finding], strict: bool) -> Tuple[List[str], int]:
    """Render the findings and decide the exit code.

    Exit 0 when clean, or when only warnings were found and ``--strict`` was
    not asked for; 1 on any error, and on any warning under ``--strict`` -
    the same rule the server applies at startup, so CI and the server agree
    about what the directory is worth.
    """
    lines = [finding.format() for finding in findings]
    errors = [f for f in findings if f.level == ERROR]
    warnings = [f for f in findings if f.level == WARNING]
    if errors:
        code = 1
    elif warnings and strict:
        code = 1
    else:
        code = 0
    if not findings:
        lines.append("ok: no findings")
    else:
        lines.append(
            f"{len(errors)} error(s), {len(warnings)} warning(s)"
            + (" (strict: warnings fail)" if strict and warnings else "")
        )
    return lines, code


def validate_config_result(config_dir: Path | str, strict: bool = False) -> Dict[str, Any]:
    """``{valid, findings, ...}`` for the MCP ``validate_config`` tool.

    ``valid`` follows the exit code of ``validate-config``: errors always
    invalidate, warnings only when the run is strict.
    """
    findings = validate_config_dir(config_dir)
    strict_run = effective_strict(config_dir, strict)
    _lines, code = report(findings, strict_run)
    return {
        "config_dir": str(config_dir),
        "config_validation": declared_mode(config_dir),
        "strict": strict_run,
        "valid": code == 0,
        "findings": [finding.to_dict() for finding in findings],
    }


__all__ = [
    "ERROR",
    "Finding",
    "WARNING",
    "declared_mode",
    "effective_strict",
    "report",
    "validate_config_dir",
    "validate_config_result",
]
