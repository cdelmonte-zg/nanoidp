"""
Hooks and plugins v1: extension points for external configuration stores,
not backends (#185).

nanoidp keeps talking only to its YAML files. A hook observes what happens
to those files (and to the audit log) and provides files before they are
read; it never replaces persistence, never sees an HTTP request and never
touches token issuance, so a broken hook cannot alter protocol behaviour.

Three hooks, called synchronously from ``ConfigManager`` and the audit
service, with ``HOOK_API_VERSION = 1`` (additive-only from here):

- ``on_before_load(config_dir)``: before settings/users are read (startup and
  every reload). Use: render files from a store into the directory.
- ``on_config_saved(path, kind)``: after an atomic write of ``settings.yaml``
  (``kind="settings"``) or ``users.yaml`` (``kind="users"``). Use: push to a
  store, ``git commit``, notify.
- ``on_audit_event(event)``: after an audit entry is recorded. Use: ship
  audit elsewhere.

Two implementations of the same contract share one dispatcher, so there is
one contract: shell commands declared in YAML (placeholders ``{config_dir}``,
``{path}``, ``{kind}``, ``{event_type}``; the audit event is also passed as
JSON on stdin), and Python plugins discovered through the ``nanoidp.plugins``
entry-point group. Order per hook: shell hook first, then plugins in
declaration order.

Error policy, per hook (identical for shell and Python):

- ``on_before_load`` is the only hook that may block an operation, because it
  runs before any mutation. Default: log and continue with whatever is in
  the directory; ``hooks.strict: true``: the load fails with the hook's error.
- ``on_config_saved`` runs after the atomic write, so the local save is
  always committed. Default: log. ``strict``: the error is propagated to the
  caller after the write (the file on disk is what was written).
- ``on_audit_event`` never propagates, strict or not: an audit plugin failure
  must not fail a ``/token`` whose token is already issued. Failures are
  counted and surfaced by ``nanoidp plugins`` and ``GET /api/config``.

Timeouts are failures. No threads or async in the core; a plugin that wants
asynchrony does it on its side.

Bootstrap: ``on_before_load`` runs before ``settings.yaml`` is read, but hook
configuration is declared in ``settings.yaml``, so the main use case (render
the files from a store) needs a surface outside the file it fetches:
``NANOIDP_BOOTSTRAP_HOOK`` (a shell command run once before the first load),
``NANOIDP_BOOTSTRAP_PLUGIN`` (an entry-point name), ``NANOIDP_PLUGIN_<NAME>_<KEY>``
variables, and an optional ``bootstrap.yaml`` inside the config directory
(``hooks:`` and ``plugins:`` keys only). See ``bootstrap_registry``.

This module imports nothing from the package except ``config_documents`` (for
the section models), so ``config.py`` and the audit service can both import
it without a cycle.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import yaml

from .config_documents import BootstrapDocument

logger = logging.getLogger(__name__)

HOOK_API_VERSION = 1

HOOK_NAMES = ("on_before_load", "on_config_saved", "on_audit_event")

ENTRY_POINT_GROUP = "nanoidp.plugins"

BOOTSTRAP_HOOK_ENV = "NANOIDP_BOOTSTRAP_HOOK"
BOOTSTRAP_PLUGIN_ENV = "NANOIDP_BOOTSTRAP_PLUGIN"
PLUGIN_ENV_PREFIX = "NANOIDP_PLUGIN_"
BOOTSTRAP_FILE = "bootstrap.yaml"

# Where a hook or plugin was declared; reported by ``nanoidp plugins``.
SOURCE_BOOTSTRAP_ENV = "bootstrap-env"
SOURCE_BOOTSTRAP_FILE = "bootstrap.yaml"
SOURCE_SETTINGS = "settings.yaml"


class HookError(RuntimeError):
    """A hook failed and the policy for that hook says the caller must know."""


@dataclass
class ShellHook:
    hook: str
    command: str
    source: str
    failures: int = 0
    # Bootstrap shell hooks run once, before the first load, and never again.
    once: bool = False
    ran: bool = False

    def describe(self) -> Dict[str, Any]:
        return {
            "hook": self.hook,
            "command": self.command,
            "source": self.source,
            "failures": self.failures,
            "once": self.once,
        }


@dataclass
class LoadedPlugin:
    name: str
    obj: Any
    api_version: int
    source: str
    config: Dict[str, Any] = field(default_factory=dict)
    failures: Dict[str, int] = field(default_factory=lambda: dict.fromkeys(HOOK_NAMES, 0))

    @property
    def hooks(self) -> List[str]:
        return [h for h in HOOK_NAMES if callable(getattr(self.obj, h, None))]

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "hook_api_version": self.api_version,
            "hooks": self.hooks,
            "source": self.source,
            "failures": dict(self.failures),
        }


class HookRegistry:
    """The single dispatcher every hook call goes through.

    Holds shell hooks and plugins from all three surfaces. Entries sourced
    from ``settings.yaml`` are replaced on every load (the file may have
    changed); bootstrap entries persist for the life of the process.
    """

    def __init__(self) -> None:
        self.shell_hooks: List[ShellHook] = []
        self.plugins: List[LoadedPlugin] = []
        self.strict: bool = False
        self.timeout_seconds: float = 10.0
        # Failure counters of entries dropped by drop_source(), keyed so the
        # same declaration re-read from settings.yaml on reload keeps its
        # history instead of reporting a fresh zero.
        self._retired_shell: Dict[tuple, int] = {}
        self._retired_plugins: Dict[tuple, Dict[str, int]] = {}

    # ------------------------------------------------------------------ setup

    def add_shell_hook(self, hook: str, command: str, source: str, once: bool = False) -> None:
        if hook not in HOOK_NAMES:
            raise ValueError(f"Unknown hook {hook!r}; expected one of {', '.join(HOOK_NAMES)}")
        entry = ShellHook(hook=hook, command=command, source=source, once=once)
        entry.failures = self._retired_shell.pop((hook, command, source), 0)
        self.shell_hooks.append(entry)

    def add_plugin(self, name: str, source: str, config: Optional[Mapping[str, Any]] = None) -> LoadedPlugin:
        """Load ``name`` from the ``nanoidp.plugins`` entry-point group."""
        if any(p.name == name for p in self.plugins):
            raise ValueError(f"Plugin {name!r} is already loaded")
        candidates = [ep for ep in metadata.entry_points(group=ENTRY_POINT_GROUP) if ep.name == name]
        if not candidates:
            raise ValueError(
                f"Plugin {name!r} not found: no '{ENTRY_POINT_GROUP}' entry point with that "
                f"name is installed (pip install the package that provides it)"
            )
        factory = candidates[0].load()
        # An entry point may point at a class (instantiate it) or at a
        # ready-made object.
        obj = factory() if isinstance(factory, type) else factory
        return self.register_plugin_object(name, obj, source, config)

    def register_plugin_object(
        self, name: str, obj: Any, source: str, config: Optional[Mapping[str, Any]] = None
    ) -> LoadedPlugin:
        """Register an already-constructed plugin (tests, in-process use)."""
        api_version = getattr(obj, "hook_api_version", None)
        if api_version != HOOK_API_VERSION:
            raise ValueError(
                f"Plugin {name!r} declares hook_api_version={api_version!r}; this nanoidp "
                f"implements hook API version {HOOK_API_VERSION}. Upgrade the plugin or nanoidp."
            )
        plugin = LoadedPlugin(name=name, obj=obj, api_version=api_version, source=source, config=dict(config or {}))
        plugin.failures.update(self._retired_plugins.pop((name, source), {}))
        configure = getattr(obj, "configure", None)
        if callable(configure):
            configure(dict(plugin.config))
        self.plugins.append(plugin)
        return plugin

    def drop_source(self, source: str) -> None:
        """Forget every entry declared by ``source`` (used before re-reading settings.yaml)."""
        for h in self.shell_hooks:
            if h.source == source:
                self._retired_shell[(h.hook, h.command, h.source)] = h.failures
        for p in self.plugins:
            if p.source == source:
                self._retired_plugins[(p.name, p.source)] = dict(p.failures)
        self.shell_hooks = [h for h in self.shell_hooks if h.source != source]
        self.plugins = [p for p in self.plugins if p.source != source]

    def configure_from_sections(
        self,
        hooks: Mapping[str, Any],
        plugins: Mapping[str, Any],
        source: str,
    ) -> None:
        """Apply a validated ``hooks:`` / ``plugins:`` pair from ``source``."""
        for hook in HOOK_NAMES:
            command = hooks.get(hook)
            if command:
                self.add_shell_hook(hook, command, source)
        if "strict" in hooks and hooks["strict"] is not None:
            self.strict = bool(hooks["strict"])
        if "timeout_seconds" in hooks and hooks["timeout_seconds"] is not None:
            self.timeout_seconds = float(hooks["timeout_seconds"])
        for name, config in plugins.items():
            self.add_plugin(name, source, config or {})

    # --------------------------------------------------------------- dispatch

    def run_before_load(self, config_dir: Path) -> None:
        """May raise ``HookError`` under ``strict``; otherwise logs and returns."""
        self._dispatch(
            "on_before_load",
            shell_placeholders={"config_dir": str(config_dir)},
            plugin_args=(config_dir,),
            propagate=self.strict,
        )

    def run_config_saved(self, path: Path, kind: str) -> None:
        """The write is already committed; under ``strict`` a failure is raised
        to the caller AFTER the file is on disk."""
        self._dispatch(
            "on_config_saved",
            shell_placeholders={"path": str(path), "kind": kind},
            plugin_args=(path, kind),
            propagate=self.strict,
        )

    def run_audit_event(self, event: Mapping[str, Any]) -> None:
        """Never raises, strict or not: hooks must not alter protocol behaviour."""
        try:
            self._dispatch(
                "on_audit_event",
                shell_placeholders={"event_type": str(event.get("event_type", ""))},
                plugin_args=(dict(event),),
                propagate=False,
                stdin_json=dict(event),
            )
        except Exception:  # pragma: no cover - defensive, _dispatch already swallows
            logger.exception("audit hook dispatch failed")

    def _dispatch(
        self,
        hook: str,
        shell_placeholders: Mapping[str, str],
        plugin_args: tuple,
        propagate: bool,
        stdin_json: Optional[Mapping[str, Any]] = None,
    ) -> None:
        errors: List[str] = []
        for shell_hook in [h for h in self.shell_hooks if h.hook == hook]:
            if shell_hook.once and shell_hook.ran:
                continue
            shell_hook.ran = True
            error = self._run_shell(shell_hook, shell_placeholders, stdin_json)
            if error is not None:
                shell_hook.failures += 1
                errors.append(error)
        for plugin in self.plugins:
            fn = getattr(plugin.obj, hook, None)
            if not callable(fn):
                continue
            try:
                fn(*plugin_args)
            except Exception as exc:
                plugin.failures[hook] += 1
                message = f"plugin {plugin.name!r} {hook} failed: {exc}"
                logger.warning(message)
                errors.append(message)
        if errors and propagate:
            raise HookError("; ".join(errors))

    def _run_shell(
        self,
        shell_hook: ShellHook,
        placeholders: Mapping[str, str],
        stdin_json: Optional[Mapping[str, Any]],
    ) -> Optional[str]:
        """Run one shell hook; return an error message or None."""
        command = shell_hook.command
        # str.replace, not str.format: a command legitimately contains braces
        # (${VAR}, jq filters) that must not be interpreted as placeholders.
        for key, value in placeholders.items():
            command = command.replace("{" + key + "}", value)
        try:
            result = subprocess.run(
                command,
                shell=True,
                timeout=self.timeout_seconds,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
                input=json.dumps(stdin_json) if stdin_json is not None else None,
            )
        except subprocess.TimeoutExpired:
            message = (
                f"{shell_hook.hook} shell hook ({shell_hook.source}) timed out after "
                f"{self.timeout_seconds}s: {shell_hook.command}"
            )
            logger.warning(message)
            return message
        except OSError as exc:
            message = f"{shell_hook.hook} shell hook ({shell_hook.source}) could not run: {exc}"
            logger.warning(message)
            return message
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            message = (
                f"{shell_hook.hook} shell hook ({shell_hook.source}) exited "
                f"{result.returncode}: {shell_hook.command}"
                + (f" [stderr: {stderr}]" if stderr else "")
            )
            logger.warning(message)
            return message
        logger.debug("%s shell hook ok: %s", shell_hook.hook, shell_hook.command)
        return None

    # ---------------------------------------------------------- introspection

    def describe(self) -> Dict[str, Any]:
        """What ``nanoidp plugins``, ``GET /api/config`` and MCP report."""
        return {
            "hook_api_version": HOOK_API_VERSION,
            "strict": self.strict,
            "timeout_seconds": self.timeout_seconds,
            "shell_hooks": [h.describe() for h in self.shell_hooks],
            "plugins": [p.describe() for p in self.plugins],
        }

    def format_report(self) -> str:
        """Human-readable form of ``describe()`` for the CLI."""
        info = self.describe()
        lines = [
            f"hook API version: {info['hook_api_version']}",
            f"strict: {info['strict']}  timeout_seconds: {info['timeout_seconds']}",
            "",
            "shell hooks:",
        ]
        if not info["shell_hooks"]:
            lines.append("  (none)")
        for h in info["shell_hooks"]:
            once = "  [bootstrap, runs once]" if h["once"] else ""
            lines.append(f"  {h['hook']:<16} {h['source']:<14} failures={h['failures']}{once}")
            lines.append(f"    {h['command']}")
        lines.append("")
        lines.append("plugins:")
        if not info["plugins"]:
            lines.append("  (none)")
        for p in info["plugins"]:
            lines.append(
                f"  {p['name']:<16} api={p['hook_api_version']} {p['source']:<14} "
                f"hooks={','.join(p['hooks']) or '-'} failures={p['failures']}"
            )
        return "\n".join(lines)


# ------------------------------------------------------------------ bootstrap


def bootstrap_registry(config_dir: Path, environ: Optional[Mapping[str, str]] = None) -> HookRegistry:
    """Build the registry from the bootstrap surface, before settings.yaml exists.

    Sources, in order: ``bootstrap.yaml`` in the config directory (``hooks:``
    and ``plugins:`` only, validated by the same section models, unknown keys
    refused), then the environment: ``NANOIDP_BOOTSTRAP_HOOK`` (an
    ``on_before_load`` shell command that runs once, before the first load),
    ``NANOIDP_BOOTSTRAP_PLUGIN`` (entry-point name) with its settings taken
    from ``NANOIDP_PLUGIN_<NAME>_<KEY>`` variables (name upper-cased, ``-``
    as ``_``, keys lower-cased). A bootstrap plugin is a plugin like any
    other: loaded once, it takes part in every hook for the life of the
    process.
    """
    env = os.environ if environ is None else environ
    registry = HookRegistry()

    bootstrap_file = config_dir / BOOTSTRAP_FILE
    if bootstrap_file.exists():
        with open(bootstrap_file, "r") as f:
            raw = yaml.safe_load(f) or {}
        document = BootstrapDocument.model_validate(raw)
        registry.configure_from_sections(
            document.hooks.model_dump(),
            document.plugins,
            SOURCE_BOOTSTRAP_FILE,
        )
        # bootstrap.yaml's on_before_load runs before the first load only,
        # like the env hook: settings.yaml owns reloads.
        for hook in registry.shell_hooks:
            if hook.source == SOURCE_BOOTSTRAP_FILE and hook.hook == "on_before_load":
                hook.once = True

    command = env.get(BOOTSTRAP_HOOK_ENV)
    if command:
        registry.add_shell_hook("on_before_load", command, SOURCE_BOOTSTRAP_ENV, once=True)

    plugin_name = env.get(BOOTSTRAP_PLUGIN_ENV)
    if plugin_name:
        registry.add_plugin(plugin_name, SOURCE_BOOTSTRAP_ENV, plugin_settings_from_env(plugin_name, env))

    return registry


def plugin_settings_from_env(plugin_name: str, environ: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """``NANOIDP_PLUGIN_<NAME>_<KEY>=value`` -> ``{"<key>": "value"}``."""
    env = os.environ if environ is None else environ
    prefix = PLUGIN_ENV_PREFIX + plugin_name.upper().replace("-", "_") + "_"
    return {
        key[len(prefix):].lower(): value
        for key, value in env.items()
        if key.startswith(prefix) and len(key) > len(prefix)
    }

