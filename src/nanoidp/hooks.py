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

Error policy, per hook (identical for shell and Python, except that
``timeout_seconds`` only applies to shell hooks: a plugin manages its own
timeouts):

- ``on_before_load`` is the only hook that may block an operation, because it
  runs before any mutation. Default: log and continue with whatever is in
  the directory; ``hooks.strict: true``: the load fails with the hook's error.
- ``on_config_saved`` runs after the atomic write, so the local save is
  always committed. Default: log. ``strict``: the error is propagated to the
  caller after the write; the caller reloads first so disk and runtime both
  carry the new value and only the mirror failed.
- ``on_audit_event`` never propagates, strict or not: an audit plugin failure
  must not fail a ``/token`` whose token is already issued. Failures are
  counted and surfaced by ``nanoidp plugins`` and ``GET /api/config``.

Timeouts are failures (shell hooks). No threads or async in the core; a
plugin that wants asynchrony or a timeout does it on its side.

Secrets: commands are stored after ``${VAR}`` expansion, so they may carry
tokens. ``describe()`` (what ``GET /api/config`` and MCP expose) therefore
never includes a command, and a propagated ``HookError`` names the hook and
its source only; the command and the hook's stderr go to the local server
log, at WARNING. Only ``nanoidp plugins`` (the operator's terminal) prints
commands.

Precedence: the bootstrap surface (``bootstrap.yaml``, env) is the baseline
for the policy values ``strict`` and ``timeout_seconds``; ``settings.yaml``
overrides a value only when it declares it explicitly, and dropping the
settings source (a reload after the file disappeared) restores the baseline.

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
import threading
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import yaml

from .config_documents import load_bootstrap_document
from .serialization import expand_env_vars

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
    """A hook failed and the policy for that hook says the caller must know.

    ``message`` is always a synthetic string built by the registry (hook
    name, source, exit code); it never embeds a command, stderr or a
    plugin's exception text, so callers may put it in an HTTP/MCP
    response. ``kind`` says which phase failed: the hook name
    (``on_before_load``, ``on_config_saved``) or ``plugin_load`` for a
    plugin that could not be registered during a load.
    """

    def __init__(self, message: str, kind: str = "hook") -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


class PluginLoadError(ValueError):
    """A plugin could not be registered, for a reason nanoidp itself
    diagnosed. ``public_reason`` is safe to expose (it is built from names
    and versions, never from plugin-provided text)."""

    def __init__(self, message: str, public_reason: str) -> None:
        super().__init__(message)
        self.public_reason = public_reason


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
        """Public metadata: never the command, which may embed expanded secrets."""
        return {
            "hook": self.hook,
            "source": self.source,
            "failures": self.failures,
            "once": self.once,
        }


@dataclass
class LoadedPlugin:
    # The entry-point name, which is also the ``plugins.<name>`` key: the
    # plugin's one identity. A ``name`` attribute on the object is ignored.
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

    DEFAULT_STRICT = False
    DEFAULT_TIMEOUT_SECONDS = 10.0
    # Highest precedence first: an explicitly declared settings.yaml value
    # overrides bootstrap.yaml's, which overrides the default.
    _POLICY_PRECEDENCE = (SOURCE_SETTINGS, SOURCE_BOOTSTRAP_FILE)

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        self.config_dir: Optional[Path] = config_dir
        self.shell_hooks: List[ShellHook] = []
        self.plugins: List[LoadedPlugin] = []
        # Policy values per source, only those a source declared explicitly.
        self._policy: Dict[str, Dict[str, Any]] = {}
        # Failure counters of entries dropped by drop_source(), keyed so the
        # same declaration re-read from settings.yaml on reload keeps its
        # history instead of reporting a fresh zero.
        self._retired_shell: Dict[tuple, int] = {}
        self._retired_plugins: Dict[tuple, Dict[str, int]] = {}
        # Plugins a source declared but that could not be loaded (missing
        # entry point, wrong hook_api_version, configure() raised): reported,
        # never fatal unless strict (review before 2.7.0rc4).
        self._failed_plugins: Dict[str, List[Dict[str, str]]] = {}
        # Set while on_before_load runs on this thread: an audit event logged
        # from inside a load must not re-enter the registry (or the config
        # singleton, whose construction may hold a non-reentrant lock).
        self._loading = threading.local()

    # ----------------------------------------------------------------- policy

    def _policy_value(self, key: str, default: Any) -> Any:
        for source in self._POLICY_PRECEDENCE:
            declared = self._policy.get(source, {})
            if key in declared:
                return declared[key]
        return default

    @property
    def strict(self) -> bool:
        return bool(self._policy_value("strict", self.DEFAULT_STRICT))

    @property
    def timeout_seconds(self) -> float:
        return float(self._policy_value("timeout_seconds", self.DEFAULT_TIMEOUT_SECONDS))

    def set_policy(self, source: str, **declared: Any) -> None:
        """Record the policy values ``source`` declared explicitly (and only those)."""
        self._policy.setdefault(source, {}).update(
            {k: v for k, v in declared.items() if v is not None}
        )

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
            raise PluginLoadError(f"Plugin {name!r} is already loaded", "already loaded")
        candidates = [ep for ep in metadata.entry_points(group=ENTRY_POINT_GROUP) if ep.name == name]
        if not candidates:
            raise PluginLoadError(
                f"Plugin {name!r} not found: no '{ENTRY_POINT_GROUP}' entry point with that "
                f"name is installed (pip install the package that provides it)",
                "not installed",
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
            raise PluginLoadError(
                f"Plugin {name!r} declares hook_api_version={api_version!r}; this nanoidp "
                f"implements hook API version {HOOK_API_VERSION}. Upgrade the plugin or nanoidp.",
                f"incompatible hook_api_version={api_version!r} (expected {HOOK_API_VERSION})",
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
        self._failed_plugins.pop(source, None)
        # A source that is gone no longer has a say in strict/timeout: the
        # bootstrap baseline (or the default) applies again.
        self._policy.pop(source, None)

    def configure_from_sections(
        self,
        hooks: Any,
        plugins: Mapping[str, Any],
        source: str,
    ) -> None:
        """Apply a validated ``hooks:`` / ``plugins:`` pair from ``source``.

        ``hooks`` is a ``HooksSection`` (preferred: only the policy values it
        declares explicitly, per ``model_fields_set``, override lower
        sources) or a plain mapping (every present key counts as declared).
        """
        if hasattr(hooks, "model_fields_set"):
            declared = set(hooks.model_fields_set)
            values = {k: getattr(hooks, k) for k in declared}
        else:
            values = dict(hooks)
            declared = set(values)
        for hook in HOOK_NAMES:
            command = values.get(hook)
            if command:
                self.add_shell_hook(hook, command, source)
        self.set_policy(
            source,
            strict=values.get("strict") if "strict" in declared else None,
            timeout_seconds=values.get("timeout_seconds") if "timeout_seconds" in declared else None,
        )
        self.load_plugins(plugins, source)

    def load_plugins(self, plugins: Mapping[str, Any], source: str) -> None:
        """Load every plugin ``source`` declares, following the error policy.

        A plugin that cannot be loaded (no entry point installed, wrong
        ``hook_api_version``, ``configure()`` raising) is logged at ERROR,
        recorded in ``describe()["plugins_failed"]`` and skipped; under
        ``strict`` the load fails with a ``HookError`` naming the plugins,
        after every plugin was attempted. Registration is part of the load,
        so it follows on_before_load's policy, not an unconditional abort.
        """
        failed: List[str] = []
        for name, config in plugins.items():
            try:
                self.add_plugin(name, source, config or {})
            except Exception as exc:
                # The public reason is one of nanoidp's own short diagnoses;
                # the exception text (import error, constructor, configure(),
                # which may embed the plugin's settings and therefore secrets)
                # goes to the local log only (#200 review).
                if isinstance(exc, PluginLoadError):
                    reason = exc.public_reason
                else:
                    reason = "initialization failed"
                logger.error(
                    "plugin %r (%s) could not be loaded: %s", name, source, str(exc) or exc.__class__.__name__
                )
                self._failed_plugins.setdefault(source, []).append({"name": name, "reason": reason})
                failed.append(name)
        if failed and self.strict:
            raise HookError(
                f"plugin(s) {', '.join(repr(n) for n in failed)} from {source} could not be loaded",
                kind="plugin_load",
            )

    # --------------------------------------------------------------- dispatch

    def run_before_load(self, config_dir: Path) -> None:
        """May raise ``HookError`` under ``strict``; otherwise logs and returns."""
        self._loading.active = True
        try:
            self._dispatch(
                "on_before_load",
                shell_placeholders={"config_dir": str(config_dir)},
                plugin_args=(config_dir,),
                propagate=self.strict,
            )
        finally:
            self._loading.active = False

    def has_hook(self, hook: str) -> bool:
        """True when at least one shell hook or plugin implements ``hook``."""
        return any(h.hook == hook for h in self.shell_hooks) or any(
            callable(getattr(p.obj, hook, None)) for p in self.plugins
        )

    def _config_dir_placeholder(self, fallback: Optional[Path] = None) -> str:
        if self.config_dir is not None:
            return str(self.config_dir)
        return str(fallback) if fallback is not None else ""

    def run_config_saved(self, path: Path, kind: str) -> None:
        """The write is already committed; under ``strict`` a failure is raised
        to the caller AFTER the file is on disk."""
        self._dispatch(
            "on_config_saved",
            shell_placeholders={
                "config_dir": self._config_dir_placeholder(path.parent),
                "path": str(path),
                "kind": kind,
            },
            plugin_args=(path, kind),
            propagate=self.strict,
        )

    def run_audit_event(self, event: Mapping[str, Any]) -> None:
        """Never raises, strict or not: hooks must not alter protocol behaviour."""
        # Nothing registered: no dict copies, no iteration (the default case).
        if not self.has_hook("on_audit_event"):
            return
        # An audit event produced while on_before_load is running on this
        # thread (a plugin logging from its load hook) stays in the audit log
        # but is not dispatched: no recursion into a half-built registry.
        if getattr(self._loading, "active", False):
            return
        try:
            self._dispatch(
                "on_audit_event",
                shell_placeholders={
                    "config_dir": self._config_dir_placeholder(),
                    "event_type": str(event.get("event_type", "")),
                },
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
        if not self.has_hook(hook):
            return
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
            except Exception:
                plugin.failures[hook] += 1
                message = f"plugin {plugin.name!r} {hook} failed"
                # The exception text may carry whatever the plugin was sent
                # (URLs with tokens, store errors): local log only.
                logger.warning(message, exc_info=True)
                errors.append(message)
        if errors and propagate:
            raise HookError("; ".join(errors), kind=hook)

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
        # Two messages on purpose: the one returned (and, under strict,
        # propagated to the UI/API/MCP caller) names the hook and its source
        # only; the one logged carries the command and stderr, which may
        # embed secrets expanded from ${VAR}, and stays in the local log.
        label = f"{shell_hook.hook} shell hook ({shell_hook.source})"
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
            logger.warning("%s timed out after %ss: %s", label, self.timeout_seconds, shell_hook.command)
            return f"{label} failed (timed out after {self.timeout_seconds}s)"
        except OSError as exc:
            logger.warning("%s could not run: %s: %s", label, exc, shell_hook.command)
            return f"{label} failed (could not run)"
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            logger.warning(
                "%s exited %s: %s%s",
                label,
                result.returncode,
                shell_hook.command,
                f" [stderr: {stderr}]" if stderr else "",
            )
            return f"{label} failed (exit {result.returncode})"
        logger.debug("%s ok: %s", label, shell_hook.command)
        return None

    # ---------------------------------------------------------- introspection

    def describe(self) -> Dict[str, Any]:
        """What ``GET /api/config`` and MCP report: metadata only, no commands
        (they are stored after ``${VAR}`` expansion and may embed secrets;
        ``/api/*`` is unauthenticated by design)."""
        return {
            "hook_api_version": HOOK_API_VERSION,
            "strict": self.strict,
            "timeout_seconds": self.timeout_seconds,
            "shell_hooks": [h.describe() for h in self.shell_hooks],
            "plugins": [p.describe() for p in self.plugins],
            "plugins_failed": [
                {"name": f["name"], "source": source, "reason": f["reason"]}
                for source, entries in self._failed_plugins.items()
                for f in entries
            ],
        }

    def format_report(self) -> str:
        """Human-readable form for the CLI. Unlike ``describe()`` it prints the
        commands: ``nanoidp plugins`` runs in the operator's own terminal, the
        only place where a command that may embed a secret is shown."""
        info = self.describe()
        commands = {(h.hook, h.source): h.command for h in self.shell_hooks}
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
            lines.append(
                f"    command (local only, may embed secrets): {commands[(h['hook'], h['source'])]}"
            )
        lines.append("")
        lines.append("plugins:")
        if not info["plugins"]:
            lines.append("  (none)")
        for p in info["plugins"]:
            lines.append(
                f"  {p['name']:<16} api={p['hook_api_version']} {p['source']:<14} "
                f"hooks={','.join(p['hooks']) or '-'} failures={p['failures']}"
            )
        for f in info["plugins_failed"]:
            lines.append(f"  {f['name']:<16} NOT LOADED ({f['source']}): {f['reason']}")
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
    registry = HookRegistry(config_dir=config_dir)

    bootstrap_file = config_dir / BOOTSTRAP_FILE
    if bootstrap_file.exists():
        # Same path as settings.yaml: ${VAR} expansion first, then the
        # document loader (unknown keys warned with their path, wrong types
        # reported as "<file>: invalid value at <path>").
        with open(bootstrap_file, "r") as f:
            raw = yaml.safe_load(f) or {}
        raw = expand_env_vars(raw)
        document = load_bootstrap_document(raw, bootstrap_file)
        registry.configure_from_sections(document.hooks, document.plugins, SOURCE_BOOTSTRAP_FILE)
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
        registry.load_plugins(
            {plugin_name: plugin_settings_from_env(plugin_name, env)}, SOURCE_BOOTSTRAP_ENV
        )

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

