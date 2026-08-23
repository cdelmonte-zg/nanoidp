"""
nanoidp-echo: the reference plugin for nanoidp's hook API v1 (#185).

It does nothing useful on purpose: every hook call is logged and, when the
plugin is configured with a ``record`` path, appended to that file as one
JSON line. Copy this package, rename it, and replace the three methods with
what your store needs; keep ``hook_api_version``. A plugin's identity is
its entry-point name (the ``plugins.<name>`` key), nothing on the object.

Install next to nanoidp::

    pip install -e examples/plugins/nanoidp-echo

then declare it in ``settings.yaml``::

    plugins:
      echo:
        record: /tmp/nanoidp-hooks.jsonl

or, for hooks that must run before settings.yaml exists::

    NANOIDP_BOOTSTRAP_PLUGIN=echo NANOIDP_PLUGIN_ECHO_RECORD=/tmp/nanoidp-hooks.jsonl nanoidp

The contract a plugin implements (all hooks optional, all synchronous):

- ``on_before_load(config_dir: Path) -> None``
- ``on_config_saved(path: Path, kind: str) -> None``  (``kind`` is ``settings`` or ``users``)
- ``on_audit_event(event: dict) -> None``
- ``configure(settings: dict) -> None``  (optional; receives ``plugins.<name>``)

Raising from a hook counts as a failure; nanoidp applies its per-hook error
policy (see the "Extending nanoidp" guide). ``on_audit_event`` failures never
reach the request that produced the event.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("nanoidp_echo")


class EchoPlugin:
    hook_api_version = 1

    def __init__(self) -> None:
        self.record: Optional[Path] = None
        self.calls: list[Dict[str, Any]] = []

    def configure(self, settings: Dict[str, Any]) -> None:
        record = settings.get("record")
        self.record = Path(record) if record else None

    def _note(self, hook: str, **payload: Any) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "hook": hook,
            **payload,
        }
        self.calls.append(entry)
        logger.info("echo plugin: %s %s", hook, payload)
        if self.record is not None:
            with open(self.record, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")

    def on_before_load(self, config_dir: Path) -> None:
        self._note("on_before_load", config_dir=str(config_dir))

    def on_config_saved(self, path: Path, kind: str) -> None:
        self._note("on_config_saved", path=str(path), kind=kind)

    def on_audit_event(self, event: Dict[str, Any]) -> None:
        self._note("on_audit_event", event_type=event.get("event_type"), status=event.get("status"))
