"""
Audit logging service for tracking IDP operations.

``AuditLog`` is a facade with no state (#363): the events and their counters
are the runtime store's, in its ``AuditStore``, so that with a backend several
processes share (#354) they are one audit, which the MCP tools already assume.
What stays here is what is about the domain and not about keeping things:
which counters an event increments, the shape of the statistics, and what
happens after an event is recorded, outside any lock of the store's - the
Python log line and the ``on_audit_event`` hooks.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import get_config_if_loaded
from .audit_store import AuditEntry, AuditEntryCodec, AuditStore
from .runtime_store import get_runtime_store

__all__ = ["AuditEntry", "AuditLog", "get_audit_log"]

logger = logging.getLogger(__name__)

# The statistics as they read before the first event. The store keeps only the
# counters that were ever incremented and knows none of them by name.
_NO_STATS = {
    "total_requests": 0,
    "token_requests": 0,
    "saml_sso_requests": 0,
    "saml_attribute_queries": 0,
    "login_attempts": 0,
    "successful_logins": 0,
    "failed_logins": 0,
}

_COPY = AuditEntryCodec().copy


def _increments(event_type: str, status: str) -> List[str]:
    """Which counters an event adds one to."""
    names = ["total_requests"]
    if event_type == "token_request":
        names.append("token_requests")
    elif event_type == "saml_request":
        names.append("saml_sso_requests")
    elif event_type == "saml_attribute_query":
        names.append("saml_attribute_queries")
    elif event_type == "login":
        names.append("login_attempts")
        names.append("successful_logins" if status == "success" else "failed_logins")
    return names


class AuditLog:
    """The audit of this process: a view, with no state, over the runtime
    store's ``AuditStore``. The bound on how many events are kept is the
    backend's (``audit_store.MAX_AUDIT_ENTRIES`` in memory)."""

    @property
    def _store(self) -> AuditStore:
        # Looked up on every use: the runtime store owns the state, whatever
        # replaces it (a reset, #354's durable backend).
        return get_runtime_store().audit

    def log(
        self,
        event_type: str,
        endpoint: str,
        method: str,
        status: str,
        username: Optional[str] = None,
        client_id: Optional[str] = None,
        ip_address: str = "unknown",
        user_agent: str = "unknown",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an audit event."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            username=username,
            client_id=client_id,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            method=method,
            status=status,
            details=details or {},
        )

        # The event and its counters, one step of the store's. Copied in, so
        # what the caller does with ``details`` afterwards is its own.
        self._store.append(entry, _increments(event_type, status))

        # Verbose logging controlled by settings. No cycle (#285: config
        # never imports services; the old comment claimed one). What DOES
        # matter is never constructing the configuration from a log call: an
        # audit event logged while the singleton is being built (a plugin's
        # on_before_load) would block on the non-reentrant init lock (review
        # before 2.7.0rc4) - hence get_config_if_loaded, never get_config.
        loaded = get_config_if_loaded()
        verbose = loaded.settings.verbose_logging if loaded is not None else True

        # Build log message - include identifiers only if verbose logging is enabled
        log_msg = f"[{event_type}] {method} {endpoint} - {status}"
        if verbose:
            if username:
                log_msg += f" (user: {username})"
            if client_id:
                log_msg += f" (client: {client_id})"

        if status == "success":
            logger.info(log_msg)
        else:
            logger.warning(log_msg)

        # on_audit_event (#185): after the entry is recorded. The registry
        # never lets a hook failure out of run_audit_event; the guard here
        # covers the config singleton itself being unavailable.
        # A hook gets an event of its own: what it does with it does not
        # reach what is kept. No copy when nobody listens (the default).
        if loaded is not None and loaded.hooks.has_hook("on_audit_event"):
            try:
                loaded.hooks.run_audit_event(_COPY(entry).to_dict())
            except Exception:
                logger.debug("audit hooks unavailable", exc_info=True)

    def get_entries(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Recent audit entries, newest first: by the order they were
        recorded in, not by their timestamps, so events of one timestamp and
        a clock that stepped back read like everything else. A filter that
        is empty is no filter; a limit below zero is none at all (it was a
        slice, and "-1" meant all but the last)."""
        found = self._store.entries(
            max(0, limit),
            event_type=event_type or None,
            username=username or None,
            client_id=client_id or None,
        )
        # Copies already, the reader's own.
        return [entry.to_dict() for entry in found]

    def get_unique_client_ids(self) -> List[str]:
        """Get list of unique client_ids from audit log."""
        return self._store.client_ids()

    def get_stats(self) -> Dict[str, Any]:
        """Get audit statistics."""
        return {**_NO_STATS, **self._store.counters()}

    def clear(self) -> None:
        """Clear the audit log."""
        self._store.clear()


def get_audit_log() -> AuditLog:
    """The audit of this process: a view over the runtime store, which is
    where the state is (#363)."""
    return AuditLog()
