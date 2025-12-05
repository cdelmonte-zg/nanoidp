"""
Audit logging service for tracking IDP operations.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Represents a single audit log entry."""
    timestamp: datetime
    event_type: str
    username: Optional[str]
    client_id: Optional[str]
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    status: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "username": self.username,
            "client_id": self.client_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "endpoint": self.endpoint,
            "method": self.method,
            "status": self.status,
            "details": self.details,
        }


class AuditLog:
    """In-memory audit log with size limit."""

    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self._entries: deque = deque(maxlen=max_entries)
        self._lock = Lock()
        self._stats = {
            "total_requests": 0,
            "token_requests": 0,
            "saml_requests": 0,
            "login_attempts": 0,
            "successful_logins": 0,
            "failed_logins": 0,
        }

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
    ):
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

        with self._lock:
            self._entries.append(entry)
            self._update_stats(event_type, status)

        # Also log to standard logger
        log_msg = f"[{event_type}] {method} {endpoint} - {status}"
        if username:
            log_msg += f" (user: {username})"
        if client_id:
            log_msg += f" (client: {client_id})"

        if status == "success":
            logger.info(log_msg)
        else:
            logger.warning(log_msg)

    def _update_stats(self, event_type: str, status: str):
        """Update statistics counters."""
        self._stats["total_requests"] += 1

        if event_type == "token_request":
            self._stats["token_requests"] += 1
        elif event_type == "saml_request":
            self._stats["saml_requests"] += 1
        elif event_type == "login":
            self._stats["login_attempts"] += 1
            if status == "success":
                self._stats["successful_logins"] += 1
            else:
                self._stats["failed_logins"] += 1

    def get_entries(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get recent audit entries."""
        with self._lock:
            entries = list(self._entries)

        # Filter
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        if username:
            entries = [e for e in entries if e.username == username]
        if client_id:
            entries = [e for e in entries if e.client_id == client_id]

        # Return most recent first
        entries = sorted(entries, key=lambda e: e.timestamp, reverse=True)

        return [e.to_dict() for e in entries[:limit]]

    def get_unique_client_ids(self) -> List[str]:
        """Get list of unique client_ids from audit log."""
        with self._lock:
            client_ids = set()
            for entry in self._entries:
                if entry.client_id:
                    client_ids.add(entry.client_id)
        return sorted(client_ids)

    def get_stats(self) -> Dict[str, Any]:
        """Get audit statistics."""
        with self._lock:
            return dict(self._stats)

    def clear(self):
        """Clear the audit log."""
        with self._lock:
            self._entries.clear()
            self._stats = {
                "total_requests": 0,
                "token_requests": 0,
                "saml_requests": 0,
                "login_attempts": 0,
                "successful_logins": 0,
                "failed_logins": 0,
            }


# Global audit log instance
_audit_log: Optional[AuditLog] = None


def get_audit_log() -> AuditLog:
    """Get or create the global audit log."""
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log
