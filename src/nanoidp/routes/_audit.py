"""
Audit helper for the route modules (#85).

Every route used to build the same ten-line ``audit.log(...)`` block, each
fetching the audit singleton and spreading a request-info dict. ``audit_event``
is that block as one call: it fills the transport fields (method, ip address,
user agent) from the active Flask request.

``endpoint`` stays an explicit parameter rather than ``request.path`` because
several routes serve multiple URL rules but audit under one canonical name
(``/device/code`` logs as ``/device_authorization``, ``/end_session`` as
``/logout``).
"""

from typing import Any, Dict, Optional

from flask import request

from ..services import get_audit_log


def audit_event(
    event_type: str,
    status: str,
    *,
    endpoint: str,
    username: Optional[str] = None,
    client_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Log an audit event for the current request."""
    get_audit_log().log(
        event_type=event_type,
        endpoint=endpoint,
        method=request.method,
        status=status,
        username=username,
        client_id=client_id,
        ip_address=request.remote_addr or "unknown",
        user_agent=request.headers.get("User-Agent", "unknown"),
        details=details,
    )
