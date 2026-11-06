"""Authenticated browser sessions at /authorize (#468).

A successful login at ``/authorize`` - the login form, the persona picker,
persona auto-login, a completed TOTP step - leaves one record per browser
here, keyed by the browser's binding (the one value the session cookie
holds for every temporary capability of that browser, shared with the
authorization transactions of #346 and the pending second factors of
#373). A later request of the same browser may reuse it instead of showing
a login page: that is what ``prompt=none``, ``max_age`` and
``id_token_hint`` are checked against, and what single sign-on rests on.

The record holds no secret: the username, how the user authenticated
(``method``), the instant of that authentication (``auth_time``, the
value the ID token carries) and an expiry computed from it. The lifetime
is ``login.session_minutes``; reuse never extends it, and ``0`` keeps no
record at all. A new login of the same browser replaces the record, whoever
it was for. The web UI's own login (``session["user"]``) is a different
thing and is never read or written here; ``/device`` and SAML neither
create nor consume these records.

A record is only ever trusted after the user it names is resolved again
by the caller (``routes/oauth``): a user that no longer exists, a login
mode that no longer allows how the session was established, or a second
factor that has since become required, are no session. Like the other
per-browser stores, every operation that is more than one look at the
repository is one decision of the repository's (#404), whole for whoever
shares the store.
"""

import time
from typing import Optional

from pydantic import BaseModel

from .runtime_repository import RuntimeObjectExists, create_within
from .runtime_repository import consume as consume_entry
from .runtime_store import PydanticCodec, RuntimeRepository, get_runtime_store

# Bounded like the other per-browser stores. One record per browser, so
# the count is the number of browsers with a live login; at the cap a login
# completes without a session rather than failing (the caller decides).
MAX_AUTHENTICATED_SESSIONS = 1000


class AuthenticatedSessionStoreFull(Exception):
    """Every slot is held by a live session of another browser."""


class AuthenticatedSession(BaseModel):
    browser_binding: str
    username: str
    # routes/_auth.AuthMethod's value: how the user authenticated, from
    # which the ID token's amr and the reuse rules derive.
    method: str
    auth_time: int
    expires_at: float

    def is_live(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at

    def age(self, now: Optional[float] = None) -> float:
        """Seconds since the authentication, for ``max_age``: not truncated,
        so an authentication 1.9 s old is older than ``max_age=1``."""
        return (now if now is not None else time.time()) - self.auth_time


class AuthenticatedSessionStore:
    """The operations on authenticated sessions, each one atomic with
    respect to the others."""

    @property
    def _repository(self) -> RuntimeRepository[AuthenticatedSession]:
        # Looked up on every use, like the authorization transactions: the
        # runtime store owns the state, whatever replaces it.
        return get_runtime_store().repository(
            "authenticated_sessions",
            lambda record: record.browser_binding,
            PydanticCodec(AuthenticatedSession),
        )

    def establish(
        self,
        *,
        browser_binding: str,
        username: str,
        method: str,
        auth_time: int,
        lifetime_seconds: int,
    ) -> AuthenticatedSession:
        """Record this browser's authentication, replacing whatever record
        the browser had. Raises AuthenticatedSessionStoreFull when every
        slot is held by another browser's live session."""
        record = AuthenticatedSession(
            browser_binding=browser_binding,
            username=username,
            method=method,
            auth_time=auth_time,
            expires_at=auth_time + lifetime_seconds,
        )
        repository = self._repository
        # The browser's previous record, live or not, makes room for its
        # own replacement before the cap is counted.
        consume_entry(repository, browser_binding)
        try:
            return create_within(
                repository,
                record,
                MAX_AUTHENTICATED_SESSIONS,
                expires_at=record.expires_at,
                full=AuthenticatedSessionStoreFull(
                    f"{MAX_AUTHENTICATED_SESSIONS} browsers already hold a live session"
                ),
            ).value
        except RuntimeObjectExists:
            # A concurrent login of the same browser got in between the two
            # steps: its record is this browser's too, and as fresh.
            current = repository.get(browser_binding)
            assert current is not None
            return current

    def live(self, browser_binding: Optional[str]) -> Optional[AuthenticatedSession]:
        """This browser's record, if live now."""
        if browser_binding is None:
            return None
        # Keyed by the binding: the lookup is the binding check.
        record = self._repository.get(browser_binding)
        if record is None or not record.is_live():
            return None
        return record

    def end(self, browser_binding: Optional[str]) -> Optional[AuthenticatedSession]:
        """Drop this browser's record, live or not: a logout. ``None`` when
        there was none."""
        if browser_binding is None:
            return None
        taken = consume_entry(self._repository, browser_binding)
        return taken.value if taken is not None else None

    def delete_all(self) -> int:
        """End every session: a runtime reset."""
        return self._repository.delete_all()


def get_authenticated_session_store() -> AuthenticatedSessionStore:
    """The authenticated sessions of this process."""
    return AuthenticatedSessionStore()
