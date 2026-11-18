"""Protocol events: what the protocol did, said to first-party observers (#402).

The audit log observes what happened and is not this: an audit event may be
renamed, split or dropped without a word, and nothing that changes behaviour
may hang on it. An event here is emitted at one point of the protocol, named
for what it means, and reaches the observers of this process in the request
that emitted it, before its response leaves.

    protocol action
       |
       +--> audit (independent)
       |
       +--> emit_protocol_event() --> ProtocolEventDispatcher --> observers

The observers are the server's own (the scenario service). They are not
plugin objects: they are not listed, loaded or reloaded with the hooks, and
what one of them does is never an audit event that comes back as a trigger.

An observer that fails does not fail the protocol action: the action has
happened by the time the event is emitted, and a token that was issued is
delivered. The failure is logged here; an observer that owes its callers
more than a log line keeps it in its own state.
"""

import logging
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

logger = logging.getLogger(__name__)

# ``/token`` built a token for a user. Emitted after the token exists: a
# request whose token could not be built is no event, and whatever an
# observer changes is seen by the next request and never by this token,
# whose user the grant read before. ``grant_type`` says which grant: a refresh is this event with
# ``refresh_token``. A client credentials token has no user and is no event.
TOKEN_ISSUED = "token_issued"
# ``/authorize`` stored an authorization code for a user: the interactive
# authorization produced its result, whichever way the user was known (the
# login form, a second factor, persona auto-login, a reused session).
AUTHORIZATION_COMPLETED = "authorization_completed"

EVENTS = (TOKEN_ISSUED, AUTHORIZATION_COMPLETED)

# The grants that issue a token for a user, which is what ``grant_type`` of
# a token_issued can be: every grant of ``/token`` but client_credentials
# (a test holds the two lists together).
USER_GRANT_TYPES = (
    "password",
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
)


@dataclass(frozen=True)
class ProtocolEvent:
    name: str
    username: str
    client_id: Optional[str] = None
    grant_type: Optional[str] = None


Observer = Callable[[ProtocolEvent], None]


class ProtocolEventDispatcher:
    """Hands an event to each observer, in order, in the caller's thread."""

    def __init__(self, observers: Sequence[Observer]) -> None:
        self._observers = tuple(observers)

    def emit(self, event: ProtocolEvent) -> None:
        for observer in self._observers:
            try:
                observer(event)
            except Exception:
                logger.exception("An observer of %s failed; the protocol action stands", event.name)


def _dispatcher() -> ProtocolEventDispatcher:
    # Imported here: the observers import the event names above.
    from .scenarios import on_protocol_event

    return ProtocolEventDispatcher((on_protocol_event,))


def emit_protocol_event(event: ProtocolEvent) -> None:
    """Say ``event`` to the observers of this process. Never raises."""
    _dispatcher().emit(event)
