"""The lifecycle of runtime users and clients, as rules (#192, #432).

Create, delete, promote and reset, with what each failure is called and what
a caller is told about it. Two surfaces offer them: ``/api/runtime`` over
HTTP and the ``*_runtime_*`` tools of the MCP server. Each maps a
``Refused`` to its own shape (a status, or a tool result) and writes its
own audit entry; neither decides what a failure is.

The rules about the identities themselves (declared first, no runtime
object under a declared name, the promotion order, the reconciliation on
reload) live in ``services.identities``.
"""

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Union

from ..config import ConfigurationRejected, DeclaredConfigurationUnloadable, OAuthClient, User
from ..config_documents import (
    DocumentRejected,
    EntryInvalid,
    parse_client_entry,
    parse_runtime_user,
)
from ..config_writer import ConflictError, LockUnavailableError
from ..hooks import HookError
from . import scenarios
from .authenticated_sessions import get_authenticated_session_store
from .dynamic_registration import prune_stale_registrations, registration_of
from .id_token_hint_references import get_parked_hint_store
from .identities import (
    DeclaredNameCollision,
    IdentityResolver,
    PromotionInProgress,
    PromotionOutcome,
    RuntimeObjectNotFound,
)
from .runtime_repository import Entry, RuntimeStoreUnavailable
from .runtime_store import RuntimeObjectExists
from .yaml_writer import PostWriteError

logger = logging.getLogger(__name__)

# The audit events of the lifecycle, whichever surface records them.
CREATED = "runtime_identity_created"
DELETED = "runtime_identity_deleted"
RESET = "runtime_identities_reset"
SCENARIO_ARMED = "runtime_scenario_armed"
SCENARIO_REMOVED = "runtime_scenario_removed"

# The file a promotion writes, by kind.
PROMOTION_FILES = {"user": "users.yaml", "client": "settings.yaml"}


@dataclass(frozen=True)
class Refused:
    """An operation that did not happen, or did not complete: ``kind`` is
    the stable name of why, ``message`` what a caller is told, and
    ``retryable`` whether coming back may help, which only a lock held by
    another writer says yes to (decided on the lock's own refusal, #477)."""

    kind: str
    message: str
    retryable: bool = False


def user_from(body: Dict[str, Any], where: str) -> User:
    """A runtime user from a ``users.yaml``-shaped entry plus ``username``,
    validated exactly like a declared user. EntryInvalid otherwise."""
    return parse_runtime_user(body, where)


def client_from(body: Dict[str, Any], where: str) -> OAuthClient:
    """A runtime client from an ``oauth.clients[]``-shaped entry, validated
    exactly like a declared client. EntryInvalid otherwise."""
    return parse_client_entry(body, where)


def source_of(client: Entry[OAuthClient]) -> Optional[str]:
    """``dcr`` when a registration record was issued for this client (#190).

    Read from the record rather than from the shape of the id, which is only
    a hint for a human reading a log, and from the entry that is being
    shown rather than by its name (#404): the fields and the label are then
    about one instance, whatever has happened to the id since it was read.
    """
    return "dcr" if registration_of(client) is not None else None


def not_found(kind: str, name: str) -> Refused:
    return Refused("not_found", f"no runtime {kind} {name!r}")


def create(kind: str, name: str, make: Callable[[], Any]) -> Union[Any, Refused]:
    try:
        return make()
    except DeclaredNameCollision:
        return Refused("declared", f"{kind} {name!r} is declared in the configuration")
    except RuntimeObjectExists:
        return Refused("exists", f"a runtime {kind} {name!r} already exists")


def delete(kind: str, name: str, remove: Callable[[str], None]) -> Optional[Refused]:
    try:
        remove(name)
    except RuntimeObjectNotFound:
        return not_found(kind, name)
    except PromotionInProgress:
        return Refused("promotion_in_progress", f"runtime {kind} {name!r} is being promoted")
    return None


def arm_scenario(resolver: IdentityResolver, body: Dict[str, Any], where: str) -> Union[Dict[str, Any], Refused]:
    """Arm the scenario ``body`` declares and create its user (#402): what
    a caller is shown of it, or why not."""
    try:
        scenario, user = scenarios.scenario_from(body, where)
    except EntryInvalid as exc:
        return Refused("invalid", exc.message)
    try:
        return scenarios.view_of(scenarios.arm(resolver, scenario, user))
    except scenarios.ScenarioExists:
        return Refused("exists", f"a scenario {scenario.name!r} already exists")
    except scenarios.ScenariosFull:
        return Refused("full", f"{scenarios.MAX_SCENARIOS} scenarios are armed already; remove one first")
    except scenarios.ScenarioRemovedWhileArming:
        return Refused("conflict", f"scenario {scenario.name!r} was removed while it was being armed")
    except DeclaredNameCollision:
        return Refused("declared", f"user {user.username!r} is declared in the configuration")
    except RuntimeObjectExists:
        return Refused("exists", f"a runtime user {user.username!r} already exists")


def scenario_not_found(name: str) -> Refused:
    return Refused("not_found", f"no scenario {name!r}")


def remove_scenario(resolver: IdentityResolver, name: str) -> Union[Dict[str, Any], Refused]:
    """Remove the scenario and the user it created; a user a promotion
    holds refuses, and the scenario stays to be removed later."""
    try:
        username, user_removed = scenarios.remove(resolver, name)
    except scenarios.ScenarioNotFound:
        return scenario_not_found(name)
    except PromotionInProgress:
        return Refused(
            "promotion_in_progress",
            f"the user of scenario {name!r} is being promoted; the scenario was not removed",
        )
    return {"deleted": name, "kind": "scenario", "user": username, "user_removed": user_removed}


def promote(kind: str, name: str, do: Callable[[], PromotionOutcome]) -> Union[Dict[str, Any], Refused]:
    """The promotion's answer: what was promoted and into which file, or why
    not. The reasons a caller must not see go to the log."""
    file_name = PROMOTION_FILES[kind]
    try:
        outcome = do()
    except RuntimeObjectNotFound:
        return not_found(kind, name)
    except PromotionInProgress:
        return Refused("promotion_in_progress", f"runtime {kind} {name!r} is being promoted")
    except DocumentRejected as exc:
        # Refused before the file was replaced (#366): a pre-write refusal,
        # like ConflictError, not the post-write reload failure below.
        return Refused("unloadable", exc.message)
    except DeclaredNameCollision:
        return Refused("declared", f"{kind} {name!r} is already declared in {file_name}")
    except ConflictError:
        return Refused("conflict", f"{file_name} changed since it was read; nothing was written")
    except LockUnavailableError as lock:
        if lock.retryable:
            return Refused("lock_unavailable", f"{file_name} is locked by another write; try again", retryable=True)
        # A lock this directory or filesystem cannot give: not later either.
        return Refused("lock_unavailable", f"the lock of {file_name} cannot be taken; nothing was written")
    except PostWriteError as exc:
        # Written, but the state after the write did not complete; the object
        # stays marked until a reload succeeds (#192).
        logger.error("Promotion of runtime %s %r: %s", kind, name, exc)
        return Refused(
            "reload_failed",
            f"{name!r} was written to {file_name}, but the configuration could not be "
            f"reloaded; a successful reload completes the promotion",
        )
    except (ConfigurationRejected, HookError) as exc:
        # The entry is in the file; the configuration around it did not load.
        # The runtime object stays until a reload succeeds, which retires it
        # as promoted.
        return Refused(
            "reload_failed",
            f"{name!r} was written to {file_name}, but the configuration could not be "
            f"reloaded: {exc.message}",
        )
    except (RuntimeStoreUnavailable, DeclaredConfigurationUnloadable):
        # Not the write's to answer for: a store held by another process, or
        # configuration files that changed and do not load. Each surface has
        # one answer for these, wherever they are met.
        raise
    except Exception:
        # Anything else stopped the write itself (an unreadable or malformed
        # file on disk, an I/O error): nothing was written, the object stays.
        # The reason goes to the log, not to the caller.
        logger.exception("Promotion of runtime %s %r could not write %s", kind, name, file_name)
        return Refused("write_failed", f"{name!r} could not be written to {file_name}")
    body: Dict[str, Any] = {"promoted": name, "kind": kind, "file": file_name}
    if outcome.mirror_error is not None:
        body["mirror_hook_error"] = outcome.mirror_error
    return body


def reset(resolver: IdentityResolver) -> Dict[str, int]:
    """Remove every runtime user and client, and the test state that goes
    with them. Never touches the declared configuration."""
    # The scenarios first (#402): a scenario without its user refuses its
    # steps, while a user without its scenario is a runtime user like any
    # other, which the next line removes.
    scenarios_removed = scenarios.reset()
    users_deleted, clients_deleted = resolver.reset_runtime_identities()
    # Every browser's authenticated session at /authorize is test state
    # too (#468): a reset ends them all, whoever they were for.
    sessions_ended = get_authenticated_session_store().delete_all()
    # So are the id_token_hint references a form POST parked (#468): test
    # state of the same store, dropped with the rest.
    get_parked_hint_store().delete_all()
    # Tidiness, and the capacity count: the records of the clients that just
    # went match nothing any more (#404), including a client created under
    # one of those ids before this line runs.
    prune_stale_registrations(resolver)
    return {
        "users_deleted": users_deleted,
        "clients_deleted": clients_deleted,
        "sessions_ended": sessions_ended,
        "scenarios_removed": scenarios_removed,
    }
