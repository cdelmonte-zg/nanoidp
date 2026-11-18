"""Stateful identity scenarios (#402): a runtime user that changes during a
test, in answer to the protocol calls of the application under test.

A scenario is disposable test state. It creates one runtime user
(``given``) and holds steps, each ``after`` a number of protocol events for
that user and with one change to make to it (``update_user``):

    given alice.roles = [USER]
    after token_issued for alice (1st) -> alice.roles = [ADMIN]

The application asks for its tokens as it always does. The token that fires
the step carries the values from before the change: a grant reads its user
before the token is built, and the event is emitted once the token exists.
The next request sees the changed user.

**Two repositories, tied by an instance.** The scenario's record and its
user are kept in two repositories, and nothing is transactional across them
(``runtime_repository``). What ties them is the user's ``instance_id``,
which the record keeps: every change to the user and its removal name that
instance, so a user deleted and created again under the same name is
another user, which a step refuses and a removal leaves alone.

- *Arming*: the record first, as ``arming``; then the user; then the record
  takes the user's instance, which is what ``armed`` means. Only an armed scenario
  counts events. A process that dies in between leaves an ``arming`` record
  that never fires and whose removal removes no user: no instance was
  recorded, so none is known to be the scenario's.
- *A step*: counted and, at its count, marked ``pending`` in one decision on
  the record; the user changed in one decision on its entry; then the
  outcome written to the record. A step is ``pending`` until its outcome is
  recorded. A process that dies after changing the user and before
  recording leaves it ``pending``: whether the change was made is not
  known, and nothing here applies a step twice or writes over what came
  after it. A step fires once.
- *Removal*: the user first, by instance, then the record. A user a
  promotion holds refuses the removal and the scenario stays as it was. A
  user already promoted is no runtime object any more: nothing is removed
  and the declared user stays.

**A step that fails does not fail the request that fired it.** The token is
delivered; the step says ``refused`` or ``failed`` with its reason, so a
test tells an applied step from one that was not.
"""

import logging
import uuid
from typing import Annotated, Any, Callable, Dict, List, Literal, Optional, Tuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    WithJsonSchema,
    model_validator,
)

from ..config import User
from ..config_documents import EntryInvalid, parse_runtime_user, parse_user_entry
from .audit import get_audit_log
from .identities import IdentityResolver, PromotionInProgress, RuntimeObjectNotFound, get_identities
from .protocol_events import TOKEN_ISSUED, EventName, ProtocolEvent, UserGrantType
from .runtime_repository import (
    Entry,
    RepositoryTransaction,
    RuntimeStoreUnavailable,
    consume,
    create_within,
    delete_if,
)
from .runtime_store import PydanticCodec, RuntimeObjectExists, RuntimeRepository, get_runtime_store

logger = logging.getLogger(__name__)

# A step's decision reads every scenario, on every event: a small cap.
MAX_SCENARIOS = 100
MAX_STEPS = 20

# What a step may change: the fields of a user that carry authority. Not
# the name, which is the key, nor the credentials.
UPDATABLE = ("roles", "groups", "entitlements", "source_acl", "identity_class", "attributes")

# The audit event of a step that reached its count, whatever became of it.
STEP = "runtime_scenario_step"

ARMING = "arming"
ARMED = "armed"

WAITING = "waiting"
PENDING = "pending"
APPLIED = "applied"
REFUSED = "refused"
FAILED = "failed"

# Why a step was refused: the user is not the instance the scenario
# created (deleted, or deleted and created again), or a promotion holds it
# and would write the value it claimed over the change.
USER_GONE = "user_gone"
USER_HELD = "user_held"
# Why a step failed: the store was held by another process for longer than
# it waits, or something else went wrong, which the log says.
STORE_UNAVAILABLE = "store_unavailable"
ERROR = "error"


class ScenarioExists(ValueError):
    """A scenario already goes by that name."""


class ScenarioNotFound(LookupError):
    """No scenario goes by that name."""


class ScenariosFull(Exception):
    """The repository holds as many scenarios as it keeps."""


class ScenarioRemovedWhileArming(Exception):
    """The record went (a reset) between its creation and its user's."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Trigger(_Strict):
    event: EventName = Field(description="The protocol event the step waits for")
    # One of the grants that issue a token for a user: any other would arm
    # a step that never fires.
    grant_type: Optional[UserGrantType] = Field(
        default=None, description="Only for token_issued: count the tokens of this grant only"
    )
    count: StrictInt = Field(
        default=1, ge=1, description="The number of matching events after which the step fires, counted from the arming"
    )

    @model_validator(mode="after")
    def _known(self) -> "Trigger":
        if self.grant_type is not None and self.event != TOKEN_ISSUED:
            raise ValueError(f"grant_type is only for {TOKEN_ISSUED}")
        return self

    def matches(self, event: ProtocolEvent) -> bool:
        return self.event == event.name and self.grant_type in (None, event.grant_type)


def _user_properties() -> Dict[str, Any]:
    properties: Dict[str, Any] = User.model_json_schema()["properties"]
    return properties


# What the two objects below are, said as the user model says its fields.
# They are read by the parser of a runtime user, in every form a users.yaml
# entry has, and not by a model of their own, so the schema is attached to
# them rather than derived from a second description of a user.
_GIVEN_USER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "description": (
        "The runtime user the scenario creates: 'username' plus the fields of a users.yaml entry. "
        "Other keys are attributes, as in the file."
    ),
    "properties": _user_properties(),
    "required": ["username"],
    "additionalProperties": True,
}
_UPDATE_USER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "description": "The fields to set on the scenario's user when the step fires; each named field is replaced whole.",
    # Without the defaults of the model: a field that is not named is left
    # as it is, not set to its default.
    "properties": {
        name: {key: value for key, value in _user_properties()[name].items() if key != "default"} for name in UPDATABLE
    },
    "minProperties": 1,
    "additionalProperties": False,
}


class StepDeclaration(_Strict):
    after: Trigger
    update_user: Annotated[Dict[str, Any], WithJsonSchema(_UPDATE_USER_SCHEMA)]


class Given(_Strict):
    user: Annotated[Dict[str, Any], WithJsonSchema(_GIVEN_USER_SCHEMA)]


class ScenarioDeclaration(_Strict):
    """What a caller declares to arm a scenario: the body of ``POST
    /api/runtime/scenarios`` and the arguments of the MCP tool, whose
    input schema is this model's."""

    # A path segment as every client sends it: no dot segment.
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", description="The scenario's name")
    given: Given
    steps: List[StepDeclaration] = Field(min_length=1, max_length=MAX_STEPS)


class Step(BaseModel):
    after: Trigger
    update_user: Dict[str, Any]
    seen: int = 0
    state: Literal["waiting", "pending", "applied", "refused", "failed"] = "waiting"
    reason: Optional[str] = None
    # Which firing marked the step pending, so that only that firing
    # records its outcome.
    attempt: Optional[str] = None


class Scenario(BaseModel):
    name: str
    username: str
    # The instance of the user this scenario created. None while arming:
    # a scenario is armed by having one, and by nothing else.
    user_instance_id: Optional[str] = None
    steps: List[Step]

    @property
    def state(self) -> str:
        return ARMED if self.user_instance_id is not None else ARMING


def _repository() -> RuntimeRepository[Scenario]:
    return get_runtime_store().repository("scenarios", lambda record: record.name, PydanticCodec(Scenario))


# ---- the declaration ---------------------------------------------------------


def _message(exc: ValidationError) -> str:
    first = exc.errors(include_url=False, include_input=False, include_context=False)[0]
    where = ".".join(str(part) for part in first["loc"])
    return f"{where}: {first['msg']}" if where else str(first["msg"])


def scenario_from(body: Dict[str, Any], where: str) -> Tuple[Scenario, User]:
    """The record of a scenario and the user it is to create, from the
    declaration. EntryInvalid when it does not validate: the scenario's own
    shape, the user as a runtime user is validated, and each change as the
    user's model validates the fields it sets."""
    try:
        spec = ScenarioDeclaration.model_validate(body)
    except ValidationError as exc:
        raise EntryInvalid(f"{where}: {_message(exc)}") from None
    user = parse_runtime_user(spec.given.user, f"{where}: given.user")
    username = user.username
    # The user as it was read, not the entry as it was written: an entry
    # may carry attributes as keys of its own, which the reading folds
    # into ``attributes``. A change validated over the written entry would
    # have them folded back in, and a step that sets ``attributes`` would
    # not replace them.
    entry = user.model_dump(exclude={"username"}, exclude_none=True)
    steps = []
    for index, step in enumerate(spec.steps):
        unknown = sorted(set(step.update_user) - set(UPDATABLE))
        if unknown or not step.update_user:
            raise EntryInvalid(
                f"{where}: steps.{index}.update_user sets one or more of {', '.join(UPDATABLE)}"
                + (f", not {', '.join(unknown)}" if unknown else "")
            )
        # Validated as the user with the change made, so what is stored is
        # what the model made of it and a step cannot fail on its value.
        changed = parse_user_entry(username, {**entry, **step.update_user}, f"{where}: steps.{index}.update_user")
        steps.append(Step(after=step.after, update_user={name: getattr(changed, name) for name in step.update_user}))
    return Scenario(name=spec.name, username=username, steps=steps), user


# ---- arming and removing -----------------------------------------------------


def arm(resolver: IdentityResolver, scenario: Scenario, user: User) -> Scenario:
    """Arm ``scenario`` and create its user. Raises ScenarioExists or
    ScenariosFull, or what the creation of the user raises
    (DeclaredNameCollision, RuntimeObjectExists)."""
    repository = _repository()
    try:
        record = create_within(repository, scenario, MAX_SCENARIOS, full=ScenariosFull())
    except RuntimeObjectExists:
        raise ScenarioExists(scenario.name) from None
    try:
        created = resolver.create_runtime_user_entry(user)
    except Exception:
        # No user of this scenario exists: the record goes, unless
        # something else took it first. Not on a BaseException: the process
        # is going, and the record says what is known, that it was arming.
        delete_if(repository, scenario.name, record.instance_id)
        raise

    try:
        result = _take_the_user(repository, record, created)
    except Exception:
        # The user exists and the record does not name it (the store held
        # by another process): both go, so that arming again can succeed.
        # What cannot be undone either stays as an arming record and a
        # runtime user, each removable on its own.
        _remove_user(resolver, user.username, created.instance_id)
        delete_if(repository, scenario.name, record.instance_id)
        raise
    if result is None:
        # A reset took the record in between: the user is this call's and
        # nobody's scenario, so it goes too.
        _remove_user(resolver, user.username, created.instance_id)
        raise ScenarioRemovedWhileArming(scenario.name)
    return result


def _take_the_user(
    repository: RuntimeRepository[Scenario], record: Entry[Scenario], created: Entry[User]
) -> Optional[Scenario]:
    """The third step of arming: that instance of the record takes the
    user's instance. None when the record is gone or another goes by its
    name."""

    def armed(view: RepositoryTransaction[Scenario]) -> Optional[Scenario]:
        current = view.entry(record.name)
        if current is None or current.instance_id != record.instance_id:
            return None
        return view.replace(
            record.name, current.value.model_copy(update={"user_instance_id": created.instance_id})
        ).value

    return repository.transact(armed)


def _remove_user(resolver: IdentityResolver, username: str, instance_id: str) -> bool:
    """Remove that instance of the user; False when it is not there: it
    was deleted, or deleted and created again, or promoted, which leaves a
    declared user and no runtime object. PromotionInProgress when a
    promotion holds it."""
    try:
        resolver.delete_runtime_user(username, instance_id)
    except RuntimeObjectNotFound:
        return False
    return True


def remove(resolver: IdentityResolver, name: str) -> Tuple[str, bool]:
    """Remove the scenario and the user it created; the user's name and
    whether a user was removed. Raises ScenarioNotFound, or
    PromotionInProgress when a promotion holds the user, and then the
    scenario stays as it was."""
    repository = _repository()
    seen = repository.entry(name)
    if seen is None:
        raise ScenarioNotFound(name)
    removed = False
    while True:
        if seen.value.user_instance_id is not None:
            removed = _remove_user(resolver, seen.value.username, seen.value.user_instance_id) or removed
        _about_to_remove_the_record(name)
        if consume(repository, name, _as_seen(seen)) is not None:
            return seen.value.username, removed
        current = repository.entry(name)
        if current is None or current.instance_id != seen.instance_id:
            return seen.value.username, removed
        seen = current


def _as_seen(seen: Entry[Scenario]) -> Callable[[Entry[Scenario]], bool]:
    """Whether a record is the one that was looked at: that instance (one
    armed under the name meanwhile is another scenario) and that user. A
    record that took its user since (an arming that completed) is looked
    at again, or its user would be left behind."""

    def as_seen(current: Entry[Scenario]) -> bool:
        return (
            current.instance_id == seen.instance_id
            and current.value.user_instance_id == seen.value.user_instance_id
        )

    return as_seen


def _about_to_remove_the_record(name: str) -> None:
    """Called after the user's removal and before the record's: a seam for
    a test to stand between the two."""


def reset() -> int:
    """Remove every scenario and say how many. Their users are runtime
    identities and go with the reset of those."""
    return _repository().delete_all()


def get(name: str) -> Optional[Scenario]:
    return _repository().get(name)


def all_scenarios() -> List[Scenario]:
    return _repository().list()


def view_of(scenario: Scenario) -> Dict[str, Any]:
    """What a caller is shown: the declaration and the state of each step."""
    return {
        "name": scenario.name,
        "state": scenario.state,
        "user": scenario.username,
        "steps": [
            {
                "after": step.after.model_dump(exclude_none=True),
                "update_user": step.update_user,
                "seen": step.seen,
                "state": step.state,
                **({"reason": step.reason} if step.reason is not None else {}),
            }
            for step in scenario.steps
        ],
    }


# ---- the steps ---------------------------------------------------------------


class _Fired(BaseModel):
    scenario: str
    index: int
    attempt: str
    username: str
    user_instance_id: str
    update_user: Dict[str, Any]


def _count(event: ProtocolEvent) -> List[_Fired]:
    """Count ``event`` on every waiting step it matches, as one decision,
    and mark pending the ones that reached their count."""

    def decide(view: RepositoryTransaction[Scenario]) -> List[_Fired]:
        fired: List[_Fired] = []
        for entry in view.entries():
            scenario = entry.value
            if scenario.user_instance_id is None or scenario.username != event.username:
                continue
            steps = list(scenario.steps)
            for index, step in enumerate(steps):
                if step.state != WAITING or not step.after.matches(event):
                    continue
                seen = step.seen + 1
                if seen < step.after.count:
                    steps[index] = step.model_copy(update={"seen": seen})
                    continue
                attempt = uuid.uuid4().hex
                steps[index] = step.model_copy(update={"seen": seen, "state": PENDING, "attempt": attempt})
                fired.append(
                    _Fired(
                        scenario=scenario.name,
                        index=index,
                        attempt=attempt,
                        username=scenario.username,
                        user_instance_id=scenario.user_instance_id,
                        update_user=step.update_user,
                    )
                )
            if steps != scenario.steps:
                view.replace(scenario.name, scenario.model_copy(update={"steps": steps}))
        return fired

    return _repository().transact(decide)


def _change(fired: _Fired) -> Optional[str]:
    """Make the step's change to the user, as one decision on that
    instance. None when it was made, or why it was refused. The rule (that
    instance, and not while a promotion holds it) is the resolver's."""
    try:
        get_identities().replace_runtime_user(
            fired.username, fired.user_instance_id, lambda user: user.model_copy(update=fired.update_user)
        )
    except RuntimeObjectNotFound:
        return USER_GONE
    except PromotionInProgress:
        return USER_HELD
    return None


def _record(fired: _Fired, state: str, reason: Optional[str]) -> None:
    """Write the outcome on the step, if it is still pending from this
    firing: a scenario removed meanwhile, or armed again under the name,
    is not this one's to write on."""

    def decide(view: RepositoryTransaction[Scenario]) -> None:
        current = view.entry(fired.scenario)
        if current is None or fired.index >= len(current.value.steps):
            return
        step = current.value.steps[fired.index]
        # The attempt is set when a step turns pending and never again: a
        # step that carries this one is pending from this firing.
        if step.attempt != fired.attempt:
            return
        steps = list(current.value.steps)
        steps[fired.index] = step.model_copy(update={"state": state, "reason": reason})
        view.replace(fired.scenario, current.value.model_copy(update={"steps": steps}))

    _repository().transact(decide)


def _apply(fired: _Fired) -> None:
    _about_to_change(fired)
    try:
        refusal = _change(fired)
        state, reason = (APPLIED, None) if refusal is None else (REFUSED, refusal)
    except RuntimeStoreUnavailable:
        state, reason = FAILED, STORE_UNAVAILABLE
    except Exception:
        logger.exception("Step %d of scenario %r could not change user %r", fired.index, fired.scenario, fired.username)
        state, reason = FAILED, ERROR
    if state != APPLIED:
        logger.error(
            "Step %d of scenario %r was not applied to user %r: %s (%s)",
            fired.index, fired.scenario, fired.username, state, reason,
        )
    _about_to_record(fired)
    try:
        _record(fired, state, reason)
    except Exception:
        # The step stays pending, which is what is known to the record.
        logger.exception(
            "The outcome of step %d of scenario %r (%s) could not be recorded; the step stays pending",
            fired.index, fired.scenario, state,
        )
    _audit(fired, state, reason)


def _about_to_change(fired: _Fired) -> None:
    """Called after a step is marked pending and before its user is
    changed: a seam for a test to stand between the two decisions."""


def _about_to_record(fired: _Fired) -> None:
    """Called after the user's decision and before the outcome is
    recorded: a seam for a test to stand between the two decisions."""


def _audit(fired: _Fired, state: str, reason: Optional[str]) -> None:
    try:
        get_audit_log().log(
            event_type=STEP,
            endpoint="scenario",
            method="internal",
            status="success" if state == APPLIED else "failed",
            username=fired.username,
            client_id=None,
            ip_address="unknown",
            user_agent="unknown",
            details={
                "scenario": fired.scenario,
                "step": fired.index,
                "outcome": state,
                **({"reason": reason} if reason is not None else {}),
            },
        )
    except Exception:  # the audit must not fail the request that fired the step
        logger.exception("Could not record %s for scenario %r", STEP, fired.scenario)


def on_protocol_event(event: ProtocolEvent) -> None:
    """The observer of the protocol events: count ``event`` and apply the
    steps that reached their count, in the order of their scenarios and
    steps. Raises nothing the dispatcher does not log; a count that could
    not be made (the store held by another process) leaves the steps as
    they were, and says so in the log."""
    # A look before the decision: most events are for no scenario's user,
    # and a decision takes the store's write lock.
    if not any(
        scenario.state == ARMED
        and scenario.username == event.username
        and any(step.state == WAITING and step.after.matches(event) for step in scenario.steps)
        for scenario in all_scenarios()
    ):
        return
    try:
        fired = _count(event)
    except RuntimeStoreUnavailable:
        logger.error(
            "%s for user %r was not counted by its scenarios: the runtime store is held by another writer",
            event.name, event.username,
        )
        return
    for one in fired:
        _apply(one)
