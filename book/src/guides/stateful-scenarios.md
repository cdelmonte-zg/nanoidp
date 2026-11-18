# Stateful identity scenarios

A scenario is a runtime user that changes during a test, in answer to the
protocol calls of the application under test. The test arms it once; the
application then asks for its tokens as it always does, and the identity
provider changes the user at the point the scenario names.

```text
given alice.roles = [USER]
after the 1st token issued for alice -> alice.roles = [ADMIN]
```

The case it is for: an application that reads the user's authorization
again on its next token, and has to reflect a change of role. Without a
scenario the test changes the user between two calls of the application,
which it has to time. With one, nothing touches the identity provider in
between.

A scenario is test state like a [disposable test
identity](runtime-identities.md): it lives in the runtime store, never
reaches the declared files, and goes with a reset.

## Arming a scenario

```bash
curl -X POST http://localhost:8000/api/runtime/scenarios \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "role-change",
    "given": {"user": {"username": "alice", "password": "pw", "roles": ["USER"]}},
    "steps": [
      {"after": {"event": "token_issued", "count": 1},
       "update_user": {"roles": ["ADMIN"]}}
    ]
  }'
```

- `given.user` is created as a runtime user, validated like one made with
  `POST /api/runtime/users`. A scenario of that name, or a user of that
  name, declared or runtime, is `409`.
- Each step is `after` a number of events for that user, and has one
  change to make to it. `count` is the number of matching events after
  which the step fires, counted for each step from the moment the scenario
  is armed; it defaults to 1. A step fires once.
- `update_user` sets one or more of `roles`, `groups`, `entitlements`,
  `source_acl`, `identity_class` and `attributes`. Each field it names is
  replaced whole, `attributes` included; a field it does not name stays as
  it is.
- Unknown keys, an unknown event and a `grant_type` that issues no token
  for a user are refused: a step that could never fire is not armed.

With `session.management_secret` set, arming and removing need it, as every
write of `/api`; reading does not.

## The events

| Event | Emitted | Matchers |
|-------|---------|----------|
| `token_issued` | by `/token`, once a token for the user is built | `grant_type`, optional: `password`, `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code` |
| `authorization_completed` | by `/authorize`, once the authorization code is stored | none |

A refresh is `token_issued` with `grant_type: refresh_token`. A client
credentials token has no user and is no event. `POST
/api/users/{username}/token` and the MCP token tools mint a token for the
test itself and are no event either.

## What the application sees

The token that fires a step carries the values from before the change: the
event is emitted once the token exists. The change is made inside that
request, before its response leaves, so the next request sees the changed
user: the next token, and `/userinfo`, which reads the user when it is
asked, also for a token issued before.

This order holds for calls made one after the other. Two requests in flight
together have no promised order.

## Reading the state

```bash
curl http://localhost:8000/api/runtime/scenarios/role-change
```

```json
{
  "name": "role-change",
  "state": "armed",
  "user": "alice",
  "steps": [
    {"after": {"event": "token_issued", "count": 1},
     "update_user": {"roles": ["ADMIN"]},
     "seen": 1,
     "state": "applied"}
  ]
}
```

| Step state | Meaning |
|------------|---------|
| `waiting` | `seen` events so far, fewer than `count` |
| `applied` | the change was made |
| `refused` | the change was not made, and `reason` says why: `user_gone` (the user the scenario created was deleted, or deleted and created again), `user_held` (a promotion holds it) |
| `failed` | the change could not be made: `store_unavailable` (the runtime store was held by another process for longer than it waits) or `error` (the server log has it) |
| `pending` | the step reached its count and its outcome was not recorded |

A step that is refused or fails does not fail the request that fired it:
the token is delivered, the server log says what happened, and a test that
depends on the change asserts `applied`.

`pending` is what a step shows between reaching its count and its outcome.
A step that still shows it after the request has ended never had its
outcome recorded: the process was lost in between, or the store could not
be written, which the server log says. From the scenario alone it is not
known whether the change was made; the user is read at
`/api/runtime/users/{username}`. Nothing applies the step later: remove the
scenario and arm it again.

A scenario whose `state` is `arming` was not armed to the end: the process
was lost while arming it. It never fires, and removing it removes no user,
so a runtime user it had already created is removed on its own.

## Removing a scenario

```bash
curl -X DELETE http://localhost:8000/api/runtime/scenarios/role-change
```

removes the scenario and the user it created, and answers the `user` and
whether it was removed (`user_removed`). The scenario owns that one user,
not its name:

- A user deleted and created again under the same name is another user.
  Its steps are refused as `user_gone`, and removing the scenario leaves
  that user alone.
- A user that is being promoted answers `409`, and the scenario stays to be
  removed afterwards.
- A user that was promoted is a declared user: removing the scenario
  removes nothing, and the declared user stays.

`DELETE /api/runtime` removes every scenario with the rest of the runtime
state and counts them in `scenarios_removed`.

Several scenarios can be armed on one instance as long as their users
differ, so tests that run in parallel each remove their own instead of
resetting.

## The same operations as MCP tools

With a [runtime store shared with the
server](shared-runtime-store.md) an agent arms and reads scenarios through
`nanoidp-mcp`:

| Tool | HTTP |
|------|------|
| `arm_scenario` | `POST /api/runtime/scenarios` |
| `list_scenarios` | `GET /api/runtime/scenarios` |
| `get_scenario` | `GET /api/runtime/scenarios/{name}` |
| `remove_scenario` | `DELETE /api/runtime/scenarios/{name}` |

The arguments of `arm_scenario` are the declaration above, and its input
schema says it in full: the events and the grant types as enums, the limits
of the name, of `count` and of the steps, the fields of the user and the
ones `update_user` may set. A declaration the schema refuses is answered
`MCP_INVALID_ARGUMENTS` before anything is created; what only the server
can judge (an invalid email, a name that is taken) is answered with the
`kind` the HTTP surface gives it. The views and the refusal kinds are the
same on both surfaces, and `get_scenario` answers `found: false` for a name
that is not there.

The schema is stricter than the HTTP body in one place: an optional field
is published as its value type, as for the other tools, so a step that
clears `identity_class` with `null` is armed over HTTP.

The MCP server arms, reads and removes; it fires nothing. A step is fired
by the server that answers the application's request, which is why the
tools need the shared store: with the default in-memory store they are
refused with `MCP_RUNTIME_STORE_NOT_SHARED`. The token tools of MCP are no
event, as `POST /api/users/{username}/token` is none. In read-only mode
`list_scenarios` and `get_scenario` stay available.

## Good to know

- **A shared store.** With `runtime.store: sqlite` the scenario is in the
  store, so whichever process serves the request counts the event and
  makes the change; see [Two processes, one runtime
  state](shared-runtime-store.md).
- **Audit.** Arming and removing are audit events
  (`runtime_scenario_armed`, `runtime_scenario_removed`), and so is every
  step that reached its count (`runtime_scenario_step`, with the scenario,
  the step and its outcome).
- **Limits.** One hundred scenarios, twenty steps each.
