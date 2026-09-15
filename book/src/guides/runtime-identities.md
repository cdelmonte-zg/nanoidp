# Disposable test identities

An integration test or a CI job often needs users and clients that exist for
one run: `ci-alice` with a given role, a client with a narrow scope, a
public client for a PKCE flow. Declaring them in `users.yaml` and
`settings.yaml` changes the baseline every other test starts from, and
restarting the IdP to pick them up is slow.

`/api/runtime` creates them on a running IdP instead. They work in every
protocol flow at once, they never touch the declared files, and a single
call removes them all. When one turns out to be worth keeping, it can be
promoted into the declared configuration.

## Create, use, remove

```bash
# A runtime user: the body is a users.yaml entry plus "username"
curl -X POST http://localhost:8000/api/runtime/users \
  -H 'Content-Type: application/json' \
  -d '{"username": "ci-alice", "password": "alice-pw", "roles": ["TESTER"]}'

# A runtime client: the body is an oauth.clients[] entry
curl -X POST http://localhost:8000/api/runtime/clients \
  -H 'Content-Type: application/json' \
  -d '{"client_id": "ci-app", "client_secret": "app-secret", "redirect_uris": ["http://localhost:3000/callback"]}'

# Use them like declared ones
curl -X POST http://localhost:8000/token -u ci-app:app-secret \
  -d grant_type=password -d username=ci-alice -d password=alice-pw

# Remove one, or everything created at runtime
curl -X DELETE http://localhost:8000/api/runtime/users/ci-alice
curl -X DELETE http://localhost:8000/api/runtime
# {"clients_deleted": 1, "users_deleted": 0}
```

Payloads are validated by the same models as a declared entry, with the same
defaults and rules, and an invalid one answers `400` with the reason. The
responses never include a password or a client secret.

Runtime objects resolve through the same lookup as declared ones, on every
surface that authenticates: `/authorize` (persona auto-login included),
`/login`, every `/token` grant, client authentication, `/userinfo`,
`/introspect`, `/revoke`, the device flow, SAML SSO and AttributeQuery, and
`POST /api/users/{username}/token`. They appear, marked as `runtime`, in
`GET /api/users`, the persona picker, and the users and clients pages of the
web UI, where they are read-only: edit and delete there act on the declared
configuration, and a runtime object's lifecycle is `/api/runtime`'s. The
MCP server is a separate process and keeps working on the declared
configuration only.

## Operations

| Endpoint | What it does |
|---|---|
| `POST /api/runtime/users` | Create a runtime user (`201`) |
| `GET /api/runtime/users`, `GET /api/runtime/users/{username}` | Read runtime users (`404` for a declared or unknown name) |
| `DELETE /api/runtime/users/{username}` | Delete one |
| `POST /api/runtime/users/{username}/promote` | Write it into `users.yaml` and retire the runtime object |
| `POST /api/runtime/clients`, `GET /api/runtime/clients[/{client_id}]`, `DELETE ...`, `POST .../promote` | The same for clients, promoted into `settings.yaml` |
| `DELETE /api/runtime` | Remove every runtime user and client; answers the counts. It waits for a promotion in progress, and keeps an object whose promotion is waiting for a successful reload |

There is no update: delete and create again. Errors are JSON with an `error`
and a `kind`: `invalid` (`400`), `not_found` (`404`), `declared` or `exists`
(`409`, the name is declared, or already a runtime object),
`promotion_in_progress` (`409`), `conflict` (`409`) and `lock_unavailable`
(`503`) from the file writer, and `write_failed` or `reload_failed` (`500`)
for a promotion.

## The rules

- **Declared first.** A name resolves to the declared object when there is
  one. A runtime object cannot be created under a declared name (`409`).
- **Declared wins on reload.** When a reload introduces a declared object with
  the name of a runtime one, the runtime one is removed, with a warning in the
  log and a `runtime_identity_removed_on_reload` audit event.
- **Reloads keep runtime state.** `POST /api/config/reload` and the writes of
  the web UI leave runtime objects in place. A restart clears them: they live
  in process memory.
- **Deleting is not revoking.** An access token already issued to a deleted
  runtime identity keeps verifying until it expires, as for a deleted declared
  one; a refresh token issued to it is refused.
- **Audit.** Creating, deleting, promoting and resetting are audit events
  (`runtime_identity_created`, `runtime_identity_deleted`,
  `runtime_identity_promoted`, `runtime_identities_reset`), with the object's
  kind and name; so are a reload removing a runtime object
  (`runtime_identity_removed_on_reload`) and an abandoned promotion
  (`runtime_identity_promotion_abandoned`).

## Promotion

`POST /api/runtime/users/{username}/promote` writes the user as a new entry
of `users.yaml` through the same writer the web UI uses, the file's comments
and placeholders included, and the runtime object is retired by the reload
that follows: one `runtime_identity_promoted` audit event, no collision
warning. The declared entry is then the only copy.

- If the name is already in the file, even one not reloaded yet, the
  promotion answers `409` and the runtime object stays.
- While a promotion runs, deleting or promoting the same object answers `409`.
- A strict `on_config_saved` hook that fails after the write does not undo it:
  the response carries `mirror_hook_error`, and the object is declared.
- If the file is written but the configuration then fails to reload (another
  file broken meanwhile, a strict plugin that does not load), the response is
  `500` (`reload_failed`) and the runtime object stays, marked, until a reload
  succeeds. That reload retires it as promoted, or, if the entry is no longer
  in the file by then, abandons the promotion with a warning and leaves the
  runtime object as it was.
- If the file cannot be written at all (it is malformed on disk, an I/O
  error), the response is `500` (`write_failed`) and nothing changes.
- A promotion holds reloads off until it finishes. Someone declaring the same
  name at that moment either wins the race to the file (the promotion answers
  `409` and that declaration's reload removes the runtime object as a
  collision) or writes after it (and gets the web UI's "already exists").

A promoted password or client secret is written as it was sent, as the web UI
forms do.

## Access

`/api/runtime` follows every other management write: open by default, like
the rest of `/api/*` and the web UI forms, and gated by
[`management_secret`](SECURITY.md#management-secret) when one is configured
(`X-Management-Secret` on `POST` and `DELETE`; reads stay open). Without a
secret, any host that can reach the IdP can already mint tokens for existing
users through `/api`, so a runtime identity adds no new capability; keep the
IdP on loopback or behind the secret when it is reachable from a network
(see [Network Binding](SECURITY.md#network-binding)).
