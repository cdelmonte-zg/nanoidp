# Architecture

This page is the map: where code lives, which direction imports are
allowed to flow, where state is kept, and the handful of modules you
must know before changing anything. Everything stated as an invariant
here is enforced by CI (import-linter, mypy, or a test), not aspired
to; when this page and the code disagree, one of the two is a bug.

## The shape

nanoidp is a layered Flask application with three entry points sharing
one core:

```text
 __main__.py (CLI)      mcp_server.py (MCP stdio)      app.py (WSGI)
        \______________________|______________________/
                               |
                        routes/  (HTTP surfaces)
                               |
                       services/  (protocol logic, runtime state)
                               |
                        config.py  (ConfigManager)
                               |
              serialization.py   models.py   config_documents.py
```

Two import contracts are enforced by `lint-imports` in CI (declared in
`pyproject.toml` under `[tool.importlinter]`):

1. **Layers: `routes` -> `services` -> `config`.** A route may import
   services and config; a service may import config; nothing imports
   upward. In practice: `services/` never imports Flask objects or
   route modules, so every service is testable without a request
   context.
2. **`serialization.py` has no runtime package imports.** It is pure
   YAML-shaping code; its only tie to the rest of the package is
   type-checking-only annotations. If you make it import a package
   module at runtime, CI fails.

Everything under `src/` is fully type-annotated
(`disallow_untyped_defs` in `[tool.mypy]`).

## Package map

Entry points:

| Module | What it is |
|---|---|
| `app.py` | `create_app()`: Flask app factory, blueprint registration, session cookie policy, startup warnings |
| `__main__.py` | The `nanoidp` CLI: serve, `init`, `wizard`, `validate-config`, `config-schema`, `plugins` |
| `mcp_server/` | The `nanoidp-mcp` stdio server: tool declarations and handlers. It keeps no configuration of its own: the tools resolve the process's `ConfigManager` (see `config.py`) |
| `wizard.py` | The `nanoidp wizard` interactive configuration builder |

HTTP surfaces (`routes/`), one blueprint per protocol surface:

| Module | What it is |
|---|---|
| `routes/oauth.py` | OAuth2/OIDC: `/authorize`, `/token` (one `_grant_*` helper per grant), `/userinfo`, discovery, JWKS, introspection, revocation, device flow |
| `routes/saml.py` | SAML 2.0 IdP: metadata, SSO, SLO, AttributeQuery |
| `routes/ui.py` | The config web dashboard: HTML form flows for users, clients, settings, keys, claims, audit |
| `routes/api.py` | JSON management API (`/api/*`): health, config, users, keys, audit |

Shared route infrastructure, all underscore-prefixed:

| Module | What it is |
|---|---|
| `routes/_auth.py` | The login-session and management-gate choke point: `establish_login_session` is the single writer of the login session (`session['user']` and `session['auth_method']`, which the SAML `AuthnContextClassRef` is derived from; every surface that establishes a UI session calls it, #301), plus the `require_ui_login` session gate and the opt-in `management_secret` write guard for `/api/*`, the UI unlock, and MCP |
| `routes/_issuer.py` | Effective-issuer resolution, shared by every endpoint that mints a token or advertises the issuer (#133: they must never disagree) |
| `routes/_audit.py` | `audit_event(...)`: shared helper for route-level audit events (not yet universal: `/api/keys/rotate` still logs directly) |

Protocol logic and runtime state (`services/`), each module small and
single-purpose:

| Module | What it is |
|---|---|
| `services/token.py` | JWT building: access tokens, ID Tokens, the `/token` response body |
| `services/userinfo.py` | What the bearer of an access token may see at `/userinfo`: the scope-to-claim gating, the claims nanoidp has no standard scope to gate by, the raw `attributes` passthrough, the `claims` request parameter |
| `services/client_policy.py` | How a client's `token_endpoint_auth_method` and secret go together: a public client has no secret, a confidential one cannot be without it, and the order an existing client is moved through (the model validates on assignment). The rest of what `is_public` decides stays at the endpoints that apply it, each with its own RFC (#300) |
| `services/introspection.py` | What an introspection reports about a token (RFC 7662 §2.2), including which client it names and the scope it defaults to |
| `services/identities.py` | The effective identities: declared users and clients composed with runtime ones. Every login, grant and client check resolves users and clients here (`identities_for(config)`), with the rules in one place: declared first, no runtime object under a declared name, declared wins on reload. The observation surfaces (`/api/users`, the persona picker, the UI lists) show declared and runtime objects with their origin; the edit forms and MCP work on the declared configuration. The lifecycle rules (promotion order, reconciliation with its audit) live here too, and so does `runtime_client_lifecycle()`, the one scope in which a runtime client is created, deleted, reset, registered, or has a registration credential checked against it, so that those operations are whole with respect to each other (one process; #404 and #405 for several) |
| `routes/runtime.py` | `/api/runtime`: create, read, delete, reset and promote runtime users and clients, mapped onto the resolver's rules; no update (the store is by value). Same management gate as `/api` |
| `services/runtime_repository.py` | The contract all runtime state is kept behind, and its in-memory backend: objects by name and by value, each in an entry with an `instance_id` the store generates and never reuses and an optional hold, and `transact(decide)`, which runs one decision against a view of one repository so that its changes appear together or not at all. `replace`, `consume`, `delete_if` and `create_within` are written once on top of it. The OAuth semantics stay in the services that write the decisions; a durable backend (#354) implements `transact` and inherits the rest |
| `services/runtime_identities.py` | The runtime identity store: users and clients created while the IdP runs, in memory, two repositories behind one lock, and the repositories it lends to services that own a record type of their own. Holds nothing else |
| `services/auth_code.py` | Authorization-code store (PKCE data rides on the code) |
| `services/device_code.py` | Device-flow code store |
| `services/revocation.py` | In-memory revocation and refresh-rotation family state |
| `services/crypto.py` | Key management: generation, rotation, JWKS, external key import |
| `services/discovery.py` | Single source of the OIDC discovery document (HTTP and MCP both render this; metadata never lies) |
| `services/redirect_uri.py` | Redirect-URI registration matching, including RFC 8252 native-app rules |
| `services/saml_verification.py` | Signed-AuthnRequest verification |
| `services/saml_assertion.py` | The parts of a SAML Response every builder spells the same way: the envelope, the `Issuer` pair, the `Status` element and the assertion's head. Deliberately not the `Conditions`: the validity window differs by surface and is declared in the SAML reference instead (#317) |
| `services/audit.py` | The audit log (in-memory ring, export) |
| `services/yaml_writer.py` | Writes the YAML files back for the UI's per-field saves. Not the only write path: `ConfigManager.save()` persists whole documents through `serialization.atomic_write_yaml` too - both build their entries in `serialization.py`, but the read-modify-write itself has two owners today (a known debt, tracked for a single write pipeline with conflict detection) |

The config layer and the pure bottom:

| Module | What it is |
|---|---|
| `config.py` | `ConfigManager`: owns loading, reloading and handing out `Settings`/users; loads are transactional (a failed reload commits nothing). One manager per process (`init_config`/`get_config`): the routes, the MCP tools and the token service all resolve it, and none of them keeps a manager, or a signing service derived from its settings, from the moment it was first built |
| `config_store.py` | `ConfigFileStore`: filesystem access to ONE configuration directory. Bytes and their revisions come back as one observation, taken under the directory lock, for readers and writers alike (#246). It owns observations, not configuration semantics: parsing, environment expansion and the document models stay outside it, and outside the lock, because the atomic unit is the directory snapshot rather than the whole reload. A read never abandons an available protocol: contention and a filesystem without advisory locking both fail. A read-only mount keeps working by reopening the lock file read-only, so it still takes part; only a view that can hold no lock file at all, or a missing directory, reads unlocked, neither having a writer to be inconsistent with |
| `config_documents.py` | Pydantic document models mirroring the YAML sections one to one; `to_settings()` / `to_users()` build the domain objects |
| `config_schema.py` | JSON Schema generated from the document models; `docs/schema/config.v1.json` is the committed artifact and a test fails when they diverge |
| `config_validation.py` | `nanoidp validate-config`: lint a config directory without starting anything (hooks never execute) |
| `hooks.py` | `HookRegistry`: the extension points (`on_before_load`, `on_config_saved`, `on_audit_event`), shell hooks, entry-point plugins, the bootstrap surface |
| `models.py` | The domain dataclass-style models: `Settings`, `User`, `OAuthClient` |
| `serialization.py` | Domain objects <-> YAML dicts, both directions, no runtime package imports; `OWNED_SETTINGS` is the one table of managed settings.yaml keys, pinned to the models by parity tests (#214) |
| `exceptions.py` | The exception taxonomy |
| `branding.py` | Per-client logo resolution (local assets only, containment-checked) |

## Where state lives

There are exactly two kinds of state, and they never share a store:

- **Declared configuration** is the two YAML files (`settings.yaml`,
  `users.yaml`, plus the optional `bootstrap.yaml` for hooks/plugins).
  It is schema-versioned (`config_version`), validated through the
  document models, editable by hand, and meant to be committed to git.
  The UI's per-field saves go through `services/yaml_writer.py`; the
  MCP `save_config` tool and reloads persist whole documents through
  `ConfigManager.save()`. Both delegate their entry-building to
  `serialization.py`, so the two paths cannot drift on content, and both
  write through the same `config_writer.compare_and_replace` pipeline
  (#229): each write can carry the revision the caller's state was read
  at, and a stale one is refused instead of overwriting a concurrent
  change - the UI's forms submit it as a hidden field, MCP callers pass
  it to `save_config`. Without a revision a write stays unconditional
  (last write wins), stated as such.
- **Runtime state** lives in memory inside `services/`: authorization
  codes, device codes, revocation and rotation families, the audit
  log, runtime users and clients (`services/runtime_identities.py`), and
  Flask sessions. It is lost on restart by design; an
  instance is disposable (see [Vision](vision.md)). If you are about
  to persist runtime state to disk, stop and re-read the
  database-persistence non-goal.

`ConfigManager.load()` is transactional: parse and validate first,
swap the live objects only on success. A failed reload leaves the
previous configuration serving. The transaction includes the signing
service (#359): a configuration becomes active only if its signing
service can be built. The load prepares that service from the candidate
settings (reusing the running one when its inputs are unchanged), then
applies the hooks and plugins, the last step that can fail, then publishes
the service, then the settings. Readers take the settings first and the
signing service second (`get_crypto_service()` has no arguments), so a
request can pair older settings with a newer key but never newer settings
with an older key. `create_app` and the MCP server pass that activation
step to `init_config`; `config` itself never imports `services`.

## The five modules to know before changing anything

- **`routes/_auth.py`**: every management mutation (UI form, `/api/*`,
  MCP tool) funnels through here. If you add a mutating endpoint and
  do not touch this file, ask yourself why.
- **`routes/_issuer.py`**: any new endpoint that mints or advertises
  tokens resolves the issuer here, or it will disagree with discovery
  behind a reverse proxy.
- **`services/discovery.py`**: the discovery document is built once,
  here. Advertise a capability by implementing it and adding it here;
  never edit an endpoint's advertisement separately.
- **`hooks.py`**: the supported way to integrate external systems.
  New integration points should be hooks, not backends (a VISION
  non-goal).
- **`config_documents.py`**: the YAML contract. A config key exists
  when it is a field here; the schema, validation, and `Settings`
  wiring all follow from it.

## Adding a field to `OAuthClient`: the full flow

This is the most-repeated multi-site change in the project, and the
place regressions have historically come from (#32: the
regenerate-secret leg was missed and the field silently dropped).
A new client field touches all of these:

1. `models.py`: the field on `OAuthClient`, with its description.
2. `config_documents.py`: the field on `ClientEntry` and its coercion
   in `to_client()`.
3. `serialization.py` `client_to_yaml`: write it when non-empty.
4. `serialization.py` `merge_client_entry`: merge it on edit.
5. `templates/clients_form.html`: the form control.
6. `routes/ui.py` client create: parse it.
7. `routes/ui.py` client edit: parse it.
8. `routes/ui.py` regenerate-secret: carry it through (the #32 leg).
9. `mcp_server.py` `_client_to_dict`: expose it.
10. `mcp_server.py` `create_client` tool schema.
11. `mcp_server.py` `update_client` tool schema.
12. `mcp_server.py` create/update handlers: normalize and apply it.
13. `nanoidp config-schema --write`: regenerate the committed schema
    (a test fails if it is stale).

Then: tests for the YAML round-trip and the persist-through-edit and
regenerate-secret paths, MCP parity coverage, and an
`e2e/test_agent.py` scenario, in the same PR (features ship
whole). #214 settled how this flow is protected: no code-generating
registry - the declarative surfaces (the YAML load contract, the MCP
read surface and tool schemas, the form template) are pinned to
`OAuthClient.model_fields` by `tests/test_client_field_parity.py`, the
regenerate-secret leg is safe by construction (`model_copy`), and the
imperative legs (form parsers, MCP handler bodies, the YAML entry
builders) stay covered by the per-feature tests this list requires.

## Tests

- `tests/` (unit and integration through the Flask test client) runs
  in CI on Python 3.10/3.11/3.12, with coverage uploaded to Codecov.
- `e2e/test_agent.py` is the end-to-end agent: it drives a real
  server over HTTP and MCP the way an agent would. CI runs it in the
  `http-e2e` and `mcp-e2e` jobs. When a test creates state through
  the UI it must use the shared session (`self.session`), or the
  management gates will silently redirect it.
- Test isolation from the repo's own `config/` directory is enforced
  by `tests/conftest.py` (it resets the config and yaml-writer
  singletons); a test must never read or write the repo's config.

## Docs layout

The mdBook site under `book/` is canonical for guides and reference.
`docs/SECURITY.md`, `docs/MCP_WORKFLOW.md`, `CHANGELOG.md`,
`CONTRIBUTING.md` and `VISION.md` are the canonical files for their
content and are symlinked into `book/src/`; edit the file at the repo
root or under `docs/`, never the symlink target's copy. The site
redeploys automatically on merges touching `book/` or `docs/`.
`docs/RELEASING.md` is the maintainers' release manual and stays out
of the site on purpose.
