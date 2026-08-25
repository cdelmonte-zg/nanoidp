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
| `mcp_server.py` | The `nanoidp-mcp` stdio server: tool declarations, handlers, and its own `ConfigManager` |
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
| `routes/_auth.py` | The management-gate choke point: `require_ui_login` session gate and the opt-in `management_secret` write guard for `/api/*`, the UI unlock, and MCP |
| `routes/_issuer.py` | Effective-issuer resolution, shared by every endpoint that mints a token or advertises the issuer (#133: they must never disagree) |
| `routes/_audit.py` | `audit_event(...)`: shared helper for route-level audit events (not yet universal: `/api/keys/rotate` still logs directly) |

Protocol logic and runtime state (`services/`), each module small and
single-purpose:

| Module | What it is |
|---|---|
| `services/token.py` | JWT building: access tokens, ID Tokens, the `/token` response body |
| `services/auth_code.py` | Authorization-code store (PKCE data rides on the code) |
| `services/device_code.py` | Device-flow code store |
| `services/revocation.py` | In-memory revocation and refresh-rotation family state |
| `services/crypto.py` | Key management: generation, rotation, JWKS, external key import |
| `services/discovery.py` | Single source of the OIDC discovery document (HTTP and MCP both render this; metadata never lies) |
| `services/redirect_uri.py` | Redirect-URI registration matching, including RFC 8252 native-app rules |
| `services/saml_verification.py` | Signed-AuthnRequest verification |
| `services/audit.py` | The audit log (in-memory ring, export) |
| `services/yaml_writer.py` | The only code that writes the YAML files back |

The config layer and the pure bottom:

| Module | What it is |
|---|---|
| `config.py` | `ConfigManager`: owns loading, reloading and handing out `Settings`/users; loads are transactional (a failed reload commits nothing) |
| `config_documents.py` | Pydantic document models mirroring the YAML sections one to one; `to_settings()` / `to_users()` build the domain objects |
| `config_schema.py` | JSON Schema generated from the document models; `docs/schema/config.v1.json` is the committed artifact and a test fails when they diverge |
| `config_validation.py` | `nanoidp validate-config`: lint a config directory without starting anything (hooks never execute) |
| `hooks.py` | `HookRegistry`: the extension points (`on_before_load`, `on_config_saved`, `on_audit_event`), shell hooks, entry-point plugins, the bootstrap surface |
| `models.py` | The domain dataclass-style models: `Settings`, `User`, `OAuthClient` |
| `serialization.py` | Domain objects <-> YAML dicts, both directions, no runtime package imports |
| `exceptions.py` | The exception taxonomy |
| `branding.py` | Per-client logo resolution (local assets only, containment-checked) |

## Where state lives

There are exactly two kinds of state, and they never share a store:

- **Declared configuration** is the two YAML files (`settings.yaml`,
  `users.yaml`, plus the optional `bootstrap.yaml` for hooks/plugins).
  It is schema-versioned (`config_version`), validated through the
  document models, editable by hand, and meant to be committed to git.
  The UI and MCP write it back through `services/yaml_writer.py` and
  nothing else does.
- **Runtime state** lives in memory inside `services/`: authorization
  codes, device codes, revocation and rotation families, the audit
  log, and Flask sessions. It is lost on restart by design; an
  instance is disposable (see [Vision](vision.md)). If you are about
  to persist runtime state to disk, stop and re-read the
  database-persistence non-goal.

`ConfigManager.load()` is transactional: parse and validate first,
swap the live objects only on success. A failed reload leaves the
previous configuration serving.

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
`examples/test_agent.py` scenario, in the same PR (features ship
whole). Issue #214 tracks whether this flow should collapse into a
declarative registry.

## Tests

- `tests/` (unit and integration through the Flask test client) runs
  in CI on Python 3.10/3.11/3.12, with coverage uploaded to Codecov.
- `examples/test_agent.py` is the end-to-end agent: it drives a real
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
