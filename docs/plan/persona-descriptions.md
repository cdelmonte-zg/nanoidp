# Persona Description Field — Implementation Plan

Tracking doc for the persona-description follow-up requested after persona login shipped. This is a focused UX extension, not a change to token or claim semantics.

## Design contract (from maintainer)

1. Add a first-class field, not a custom attribute: `User.description: str = ""` with a hard limit of 200 characters.
2. It is display-only in the persona selector UI: it is shown beside or under the username in the interactive persona picker.
3. It must not be exported as an OIDC claim, SAML attribute, authority, or token payload.
4. The style requirement is `small text-muted` in the picker, with a tooltip allowed as secondary support but not the primary UX.
5. The field should be included wherever the user object is created, rendered, persisted, or exposed over the API/MCP surface.
6. The PR must cover all persona surfaces in one pass: nanoidp `/login`, OAuth `/authorize`, device flow, and SAML inline login.
7. Docs and changelog stay last; the feature is implemented and tested before editorial work.

## Not "just a UI change" — scope clarification

This is not a token/claims feature. The key subtlety is that the user model and YAML persistence are the real write surface; once the description is added as a real user field it will automatically flow through serialization and editing unless we explicitly prevent it. The UI work only exposes it in the persona picker.

The feature must remain display-only in behavior, which means:

- No mapping into `user.attributes`
- No authority prefix logic
- No SAML export
- No OIDC claim export
- No token field emission

This is therefore a cross-surface schema + rendering change, not just a template tweak.

## Breakdown into commits (single feature branch / PR)

### 1. Data model + YAML persistence (completed)
- [x] `src/nanoidp/models.py`: add `User.description` field, default empty string, and 200-char validation.
- [x] `src/nanoidp/config_documents.py`: include the field in the YAML-backed user entry so it round-trips through `users.yaml`.
- [x] `src/nanoidp/config.py` / relevant save/load path: ensure the persisted user object retains the field without affecting token or auth logic.
- [x] Tests:
  - `tests/test_config.py`: verifies the field exists and defaults to an empty string.
  - `tests/test_persistence_unification.py`: verifies YAML round-trip preserves the description.
  - `tests/test_persona_login.py`: ensures persona-mode user creation/edit flows accept empty descriptions without affecting auth semantics.
- [x] Regenerate the committed `docs/schema/config.v1.json` artifact (`nanoidp config-schema --write`) — missed in the initial stage 1 pass, caught by `test_config_schema.py` and fixed during stage 3.

### 2. User create/edit forms and detail rendering (completed)
- [x] `src/nanoidp/templates/users_form.html`: add a description input with `maxlength="200"` alongside the user identity fields.
- [x] `src/nanoidp/routes/ui.py`: include the field in user create/edit handlers and validation.
- [x] `src/nanoidp/templates/user_detail.html`: show stored description in the user detail page.
- [x] Tests:
  - `tests/test_persona_login.py`: create/edit flow accepts a valid description; form renders the field.
  - ~~`tests/test_config.py`: round-trip for new user field persists correctly after UI-driven save.~~ Not needed — the YAML round-trip already goes through the same `user_to_yaml`/`ConfigManager.save()` path proven in stage 1.
  - ~~`tests/test_basic.py` or closest user-management route tests: validate form POST with description does not error.~~ Not the right file — user-management route coverage lives in `test_persona_login.py`, covered there instead.
  - ~~`tests/test_ui_oauth_settings.py` or similar UI-render tests if applicable: ensure form renders the new field without breaking the page.~~ Not applicable — that file covers OAuth settings, not user forms; rendering is covered in `test_persona_login.py`.

### 3. API / MCP / serialization coverage (completed)
- [x] `src/nanoidp/routes/api.py`: add `description` to the `list_users`/`get_user` response dicts (both build their JSON by hand, not via `User.to_dict()`).
- [x] Update the relevant MCP input schemas and `_user_to_dict` output for `create_user`, `create_persona_user`, and `update_user`.
- [x] Tests:
  - `tests/test_mcp.py`: verify the user description is accepted and serialized correctly in MCP user creation/update (`TestMCPUserDescription`).
  - `tests/test_config.py`: verify the REST API exposes `description` on both `list_users`/`get_user` without leaking into `authorities` (`TestUserRestApiDescription`).
  - ~~`tests/test_persona_login.py`: verify a persona user with a description still authenticates normally and does not gain claim/export behavior.~~ Not needed here — auth semantics are untouched by this field and already covered by stage 1/2 persona tests; this stage only adds serialization surface.

### 4. Persona picker rendering across all interactive surfaces (completed)
- [x] `src/nanoidp/config.py`: add `ConfigManager.persona_picker_entries()` returning `(username, description)` pairs, the single source all four surfaces read from.
- [x] `src/nanoidp/templates/_macros.html`: centralize the persona picker body so it renders the username and text description in the `small text-muted` style.
- [x] `src/nanoidp/templates/login.html`: fix the password-mode "quick fill username" block, which also consumed the old plain-username list shape.
- [x] `src/nanoidp/routes/ui.py`: pass `(username, description)` data into the picker for the nanoidp login form.
- [x] `src/nanoidp/routes/oauth.py`: apply the same picker rendering on the OIDC `/authorize` inline login path and the device flow's `/device` page.
- [x] `src/nanoidp/routes/saml.py`: apply the same picker rendering on the SAML inline login path.
- [x] Tests:
  - `tests/test_persona_login.py`: description renders on `/login`, and is omitted cleanly when blank (`TestPersonaLoginPage`).
  - `tests/test_persona_login_flows.py`: description renders on `/authorize`, SAML `/saml/sso`, and device `/device` pickers.
  - ~~`tests/test_saml.py` / `tests/test_saml_signed_authnrequests.py` / `tests/test_device_flow_complete.py`: dedicated new tests.~~ Not needed — ran as regression only (all passing unchanged); the SAML assertion/device-code paths never touch `description`, so there's no new behavior there to test.

### 5. Server-side validation + no-export guarantee (completed)
- [x] 200-character validation: already enforced by `User.description`'s Pydantic `max_length=200` (stage 1) — `ValidationError` is a `ValueError` subclass, so it's caught cleanly by the existing UI `except ValueError` handlers and rejected at the MCP protocol layer by the `maxLength: 200` schema property (stage 3). No new production code needed; confirmed with new tests instead.
- [x] No-export guard: already true by construction — `description` is a dedicated `User` field, never folded into `attributes`, never read by `resolve_user_claim`, `build_authorities`, `create_token`'s `extra` dict, or `_sso_build_attributes` (stage 1's "not an attribute" decision). No new production code needed; confirmed with new tests instead.
- [x] Tests:
  - `tests/test_config.py`: `User(description="a"*201)` raises, `"a"*200` is accepted (`test_user_description_over_200_chars_rejected`, `test_user_description_exactly_200_chars_accepted`).
  - `tests/test_persona_login.py`: overlong description rejected cleanly on create and edit, no partial write (`test_overlong_description_rejected_on_create`, `test_overlong_description_rejected_on_edit`).
  - `tests/test_mcp.py`: `call_tool` rejects an overlong description with `MCP_INVALID_ARGUMENTS` before dispatch (`test_overlong_description_rejected_by_schema`).
  - `tests/test_token_service.py`: a described user's access token contains no `description` claim and no trace of the text anywhere in the payload (`test_description_is_never_a_token_claim`).
  - `tests/test_saml.py`: a described user's SAML assertion contains no `description` attribute and no trace of the text (`test_sso_never_exports_the_description_field`).

### 6. Final integration checks and repo-wide verification
- [ ] Verify the field is present and consistent across all user forms and screens.
- [ ] Run the focused test set covering user rendering, persona login, device authorization, SAML, and MCP.
- [ ] Confirm the description stays display-only and does not leak into claims/authorities.
- [ ] Tests:
  - `pytest -q tests/test_persona_login.py tests/test_persona_login_flows.py tests/test_mcp.py tests/test_saml.py tests/test_device_flow_complete.py tests/test_config.py`
  - plus any newly added targeted tests for the max-length validation and user-form rendering.

## Sequencing rationale

Steps 1-2 are safe standalone and establish the real data contract. Step 3 closes the write surface and API/MCP exposure before the UI work. Step 4 delivers the user-visible behavior across all interactive persona flows. Step 5 locks down the display-only safety guarantees and validation. Step 6 is repo-level verification before docs are added.

## How this gets tested

No dedicated interactive test harness exists for this repo — testing is layered:

1. Manual/interactive: run the app locally with a persona user containing a description and verify the picker on `/login`, `/authorize`, `/device`, and the SAML inline login path.
2. Scripted e2e against a running server: use `examples/test_agent.py` and the existing persona-login coverage to hit the live HTTP surfaces.
3. Unit/integration suite: most of the verification happens in Flask test-client tests, where the form posts, YAML round-trips, and serialization are checked in code.

## Docs and changelog

- [ ] `README.md` / user docs: document the new display-only `description` field for persona users.
- [ ] `CHANGELOG.md`: add a short entry for the persona-description field.
- [ ] `book/` docs if needed: keep the user-facing docs aligned with the feature.

This is intentionally left for the end of the PR, after the feature is implemented and tested.

## Out of scope

- Exporting the description as an OIDC claim
- Turning it into a SAML attribute
- Creating an authority prefix for it
- Adding HTML markup support
- Making the text a generic custom attribute or token claim
