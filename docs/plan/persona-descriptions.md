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

### 2. User create/edit forms and detail rendering (completed)
- [x] `src/nanoidp/templates/users_form.html`: add a description input with `maxlength="200"` alongside the user identity fields.
- [x] `src/nanoidp/routes/ui.py`: include the field in user create/edit handlers and validation.
- [x] `src/nanoidp/templates/user_detail.html`: show stored description in the user detail page.
- [x] Tests:
  - `tests/test_persona_login.py`: create/edit flow accepts a valid description; form renders the field.
  - ~~`tests/test_config.py`: round-trip for new user field persists correctly after UI-driven save.~~ Not needed — the YAML round-trip already goes through the same `user_to_yaml`/`ConfigManager.save()` path proven in stage 1.
  - ~~`tests/test_basic.py` or closest user-management route tests: validate form POST with description does not error.~~ Not the right file — user-management route coverage lives in `test_persona_login.py`, covered there instead.
  - ~~`tests/test_ui_oauth_settings.py` or similar UI-render tests if applicable: ensure form renders the new field without breaking the page.~~ Not applicable — that file covers OAuth settings, not user forms; rendering is covered in `test_persona_login.py`.

### 3. API / MCP / serialization coverage
- [ ] `src/nanoidp/routes/api.py`: add `description` to the `list_users`/`get_user` response dicts (both build their JSON by hand, not via `User.to_dict()`).
- [ ] Update the relevant MCP input schemas and `_user_to_dict` output for `create_user`, `create_persona_user`, and `update_user`.
- [ ] Tests:
  - `tests/test_mcp.py`: verify the user description is accepted and serialized correctly in MCP user creation/update.
  - `tests/test_persona_login.py`: verify a persona user with a description still authenticates normally and does not gain claim/export behavior.
  - `tests/test_config.py`: ensure `description` remains non-claim metadata rather than an authority prefix or token attribute.

### 4. Persona picker rendering across all interactive surfaces
- [ ] `src/nanoidp/templates/_macros.html`: centralize the persona picker body so it renders the username and text description in the `small text-muted` style.
- [ ] `src/nanoidp/routes/ui.py`: pass user objects or `(username, description)` data into the picker for the nanoidp login form.
- [ ] `src/nanoidp/routes/oauth.py`: apply the same picker rendering on the OIDC `/authorize` inline login path.
- [ ] `src/nanoidp/routes/saml.py`: apply the same picker rendering on the SAML inline login path.
- [ ] Device flow surface: render the same description-rich choice in the device authorization path.
- [ ] Tests:
  - `tests/test_persona_login.py`: verifies the description is visible in the nanoidp login page.
  - `tests/test_persona_login_flows.py`: verifies the description appears in the OIDC authorize flow and device flow surfaces.
  - `tests/test_saml.py` and/or `tests/test_saml_signed_authnrequests.py`: verifies SAML persona login still renders correctly with the display text and does not export the field.
  - `tests/test_device_flow_complete.py` or equivalent device-flow tests: verifies the persona description is available in the device picker and does not change authorization semantics.

### 5. Server-side validation + no-export guarantee
- [ ] Add a 200-character validation check in the server-side user creation/edit path so values over the limit are rejected.
- [ ] Add a guard so the description is never copied into `user.attributes`, `token_claims`, SAML attributes, or configured authority prefixes.
- [ ] Tests:
  - `tests/test_config.py`: reject description lengths above 200.
  - `tests/test_persona_login.py`: invalid descriptions fail cleanly on create/edit.
  - `tests/test_saml.py`: ensure SAML output is unchanged and does not include the description field.
  - `tests/test_id_token_audience.py` or any claim-related tests: confirm token payload remains unaffected.

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
