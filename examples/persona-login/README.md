# Persona Login (Passwordless Local Dev Convenience)

This preset demonstrates **persona login mode**: interactive logins list the
configured users instead of prompting for a password. It's a local
development/testing convenience, off by default, and not intended as an
authentication mode for deployed environments.

## Quick Start

1. Copy configuration files:
```bash
cp examples/persona-login/*.yaml ./config/
python -m nanoidp --debug
```

2. Open the login page: http://localhost:8000/login

Instead of a username/password form, you'll see a list of the configured
users (`admin`, `alice`, `bob`) - click one to sign in immediately, no
password needed. `admin` and `alice` show a short description under their
name (display-only, never a claim); `bob` has none, showing the picker
handles a mix of described and undescribed users.

## What `login.mode: persona` changes

- Interactive logins show a user picker instead of a password prompt.
- Users without a `password` field in `users.yaml` (`alice` and `bob` here)
  can *only* sign in this way - they cannot authenticate via password-mode
  login or the OAuth password grant (`grant_type=password`).
- A user that still has a password (`admin` here) remains selectable in the
  picker too - persona mode changes the login *UI*, not what an individual
  user is configured with.
- An optional `description` per user renders as a small note next to their
  name in the picker (max 200 chars, plain text, never exported as a claim,
  SAML attribute, or authority).

## What's unaffected

- The OAuth password grant (`grant_type=password`) is unchanged - it never
  authenticates a password-less user, regardless of this setting.
- `security_profile` (`dev`/`stricter-dev`/`oauth21`) is orthogonal: it
  governs OAuth protocol strictness, not how the resource owner
  authenticates interactively.

## Auto-login for automated tests (#250)

A further opt-in on top of persona mode, for driving a real OIDC client
library in automated integration tests - uncomment `auto_login: true` in
`settings.yaml` (has no effect unless `login.mode` is also `persona`), then
send a `login_hint` prefixed `persona-auto-login:USERNAME` to `/authorize`:

```bash
curl -i "http://localhost:8000/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=openid&login_hint=persona-auto-login:alice"
```

That returns a `302` straight to `redirect_uri` with a `code` - no picker,
no HTML page in between. A `login_hint` naming an unknown user reports
through the ordinary OAuth error redirect (`error=invalid_request`, `state`
preserved), never a bare `400`; any other `login_hint` value is passed
through unchanged, and with `auto_login` left off, a prefixed hint is inert
too - the picker shows exactly as in the rest of this example.

## Reverting

Set `login.mode: password` (or delete the `login:` section) and restart -
every user with a configured password logs in exactly as before.
