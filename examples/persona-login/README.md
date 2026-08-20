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
password needed.

## What `login.mode: persona` changes

- Interactive logins show a user picker instead of a password prompt.
- Users without a `password` field in `users.yaml` (`alice` and `bob` here)
  can *only* sign in this way - they cannot authenticate via password-mode
  login or the OAuth password grant (`grant_type=password`).
- A user that still has a password (`admin` here) remains selectable in the
  picker too - persona mode changes the login *UI*, not what an individual
  user is configured with.

## What's unaffected

- The OAuth password grant (`grant_type=password`) is unchanged - it never
  authenticates a password-less user, regardless of this setting.
- `security_profile` (`dev`/`stricter-dev`/`oauth21`) is orthogonal: it
  governs OAuth protocol strictness, not how the resource owner
  authenticates interactively.

## Reverting

Set `login.mode: password` (or delete the `login:` section) and restart -
every user with a configured password logs in exactly as before.
