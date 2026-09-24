# Test a CLI login with the device authorization flow

A command-line tool, a smart TV or a build agent cannot show a login page.
The OAuth 2.0 device authorization grant (RFC 8628) solves that: the tool
asks for a short code, tells the user to enter it in a browser anywhere, and
polls until the user has logged in and approved. The GitHub CLI logs in
this way, and so can several cloud CLIs.

Testing that loop needs an authorization server that issues device codes,
serves the page where the user enters them, and answers the polling
correctly: pending, denied, used once. NanoIDP does all of it locally, and
the browser step can be scripted, so the whole login runs in a test.

Everything here is in
[`examples/cli-device-flow/`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/cli-device-flow),
and the repository's CI runs the tests below on every change.

## 1. Register the CLI as a public client

A CLI ships to its users, so a secret inside it is not a secret. Register it
as a public client, identified by its `client_id` alone:

```bash
pip install nanoidp
mkdir -p config
base=https://raw.githubusercontent.com/cdelmonte-zg/nanoidp/main/examples/cli-device-flow
curl -fsSL -o config/settings.yaml "$base/settings.yaml"
curl -fsSL -o config/users.yaml "$base/users.yaml"
python -m nanoidp --config ./config
```

```yaml
{{#include ../../../examples/cli-device-flow/settings.yaml}}
```

The users are `admin` / `admin` (roles `ADMIN`, `USER`) and `user` /
`user` (role `USER`).

## 2. The CLI side

```python
{{#include ../../../examples/cli-device-flow/cli_login.py}}
```

```text
$ python cli_login.py
Open http://localhost:8000/device and enter the code H3V74VHV
(or open http://localhost:8000/device?user_code=H3V74VHV)
Logged in; access token expires in 3600 seconds
```

The user opens the URL and enters the code (with
`verification_uri_complete` it is already filled in), logs in and chooses
**Authorize Device** or **Deny**. Meanwhile the CLI polls `/token`
every `interval` seconds:

| NanoIDP's answer to a poll | What the CLI does |
|---|---|
| `authorization_pending` | waits and polls again |
| `slow_down` | waits 5 seconds longer from then on (RFC 8628 §3.5; NanoIDP does not send it today, a CLI should handle it anyway) |
| tokens | done |
| `access_denied` | the user chose Deny: stop |
| `invalid_grant` | the device code is unknown or already used: stop |
| `expired_token`, or its own deadline | the code's 600 seconds are over: start again |

The access token is the user's: its `sub` is the user who approved, with
that user's roles, and its `client_id` is `cli-tool`.

## 3. Script the browser step and test the loop

What the user does in the browser is one form post to `/device`, with the
user code, the credentials and the button pressed. The tests run the CLI's
own polling in a thread, and approve or deny while it waits:

```python
{{#include ../../../examples/cli-device-flow/tests/test_device_flow.py}}
```

The form fields (`user_code`, `username`, `password`, `action`) belong to
NanoIDP's verification page; the device code request and the polling are
RFC 8628 and look the same against any authorization server.

## Refresh tokens rotate

A CLI keeps its refresh token between runs. For a public client NanoIDP
always rotates it: each refresh answers a new refresh token, and the old one
stops working. Using an old one again is treated as a stolen token: it
fails, and it also revokes the newest one, so the CLI has to log in again.
A CLI must therefore write the new refresh token to disk after every
refresh, before anything else can fail. The last test pins that behaviour.

## Takeaways

- Register a CLI as a public client (`token_endpoint_auth_method: "none"`):
  it cannot keep a secret.
- Poll at the interval the server gives, handle `slow_down` by waiting
  longer, and stop on every error that is not `authorization_pending`.
- A device code gives tokens once.
- Store the rotated refresh token every time. Reusing an old one logs the
  user out everywhere.
- The browser step is one form post, so the whole device login is a test
  that runs in CI.
