# Test an SPA login with Authorization Code and PKCE, locally

A single-page app (React, Vue, Angular, Svelte) logs its users in with the
Authorization Code flow and PKCE. It runs in the browser, so it cannot keep
a secret: it is a *public client*, and the PKCE `code_verifier` is the only
proof that the app which asked for the code is the one redeeming it.

Testing that login against a cloud tenant means a network dependency and an
account; against Keycloak, a realm to configure. NanoIDP gives you the same
flow from two YAML files, with a public client that behaves as the specs
say: PKCE with `S256` required, redirect URIs matched exactly, a code that
works once.

The configuration below is the
[`react-spa-pkce`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/react-spa-pkce)
preset.

## 1. Register the SPA as a public client

```yaml
# settings.yaml
oauth:
  issuer: "http://localhost:8000"
  audience: "spa-api"          # the access token's aud: the API your SPA calls
  clients:
    - client_id: "spa-client"
      token_endpoint_auth_method: "none"   # public client: no secret
      redirect_uris:                        # exact string match at /authorize
        - "http://localhost:3000/callback"
        - "http://localhost:5173/callback"  # Vite default port
```

Fetch the preset into a config directory and start NanoIDP on it
(`pip install nanoidp` first; no checkout of the repository needed):

```bash
mkdir -p config
base=https://raw.githubusercontent.com/cdelmonte-zg/nanoidp/main/examples/react-spa-pkce
curl -fsSL -o config/settings.yaml "$base/settings.yaml"
curl -fsSL -o config/users.yaml "$base/users.yaml"
python -m nanoidp --config ./config
```

The preset's `users.yaml` has two users, `admin` / `admin` and
`user` / `user`.

CORS needs nothing: the default `dev` profile allows every origin, and
under `security_profile: stricter-dev` it is limited to `localhost` and
`127.0.0.1` on any port. To test the SPA against a policy that names its
origin, releases after 3.3.0 take a list, which applies in every profile:

```yaml
cors_allowed_origins:
  - "http://localhost:3000"
```

## 2. Point the SPA at NanoIDP

With [react-oidc-context](https://github.com/authts/react-oidc-context),
in an existing React app (for example one created with
`npm create vite@latest -- --template react-ts`, which serves on port 5173:
use `http://localhost:5173/callback` as the `redirect_uri` there):

```bash
npm install react-oidc-context oidc-client-ts
```

```tsx
// src/main.tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider } from "react-oidc-context";
import App from "./App";

const oidcConfig = {
  authority: "http://localhost:8000",
  client_id: "spa-client",
  redirect_uri: "http://localhost:3000/callback",
  scope: "openid profile email",
  response_type: "code",
  loadUserInfo: true, // in NanoIDP, email and profile come from /userinfo
  // Required by react-oidc-context: remove the code and state from the URL
  // once the login completes, or token renewal fails after a page reload
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  },
};

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthProvider {...oidcConfig}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
```

```tsx
// src/App.tsx
import { useAuth } from "react-oidc-context";

function App() {
  const auth = useAuth();

  if (auth.isLoading) return <div>Loading...</div>;
  if (auth.error) return <div>Error: {auth.error.message}</div>;
  if (auth.isAuthenticated) {
    return (
      <div>
        <p>Hello {auth.user?.profile.sub} ({auth.user?.profile.email})</p>
        {/* local logout: clears the library's state, not NanoIDP's session */}
        <button onClick={() => void auth.removeUser()}>Log out</button>
      </div>
    );
  }
  return <button onClick={() => void auth.signinRedirect()}>Log in</button>;
}
```

The library does the PKCE work: it generates the verifier, sends the
`S256` challenge to `/authorize`, and redeems the code at `/token` with the
verifier and no secret. Other OIDC client libraries take the same values:
the `authority`, the `client_id` and the `redirect_uri`.

The Log out button is a local logout: `removeUser()` forgets the user in
the SPA and does not call NanoIDP.

## 3. Know which token carries what

Three places hold facts about the user, and looking in the wrong one is
the most common surprise. Providers split the claims differently; in
NanoIDP:

| Where | What is in it | Who reads it |
|---|---|---|
| ID token | `sub`, `aud` = `spa-client`, `auth_time`, `at_hash`: who logged in, for this app | the SPA's OIDC library, to confirm the login |
| Access token | `aud` = `spa-api`, `scope`, `roles`, `authorities` and the other user attributes | your API, on every request |
| `/userinfo` | `email`, `email_verified`, profile claims, per granted scope | the SPA, with `loadUserInfo: true` |

NanoIDP's ID token does not carry `email`: without `loadUserInfo: true`,
`auth.user.profile.email` is `undefined`. The details are in
[Tokens and claims](../reference/tokens.md#where-do-the-email--profile-claims-come-from).

## 4. Run the login without a browser

The whole flow can be scripted, which makes it a test you can run in CI.
This script does what the browser and the SPA do together, then checks the
ID token's signature against NanoIDP's JWKS, its issuer, its audience and
its expiry. An OIDC library may check more, depending on the library and its
settings; this is a test of the flow, not a replacement for the library. It needs `requests`
(`pip install requests`); PyJWT comes with NanoIDP.

```python
"""Log in as a browser-based SPA would: Authorization Code with PKCE, no secret."""
import base64, hashlib, re, secrets
from urllib.parse import parse_qs, urlparse

import jwt  # PyJWT, installed with nanoidp
import requests

IDP = "http://localhost:8000"
CLIENT_ID = "spa-client"
REDIRECT_URI = "http://localhost:3000/callback"

# 1. PKCE: a random verifier, and its S256 hash as the challenge
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_urlsafe(16)

# 2. The browser goes to /authorize and gets the login form
browser = requests.Session()
page = browser.get(f"{IDP}/authorize", params={
    "response_type": "code", "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI, "scope": "openid profile email",
    "state": state, "code_challenge": challenge,
    "code_challenge_method": "S256",
})
page.raise_for_status()
transaction = re.search(r'name="transaction_id" value="([^"]+)"', page.text)[1]

# 3. The user submits the form; nanoidp redirects back with a code
answer = browser.post(f"{IDP}/authorize", allow_redirects=False, data={
    "transaction_id": transaction, "username": "user", "password": "user",
})
callback = parse_qs(urlparse(answer.headers["Location"]).query)
assert callback["state"] == [state], "state must come back unchanged"
code = callback["code"][0]

# 4. The SPA exchanges the code: client_id and code_verifier, no secret
tokens = requests.post(f"{IDP}/token", data={
    "grant_type": "authorization_code", "code": code,
    "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
    "code_verifier": verifier,
}).json()

# 5. Check the ID token: signature (JWKS), issuer, audience, expiry
discovery = requests.get(f"{IDP}/.well-known/openid-configuration").json()
id_token = tokens["id_token"]
key = jwt.PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(id_token)
claims = jwt.decode(id_token, key, algorithms=["RS256"],
                    issuer=discovery["issuer"], audience=CLIENT_ID)
print("logged in:", claims["sub"], "| id_token aud:", claims["aud"],
      "| refresh token:", "refresh_token" in tokens)
```

```
logged in: user | id_token aud: spa-client | refresh token: True
```

Steps 2 and 3 are specific to NanoIDP: `transaction_id`, `username` and
`password` are the fields of its login page. The rest is the standard
Authorization Code exchange with PKCE.

## 5. Drive the real SPA in an end-to-end test

To test the SPA itself with Playwright or Cypress, without typing a
password into a form, turn on auto-login:

```yaml
# settings.yaml
login:
  mode: persona
  auto_login: true
```

An `/authorize` request whose `login_hint` is `persona-auto-login:USERNAME`
then logs that user in directly and redirects back with a code. The SPA
passes the hint through its library:

```ts
auth.signinRedirect({ login_hint: "persona-auto-login:admin" });
```

An unknown user comes back to the SPA as a standard OAuth error
(`error=invalid_request`, "Unknown persona for auto-login", `state`
preserved), so the failure path is testable too. See
[Auto-login](../reference/configuration.md#auto-login).

## What must fail

A login test that only checks the happy path does not tell you the client
is correct. With this preset, NanoIDP answers each of these as below, and
each one is worth a test on your side. The protocol answers follow the
OAuth and PKCE specifications; the login form is NanoIDP's own.

| What the client does | NanoIDP's answer, with this preset |
|---|---|
| `/authorize` without `code_challenge` | redirect with `error=invalid_request`: PKCE with `S256` is required for a public client |
| `code_challenge_method=plain` | redirect with `error=invalid_request`: must be `S256` |
| a `redirect_uri` not in `redirect_uris` | `400 invalid_request` answered directly, never a redirect to the unregistered URI |
| the code redeemed with the wrong `code_verifier` | `400 invalid_grant` |
| the same code redeemed twice | `400 invalid_grant` the second time |
| a wrong password | the login form again, with an error |

## Takeaways

- An SPA is a public client: register it with
  `token_endpoint_auth_method: "none"` and no secret. PKCE is what
  protects the code.
- Register the redirect URIs. Exact matching is what stops a code from
  being sent somewhere else, and it is what production providers enforce.
- The ID token says who logged in; the access token is for your API. In
  NanoIDP, email and profile come from `/userinfo`.
- The flow is scriptable end to end, and auto-login lets a browser test
  drive the real SPA without a login form.
