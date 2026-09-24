# React SPA + PKCE

This preset configures NanoIDP for a single-page application that logs in
with the Authorization Code flow and PKCE: `spa-client` is a public client
(no secret, PKCE `S256` required) with its redirect URIs registered.

```bash
cp examples/react-spa-pkce/*.yaml ./config/
python -m nanoidp --config ./config
```

Test users: `admin` / `admin` (roles `ADMIN`, `USER`) and `user` / `user`
(role `USER`).

The guide walks through the rest, from the react-oidc-context setup to a
scripted login for CI and the cases that must fail:
[Test an SPA login with Authorization Code and PKCE, locally](https://cdelmonte-zg.github.io/nanoidp/use-cases/spa-login-pkce.html).
