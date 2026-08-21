# Running behind a TLS-terminating reverse proxy

This guide walks through deploying NanoIDP behind a reverse proxy (nginx,
Traefik, an API gateway, etc.) that terminates TLS and forwards plain HTTP
to NanoIDP - a common setup in containerized environments (Docker Compose,
Kubernetes). It composes six existing, independently-documented settings
into one end-to-end configuration, since getting this wrong can silently
produce a working-looking IdP that issues tokens with the wrong `issuer`.

**None of this is required for local development** - `http://localhost:8000`
with the defaults works out of the box. Use this guide once NanoIDP needs to
be reachable through a proxy under a public hostname.

## The problem this solves

A discovery document's `issuer`, a token's `iss` claim, and the device flow's
`verification_uri` must all agree with whatever hostname the client actually
used to reach NanoIDP. Behind a reverse proxy, NanoIDP itself only ever sees
the proxy's own internal connection (e.g. `http://nanoidp:8000`), never the
public hostname the end user typed (e.g. `https://idp.example.com`) - unless
it's told how to recover that information from the request.

Getting this wrong shows up as: a discovery `issuer` that doesn't match the
URL it was fetched from, a token rejected because its `iss` doesn't match the
resource server's expected issuer, or a device-flow `verification_uri` that
points at a hostname the end user's browser can't resolve.

## Option A: fixed public issuer (simplest)

If NanoIDP is only ever reachable under one public hostname, skip request-based
derivation entirely and set a fixed issuer, resolved from the environment so
the same `settings.yaml` works in every environment:

```yaml
oauth:
  issuer: ${OAUTH_ISSUER:http://localhost:8000}
```

Set `OAUTH_ISSUER=https://idp.example.com` in the proxy's environment (or the
container's), and every environment that doesn't set it falls back to the
`http://localhost:8000` default for local development. This is the
recommended starting point - it requires none of the request-derivation flags
below, and there's nothing for a spoofed header to influence.

## Option B: multiple hostnames (request-derived issuer)

If NanoIDP must be reachable under more than one hostname at once (e.g. a
Docker Compose service name from other containers *and* `localhost` from the
host browser, or several public hostnames behind the same proxy), a single
fixed `issuer` can't satisfy all of them. Instead, derive it per request:

```yaml
oauth:
  issuer_from_request: true
```

With this on, discovery's `issuer`, a token's `iss`, and the device flow's
`verification_uri` all reflect the Host header of the request that fetched or
requested them - each hostname NanoIDP is reached under consistently
advertises and issues tokens against itself.

This introduces two trust problems, both of which have a corresponding flag:

### 1. The proxy terminates TLS

By default, NanoIDP builds the issuer from its own `request.scheme` and
`host_url`, which - behind a reverse proxy - reflect the proxy's own
internal, unencrypted connection to NanoIDP (`http://`), not the scheme and
host the end user's browser used (`https://idp.example.com`). Tell NanoIDP to
trust the proxy's forwarding headers instead:

```yaml
oauth:
  issuer_from_request: true
  issuer_from_proxy_headers: true
```

`issuer_from_proxy_headers` applies werkzeug's `ProxyFix` for a **single**
trusted proxy hop, so `request.scheme` / `host_url` follow
`X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-For` instead of the
proxy's own connection.

> **Security caveat:** only enable this when NanoIDP sits directly behind
> exactly one trusted reverse proxy that *sets or overwrites* these headers
> itself. If a client can reach NanoIDP directly (bypassing the proxy) or the
> proxy blindly forwards client-supplied `X-Forwarded-*` headers, this
> setting lets an untrusted client spoof its own scheme, host and IP -
> and the resulting effect isn't limited to the issuer: `X-Forwarded-For`
> also feeds rate-limit and audit-log client IP attribution, regardless of
> whether `issuer_from_request` is even on. Configure the proxy to strip any
> inbound `X-Forwarded-*` headers from clients before it sets its own.
>
> This is wired at app startup, so a value changed at runtime (Settings page
> or MCP `update_settings`) only takes effect after a restart.

### 2. Trusting an arbitrary Host header

Even with the proxy hop trusted, `issuer_from_request` still reflects
whatever Host it's given. On a network where anything other than the proxy
could reach NanoIDP, restrict which hostnames are allowed to be reflected:

```yaml
oauth:
  issuer_from_request: true
  issuer_from_proxy_headers: true
  issuer_allowlist:
    - "https://idp.example.com"
    - "http://nanoidp:8000"
```

Each entry is an origin: `scheme://host[:port]`. A request whose derived
origin isn't in the list falls back to the fixed `oauth.issuer` instead of
trusting the Host header. Leaving `issuer_allowlist` empty (the default)
allows any Host, matching pre-#`issuer_allowlist` behavior - only appropriate
on a fully trusted network where the proxy is the sole entry point.

## Device flow: pinning a human-reachable URL

The device flow's `verification_uri` is opened by a human in their own
browser, but `/device_authorization` is typically called by a
backend/container/CLI on a different host than that browser - so reflecting
*that caller's* Host (e.g. `Host: nanoidp:8000`, an internal Docker Compose
service name) produces a URL the human can't actually reach.

Pin it to a fixed, human-reachable URL instead, independent of whatever
Host called `/device_authorization`:

```yaml
oauth:
  issuer_from_request: true
  device_verification_base_url: "https://idp.example.com"
```

`device_verification_base_url` only overrides the device flow's
`verification_uri`; discovery's `issuer` and a token's `iss` are unaffected
and keep following the request that fetched/requested them. It's only
consulted when `issuer_from_request` is on.

## Reloading configuration without a restart

`ProxyFix` (via `issuer_from_proxy_headers`) is wired once at app startup, so
a value changed at runtime only takes effect after a process restart.
Everything else in this guide - `issuer`, `issuer_allowlist`,
`device_verification_base_url` - can be changed in `settings.yaml` (or via the
Settings page / MCP `update_settings`) and picked up without a restart:

```bash
curl -X POST http://localhost:8000/api/config/reload
```

This re-reads both `settings.yaml` and `users.yaml` from
`NANOIDP_CONFIG_DIR` (default `./config`) in place.

## Putting it together

A full `settings.yaml` for NanoIDP behind a single trusted TLS-terminating
proxy, reachable under both its public hostname and an internal Docker
Compose service name, with the device flow pinned to the public hostname:

```yaml
server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: ${OAUTH_ISSUER:http://localhost:8000}  # fallback when the flags below don't match
  issuer_from_request: true
  issuer_from_proxy_headers: true
  issuer_allowlist:
    - "https://idp.example.com"
    - "http://nanoidp:8000"
  device_verification_base_url: "https://idp.example.com"
```

> **Note on `host: "0.0.0.0"`.** Since 2.6.0 the default bind address is
> `127.0.0.1` ([GHSA-2473-px8h-rvg6](https://github.com/cdelmonte-zg/nanoidp/security/advisories/GHSA-2473-px8h-rvg6)):
> the `/api/*` management API is unauthenticated by design, so NanoIDP no
> longer listens on all interfaces unless you ask it to. Behind a reverse
> proxy you *do* want `0.0.0.0` - the proxy must reach NanoIDP over the
> container or host network - so setting it here is a deliberate opt-in.
> Only do this on a trusted network (for example a private Docker Compose
> network that publishes just the proxy's port), and expect a startup
> warning reminding you the management API is exposed to that network.

And the corresponding environment for the container:

```yaml
environment:
  - NANOIDP_CONFIG_DIR=/app/config
  - OAUTH_ISSUER=https://idp.example.com
```

## Checklist

- [ ] Reverse proxy terminates TLS and sets `X-Forwarded-Proto` /
      `X-Forwarded-Host` / `X-Forwarded-For` itself (strips any client-supplied
      values first)
- [ ] NanoIDP is not reachable except through that proxy
- [ ] `issuer_from_proxy_headers: true` only if the above two hold
- [ ] `issuer_allowlist` set to the exact origins NanoIDP should ever
      advertise as its issuer
- [ ] `device_verification_base_url` set if `/device_authorization` is ever
      called from a different host than the end user's own browser
- [ ] Restarted the process after changing `issuer_from_proxy_headers`
      (`ProxyFix` is startup-only)

## Related documentation

- [Configuration reference](../reference/configuration.md) - full
  `settings.yaml` shape
- [Environment variables](SECURITY.md#environment-variables) -
  `NANOIDP_CONFIG_DIR` and MCP-related variables
- [Security guide: multi-hostname issuer](SECURITY.md#multi-hostname-issuer-issuer_from_request) -
  the trust model behind `issuer_from_request`
- [Endpoints reference](../reference/endpoints.md) - `GET /api/config`,
  `POST /api/config/reload`
