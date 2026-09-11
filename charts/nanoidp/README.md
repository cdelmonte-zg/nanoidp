# nanoidp Helm Chart

Deploys [nanoidp](https://github.com/cdelmonte-zg/nanoidp), a configurable
mock Identity Provider for testing OAuth2/OIDC and SAML integrations, on
Kubernetes.

## Installation

```bash
helm install nanoidp oci://ghcr.io/cdelmonte-zg/charts/nanoidp --values values.yaml
```

See the repository's `values.yaml` for the full set of options and their
defaults.

## Limitations

### Single replica only

nanoidp keeps authorization codes, refresh-token families, revocations and
the audit log in-process, with no coordination between instances. Running
more than one pod means a code minted by one pod is unknown to another.
There is no `replicaCount` value, the Deployment always runs exactly one
replica with `strategy: Recreate`, so a rollout never runs two pods at
once. This is not planned to change.

### Read-only config mount

The mounted config Secret (generated or `configFiles.existingSecret`) is
read-only, the same way `docker-compose.yml`'s `:ro` config mount is
today. nanoidp does not detect this or adapt its UI/MCP server for it, a
save attempt from the settings UI or an MCP `save_config` call against a
running pod will fail with whatever OS error the write hits (a read-only
filesystem error, not a nanoidp-specific message). Configuration changes
on Kubernetes go through `values.yaml` and a `helm upgrade`, not through
the running instance.

### Ephemeral signing keys

nanoidp generates its RSA signing keypair on first start if it doesn't
already exist, and the chart provides no persistent storage for it. Every
pod restart, including the `Recreate` rollout above, generates a new
keypair, invalidating every previously issued token and the SAML
certificate. This is acceptable for a short-lived test IdP, but worth
knowing before relying on long-lived sessions across restarts.
`keys.existingSecret` (mounting a pre-generated keypair from a Secret you
manage) is a possible future addition, not implemented in this version of
the chart.

### Pod Security Standard: `baseline`, not `restricted`

This chart targets the `baseline` Pod Security Standard, not
`restricted`. Running it in a namespace enforcing `restricted` will fail
on `runAsNonRoot`, the image has no `USER` directive, an image-side
change outside this chart's scope. The default `securityContext`
(`allowPrivilegeEscalation: false`, dropping all capabilities,
`seccompProfile: RuntimeDefault`) already covers everything else
`restricted` checks, verified against namespaces enforcing both
standards.

## Configuration files (`configFiles`)

`configFiles.users` and `configFiles.settings` are the literal contents
of `users.yaml`/`settings.yaml`, written verbatim (not as structured
Helm values) into a generated Secret and mounted read-only into the
container. A `Secret`, not a `ConfigMap`, is used because `settings.yaml`
carries client secrets.

`configFiles.users`/`configFiles.settings` are mandatory (`helm
install`/`lint`/`template` refuses an empty default) unless
`configFiles.existingSecret` is set instead.

```yaml
configFiles:
  users: |
    users:
      admin:
        password: admin
  settings: |
    login:
      mode: password
    oauth:
      issuer: ${INGRESS_URL}
```

Do not set a `config_version` key in either file: it must be a literal
integer identical between both files, or the app refuses to start, and
this chart does not manage it.

A `configFiles.users`/`configFiles.settings` change rolls the pod
automatically (a `checksum/config` pod annotation, computed from the
rendered Secret, changes whenever the content does), nanoidp only reads
its config at boot, so nothing else would pick up the change.

Set `configFiles.existingSecret` to the name of a Secret you manage
yourself (e.g. rendered by External Secrets, Vault Agent, or an init
container elsewhere) to skip the generated Secret entirely. That Secret
must contain the same `users.yaml`/`settings.yaml` keys. The automatic
pod rollout above does not apply here, the chart cannot compute a
checksum over content it doesn't render, rolling the pod on a change to
an externally managed Secret is your own responsibility (e.g. your own
checksum annotation, or `kubectl rollout restart`).

## Ingress and the issuer

Set `ingress.className` to your cluster's IngressClass name. Most
ingress controllers (e.g. ingress-nginx's own chart) default to ignoring
an Ingress with no class set, rather than falling back to the deprecated
`kubernetes.io/ingress.class` annotation.

OIDC requires the issuer advertised in discovery and tokens to match the
URL clients actually reach nanoidp at. Since `configFiles.settings` is
written verbatim, the chart cannot fill `oauth.issuer` in for you. When
`ingress.host` is set, the chart injects two environment variables you
can reference from `configFiles.settings` using nanoidp's own `${VAR}`
placeholder expansion:

- `INGRESS_HOST`: the bare hostname (`ingress.host`).
- `INGRESS_URL`: the full external URL, scheme included. The scheme is
  `https` when `ingress.tls` is set, `http` otherwise, this follows
  whether the chart itself renders a TLS block on the Ingress, it is not
  a guess.

```yaml
oauth:
  issuer: ${INGRESS_URL}
```

An unset `${INGRESS_URL}` (e.g. `ingress.create: false`, so nothing sets
it) expands to an empty string, and nanoidp's issuer validator rejects
anything not starting with `http://`/`https://`, so a missing value is a
loud boot failure, not a silently broken issuer.

`INGRESS_HOST`/`INGRESS_URL` are a convenience for the common case where
TLS terminates at the Ingress this chart renders. If TLS actually
terminates upstream of it (a load balancer or CDN in front of the
cluster), set `oauth.issuer` directly, or use nanoidp's own
`oauth.issuer_from_request` with `oauth.issuer_from_proxy_headers` and an
`oauth.issuer_allowlist` naming the trusted origin, this derives the
issuer from the request through one proxy hop, which is the topology it
was built for.

## Complete example

The snippets above show what individual values look like. This is a
`values.yaml` that actually works end to end: one user, one registered
OAuth client, and the client secret kept out of `configFiles.settings`
entirely by sourcing it from a Kubernetes Secret you create yourself.

First, create the Secret holding the client secret and a management
secret (any key names, `env` below just has to reference the same ones):

```bash
kubectl create secret generic nanoidp-client-secret \
  --from-literal=secret=$(openssl rand -base64 32) \
  --from-literal=management-secret=$(openssl rand -base64 32)
```

You can import this same Secret into your application's own OIDC client
configuration, so `myapp` and nanoidp agree on the secret without either
side hardcoding it.

Then the chart values:

```yaml
ingress:
  create: true
  host: idp.example.com
  className: nginx # your cluster's IngressClass, see "Ingress and the issuer" above

env:
  - name: CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: nanoidp-client-secret
        key: secret
  # nanoidp's /api/* management endpoints are unauthenticated by design
  # otherwise, this gates mutations (rotating keys, minting tokens for
  # any user, clearing the audit log) behind a shared secret. Safe
  # methods (/api/health, discovery) are unaffected.
  - name: NANOIDP_MANAGEMENT_SECRET
    valueFrom:
      secretKeyRef:
        name: nanoidp-client-secret
        key: management-secret

configFiles:
  users: |
    users:
      admin:
        password: admin

  settings: |
    session:
      # Same reasoning as NANOIDP_MANAGEMENT_SECRET above, this gates
      # the settings/users/clients/keys/audit UI behind /login.
      require_ui_login: true

    login:
      mode: password
      # WARNING: only enable persona/auto_login on a network nobody
      # untrusted can reach, this logs anyone who hits the URL in as the
      # named user with no credentials at all.
      # mode: persona
      # auto_login: true

    oauth:
      issuer: ${INGRESS_URL}
      clients:
        - client_id: myapp
          client_secret: ${CLIENT_SECRET}
          redirect_uris:
            - https://myapp.example.com/callback
          token_endpoint_auth_method: client_secret_post
```

This example omits `ingress.tls` for simplicity, so `INGRESS_URL` resolves
to `http://idp.example.com`, set `ingress.tls.secretName` (with a
certificate Secret of your own) to switch it to `https://` automatically.

With both `NANOIDP_MANAGEMENT_SECRET` and `session.require_ui_login` set,
mutating requests without the shared secret/a session get `401`/redirected
to `/login`, `/api/health` and `/.well-known/openid-configuration` keep
returning `200`, so probes and discovery are unaffected.

After `helm install`/`helm upgrade`,
`http://idp.example.com/.well-known/openid-configuration` serves
discovery for a real client (`myapp`) that can complete an authorization
code flow against `admin`/`admin`, with its secret never committed to
`values.yaml`.

## Security

nanoidp is a test/mock Identity Provider, not a production-hardened one.
We recommend keeping an Ingress on an internal cluster network or behind
an authenticating reverse proxy, rather than exposed to the public
internet, the right boundary depends on your own security requirements.

## Versioning

This chart's `version` equals the nanoidp release it ships, there is no
separate `appVersion`, `helm ls` answers "which nanoidp is this" on its
own. `image.tag` defaults to the chart's own `version`. The one stated
exception: a chart-only fix (no nanoidp code change) may ship as a
patch-bump of `version` with `image.tag` left pinned to the last app
release, this is expected to be rare.
