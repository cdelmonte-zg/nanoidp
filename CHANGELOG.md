# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **A client ID metadata document is fetched at `/authorize`** (#196, last
  part). An `https` `client_id` that no declared and no runtime client
  holds is looked up: the document is fetched, validated, cached, and the
  client resolves from then on with `origin: cimd`.
  `client_id_metadata_document_supported` is advertised while the feature
  is on. **Only `/authorize` fetches**: `/token` and every other surface
  read the cache, so a document that is not cached is an unknown client
  there, which is what keeps a token request from waiting on somebody
  else's web server. A document whose response says it must not be cached
  is refused at the authorization request rather than turned into a code no
  token request could redeem. Every refusal answers the same
  `invalid_client` / `Unknown client_id`, with the reason in the server log
  only: which rule refused it is not something to tell whoever chose the
  URL. The
  client list shows cached clients read-only with a Forget button, which is
  how a developer re-fetches a document they have just changed.
  An `allowed_hosts` entry names a host **and a port** (443 when none is
  given), so opting a host in does not authorise every port on it. This
  process makes at most 30 metadata fetches a minute, all callers together:
  the limit is on the fetch rather than on `/authorize`, because that is
  where the cost is and the endpoint is where people log in. The audit
  records that a document was refused and not why, since `GET /api/audit`
  is readable by anyone who can reach it and the reason is exactly what the
  uniform error withholds. An authorization code keeps the cached client it
  was issued for resolvable until the code expires, so neither a short
  `max-age` nor the cache's own capacity can leave a valid code with no
  client behind it: such an entry is not evicted to make room, and when
  every entry is holding up a live code the new authorization request is
  refused rather than an existing flow broken. The client is held before
  the code is minted, so a code is never handed over for a client that is
  already gone; when it cannot be held the authorization request comes back
  as `temporarily_unavailable`. An operator's Forget still drops the entry
  and invalidates such a code, which is the point of it.
  A client identified this way gets **no refresh token and cannot use the
  device grant**: both outlive the authorization code that is the only
  thing the cache promises to keep an entry for, and a credential this
  server can invalidate long before its expiry is worse than one it never
  issued. `/device_authorization` answers such a client_id exactly as it
  answers a name nobody knows.
- **The metadata document is fetched** (#196, second part), by the one
  outbound request nanoidp makes. `oauth.client_id_metadata_documents`
  gains `allowed_hosts` (exact DNS names, empty by default, so nothing is
  fetched until an operator names a host) and `allow_loopback` (the draft's
  development exception: loopback only, only when this server is itself on
  loopback, only for the family it is bound to; private, link-local and
  unique-local addresses stay refused).
  Built on the standard library rather than an HTTP client, so the rules
  are the shape rather than flags: the connection goes to an address this
  code resolved and checked while the hostname is kept for TLS and `Host`,
  which is what makes it not a DNS time-of-check-to-time-of-use; a name is
  refused unless **every** address it answers with is acceptable, so one
  that offers a public address and a loopback one cannot be raced;
  redirects cannot be followed; the body is bounded at 5 KiB while it is
  read, so a missing or dishonest `Content-Length` changes nothing; and
  there is exactly one request, with no retry and no second address.
  The 5 second budget covers the whole fetch, not each operation, so a
  server sending a few bytes at a time cannot hold a worker: the timeout is
  recomputed from one deadline before every HTTP read, the name is resolved
  under the same deadline through a process-wide resolver pool, and the TLS
  handshake takes what is left of it as its own whole-handshake timeout,
  which is what `ssl` applies it as. An address is judged by what it reaches, so an IPv4 address
  carried inside an IPv6 one (`::ffff:169.254.169.254`, NAT64) is read as
  the address it translates to, and the ranges CVE-2024-4032 affects are
  named in the code rather than left to `ipaddress`: nanoidp supports
  Python 3.10, where older patch releases call several special-purpose
  ranges globally reachable, and raising the floor would not settle it
  either. Only `max-age` is read from `Cache-Control`;
  `no-store` and `no-cache` answer that the document is valid and must not be
  cached, rather than discarding it: what a caller can do with a document it
  may not keep is the caller's decision, and with the cache the only place a
  CIMD client exists between `/authorize` and `/token`, the wiring will
  refuse such an authorization request rather than issue a code for a client
  `/token` could not resolve.
  **Nothing calls this yet**: `/authorize` is the rest of #196.
- **A client can come from a metadata document it publishes** (#196, first
  part): `IdentityResolver` resolves a third origin, `cimd`, after the two
  it already knew. Precedence is declared, then runtime, then a cached
  metadata document, and the first two are answered without the cache being
  consulted at all: an `https` client_id does not by itself make a client a
  CIMD one. The rules about what a client identifier URL is, and what a
  document must say to become a client, live in
  `services/client_metadata.py` as pure functions, with the cache as a
  repository the runtime store lends them. A document authenticates with
  `none` and nothing else, since the draft forbids every shared-secret
  method and those are two of the three nanoidp supports.
  `oauth.client_id_metadata_documents.enabled` is off by default and set in
  the file only, like `dynamic_registration`.
  Only successes are cached, at most 100 documents at a time with the
  oldest fetch evicted at the cap and expired entries swept on every write:
  the entries will come from client-chosen URLs on an unauthenticated
  endpoint, so a lifetime per entry is not a bound. There is deliberately
  no negative cache, which the draft forbids.
  **Nothing fetches yet**: the resolver reads the cache and never fills it,
  which is what keeps network I/O out of `/token` and the other fifteen
  places that resolve a client. The fetcher and the wiring to `/authorize`
  are the rest of #196.
  For code embedding nanoidp: `Origin` is now `UserOrigin` and
  `ClientOrigin`, because only a client can have this third one.

### Fixed
- **A password field holding only spaces means "unchanged" on the users edit
  form, as it already did on create** (#386). The create leg stripped the
  field before deciding it was blank and the edit leg did not, so `"   "`
  was no password on one and a real new password on the other: an operator
  who left stray spaces in the field, from a paste, an autofill or the
  spacebar, silently replaced that account's password with whitespace, with
  nothing flashed and nothing logged, and the account stopped authenticating
  with the password they believed it had. Both legs now share one notion of
  "the field was left blank". Stripping decides only that: a password that
  is not blank is stored exactly as typed, leading and trailing spaces
  included, since those may be deliberate.
- **A refused field on the users or clients edit form is answered, not
  reported as a server failure** (#298). An email without `@`, a colour that
  is not a hex triplet or any other value the model refuses reached the
  catch-all on the edit routes: the operator was told "Failed to update
  user: 1 validation error for User ..." and the server logged a stack trace
  at ERROR for what is ordinary form input. The create routes had always
  answered the same input with the refusal itself, and both legs now build
  the record through one reader, so both answer it the same way. Nothing is
  written in either case.
- **A write that would leave a file unloadable is refused, not written**
  (#366). Every writer replaced the file and reloaded afterwards, so a
  document the models refuse reached disk first and was discovered second,
  leaving a `settings.yaml` the next process could not start from. The
  composed document is now parsed, exactly as a load parses it, before any
  file is replaced: the error names the file and the key and nothing is
  written. Reachable from the settings form (a blank `oauth.audience` or
  `oauth.issuer`) and from the MCP tools, where `update_settings` writes
  onto a model without `validate_assignment` and `save_config` persisted
  the result, so an `issuer` refused by a validator rather than by a field
  constraint could be saved and then fail to load back. `${VAR}`
  placeholders are expanded into a copy for the check, so what is written
  keeps them. The check is of the document only, never of activation.
  `nanoidp init` and the setup wizard go through it too: they validated the
  document model but not the domain rules, so an issuer like
  `localhost:8000` finished the wizard and left a directory the server it
  had just configured could not start from. Both files are now checked
  before either is written, so a refused answer leaves no half-configured
  directory behind. The check follows the loader's order, `config_version`
  included: that rule lives on the raw mapping rather than in the document
  models, so without it a candidate could pass every model and be refused
  by the very next load, and a batch holding both files also has to see
  them declare the same version.

### Added
- **Dynamic client registration** (#190), RFC 7591 with the read and delete
  of RFC 7592, behind `oauth.dynamic_registration.enabled` (off by default).
  `POST /register` issues a client from the metadata a host sends and is
  open when enabled: the flag is the gate, not `management_secret`, because
  a client that was handed only a server URL has nothing else to present.
  A registered client is a runtime client (#235): in memory, listed by
  `GET /api/runtime/clients` with `"source": "dcr"`, gone on restart, and
  written to `settings.yaml` only if an operator promotes it through
  `/api/runtime` - registering never writes the operator's file. The
  registration access token is shown once and stored only as a hash;
  promotion, deletion or a reload that declares the name ends RFC 7592
  management of that client. `oauth.dynamic_registration.max_clients`
  (default 100) bounds live registrations and answers `429
  registration_limit_reached`, a nanoidp name, since RFC 7591's error codes
  describe metadata. `grant_types` are validated and echoed but do not
  restrict the client: nanoidp has no per-client grant enforcement, which
  is also why `redirect_uris` are required for every registration and not
  only for the authorization code grant. With `rate_limit_enabled`, the
  rate configured for `/token` applies to `/register` as well.
  The flag is deliberately absent from the settings form and from the MCP
  `update_settings` tool.
- **RFC 8414 authorization server metadata** (#190).
  `/.well-known/oauth-authorization-server` serves the same document as
  `/.well-known/openid-configuration`, from the same builder and the same
  issuer resolution, so `issuer_from_request` applies to both and the two
  cannot drift. nanoidp is one server advertising one set of endpoints; a
  client that speaks only OAuth looks under this name and used to get a
  404 and a longer route to the same answer. A client registration
  endpoint is not advertised yet: that is the rest of #190.
- **Disposable runtime users and clients: `/api/runtime`** (#192). A CI job or
  an integration test creates users and clients on a running IdP, uses them in
  every protocol flow, and removes them without touching `users.yaml` or
  `settings.yaml`: `POST /api/runtime/users` and `/api/runtime/clients` (the
  body is a declared entry, validated by the same models), `GET` and `DELETE`
  per object, `DELETE /api/runtime` for all of them (answers the counts), and
  `POST .../promote` to write one into the declared file through the web UI's
  writer and retire the runtime copy. There is no update. A name the
  configuration declares answers `409`; a reload that declares a runtime
  object's name removes it with a warning and an audit event; a promotion
  records exactly one `runtime_identity_promoted` event, holds reloads off
  while it runs, and a promotion whose entry reached the file but whose
  reload failed resolves on the next successful load (promoted, or abandoned
  with a warning). Runtime objects
  survive reloads, not restarts. `GET /api/users`, `GET /api/users/{username}`,
  the token endpoint, the persona picker and the web UI's users and clients
  pages now show the effective identities, runtime ones marked with their
  origin and read-only in the UI; the dashboard counts them separately;
  `GET /api/config` and the MCP server stay on the declared configuration.
  Writes follow the `management_secret` gate of `/api`. See the new guide,
  "Disposable test identities".

### Fixed
- **Tokens are signed with the key the JWKS serves after a reload changes
  `jwt.keys_dir`** (#230). The token service kept the signing key it was
  built with, so after `POST /api/config/reload` had moved `keys_dir`,
  every grant at `/token` and `POST /api/users/<username>/token` kept
  signing with the old key while the JWKS, introspection and `/userinfo`
  already used the new one: tokens issued after the reload failed
  verification until a restart.
- **A reload no longer activates a configuration whose signing service
  cannot be built** (#359). `POST /api/config/reload` accepted a
  `jwt.keys_dir` the process could not create and answered 200, after which
  the JWKS answered 500 and `/token` failed (before #357 it kept signing with
  a key the JWKS no longer served). The load now prepares the signing
  service from the candidate settings before it commits anything: a
  configuration that cannot build it is rejected and the running one stays
  in effect, on `POST /api/config/reload`, on MCP `reload_config` and on
  the refresh that follows a UI write. An unrelated reload reuses the running
  signing service instead of rebuilding it, and loads now run one at a time,
  so two concurrent reloads can no longer generate keys into a new
  `keys_dir` over each other.
- **`jwt.external_keys` and `jwt.max_previous_keys` are read from
  `settings.yaml`** (#358). Both were documented in the security guide, but
  the loader ignored them as unknown keys, so an operator's own signing key
  was silently replaced by a generated one and the retention stayed at 2.
  They are now part of the settings document and the JSON schema, and they
  are signing inputs of #359's activation: the configured key signs tokens
  and is the only key the JWKS serves, the MCP server signs with it too, and
  a reload that changes either setting reinitialises the signing service.
  `private_key` and `public_key` are given together; a missing, unreadable
  or malformed key file, or a public key that does not belong to the private
  key, rejects the configuration. Without `kid`, the key id is the RFC 7638
  thumbprint of the public key (the docs promised a fingerprint; a random id
  was generated on every start). Rotation is refused for external keys
  (`409` from `POST /api/keys/rotate`, an error on the keys page and from
  MCP `rotate_keys`) instead of replacing the operator's key with a
  generated one. The key files are not watched: a key replaced at the same
  paths is read at the next start. The SAML certificate for an external key
  lives in its own file (`external-cert-<thumbprint>.pem`, stable across
  starts), so switching back to generated keys no longer leaves SAML
  signing with a certificate for the wrong key; a certificate that does not
  belong to the signing key is regenerated, SAML signing uses the published
  service's certificate instead of re-reading the file per request, and a
  lowered `max_previous_keys` trims the JWKS as soon as it is applied.

### Changed
- **A configuration directory is read as one observation, not several**
  (#246, first part). `settings.yaml` and `users.yaml` were opened by two
  separate unlocked reads, so a save landing between them, from another
  process or another thread, was observed as a settings/users pair that
  never existed on disk, and the runtime was built from it. Reads now go
  through `ConfigFileStore`, which acquires the directory under the same
  lock the writer takes and returns each file's bytes together with the
  revision of exactly those bytes, so a precondition can no longer describe
  content nobody read. Only the acquisition is inside the lock: parsing,
  environment expansion, the document models and the profile hardening all
  run afterwards, because the atomic unit is the filesystem snapshot rather
  than the whole reload. The revision a form stamps into the page, which the
  save hands back as its precondition, is observed through the same
  boundary. A read never abandons an available protocol: contention fails,
  and so does a filesystem without advisory locking, because both mean the
  protocol is there and this process could not join it. A **read-only
  configuration mount keeps working**, which is a supported deployment here
  and which an earlier version of this change broke: the lock file is
  reopened read-only, so such a mount still takes part in the protocol
  rather than stepping outside it, and only a view that can hold no lock
  file at all, or a directory that does not exist, reads unlocked - neither
  has a writer to be inconsistent with. The whole acquisition shares one
  deadline, so waiting for another process is bounded and never leaves this
  one holding a lock indefinitely. Since a read can now fail, a request that
  cannot observe the configuration answers **503** with the classified
  reason instead of a 500 and a traceback.
- **`claims_supported` no longer advertises `source_acl` and `authorities`**
  (#316). OpenID Connect Discovery 1.0 §3 defines that field as the Claim
  Names a provider may be able to supply values for; on top of it nanoidp
  holds its own invariant, that only a claim which can appear in an ID Token
  or a UserInfo response is advertised. Those two appear in neither: they
  are authorization facts a resource server reads off an access token, and
  the claim resolver does not know them, so a client that read the document
  and asked for one got nothing back. The document now keeps the rule #41
  set for it, and a test checks the rule rather than the two names.
  `attributes` stays advertised: it is a Claim Name and `/userinfo` supplies
  it as a composite member, even though the resolver does not address it, so
  a `claims` request for it is answered only when the user owns a custom
  attribute by that name. What every surface asserts about a user is now
  written down in the new reference page rather than being a consequence of
  two independently written assemblers.
- **The three SAML Response builders share the part of the document that is
  the same in all three** (#317). The `Response` envelope, the `Issuer`
  pair, the `Status` element and the assertion's head were written three
  times over, in the SSO login assertion, the attribute-query assertion and
  the error Response for an unknown principal, so a change to the NameID
  policy had to be made in each. They come from `services/saml_assertion.py`
  now. What is NOT shared is what actually differs, and the census found six
  differences that were declared nowhere and covered by no test: the
  `Conditions` window (five minutes against one hour), `Destination`,
  whether `InResponseTo` is conditional, the `ds` namespace, the
  serialization and the signing path. They are documented in the SAML
  reference and pinned byte-for-byte, deliberately not unified: the two
  validity windows in particular have never been decided to be one policy,
  so folding them behind a `ttl` argument would have hidden a difference
  this work exists to declare. The bytes of all three documents are
  unchanged.
- **A client's authentication method and secret are normalized in one
  place** (#300). "`none` drops the secret" was written four times - the UI
  create and edit forms, MCP `create_client` and `update_client` - with the
  reasoning repeated at each site, and the order an existing client must be
  moved through (the model validates on assignment) was a comment in the
  one place that hit it. Both live in `services/client_policy.py` now.
  The difference between an omitted secret, which keeps the stored one, and
  an empty one, which a confidential client refuses, is unchanged, and the
  UI form's "blank means unchanged" stays in the route, where the convention
  belongs. The other consequences of a client being
  public - PKCE at `/authorize`, the refusal at `/introspect`, the ownership
  check at `/revoke`, the channel rule at `/device_authorization`, forced
  refresh rotation - deliberately stay where they are applied: they are
  different rules sharing a predicate, not one policy written ten times.

- **What `/userinfo` returns and what `/introspect` reports are services**
  (#303), not response dicts assembled inside the routes. Which claims a
  token's bearer may see, and what an introspection says about a token, are
  protocol policy and are now testable without an HTTP request; the routes
  keep the adapter's work - the Bearer token, client authentication, the JWT
  checks, revocation, the user lookup and the audit entries. Behaviour is
  unchanged, including the two rules that read on key presence rather than
  truthiness: a token naming a null client reports null rather than the
  caller, and a token whose scope is empty is reported with an empty scope
  rather than the default. Which profiles gate the standard claims is now a
  property of `Settings` next to the other profile-derived predicates.

- **The settings keys written only when they differ from their default are
  table rows** (#319). `security_profile`, `login.mode`, `login.auto_login`,
  `login.two_step` and `login.totp` were hand-coded below the loop that
  drives every other key from `OWNED_SETTINGS`, so the parity test that
  holds a setting to every surface did not cover them; a new `login.*` key
  had to be threaded by hand through six places, which is the shape of bug
  that table exists to prevent. They are rows with an `omit_when_default`
  mode now, one rule serves both a top-level key and a key in a section
  that disappears with its last entry, and the writer's four one-line
  helpers and its positional four-tuple of defaults are one helper and one
  mapping. The fallback defaults `serialization.py` keeps (it must not
  import the document models) are now pinned to those rows and to the real
  defaults. No behaviour changes: what a save writes, omits and leaves
  untouched is unchanged, and the writer keeps its API, including
  "blank mode means unchanged" and "an absent checkbox means unchanged".

- **SAML XML is parsed through a parser built per call** (#378), not one
  shared by every request thread. Sharing one was never a correctness
  problem - an `lxml` parser owns a lock and holds it for each parse - but
  that lock serialized every SAML parse in the process: measured on 24000
  parses of a 5 KB document, the shared parser took 3.0 s on one thread and
  2.3 s on eight, while a parser per call took 3.2 s on one and 0.64 s on
  eight. The cost sits at the small end, about a microsecond per parse of a
  300-byte AuthnRequest, against requests that take milliseconds. It also
  removes the shared object that twice stood as an alternative explanation
  for a surprising parse while #309 was being diagnosed. The parser options
  are unchanged and spelled out literally where the parser is built, which
  is what both a reader and a static analyser go by; they are now pinned by
  tests, where one of them used to be a comment block asserting nothing.

- **Every `/saml/attribute-query` outcome is attributable to its sender**
  (#309). A query refused for its shape - not well-formed, no
  `AttributeQuery`, no `Subject`, no `NameID` - used to write no audit entry
  at all, and the query's own `ID` was read only after those three were
  found, so a refused request could not be matched to whoever sent it. Each
  outcome now writes a `saml_attribute_query` entry carrying `request_id`
  and `content_length`, and the id is read as early as the body allows,
  including from a query posted without the SOAP envelope. The body itself
  is logged only under `verbose_logging`, since it names a principal, and
  the recorded id is truncated, since it comes from an unauthenticated
  caller and is kept in the audit ring - a shortening of the evidence only:
  what the protocol sends back in `InResponseTo` is the id exactly as it
  arrived. Auditing refusals also means that
  reaching this endpoint is a way to push older audit entries out, which the
  endpoint reference now says. This is diagnosis for a flake that has not
  been reproduced, not a fix for it.

### Fixed
- **Switching a client to public through the UI edit form drops a secret
  typed in the same submission** (#300). The form only dropped it when the
  field was left blank, so an operator who picked
  `token_endpoint_auth_method: none` while a secret sat in the input
  persisted a dead, ignored value - the state the create form has refused
  to write since #254. The two forms now apply the same rule.

- **Two signed Redirect AuthnRequests in one browser no longer interfere**
  (#375). With `saml.want_authn_requests_signed`, a verified `GET
  /saml/sso` was remembered in a single session key, so a second signed
  request overwrote the first and its login post was then refused as not
  matching a verified request. The browser's session now holds the set of
  requests it had verified: ten of them, an eleventh making the oldest
  non-continuable, each kept for 10 minutes of inactivity and refreshed
  while the login is continued, and remembered only when a login actually
  has to be continued. Two signed requests issued before either response's
  cookie reaches the browser still leave only the later one continuable,
  since the set travels in that cookie. What the login post must present is unchanged, and
  an expired verification now says so in the audit and the log instead of
  reporting the signature as invalid.

### Changed
- **The TOTP code screen of `/login`, `/saml/sso` and `/device` no longer
  sends the verified password back to the browser** (#373). The password
  check is recorded on the server as a pending second factor, bound to the
  browser, to the surface and to what the login is for there (the SAML
  request in flight, the device `user_code`), valid for 5 minutes and used
  once, and the code screen carries only its id. The code is checked
  against the user's current secret; a user deleted or left without a
  secret, TOTP switched off or persona mode switched on in between ends the
  login with an error instead. "Change username" is a form post that
  discards it, and on `/device` a deny from the code screen discards it too
  and still needs no credentials; the `user_code` is read-only on that
  screen. A post carrying the password and the code together works as
  before, with nothing stored. At most 1000 such logins wait at once.
- **`/authorize` keeps each request as a server-side authorization
  transaction** (#346). An accepted GET validates the request once and
  stores it, bound to the browser, instead of copying ten parameters into
  the session; the login page's forms name it with `transaction_id`, and
  issuing the code consumes it. The TOTP code screen no longer sends the
  verified password back to the browser: the transaction records it, and
  the code is checked against the user's current secret. A POST without
  `transaction_id` (a script posting credentials after its GET) still
  works while exactly one request is pending in that cookie jar; with
  several it is now refused instead of completing whichever GET came last.
  A POST carrying the whole request in its query string keeps working with
  or without a GET before it, and still leaves the browser's pending
  requests alone. "Change
  username" is a form on the transaction rather than a link carrying the
  request. A request opened before a configuration change keeps the client
  it was validated against; only a client that no longer exists ends it.
  Pending requests are capped at 1000 and expire after 10 minutes; at the
  cap a new request gets `temporarily_unavailable` rather than any pending
  one being dropped.
- **MCP tool arguments take their shape from the domain models** (#297).
  An argument that carries a configuration field's value now derives its
  type, enum, bounds, length, pattern and item type from that field; the
  tool keeps its own description, its `required` list and the wider
  vocabulary it defines (an empty `client_secret` or branding colour still
  means "none"/"clear it", an empty `get_audit_log` username still means
  "no filter", and the handler answers those). The schemas gained 16
  constraints the models already enforced and nobody advertised:
  `minLength` on every name and secret that has no wider tool vocabulary,
  and the range of `token_expiry_minutes`. For a client this moves those
  rejections to a dispatch refusal (`MCP_INVALID_ARGUMENTS`), the two
  layers the MCP error model already describes.
- **`update_settings` no longer applies a value the model would refuse**
  (#297). It writes its arguments onto `Settings` with `setattr`, and
  `Settings` has no `validate_assignment`, so its tool schema was the only
  check between an argument and the running configuration - and that schema
  carried two enums and no bounds. `update_settings` with
  `token_expiry_minutes: 0` or `99999` was applied and reported as a
  success; both are now refused before dispatch.
- **`saml.c14n_algorithm` is a closed set** (#297), in the models and in
  the configuration document. An unknown value used to reach `routes/saml.py`,
  which silently signed with Exclusive C14N, so a typo changed the algorithm
  without a word; it now fails the configuration load. Blank keeps meaning
  "the default", so an unset `${VAR}` placeholder loads exactly as before,
  and the settings writer checks the value before it replaces the file.
  (`login.mode` was already a closed set on the `Settings` model and only
  moves into the document type here.)
- **Users and clients resolve through one identity resolver** (#235), in
  preparation for runtime-created test identities (#192). Every login,
  grant, client authentication and SAML lookup resolves users and clients
  through `nanoidp.services.identities`, which composes the declared
  configuration with an in-memory runtime identity store, declared first;
  a reload that declares a name a runtime object holds removes the runtime
  one with a warning. Nothing creates runtime objects yet, so no HTTP, UI
  or MCP behaviour changes. The management surfaces (UI pages and forms,
  the persona picker, `/api/users` including its token endpoint, MCP) stay
  on the declared configuration until #192. For code embedding nanoidp:
  `ConfigManager.authenticate`, `interactive_authenticate` and
  `check_client` moved to `IdentityResolver` (`identities_for(config)`);
  `ConfigManager.get_user` and `get_client` stay, and return declared
  objects only; `init_config` gains `after_load`, which `create_app` uses
  for the reconciliation.
- **One `ConfigManager` per process** (#230). The MCP server no longer keeps
  a configuration global of its own next to `nanoidp.config`'s; its tools,
  the HTTP routes and the token service resolve the same manager, and
  `TokenService` takes that manager explicitly instead of looking it up and
  caching it. No change to the MCP tools or to any HTTP surface. For code
  embedding nanoidp: `nanoidp.mcp_server._config` no longer exists (use
  `nanoidp.config.init_config`), and `TokenService()` now needs the
  manager, `TokenService(config)`; `get_token_service()` is unchanged.
- **A rejected reload answers a JSON `422`** (#359): `{"status": "error",
  "error": ..., "kind": "invalid" | "activation"}` from
  `POST /api/config/reload`, and an error result with the same `kind` from
  MCP `reload_config`, for files that cannot be read or do not validate as
  well as for a signing configuration that cannot be used. Such a file used
  to answer Flask's HTML 500. A strict hook or plugin failure keeps its
  `503`. At startup the same conditions print
  `error: configuration rejected: ...` and exit 1 instead of a traceback.
  For code embedding nanoidp: a failed load raises
  `nanoidp.config.ConfigurationRejected` (a `ValueError`, with the original
  error as its cause); `get_crypto_service()` takes no argument and returns
  the service the configuration published; `init_crypto_service` is replaced
  by the activation step `activate_crypto_service`, passed as
  `init_config(..., activate=...)`.

## [3.2.0] - 2026-09-15

### Added
- **Declarative TOTP second factor** (#348, opt-in, off by default):
  `login.totp: true` requires a time-based one-time code after a successful
  password check, across every interactive login surface - `/authorize`,
  `/login`, `/saml/sso` and the device flow's `/device` - the same
  surfaces `login.two_step` covers, riding its phase machinery. A
  declarative demo factor, not IdP hardening: the secret is a plain
  `totp_secret` field of the user entry in `users.yaml` (its presence is
  the enrolment, no per-user `enabled` flag, `${VAR}` allowed like any
  value), never accepted or returned by the users form or any MCP user
  tool. Verification is RFC 6238 (6 digits, 30s period, HMAC-SHA1, one
  step of clock skew), standard library only, no new dependency, and
  deliberately has no replay protection. Inert under `login.mode: persona`,
  which checks no password; the OAuth password grant and client
  credentials are unaffected. While `login.totp` is on, the ID Token
  carries an OIDC `amr` claim (RFC 8176): `["pwd"]` for a plain password
  login, `["pwd", "otp"]` once the code is verified, preserved across a
  refresh like `auth_time`; with it off no new claim appears. A third SAML
  `AuthnContextClassRef` value,
  `urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken`, next to the
  existing password/unspecified pair. Configurable through YAML, the
  Settings UI, and the MCP settings tools.
  Two side effects on existing configurations: `totp_secret` is now a
  reserved top-level user key (before, an unknown key of that name was
  folded into the user's `attributes`), and `amr` joined the reserved
  claim names, so a user attribute named `amr` requested through the
  `claims` parameter is no longer resolved, whether `login.totp` is on or
  off (#110).

### Fixed
- **Pydantic configuration validation no longer echoes rejected secret
  values** (#352). The loader raises its own message from pydantic's
  validation error, and that error rendered the offending input as
  `input_value=...`, so the value reached every place that prints the
  chained traceback: the startup output, the server log on
  `POST /api/config/reload` and the MCP server's log on `reload_config`.
  Affected: a `client_secret`, `session.secret_key`
  or `session.management_secret` that YAML reads as a number, a
  `management_secret` rejected for a non-ASCII character (that one also
  appeared in `nanoidp validate-config` and in both MCP tool results), and
  the settings of every plugin when one `plugins:` entry is malformed, in
  `settings.yaml` or `bootstrap.yaml`. The three document roots and the
  `Settings` and `OAuthClient` models now hide the input (`UserEntry` keeps
  its own flag as defense in depth); the error still names the file, the
  field and the rule. #350 had closed the same gap for `users.yaml`. The
  scope is pydantic's rendering of validation errors, not a general
  redaction of every exception that may carry configuration data.

## [3.1.0] - 2026-09-14

### Migration notes

Nothing below changes a supported API. This release stays a minor: the
`/authorize` changes correct behaviour the protocol never allowed, and the
non-root image is a deployment-compatibility change. What needs a hand on
upgrade is collected here.

- **The container image runs as a non-root user** (#332): uid 1000, gid 0,
  with `/app/keys` and `/app/config` owned by that user and group-writable
  by group 0, so the image also runs where the platform assigns an
  arbitrary uid with gid 0. Every Kubernetes namespace enforcing the
  `restricted` Pod Security Standard rejected the previous image on
  `runAsNonRoot`; the Helm chart's default `securityContext` now sets
  `runAsNonRoot: true` and is admitted there. It pins no `runAsUser`
  (#339): the standard does not need one, and a platform that assigns its
  own uid per namespace (OpenShift's `restricted-v2`) would reject a pinned
  `1000` while the image runs fine under the assigned uid. A plain
  `docker run` with nothing mounted is unaffected. *Migration:* a keys
  volume or bind mount first created by an earlier release is root-owned.
  The new image still starts on it, because the existing keys are readable,
  but the next key rotation fails with `Permission denied: 'keys/previous'`.
  Chown it once: `docker run --rm -v nanoidp-keys:/k alpine chown -R 1000:0 /k`
  (or `chown -R 1000:0` on the host directory of a bind mount). A read-only
  config mount needs nothing. To run an older image tag with the chart,
  set `securityContext.runAsNonRoot=false` and `securityContext.runAsUser=0`.
- **`/authorize` contract corrections** (#325, #328, #331, details under
  Fixed): the POST leg reads the OAuth parameters from its own query
  string, never from the form body; a request carrying any OAuth parameter
  is a complete request and no longer borrows missing fields from the
  session; a rejected request no longer replaces the pending one. *Migration:*
  a client that packed the OAuth parameters into a single `POST /authorize`
  body with no preceding GET must send them on the query string instead.
  Browser flows are unaffected.

### Added
- **Two-step login** (#322/#323, opt-in, off by default): `login.two_step:
  true` collects the username first and the password on a second screen,
  across every interactive login surface - `/authorize`, `/login`,
  `/saml/sso` and the device flow's `/device`. A global setting alongside
  `login.mode`/`login.auto_login`, not a per-client one; inert under
  `login.mode: persona`, which is passwordless and has no password screen
  to split off. The step is stateless: the username travels as a plain
  form field, carried forward as a hidden input on the password screen -
  a request that already carries both authenticates directly, so anything
  written against the combined form keeps working unchanged. Configurable
  through YAML, the Settings UI, and the MCP settings tools.
- **Helm chart** (#327/#330) under `charts/nanoidp`, published to
  `oci://ghcr.io/cdelmonte-zg/charts/nanoidp` on every release tag by the
  new `Publish Helm chart` workflow, with the chart version taken from the
  tag. Single replica by design, configuration as whole `users.yaml`/
  `settings.yaml` files in a generated Secret (or one you manage), Ingress
  with `${INGRESS_URL}` for the issuer, a `checksum/config` annotation that
  rolls the pod on a configuration change, and a default `securityContext`
  admitted by a namespace enforcing the `restricted` Pod Security Standard
  (with the non-root image, see Migration notes). The chart README states
  the limitations that hold by design: read-only config mount, signing keys
  regenerated on every pod restart. `helm install` without `--version`
  resolves the newest final release; pre-releases need `--devel` or an
  explicit version.
- **n8n end to end, path 1** (#194): `examples/agentic-stack/docker-compose.yml`
  runs nanoidp, the RFC 9728 mock MCP server and a pinned n8n (2.38.7) on one
  network, and `e2e/n8n_e2e.py` drives it headless: n8n's own OAuth2 flow
  (PKCE, public client, RFC 8707 `resource`) against nanoidp, then a workflow
  whose MCP Client node calls `read_document` with the token n8n obtained,
  plus the insufficient-scope and wrong-audience negatives. A manual and
  nightly workflow (`n8n E2E`) runs it. No change to nanoidp was needed;
  n8n's dynamic client registration mode stays out of scope until #190.
- **n8n end to end, path 2** (#194): the same stack now also runs n8n's AI
  Agent with the MCP Client Tool node inside its tool-calling loop. The
  agent's model is `e2e/mock_chat_model.py`, an OpenAI-compatible fixture
  that always asks for the MCP tool and then quotes the tool's answer, so
  the run needs no LLM. `e2e/n8n_e2e.py` asserts that the agent offers the
  model the tools the resource server lists, calls `read_document` with the
  token n8n obtained and quotes the document; that an `insufficient_scope`
  refusal comes back to the model as the tool's result rather than as a
  crash; and that a wrong-audience token stops the agent at `tools/list`,
  before the model is called. The Compose file gains an optional `ollama`
  profile for running the same loop by hand with a real local model; CI
  never uses it. Still no change to nanoidp.

### Changed
- **Test suite hygiene** (#305, #320): the shared `conftest` reset now
  covers the three runtime stores (authorization codes, device codes,
  revocation) next to the service singletons, and the per-file cleanup
  fixtures that patched that gap are gone; the crypto leg of the singleton
  concurrency test uses a stub that carries what `get_crypto_service` reads
  since #281, and the test now asserts that every racing thread returned an
  instance, so it cannot go silently vacuous again.
- **The Helm chart is published only once its image is in the registry**
  (#340). `docker.yml` and the chart workflow both start on the same
  release tag with nothing ordering them; the chart workflow now waits for
  the image's manifest (bounded at twenty minutes, well above the
  multi-arch build) before `helm push`, and fails instead of publishing a
  chart that runs nothing. On the chart-only dispatch path the same wait
  confirms the pinned `image.tag` exists.
- **The login session has a single writer** (#301). The dashboard's `/login`
  and the SAML SSO inline login each used to set `session['user']` and
  `session['auth_method']` by hand, and the SAML assertion's
  `AuthnContextClassRef` is derived from the latter. Both now call one
  helper, `establish_login_session`, which records the user and how it
  authenticated together. A future login surface is held to the helper by
  a contract test (direct forms only: a subscript store, `session.update`
  or `session.setdefault` naming the key, the `'auth_method'` literal
  anywhere), so recording a user without recording the method, which would
  have made its persona logins silently claim `PasswordProtectedTransport`,
  fails the suite rather than passing unnoticed. No behavior changes for
  existing logins.

### Fixed
- **Rejected `/authorize` requests no longer replace an earlier pending
  request in the same browser session** (#331). The session capture now
  updates only after client, redirect URI, response type, scope, PKCE, and
  resource validation succeeds, and after persona auto-login remains inert.
  A later bare login submission can therefore complete the original request
  instead of inheriting a rejected request's client, callback, or state.
- **A fresh `/authorize` request no longer inherits optional parameters left
  behind by an earlier, abandoned request in the same browser session**
  (#328). A query string carrying any OAuth request parameter is now a
  complete request: omitted required parameters are rejected, while omitted
  `state`, `nonce`, PKCE, `claims`, `resource`, and `scope` values remain
  omitted or use their normal defaults instead of falling back field by field
  to stale session values. A request carrying only unrelated query parameters
  still resumes the complete request captured by the preceding GET. Only a
  complete, accepted GET updates that capture; POST requests never do, so a failed
  direct POST carrying its own OAuth query string cannot rebind a later bare
  form submission. A valid GET in another tab still replaces the shared session
  capture. **Contract changes:** a partial request no longer borrows its
  missing required fields from the session, and a client that starts with a
  POST cannot retry it as a bare POST after failed credentials. Browser form
  retries are unaffected because the form resubmits to its full query-string
  URL.
- **`/authorize` POST leg no longer trusts OAuth params from the login form
  body** (#325): `client_id`, `redirect_uri`, `scope`, `state`,
  `code_challenge`/`code_challenge_method`, `nonce`, `claims`, and `resource`
  are now read from the query string on both legs - the POST's own (the
  login form has no `action`, so it always submits back to the exact
  `/authorize?...` URL of the page it rendered), falling back to the session
  captured on the preceding GET when the query string has no OAuth request
  parameters of its own - and never from the POST body. Previously the POST
  leg fell back to the form body for these fields, so a forged hidden form
  field could override the request the user actually approved, breaking the
  binding between that approved request and the issued authorization code; a
  completed login or a mere page load in another browser tab sharing the same
  cookie jar could do the same by clearing or overwriting the session's copy
  out from under an in-flight tab. Binding each POST to its own page's query
  string closes all three. **Contract change:** a single
  `POST /authorize` that packs the OAuth parameters into the body together
  with the credentials, with no preceding GET, is no longer honored - send
  those parameters on the query string instead
  (`POST /authorize?client_id=...&redirect_uri=...`),
  or do the GET first as before. The login form itself only ever
  legitimately carries `username`/`password`, and a POST already routed
  through the preceding GET's page (the common case) is unaffected.
- **`login_hint` is no longer honored on the POST leg** of `/authorize`
  (#325): the persona auto-login prefix (see "Auto-Login" below) it feeds
  only ever had a meaningful GET-time use, so a value posted with the login
  form - which the login page itself never sends - is now always ignored
  rather than read from the request.

## [3.0.0] - 2026-09-06

### Breaking Changes

This release tightens and unifies nanoidp's OAuth **client-authentication
contract**. A confidential client that already presents its registered method
over the matching channel, and any public client, are unaffected; a client that
authenticated over a different channel at one of these endpoints - which the
previous leniency allowed - needs a one-time adjustment.

- **The registered `token_endpoint_auth_method` is now enforced at every
  client-authenticated endpoint** (#188, #259, #262): `/token`, `/introspect`,
  `/revoke` and `/device_authorization`.
  - A **confidential client must authenticate on `authorization_code`** too -
    the code exchange no longer has a client-authentication exemption (RFC 6749
    §3.2.1). *Migration:* present the client secret on the code exchange, or
    re-register the client as `token_endpoint_auth_method: "none"` if it cannot
    keep a secret (and use PKCE).
  - The registered method decides the **channel**: a `client_secret_basic`
    client must use HTTP Basic and a `client_secret_post` client must use the
    request body - the wrong channel is rejected with `invalid_client`.
    Previously a body secret was accepted (or silently ignored) regardless of
    the registered method. Applying the one registered method across all four
    endpoints is nanoidp's **consistency policy**: RFC 7009 and RFC 8628 tie
    `/revoke` and `/device_authorization` to the token-endpoint method, while
    RFC 7662 permits client authentication at `/introspect` but does not mandate
    reusing that method - so a client that legitimately used a different channel
    for introspection stops working here by nanoidp's choice, not because it was
    non-compliant. *Migration:* send credentials over the channel the client is
    registered for; set `token_endpoint_auth_method` to match how your client
    actually authenticates.
  - **Two authentication methods in one request are rejected** (HTTP Basic and a
    body `client_secret` together, RFC 6749 §2.3) - Basic no longer silently
    wins. *Migration:* send credentials one way only.
  - Public-client policy: `/introspect` refuses public clients (RFC 7662),
    `/revoke` keeps its RFC 7009 §2.1 ownership relaxation, and
    `/device_authorization` now accepts a public client by client_id alone
    (RFC 8628, see the device-flow entry below).
- **`/authorize` reports errors after `redirect_uri` validation by redirecting
  to the client** (#189, RFC 6749 §4.1.2.1 / RFC 9207): `unsupported_response_type`,
  `invalid_scope`, PKCE errors and `invalid_target` are now `302` redirects
  carrying `error`, `error_description`, `state` and `iss`, not a local JSON
  `400`. Errors before `redirect_uri` is validated (unknown client,
  missing/malformed/unregistered `redirect_uri`) still return JSON locally.
  *Migration:* a client that parsed the `400` body should read the error from
  the redirect query instead - which is what a spec-compliant client already does.
- **A refresh token without a `client_id` binding claim is rejected** (#73,
  `invalid_grant`, RFC 6749 §5.2). The binding was added in 2.2.0 (#56);
  tokens minted before it were still spendable by any authenticated client
  until they expired - a transitional compat deferred to the next major, now
  closed. *Migration:* discard refresh tokens minted before 2.2.0 and obtain
  new ones (every grant since 2.2.0 already binds them). The MCP `generate_token`
  tool gains an optional `client_id` (which must name a real client) that binds
  the minted token and issues a refresh token spendable by it; without it the
  tool mints an unbound access token with no refresh token at all, rather than
  hand back one that could not be spent. The HTTP testing endpoint
  `POST /api/users/<username>/token` gets the same treatment - a new optional
  `client_id` binds the token, and it no longer returns a `refresh_token` when
  unbound - so all three token minters (a grant, the MCP tool, this endpoint)
  agree.
- **One request, one client identity** (#277). `/introspect`, `/revoke` and
  `/device_authorization` now resolve the requesting client exactly as
  `/token` always has: HTTP Basic naming client A plus `client_id=B` in the
  body is one request claiming two identities and is rejected with
  `invalid_client` (previously the Basic username silently won and the body
  value was ignored). *Migration:* drop the contradictory body `client_id`,
  or make it match the authenticated client.
- **The `device_code` grant re-validates the stored scope at redemption**
  (#276): a scope removed from the client's `allowed_scopes` (or from
  `scopes_supported`) between `/device_authorization` and the poll now fails
  the poll with `invalid_scope`, exactly as the `authorization_code` and
  `refresh_token` grants already re-check theirs. Previously the stale scope
  was still minted.
- **`/saml/attribute-query` answers an unknown NameID with a SAML error
  status** (#275): top-level `Requester` with subordinate `UnknownPrincipal`,
  no assertion. Previously an unknown user got a **signed assertion with
  fabricated attributes** (`<user>@example.com`, `identity_class: INTERNAL`,
  `entitlements: DOCUMENT_READ`) - an SP under test would pass with data
  nanoidp invented. The endpoint's docs now also state plainly that it is
  unauthenticated by design (the same read model as the REST API, #163):
  it previously claimed "after JWT authentication", which the code never did.

- **The `exp` claim is required on every token nanoidp accepts** (#306).
  `verify_jwt` now enforces `require: ["exp"]` - a correctly signed JWT
  WITHOUT an expiry is rejected everywhere (`/userinfo`, `/introspect`,
  `/revoke`, the refresh grant, MCP `verify_token`). This is nanoidp's
  token-profile policy, not a JWT-spec rule (RFC 7519 leaves `exp`
  optional; OIDC Core and RFC 9068 require it on the profiles that
  matter): a token accepted by an IdP should have a finite lifetime, and
  an eternal bearer token would let an integration test pass here and
  fail against any real IdP. Everything nanoidp mints has always carried
  `exp`; only hand-crafted tokens signed with the nanoidp key are
  affected. *Migration:* add an `exp` to such fixtures. No other claim is
  newly required.
- **An unverifiable refresh token now answers RFC 6749 §5.2 JSON**
  (`invalid_grant`, HTTP 400) instead of a Werkzeug 401 HTML page, per
  the "Error surfaces" rule (#287).
- **Every `/token` error branch now answers RFC 6749 §5.2 JSON** (#308):
  roughly twenty conditions across the endpoint shell and all five grant
  handlers used to answer Werkzeug HTML via `abort()`. Now: missing or
  malformed parameters are `invalid_request` (400); a bad, expired,
  revoked or foreign code/refresh-token - and invalid resource-owner
  credentials on the password grant - are `invalid_grant` (400); an
  unknown or profile-disabled grant type is `unsupported_grant_type`
  (400); client-authentication failures are `invalid_client` - 401 with
  the `WWW-Authenticate: Basic` challenge when the client attempted HTTP
  Basic (the §5.2 MUST), 400 otherwise (§5.2's default; RFC 9110 §11.6.1
  forbids a challenge-less 401, and a Basic challenge would be wrong for
  a `client_secret_post` client anyway). The attempt is detected from the
  raw `Authorization` header (#311): a syntactically broken Basic header -
  which werkzeug parses to nothing - still counts as an attempted Basic
  and gets the 401 + challenge. Descriptions are fixed text (no library
  detail and no reflected caller input - the unsupported grant type's raw
  value lives in the audit event, not the response). *Migration:* branches that used to answer 401 for GRANT problems
  (revoked/foreign refresh token, unknown user, wrong password) now
  answer 400 with `error: invalid_grant` - §5.2 reserves 401 for client
  authentication; read `error` from the JSON body instead of matching
  HTML.

### Changed
- **`mcp_server` is a package** (#286): the 2,100-line module is now
  `mcp_server/` - `schemas.py` (tool declarations and compiled validators),
  `normalize.py` (argument pre-validation), `serializers.py`,
  `handlers_users/clients/tokens/config.py` (the 25 tool handlers by
  domain), with dispatch, the guards, transport bootstrap and the mutable
  process state in `__init__.py`. The `nanoidp-mcp` entry point and every
  explicitly re-exported name keep their import paths (`from
  nanoidp.mcp_server import ...` for everything tests and callers actually
  use; `python -m nanoidp.mcp_server` now goes through the package's
  `__main__.py`) - arbitrary internal symbols of the old monolith are not
  a compatibility surface. `verify_secret` moved to a new framework-free
  `nanoidp.security` (re-exported from `routes/_auth.py`), so the stdio MCP
  process no longer imports Flask at all - pinned by a subprocess test.
  Behavior-preserving: handler bodies and schemas are unchanged.
- **`/saml/attribute-query` transport errors are SOAP 1.1 Faults** (#287):
  a malformed query (missing AttributeQuery/Subject/NameID) or an internal
  failure now answers with a proper `soap:Fault` (HTTP 500, `faultcode`
  Client/Server per SOAP 1.1 §6.2) instead of bare plain text with a 400 -
  a shape no SOAP stack could parse. Protocol-level conditions (unknown
  principal) keep answering inside the SAML Response as before.
- **The dead exception hierarchy is gone** (#287): `exceptions.py` declared
  20 classes of which exactly one was ever raised; only `SAMLSignatureError`
  remains (now a plain `Exception` subclass). Errors are shaped per surface
  - the model is written down in CONTRIBUTING ("Error surfaces"), including
  the deliberate two-layer MCP contract (dispatch refusals vs domain
  results), now documented where the shapes are defined.
- `TokenService.create_token` now owns the #73 mint-side rule (#278):
  `issue_refresh_token` defaults to "only when the token is bound"
  (`client_id` given), and asking for a refresh token without a binding
  raises instead of minting a credential `/token` would reject. The three
  minting surfaces (grants, MCP `generate_token`,
  `POST /api/users/<username>/token`) behave as before; the rule just lives
  in one place.
- The MCP `generate_token` and `verify_token` tool descriptions now document
  their simulation boundary (#279): `generate_token` stamps `scope` and
  `resource` as given with no vocabulary check and no per-client ceiling
  (minting an out-of-ceiling token is how a resource server's rejection path
  gets tested), and `verify_token` checks signature/expiry like a stateless
  resource server - revocation is `/introspect`'s answer. Behavior is
  unchanged; both exemptions are now pinned by tests.
- **The end-to-end test harness moved from `examples/` to a dedicated `e2e/`
  directory.** `test_agent.py`, `mock_mcp_server.py`, `mcp_smoke_test.py` and
  `gen_sp_keypair.py` now live under `e2e/`; `examples/` keeps only the real
  usage examples (client integrations, plugins). The harness was never a
  usage example - it is the CI end-to-end suite - and mixing the two made the
  repository harder to read. Invocations change from `python examples/...` to
  `python e2e/...` (CI, CONTRIBUTING and the docs are updated); no behaviour
  and no packaged code changed.
- **Resource indicators are validated per RFC 3986 component, not by a single
  character whitelist** (#257). A `resource` is still an absolute URI without a
  fragment (RFC 8707 §2), but each component is now checked against its own
  ABNF: `[`/`]` are accepted only inside an IP-literal host (so
  `https://host/a[b]` is rejected where it used to pass), a port is `*DIGIT`
  (no numeric-range limit, matching RFC 3986 §3.2.3), and IPv6 host literals
  are validated (a scoped `[fe80::1%eth0]` is rejected: RFC 3986 IPv6address
  has no ZoneID, per RFC 9844). Mostly a tightening on malformed input to an
  opt-in feature; it also stops rejecting a valid path-empty absolute URI
  (RFC 3986 §3, e.g. `about:`). No audience bypass or escalation.

### Added
- **Auto-login personas** (#250, opt-in, off by default): with
  `login.mode: persona`, a new `login.auto_login: true` lets an OIDC
  `/authorize` request log a configured user in directly - no picker, no
  HTML - by sending `login_hint: persona-auto-login:USERNAME`, for driving a
  real OIDC client library in automated integration tests. Any other
  `login_hint` is passed through unchanged, and with the flag off a
  prefixed hint is inert too, so the picker still shows exactly as before.
  An unknown persona reports through the standard OAuth error redirect
  (`error=invalid_request`, `state` preserved), never a bare `400`. First
  implementation surface is OIDC `/authorize` only; the device flow and
  SAML have no defined transport for the hint yet. Ships with settings UI
  and MCP (`get_settings`/`update_settings`) exposure, an `/api/config`
  `login` block (which also picked up the pre-existing `login_mode` field
  it was missing since persona mode shipped), and an
  `examples/persona-login` walkthrough. Like the rest of NanoIDP, a local
  development/testing convenience only - not an authentication mode for
  deployed environments.
- **Access-point parity contract for token issuance** (#283,
  `tests/test_token_issuance_parity.py`): the set of CALL SITES of
  `TokenService.create_token` (`file::function`, AST-checked) must equal a
  declared registry, and every (surface, policy) pair - client binding,
  scope ceiling, resource ceiling - must declare `enforced` (behaviorally
  asserted) or `exempt` (the exemption itself pinned, with its documented
  reason). A new minting call site - even a second function in an
  already-registered module - fails the suite until it takes a stance;
  this mechanizes the #269/#272 bug class out of existence.
- **User-field parity test** (#284, `tests/test_user_field_parity.py`):
  the nine user shapes (model, YAML entry, MCP read/create/update surfaces,
  UI form, REST read) are held to field-set equality with documented,
  asserted exclusions - the guard whose absence let #280 drift silently.
  Found #291 - originally misfiled as "no `attributes` input in the UI
  form" (the dynamic `attr_key[]`/`attr_value[]` widget was there all
  along, invisible to the single-name regex); the real defect behind it is
  fixed below.
- **"Domain invariants have one home" review rule** (#285) in CONTRIBUTING,
  echoed from VISION principle 4; five deferred imports claiming
  nonexistent circular dependencies hoisted to module top, and the one
  legitimately special case (`services/audit.py`) now documents its real
  reason (never construct config from a log path).
- **Horizontal `/authorize` login card composition** (#249). New per-client
  `layout` field, `"vertical"` (default, unchanged) or `"horizontal"`: the
  latter places the client info block and the login form side by side in a
  Bootstrap two-column split, with the header and footer still full width,
  collapsing back to the single-column stack on narrow viewports. One of
  exactly two nanoidp-owned layouts - no per-client CSS or column widths.
  Full support across settings.yaml, the UI client form, and the MCP
  `create_client`/`update_client` tools; omitted (or `"vertical"`) writes
  nothing to YAML, matching every other default-valued client field.
- **Public clients on the device flow** (#255, RFC 8628). A public client
  (`token_endpoint_auth_method: "none"`) can now use the device authorization
  grant: it presents its `client_id` alone at `/device_authorization` (§3.1)
  and again when polling `/token` (§3.4), with no secret. The issued
  `device_code` is bound to that `client_id` and only it can redeem it, which
  stands in for client authentication (it presents client_id as a parameter,
  not via HTTP Basic or a secret, RFC 8628 §3.1; both are rejected). Confidential
  clients still authenticate as before; #188 shipped public clients for
  authorization_code + PKCE, and this completes the pair for CLI/TV/IoT-style
  clients. Because an unauthenticated device authorization request is cheaper to
  spam, the in-memory device-code store is now capacity-bounded: at the cap it
  returns a plain `503` (with `Retry-After`) rather than growing without bound or
  evicting a live authorization - not an OAuth error code, since RFC 6749 §5.2
  has no registered code for server saturation.
- **Mock protected MCP server as an e2e fixture** (#191). `e2e/mock_mcp_server.py`
  is a minimal MCP Streamable HTTP resource server (the `mcp` SDK's
  resource-server mode) with three scope-gated tools (`read_document` /
  `documents:read`, `delete_document` / `documents:write`, `admin_operation`
  / `admin`). It validates bearer tokens JWKS-only against nanoidp (signature,
  `iss`, `aud` == its own resource URL, `exp`, scopes), serves the RFC 9728
  `/.well-known/oauth-protected-resource` document naming nanoidp as its
  authorization server, and answers an unauthenticated call with `401` +
  `WWW-Authenticate` pointing at that metadata. It demonstrates two
  authorization layers, kept distinct: a resource-level scope floor
  (`documents:read`), enforced by the SDK's bearer middleware, which returns
  the conformant MCP/RFC 9728 `403` `WWW-Authenticate: Bearer
  error="insufficient_scope"` + `resource_metadata` challenge before any tool
  runs; and an application-level per-tool check inside each tool for the finer
  `documents:write` / `admin` operations, which surfaces as an in-band MCP
  tool error. `e2e/test_agent.py` gains an `--mcp` suite that drives the
  whole loop deterministically as the MCP client (401 -> RFC 9728 discovery ->
  `/authorize` with PKCE and `resource=` -> `/token` -> `tools/call`):
  delegated login as a PUBLIC client (PKCE, no secret) yielding a
  resource-bound token accepted for a scoped tool; a wrong-audience token
  rejected with `401` at the transport (asserted at the HTTP layer); the
  conformant `403` insufficient-scope challenge; the application-level
  per-tool refusal; a refresh token that cannot be widened in scope on refresh
  (RFC 6749 §6); a client_credentials workload; a token revoked at nanoidp
  still accepted by the JWKS-only server until `exp` (the documented
  consequence of self-contained tokens); and a pre-rotation token still
  verifying after a key rotation, with the test asserting nanoidp retains the
  previous key's `kid` in its published JWKS. Adds the `mcp-public-client`
  (`token_endpoint_auth_method: none`) to the example config. New guide
  "Testing an MCP client against nanoidp". This is the deliverable that ties
  #186 (scopes), #187 (resource indicators) and #188 (public clients)
  together into a demonstrable OAuth/MCP round trip.
- **RFC 9207: `iss` on the authorization response** (#189). `/authorize`
  returns `iss=<effective issuer>` on every response delivered through a
  validated `redirect_uri` - success and error alike - so a client can
  detect an authorization-server mix-up (MCP 2026-07-28 recommends this).
  The value is the per-request effective issuer, so it stays correct under
  `issuer_from_request` (#126). `iss` is delivered exactly when discovery
  advertises `authorization_response_iss_parameter_supported`: one
  condition drives both, so metadata and behaviour never disagree. RFC
  9207 requires an `https` issuer with a host and no query or fragment, so
  the default `http://localhost:8000` sends no `iss` and advertises
  `false`; point the issuer at `https` (directly or reflected via
  `issuer_from_request` behind a TLS proxy) to turn RFC 9207 on. **Related
  behaviour change**: authorization errors that occur after the
  `redirect_uri` is validated (invalid_scope, PKCE errors, invalid_target)
  are now OAuth error redirects to the client (`error`,
  `error_description`, `state`, `iss`) instead of a local JSON 400, per
  RFC 6749 §4.1.2.1 - completing the RFC 9207 "error responses too"
  requirement. `unsupported_response_type` (a non-`code` `response_type`)
  is validated after the `redirect_uri` too, so it redirects as well.
  Errors before the `redirect_uri` is trusted (unknown client, malformed
  or unregistered `redirect_uri`) stay local JSON. A `redirect_uri` that
  carries its own query keeps it: the response parameters are appended,
  never fold into an existing value. The device flow is unaffected.
- **RFC 8707 Resource Indicators: `resource` binds the access token
  audience** (#187). A client may send one or more `resource` parameters
  on `/authorize`, `/token` (every grant) and `/device_authorization`;
  the access token's `aud` is then those resources (a plain string for
  one, an array for several) instead of the global `oauth.audience`, so a
  token minted for one MCP server is rejected by another and a
  wrong-audience test can finally be written. A `resource` must be an
  absolute URI without a fragment or the request is `invalid_target`
  (RFC 8707 §2). New per-client `allowed_resources` gates which resources
  a client may target (empty = any valid resource, the dev default, same
  "empty = unrestricted" convention as `allowed_scopes`). The
  authorization code and refresh token remember the bound resources; a
  `/token` request may narrow them to a subset but never widen them.
  Narrowing the access token does not narrow the refresh token, which keeps
  the full original grant so a later refresh can still request any resource
  the authorization covered (RFC 8707 §2.2).
  Sending no `resource` leaves `aud` at `oauth.audience` - **no change
  for existing clients**. `/introspect` reports the token's `aud`, and
  now verifies a token's signature without pinning its audience (so a
  resource-bound token can be introspected and revoked); `/userinfo`
  still requires the OP audience. No `resource_indicators_supported`
  discovery metadata (RFC 8707 defines none). Full support across
  settings.yaml (`allowed_resources`), the UI client form and the MCP
  `create_client`/`update_client` tools.
- **Public clients: `token_endpoint_auth_method: "none"` with mandatory
  PKCE S256** (#188). A client that cannot keep a secret (CLI, desktop
  app, SPA, MCP client) can now be declared with
  `token_endpoint_auth_method: "none"`: `client_secret` becomes optional
  (ignored - and never a credential - if present), and `/token`
  identifies the client by `client_id` alone. The protections that stand
  in for client authentication are enforced regardless of profile:
  `/authorize` requires PKCE with `S256` (OAuth 2.1 §7.5.1),
  `client_credentials` is refused with `unauthorized_client`, and
  refresh tokens always rotate with reuse detection (OAuth 2.1
  §4.3.1/§6.1) whatever `refresh_token_rotation` says. `/revoke` accepts
  a public client's `client_id` with an ownership check (the token's
  `client_id` claim must match; otherwise still `200`, nothing revoked -
  RFC 7009 §2.1 and its privacy guidance). `/introspect` deliberately
  stays authenticated (RFC 7662) and its discovery list does not gain
  `none`; the token and revocation lists do. Full support across
  settings.yaml, the UI client form, and the MCP
  `create_client`/`update_client` tools (`client_secret` no longer
  required when the method is `none`). At `/token` the registered method
  is **enforced**, not just recorded (RFC 7591): a `client_secret_basic`
  client must present its secret over HTTP Basic and a
  `client_secret_post` client in the request body - the wrong channel is
  rejected with `invalid_client`. `client_secret_post` is now validated
  at `/token`, `/introspect`, `/revoke` and `/device_authorization`;
  discovery had advertised it forever while the body secret was silently
  ignored. (The registered method is enforced at all four endpoints -
  see Breaking Changes, #262.)
  Confidential clients now authenticate on **every** grant, including
  `authorization_code` (RFC 6749 §3.2.1): the code exchange no longer had
  a client-authentication exemption - a confidential client doing
  `authorization_code` + PKCE must now present its secret or be
  re-registered as `token_endpoint_auth_method: none`. And **access
  tokens carry a `client_id` claim** (RFC 9068 §2.2) binding them to the
  client they were issued to, as refresh tokens have since 2.2.0.

### Fixed
- **Rate limiting on `/token` is enforced for real** (#304): the limiter
  was constructed with no limits and no view was ever decorated, so
  `rate_limit_enabled: true` logged "Rate limiting: enabled (10/minute on
  /token)" while enforcing nothing - a "metadata never lies" violation.
  The configured `rate_limit_token_endpoint` now actually applies to
  `POST /token` (429 with a JSON body and `Retry-After`/`X-RateLimit-*`
  headers; every other endpoint stays unlimited), and the rate string is
  VALIDATED at the config boundary: flask-limiter silently ignores a
  malformed one and falls back to the (empty) defaults, so an unparsable
  `rate_limit_token_endpoint` now refuses to load instead of silently
  recreating the enabled-but-unenforced lie. No fallback value either. The two settings are
  also configurable from YAML at last (`server.rate_limit_enabled`,
  `server.rate_limit_token_endpoint`) - the fields existed on Settings
  but no document section carried them, so only the profile could flip
  them. **Behavior change for `stricter-dev`**: that profile has always
  forced `rate_limit_enabled: true`, so its instances now really throttle
  `/token` at the configured rate (default 10/minute) - the hardening the
  profile always claimed.
- **One resolver for SAML attributes; the query surface stops fabricating
  and mangling values** (#302). The SSO assertion and the attribute-query
  assertion resolved a user's attributes through two independent
  implementations that had drifted five ways; both now share
  `services/saml_attributes.py`, and the emission of the
  `AttributeStatement` is one helper. Three visible corrections, each
  finishing an existing rule: the query no longer invents
  `<user>@example.com` for a user without an email (#275 - an absent fact
  is an absent attribute); a custom LIST attribute reaches the XML as one
  `AttributeValue` per entry and a comma-bearing STRING is never split
  (#134 - the query used to `",".join` lists and re-split any string with
  a comma); an empty collection no longer emits an empty `Attribute`
  element. The differences that remain between the two surfaces
  (`source_acl` only on the query; no AuthnStatement/SubjectConfirmation/
  AudienceRestriction on the query assertion) are deliberate and now
  documented in a table in the SAML reference.
- **`RevocationStore` entries now expire** (#288): revoked jtis and rotation
  family markers lived in two sets that were never swept - every revocation
  and every refresh rotation on a long-lived instance was a permanent memory
  increment. Entries now carry an expiry and the store sweeps
  opportunistically on the mutating paths. A VERIFIED token's own `exp` is
  kept exactly - tokens minted via `/api/users/<u>/token` or MCP
  `generate_token` take arbitrary lifetimes, so no fixed cap is safe for
  them; a verified payload WITHOUT an `exp` claim (which `verify_jwt`
  accepts) gets indefinite retention, since a token that never expires can
  never have its revocation forgotten; callers holding only unverified
  claims (the `/logout` id_token_hint) pass nothing and get a bounded
  8-day default; and writes are monotonic, so re-revoking a jti can only
  extend its retention, never shorten it.
- **The UI users form no longer corrupts non-string attributes on edit**
  (#291): a list- or mapping-valued custom attribute (settable via YAML and
  MCP) rendered in the edit form as its Python repr, so an untouched edit
  round-trip silently replaced `{"teams": ["alpha", "beta"]}` with the
  string `"['alpha', 'beta']"`. Each row now carries an explicit
  `attr_encoding[]` (review round 1): `string` values stay verbatim even
  when they LOOK like JSON (so the string `'["a"]'` survives an edit as a
  string), `json` rows (container values rendered as JSON) parse back, and
  rows typed fresh in the browser use `auto` - the `[`/`{` heuristic, with
  malformed JSON degrading to the literal string.
  The duplicated attribute-row parser in the create and edit routes is now
  one shared helper, and the user-field parity test recognizes the widget
  explicitly instead of excluding the field.
- **MCP `update_user` can now update custom `attributes`** (#280): the field
  was accepted by `create_user` and returned by every read surface, but the
  `update_user` schema and handler silently lacked it - an agent could set
  attributes at creation and never change them again. The new mapping
  replaces the whole `attributes` object, like every other field there.
- **`get_crypto_service` honours `keys_dir` on every call** (#281): once the
  singleton existed the argument was silently ignored, so a config reload
  that changed `keys_dir` kept signing tokens and serving JWKS from the old
  directory. The service is now recreated when the requested directory
  differs; operator-provided external keys (`init_crypto_service`) stay
  authoritative and are never discarded over a `keys_dir` change.
- **The wizard and `init` write configuration atomically and validated**
  (#282): both used to write raw template text with `open()`, bypassing the
  temp-then-replace primitive every other config writer uses - a crash could
  leave a torn file, and a template error reached disk unvalidated. Both now
  validate through the document models before anything touches disk.

## [2.8.0] - 2026-08-29

### Fixed
- **`client_credentials` no longer returns a refresh token** (#239). RFC
  6749 §4.4.3: "A refresh token SHOULD NOT be included" - the client
  authenticates itself on every request, and the token handed out was a
  second, 7-day credential bound to the default user (or the synthetic
  service account) that the grant never authenticated, spendable at
  `grant_type=refresh_token` for user-context tokens. The response now
  has no `refresh_token` key at all; every other grant is unchanged. A
  client that refreshed a client-credentials token must request a new
  one with its credentials, which is what the RFC asks of it.
- **/saml/sso rejects a request with nowhere to send the assertion** (#227):
  an AuthnRequest without `AssertionConsumerServiceURL` against a config
  whose `saml.default_acs_url` is blank now gets a 400 naming both missing
  sources (with a failed `saml_request` audit entry), instead of rendering
  an auto-submit form posting to `action=""` - the IdP's own page.
- **`client_credentials` no longer 500s when `default_user` names a missing
  user** (#241): the synthetic `service-account` fallback was built with an
  empty password, which `User` rejects since #158 made `password` optional
  with `min_length=1`. The fallback now carries no password, as it never
  authenticates with one, and the grant answers with `sub=service-account`
  again.
- **The dashboard's Logout button logs the UI session out again** (#221).
  The UI logout route registered the same `/logout` rule as the OIDC
  end-session endpoint and always lost: clicking Logout landed on the
  end-session confirmation page and the UI logout audit event was never
  written. The UI logout now lives at `GET /ui/logout` (the button follows
  automatically via `url_for`), redirects back to the dashboard, and writes
  its `logout` audit event; `/logout` (alias `/end_session`) remains the
  OIDC endpoint, unchanged.
- **Regenerating a client secret no longer resets the client's branding**
  (#213 review): `/clients/<id>/regenerate-secret` rebuilt the client with
  only five fields, silently dropping `background_color`, `header_color`
  and `footer_color` and resetting `show_client_id`/`show_description` to
  their defaults - the same rebuild-by-hand shape that lost
  `additional_audiences` in #32. The route now copies the client and
  changes only the secret, so every field (present and future) is carried.

### Added
- **MCP callers can make `save_config` conflict-checked** (#229 phase 5,
  the MCP leg of the same loop the web UI's forms got in phase 4): the
  read tools return the revision of the file the runtime was loaded
  from (`list_users`/`get_user` carry `users_revision`;
  `list_clients`/`get_client`/`get_settings` carry `settings_revision`),
  and `save_config` accepts them back as `expected_users_revision` /
  `expected_settings_revision`, refusing the save with
  `{"success": false, "kind": "conflict"}` - nothing written - when
  another writer (the web UI, another agent, a second nanoidp process
  on the same directory) moved a file since. `reload_config` and a
  successful `save_config` return fresh revisions, so the retry loop is
  reload, reapply, save. The revision is deliberately the one the
  runtime was LOADED from, not the file's hash at ask time: on a
  runtime that is stale against the directory, a fresh disk hash would
  pass the precondition exactly when the lost update is real. Because
  `save_config` always writes both files, there are exactly two modes:
  omitting both revisions keeps the save unconditional (last write
  wins, same as before), and supplying either makes the whole save
  conflict-checked, with the omitted revision defaulting to the one
  this runtime was loaded from - a save guarded on one file can never
  silently overwrite the other from a stale snapshot.
- **Display-only `description` on users, shown in the persona login
  picker** (#244): a user in `users.yaml` can carry an optional
  `description` (max 200 characters, plain text) rendered next to the
  username on every interactive persona picker (`/login`, `/authorize`,
  `/saml/sso`, the device flow's `/device`), so a directory of test
  personas (`admin`, `reader`, `tenant-a-manager`, ...) is
  self-explanatory at the point of selection. It is a first-class field,
  not a custom attribute: never a claim, never a SAML attribute, never
  part of a token. Settable from the UI create/edit form and the MCP
  `create_user`/`create_persona_user`/`update_user` tools, and exposed
  by the read-only `/api/users` responses.
  `User` now validates on assignment as well (`validate_assignment=True`,
  the rule `OAuthClient` has followed since #37), and the MCP
  `update_user` tool applies every requested field to a scratch copy
  before replacing the live user, so one invalid field can no longer
  leave the user half-updated. Behaviour change for an existing file: a
  `description:` key already present under a user used to fold into that
  user's `attributes` and therefore shipped inside the token's
  `attributes` claim; it is now the display-only field and no longer
  appears in any token.
- **Per-client allowed scopes and `invalid_scope`** (#186). `oauth.scopes_supported`
  is the global scope vocabulary (default `openid`, `profile`, `email`,
  `offline_access`, also what discovery's `scopes_supported` now advertises
  instead of a hardcoded list); a client's new `allowed_scopes` is an
  optional subset of it. A requested scope outside the vocabulary is
  `invalid_scope` for every client - a small behavior change, since any
  scope string used to be accepted unchecked; a scope outside a client's own
  `allowed_scopes`, when set, is `invalid_scope` for that client
  specifically. Enforced at `/authorize`, every `/token` grant (including
  `client_credentials`, RFC 6749 §4.4, which previously dropped any
  requested scope entirely) and `/device_authorization`; an omitted `scope`
  defaults to the client's full allowed set, or today's default when
  unrestricted. Every `/token` rejection - including the pre-existing
  refresh-token scope-narrowing check - now returns the RFC 6749 §5.2 JSON
  error shape (`{"error": "invalid_scope", ...}`) instead of a bare 400.
  `oauth.scope_enforcement: false` is a dev-only escape hatch back to the
  pre-#186 behavior (any scope string accepted, unchecked); refused outside
  the `dev` profile. `allowed_scopes` is settable from the clients UI form
  and the MCP `create_client`/`update_client` tools, same as
  `additional_audiences`/`redirect_uris`.

### Changed
- **`ConfigManager.save()` writes `users.yaml` and `settings.yaml` as one
  coordinated, conflict-checked save** (#229): both files' preconditions (an optional
  content-hash revision per file, for a future caller that supplies one)
  are checked before either file is written, both are then written, both
  fire their own `on_config_saved` hook, and the running configuration is
  refreshed from disk exactly once before any `hooks.strict` failure is
  raised - matching the `write -> notify -> reload_local -> raise`
  contract the web UI's writer already had. Previously a hook failure on
  `users.yaml` under `hooks.strict` left `settings.yaml` unwritten even
  when nothing was actually wrong with it; now a hook failure on either
  file still raises, but by then both files are already saved and the
  runtime already reflects them - only the mirror push failed. This also
  closes a gap where MCP's `save_config` tool left the process holding
  its pre-save view of anything the save's read-modify-write cycle picked
  up from disk: it now sees the refreshed state too. The precondition
  revisions were unused when this entry was first written; MCP's
  `save_config` now supplies them (see Added).
  The runtime refresh can itself fail (an in-memory value that bypassed
  field validation, since `Settings` has no `validate_assignment`, can
  reach the file and then fail to parse back in) - `save()` now tells
  that apart from every other outcome: a new `ReloadAfterSaveError` means
  both files ARE written but the runtime could not adopt them, and it
  never replaces or hides a pending `hooks.strict` failure, which keeps
  priority. `save_config`'s MCP response carries a `kind` for all three
  failure shapes (`conflict`, the hook's own kind, or
  `reload_after_save`) so a caller can tell them apart without parsing
  the error text. The advisory cross-process lock now fails as a named
  `LockUnavailableError` - instead of a bare `OSError` or an indefinite
  hang - when the lock file's filesystem does not support advisory locks
  or a peer process holds it for more than 10 seconds.
- **The web UI's writer (`YamlWriter`) now uses the same write primitive
  as `ConfigManager.save()`** (#229): `save_user`, `delete_user`,
  `save_client`, `delete_client` and the rest of its write methods route
  through `compare_and_replace`, and each gained an optional
  `expected_revision` precondition. The practical effect: creating or
  deleting a user/client now checks "does this already exist / does
  this exist at all" against the same document it writes, under the
  same lock, instead of against a copy loaded before the write started.
  Previously, two near-simultaneous submissions creating the same new
  user or client could both pass their "already exists" check and the
  second would silently overwrite the first, with no error to either
  request; that lost update is now impossible - the second request
  correctly gets an "already exists" error instead.
- **Every web UI form that writes `users.yaml`/`settings.yaml` now
  carries the revision it was rendered with, and refuses a stale
  submission** (#229 phase 4): create/edit/delete user, create/edit
  client, regenerate client secret, settings, and authority prefixes
  all send a hidden `expected_revision` field and get a clear
  "changed since it was last read - please reload and try again" flash
  instead of silently overwriting someone else's concurrent change (an
  edit based on a page loaded before another admin deleted or changed
  the same user/client, for instance). The settings page's OAuth, SAML,
  identity-classes and login-mode fields are now applied as one write
  instead of four separate ones, so a conflict there is all-or-nothing,
  the same guarantee every other form already had - an earlier version
  of this ran four writes chained by revision, which meant a conflict
  partway through could leave the earlier sections already saved while
  the page reported that nothing had changed. A submission with no
  `expected_revision` at all (an old cached page, a script, the e2e
  test agent) keeps today's unconditional last-write-wins - nothing
  about this requires an existing caller to opt in.

### Security
- **Opt-in `management_secret` mutation gate** (#163): one shared secret that
  gates state-changing calls across all three management surfaces - the MCP
  server (via the existing `admin_secret` tool argument, which now reads from
  this setting instead of a standalone env var), `/api/*` (via a new
  `X-Management-Secret` request header on mutating calls), and the config web
  UI (a one-time "unlock" form at `/login` that then trusts the session for
  further mutating requests). Off by default - unset, nothing changes.
  Configurable via `settings.yaml`'s `session.management_secret` or the
  `NANOIDP_MANAGEMENT_SECRET` env var; the previous MCP-only
  `NANOIDP_MCP_ADMIN_SECRET` still works as an alias, though an explicit
  `management_secret: null`/`""` in `settings.yaml` now wins over either env
  var rather than falling through to it. Independent of `require_ui_login`:
  that gate is the UI's session front door (who can view the dashboard),
  this is the write guard (who can change anything) - either, both, or
  neither can be enabled; the unlock form stays reachable even when
  `require_ui_login` is also on. YAML-only, same treatment as
  `require_ui_login`/`secret_key`. Hardened since first landing: the UI
  unlock flag is now an HMAC of the secret itself (not a bare session
  boolean), so it can't be forged just by knowing `secret_key`'s public
  default; a non-ASCII or non-string secret compares safely instead of
  500ing; an unlocked UI session now also satisfies the `/api/*` gate, so
  the dashboard's own buttons (generate token, clear audit log) keep working
  after one unlock; and the MCP check now always reads the `ConfigManager`
  actually serving the request.

## [2.7.0] - 2026-08-25

### Changed
- **Configuration files load through document models** (#175, piece 2).
  `settings.yaml` and `users.yaml` are now parsed into Pydantic document
  models that mirror the YAML sections one to one
  (`nanoidp.config_documents`), and the domain `Settings` / `User` objects
  are built from them; the hand-written `.get(key, default)` mapping in
  `config.py` is gone and the defaults live on the models, which the writer
  reads as well. No file format change and no behavioural change for files
  that loaded before. One visible improvement: an unknown key (a typo such
  as `oauth.isuer`, or a key nanoidp does not know) is now logged as a
  warning with its dotted path and ignored, instead of vanishing silently;
  keys that shipped presets carry but the loader never consumed
  (`cors_allowed_origins`, `device_flow`, `logging.format`,
  `oauth.refresh_token_expiry_minutes`, `session.permanent`) are declared so
  they do not warn. Fields inside a user entry keep folding into
  `attributes`, as always. Stricter handling is a later piece.

### Config schema
- `config_version` 1 introduced (#175, piece 1). No changes required to
  existing files: a file without the key is version 1. The version is the
  contract of the config directory as a whole: both files declare the same
  number, each is checked independently, and it must be a literal integer
  (checked before `${VAR}` expansion).

### Added
- **Generated config schema, `validate-config` and strict validation** (#175,
  pieces 3 and 4). Three additions to the config contract, none of which
  restates it a seventh time:
  - `nanoidp config-schema` prints the JSON Schema of `settings.yaml`,
    `users.yaml` and `bootstrap.yaml`, generated from the document models
    (`--file` for one of them, `--write` to regenerate the committed
    artifact from a source checkout). The artifact is
    `docs/schema/config.v1.json`: one standalone schema per file under the
    keys `settings`, `users` and `bootstrap`, next to the `config_version`
    they describe, ready to point an editor's YAML-schema support at. A test
    fails when the committed file no longer matches the models, and parity
    tests fail when the MCP `update_settings` tool or the web UI's settings
    form grows a knob that is not a key of the contract - or offers one of
    the YAML-only fields (`secret_key`, `require_ui_login`, `hooks`,
    `plugins`).
  - `config_validation: warn|strict` (top level of `settings.yaml`, default
    `warn`) and the server flag `--strict-config` decide what an unknown key
    does: log its path and keep loading, or refuse to start and refuse every
    later reload with the same message. The flag wins over the file for that
    run only and is never written back, like `--profile` (#172). One
    contract per directory: `users.yaml` and `bootstrap.yaml` follow what
    `settings.yaml` declares. Wrong types stay errors in both modes.
  - `nanoidp validate-config [--config DIR] [--strict]` lints a
    configuration directory without starting anything: one line per finding,
    exit 0 when clean or with warnings only, exit 1 on errors and on
    warnings under `--strict`. It reads the three files through the same
    loaders the server uses and nothing else - no `ConfigManager`, no hook
    dispatched, no plugin imported, `bootstrap.yaml` checked for its shape
    only - so it is safe as a pre-commit or CI step on a directory whose
    hooks name commands. MCP agents get the same check as the read-only
    `validate_config` tool (`{valid, findings}`), which brings the MCP
    surface to 26 tools.
- **Hooks and plugins v1** (#185): extension points for external
  configuration stores, not backends. Three synchronous hooks with
  `HOOK_API_VERSION = 1`: `on_before_load(config_dir)` before the files are
  read (startup and every reload), `on_config_saved(path, kind)` after an
  atomic write of `settings.yaml` or `users.yaml`, `on_audit_event(event)`
  after an audit entry. Implement them as shell commands under `hooks:` in
  `settings.yaml` (placeholders `{config_dir}`, `{path}`, `{kind}`,
  `{event_type}`, audit event JSON on stdin) or as Python plugins packaged
  separately and discovered through the `nanoidp.plugins` entry-point group,
  configured under `plugins.<name>:`. Per-hook error policy: `on_before_load`
  may block under `hooks.strict`, `on_config_saved` is propagated to the
  caller under `strict` after the write (the local save is always
  committed and the running configuration reloaded from it, so only the
  mirror is behind), `on_audit_event` never propagates. Commands are never
  reported by `/api/config` or MCP (they may embed expanded secrets) and a
  propagated error names the hook and its source only; the bootstrap
  surface is the baseline for `strict`/`timeout_seconds`, `settings.yaml`
  overrides only what it declares. Bootstrap surface for hooks
  that must run before `settings.yaml` exists: `NANOIDP_BOOTSTRAP_HOOK` /
  `--bootstrap-hook`, `NANOIDP_BOOTSTRAP_PLUGIN` with
  `NANOIDP_PLUGIN_<NAME>_<KEY>` settings, and `bootstrap.yaml` in the config
  directory (`hooks:` and `plugins:` only). `nanoidp plugins`, `GET
  /api/config` and the MCP `get_settings` tool report what is loaded, from
  which surface, with failure counters and the plugins that could not be
  loaded (`plugins_failed`: a missing package or a wrong `hook_api_version`
  is reported, never fatal unless `strict`); `hooks:`/`plugins:` are
  YAML-only. `bootstrap.yaml` goes through the same loader as
  `settings.yaml` (placeholders, unknown-key warnings). A strict
  `on_before_load` failure is a JSON `503` on `POST /api/config/reload` and
  an error result from the MCP `reload_config` tool. Audit logging never
  constructs the configuration and an audit event produced inside a load is
  not dispatched to hooks. An unchanged `hooks:`/`plugins:` declaration is
  not re-applied on the refresh that follows a local write, so plugins are
  not re-instantiated on every save. Reference plugin
  `examples/plugins/nanoidp-echo`; guide "Extending nanoidp: hooks and
  plugins".
- **Import contracts enforced in CI** (#149): `import-linter` now pins the
  package layering (`routes -> services -> config`) and the invariant that
  `serialization.py` has no runtime imports from the package (it is what
  lets `config.py` import it without a cycle). Both used to live only in
  comments; `lint-imports` runs next to ruff and mypy in the Tests workflow
  and fails when a change adds a forbidden import.
- **`config_version` field** (#175, piece 1): `settings.yaml` and
  `users.yaml` accept a top-level integer `config_version: 1`. Absent means
  1, so existing files load unchanged; a value that is not a positive
  integer, or newer than the running release supports, is refused at
  startup with a message naming the file, the value and the supported
  version. `nanoidp init` and the wizard write it into the files they
  create; UI/MCP saves preserve an existing key and never add one. `GET
  /api/config` and the MCP `get_settings` tool expose the effective value;
  the e2e agent asserts it. Bumps only on renames, removals or semantic
  changes (with a loader migration), never on optional additions.
- **Native-app redirect URIs** (#81, RFC 8252): `/authorize` accepts
  private-use scheme redirect URIs such as `com.example.app:/oauth2redirect`
  (§7.1: a scheme and a path, no authority) as absolute URIs and applies
  §7.1's minimum rule to them (a non-`http(s)` scheme without a period,
  such as `myapp://`, is rejected with a message naming the rule; domain
  ownership is not verified), and a
  registered loopback URI (`http://127.0.0.1:{port}/...`,
  `http://[::1]:{port}/...`) matches any port (§7.3), since native apps
  bind an ephemeral port. Everything else keeps exact string matching (RFC
  6749 §3.1.2.3): scheme, host, path and query of a loopback URI, every
  port of a non-loopback or `localhost` registration. Fragments are now
  rejected explicitly (§3.1.2). One shared matcher,
  `services/redirect_uri.py`, serves both legs of `/authorize`; MCP tool
  descriptions and `examples/test_agent.py` updated.
- **Persona login mode** (#156): opt-in `login.mode: persona` lists the
  configured users on every interactive login surface (`/login`,
  `/authorize`, `/saml/sso` and the device flow's verification page) and
  signs in by selecting one, with no password prompt - a local
  development/testing convenience, off by default. `User.password` is now
  optional: a password-less user can only authenticate via persona-mode
  interactive login, never via password-mode login or the OAuth password
  grant. Persona-authenticated sessions emit SAML
  `AuthnContextClassRef: unspecified` instead of falsely claiming
  `PasswordProtectedTransport`. New MCP tool `create_persona_user`, a
  `persona-login` example preset, settings-UI persistence and e2e coverage.
- **Per-client login page branding**: optional per-client colors (background,
  header, footer, all as validated hex values), show/hide client_id and
  description on the `/authorize` login page, and per-client logo images
  stored locally in `static/logos/` keyed by client ID (no YAML config needed
  for logos; place the image file and it's served automatically; the
  directory is overridable via `oauth.logos_dir`). Colours and toggles are
  editable from the OAuth client form in the UI and from the MCP
  `create_client`/`update_client`/`get_client` tools, descriptions are
  already supported, and logos are deployed by the operator to the server
  filesystem. Designed for demos and prototyping; colours are structured
  (not free-form CSS) to prevent stored-XSS on the auth UI, and logos are
  local files only (no remote URLs) to avoid beacons.

### Fixed
- **The unit suite no longer rewrites the repo's `config/` files.** Tests
  that build an app without an explicit config directory used to load the
  committed preset through ConfigManager's `./config` fallback, and any save
  that followed rewrote `config/settings.yaml` or `users.yaml` in the
  checkout - twice committed by accident during review. `tests/conftest.py`
  now points `NANOIDP_CONFIG_DIR` at a fresh copy of `config/` for every
  test and resets the `yaml_writer` singleton alongside the others.
- **`--profile` overrides settings.yaml for every value and survives reloads**
  (#172). An explicit `--profile dev` could not bring a file configured with
  `oauth21`/`stricter-dev` back to `dev` (the flag defaulted to `dev`, so the
  code could not tell "asked for dev" from "omitted"), and any CLI profile was
  dropped by the first configuration reload, i.e. by the first web UI or MCP
  save. Worse, the `stricter-dev` runtime hardening (`require_pkce`,
  `password_hashing`, `rate_limit_enabled`, debug off) was applied once in
  `create_app()` and silently lost on that same first reload, even when the
  profile came from `settings.yaml` itself. The override now lives on
  `ConfigManager` (`--profile` defaults to none, `init_config(...,
  profile_override=)`), the effective profile and its hardening are re-derived
  after every settings load, and a save serializes the DECLARED state
  (`ConfigManager.persistable_settings()`), so neither the override nor
  the hardening it implies is ever written into the operator's file. `GET /api/config` and the MCP `get_settings` tool expose `security_profile`,
  `profile_override` and the derived `effective` values; the e2e agent checks
  they are stable across a reload.
- **`users.yaml` now expands `${VAR}` / `${VAR:default}` placeholders** like
  `settings.yaml` always did (#175 review). A `password: ${ALICE_PASSWORD}`
  used to be taken literally, so the documented "secrets kept out of the
  file" use case only worked for settings. A UI/MCP save of one user still
  rewrites only that user's entry; the MCP `save_config` tool rewrites the
  whole map and materializes expanded placeholders, as documented.
- **SAML `entity_id`/`sso_url` follow the effective issuer** (#181). With
  `oauth.issuer_from_request` on (or behind a proxy), OIDC discovery reflected
  the request host while `/saml/metadata`, the `<Issuer>` in responses and
  assertions and the SSO location kept the fixed `http://localhost:8000/...`
  strings. Both settings are now optional: absent (or blank in the UI/MCP)
  means derived as `<effective issuer>/saml` and `<effective issuer>/saml/sso`
  through one helper shared by every SAML surface, an explicit value still
  wins, and a derived value is never written back to `settings.yaml`. SAML 2.0
  Metadata 2.3.2 requires `entityID` to be the value used as `<Issuer>` (Core
  2.2.5). `/api/config` and the MCP `get_settings` tool report the effective
  values plus `entity_id_derived`/`sso_url_derived`; `update_settings` gains
  `saml_entity_id`/`saml_sso_url` (empty string clears); the e2e agent checks
  metadata against discovery and no longer posts derived values back as
  explicit ones.
- **Example presets now bind to `127.0.0.1`** (#164). All four pre-2.6.0
  presets (`cli-device-flow`, `microservices-client-credentials`,
  `react-spa-pkce`, `spring-boot-saml`) still shipped an explicit
  `host: "0.0.0.0"`, overriding the loopback default introduced with
  GHSA-2473-px8h-rvg6 for anyone who copied them. Each now ships loopback
  with a commented `# host: "0.0.0.0"` opt-in line, matching the
  `persona-login` preset and the reverse-proxy guide's framing.
- **`/api/config` now exposes `saml.default_acs_url`** (#165). The e2e agent
  rebuilds the settings form from that document, so the missing field was
  posted back blank on every run and the "present-but-blank = clear"
  contract (#131) silently wiped `default_acs_url` from `settings.yaml`.

### Security
- **Opt-in login gate for the config web UI**: new `session.require_ui_login`
  setting (off by default) makes `/login` actually enforce a logged-in
  session on the dashboard, users, clients, settings, keys, claims, audit log
  and token tester pages - previously `/login`/`/logout` existed but nothing
  gated on them, so the login page implied protection it didn't provide.
  Does not affect the separate `/api/*` management API, which remains
  unauthenticated by design regardless. YAML-only for now, following the
  `secret_key`/`security_profile` precedent. Related to the network-binding
  hardening in GHSA-2473-px8h-rvg6.
- **Opt-in removal of the invalid-bcrypt-hash plaintext fallback**: new
  `session.enforce_password_check` setting (off by default). When
  `password_hashing` is on, a `users.yaml` password that isn't a valid
  bcrypt hash previously fell back to plaintext comparison with only a
  warning logged - this setting removes that fallback, rejecting the login
  outright instead. Default behavior (the fallback) is unchanged; opt-in
  only. YAML-only, same treatment as `require_ui_login`.

## [2.6.0] - 2026-08-21

### Documentation
- **New guide: [Running behind a TLS-terminating reverse proxy](book/src/guides/reverse-proxy.md)**,
  walking through composing `oauth.issuer`, `issuer_from_request`,
  `issuer_from_proxy_headers`, `issuer_allowlist`, `device_verification_base_url`
  and `POST /api/config/reload` for a proxied/containerized deployment, with
  the security caveats inline.

### Added
- **First-class group support**: users gain a `groups` list alongside `roles`,
  modelled exactly the same way. It is loaded from and persisted to
  `users.yaml` (omitted when empty), emitted as a `groups` claim on the access
  token and from `/userinfo`, requestable in the ID Token via the OIDC `claims`
  parameter, advertised in `claims_supported`, and flattened into `authorities`
  using the new `groups` authority prefix (default `GROUP_`, editable on the
  Claims page). Groups are editable from the user form, shown on the users list
  and user detail pages, exposed by `/api/users`, and settable through the MCP
  `create_user` / `update_user` tools. Users without groups behave exactly as
  before: no claim, no authorities, nothing written to YAML.
- **Optional SAML export of roles and groups**: new `saml.export_roles` /
  `saml.export_groups` toggles (both off by default, so the previous behaviour
  is preserved) with companion `saml.roles_attr_name` / `saml.groups_attr_name`
  settings defaulting to `roles` and `groups`. Roles and groups are not
  standard SAML attributes and every SP expects a different name, so the name
  is configurable; blanking it restores the default. Both toggles are on the
  Settings page and the MCP `update_settings` tool, and apply to both the SSO
  assertion and the AttributeQuery endpoint, with one `AttributeValue` per
  entry.
- **`oauth.issuer_from_request`** (off by default): when enabled, the
  discovery document's `issuer`, every minted token's `iss`, and the device
  flow's `verification_uri` are derived from the incoming request's own Host
  header instead of the fixed `oauth.issuer`. Lets the same NanoIDP be
  reachable under more than one hostname (e.g. a Docker Compose service name
  from other containers and `localhost` from the host browser) without a
  discovery/token issuer mismatch - each hostname advertises and issues
  tokens against itself. The MCP `get_oidc_discovery`/`get_settings` tools
  have no request of their own and always report the fixed `issuer`.
- **`oauth.issuer_allowlist`**: restricts `issuer_from_request` to a list of
  allowed origins (e.g. `["http://localhost:8000", "http://nanoidp:9900"]`).
  Empty (default) allows any Host header, unchanged from before; when set, a
  request whose Host doesn't match falls back to the fixed `oauth.issuer`
  instead of trusting an arbitrary Host header. Settable from the Settings
  page and the MCP `update_settings` tool.
- **`oauth.device_verification_base_url`**: pins the device flow's
  `verification_uri` to a fixed, human-reachable URL (e.g.
  `https://idp.example.com`), overriding `issuer_from_request`'s derivation
  for that field only - discovery's `issuer` and a token's `iss` are
  unaffected. Fixes a backend/container caller of `/device_authorization`
  (e.g. `Host: nanoidp:9900`) otherwise leaking its own Host into a URL the
  end user's browser can't open. Unset by default. Settable from the
  Settings page and the MCP `update_settings` tool.
- **`oauth.issuer_from_proxy_headers`** (off by default): trusts
  `X-Forwarded-Proto`/`X-Forwarded-Host`/`X-Forwarded-For` from a single
  reverse-proxy hop (via werkzeug's `ProxyFix`), so `issuer_from_request` and
  rate-limit and audit-log client IPs see the original scheme/host/client
  instead of the
  proxy's own connection when TLS is terminated upstream. Only changes the
  derived issuer/`iss`/`verification_uri` when `issuer_from_request` is also
  on; the rate-limit effect applies regardless. Only enable this when
  NanoIDP is deployed directly behind exactly one trusted proxy - these
  headers are otherwise spoofable by any client. Readable/settable via the
  Settings page and the MCP `get_settings`/`update_settings` tools; since
  `ProxyFix` is wired at app startup, a value changed at runtime only takes
  effect after a restart.

### Changed
- **Raised the `PyJWT` floor to `>=2.13.0`** (was `>=2.8.0`). `/userinfo` and
  `/introspect` pass a client-supplied token to `jwt.decode()`, and 2.8.0-2.12.1
  are affected by CVE-2026-48525 (unbounded Base64URL decoding of a `b64=false`
  detached JWS payload, a DoS vector).
- **Added a CI license gate** (#148): the build fails if a dependency in the
  redistributed closure carries a GPL/LGPL/AGPL/SSPL/EUPL license, which the
  project's dependency-license policy blocks from redistribution without
  explicit review.
- **Lowered the `cryptography` floor from `>=46.0.3` to `>=45.0.0`** (#140). The
  previous floor came from a generic dependency bump, not a real requirement:
  our own API usage needs nothing newer than ~3.1. The effective minimum is set
  by `signxml`, which imports `x509.verification.ExtensionPolicy` (added in
  cryptography 45.0.0) at load time. This unblocks installs on environments
  pinned to a `cryptography` between 45 and 46.
- **Consolidated the OAuth client YAML merge logic** into a single
  `serialization.merge_client_entry()` helper, shared by the settings save
  path (`merge_oauth_clients()`) and `YamlWriter.save_client()`'s web UI
  edit path, which previously duplicated the same field-by-field merge
  rules. Internal cleanup, no behavior change.
- **Migrated the MCP server to the mcp 2.0 SDK** and pinned `mcp>=2,<3`. mcp 2.0
  replaced the lowlevel `Server` decorators (`@server.list_tools()` /
  `@server.call_tool()`) with `on_*` constructor parameters, so a fresh install
  resolving to 2.0 could not import `nanoidp.mcp_server` at all. Handlers now
  take `(ctx, params)` and return `ListToolsResult` / `CallToolResult` instead
  of relying on the SDK's removed return-value wrapping. The tool set, tool
  schemas, readonly mode, and the admin-secret gate are unchanged, and the
  stdio transport and `nanoidp-mcp` entry point are untouched.
- **Rejected and failed MCP tool calls now set `is_error: true`.** mcp 2.0 no
  longer converts a handler exception into an error-flagged result, so nanoidp
  builds it explicitly for every case that previously came back as a
  successful result whose JSON body happened to carry an `error` key:
  readonly-mode and admin-secret rejections, an unknown tool name, arguments
  that fail schema validation (see below), and tool-level failures such as
  "user not found" or "client already exists". The response body is
  unchanged.
- **Tool arguments are now validated against each tool's schema before
  dispatch.** mcp 1.x's `@server.call_tool(validate_input=True)` did this
  automatically; mcp 2.0's `on_call_tool` does not, so nanoidp now runs the
  same check itself and returns an `is_error: true` result (`code:
  "MCP_INVALID_ARGUMENTS"`) instead of letting a missing required field reach
  the tool implementation as a bare `KeyError`.
- **Consolidated the MCP `isError` contract** (#120): the rule is now written
  once as a table in the `mcp_server` module docstring (a negative query answer
  is not a failure) and the code follows it. `verify_token` on an invalid token
  returns `{"valid": false, "reason": ...}` (was `error`) so a rejected token,
  the tool's designed answer, is no longer flagged `is_error`. A domain-failure
  audit entry now records the failure reason instead of only the tool name; the
  uncaught-exception path now carries a `code` (`MCP_INTERNAL_ERROR`) and `tool`
  like the guard rejections; and `_execute_tool`'s unreachable unknown-tool
  fallback now raises rather than returning a divergent shape. The MCP audit
  `details` codes are namespaced (`MCP_READONLY_MODE`,
  `MCP_ADMIN_SECRET_REQUIRED`, `MCP_UNKNOWN_TOOL`, `MCP_INVALID_ARGUMENTS`),
  observable via `get_audit_log` and `/api/audit`.
- **Precompiled MCP tool-argument validators** (#121): each tool's JSON Schema
  is compiled once at import (`Draft202012Validator`) instead of being
  recompiled on every `tools/call`, which also surfaces a malformed schema at
  import time. The direct `jsonschema` floor is raised to `>=4.20.0` to match
  what mcp 2.0 already resolves.
- **MCP tests drive the real protocol** (#122): the test harness now calls
  tools through the mcp 2.0 in-memory client (real SDK dispatch and result
  serialization) instead of invoking the lowlevel handlers with a fake request
  context, so wire-level regressions fail the suite instead of only breaking a
  real client.

### Fixed
- **Duplicate OAuth `client_id`s are rejected at load** (#127). Two clients
  that resolve to the same effective id (including two `${VAR}` placeholders
  expanding to the same value) made client lookup ambiguous and caused the
  save-merge to match the wrong raw entry, materializing a secret; the loader
  now fails fast with a clear error instead.
- **Import no longer crashes when package metadata is absent** (#139). Running
  from an uninstalled source tree (vendored, or copied into an image without
  `pip install`) raised `PackageNotFoundError`; the version now falls back to
  reading `pyproject.toml`, then to a static string.
- **Default admin user's `identity_class` is `INTERNAL`, not `INTERN`**. The
  no-`users.yaml` fallback used a typo'd class that didn't match the generated
  template or the default allowed classes.
- **Env-backed `client_id` placeholders are preserved on save** (#127). When a
  client's `client_id` was itself a placeholder (`client_id: ${CLIENT_ID:app1}`),
  the settings save matched the raw entry against the expanded id, missed it,
  and rewrote the client from expanded values - losing the placeholders and
  materializing the client secret; the web UI path appended a duplicate entry,
  and `delete_client` could not find the client at all. Client matching now
  expands the placeholder before comparing (`client_id_matches()`), used by the
  settings save, `save_client()` and `delete_client()`.
- **Saving settings no longer discards comments, inline `#` text or `${VAR:default}`
  placeholders in `settings.yaml`** (#127): the settings writer now round-trips
  the file with `ruamel.yaml` (comments and quote style survive) and only
  rewrites a field when its expanded on-disk value actually differs from the
  new one, so an untouched `${PORT:8000}`-style placeholder is no longer
  replaced by its resolved value on the next save. Free-form text
  (`description`, `client_secret`, `password`, attribute values) is now quoted
  on write so an embedded `#` can't be mistaken for a comment. Applies to both
  the web UI settings form and the MCP `save_config` tool.
- **Env-backed client secrets and empty optional placeholders are preserved when
  unrelated settings change.** The OAuth client merge now updates entries by
  `client_id` field-by-field instead of rewriting the whole list, so an
  unchanged `${APP1_SECRET:dev}` secret stays in the raw file even when a
  sibling client is edited. Empty optional values such as
  `${DEVICE_URL:}` are also treated as unchanged when they still expand to an
  empty string, instead of being popped out of the YAML on a save that changed
  some other field.
- **`/api/config` now exposes `issuer_allowlist`, `device_verification_base_url`
  and `issuer_from_proxy_headers`** alongside `issuer_from_request`. The
  config-agnostic e2e agent reads the allowlist from `/api/config` to predict
  the effective issuer; without the exposure it assumed an empty allowlist and
  failed on any server with one configured. The agent also takes its
  fixed-issuer baseline from `/api/config`'s `oauth.issuer` now: a plain
  discovery response reflects the request's own Host when the flag is on, so
  it is only a valid baseline when the flag is off.
- **`examples/test_agent.py` SAML export check honours the configured attribute
  names**: it now reads `saml.roles_attr_name` / `saml.groups_attr_name` from
  `/api/config` instead of assuming the default `roles` / `groups` names, so it
  no longer fails on servers exporting under custom names.
- **SAML export: colliding attribute names merge instead of overwriting, and
  values are passed as lists** (#134). With both exports enabled and
  `saml_roles_attr_name` equal to `saml_groups_attr_name` (e.g. both
  `memberOf`), the groups list silently replaced the roles list; the two are
  now merged into the single shared attribute, roles first, deduplicated. The
  AttributeQuery path also passes roles/groups (and entitlements) to the
  response builder as lists instead of comma-joined strings, so a legitimate
  comma-bearing value like `"Finance, EMEA"` stays one `AttributeValue`, as it
  already did in the SSO assertion.
- **`/api/users/<username>/token` now honours `issuer_from_request`** (#133):
  the endpoint mints real JWTs but kept using the fixed `settings.issuer`,
  so with the flag on its tokens carried an `iss` that failed validation
  against the discovery document the same hostname had just advertised. The
  effective-issuer resolution (including the allowlist fallback) now lives in
  a shared routes helper used by discovery, `/token`, the device flow and the
  API token endpoint alike; the MCP tools remain the documented exception.
  Also clarified in the setting descriptions that `issuer_from_proxy_headers`
  affects the audit log's recorded client IP as well as the rate limiter's.
- **`POST /settings` no longer resets settings that were not on the submitted
  form** (#131). Previously every checkbox absent from the form was stored as
  `false` and every absent text field was cleared, so any partial form (a
  stale tab, a script, the e2e agent's c14n round-trip) silently wiped
  unrelated configuration - observed live as `issuer_from_request`,
  `issuer_from_proxy_headers` and the SAML export toggles flipping off and the
  allowlist, device verification URL and attribute names being deleted
  mid-test-run. The handler now follows an "absent = unchanged" contract: text
  fields and textareas are only applied when present (present-but-blank still
  clears), and each checkbox is paired with a hidden `__on_form` marker so
  "rendered but unchecked" (persist `false`) is distinguishable from "not on
  this form" (leave unchanged).

### Security
- **Default server bind address is now `127.0.0.1` (loopback) instead of
  `0.0.0.0`** (GHSA-2473-px8h-rvg6, CWE-306). The unauthenticated `/api/*`
  management API (which can mint admin tokens, rotate signing keys and clear
  the audit log) is a deliberate dev-tool convenience, but the previous
  all-interfaces default exposed it to any network-reachable host without the
  operator choosing to. The out-of-the-box experience is unchanged for local
  development (clients still reach `localhost:8000`). To expose NanoIDP on a
  network, set `server.host` (or `--host 0.0.0.0`) explicitly; a startup
  warning is logged whenever the bind address covers all interfaces. This
  aligns `nanoidp init` with the value `nanoidp wizard` already wrote, and the
  bundled Docker image is unaffected (its entrypoint already passes
  `--host 0.0.0.0`).

## [2.5.0] - 2026-07-19

### Added
- **`claims` parameter requests persist across token refresh** (#112, OIDC
  Core §12.2): the claim names requested via the OIDC `claims` parameter are
  now persisted in the refresh token (`req_id_token_claims` /
  `req_userinfo_claims`, alongside `scope` and `auth_time`), so a refreshed ID
  Token keeps the requested claims and `/userinfo` keeps honouring the
  `userinfo` member for the refreshed access token. Refresh tokens minted
  before this change carry neither claim and refresh as before. Both names are
  reserved: they cannot be requested via the `claims` parameter nor injected
  through the `/token` `extra` parameter. Requested-claims values are
  sanitized at the token service (`sanitize_claim_names`): a hand-crafted
  refresh or access token carrying a non-list value (or non-string entries)
  refreshes and serves `/userinfo` cleanly instead of failing token issuance
  after the refresh token was consumed. A claims request deliberately
  survives scope narrowing on refresh (OIDC Core §5.5 is orthogonal to
  scope); see the token reference docs.
- **MCP `generate_token` gains `userinfo_claims`** (#113): parity with the
  HTTP `claims` flow's `userinfo` member; the names are stamped on the access
  token as `req_userinfo_claims` and honoured by `/userinfo`. Both
  `id_token_claims` and `userinfo_claims` are now validated like
  `additional_audiences`: a non-list value is rejected with a clean error
  instead of being minted into the token.

### Changed
- **`/userinfo` reuses `resolve_user_claim` for its default claim assembly**
  (#113): the scope-gated standard claims and the nanoidp-specific claims now
  come from the same resolver that backs the `claims` request parameter, so
  the two mappings cannot diverge. No behavior change.

### Fixed
- **`claims` parameter could overwrite registered ID Token claims** (#110): a
  requested claim name that collided with a user attribute (e.g. an attribute
  named `aud` or `exp`) could hijack the corresponding registered claim, because
  `create_jwt` applies `extra` after setting the registered claims and the
  `setdefault` guard only covered the protocol claims. `resolve_user_claim` now
  refuses reserved registered/protocol names outright (`iss`, `sub`, `aud`,
  `exp`, `iat`, `nbf`, `jti`, `token_use`, `auth_time`, `at_hash`, `azp`,
  `nonce`, `scope`, `req_userinfo_claims`), protecting both the ID Token and
  `/userinfo` paths at a single choke point.

## [2.4.0] - 2026-07-08

### Added
- **`scope` claim on access tokens** (#102): access tokens now advertise the
  granted scope (RFC 9068 §2.2.3), letting resource endpoints reason about it.
  Set authoritatively in `TokenService.create_token`, so a caller-supplied
  `extra_claims` cannot override it.
- **OIDC `claims` request parameter** (#104, OIDC Core §5.5): `/authorize`
  accepts a `claims` parameter to request specific claims in the ID Token
  (`id_token` member) or from UserInfo (`userinfo` member), e.g.
  `claims={"id_token":{"email":null}}`. Requested claims are resolved from the
  user and added when available (voluntary form, §5.5.1); protocol claims are
  never overwritten and unresolvable names are skipped. Malformed input is
  ignored with a warning rather than failing the flow. Discovery advertises
  `claims_parameter_supported: true`, and the MCP `generate_token` tool gains an
  `id_token_claims` argument. Scoped to the authorization code grant; the
  requested claims are not yet persisted across a refresh.
  `TokenService.create_token` now strips `scope`/`req_userinfo_claims` from a
  caller-supplied `extra` before setting them authoritatively, so the `/token`
  `extra` parameter can never smuggle scope-gated claims past `/userinfo`
  (closes a spoofing gap in the #102 scope handling too).

### Changed
- **`/userinfo` gates `email`/`profile` claims by granted scope** (#102, OIDC
  Core §5.4): `email`/`email_verified` require the `email` scope and
  `preferred_username` requires the `profile` scope. Enforced only under the
  `stricter-dev` and `oauth21` profiles; the default `dev` profile keeps
  returning them unconditionally, so this is not a breaking change for existing
  setups. nanoidp-specific claims (`roles`, `tenant`, `identity_class`,
  `attributes`) have no standard scope and are always returned.

## [2.3.0] - 2026-07-08

### Added
- **`oauth21` security profile** (#68): opt-in draft-OAuth-2.1 protocol
  strictness alongside `dev` and `stricter-dev`: PKCE required on the
  authorization code flow with S256 only (draft-ietf-oauth-v2-1 §4.1.1,
  §7.5.2), refresh token rotation forced on (§4.3.1), the password grant
  removed (RFC 6749 §5.2) and absent from discovery, and registered
  redirect URIs mandatory at `/authorize`. Protocol behavior lives in
  derived `Settings` properties consumed by both the routes and the shared
  discovery builder, so the profile means the same thing from `--profile`
  or `settings.yaml` and discovery can never advertise what the endpoints
  refuse. Deliberately orthogonal to `stricter-dev` (runtime hardening).
- **Registered redirect URIs with exact matching** (#67): clients gain an
  optional `redirect_uris` list; when non-empty, `/authorize` compares the
  requested `redirect_uri` with simple string comparison (RFC 6749
  §3.1.2.3, OAuth 2.1 §4.1.1) and answers a mismatch with
  `400 invalid_request` directly, never by redirecting to the unvalidated
  URI (§3.1.2.4). Exposed in the web UI, MCP client tools and YAML.
- **Signed AuthnRequest verification** (#69): with
  `saml.want_authn_requests_signed: true` and PEM certificates in
  `saml.sp_certificates`, nanoidp requires and verifies AuthnRequest
  signatures under both bindings: the HTTP-Redirect query-string
  signature over the raw transmitted fragment (SAML 2.0 Bindings
  §3.4.4.1; rsa-sha256/rsa-sha512/legacy rsa-sha1) and the HTTP-POST
  enveloped `ds:Signature` (Core §5), rejecting unsigned or invalid
  requests with 400, failing closed without registered certificates. The
  verified Redirect request is bound server-side in the session, so the
  inline-login leg only accepts byte-identical values. Metadata advertises
  `WantAuthnRequestsSigned="true"` if and only if enforcement is on.
  `examples/gen_sp_keypair.py` generates a test SP keypair.
- **E2E workflow in CI** (#79): every PR now boots real servers and runs
  `examples/test_agent.py` against them (default profile, `--oauth21`,
  `--saml-signed` with a generated SP keypair) plus an MCP **stdio** smoke
  test (`examples/mcp_smoke_test.py`) driving the real transport, the
  regression guard for the class of bug where the stdio entrypoint crashed
  unnoticed because unit tests bypass it (#56).
- **Coverage gate in CI** (#71, #72): `--cov-fail-under`, introduced at 70
  and ratcheted to 75 after the wizard went from 0% to 99% coverage;
  measured coverage 78%. The dead Codecov upload (never configured, failed
  silently since inception) was removed in favor of in-CI enforcement.
- **Documentation site**: mdBook on GitHub Pages
  (<https://cdelmonte-zg.github.io/nanoidp/>) with getting-started, guides
  and a full reference; canonical docs are symlinked so there is a single
  source of truth, and the README became a landing page.
- **Web UI parity** (#94): `require_pkce` and `refresh_token_rotation`
  toggles on the settings page; SP-certificates and signed-AuthnRequests
  fields (#69); `redirect_uris` on the client form (#67); the dashboard
  badge distinguishes the `oauth21` profile.
- MCP: `get_settings` reports `security_profile`; `update_settings` covers
  the SAML verification fields; client tools carry `redirect_uris`.

### Changed
- **`src/` is fully annotated** and mypy runs with a global
  `disallow_untyped_defs` (#70): new unannotated code fails CI.
- **Internal architecture** (behavior-invariant, #83–#86): one shared YAML
  serialization path for `ConfigManager` and the UI writer; the token
  endpoint dispatches to per-grant handlers with device-flow and
  revocation state in dedicated services (`DeviceCodeStore`,
  `RevocationStore`); a single `audit_event` helper replaced 58 duplicated
  audit blocks (invariance proven by a before/after snapshot harness); the
  Pydantic models moved to `models.py` with compatibility re-exports.
- `security_profile` is now read from `settings.yaml` (top-level key) and
  round-trips on save; the CLI `--profile` still wins. A YAML-declared
  `stricter-dev` now applies its runtime hardening (previously the YAML
  value was silently ignored).

### Fixed
- **`ConfigManager.save()` was lossy** (#87): the save path behind MCP
  `save_config` rewrote `settings.yaml` from scratch, silently deleting
  every section it didn't own: `jwt` (external keys!), `session`,
  `logging` levels, `server.debug` and custom keys. Saving is now
  read-modify-write and preserves them, atomically and with a `.bak`
  backup like the UI path always did.

## [2.2.0] - 2026-06-11

### Added
- The **refresh_token** grant now re-issues an ID Token when the original grant
  included the `openid` scope (OIDC Core §12.2, #39). The granted scope is
  persisted in the refresh token claims and recovered on refresh; a `scope`
  form parameter may narrow, but never broaden, the original grant (RFC 6749
  §6: broadening is rejected with `400`). The refreshed ID Token carries no
  `nonce` (it binds the original authentication request). Refresh tokens minted
  before this change have no persisted scope and keep the old behavior.
- ID Tokens now carry `auth_time` and `at_hash` (#42). `auth_time` reflects
  when the end-user actually authenticated: the login page for the
  authorization code flow, the `/device` verification for the device flow,
  the request itself for the password grant. It is preserved unchanged
  across refreshes (OIDC Core §12.2), carried in the refresh token claims
  like the scope. `at_hash` binds the ID Token to the access token issued
  alongside it (left half of SHA-256, base64url, §3.1.3.6). Discovery
  `claims_supported` now also advertises `auth_time`, `nonce` and `at_hash`.
- Optional **refresh token rotation** (#46): with `oauth.refresh_token_rotation: true`
  (default off), each refresh atomically invalidates the consumed refresh
  token, so its reuse fails with 401; reuse of a consumed token revokes its
  whole rotation family, including the live descendant (RFC 9700 §4.14.2).
- **PKCE enforcement** (#47): new `require_pkce` setting (enabled by the
  `stricter-dev` profile, persisted in `settings.yaml`) rejects `/authorize`
  requests without a `code_challenge`; `stricter-dev` also rejects
  `code_challenge_method=plain`, whether explicit or implicit via the RFC 7636 §4.3
  omitted-parameter default, and discovery only advertises `S256` there.
  Unsupported methods are rejected at the authorization endpoint (§4.4.1).
  Default profile unchanged.
- **MCP audit & key tools** (#48): `get_audit_log`, `get_audit_stats`,
  `clear_audit_log`, `get_keys_info` and `rotate_keys` mirror the HTTP API,
  so agent workflows can inspect what the IdP recorded and exercise JWKS
  refresh handling. `clear_audit_log`/`rotate_keys` count as mutating tools
  (admin secret / readonly rules apply). MCP `get_settings`/`update_settings`
  expose the new `refresh_token_rotation` and `require_pkce` settings, and
  `generate_token` accepts an optional `scope` argument and returns an
  `id_token` when `openid` is included, matching the HTTP token endpoint.
- CI now lints with **ruff** (#45) and type-checks `src/` with **mypy**
  (#55, documented gradual-adoption baseline in `pyproject.toml`). The
  codebase is lint-clean, 153 findings fixed (#49): deprecated
  `datetime.utcnow()` replaced (removes 80 DeprecationWarnings), unused
  imports/variables dropped, imports sorted and moved to module level,
  `Optional[...]` type hints in the crypto service, `verify_jwt` accepts an
  array audience, exceptions re-raised with `from e`, and mypy-clean (40
  baseline errors fixed; the baseline also surfaced the broken `nanoidp-mcp`
  entrypoint below).

### Fixed
- **The `nanoidp-mcp` stdio entrypoint crashed at startup** ("a coroutine
  was expected"): `stdio_server()` is an async context manager yielding the
  message streams, not a coroutine. Verified with a JSON-RPC initialize
  handshake.
- Review follow-ups of the 2026-06-11 merge block (#56):
  - **Refresh tokens are bound to their client**: the issuing `client_id` is
    persisted in the refresh token claims and the refresh grant rejects any
    other client (RFC 9700 §4.14), which also guarantees the refreshed ID
    Token keeps the original `aud` (OIDC Core §12.2). Tokens minted before
    the claim existed keep working.
  - **Rotation is atomic and revokes families on reuse**: the revocation
    check and the claim of the consumed token now happen in one critical
    section, so two concurrent refreshes of the same token can no longer
    both succeed. Each grant starts a refresh-token family (`rt_family`
    claim, stable across rotations); reusing an already-consumed token
    revokes the whole family, including the live descendant (RFC 9700
    §4.14.2).
  - **PKCE `plain` can no longer slip through stricter-dev by omitting the
    method**: per RFC 7636 §4.3 an absent `code_challenge_method` defaults
    to `plain`; the method is now normalized before validation, and unknown
    methods are rejected at the authorization endpoint (§4.4.1).
  - **`require_pkce` is persisted**: it is now read from and written to
    `settings.yaml` (oauth section), so `update_settings` → `save_config` →
    `reload_config` no longer silently reverts it.
  - **The token response reports the scope actually granted** (RFC 6749
    §5.1) instead of a hardcoded `"openid"`; when no scope was involved the
    parameter is omitted, and a narrowed refresh reports the narrowed scope.
- The token endpoint validates `exp` and `extra` before the grant dispatch:
  with rotation enabled, a malformed value can no longer consume the refresh
  token without delivering its replacement (the last tradeoff noted in the
  #56 review). Validation is semantic, not just syntactic: `extra` must be a
  JSON object (a scalar/array used to raise a `TypeError` 500 later) and
  `exp` must be an integer within the same `1..1440` bounds the Settings
  model enforces (non-numeric values used to be an unhandled `ValueError`
  500; astronomical ones an `OverflowError` 500).
- Thread-safety hardening for shared in-memory state (#43): the
  authorization code store now performs its check-then-mark sequence under a
  lock (one-time use can no longer be defeated by concurrent redemptions),
  device codes are claimed/transitioned atomically and pruned when expired,
  and the lazily-created service singletons (config, token, crypto, audit,
  auth codes) use double-checked locking so concurrent first access creates
  exactly one instance.
- The MCP `get_oidc_discovery` tool now returns the exact same document as the
  HTTP `/.well-known/openid-configuration` endpoint (#40). Both build it via a
  new shared helper (`services.discovery.build_discovery_document`), so the
  MCP tool now advertises `claims_supported` (including `azp`),
  `response_types_supported`, `id_token_signing_alg_values_supported`,
  `code_challenge_methods_supported` and the endpoint auth methods. The
  two documents can no longer drift apart.
- Discovery no longer advertises the `token` response type (#41): the implicit
  flow was never implemented (`/authorize` only accepts `response_type=code`)
  and is deprecated by the OAuth 2.0 Security BCP, so advertising it misled
  clients. `response_types_supported` is now `["code"]`.

### Documentation
- The MCP tools tables in the README and `docs/MCP_WORKFLOW.md` now list all
  24 tools (#44, #48); the README was missing `create_client`,
  `update_client`, `delete_client`, `update_user`, `update_settings` and
  `save_config`.

## [2.1.0] - 2026-05-26

### Added
- ID Tokens are now issued for the **password** and **device** (RFC 8628) grants
  when `openid` scope is requested, not just `authorization_code` (#36). These
  grants authenticate an end-user, so an ID Token is meaningful; `client_credentials`
  still never emits one (no end-user).

### Fixed
- Friendlier loading of client `additional_audiences` from `settings.yaml` (#35):
  a scalar value (`additional_audiences: api://x`) is coerced to a one-element list,
  and an unsupported shape (e.g. a non-string item) now fails with a clear,
  client-scoped error instead of an opaque Pydantic `ValidationError` at startup.
- Minor hardening/polish from the #32 review (#37): `OAuthClient` now validates on
  direct attribute assignment (`validate_assignment`), discovery advertises `azp` in
  `claims_supported`, and the MCP `_normalize_audiences` rejects falsy non-list inputs
  instead of silently returning an empty list.

### Security
- Harden the ID Token vs access-token boundary (#34). The resource audience
  (`oauth.audience`) is now filtered out of the ID Token `aud` even if a client
  lists it in `additional_audiences`, and every token carries a `token_use`
  marker (`access` / `id` / `refresh`). `/userinfo` rejects tokens marked as ID or
  refresh tokens and `/introspect` reports ID Tokens as inactive, so an ID Token can
  no longer be spent as an access token. (Refresh tokens stay introspectable per
  RFC 7662.)

## [2.0.0] - 2026-05-25

### Changed
- **ID Token `aud`** now contains the requesting client's `client_id`, as required by
  OpenID Connect Core 1.0 §2 (was previously the static `oauth.audience`). This makes
  it possible to test multiple clients and brings nanoidp in line with the OIDC spec.
  - **Breaking:** relying parties that validated the ID Token `aud` against the old
    static `oauth.audience` value must now expect their own `client_id`.
  - The **access token** `aud` is unchanged and still reflects `oauth.audience`
    (the resource audience, per RFC 9068 §2.2).

### Added
- `additional_audiences` per-client setting: extra audiences appended to the ID Token
  `aud`. If this produces more than one distinct audience value, `aud` is emitted as an
  array and nanoidp also emits `azp` equal to the `client_id`, so clients can test
  authorized-party handling.

## [1.4.0] - 2026-04-28

### Added
- Environment variable substitution in `settings.yaml` using `${NAME}` / `${NAME:default}` syntax
- `PORT` env var honoured in the Docker image via shell expansion in `CMD`

## [1.3.3] - 2026-04-22
  
### Fixed
- Return `id_token` in /token response for Authorization Code Flow when `openid` scope is requested, as required by OIDC Core spec (Section 3.1.3.3)
- Include `nonce` claim in `id_token` when provided by the client

### Changed
- Use `pyproject.toml` as single source of truth for version number
- Remove outdated version label from Dockerfile

## [1.3.2] - 2026-03-27

### Fixed
- Token endpoint now rejects requests when `client_id` cannot be determined from either the request body or the `Authorization` header
- Token endpoint now rejects requests where `client_id` in the body conflicts with the authenticated client in the `Authorization` header

### Added
- Tests for client_id mismatch and missing client_id edge cases

## [1.3.1] - 2026-03-26

### Fixed
- Allow authorization code flow without `Authorization` header for PKCE public clients (RFC 6749 §2.1)
  - Libraries like authlib send `client_id` in the request body instead of the header when no client secret exists
  - Auth header validation is now only enforced for grant types other than `authorization_code`

### Added
- Test for PKCE plain flow without auth header (`test_pkce_plain_flow_no_auth_header`)

## [1.3.0] - 2026-03-25

### Added
- GitHub Actions workflow to build and publish Docker images to GitHub Container Registry (GHCR)
  - Triggered on version tags (`v*`), builds multi-platform images (`linux/amd64`, `linux/arm64`)
  - `latest` tag published only for non-prerelease versions
- Docker usage instructions in README (`docker pull` and `docker run` examples)

### Changed
- Dockerfile healthcheck switched from Python `urllib` to `curl` for Podman compatibility and reduced overhead
- Updated `actions/checkout` from v4 to v6 in publish workflow

## [1.2.3] - 2026-03-03

### Fixed
- Dockerfile and docker-compose.yml: replaced `curl` with Python's `urllib` for healthcheck: avoids adding `curl` as a system dependency in the image

### Docs
- Added mascotte/logo images to the project

## [1.2.2] - 2026-01-19

### Added
- New `strict_saml_binding` setting to enforce SAML 2.0 binding compliance
  - When `false` (default): lenient mode accepts GET with uncompressed data (useful for debugging)
  - When `true`: strict mode rejects non-compliant requests per SAML spec
- Setting exposed in UI (Settings page), REST API (`/api/config`), and MCP server
- Exclusive C14N (`exc_c14n`) is now the default XML canonicalization algorithm
  - Standard for SAML 2.0 signatures, handles namespace isolation correctly
  - Available algorithms: `exc_c14n` (Exclusive C14N 1.0, default), `c14n` (C14N 1.0), `c14n11` (C14N 1.1)
- UI select dropdown for C14N algorithm in Settings page
- `strict_saml_binding` and `verbose_logging` now persist correctly on save/reload
- Comprehensive E2E test coverage for all SAML flows in `test_agent.py`:
  - `test_saml_metadata_bindings` - verifies both HTTP-POST and HTTP-Redirect advertised
  - `test_saml_sso_post_binding` - SP-initiated SSO with HTTP-POST (InResponseTo verification)
  - `test_saml_sso_redirect_binding` - SP-initiated SSO with HTTP-Redirect (InResponseTo verification)
  - `test_saml_idp_initiated_not_supported` - documents IdP-initiated SSO is not supported
  - `test_saml_strict_binding_mode` - tests strict/lenient binding behavior
  - `test_saml_attribute_query_verification` - verifies actual attributes returned
- Unit tests for inline login flow (`test_inline_login_flow_preserves_post/redirect_binding`)
- Unit test for strict mode + inline login (`test_strict_mode_inline_login_preserves_redirect_binding`)
- Unit test for Exclusive C14N configuration (`test_c14n_algorithm_configurable_to_exclusive`)

### Fixed
- SAML SSO now correctly handles both HTTP-POST and HTTP-Redirect bindings
- Parser always tries DEFLATE decompression first, falls back to raw XML (handles all edge cases)
- Strict mode now works with inline login by passing original HTTP verb via hidden field
  - Fixes: GET compressed → login form → POST would fail in strict mode
  - Stateless: no server-side session needed, works in CI/CD pipelines
- Explicit `|e` escape filter in login template hidden fields (XSS defense-in-depth)
- Normalized `original_verb` handling (uppercase, validated to GET/POST)
- Quick-fill username buttons use `tojson` filter to handle special characters safely

## [1.2.1] - 2026-01-16

### Fixed
- SAML SSO now correctly handles HTTP-POST binding (uncompressed SAMLRequest)
- Previously, `_parse_saml_request` unconditionally attempted DEFLATE decompression, causing parsing to fail for POST requests
- Now uses HTTP method to determine binding type: GET = HTTP-Redirect (compressed), POST = HTTP-POST (uncompressed)

### Changed
- E2E test agent now verifies actual SAML parsing (InResponseTo matching) instead of just endpoint availability
- Added separate tests for HTTP-POST and HTTP-Redirect bindings in `test_agent.py`

### Changed (Architecture)
- **Inline login for SAML SSO**: `/saml/sso` now shows login form directly instead of redirecting to `/login`
  - This preserves SAML binding context naturally (no redirect = no method change)
  - Follows the pattern used by Keycloak and other IdPs
  - Removes the complex edge cases caused by redirect-based login
- `/login` endpoint simplified - now only used for direct web UI access, not SAML flows
- Login form now posts to current URL (no hardcoded action) - works for both `/login` and `/saml/sso`

### Changed
- SAML metadata now advertises both HTTP-POST and HTTP-Redirect bindings for SingleSignOnService
- Audit stats now track SAML SSO and Attribute Query separately (`saml_sso_requests`, `saml_attribute_queries`)
- Dashboard shows combined SAML total with SSO/AttrQuery breakdown
- E2E test agent expanded to 35 tests (was 28), now covering all SAML flows with parsing verification

## [1.2.0] - 2026-01-14

### Added
- Configurable `verbose_logging` setting to control sensitive data in logs
- `verbose_logging` exposed in MCP `get_settings` and `update_settings` tools
- `logging.verbose_logging` exposed in REST API `/api/config` endpoint
- MCP tests (`tests/test_mcp.py`) with 8 tests for MCP functionality
- Verbose logging test in E2E test agent

### Changed
- Replaced deprecated `defusedxml.lxml` with native lxml secure parser for XXE protection
- Added `html.escape` for XSS prevention in SAML responses
- Audit logging now respects `verbose_logging` setting (usernames/client_ids only when enabled)

### Security
- XXE (XML External Entity) protection using secure lxml parser configuration
- XSS prevention in SAML response forms
- Configurable sensitive data logging (verbose_logging defaults to true for dev convenience)

## [1.1.1] - 2026-01-14

### Added
- Configurable XML canonicalization algorithm via `saml.c14n_algorithm` setting

## [1.1.0] - 2026-01-14

### Added
- Configurable SAML response signing via `saml.sign_responses` setting
- UI toggle for SAML signing in Settings page (`/settings`)
- `sign_responses` exposed in `/api/config` endpoint
- Test agent (`examples/test_agent.py`) for comprehensive endpoint testing

### Changed
- SAML SSO and AttributeQuery endpoints now respect `sign_responses` configuration
- Changed default XML canonicalization to C14N 1.0 for maximum compatibility
- Updated documentation with SAML signing configuration instructions

## [1.0.0] - 2025-12-04

### Added
- Initial release
- OAuth2/OIDC support (Authorization Code, Password, Client Credentials, Refresh Token, Device Flow)
- PKCE support (S256 and plain methods)
- Token Introspection (RFC 7662) and Revocation (RFC 7009)
- OIDC Logout / End Session endpoint
- Device Authorization Grant (RFC 8628)
- SAML 2.0 SSO and AttributeQuery endpoints with signed assertions
- MCP Server integration for Claude Code
- Web UI for configuration (users, clients, settings, keys, audit log)
- YAML-based configuration
- Attribute-based access control with configurable authority prefixes
- Audit logging
- Docker support
- Security profiles (`dev` and `stricter-dev`)
- Key rotation with JWKS support for multiple keys
- External key import support

[3.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.8.0...v3.0.0
[2.8.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.3...v1.3.0
[1.2.3]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cdelmonte-zg/nanoidp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cdelmonte-zg/nanoidp/releases/tag/v1.0.0
