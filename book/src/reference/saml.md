# SAML options

## Bindings

NanoIDP supports both standard SAML 2.0 bindings for the SSO endpoint:

| Binding | HTTP Method | SAMLRequest Encoding |
|---------|-------------|---------------------|
| HTTP-POST | POST | Base64 only (uncompressed) |
| HTTP-Redirect | GET | DEFLATE compressed + Base64 |

Both bindings are advertised in the SAML metadata (`/saml/metadata`).

## Strict binding mode

By default, NanoIDP operates in **lenient mode** for developer
convenience, accepting GET requests with uncompressed SAMLRequest data
(non-compliant but useful for debugging).

To enforce strict SAML 2.0 binding compliance:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  strict_binding: true  # Reject GET with uncompressed data
```

**Via web UI:** Settings → SAML Settings → toggle **"Strict SAML
Binding"** → Save Settings.

| Mode | GET with uncompressed data | GET with DEFLATE | POST uncompressed |
|------|---------------------------|------------------|-------------------|
| Lenient (default) | Accepted | Accepted | Accepted |
| Strict | **Rejected (400)** | Accepted | Accepted |

## Response signing

By default, NanoIDP signs all SAML responses with an XML digital
signature. You can disable signing for testing scenarios that require
unsigned SAML flows:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  sign_responses: false  # Disable SAML response signing
```

**Via web UI:** Settings → SAML Settings → toggle **"Sign SAML
Responses"** → Save Settings.

When `sign_responses: true` (default), responses include:

- `<ds:Signature>` element with RSA-SHA256 signature
- `<ds:X509Certificate>` with the IdP certificate

When `sign_responses: false`, responses are sent without any signature
elements.

## Exporting roles and groups as attributes

Roles and groups are **not** included in SAML assertions by default. Enable
them explicitly - and, because every SP expects a different attribute name,
name them to match your SP:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  export_roles: false        # default; true to include the roles attribute
  export_groups: false       # default; true to include the groups attribute
  roles_attr_name: "roles"   # name used when export_roles is on
  groups_attr_name: "groups" # name used when export_groups is on
```

**Via web UI:** Settings → SAML Settings → toggle **"Export Roles
Attribute"** / **"Export Groups Attribute"** and set the matching attribute
name → Save Settings. Clearing a name field restores its default.

Each entry becomes its own `AttributeValue`, in both the SSO assertion and
the AttributeQuery response, so a value containing a comma stays a single
value. Configuring the same name for both exports (e.g. `memberOf` for roles
and groups alike) is supported: the two lists are merged into that one
attribute, roles first, deduplicated.

Any name works, including the URIs SPs commonly expect:

| SP | Typical roles attribute name |
|----|------------------------------|
| Spring Security | `roles` (whatever your `AttributeConverter` reads) |
| ADFS / Entra ID | `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` |
| Shibboleth | `urn:oid:1.3.6.1.4.1.5923.1.5.1.1` (groups / `isMemberOf`) |
| Generic LDAP-style | `memberOf` |

Both toggles apply to the SSO assertion and to the AttributeQuery endpoint,
and each entry becomes its own `<AttributeValue>`. A user with no roles (or
no groups) gets no attribute even when the export is on, and a custom user
attribute with the same name still takes precedence.

Note that these attributes are independent of the `authority_prefixes`
mapping, which only affects the `authorities` claim in OAuth/OIDC tokens.

## Signed AuthnRequests

By default, nanoidp accepts unsigned AuthnRequests (and ignores
`Signature`/`SigAlg` query parameters). SPs that sign their requests can
turn on verification:

```yaml
saml:
  want_authn_requests_signed: true
  sp_certificates:
    - /path/to/sp-cert.pem   # PEM; one entry per trusted SP
```

With the flag on, nanoidp **requires and verifies** the signature under
both bindings and rejects unsigned or invalid requests with `400`:

- **HTTP-Redirect**: the query-string signature over the URL-encoded
  `SAMLRequest[&RelayState]&SigAlg` fragment (SAML 2.0 Bindings
  §3.4.4.1); `rsa-sha256`, `rsa-sha512` and legacy `rsa-sha1` SigAlg
  values are supported.
- **HTTP-POST**: the enveloped `<ds:Signature>` inside the AuthnRequest
  (SAML 2.0 Core §5).

The metadata advertises `WantAuthnRequestsSigned="true"` if and only if
enforcement is on. A request verifies if any registered certificate
validates it.

A Redirect-binding signature exists only on the original URL, so it cannot
be re-verified when the inline login form posts the request back. nanoidp
therefore remembers, in the browser's own signed session, which Redirect
requests that browser had verified, and admits the login post only for one
of them, which is what keeps the hidden form fields from standing in for the
signature. Each request is remembered on its own (#375, where it used to be
a single slot, so a second signed request made the first non-continuable):
ten per browser, an eleventh making the oldest non-continuable, each kept
for **10 minutes of inactivity** and refreshed while the login is being
continued. Nothing is shared between browsers, and the set survives a
restart or several workers as long as they share `session.secret_key`. The
set travels in the cookie, so two signed requests issued before either
response's cookie reaches the browser (two SP iframes on one page, a
prefetch, two tabs restored at once) still leave only the later one
continuable; requests that follow one another, which is what a person
opening two logins produces, are unaffected. The
POST binding needs none of this: its signature travels inside the
AuthnRequest and is verified again on every leg.

Every attribute query is recorded in the audit log as a
`saml_attribute_query` event - the successful ones, the unknown principals,
and the ones refused for their shape - with the query's own `ID` as
`request_id` and the request size, so an entry can be matched to the caller
that sent it (#309). The query body is written to the log only when
`logging.verbose_logging` is on, because it names a principal.

Need a test SP keypair? `python e2e/gen_sp_keypair.py --out .`
generates `sp-key.pem`/`sp-cert.pem`, and
`e2e/test_agent.py --saml-signed` exercises the whole behavior
against a running server.

## XML canonicalization algorithm

By default, NanoIDP uses **Exclusive C14N** for XML canonicalization,
which is the standard for SAML signatures and compatible with most modern
SAML implementations. You can configure the algorithm based on your SP
requirements:

**Via configuration file (`settings.yaml`):**

```yaml
saml:
  c14n_algorithm: exc_c14n  # Default: Exclusive C14N 1.0 (standard for SAML)
  # c14n_algorithm: c14n    # C14N 1.0
  # c14n_algorithm: c14n11  # C14N 1.1
```

**Via web UI:** Settings → SAML Settings → select the **Canonicalization
Algorithm** from the dropdown → Save Settings.

| Value | Algorithm | Use Case |
|-------|-----------|----------|
| `exc_c14n` (default) | Exclusive C14N 1.0 | Standard for SAML, handles namespace isolation |
| `c14n` | C14N 1.0 | Legacy SAML implementations |
| `c14n11` | C14N 1.1 | Newer implementations |

**Why Exclusive C14N is the default:**

Exclusive C14N is recommended by the SAML 2.0 specification because it
only includes namespaces actually used in the signed element. This is
important when SPs extract the `<Assertion>` element from the `<Response>`
to verify the signature independently. With standard C14N, the signature
includes parent namespaces that break when the Assertion is extracted.

## The two SAML surfaces: one resolver, declared differences (#302, #317)

Both the SSO assertion and the attribute-query assertion resolve a user's
attributes through the same service (`services/saml_attributes.py`), and
both build the identical part of the document, the `Response` envelope, the
`Issuer` pair, the `Status` element and the assertion's own head, through
`services/saml_assertion.py` (#317). So they cannot drift silently. Their
remaining differences are deliberate:

| Aspect | SSO assertion | Attribute-query assertion | Why |
|---|---|---|---|
| `source_acl` | not exported | exported | the query surface exists for backend authorization lookups; a login assertion carries no document-level ACLs |
| `AuthnStatement` / `AuthnContextClassRef` | present | absent | an attribute lookup is not an authentication event; asserting one would be false |
| `SubjectConfirmation` | present (bearer, 5-minute window) | absent | ties an assertion to a login exchange the query never had |
| `AudienceRestriction` | pinned to `oauth.audience` | absent | the query requester's audience is unknown (the endpoint is unauthenticated by design) |
| `Conditions` validity | 5 minutes | 1 hour | a login assertion is spent immediately at an ACS; a backend lookup is not. The two windows have never been decided to be one policy, so they are stated here rather than shared behind an argument |
| `Response/@Destination` | the ACS URL | absent | only a login assertion is delivered to an endpoint the IdP was told about |
| `InResponseTo` | only when answering an AuthnRequest | always | an IdP-initiated login answers no request; an attribute query always does |
| `ds` namespace | declared on the envelope | absent | the SSO document is signed in place, and the prefix is declared whether or not signing runs |
| Serialization | bytes, with an XML declaration | unicode, pretty-printed | historical, and part of what the SP receives, so it is pinned rather than unified |
| Signing | inline in the builder | a separate `_sign_attribute_query_response` | the query surface signs after serializing, by reparsing its own output |

The last six rows were found by the #317 census, not declared anywhere
before it, and none of them were covered by a test. They are pinned
byte-for-byte in `tests/test_saml_assertion_shapes.py`.

There is a third builder on the query surface: the error Response for an
unknown principal (#275) shares the same envelope and `Issuer`, carries a
`Requester` / `UnknownPrincipal` status pair instead of `Success`, and has
no assertion at all.

Shared rules on both surfaces: an absent or empty fact is an absent
attribute (no fabricated `email`, no empty `Attribute` elements - None and
empty list/tuple/set/dict/string alike); a list value becomes one
`AttributeValue` per entry and a string is never split on commas (#134);
roles/groups exports are opt-in under their configured names. When the
roles and groups exports target the SAME configured name, their lists are
merged (roles first, deduplicated); a collision between an export name and
a scalar core attribute is not merged - the export list replaces it.
