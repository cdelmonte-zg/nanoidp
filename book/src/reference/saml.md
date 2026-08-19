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

Need a test SP keypair? `python examples/gen_sp_keypair.py --out .`
generates `sp-key.pem`/`sp-cert.pem`, and
`examples/test_agent.py --saml-signed` exercises the whole behavior
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
