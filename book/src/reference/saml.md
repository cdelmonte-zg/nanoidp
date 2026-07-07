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
