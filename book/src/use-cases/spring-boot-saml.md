# Test a Spring Boot SAML service provider without a real IdP

A Spring Boot application that logs its users in over SAML 2.0 needs an
identity provider to test against: one that serves metadata, answers an
AuthnRequest with a signed assertion, and sends the attributes your
authorization rules read. A corporate IdP is rarely available to a
developer machine or a CI job, and a hosted one means an account and a
network dependency.

NanoIDP is that IdP on `localhost`: SAML SSO over the HTTP-POST and
HTTP-Redirect bindings, signed responses, and users with roles and groups
from a YAML file. This page connects a Spring Boot 4 service provider to
it, maps the roles to Spring authorities, and tests the login without a
browser.

Everything here is in
[`examples/spring-boot-saml/`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/spring-boot-saml),
and the repository's CI builds the SP and runs the tests below against it.

## 1. Start NanoIDP with the preset

```bash
pip install nanoidp requests pytest   # requests and pytest for the tests below
mkdir -p config
base=https://raw.githubusercontent.com/cdelmonte-zg/nanoidp/main/examples/spring-boot-saml
curl -fsSL -o config/settings.yaml "$base/settings.yaml"
curl -fsSL -o config/users.yaml "$base/users.yaml"
python -m nanoidp --config ./config
```

```yaml
{{#include ../../../examples/spring-boot-saml/settings.yaml}}
```

NanoIDP does not send roles and groups over SAML unless `export_roles` and
`export_groups` are on. The users are `admin` / `admin` (roles `ADMIN`,
`USER`, group `ADMINISTRATORS`), `user` / `user` (role `USER`) and
`readonly` / `readonly` (role `VIEWER`).

## 2. Point Spring Boot at NanoIDP

Spring Boot 4 has a starter for SAML. Its OpenSAML dependency is not on
Maven Central, so the build needs the Shibboleth repository as well; without
it, the build fails with `Could not find artifact
org.opensaml:opensaml-saml-api`:

```xml
{{#include ../../../examples/spring-boot-saml/sp/pom.xml:deps}}
```

The registration needs one URL, NanoIDP's metadata, which carries the SSO
endpoint, both bindings and the signing certificate:

```yaml
{{#include ../../../examples/spring-boot-saml/sp/src/main/resources/application.yml}}
```

> **The `entity-id` line is a workaround for
> [#443](https://github.com/cdelmonte-zg/nanoidp/issues/443).** NanoIDP
> puts `oauth.audience` in every assertion's `Audience`, where the SAML
> profile requires the service provider's own entity ID. Spring checks the
> audience, so with its default entity ID it rejects every response and
> sends the browser to `/login?error`; the log says only `Found 1
> validation errors in SAML response`. Setting the SP's entity ID to the
> value of `oauth.audience` makes the two agree. Once #443 is fixed, the
> line goes.

## 3. Turn SAML roles into Spring authorities

A SAML login in Spring Security carries no role by default: `hasRole` fails
for everyone, and `/admin` answers `403` even for `admin`. The response
converter below reads the `roles` attribute and grants `ROLE_ADMIN`,
`ROLE_USER` and so on:

```java
{{#include ../../../examples/spring-boot-saml/sp/src/main/java/example/SecurityConfig.java}}
```

NanoIDP sends attribute values without an `xsi:type`, which OpenSAML reads
as `XSAny`, not `XSString`; a converter that only accepts `XSString` finds
no role at all. The one above accepts both.

## 4. What arrives in Spring

For `admin`, the application sees:

| Where | Value |
|---|---|
| principal name (the `NameID`) | `admin@example.org`: NanoIDP uses the user's email |
| `roles` attribute | `ADMIN`, `USER` |
| `groups` attribute | `ADMINISTRATORS` |
| other attributes | `email`, `identity_class`, `entitlements` |
| authorities, with the converter | `ROLE_ADMIN`, `ROLE_USER`, and `FACTOR_SAML_RESPONSE`, which Spring Security 7 adds to every SAML login |

`tenant` and `source_acl` are not in the login assertion; the SAML
reference lists what each SAML surface sends in
[The two SAML surfaces](../reference/saml.md#the-two-saml-surfaces-one-resolver-declared-differences-302-317).

## 5. Test the login without a browser

The SAML login is four HTTP exchanges, and they can be scripted: the SP's
auto-submitting form with the AuthnRequest, NanoIDP's login form, NanoIDP's
auto-submitting form with the SAMLResponse, and the SP's answer. The tests
below do what a browser does, against the SP on `:8080` and NanoIDP on
`:8000`:

```python
{{#include ../../../examples/spring-boot-saml/tests/test_saml_login.py}}
```

The login form fields (`username`, `password`) are NanoIDP's own; the rest
is the standard SAML Web Browser SSO profile over the HTTP-POST binding.

## What must fail

| What happens | Result with this example |
|---|---|
| `user` opens `/admin` | `403`: the login works, the role is missing |
| a wrong password | NanoIDP shows its form again; no SAMLResponse reaches the SP |
| the SP's entity ID differs from `oauth.audience` (#443) | Spring rejects the response and redirects to `/login?error` |

## Limits to know

- **No single logout.** NanoIDP's metadata has no `SingleLogoutService`, so
  `saml2Logout()` has nothing to talk to. Log out locally with Spring's
  ordinary `logout()`.
- **The audience** is NanoIDP's `oauth.audience` for every service
  provider, until [#443](https://github.com/cdelmonte-zg/nanoidp/issues/443)
  is fixed.

## Takeaways

- Spring Boot 4 needs the `spring-boot-starter-security-saml2` starter and
  the Shibboleth Maven repository; the IdP side is one metadata URL.
- Roles are not authorities until you map them. Map the attribute your IdP
  sends, and accept values without `xsi:type`.
- An SP that rejects every response with "validation errors" is most often
  an audience mismatch. Compare the assertion's `Audience` with the SP's
  entity ID.
- The login is scriptable end to end, so SAML can be tested in CI like
  anything else.
