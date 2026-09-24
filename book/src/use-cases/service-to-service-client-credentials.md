# Test service-to-service auth with client credentials

When one microservice calls another, there is no user: the calling service
gets a token with the OAuth 2.0 client credentials grant and sends it as a
bearer token. The receiving service has to check three things: that the
token is genuine, that it was issued for *this* service, and that the
caller has the scope for the operation. The second check is the one most
often missing, and the one a test should prove.

NanoIDP issues these tokens locally, with per-client scopes and per-service
audiences (RFC 8707 resource indicators), so you can test both what a
service accepts and what it must refuse. This page sets up two services
calling two APIs, and a Spring Boot resource server that enforces the three
checks.

Everything here is in
[`examples/microservices-client-credentials/`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/microservices-client-credentials),
and the repository's CI builds the API and runs the tests below against it.

## 1. Declare the services, their scopes and their audiences

```bash
pip install nanoidp
mkdir -p config
base=https://raw.githubusercontent.com/cdelmonte-zg/nanoidp/main/examples/microservices-client-credentials
curl -fsSL -o config/settings.yaml "$base/settings.yaml"
curl -fsSL -o config/users.yaml "$base/users.yaml"
python -m nanoidp --config ./config
```

```yaml
{{#include ../../../examples/microservices-client-credentials/settings.yaml}}
```

- **`scopes_supported`** is the vocabulary: NanoIDP refuses a scope outside
  it with `invalid_scope`, for every client.
- **`allowed_scopes`** narrows what one client may ask for.
- **`allowed_resources`** lists the APIs a client may get a token for. A
  token requested with `resource=https://inventory.internal` has that as
  its `aud`; without a `resource`, its `aud` is `oauth.audience`, which no
  API here accepts.

## 2. Get a token as a service

```bash
curl -X POST http://localhost:8000/token \
  -u 'order-service:order-service-secret' \
  -d 'grant_type=client_credentials' \
  -d 'scope=inventory:read' \
  -d 'resource=https://inventory.internal'
```

The access token's claims include:

```json
{
  "iss": "http://localhost:8000",
  "aud": "https://inventory.internal",
  "client_id": "order-service",
  "scope": "inventory:read",
  "sub": "service-account"
}
```

No refresh token: the service asks again when the token expires.

> **In NanoIDP, `sub` is not the calling service
> ([#445](https://github.com/cdelmonte-zg/nanoidp/issues/445)).** A
> client credentials token is issued for the `default_user` of
> `users.yaml`, with that user's roles and attributes. The preset's
> `default_user` is a `service-account` user with no roles, so no human
> privileges reach a service's token; the service itself is the
> `client_id`. Authorize services on `client_id`, `scope` and `aud`, which
> is also what tokens from production identity providers support.

```yaml
{{#include ../../../examples/microservices-client-credentials/users.yaml}}
```

## 3. Enforce the checks in the receiving service

A Spring Boot 4 resource server needs one starter:

```xml
{{#include ../../../examples/microservices-client-credentials/inventory-api/pom.xml:deps}}
```

The issuer URI gives Spring NanoIDP's discovery document and JWKS, so the
signature and `iss` are checked. **The audience is not checked unless you
say so**: without the `audiences` line, the inventory API accepts a token
issued for any other service.

```yaml
{{#include ../../../examples/microservices-client-credentials/inventory-api/src/main/resources/application.yml}}
```

Spring turns the `scope` claim into `SCOPE_` authorities, one per scope:

```java
{{#include ../../../examples/microservices-client-credentials/inventory-api/src/main/java/example/SecurityConfig.java}}
```

## 4. Test what is accepted and what is refused

These tests play `order-service` and `notification-service` against the
inventory API on `:8081`, and ask NanoIDP for tokens it must refuse:

```python
{{#include ../../../examples/microservices-client-credentials/tests/test_service_calls.py}}
```

| Case | Answer |
|---|---|
| `order-service`, `inventory:read`, audience `https://inventory.internal`, `GET /stock` | `200`, the caller is `order-service` |
| the same token on `POST /reservations` | `403`: the scope is missing |
| no token | `401` |
| a token requested without `resource` (`aud` is `microservices`) | `401` |
| `notification-service`'s token for `https://orders.internal` | `401`: issued for another API |
| `order-service` asks for `orders:read` | NanoIDP: `invalid_scope` |
| `order-service` asks for `https://orders.internal` | NanoIDP: `invalid_target` |
| a wrong client secret | NanoIDP: `401 invalid_client` |

Remove the `audiences` line from the API and the two "issued for another
API" cases turn into accepted calls: the tests catch it.

## Takeaways

- Give every API its own audience and have clients request it with
  `resource`. A shared audience means any service's token works everywhere.
- Spring checks the signature and the issuer by itself, the audience only
  when configured. Test that a token for another service is refused.
- Authorize a service on its scopes, and identify it by `client_id`. In
  NanoIDP, the `sub` and roles of a client credentials token belong to
  `default_user` (#445).
- Declare scopes in `scopes_supported` and per client in `allowed_scopes`:
  a scope NanoIDP does not know is refused, not silently dropped.
