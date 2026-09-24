# Microservices: client credentials

Two services calling APIs with client_credentials tokens: per-client scopes,
an audience per API (RFC 8707 resource indicators), and a Spring Boot 4
resource server (`inventory-api/`) that checks signature, issuer, audience
and scope. The tests (`tests/`) cover what the API accepts and what it, or
NanoIDP, must refuse.

```bash
# NanoIDP with this preset, on :8000
mkdir -p idp-config && cp settings.yaml users.yaml idp-config/
python -m nanoidp --config ./idp-config

# The inventory API, on :8081 (another terminal; Java 21+ and Maven)
cd inventory-api && mvn -q package -DskipTests && java -jar target/inventory-api-1.0.jar

# The service calls (a third terminal)
pip install requests pytest && pytest tests
```

| Client | Secret | May ask for | For the audience |
|---|---|---|---|
| `order-service` | `order-service-secret` | `inventory:read`, `inventory:reserve` | `https://inventory.internal` |
| `notification-service` | `notification-service-secret` | `orders:read` | `https://orders.internal` |

`default_user` is a user with no roles, a workaround for #445: a
client_credentials token is issued for that user. The guide explains it and
the rest:
[Test service-to-service auth with client credentials](https://cdelmonte-zg.github.io/nanoidp/use-cases/service-to-service-client-credentials.html).
The repository runs this directory in `.github/workflows/client-credentials-example.yml`.
