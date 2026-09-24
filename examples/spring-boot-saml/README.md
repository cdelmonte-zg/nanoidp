# Spring Boot SAML

A Spring Boot 4 service provider logging in over SAML 2.0 against NanoIDP:
the preset (`settings.yaml`, `users.yaml`), the SP (`sp/`), and tests that
drive the login without a browser (`tests/`).

```bash
# NanoIDP with this preset, on :8000
mkdir -p idp-config && cp settings.yaml users.yaml idp-config/
python -m nanoidp --config ./idp-config

# The SP, on :8080 (another terminal; Java 21+ and Maven)
cd sp && mvn -q package -DskipTests && java -jar target/nanoidp-saml-sp-1.0.jar

# The login, admin and non-admin (a third terminal)
pip install requests pytest && pytest tests
```

Test users: `admin` / `admin` (roles `ADMIN`, `USER`, group
`ADMINISTRATORS`), `user` / `user` (role `USER`), `readonly` / `readonly`
(role `VIEWER`).

The SP sets its entity ID to `oauth.audience` as a workaround for #443.
The guide explains that and the rest, from the Maven setup to mapping
roles to Spring authorities:
[Test a Spring Boot SAML service provider without a real IdP](https://cdelmonte-zg.github.io/nanoidp/use-cases/spring-boot-saml.html).
The repository runs this directory in `.github/workflows/saml-example.yml`.
