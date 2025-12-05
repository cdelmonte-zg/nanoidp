# Spring Boot SAML Integration

This preset configures NanoIDP for integration with Spring Security SAML.

## Quick Start

1. Copy configuration files:
```bash
cp examples/spring-boot-saml/*.yaml ./config/
python -m nanoidp
```

2. Get the IdP metadata for your Spring app:
```
http://localhost:8000/saml/metadata
```

## Spring Boot Configuration

Add the following to your `application.yml`:

```yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          nanoidp:
            entity-id: "{baseUrl}/saml2/service-provider-metadata/{registrationId}"
            assertingparty:
              metadata-uri: http://localhost:8000/saml/metadata
            acs:
              location: "{baseUrl}/login/saml2/sso/{registrationId}"
            singlelogout:
              binding: POST
              url: "{baseUrl}/logout/saml2/slo"
```

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `admin` | ADMIN, USER |
| `user` | `user` | USER |
| `readonly` | `readonly` | VIEWER |

## SAML Attributes Mapping

NanoIDP sends these SAML attributes:

| Attribute | Description |
|-----------|-------------|
| `email` | User's email address |
| `roles` | Comma-separated list of roles |
| `tenant` | User's tenant |
| `authorities` | All Spring GrantedAuthorities |

## Spring Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )
            .saml2Login(Customizer.withDefaults())
            .saml2Logout(Customizer.withDefaults());
        return http.build();
    }
}
```

## Troubleshooting

### Certificate Validation Errors

If you get certificate validation errors, NanoIDP generates self-signed certificates.
For development, you can disable signature validation:

```yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          nanoidp:
            assertingparty:
              verification:
                credentials:
                  - certificate-location: classpath:idp-cert.pem
```

Download the certificate from: `http://localhost:8000/keys/download/certificate`

### Clock Skew

If you get "Assertion is not yet valid" errors, ensure your system clocks are synchronized.
