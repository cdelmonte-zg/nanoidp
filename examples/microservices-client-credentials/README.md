# Microservices Client Credentials Integration

This preset configures NanoIDP for service-to-service authentication using the Client Credentials grant.

## Quick Start

1. Copy configuration files:
```bash
cp examples/microservices-client-credentials/*.yaml ./config/
python -m nanoidp
```

2. Request a token for your service:
```bash
curl -X POST http://localhost:8000/token \
  -u 'order-service:order-service-secret' \
  -d 'grant_type=client_credentials&scope=orders:read orders:write'
```

## Use Case

The Client Credentials grant is used when:
- Services need to authenticate without user context
- Background jobs or workers need API access
- Service mesh authentication

## Pre-configured Services

| Service | Client ID | Secret |
|---------|-----------|--------|
| Order Service | `order-service` | `order-service-secret` |
| Inventory Service | `inventory-service` | `inventory-service-secret` |
| Notification Service | `notification-service` | `notification-service-secret` |

## Token Request Example

```bash
# Get token for Order Service
curl -X POST 'http://localhost:8000/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'order-service:order-service-secret' \
  -d 'grant_type=client_credentials'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Spring Boot Integration

### Resource Server Configuration

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8000
```

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/internal/**").hasAuthority("SCOPE_internal")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
```

### Client Configuration (WebClient)

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          nanoidp:
            client-id: order-service
            client-secret: order-service-secret
            authorization-grant-type: client_credentials
            scope: orders:read,orders:write
        provider:
          nanoidp:
            token-uri: http://localhost:8000/token
```

```java
@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oauth2Client.setDefaultClientRegistrationId("nanoidp");

        return WebClient.builder()
            .apply(oauth2Client.oauth2Configuration())
            .build();
    }
}
```

## Token Introspection

Services can validate tokens:

```bash
curl -X POST http://localhost:8000/introspect \
  -u 'order-service:order-service-secret' \
  -d 'token=YOUR_ACCESS_TOKEN'
```

## Token Claims

Client Credentials tokens include:

```json
{
  "iss": "http://localhost:8000",
  "sub": "order-service",
  "aud": "microservices",
  "client_id": "order-service",
  "scope": "orders:read orders:write",
  "exp": 1704107200,
  "iat": 1704103600
}
```
