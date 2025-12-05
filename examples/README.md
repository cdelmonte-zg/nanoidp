# NanoIDP Configuration Examples

This directory contains ready-to-use configuration presets for common integration scenarios.

## Available Presets

| Preset | Use Case | OAuth Grant Type |
|--------|----------|------------------|
| [spring-boot-saml](./spring-boot-saml/) | Spring Security SAML integration | SAML 2.0 |
| [react-spa-pkce](./react-spa-pkce/) | Single Page Applications | Authorization Code + PKCE |
| [microservices-client-credentials](./microservices-client-credentials/) | Service-to-service auth | Client Credentials |
| [cli-device-flow](./cli-device-flow/) | CLI tools and IoT devices | Device Authorization |

## How to Use

1. Copy the desired preset's `users.yaml` and `settings.yaml` to your config directory:

```bash
# Example: Using the React SPA PKCE preset
cp examples/react-spa-pkce/*.yaml ./config/
```

2. Start NanoIDP:

```bash
python -m nanoidp --config ./config
```

3. Follow the preset's README for integration instructions.

## Customizing Presets

Each preset is designed as a starting point. You can:

- Add more users to `users.yaml`
- Modify client credentials in `settings.yaml`
- Adjust token expiry times
- Customize authority prefixes

## Creating Your Own Preset

1. Create a new directory in `examples/`
2. Add `users.yaml` with your test users
3. Add `settings.yaml` with OAuth/SAML settings
4. Add a `README.md` with integration instructions
