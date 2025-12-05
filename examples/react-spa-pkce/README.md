# React SPA + PKCE Integration

This preset configures NanoIDP for Single Page Applications using Authorization Code flow with PKCE.

## Quick Start

1. Copy configuration files:
```bash
cp examples/react-spa-pkce/*.yaml ./config/
python -m nanoidp
```

2. Start your React app on `http://localhost:3000`

## OIDC Discovery

Your app can fetch configuration from:
```
http://localhost:8000/.well-known/openid-configuration
```

## React Configuration (react-oidc-context)

```bash
npm install react-oidc-context oidc-client-ts
```

```tsx
// src/index.tsx
import { AuthProvider } from "react-oidc-context";

const oidcConfig = {
  authority: "http://localhost:8000",
  client_id: "spa-client",
  redirect_uri: "http://localhost:3000/callback",
  post_logout_redirect_uri: "http://localhost:3000",
  scope: "openid profile email",
  response_type: "code",
};

<AuthProvider {...oidcConfig}>
  <App />
</AuthProvider>
```

```tsx
// src/App.tsx
import { useAuth } from "react-oidc-context";

function App() {
  const auth = useAuth();

  if (auth.isLoading) return <div>Loading...</div>;

  if (auth.error) return <div>Error: {auth.error.message}</div>;

  if (auth.isAuthenticated) {
    return (
      <div>
        <p>Hello {auth.user?.profile.sub}</p>
        <pre>{JSON.stringify(auth.user?.profile, null, 2)}</pre>
        <button onClick={() => auth.removeUser()}>Log out</button>
      </div>
    );
  }

  return <button onClick={() => auth.signinRedirect()}>Log in</button>;
}
```

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `admin` | ADMIN, USER |
| `user` | `user` | USER |

## OAuth Endpoints

| Endpoint | URL |
|----------|-----|
| Authorization | `http://localhost:8000/authorize` |
| Token | `http://localhost:8000/token` |
| UserInfo | `http://localhost:8000/userinfo` |
| JWKS | `http://localhost:8000/.well-known/jwks.json` |
| Logout | `http://localhost:8000/logout` |

## Callback Route

Create a callback route in your React app:

```tsx
// src/Callback.tsx
import { useAuth } from "react-oidc-context";
import { Navigate } from "react-router-dom";

function Callback() {
  const auth = useAuth();

  if (auth.isLoading) return <div>Processing login...</div>;
  if (auth.isAuthenticated) return <Navigate to="/" />;

  return <div>Login failed</div>;
}
```

## CORS Configuration

This preset is configured to allow requests from `http://localhost:3000`.

If your app runs on a different port, update `settings.yaml`:

```yaml
cors_allowed_origins:
  - "http://localhost:3000"
  - "http://localhost:5173"  # Vite default
```

## Token Claims

The ID token includes these claims:

```json
{
  "sub": "admin",
  "iss": "http://localhost:8000",
  "aud": "spa-client",
  "roles": ["ADMIN", "USER"],
  "email": "admin@example.org",
  "authorities": ["ROLE_ADMIN", "ROLE_USER", "ENT_ADMIN_ACCESS"]
}
```
