# CLI / IoT Device Flow Integration

This preset configures NanoIDP for Device Authorization Grant (RFC 8628), ideal for CLI tools, smart TVs, and IoT devices.

## Quick Start

1. Copy configuration files:
```bash
cp examples/cli-device-flow/*.yaml ./config/
python -m nanoidp
```

2. Test the device flow (see below)

## How Device Flow Works

1. **Device requests authorization**: The CLI requests a device code
2. **User opens browser**: User visits verification URL and enters code
3. **User authenticates**: User logs in and approves the request
4. **Device polls for token**: CLI polls until user completes authentication

## Step-by-Step Example

### 1. Request Device Code

```bash
curl -X POST http://localhost:8000/device_authorization \
  -u 'cli-tool:cli-tool-secret' \
  -d 'scope=openid profile'
```

Response:
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "http://localhost:8000/device",
  "verification_uri_complete": "http://localhost:8000/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

### 2. User Opens Browser

Display to the user:
```
To sign in, open: http://localhost:8000/device
Enter code: WDJB-MJHT
```

Or provide the complete URL:
```
http://localhost:8000/device?user_code=WDJB-MJHT
```

### 3. Poll for Token

While the user is authenticating, poll for the token:

```bash
curl -X POST http://localhost:8000/token \
  -u 'cli-tool:cli-tool-secret' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS'
```

Pending response:
```json
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending"
}
```

Success response (after user authenticates):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "..."
}
```

## Python CLI Example

```python
import requests
import time

CLIENT_ID = "cli-tool"
CLIENT_SECRET = "cli-tool-secret"
IDP_URL = "http://localhost:8000"

def device_flow_login():
    # Step 1: Request device code
    resp = requests.post(
        f"{IDP_URL}/device_authorization",
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"scope": "openid profile"}
    )
    device_data = resp.json()

    print(f"\nTo sign in, open: {device_data['verification_uri']}")
    print(f"Enter code: {device_data['user_code']}\n")

    # Step 2: Poll for token
    interval = device_data.get("interval", 5)
    expires_in = device_data["expires_in"]
    start_time = time.time()

    while time.time() - start_time < expires_in:
        time.sleep(interval)

        resp = requests.post(
            f"{IDP_URL}/token",
            auth=(CLIENT_ID, CLIENT_SECRET),
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_data["device_code"]
            }
        )
        result = resp.json()

        if "access_token" in result:
            print("Successfully authenticated!")
            return result

        if result.get("error") == "authorization_pending":
            print(".", end="", flush=True)
            continue

        if result.get("error") == "slow_down":
            interval += 5
            continue

        if result.get("error") in ("expired_token", "access_denied"):
            raise Exception(result.get("error_description"))

    raise Exception("Authentication timed out")

if __name__ == "__main__":
    tokens = device_flow_login()
    print(f"Access Token: {tokens['access_token'][:50]}...")
```

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `admin` | ADMIN, USER |
| `user` | `user` | USER |

## Pre-configured Clients

| Client ID | Secret | Description |
|-----------|--------|-------------|
| `cli-tool` | `cli-tool-secret` | General purpose CLI |
| `iot-device` | `iot-device-secret` | IoT/Smart device |

## Token Claims

Device flow tokens include user claims:

```json
{
  "iss": "http://localhost:8000",
  "sub": "admin",
  "aud": "cli-devices",
  "roles": ["ADMIN", "USER"],
  "email": "admin@example.org",
  "device_code_used": true
}
```
