"""Log a command-line tool in with the device authorization grant (RFC 8628)."""
import time

import requests

IDP = "http://localhost:8000"
CLIENT_ID = "cli-tool"  # a public client: no secret
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
TIMEOUT = 10  # seconds, per HTTP request


class LoginFailed(Exception):
    pass


def request_device_code(scope="openid profile offline_access"):
    response = requests.post(f"{IDP}/device_authorization",
                             data={"client_id": CLIENT_ID, "scope": scope},
                             timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def poll_for_token(device, sleep=time.sleep):
    """Poll /token until the user decides, the code expires, or it fails."""
    interval = device.get("interval", 5)
    deadline = time.monotonic() + device["expires_in"]
    while time.monotonic() < deadline:
        sleep(interval)
        answer = requests.post(f"{IDP}/token", timeout=TIMEOUT, data={
            "grant_type": DEVICE_GRANT,
            "client_id": CLIENT_ID,
            "device_code": device["device_code"],
        }).json()
        error = answer.get("error")
        if error is None:
            return answer
        if error == "authorization_pending":
            continue
        if error == "slow_down":  # RFC 8628 §3.5: wait 5 seconds longer
            interval += 5
            continue
        raise LoginFailed(error)  # access_denied, expired_token, invalid_grant...
    raise LoginFailed("expired_token")


def refresh(refresh_token):
    """Exchange a refresh token. It rotates: store the new one, drop the old."""
    response = requests.post(f"{IDP}/token", timeout=TIMEOUT, data={
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    })
    answer = response.json()
    if "error" in answer:
        raise LoginFailed(answer["error"])
    return answer


if __name__ == "__main__":
    device = request_device_code()
    print(f"Open {device['verification_uri']} and enter the code {device['user_code']}")
    print(f"(or open {device['verification_uri_complete']})")
    tokens = poll_for_token(device)
    print("Logged in; access token expires in", tokens["expires_in"], "seconds")
