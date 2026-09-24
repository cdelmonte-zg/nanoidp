"""The CLI's device flow against NanoIDP, with the browser step scripted.

Needs NanoIDP on :8000 with this preset.
"""
import threading
import time

import jwt
import pytest
import requests
from cli_login import IDP, TIMEOUT, LoginFailed, poll_for_token, refresh, request_device_code


def user_decides(user_code, username, password, action="authorize"):
    """What the user does in the browser at verification_uri."""
    return requests.post(f"{IDP}/device", timeout=TIMEOUT, data={
        "user_code": user_code, "username": username, "password": password,
        "action": action,
    })


def poll_in_background(device):
    """Start polling as the CLI does, and return a way to collect the result.

    Returns once the CLI has polled at least once and gone back to waiting,
    so the user's decision always finds it mid-poll, as in real use.
    """
    outcome = {}
    pauses = threading.Semaphore(0)

    def pause(seconds):
        # Tests do not wait out the polling interval, only a moment
        pauses.release()
        time.sleep(0.05)

    def run():
        try:
            outcome["tokens"] = poll_for_token(device, sleep=pause)
        except LoginFailed as failure:
            outcome["error"] = str(failure)

    thread = threading.Thread(target=run, daemon=True)  # a stuck CLI fails the test, not the run
    thread.start()
    # One pause before the first poll, one after its authorization_pending
    assert pauses.acquire(timeout=10) and pauses.acquire(timeout=10)
    return lambda: (thread.join(timeout=30), outcome)[1]


def test_the_user_approves_and_the_cli_gets_tokens_for_that_user():
    device = request_device_code()
    result = poll_in_background(device)
    assert user_decides(device["user_code"], "user", "user").status_code == 200
    tokens = result()["tokens"]
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "user"
    assert claims["client_id"] == "cli-tool"
    assert claims["roles"] == ["USER"]
    assert "refresh_token" in tokens


def test_the_user_denies():
    device = request_device_code()
    result = poll_in_background(device)
    user_decides(device["user_code"], "user", "user", action="deny")
    assert result()["error"] == "access_denied"


def test_a_wrong_password_leaves_the_request_pending():
    device = request_device_code()
    page = user_decides(device["user_code"], "user", "wrong")
    assert "Invalid username or password" in page.text
    # The CLI keeps polling; the request is still open for a correct login
    pending = requests.post(f"{IDP}/token", timeout=TIMEOUT, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": "cli-tool", "device_code": device["device_code"],
    }).json()
    assert pending["error"] == "authorization_pending"


def test_an_unknown_user_code_is_refused():
    page = user_decides("ZZZZZZZZ", "user", "user")
    assert "Invalid or expired user code" in page.text


def test_a_device_code_gives_tokens_once():
    device = request_device_code()
    result = poll_in_background(device)
    user_decides(device["user_code"], "user", "user")
    result()
    # A short deadline, so a CLI that retried every error would fail here
    # within seconds instead of polling for the code's full lifetime
    with pytest.raises(LoginFailed, match="invalid_grant"):
        poll_for_token(dict(device, expires_in=3), sleep=lambda seconds: time.sleep(0.05))


def test_refresh_tokens_rotate_and_a_reused_one_revokes_the_rest():
    device = request_device_code()
    result = poll_in_background(device)
    user_decides(device["user_code"], "user", "user")
    first = result()["tokens"]["refresh_token"]

    second = refresh(first)["refresh_token"]
    assert second != first
    # Using the old one again is treated as theft: it fails, and it revokes
    # the newest one too, so the CLI must log in again
    with pytest.raises(LoginFailed, match="invalid_grant"):
        refresh(first)
    with pytest.raises(LoginFailed, match="invalid_grant"):
        refresh(second)
