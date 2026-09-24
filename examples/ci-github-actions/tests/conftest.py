import os
import uuid

import pytest
import requests

IDP = os.environ.get("NANOIDP_URL", "http://localhost:8000")
TIMEOUT = 10  # seconds: a request to a stuck IdP fails instead of hanging


@pytest.fixture
def test_user():
    """A user that exists for one test only, under a name no other test uses."""
    user = {
        "username": f"ci-{uuid.uuid4().hex[:12]}",
        "password": uuid.uuid4().hex,
        "roles": ["TESTER"],
    }
    created = requests.post(f"{IDP}/api/runtime/users", json=user, timeout=TIMEOUT)
    assert created.status_code == 201, created.text
    yield user
    # Delete this user by name, never with DELETE /api/runtime: that removes
    # every runtime identity, including those of tests running in parallel
    deleted = requests.delete(f"{IDP}/api/runtime/users/{user['username']}",
                              timeout=TIMEOUT)
    # 404: the test deleted the user itself, as two tests here do on purpose
    assert deleted.status_code in (200, 404), deleted.text


def password_token(user, **extra):
    """A token for the user, from the client every default config declares."""
    return requests.post(f"{IDP}/token", auth=("demo-client", "demo-secret"), data={
        "grant_type": "password",
        "username": user["username"], "password": user["password"], **extra,
    }, timeout=TIMEOUT)
