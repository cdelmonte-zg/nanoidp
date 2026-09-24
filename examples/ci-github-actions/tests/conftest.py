import os
import uuid

import pytest
import requests

IDP = os.environ.get("NANOIDP_URL", "http://localhost:8000")


@pytest.fixture
def test_user():
    """A user that exists for one test only, under a name no other test uses."""
    user = {
        "username": f"ci-{uuid.uuid4().hex[:12]}",
        "password": uuid.uuid4().hex,
        "roles": ["TESTER"],
    }
    created = requests.post(f"{IDP}/api/runtime/users", json=user)
    assert created.status_code == 201, created.text
    yield user
    # Delete this user by name, never with DELETE /api/runtime: that removes
    # every runtime identity, including those of tests running in parallel
    requests.delete(f"{IDP}/api/runtime/users/{user['username']}")


def password_token(user, **extra):
    """A token for the user, from the client every default config declares."""
    return requests.post(f"{IDP}/token", auth=("demo-client", "demo-secret"), data={
        "grant_type": "password",
        "username": user["username"], "password": user["password"], **extra,
    })
