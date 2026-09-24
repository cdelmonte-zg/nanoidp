import jwt
import pytest
import requests
from conftest import IDP, password_token


@pytest.mark.parametrize("attempt", range(8))
def test_each_test_gets_its_own_user(test_user, attempt):
    response = password_token(test_user)
    assert response.status_code == 200, response.text
    claims = jwt.decode(response.json()["access_token"],
                        options={"verify_signature": False})
    assert claims["sub"] == test_user["username"]
    assert claims["roles"] == ["TESTER"]


def test_a_deleted_user_cannot_log_in(test_user):
    requests.delete(f"{IDP}/api/runtime/users/{test_user['username']}")
    assert password_token(test_user).json()["error"] == "invalid_grant"


def test_deleting_a_user_does_not_revoke_its_tokens(test_user):
    tokens = password_token(test_user, scope="openid offline_access").json()
    requests.delete(f"{IDP}/api/runtime/users/{test_user['username']}")

    # The access token taken before the delete is still valid until it expires
    introspection = requests.post(f"{IDP}/introspect", auth=("demo-client", "demo-secret"),
                                  data={"token": tokens["access_token"]}).json()
    assert introspection["active"] is True
    # The refresh token is refused
    refreshed = requests.post(f"{IDP}/token", auth=("demo-client", "demo-secret"), data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
    })
    assert refreshed.json()["error"] == "invalid_grant"
