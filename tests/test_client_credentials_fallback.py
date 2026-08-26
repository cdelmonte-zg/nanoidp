"""
Issue #241: the client_credentials service-account fallback must not 500.

When ``default_user`` names a user that does not exist, the grant mints for a
synthetic ``service-account`` user. Since #158 ``User.password`` rejects the
empty string, so the fallback has to be built without a password.
"""

import base64
import json

import jwt as pyjwt

from nanoidp.config import get_config

BASIC = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def test_missing_default_user_falls_back_to_the_service_account(app, client):
    with app.app_context():
        config = get_config()
        assert config.get_user("nobody-here") is None
        config.default_user = "nobody-here"

    response = client.post("/token", data={"grant_type": "client_credentials"}, headers=BASIC)

    assert response.status_code == 200, response.data
    payload = pyjwt.decode(
        json.loads(response.data)["access_token"], options={"verify_signature": False}
    )
    assert payload["sub"] == "service-account"
    assert payload["roles"] == ["user"]


def test_existing_default_user_is_still_preferred(app, client):
    with app.app_context():
        default_user = get_config().default_user

    response = client.post("/token", data={"grant_type": "client_credentials"}, headers=BASIC)

    payload = pyjwt.decode(
        json.loads(response.data)["access_token"], options={"verify_signature": False}
    )
    assert payload["sub"] == default_user
