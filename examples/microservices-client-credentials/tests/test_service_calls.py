"""order-service calls the inventory API with a client_credentials token.

Needs NanoIDP on :8000 with this preset and the inventory API
(inventory-api/) on :8081.
"""
import jwt
import requests

IDP = "http://localhost:8000"
INVENTORY_API = "http://localhost:8081"
INVENTORY = "https://inventory.internal"   # the inventory API's audience
TIMEOUT = 10  # seconds: a stuck server fails the test instead of hanging it


def token_request(client_id, secret, scope=None, resource=None):
    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    if resource:
        data["resource"] = resource  # RFC 8707: the token's aud becomes this
    return requests.post(f"{IDP}/token", auth=(client_id, secret), data=data,
                         timeout=TIMEOUT)


def token(client_id, secret, scope=None, resource=None):
    response = token_request(client_id, secret, scope, resource)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def call(method, path, access_token=None):
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    return requests.request(method, INVENTORY_API + path, headers=headers,
                            timeout=TIMEOUT)


ORDER_SERVICE = ("order-service", "order-service-secret")


# What the inventory API accepts

def test_order_service_reads_stock():
    access = token(*ORDER_SERVICE, scope="inventory:read", resource=INVENTORY)
    response = call("GET", "/stock/sku-1", access)
    assert response.status_code == 200
    assert response.json()["caller"] == "order-service"


def test_reserving_needs_the_reserve_scope():
    read_only = token(*ORDER_SERVICE, scope="inventory:read", resource=INVENTORY)
    assert call("POST", "/reservations", read_only).status_code == 403
    both = token(*ORDER_SERVICE, scope="inventory:read inventory:reserve",
                 resource=INVENTORY)
    assert call("POST", "/reservations", both).status_code == 200


# What the inventory API refuses

def test_no_token_is_refused():
    assert call("GET", "/stock/sku-1").status_code == 401


def test_a_token_without_a_resource_is_refused():
    # aud is oauth.audience ("microservices"), not this API's audience
    access = token(*ORDER_SERVICE, scope="inventory:read")
    assert call("GET", "/stock/sku-1", access).status_code == 401


def test_a_token_for_another_service_is_refused():
    access = token("notification-service", "notification-service-secret",
                   scope="orders:read", resource="https://orders.internal")
    assert call("GET", "/stock/sku-1", access).status_code == 401


# What NanoIDP refuses to issue

def test_a_scope_the_client_may_not_have():
    response = token_request(*ORDER_SERVICE, scope="orders:read", resource=INVENTORY)
    assert response.json()["error"] == "invalid_scope"


def test_a_resource_the_client_may_not_target():
    response = token_request(*ORDER_SERVICE, scope="inventory:read",
                             resource="https://orders.internal")
    assert response.json()["error"] == "invalid_target"


def test_a_wrong_secret():
    response = token_request("order-service", "wrong", scope="inventory:read")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


# What the token says about the caller

def test_the_caller_is_the_client_id_and_carries_no_user_privileges():
    access = token(*ORDER_SERVICE, scope="inventory:read", resource=INVENTORY)
    claims = jwt.decode(access, options={"verify_signature": False})
    assert claims["client_id"] == "order-service"
    assert claims["aud"] == INVENTORY
    # The token is the client's own (RFC 9068 §2.2): its subject is the
    # client, and no user's roles or attributes come with it
    assert claims["sub"] == "order-service"
    for user_claim in ("roles", "authorities", "tenant", "entitlements", "groups", "attributes"):
        assert user_claim not in claims
