"""The runtime store contract's parameters (#235, #404): which store factories
and which repositories every contract test runs against.

A later backend (#354) runs the whole contract, the atomic operations
included, by adding its factory to ``STORE_FACTORIES``.
"""

import pytest

from nanoidp.config import OAuthClient, User
from nanoidp.services.dynamic_registration import DynamicRegistration
from nanoidp.services.runtime_identities import MemoryRuntimeIdentityStore

REDIRECT = "http://localhost:3000/callback"


def user(name: str, password: str = "pw") -> User:
    return User(username=name, password=password, email=f"{name}@runtime.test")


def client(client_id: str, secret: str = "runtime-secret") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_secret=secret,
        redirect_uris=[REDIRECT],
        allowed_scopes=["openid", "profile", "email"],
    )


def registration(client_id: str) -> DynamicRegistration:
    return DynamicRegistration(
        client_id=client_id,
        registration_token_hash="0" * 64,
        client_id_issued_at=0,
        grant_types=["authorization_code"],
    )


STORE_FACTORIES = [pytest.param(MemoryRuntimeIdentityStore, id="memory")]
# Each entry: how to reach the repository on a store, how to make an object,
# its name, and a list field to mutate in place. The third one is a record
# type the store does not know (#190): it is lent the same machinery through
# repository(), so it owes the same contract.
REPOSITORIES = [
    pytest.param(
        (lambda store: store.users, user, lambda u: u.username, lambda u: u.roles),
        id="users",
    ),
    pytest.param(
        (
            lambda store: store.clients,
            client,
            lambda c: c.client_id,
            lambda c: c.redirect_uris,
        ),
        id="clients",
    ),
    pytest.param(
        (
            lambda store: store.repository(
                "dynamic_registrations", lambda r: r.client_id
            ),
            registration,
            lambda r: r.client_id,
            lambda r: r.grant_types,
        ),
        id="dynamic_registrations",
    ),
]


