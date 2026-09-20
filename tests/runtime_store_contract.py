"""The runtime store contract's parameters (#235, #404): which store factories
and which repositories every contract test runs against.

A later backend (#354) runs the whole contract, the atomic operations
included, by adding its factory to ``STORE_FACTORIES``.
"""

import dataclasses
import datetime
from typing import Any, List

import pytest

from nanoidp.config import OAuthClient, User
from nanoidp.services.dynamic_registration import DynamicRegistration
from nanoidp.services.runtime_identities import MemoryRuntimeIdentityStore, PydanticCodec

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
        client_instance="0" * 32,
        registration_token_hash="0" * 64,
        client_id_issued_at=0,
        grant_types=["authorization_code"],
    )


@dataclasses.dataclass
class Grant:
    """A record that is not a pydantic model, with a field JSON has no type
    for: what the protocol state of #363 looks like (authorization codes,
    device codes and audit entries are dataclasses with datetimes)."""

    code: str
    expires_at: datetime.datetime
    scopes: List[str] = dataclasses.field(default_factory=list)


class GrantCodec:
    def copy(self, value: Grant) -> Grant:
        return dataclasses.replace(value, scopes=list(value.scopes))

    def dump(self, value: Grant) -> Any:
        return {"code": value.code, "expires_at": value.expires_at.isoformat(), "scopes": value.scopes}

    def load(self, data: Any) -> Grant:
        return Grant(data["code"], datetime.datetime.fromisoformat(data["expires_at"]), list(data["scopes"]))


def grant(code: str) -> Grant:
    return Grant(code, datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc), ["openid"])


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
                "dynamic_registrations", lambda r: r.client_id, PydanticCodec(DynamicRegistration)
            ),
            registration,
            lambda r: r.client_id,
            lambda r: r.grant_types,
        ),
        id="dynamic_registrations",
    ),
    pytest.param(
        (
            lambda store: store.repository("grants", lambda g: g.code, GrantCodec()),
            grant,
            lambda g: g.code,
            lambda g: g.scopes,
        ),
        id="a_dataclass",
    ),
]


