"""Who an access token is about (#445).

A module of its own at the package root, with no imports from the package,
so that the configuration loader, the pure services (``introspection``) and
the routes can share the one rule across the import layers.
"""

from typing import Any, Mapping, Optional


def names_no_end_user(payload: Mapping[str, Any]) -> bool:
    """Whether an access token's subject is its client, so that no end user
    stands behind it: client_credentials issues exactly those (#445).

    Fail-safe for a user and a client of the same name: such a token is
    never resolved as the user, so /userinfo answers the subject alone and
    /introspect names no resource owner, at worst losing UserInfo for that
    ambiguous user, never disclosing a user's profile to a client."""
    subject = payload.get("sub")
    return subject is not None and subject == payload.get("client_id")


def end_user_of(payload: Mapping[str, Any]) -> Optional[str]:
    """The user a token is about, for the lookups and the audit trail:
    its ``sub``, or None when the token is its client's own."""
    return None if names_no_end_user(payload) else payload.get("sub")


def shared_name_warning(name: str) -> str:
    """What a user and a client of the same name means, for the warning the
    load and the runtime API log: not refused, since configurations that do
    this load today, but said, since the name's tokens change meaning."""
    return (
        f"{name!r} is both a user and a client: a token whose subject and "
        f"client are both {name!r} is taken as the client's own "
        "(client_credentials), so /userinfo answers it with the subject alone "
        "and /introspect names no user (#445)"
    )
