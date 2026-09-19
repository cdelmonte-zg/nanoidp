"""Dynamic client registration records (#190).

A client registered through RFC 7591 is an ordinary runtime client: the
resolver decides that it exists and may be used, exactly as for one created
through ``/api/runtime``. What this module keeps beside it is the little
that is not the client - the credential RFC 7592 manages it with, and the
metadata the registration response has to reproduce.

The record is never the source of truth for existence. A runtime client can
go away while a record survives: promoted into the declared configuration,
deleted, or shadowed by a reload. Rather than teach ``services.identities``
about registration, every read checks that the client is still there and
drops the record if it is not, and ``prune_stale_registrations`` does the
same sweep for the records nobody asks about. ``source: dcr`` on a client is
therefore derived from a live record, never from the shape of its id.

Those checks are by name, so they hold only while no other client can take
the name between two visits to the store. The callers see to that: every
operation that touches a client and its record, the check of a credential
included, runs inside ``IdentityResolver.runtime_client_lifecycle`` (#403).
"""

import hashlib
import logging
import secrets
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from ..config import OAuthClient
from ..security import verify_secret
from .identities import IdentityResolver
from .redirect_uri import redirect_uri_rejection_reason
from .runtime_identities import MemoryRuntimeRepository, get_runtime_identity_store

logger = logging.getLogger(__name__)

# The prefix is a human hint in a log or an audit entry, nothing more: what
# makes a client a registered one is a live record, not its name.
CLIENT_ID_PREFIX = "dcr-"
_ID_ATTEMPTS = 5


class DynamicRegistration(BaseModel):
    """What RFC 7592 needs beside the client it manages.

    Only what the ``OAuthClient`` does not already carry: the rest of the
    registration response (``redirect_uris``, the auth method, the scopes,
    the name) is read back from the client itself, so the two cannot
    disagree about the same field.
    """

    client_id: str
    # sha256 of the value handed out once at registration. A random token of
    # this size needs no password KDF; what a hash buys is that the store
    # cannot hand the credential to anything that reads it.
    registration_token_hash: str
    client_id_issued_at: int
    # Validated against the server's own grant types and echoed back,
    # never enforced per client: nanoidp has no per-client grant rule and
    # this issue does not invent one.
    grant_types: List[str] = Field(default_factory=list)


def new_registration_token() -> str:
    """The credential handed out once, at registration."""
    return secrets.token_urlsafe(32)


def new_client_secret() -> str:
    """The secret a confidential registration is issued, same strength as
    the one the UI generates for a declared client."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: str, registration: DynamicRegistration) -> bool:
    """Constant time, like every other secret comparison here."""
    return verify_secret(token_hash(token), registration.registration_token_hash)


def registrations() -> MemoryRuntimeRepository[DynamicRegistration]:
    """The repository the runtime store keeps for this module."""
    return get_runtime_identity_store().repository(
        "dynamic_registrations", lambda registration: registration.client_id
    )


def new_client_id(identities: IdentityResolver) -> str:
    """An id the server picks, not one the client asks for (RFC 7591).

    A collision with a name that already exists is not impossible, only
    unlikely, and a declared one would be refused later by the resolver
    anyway, so the generation retries rather than assuming.
    """
    for _ in range(_ID_ATTEMPTS):
        candidate = f"{CLIENT_ID_PREFIX}{secrets.token_urlsafe(12)}"
        if identities.resolve_client(candidate) is None:
            return candidate
    raise RuntimeError("could not generate an unused client_id")


def _client_is_gone(client_id: str, identities: IdentityResolver) -> bool:
    """The registration outlived the runtime client it managed.

    By name, which is all a record has: this cannot tell the client it was
    issued for from a later one created under the same name. What keeps a
    record from being inherited is that it never survives its client - every
    surface that removes one drops the record with it, in the same lifecycle
    scope, so no client is created in between (#403), and the sweep after a
    configuration load catches promotion, which is the case nothing else
    would. Code embedding nanoidp that calls
    ``IdentityResolver.delete_runtime_client`` directly, and creates another
    client of that name before the next load, is the one path that would.
    """
    resolved = identities.resolve_client(client_id)
    return resolved is None or resolved.origin != "runtime"


def prune_stale_registrations(identities: IdentityResolver) -> int:
    """Drop the records whose runtime client is gone, and say how many.

    Without this, a record left behind by a promotion or a reset would sit
    in the repository until someone happened to ask for its registration
    URI, and would keep counting against the capacity limit. Called before
    the capacity check, so the limit counts live registrations.
    """
    dropped = 0
    for registration in registrations().list():
        if _client_is_gone(registration.client_id, identities):
            if registrations().delete(registration.client_id):
                dropped += 1
    if dropped:
        logger.debug("Dropped %d dynamic registration(s) whose client is gone", dropped)
    return dropped


def live_registration(
    client_id: str, identities: IdentityResolver
) -> Optional[DynamicRegistration]:
    """The record for a client that is still a runtime client, or nothing.

    The one read RFC 7592 goes through, so a promoted, deleted or shadowed
    client answers as an unknown registration rather than as one whose
    credential still works.
    """
    registration = registrations().get(client_id)
    if registration is None:
        return None
    if _client_is_gone(client_id, identities):
        registrations().delete(client_id)
        return None
    return registration


def record_registration(
    client_id: str, grant_types: List[str], token: str
) -> DynamicRegistration:
    """Keep the record for a client that has just been created."""
    registration = DynamicRegistration(
        client_id=client_id,
        registration_token_hash=token_hash(token),
        client_id_issued_at=int(time.time()),
        grant_types=list(grant_types),
    )
    return registrations().create(registration)


def forget_registration(client_id: str) -> bool:
    return registrations().delete(client_id)


class RegistrationRejected(ValueError):
    """The metadata cannot become a client. Carries the RFC 7591 error code.

    ``invalid_redirect_uri`` and ``invalid_client_metadata`` are the two the
    specification defines that apply here; nothing else is invented, and the
    description never repeats a value the caller sent.
    """

    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


DEFAULT_GRANT_TYPES = ("authorization_code",)
# RFC 7591 section 2: absent means client_secret_basic, so a secret is issued
# unless the client asks to be public.
DEFAULT_AUTH_METHOD = "client_secret_basic"


def _string_list(data: Dict[str, Any], field: str) -> List[str]:
    value = data.get(field)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RegistrationRejected(
            "invalid_client_metadata", f"{field} must be a list of strings"
        )
    return value


def translate_registration_request(
    data: Any,
    supported_grant_types: Sequence[str],
    supported_auth_methods: Sequence[str],
    vocabulary: Sequence[str],
) -> Tuple[Dict[str, Any], List[str]]:
    """RFC 7591 metadata to the fields a client entry is made of.

    Only the subset nanoidp understands is read. Every other member is
    ignored rather than refused, which is what the specification asks of a
    server for metadata it does not understand: a client that sends
    ``software_statement`` or ``logo_uri`` registers, without those becoming
    a promise nanoidp does not keep.

    Returns the entry fields and the grant types, which are kept as
    registration metadata rather than written onto the client: nanoidp has
    no per-client grant rule to apply them to.
    """
    if not isinstance(data, dict):
        raise RegistrationRejected("invalid_client_metadata", "the body must be a JSON object")

    grant_types = _string_list(data, "grant_types") or list(DEFAULT_GRANT_TYPES)
    unsupported = [grant for grant in grant_types if grant not in supported_grant_types]
    if unsupported:
        raise RegistrationRejected(
            "invalid_client_metadata",
            "grant_types includes a grant this server does not support",
        )

    method = data.get("token_endpoint_auth_method", DEFAULT_AUTH_METHOD)
    if not isinstance(method, str) or method not in supported_auth_methods:
        raise RegistrationRejected(
            "invalid_client_metadata",
            "token_endpoint_auth_method is not one this server supports",
        )

    redirect_uris = _string_list(data, "redirect_uris")
    if not redirect_uris:
        # Never conditional on the grant types: those are recorded and not
        # enforced, so a registration naming only client_credentials would
        # otherwise get an empty list, which the model reads as "any
        # redirect URI is acceptable". That is a fine default for an
        # operator writing YAML and an open redirect for metadata that
        # arrived over the network.
        raise RegistrationRejected(
            "invalid_redirect_uri", "at least one redirect_uri is required"
        )
    for uri in redirect_uris:
        # Through the gate /authorize applies, not a second reading of it
        # (#196 review): services.redirect_uri exists to be the only home
        # for this, and it knows what this had missed - RFC 6749 forbids a
        # fragment, and RFC 8252 has a rule for private-use schemes.
        rejection = redirect_uri_rejection_reason(uri)
        if rejection is not None:
            raise RegistrationRejected("invalid_redirect_uri", rejection)

    entry: Dict[str, Any] = {
        "client_id": "",  # the caller fills in the id the server picked
        "token_endpoint_auth_method": method,
        "redirect_uris": redirect_uris,
    }

    scope = data.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise RegistrationRejected("invalid_client_metadata", "scope must be a string")
    requested = scope.split() if isinstance(scope, str) else []
    if requested:
        granted = [name for name in requested if name in vocabulary]
        if not granted:
            # An empty allowed_scopes means "every scope" (#186), so
            # narrowing to nothing would widen the client instead.
            raise RegistrationRejected(
                "invalid_client_metadata",
                "scope names none of the scopes this server supports",
            )
    else:
        # Asked for nothing, or asked with an empty string: the scopes are
        # still written out rather than left as the unrestricted marker, so
        # the registration says what it granted and a vocabulary that grows
        # later does not silently grow this client with it.
        granted = list(vocabulary)
    entry["allowed_scopes"] = granted

    name = data.get("client_name")
    if name is not None:
        if not isinstance(name, str):
            raise RegistrationRejected("invalid_client_metadata", "client_name must be a string")
        entry["description"] = name

    return entry, grant_types


def registration_response(
    client: OAuthClient,
    registration: DynamicRegistration,
    token: str,
    issuer: str,
    include_secret: bool,
) -> Dict[str, Any]:
    """The RFC 7591 registration response, and RFC 7592's read of it.

    Built from the client itself, so the two surfaces cannot describe the
    same registration differently. ``token`` is the raw credential: handed
    out once here, and on a read it is the one the caller has just presented,
    which is why the server never has to keep it.
    """
    body: Dict[str, Any] = {
        "client_id": client.client_id,
        "client_id_issued_at": registration.client_id_issued_at,
        "registration_access_token": token,
        "registration_client_uri": f"{issuer.rstrip('/')}/register/{client.client_id}",
        "redirect_uris": list(client.redirect_uris),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "grant_types": list(registration.grant_types),
    }
    if include_secret and client.client_secret is not None:
        body["client_secret"] = client.client_secret
        # RFC 7591: 0 means the secret does not expire. nanoidp has no
        # expiry for client secrets, declared or registered.
        body["client_secret_expires_at"] = 0
    if client.allowed_scopes:
        body["scope"] = " ".join(client.allowed_scopes)
    if client.description:
        body["client_name"] = client.description
    return body
