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

Those checks are by instance, not by name (#403, #404). A record carries the
``instance_id`` the store gave its client, and a client created under the
same id later is another instance, so a record that outlives its client is
an orphan that matches nothing: it authenticates nothing, it labels nothing
``source: dcr``, and removing it is tidiness. What touches both the client
and the record is built from that identity, a conditional delete and, for
registering, a compensation and a postcondition (``routes.registration``),
with no lock around the pair and no transaction across the two
repositories. That much, the pairing of a record with its client, holds
for whoever shares the store. What a runtime client itself still rests on
within one process (the check against the declared names, the promotion
marks, a reset and a reconciliation that go by name) is #405's.
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
from .runtime_identities import (
    MemoryRuntimeRepository,
    PydanticCodec,
    get_runtime_identity_store,
)
from .runtime_repository import Entry, consume, create_within, delete_if

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
    # The instance of the runtime client this record was issued for (#404):
    # the store's identity for it, not a field of the client. A record is
    # about that instance and no other that later goes by the same id.
    client_instance: str
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
        "dynamic_registrations",
        lambda registration: registration.client_id,
        PydanticCodec(DynamicRegistration),
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


class RegistrationLimitReached(Exception):
    """The server holds as many dynamic registrations as it accepts."""


def managed_client(
    registration: DynamicRegistration, identities: IdentityResolver
) -> Optional[OAuthClient]:
    """The runtime client this record is about, by value, or nothing.

    The one home of the rule, by instance and not by name (#403, #404): a
    client deleted and created again under the id is another client, and a
    record issued for the first says nothing about the second. So a record
    that outlives its client, for whatever reason and for however long, is
    an orphan that matches nothing, and everything below is a comparison
    rather than an order of steps somebody has to keep. What RFC 7592
    answers with is this client, never whoever holds the id by then.

    The origin is asked too. A load that declares the id assigns the new
    configuration before its reconciliation retires the runtime client, and
    in between the client that answers to the id is the declared one: the
    registration has ended, even though its instance is still in the store.
    """
    resolved = identities.resolve_client(registration.client_id)
    if resolved is None or resolved.origin != "runtime":
        return None
    entry = identities.store.clients.entry(registration.client_id)
    if entry is None or entry.instance_id != registration.client_instance:
        return None
    return entry.value


def prune_stale_registrations(identities: IdentityResolver) -> int:
    """Drop the records whose runtime client is gone, and say how many.

    Housekeeping, not protection: an orphan record authenticates nothing.
    Without this it would sit in the repository until someone happened to
    ask for its registration URI, and would keep counting against the
    capacity limit. Each one goes by its own instance, so a record created
    under the same id since this one was read is left alone.
    """
    dropped = 0
    for entry in registrations().entries():
        if managed_client(entry.value, identities) is None:
            if delete_if(registrations(), entry.name, entry.instance_id):
                dropped += 1
    if dropped:
        logger.debug("Dropped %d dynamic registration(s) whose client is gone", dropped)
    return dropped


def live_registration_and_client(
    client_id: str, identities: IdentityResolver
) -> Optional[Tuple[DynamicRegistration, OAuthClient]]:
    """The record for a client that is still the runtime client it was
    issued for, with that client, or nothing.

    The one read RFC 7592 goes through, so a promoted, deleted, recreated
    or shadowed client answers as an unknown registration rather than as one
    whose credential still works. A record found stale is dropped on the
    way past, by its own instance.
    """
    entry = registrations().entry(client_id)
    if entry is None:
        return None
    client = managed_client(entry.value, identities)
    if client is None:
        delete_if(registrations(), client_id, entry.instance_id)
        return None
    return entry.value, client


def live_registration(
    client_id: str, identities: IdentityResolver
) -> Optional[DynamicRegistration]:
    """``live_registration_and_client`` for a caller that needs the record
    only, such as the ``source: dcr`` label."""
    found = live_registration_and_client(client_id, identities)
    return found[0] if found is not None else None


def record_registration(
    client: Entry[OAuthClient], grant_types: List[str], token: str, limit: int
) -> Entry[DynamicRegistration]:
    """Keep the record for the client instance that has just been created.
    Raises RegistrationLimitReached: the limit is the only bound an open
    endpoint has, so the count and the create are one step."""
    registration = DynamicRegistration(
        client_id=client.name,
        client_instance=client.instance_id,
        registration_token_hash=token_hash(token),
        client_id_issued_at=int(time.time()),
        grant_types=list(grant_types),
    )
    return create_within(registrations(), registration, limit, full=RegistrationLimitReached())


def forget_registration_of(client: Entry[OAuthClient]) -> bool:
    """Drop the record issued for that client instance, if there is one."""
    return forget_registration_for(client.name, client.instance_id)


def forget_registration_for(client_id: str, client_instance: str) -> bool:
    """``forget_registration_of`` for a caller that knows the instance and no
    longer has the client: it went behind the registration's back."""
    removed = consume(
        registrations(),
        client_id,
        lambda entry: entry.value.client_instance == client_instance,
    )
    return removed is not None


def delete_client_and_registration(
    client_id: str, identities: IdentityResolver, client_instance: Optional[str] = None
) -> None:
    """Remove a runtime client, and the record issued for it if any.

    The one way a surface deletes a runtime client (#403), registered or
    not. ``client_instance`` is the instance that is meant, for a caller
    that holds a credential for one (RFC 7592): the client that took the id
    since is not that one and stays. After the client and not before, so a
    delete the resolver refuses (``PromotionInProgress``,
    ``RuntimeObjectNotFound``) has changed nothing; both propagate. The
    record goes for tidiness: once its client is gone it matches nothing.
    """
    removed = identities.delete_runtime_client(client_id, client_instance)
    forget_registration_of(removed)


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
