"""Shared effective-issuer resolution for request-handling routes.

Every HTTP endpoint that mints a token or advertises the issuer must resolve
it the same way, or a token's ``iss`` can disagree with what discovery
advertised for the same hostname (#133: ``/api/users/<username>/token`` used
the fixed issuer while ``/token`` and discovery reflected the request). The
MCP tools are the one documented exception: they have no HTTP request of
their own and always use the fixed ``settings.issuer``.
"""

from flask import request

from ..config import Settings


def effective_issuer(settings: Settings) -> str:
    """The issuer for the current request: fixed, unless opted into reflecting
    how this request actually reached NanoIDP.

    Docker Compose / multi-hostname dev setups often make the same NanoIDP
    reachable at more than one hostname (e.g. ``nanoidp:9900`` from other
    containers, ``localhost:9900`` from the host browser), each of which must
    see a matching issuer: OIDC Discovery requires the document's ``issuer``
    to exactly equal the URL it was fetched from, and a token's ``iss`` must
    match what discovery advertised. Off by default, so every existing
    deployment keeps its fixed, configured issuer.

    When ``issuer_allowlist`` is non-empty, a request whose Host doesn't match
    any allowed origin falls back to the fixed ``issuer`` rather than
    reflecting an arbitrary Host header.
    """
    if not settings.issuer_from_request:
        return settings.issuer
    candidate = request.host_url.rstrip("/")
    if settings.issuer_allowlist and candidate not in settings.issuer_allowlist:
        return settings.issuer
    return candidate


def effective_saml_entity_id(settings: Settings) -> str:
    """SAML entityID for the current request (#181).

    Explicit ``saml.entity_id`` wins; otherwise ``<effective issuer>/saml``,
    so the metadata a SAML SP fetches through a proxy or a second hostname
    names the same origin OIDC discovery does. SAML 2.0 Metadata 2.3.2:
    ``entityID`` is the unique identifier the entity uses as ``<Issuer>``
    (Core 2.2.5), which is why responses and assertions call this too.
    """
    return settings.resolve_saml_entity_id(effective_issuer(settings))


def effective_saml_sso_url(settings: Settings) -> str:
    """SAML SingleSignOnService location for the current request (#181)."""
    return settings.resolve_saml_sso_url(effective_issuer(settings))
