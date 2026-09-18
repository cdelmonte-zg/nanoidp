"""The parts of a SAML Response that every builder spells the same way (#317).

Three builders in ``routes/saml.py`` produce a ``Response``: the SSO login
assertion, the attribute-query assertion, and the attribute-query error
response for an unknown principal (#275). They were written independently,
so the identical parts, the envelope, the ``Issuer`` pair, the status
element and the assertion's own head, existed three times over, and a
change to the NameID policy had to be made in each.

What this module knows is the structural identity of a Response and an
Assertion. What it deliberately does NOT know is why an SSO assertion names
an audience, why an attribute query is valid for an hour where a login
assertion is valid for five minutes, how either document is serialized, or
how it is signed. Those differ between the builders, are declared in
book/src/reference/saml.md, and stay with the builder they belong to: the
#317 census found two of them (the Conditions window and the ``ds``
namespace) undocumented and untested, which is the opposite of the reason
to share code.

``issued_at`` is passed in rather than read here: the caller owns "now", so
one document cannot carry two different instants, and a test can freeze it.
"""

from datetime import datetime
from typing import Mapping, Optional, Tuple

from lxml import etree

SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML2P_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

#: The namespaces every Response declares. A builder that needs more (the
#: SSO one declares ``ds`` for the signature) passes them alongside.
BASE_NSMAP: Mapping[str, str] = {"saml2p": SAML2P_NS, "saml2": SAML2_NS}

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
STATUS_UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

#: The NameID format all three builders assert. nanoidp names a principal by
#: the username it was looked up with, which is neither persistent nor
#: transient in the SAML sense.
NAMEID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

_INSTANT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def saml_instant(moment: datetime) -> str:
    """A SAML timestamp: UTC, second precision, no offset."""
    return moment.strftime(_INSTANT_FORMAT)


def build_response_envelope(
    *,
    issuer: str,
    issued_at: datetime,
    extra_namespaces: Optional[Mapping[str, str]] = None,
    extra_attributes: Optional[Mapping[str, str]] = None,
    response_id: str,
) -> "etree._Element":
    """A ``Response`` carrying its ``Issuer``, and nothing else yet.

    ``extra_attributes`` are set after ``ID``/``Version``/``IssueInstant``
    and in the order given: lxml serializes attributes in insertion order,
    and what a service provider receives is the exact byte sequence, so the
    order is part of the output rather than an implementation detail.
    """
    nsmap = dict(BASE_NSMAP)
    if extra_namespaces:
        nsmap.update(extra_namespaces)

    response = etree.Element(
        f"{{{SAML2P_NS}}}Response",
        nsmap=nsmap,
        ID=response_id,
        Version="2.0",
        IssueInstant=saml_instant(issued_at),
    )
    for name, value in (extra_attributes or {}).items():
        response.set(name, value)

    issuer_element = etree.SubElement(response, f"{{{SAML2_NS}}}Issuer")
    issuer_element.text = issuer
    return response


def append_status(
    response: "etree._Element", *, value: str, subordinate: Optional[str] = None
) -> None:
    """The ``Status`` element, with an optional second-level code.

    A subordinate code is how SAML 2.0 Core 3.2.2.2 says what went wrong
    under a top-level Requester or Responder; a success carries none.
    """
    status = etree.SubElement(response, f"{{{SAML2P_NS}}}Status")
    status_code = etree.SubElement(status, f"{{{SAML2P_NS}}}StatusCode")
    status_code.set("Value", value)
    if subordinate:
        sub_code = etree.SubElement(status_code, f"{{{SAML2P_NS}}}StatusCode")
        sub_code.set("Value", subordinate)


def build_assertion_core(
    response: "etree._Element",
    *,
    issuer: str,
    issued_at: datetime,
    name_id: str,
    assertion_id: str,
) -> Tuple["etree._Element", "etree._Element"]:
    """The assertion's head: its own ``Issuer``, ``Subject`` and ``NameID``.

    Returns the assertion and its subject, because what each builder adds
    next goes to a different one of the two: the SSO builder confirms the
    subject and then states an authentication under the assertion, the
    attribute query states neither.

    Conditions are NOT built here. The two windows differ (five minutes
    against one hour) and nobody has decided whether they are one policy, so
    folding them in behind a ``ttl`` argument would turn a difference this
    refactor documented into an abstraction that hides it again.
    """
    assertion = etree.SubElement(
        response,
        f"{{{SAML2_NS}}}Assertion",
        ID=assertion_id,
        Version="2.0",
        IssueInstant=saml_instant(issued_at),
    )
    assertion_issuer = etree.SubElement(assertion, f"{{{SAML2_NS}}}Issuer")
    assertion_issuer.text = issuer

    subject = etree.SubElement(assertion, f"{{{SAML2_NS}}}Subject")
    nameid = etree.SubElement(
        subject, f"{{{SAML2_NS}}}NameID", Format=NAMEID_FORMAT_UNSPECIFIED
    )
    nameid.text = name_id
    return assertion, subject
