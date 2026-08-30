"""
SAML routes for SSO and metadata.
"""

import html
import logging
import uuid
import zlib
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, Response, abort, render_template, request, session
from flask.typing import ResponseReturnValue
from lxml import etree

from ..config import get_config
from ..exceptions import SAMLSignatureError
from ..services import get_crypto_service
from ..services.saml_verification import (
    load_sp_certificates,
    verify_post_signature,
    verify_redirect_signature,
)
from ._audit import audit_event
from ._issuer import effective_saml_entity_id, effective_saml_sso_url

# Create secure XML parser (XXE protection without deprecated defusedxml.lxml)
_secure_parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False,
)


def secure_fromstring(xml_bytes: bytes) -> etree._Element:
    """Parse XML securely, preventing XXE attacks."""
    return etree.fromstring(xml_bytes, parser=_secure_parser)


# Try to import signxml for SAML signing
try:
    from signxml import CanonicalizationMethod, XMLSigner, methods

    SIGNXML_AVAILABLE = True
except ImportError:
    SIGNXML_AVAILABLE = False

logger = logging.getLogger(__name__)


def _get_c14n_algorithm(config_value: str) -> "CanonicalizationMethod":
    """Map config string to CanonicalizationMethod enum.

    Args:
        config_value: Canonicalization algorithm identifier:
            - 'exc_c14n': Exclusive C14N 1.0 (default, standard for SAML)
            - 'c14n': C14N 1.0
            - 'c14n11': C14N 1.1

    Returns:
        CanonicalizationMethod enum value
    """
    if not SIGNXML_AVAILABLE:
        # All callers are inside `if ... SIGNXML_AVAILABLE` guards; raising
        # here (instead of returning None) keeps the return type honest.
        raise RuntimeError("signxml is not available; cannot sign SAML XML")

    if config_value == "c14n":
        return CanonicalizationMethod.CANONICAL_XML_1_0
    if config_value == "c14n11":
        return CanonicalizationMethod.CANONICAL_XML_1_1
    # Default to Exclusive C14N for SAML standard compliance
    return CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0


saml_bp = Blueprint("saml", __name__, url_prefix="/saml")


def _decode_saml_request_bytes(saml_request_b64: str) -> bytes:
    """Decode a SAMLRequest to raw XML bytes, deflate-tolerant (#69).

    Signature verification needs the XML before the full parse; binding
    strictness is still enforced later by ``_parse_saml_request``.
    """
    decoded = b64decode(saml_request_b64)
    try:
        return zlib.decompress(decoded, -zlib.MAX_WBITS)
    except zlib.error:
        return decoded


def _parse_saml_request(
    saml_request_b64: str, http_verb: str, strict: bool = False
) -> Optional[Dict[str, Optional[str]]]:
    """Parse a SAMLRequest to extract ID, ACS URL, and Issuer.

    Args:
        saml_request_b64: Base64-encoded SAMLRequest
        http_verb: HTTP verb used to receive the request ("GET" or "POST").
            Note: This is the transport method, not the SAML binding.
            - GET typically indicates HTTP-Redirect binding (DEFLATE compressed)
            - POST typically indicates HTTP-POST binding (not compressed)
            However, after inline login the verb may not match the original binding.
        strict: If True, enforce SAML 2.0 binding compliance:
            - GET must be DEFLATE compressed
            - POST must NOT be compressed
            If False (default), try decompress first then fallback to raw.

    Note:
        In lenient mode, we always try DEFLATE first then fallback to raw XML.
        This handles the inline login case where the form POSTs but the original
        SAMLRequest may have been from a GET (compressed) request.
    """
    try:
        saml_decoded = b64decode(saml_request_b64)

        if strict:
            if http_verb == "GET":
                # Strict GET: must be DEFLATE compressed per HTTP-Redirect binding
                saml_xml = zlib.decompress(saml_decoded, -zlib.MAX_WBITS)
                logger.debug("Strict mode: decompressed GET request (HTTP-Redirect binding)")
            else:
                # Strict POST: must NOT be compressed per HTTP-POST binding
                saml_xml = saml_decoded
                logger.debug("Strict mode: using raw POST request (HTTP-POST binding)")
        else:
            # Lenient mode: try decompress first, fallback to raw
            # This handles:
            # - GET compressed (HTTP-Redirect) → decompress works
            # - POST uncompressed (HTTP-POST) → decompress fails → use raw
            # - Inline login: original GET compressed, but form POSTs → decompress works
            try:
                saml_xml = zlib.decompress(saml_decoded, -zlib.MAX_WBITS)
                logger.debug("Lenient mode: decompressed OK (likely HTTP-Redirect binding)")
            except zlib.error:
                saml_xml = saml_decoded
                logger.debug("Lenient mode: fallback to raw XML (likely HTTP-POST binding)")

        root = secure_fromstring(saml_xml)

        request_id = root.get("ID")
        acs_url = root.get("AssertionConsumerServiceURL")

        issuer = None
        issuer_el = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        if issuer_el is not None and issuer_el.text:
            issuer = issuer_el.text.strip()

        return {
            "id": request_id,
            "acs_url": acs_url,
            "issuer": issuer,
        }
    except Exception as e:
        logger.warning(f"Failed to parse SAMLRequest: {e}")
        return None


def _add_export_attr(attrs: dict, name: str, values: list) -> None:
    """Add an exported roles/groups attribute, merging on a name collision.

    ``saml_roles_attr_name`` and ``saml_groups_attr_name`` are configured
    independently, so both exports can target the same attribute (e.g.
    ``memberOf``). Plain assignment would let the second list silently replace
    the first (#134); merging keeps both, roles first, deduplicated.
    """
    existing = attrs.get(name)
    if isinstance(existing, (list, tuple)):
        attrs[name] = list(existing) + [v for v in values if v not in existing]
    else:
        attrs[name] = list(values)


def _build_saml_response(
    acs_url: str,
    issuer: str,
    audience: str,
    name_id: str,
    attributes: dict,
    in_response_to: Optional[str] = None,
    sign: bool = True,
    authn_context: str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
) -> bytes:
    """Build a SAML Response XML.

    ``authn_context`` (AuthnContextClassRef) defaults to
    PasswordProtectedTransport - accurate for every existing caller, which
    all authenticate by password. A persona-mode login authenticates by
    identity selection instead, so the caller passes 'unspecified' there;
    claiming PasswordProtectedTransport for that login would be false (#persona
    login design contract, point 6).
    """
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)

    now = datetime.now(timezone.utc)

    def iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    response_id = f"_{uuid.uuid4().hex}"
    assertion_id = f"_{uuid.uuid4().hex}"

    NSMAP = {
        "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }

    resp = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap=NSMAP,
        ID=response_id,
        Version="2.0",
        IssueInstant=iso(now),
        Destination=acs_url,
    )
    if in_response_to:
        resp.set("InResponseTo", in_response_to)

    issuer_el = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer_el.text = issuer

    status = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
    sc = etree.SubElement(status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    sc.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    assertion = etree.SubElement(
        resp,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
        ID=assertion_id,
        Version="2.0",
        IssueInstant=iso(now),
    )
    a_issuer = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    a_issuer.text = issuer

    subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
    nameid = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}NameID",
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    )
    nameid.text = name_id

    subj_conf = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
    )
    subj_conf_data = etree.SubElement(
        subj_conf,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
        NotOnOrAfter=iso(now + timedelta(minutes=5)),
        Recipient=acs_url,
    )
    if in_response_to:
        subj_conf_data.set("InResponseTo", in_response_to)

    cond = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
        NotBefore=iso(now),
        NotOnOrAfter=iso(now + timedelta(minutes=5)),
    )
    audr = etree.SubElement(cond, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")
    aud = etree.SubElement(audr, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
    aud.text = audience

    authn = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
        AuthnInstant=iso(now),
        SessionIndex=f"_{uuid.uuid4().hex}",
    )
    ctx = etree.SubElement(authn, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")
    ctxc = etree.SubElement(ctx, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")
    ctxc.text = authn_context

    if attributes:
        attrs = etree.SubElement(
            assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
        )
        for k, v in attributes.items():
            if v is None:
                continue
            attr = etree.SubElement(
                attrs, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute", Name=k
            )
            if isinstance(v, (list, tuple)):
                for item in v:
                    av = etree.SubElement(
                        attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
                    )
                    av.text = str(item)
            else:
                av = etree.SubElement(attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
                av.text = str(v)

    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

    if sign and SIGNXML_AVAILABLE:
        cert_path = crypto.keys_dir / "idp-cert.pem"
        with open(cert_path, "rb") as f:
            cert_pem = f.read()

        c14n_algo = _get_c14n_algorithm(config.settings.saml_c14n_algorithm)
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm=c14n_algo,
        )
        signed = signer.sign(
            # signxml's typed API takes the certificate as a PEM string
            assertion,
            key=crypto.priv_pem,
            cert=cert_pem.decode("ascii"),
            reference_uri=assertion_id,
        )
        resp.remove(assertion)
        resp.append(signed)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

    return xml


@saml_bp.route("/metadata")
def metadata() -> ResponseReturnValue:
    """SAML IdP Metadata endpoint."""
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)
    settings = config.settings

    NS = {
        "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }

    ent = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor",
        entityID=effective_saml_entity_id(settings),
        nsmap=NS,
    )
    idpsso = etree.SubElement(
        ent,
        "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor",
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
    )
    # Advertised if and only if verification is actually enforced (#69,
    # principle 2: metadata never lies).
    if settings.saml_want_authn_requests_signed:
        idpsso.set("WantAuthnRequestsSigned", "true")

    # KeyDescriptor
    kd = etree.SubElement(
        idpsso, "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor", use="signing"
    )
    ki = etree.SubElement(kd, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
    x509d = etree.SubElement(ki, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
    x509c = etree.SubElement(x509d, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    x509c.text = crypto.get_certificate_base64()

    # SingleSignOnService - support both POST and Redirect bindings
    etree.SubElement(
        idpsso,
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService",
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        Location=effective_saml_sso_url(settings),
    )
    etree.SubElement(
        idpsso,
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService",
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        Location=effective_saml_sso_url(settings),
    )

    xml = etree.tostring(ent, xml_declaration=True, encoding="UTF-8", pretty_print=True)
    return Response(xml, mimetype="application/samlmetadata+xml")


@saml_bp.route("/cert.pem")
def cert() -> ResponseReturnValue:
    """Download the IdP certificate."""
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)
    return Response(crypto.cert_pem, mimetype="application/x-pem-file")


def _verify_authn_request_signature(
    config: Any, saml_request_b64: str, relay_state: str
) -> Optional[ResponseReturnValue]:
    """AuthnRequest signature verification (#69), opt-in via
    saml.want_authn_requests_signed. Verified where the request ENTERS:

    - GET = Redirect binding: query-string signature (Bindings §3.4.4.1).
      The signature only exists on the original URL and cannot survive the
      login-form roundtrip, so the verified request is bound SERVER-SIDE in
      the session; the POST login leg (saml_original_verb=GET) is admitted
      only for values byte-identical to a request this session already
      verified, and fails closed otherwise (#69 review: hidden form fields
      are client-controlled and must not be trusted on their own).
    - POST without saml_original_verb = POST-binding entry: enveloped XML
      signature (Core §5).
    - POST login leg of a POST-binding request (saml_original_verb=POST):
      the signature still travels inside the XML, so it is re-verified.

    Returns the rejection response, or None when the request may proceed
    (verification passed, or the opt-in is off).
    """
    if not config.settings.saml_want_authn_requests_signed:
        return None

    form_leg_verb = (request.form.get("saml_original_verb") or "").upper()
    try:
        if request.method == "GET":
            verify_redirect_signature(
                request.query_string.decode("latin-1"),
                load_sp_certificates(config.settings.saml_sp_certificates),
            )
            # A later Redirect-leg POST may only replay exactly this
            # verified request. Overwritten by each newly verified GET.
            session["saml_verified_redirect"] = {
                "SAMLRequest": saml_request_b64,
                "RelayState": relay_state,
            }
        elif form_leg_verb == "GET":
            verified = session.get("saml_verified_redirect")
            if (
                not isinstance(verified, dict)
                or verified.get("SAMLRequest") != saml_request_b64
                or verified.get("RelayState") != relay_state
            ):
                raise SAMLSignatureError(
                    "Redirect-binding login continuation does not match a "
                    "signature-verified request in this session"
                )
        else:
            xml_bytes = _decode_saml_request_bytes(saml_request_b64)
            verify_post_signature(
                xml_bytes,
                load_sp_certificates(config.settings.saml_sp_certificates),
            )
    except SAMLSignatureError as e:
        audit_event(
            "saml_request",
            "failed",
            endpoint="/saml/sso",
            details={"reason": f"AuthnRequest signature rejected: {e}"},
        )
        return abort(400, description=f"AuthnRequest signature rejected: {e}")
    return None


def _sso_authenticate_inline(
    config: Any, saml_request_b64: str, relay_state: str
) -> tuple[Optional[str], Optional[ResponseReturnValue]]:
    """The inline-login leg: (username, None) once authenticated, or
    (None, login-page response) while not.

    Login happens inline (no redirect) to preserve the original binding
    context. Persona mode authenticates by identity selection only;
    password mode is unchanged.
    """
    username = session.get("user")
    if username:
        return username, None

    persona_mode = config.settings.persona_mode_enabled
    login_error = None

    form_username = request.form.get("username", "").strip()
    form_password = request.form.get("password", "")

    user = config.interactive_authenticate(form_username, form_password)

    if user:
        session["user"] = form_username
        # Recorded so the assertion's AuthnContextClassRef reflects how this
        # session actually authenticated (#persona login design contract,
        # point 6) - persona logins must not claim
        # PasswordProtectedTransport.
        session["auth_method"] = "persona" if persona_mode else "password"
        session.permanent = True
        audit_event(
            "login",
            "success",
            endpoint="/saml/sso",
            username=form_username,
        )
        return form_username, None

    if (persona_mode and form_username) or (not persona_mode and form_username and form_password):
        # A real (failed) selection/login attempt, not just missing input
        login_error = "Invalid credentials"
        audit_event(
            "login",
            "failed",
            endpoint="/saml/sso",
            username=form_username,
            details={"reason": "Invalid credentials"},
        )

    # Still not authenticated - show login form. Pass the original HTTP verb
    # to the template for strict mode parsing after inline login (POST with
    # compressed SAMLRequest from an original GET needs to decompress).
    return None, render_template(
        "login.html",
        error=login_error,
        saml_request=saml_request_b64,
        relay_state=relay_state,
        original_verb=request.method,
        users=config.persona_picker_entries(),
        persona_mode=persona_mode,
    )


def _sso_build_attributes(config: Any, user: Any) -> Dict[str, Any]:
    """The assertion's attribute set for this user.

    Roles/groups are opt-in: they have no standard SAML attribute name, so
    the SP-specific name is configured alongside the switch.
    """
    saml_attrs: Dict[str, Any] = {
        "identity_class": user.identity_class,
        "entitlements": user.entitlements,
        "email": user.email,
    }
    if config.settings.saml_export_roles and user.roles:
        _add_export_attr(saml_attrs, config.settings.saml_roles_attr_name, user.roles)
    if config.settings.saml_export_groups and user.groups:
        _add_export_attr(saml_attrs, config.settings.saml_groups_attr_name, user.groups)
    if user.attributes:
        saml_attrs.update(user.attributes)
    return saml_attrs


def _sso_parse_request(
    config: Any, saml_request_b64: str
) -> tuple[Optional[str], Optional[str], Optional[ResponseReturnValue]]:
    """Parse the SAMLRequest: (acs_url, in_response_to, None) or (None, None, error).

    Signature verification (when enabled) already happened in
    _verify_authn_request_signature (#69); without the opt-in,
    Signature/SigAlg query params are accepted and ignored, as before.

    Uses the original HTTP verb from the form if set (inline login case: an
    original GET's compressed SAMLRequest is POSTed back after the login
    form submission). Normalized to uppercase and validated.
    """
    form_verb = request.form.get("saml_original_verb")
    if form_verb and form_verb.upper() not in ("GET", "POST"):
        return None, None, abort(400, description="invalid saml_original_verb")
    original_verb = (form_verb or request.method or "POST").upper()
    saml_info = _parse_saml_request(
        saml_request_b64, http_verb=original_verb, strict=config.settings.strict_saml_binding
    )

    requested_acs = saml_info.get("acs_url") if saml_info else None
    acs_url = requested_acs or config.settings.default_acs_url
    in_response_to = saml_info.get("id") if saml_info else None
    return acs_url, in_response_to, None


def _sso_success_response(
    config: Any,
    user: Any,
    username: str,
    acs_url: str,
    in_response_to: Optional[str],
    relay_state: str,
) -> ResponseReturnValue:
    """Build, audit and auto-submit the SAML Response for an authenticated user."""
    saml_attrs = _sso_build_attributes(config, user)

    name_id = user.email or f"{username}@example.org"

    # AuthnContextClassRef must reflect how THIS session actually
    # authenticated, not the current server-wide setting - the session may
    # have been authenticated earlier (e.g. via the nanoidp dashboard's own
    # /login) and is only being reused here. Defaults to "password" when
    # unset (sessions predating this feature, or seeded directly in tests),
    # preserving the prior unconditional PasswordProtectedTransport behavior.
    authn_context = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
        if session.get("auth_method", "password") == "persona"
        else "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )

    # Generate SAML Response
    xml = _build_saml_response(
        acs_url=acs_url,
        issuer=effective_saml_entity_id(config.settings),
        audience=config.settings.audience,
        name_id=name_id,
        attributes={k: v for k, v in saml_attrs.items() if v is not None},
        in_response_to=in_response_to,
        sign=config.settings.saml_sign_responses,
        authn_context=authn_context,
    )
    saml_b64 = b64encode(xml).decode("ascii")

    audit_event(
        "saml_request",
        "success",
        endpoint="/saml/sso",
        username=username,
        details={"acs_url": acs_url},
    )

    if config.settings.log_saml_requests:
        logger.info(f"SAML Response issued for user '{username}' to {acs_url}")

    # Auto-submit form (escape user-controlled values to prevent XSS)
    safe_acs_url = html.escape(acs_url, quote=True)
    safe_relay_state = html.escape(relay_state, quote=True)
    return f"""<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="{safe_acs_url}">
  <input type="hidden" name="SAMLResponse" value="{saml_b64}"/>
  <input type="hidden" name="RelayState" value="{safe_relay_state}"/>
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>"""


@saml_bp.route("/sso", methods=["GET", "POST"])
def sso() -> ResponseReturnValue:
    """SAML SSO endpoint.

    Handles both SP-initiated SSO flows:
    - HTTP-Redirect binding (GET with DEFLATE compressed SAMLRequest)
    - HTTP-POST binding (POST with uncompressed SAMLRequest)

    If user is not authenticated, shows login form inline (no redirect)
    to preserve the original binding context.

    Each step is a named helper; every rejection keeps its historical
    error and audit behavior (#212).
    """
    config = get_config()

    saml_request_b64 = request.form.get("SAMLRequest") or request.args.get("SAMLRequest")
    relay_state = request.form.get("RelayState") or request.args.get("RelayState", "")

    if not saml_request_b64:
        return abort(400, description="missing SAMLRequest")

    rejected = _verify_authn_request_signature(config, saml_request_b64, relay_state)
    if rejected is not None:
        return rejected

    username, login_page = _sso_authenticate_inline(config, saml_request_b64, relay_state)
    if login_page is not None:
        return login_page
    assert username is not None  # _sso_authenticate_inline returns one or the other

    user = config.get_user(username)
    if not user:
        audit_event(
            "saml_request",
            "failed",
            endpoint="/saml/sso",
            username=username,
            details={"reason": "User not found"},
        )
        return abort(401, description=f"user '{username}' not found")

    acs_url, in_response_to, invalid = _sso_parse_request(config, saml_request_b64)
    if invalid is not None:
        return invalid

    # No ACS URL to send the assertion to: the request names none and
    # saml.default_acs_url is blank. Reject cleanly (#227). The None arm of
    # this used to 500 on html.escape(None) but became unreachable when the
    # document models gave default_acs_url a non-None default (#175); the
    # arm that IS reachable is an explicit default_acs_url: "" (a valid str),
    # which used to render an auto-submit form posting to action="" - the
    # IdP's own page - instead of failing. The message names both missing
    # sources, in the spirit of "metadata never lies": neither should errors.
    if not acs_url:
        audit_event(
            "saml_request",
            "failed",
            endpoint="/saml/sso",
            username=username,
            details={
                "reason": "AuthnRequest has no AssertionConsumerServiceURL "
                "and saml.default_acs_url is not configured"
            },
        )
        return abort(
            400,
            description="AuthnRequest has no AssertionConsumerServiceURL "
            "and saml.default_acs_url is not configured",
        )

    return _sso_success_response(config, user, username, acs_url, in_response_to, relay_state)


def _build_attribute_query_error_response(request_id: str, issuer_url: str) -> str:
    """A SAML error Response for an AttributeQuery naming an unknown principal.

    Top-level status Requester with subordinate UnknownPrincipal (SAML 2.0
    Core §3.2.2.2), no assertion. Until #275 an unknown NameID got a SIGNED
    assertion with fabricated attributes (email `<user>@example.org`-style,
    default entitlements) - a trap for the SP under test, which would pass
    with data nanoidp made up about a principal that does not exist.
    """
    now = datetime.now(timezone.utc)
    SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
    SAML2P_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
    response = etree.Element(
        f"{{{SAML2P_NS}}}Response",
        nsmap={"saml2p": SAML2P_NS, "saml2": SAML2_NS},
        ID=f"_{uuid.uuid4().hex}",
        Version="2.0",
        IssueInstant=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        InResponseTo=request_id,
    )
    issuer_el = etree.SubElement(response, f"{{{SAML2_NS}}}Issuer")
    issuer_el.text = issuer_url
    status = etree.SubElement(response, f"{{{SAML2P_NS}}}Status")
    status_code = etree.SubElement(status, f"{{{SAML2P_NS}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")
    sub_code = etree.SubElement(status_code, f"{{{SAML2P_NS}}}StatusCode")
    sub_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal")
    return etree.tostring(response, pretty_print=False).decode("utf-8")


def _build_attribute_query_response(
    user_id: str, attributes: dict, request_id: str, issuer_url: str
) -> str:
    """
    Build a SAML Response for AttributeQuery (backend-to-backend).

    This endpoint is used by resource servers to fetch user attributes
    after initial authentication (e.g., JWT-based).
    """
    now = datetime.now(timezone.utc)

    def iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
    SAML2P_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

    NSMAP = {
        "saml2p": SAML2P_NS,
        "saml2": SAML2_NS,
    }

    # Create Response
    response = etree.Element(
        f"{{{SAML2P_NS}}}Response",
        nsmap=NSMAP,
        ID=f"_{uuid.uuid4().hex}",
        Version="2.0",
        IssueInstant=iso(now),
        InResponseTo=request_id,
    )

    # Issuer
    issuer_el = etree.SubElement(response, f"{{{SAML2_NS}}}Issuer")
    issuer_el.text = issuer_url

    # Status
    status = etree.SubElement(response, f"{{{SAML2P_NS}}}Status")
    status_code = etree.SubElement(status, f"{{{SAML2P_NS}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    # Assertion
    assertion = etree.SubElement(
        response,
        f"{{{SAML2_NS}}}Assertion",
        ID=f"_{uuid.uuid4().hex}",
        Version="2.0",
        IssueInstant=iso(now),
    )

    # Assertion Issuer
    assertion_issuer = etree.SubElement(assertion, f"{{{SAML2_NS}}}Issuer")
    assertion_issuer.text = issuer_url

    # Subject
    subject = etree.SubElement(assertion, f"{{{SAML2_NS}}}Subject")
    name_id = etree.SubElement(subject, f"{{{SAML2_NS}}}NameID")
    name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
    name_id.text = user_id

    # Conditions
    conditions = etree.SubElement(assertion, f"{{{SAML2_NS}}}Conditions")
    not_after = now + timedelta(hours=1)
    conditions.set("NotBefore", iso(now))
    conditions.set("NotOnOrAfter", iso(not_after))

    # AttributeStatement - user authorization attributes
    if attributes:
        attr_statement = etree.SubElement(assertion, f"{{{SAML2_NS}}}AttributeStatement")

        for attr_name, attr_value in attributes.items():
            if attr_value is None:
                continue

            attribute = etree.SubElement(attr_statement, f"{{{SAML2_NS}}}Attribute")
            attribute.set("Name", attr_name)

            # Handle multi-value attributes
            # Lists are expanded to multiple AttributeValue elements
            # Scalar values are kept as a single AttributeValue
            if isinstance(attr_value, (list, tuple)):
                for value in attr_value:
                    attr_val_elem = etree.SubElement(attribute, f"{{{SAML2_NS}}}AttributeValue")
                    attr_val_elem.text = str(value)
            elif isinstance(attr_value, str) and "," in attr_value and "\\" not in attr_value:
                # Split comma-separated values (like entitlements)
                for value in attr_value.split(","):
                    attr_val_elem = etree.SubElement(attribute, f"{{{SAML2_NS}}}AttributeValue")
                    attr_val_elem.text = value.strip()
            else:
                # Single scalar value
                attr_val_elem = etree.SubElement(attribute, f"{{{SAML2_NS}}}AttributeValue")
                attr_val_elem.text = str(attr_value)

    return etree.tostring(response, encoding="unicode", pretty_print=True)


def _sign_attribute_query_response(response_xml: str, sign: bool = True) -> str:
    """Sign a SAML Response for AttributeQuery using signxml."""
    if not sign:
        return response_xml
    if not SIGNXML_AVAILABLE:
        logger.warning("signxml not available, returning unsigned response")
        return response_xml

    try:
        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        root = secure_fromstring(response_xml.encode("utf-8"))

        cert_path = crypto.keys_dir / "idp-cert.pem"
        with open(cert_path, "rb") as f:
            cert_pem = f.read()

        c14n_algo = _get_c14n_algorithm(config.settings.saml_c14n_algorithm)
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm=c14n_algo,
        )

        signed_root = signer.sign(root, key=crypto.priv_pem, cert=cert_pem.decode("ascii"))
        return etree.tostring(signed_root, encoding="unicode", pretty_print=True)

    except Exception as e:
        logger.warning(f"Cannot sign SAML Response: {e}")
        return response_xml


@saml_bp.route("/attribute-query", methods=["POST"])
def attribute_query() -> ResponseReturnValue:
    """
    SAML 2.0 AttributeQuery endpoint (Backend-to-Backend).

    Returns user attributes - core fields (identity_class, entitlements,
    source_acl) and any custom attributes from the user configuration - for
    the NameID in the query.

    UNAUTHENTICATED BY DESIGN (#275): this endpoint verifies nothing about
    the caller - no signature on the query, no JWT, no secret. That follows
    the same model as the REST read surfaces (reads are never gated, #163):
    nanoidp is a testing IdP and its user directory is test data. The flip
    side is real: on a shared instance, anyone who can reach this endpoint
    can read any configured user's attributes. Deploy accordingly.

    An unknown NameID gets a SAML error status (Requester/UnknownPrincipal),
    never a fabricated assertion (#275).
    """
    config = get_config()

    try:
        # Parse SOAP request body (using defusedxml to prevent XXE attacks)
        soap_body = request.data
        root = secure_fromstring(soap_body)

        # SAML namespaces
        namespaces = {
            "soap": "http://schemas.xmlsoap.org/soap/envelope/",
            "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
        }

        # Extract AttributeQuery from SOAP body
        attr_query = root.find(".//saml2p:AttributeQuery", namespaces)
        if attr_query is None:
            logger.warning("Invalid AttributeQuery: AttributeQuery element not found")
            return "Invalid AttributeQuery: AttributeQuery element not found", 400

        # Extract Subject/NameID (user identifier)
        subject = attr_query.find(".//saml2:Subject", namespaces)
        if subject is None:
            logger.warning("Invalid AttributeQuery: Subject not found")
            return "Invalid AttributeQuery: Subject not found", 400

        name_id_el = subject.find(".//saml2:NameID", namespaces)
        if name_id_el is None:
            logger.warning("Invalid AttributeQuery: NameID not found")
            return "Invalid AttributeQuery: NameID not found", 400

        user_id = name_id_el.text
        request_id = attr_query.get("ID", "_unknown")

        logger.info(f"AttributeQuery for user: {user_id}")

        # Get user from config
        user = config.get_user(user_id)

        if user:
            # Build attributes from user config
            attributes: Dict[str, Any] = {
                "email": user.email or f"{user_id}@example.com",
            }

            # Add core authorization attributes
            if user.identity_class:
                attributes["identity_class"] = user.identity_class
            if user.entitlements:
                # Passed as a list: the response builder emits one
                # AttributeValue per entry, and a comma-bearing entitlement
                # stays a single value instead of being split (#134).
                attributes["entitlements"] = user.entitlements
            # Add source_acl for data source authorization
            if user.source_acl:
                attributes["source_acl"] = user.source_acl  # List for multiple values

            # Roles/groups only when explicitly enabled (see /saml/sso).
            # Lists, not ",".join: same reason as entitlements above (#134).
            if config.settings.saml_export_roles and user.roles:
                _add_export_attr(attributes, config.settings.saml_roles_attr_name, user.roles)
            if config.settings.saml_export_groups and user.groups:
                _add_export_attr(attributes, config.settings.saml_groups_attr_name, user.groups)

            # Add custom attributes
            if user.attributes:
                for key, value in user.attributes.items():
                    if isinstance(value, list):
                        attributes[key] = ",".join(str(v) for v in value)
                    else:
                        attributes[key] = value
        else:
            # Unknown principal (#275): a SAML error status, not a signed
            # assertion full of invented attributes - the SP under test must
            # see the miss, not silently pass on data nanoidp made up.
            logger.warning(f"AttributeQuery for unknown user '{user_id}'")
            error_xml = _build_attribute_query_error_response(
                request_id=request_id,
                issuer_url=effective_saml_entity_id(config.settings),
            )
            # Same signing path as the success response (#289 review): with
            # saml_sign_responses on, an SP validating signatures must never
            # meet the one response shape nanoidp forgot to sign.
            error_xml = _sign_attribute_query_response(
                error_xml, config.settings.saml_sign_responses
            )
            audit_event(
                "saml_attribute_query",
                "failed",
                endpoint="/saml/attribute-query",
                username=user_id,
                details={"reason": "unknown principal"},
            )
            soap_error = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        {error_xml}
    </soap:Body>
</soap:Envelope>"""
            return Response(soap_error, mimetype="text/xml")

        # Build SAML Response
        issuer_url = effective_saml_entity_id(config.settings)
        response_xml = _build_attribute_query_response(
            user_id=user_id,
            attributes=attributes,
            request_id=request_id,
            issuer_url=issuer_url,
        )

        # Sign the response (if configured)
        signed_response = _sign_attribute_query_response(
            response_xml, config.settings.saml_sign_responses
        )

        # Wrap in SOAP envelope
        soap_response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        {signed_response}
    </soap:Body>
</soap:Envelope>"""

        audit_event(
            "saml_attribute_query",
            "success",
            endpoint="/saml/attribute-query",
            username=user_id,
            details={"attributes_count": len(attributes)},
        )

        logger.info(
            f"AttributeQuery response issued for user '{user_id}' with {len(attributes)} attributes"
        )

        return Response(soap_response, mimetype="text/xml")

    except Exception as e:
        logger.error(f"AttributeQuery error: {e}")
        import traceback

        traceback.print_exc()

        audit_event(
            "saml_attribute_query",
            "failed",
            endpoint="/saml/attribute-query",
            details={"error": str(e)},
        )

        return "AttributeQuery failed", 500
