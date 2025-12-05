"""
SAML routes for SSO and metadata.
"""

import uuid
import zlib
import logging
from base64 import b64encode, b64decode
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, abort, session, redirect, url_for, Response

from lxml import etree

from ..config import get_config
from ..services import get_crypto_service, get_audit_log

# Try to import signxml for SAML signing
try:
    from signxml import XMLSigner, methods
    SIGNXML_AVAILABLE = True
except ImportError:
    SIGNXML_AVAILABLE = False

logger = logging.getLogger(__name__)

saml_bp = Blueprint("saml", __name__, url_prefix="/saml")


def _get_request_info():
    """Get request info for audit logging."""
    return {
        "ip_address": request.remote_addr or "unknown",
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }


def _parse_saml_request(saml_request_b64: str):
    """Parse a SAMLRequest to extract ID, ACS URL, and Issuer."""
    try:
        saml_compressed = b64decode(saml_request_b64)
        saml_xml = zlib.decompress(saml_compressed, -zlib.MAX_WBITS)
        root = etree.fromstring(saml_xml)

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


def _build_saml_response(
    acs_url: str,
    issuer: str,
    audience: str,
    name_id: str,
    attributes: dict,
    in_response_to: str = None,
    sign: bool = True,
):
    """Build a SAML Response XML."""
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)

    now = datetime.now(timezone.utc)

    def iso(dt):
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
    ctxc.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    if attributes:
        attrs = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement")
        for k, v in attributes.items():
            if v is None:
                continue
            attr = etree.SubElement(attrs, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute", Name=k)
            if isinstance(v, (list, tuple)):
                for item in v:
                    av = etree.SubElement(attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
                    av.text = str(item)
            else:
                av = etree.SubElement(attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
                av.text = str(v)

    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

    if sign and SIGNXML_AVAILABLE:
        cert_path = crypto.keys_dir / "idp-cert.pem"
        with open(cert_path, "rb") as f:
            cert_pem = f.read()

        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
        )
        signed = signer.sign(
            assertion, key=crypto.priv_pem, cert=cert_pem, reference_uri=assertion_id
        )
        resp.remove(assertion)
        resp.append(signed)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

    return xml


@saml_bp.route("/metadata")
def metadata():
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
        entityID=settings.saml_entity_id,
        nsmap=NS,
    )
    idpsso = etree.SubElement(
        ent,
        "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor",
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
    )

    # KeyDescriptor
    kd = etree.SubElement(idpsso, "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor", use="signing")
    ki = etree.SubElement(kd, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
    x509d = etree.SubElement(ki, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
    x509c = etree.SubElement(x509d, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    x509c.text = crypto.get_certificate_base64()

    # SingleSignOnService
    etree.SubElement(
        idpsso,
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService",
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        Location=settings.saml_sso_url,
    )

    xml = etree.tostring(ent, xml_declaration=True, encoding="UTF-8", pretty_print=True)
    return Response(xml, mimetype="application/samlmetadata+xml")


@saml_bp.route("/cert.pem")
def cert():
    """Download the IdP certificate."""
    config = get_config()
    crypto = get_crypto_service(config.settings.keys_dir)
    return Response(crypto.cert_pem, mimetype="application/x-pem-file")


@saml_bp.route("/sso", methods=["GET", "POST"])
def sso():
    """SAML SSO endpoint."""
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    saml_request_b64 = request.form.get("SAMLRequest") or request.args.get("SAMLRequest")
    relay_state = request.form.get("RelayState") or request.args.get("RelayState", "")

    if not saml_request_b64:
        return abort(400, description="missing SAMLRequest")

    # Check if user is authenticated
    username = session.get("user")
    if not username:
        # Redirect to login
        return redirect(url_for("ui.login", SAMLRequest=saml_request_b64, RelayState=relay_state))

    user = config.get_user(username)
    if not user:
        audit.log(
            event_type="saml_request",
            endpoint="/saml/sso",
            method=request.method,
            status="failed",
            username=username,
            details={"reason": "User not found"},
            **req_info,
        )
        return abort(401, description=f"user '{username}' not found")

    # Parse SAMLRequest
    saml_info = _parse_saml_request(saml_request_b64)

    # Determine ACS URL
    if saml_info and saml_info.get("acs_url"):
        acs_url = saml_info["acs_url"]
    else:
        acs_url = config.settings.default_acs_url

    in_response_to = saml_info.get("id") if saml_info else None

    # Build SAML attributes
    saml_attrs = {
        "identity_class": user.identity_class,
        "entitlements": user.entitlements,
        "email": user.email,
    }
    # Add custom attributes
    if user.attributes:
        saml_attrs.update(user.attributes)

    name_id = user.email or f"{username}@example.org"

    # Generate SAML Response
    xml = _build_saml_response(
        acs_url=acs_url,
        issuer=config.settings.saml_entity_id,
        audience=config.settings.audience,
        name_id=name_id,
        attributes={k: v for k, v in saml_attrs.items() if v is not None},
        in_response_to=in_response_to,
        sign=True,
    )
    saml_b64 = b64encode(xml).decode("ascii")

    audit.log(
        event_type="saml_request",
        endpoint="/saml/sso",
        method=request.method,
        status="success",
        username=username,
        details={"acs_url": acs_url},
        **req_info,
    )

    if config.settings.log_saml_requests:
        logger.info(f"SAML Response issued for user '{username}' to {acs_url}")

    # Auto-submit form
    html = f"""<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="{acs_url}">
  <input type="hidden" name="SAMLResponse" value="{saml_b64}"/>
  <input type="hidden" name="RelayState" value="{relay_state}"/>
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>"""

    return html


def _build_attribute_query_response(user_id: str, attributes: dict, request_id: str, issuer_url: str) -> str:
    """
    Build a SAML Response for AttributeQuery (backend-to-backend).

    This endpoint is used by resource servers to fetch user attributes
    after initial authentication (e.g., JWT-based).
    """
    now = datetime.now(timezone.utc)

    def iso(dt):
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


def _sign_attribute_query_response(response_xml: str) -> str:
    """Sign a SAML Response for AttributeQuery using signxml."""
    if not SIGNXML_AVAILABLE:
        logger.warning("signxml not available, returning unsigned response")
        return response_xml

    try:
        config = get_config()
        crypto = get_crypto_service(config.settings.keys_dir)

        root = etree.fromstring(response_xml.encode("utf-8"))

        cert_path = crypto.keys_dir / "idp-cert.pem"
        with open(cert_path, "rb") as f:
            cert_pem = f.read()

        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
        )

        signed_root = signer.sign(root, key=crypto.priv_pem, cert=cert_pem)
        return etree.tostring(signed_root, encoding="unicode", pretty_print=True)

    except Exception as e:
        logger.warning(f"Cannot sign SAML Response: {e}")
        return response_xml


@saml_bp.route("/attribute-query", methods=["POST"])
def attribute_query():
    """
    SAML 2.0 AttributeQuery endpoint (Backend-to-Backend).

    This endpoint implements SAML AttributeQuery for backend-to-backend
    attribute fetching after JWT authentication. It returns user attributes
    including core fields (identity_class, entitlements, source_acl) and
    any custom attributes defined in the user configuration.
    """
    config = get_config()
    audit = get_audit_log()
    req_info = _get_request_info()

    try:
        # Parse SOAP request body
        soap_body = request.data
        root = etree.fromstring(soap_body)

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
            attributes = {
                "email": user.email or f"{user_id}@example.com",
            }

            # Add core authorization attributes
            if user.identity_class:
                attributes["identity_class"] = user.identity_class
            if user.entitlements:
                # Convert list to comma-separated for SAML
                if isinstance(user.entitlements, list):
                    attributes["entitlements"] = ",".join(user.entitlements)
                else:
                    attributes["entitlements"] = user.entitlements
            # Add source_acl for data source authorization
            if user.source_acl:
                attributes["source_acl"] = user.source_acl  # List for multiple values

            # Add custom attributes
            if user.attributes:
                for key, value in user.attributes.items():
                    if isinstance(value, list):
                        attributes[key] = ",".join(str(v) for v in value)
                    else:
                        attributes[key] = value
        else:
            # Fallback for unknown users - provide default attributes
            logger.warning(f"User '{user_id}' not found, using default attributes")
            attributes = {
                "email": f"{user_id}@example.com",
                "identity_class": "INTERNAL",
                "entitlements": "DOCUMENT_READ",
            }

        # Build SAML Response
        issuer_url = f"{config.settings.saml_entity_id}"
        response_xml = _build_attribute_query_response(
            user_id=user_id,
            attributes=attributes,
            request_id=request_id,
            issuer_url=issuer_url,
        )

        # Sign the response
        signed_response = _sign_attribute_query_response(response_xml)

        # Wrap in SOAP envelope
        soap_response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        {signed_response}
    </soap:Body>
</soap:Envelope>"""

        audit.log(
            event_type="saml_attribute_query",
            endpoint="/saml/attribute-query",
            method="POST",
            status="success",
            username=user_id,
            details={"attributes_count": len(attributes)},
            **req_info,
        )

        logger.info(f"AttributeQuery response issued for user '{user_id}' with {len(attributes)} attributes")

        return Response(soap_response, mimetype="text/xml")

    except Exception as e:
        logger.error(f"AttributeQuery error: {e}")
        import traceback
        traceback.print_exc()

        audit.log(
            event_type="saml_attribute_query",
            endpoint="/saml/attribute-query",
            method="POST",
            status="failed",
            details={"error": str(e)},
            **req_info,
        )

        return f"AttributeQuery failed: {str(e)}", 500
