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

from ..config import ConfigSnapshot, get_config
from ..exceptions import SAMLSignatureError
from ..services import get_crypto_service, identities_for
from ..services.saml_assertion import (
    SAML2_NS,
    STATUS_REQUESTER,
    STATUS_SUCCESS,
    STATUS_UNKNOWN_PRINCIPAL,
    append_status,
    build_assertion_core,
    build_response_envelope,
    saml_instant,
)
from ..services.saml_attributes import (
    append_attribute_statement,
    resolve_saml_attributes,
)
from ..services.saml_verification import (
    load_sp_certificates,
    verify_post_signature,
    verify_redirect_signature,
)
from ..services.saml_verified_requests import (
    VerificationState,
    remember_verified,
    request_digest,
    state_of,
)
from ._audit import audit_event
from ._auth import (
    PENDING_SECOND_FACTOR_FIELD,
    SECOND_FACTOR_STORE_FULL,
    AuthMethod,
    SecondFactorPhase,
    TwoStepPhase,
    authenticate_interactively,
    begin_second_factor,
    continue_second_factor,
    discard_pending_second_factor,
    establish_login_session,
    no_store,
    session_auth_method,
    two_step_phase,
)
from ._config import request_config
from ._issuer import effective_saml_entity_id, effective_saml_sso_url


def _secure_parser() -> etree.XMLParser:
    """A parser that resolves no entity, loads no DTD and reaches no
    network: XXE protection without the deprecated defusedxml.lxml.

    The options are written out here, literally, at the one place that
    builds a parser. Passing them as a mapping hid them from static
    analysis - CodeQL reported ``py/xxe`` on the call, because from where it
    stands a parser built from ``**options`` may resolve entities - and it
    would also have been a dial a caller could turn process-wide.
    """
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )


def secure_fromstring(xml_bytes: bytes) -> etree._Element:
    """Parse XML securely, preventing XXE attacks.

    The parser is built per call, not once at module scope (#378).

    Sharing one was never a correctness problem: an ``lxml`` parser owns a
    lock and takes it for the duration of each parse (``_ParserContext``
    in lxml's ``parser.pxi``). That lock is the reason to stop sharing it -
    it serializes every SAML parse in the process. Measured here on 24000
    parses of a 5 KB document: shared, 3.0 s on one thread and 2.3 s on
    eight, which is no scaling at all; a parser per call, 3.2 s on one
    thread and 0.64 s on eight. The cost is at the other end of the size
    range, where building the parser outweighs the parse: about a
    microsecond per parse of a 300-byte AuthnRequest, against requests that
    take milliseconds.

    It also removes the shared object that twice stood as an alternative
    explanation for a surprising parse while #309 was being diagnosed -
    probed there with three documents across twelve threads and 36000
    parses, checking every root tag, with no mixes.
    """
    return etree.fromstring(xml_bytes, parser=_secure_parser())


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


def _build_saml_response(
    loaded: ConfigSnapshot,
    acs_url: str,
    issuer: str,
    audience: str,
    name_id: str,
    attributes: dict,
    in_response_to: Optional[str] = None,
    sign: bool = True,
    authn_context: str = AuthMethod.PASSWORD.saml_context,
) -> bytes:
    """Build a SAML Response XML.

    ``authn_context`` (AuthnContextClassRef) defaults to
    PasswordProtectedTransport - accurate for every existing caller, which
    all authenticate by password. A persona-mode login authenticates by
    identity selection instead, so the caller passes 'unspecified' there;
    claiming PasswordProtectedTransport for that login would be false (#persona
    login design contract, point 6).
    """
    # The configuration this operation began with (#406), and the signing
    # service after it (#359): see get_crypto_service().
    settings = loaded.settings
    crypto = get_crypto_service()

    now = datetime.now(timezone.utc)

    # The envelope, the Issuer pair, the Status and the assertion's head are
    # the same document in all three builders here (#317). The Destination
    # is not: only a login assertion is delivered to an ACS. InResponseTo is
    # set after it, and only when the request's ID is known: /saml/sso
    # answers no login without a SAMLRequest, but one that did not parse is
    # still answered at saml.default_acs_url, without it.
    response_id = f"_{uuid.uuid4().hex}"
    assertion_id = f"_{uuid.uuid4().hex}"
    resp = build_response_envelope(
        issuer=issuer,
        issued_at=now,
        extra_namespaces={"ds": "http://www.w3.org/2000/09/xmldsig#"},
        extra_attributes={"Destination": acs_url},
        response_id=response_id,
    )
    if in_response_to:
        resp.set("InResponseTo", in_response_to)
    append_status(resp, value=STATUS_SUCCESS)

    assertion, subject = build_assertion_core(
        resp,
        issuer=issuer,
        issued_at=now,
        name_id=name_id,
        assertion_id=assertion_id,
    )

    subj_conf = etree.SubElement(
        subject,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
    )
    subj_conf_data = etree.SubElement(
        subj_conf,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
        NotOnOrAfter=saml_instant(now + timedelta(minutes=5)),
        Recipient=acs_url,
    )
    if in_response_to:
        subj_conf_data.set("InResponseTo", in_response_to)

    cond = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
        NotBefore=saml_instant(now),
        NotOnOrAfter=saml_instant(now + timedelta(minutes=5)),
    )
    audr = etree.SubElement(cond, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")
    aud = etree.SubElement(audr, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
    aud.text = audience

    authn = etree.SubElement(
        assertion,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
        AuthnInstant=saml_instant(now),
        SessionIndex=f"_{uuid.uuid4().hex}",
    )
    ctx = etree.SubElement(authn, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")
    ctxc = etree.SubElement(ctx, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")
    ctxc.text = authn_context

    # One shared emission path for both builders (#302).
    append_attribute_statement(assertion, attributes)

    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

    if sign and SIGNXML_AVAILABLE:
        # The published service's certificate, the one for the key it signs
        # with (#358), not the idp-cert.pem file re-read per request. Both
        # taken at once: between two reads a rotation could pair one key's
        # certificate with the other's signature (#420).
        keys = crypto.keys
        cert_pem = keys.cert_pem

        c14n_algo = _get_c14n_algorithm(settings.saml_c14n_algorithm)
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm=c14n_algo,
        )
        signed = signer.sign(
            # signxml's typed API takes the certificate as a PEM string
            assertion,
            key=keys.priv_pem,
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
    settings = request_config().settings
    crypto = get_crypto_service()

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
    crypto = get_crypto_service()
    return Response(crypto.cert_pem, mimetype="application/x-pem-file")


def _verify_authn_request_signature(
    loaded: ConfigSnapshot, saml_request_b64: str, relay_state: str
) -> Optional[ResponseReturnValue]:
    """AuthnRequest signature verification (#69), opt-in via
    saml.want_authn_requests_signed. Verified where the request ENTERS:

    - GET = Redirect binding: query-string signature (Bindings §3.4.4.1).
      The signature only exists on the original URL and cannot survive the
      login-form roundtrip, so a verified request this browser still has to
      continue is remembered in its own session (#375, a bounded expiring
      set rather than #69's single slot); the POST login leg
      (saml_original_verb=GET) is admitted only for a request that set says
      this browser had verified, and fails closed otherwise (#69 review:
      hidden form fields are client-controlled and must not be trusted on
      their own).
    - POST without saml_original_verb = POST-binding entry: enveloped XML
      signature (Core §5).
    - POST login leg of a POST-binding request (saml_original_verb=POST):
      the signature still travels inside the XML, so it is re-verified.

    Returns the rejection response, or None when the request may proceed
    (verification passed, or the opt-in is off).
    """
    if not loaded.settings.saml_want_authn_requests_signed:
        return None

    form_leg_verb = (request.form.get("saml_original_verb") or "").upper()
    try:
        if request.method == "GET":
            verify_redirect_signature(
                request.query_string.decode("latin-1"),
                load_sp_certificates(loaded.settings.saml_sp_certificates),
            )
            # Remembering this request is the caller's, once it knows a
            # login continuation is actually needed (#375): a browser that
            # is already signed in completes the SSO on this GET and has
            # nothing to continue.
        elif form_leg_verb == "GET":
            refused = _admit_redirect_login_leg(saml_request_b64, relay_state)
            if refused is not None:
                return refused
        else:
            xml_bytes = _decode_saml_request_bytes(saml_request_b64)
            verify_post_signature(
                xml_bytes,
                load_sp_certificates(loaded.settings.saml_sp_certificates),
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


# The one session key /saml/sso writes for this (#375): the bounded,
# expiring set of Redirect requests this browser had verified.
_VERIFIED_REDIRECTS_SESSION_KEY = "saml_verified_redirects"


def _remember_verified_redirect(saml_request_b64: str, relay_state: str) -> None:
    """Remember that this browser had this Redirect request verified, or
    refresh it while the browser is still continuing it."""
    session[_VERIFIED_REDIRECTS_SESSION_KEY] = remember_verified(
        session.get(_VERIFIED_REDIRECTS_SESSION_KEY),
        request_digest(saml_request_b64, relay_state),
    )


def _admit_redirect_login_leg(
    saml_request_b64: str, relay_state: str
) -> Optional[ResponseReturnValue]:
    """The login leg of a Redirect-binding request: ``None`` to proceed, or
    the refusal.

    An expired verification is told apart from one that never happened, in
    the audit and the log, so neither says the signature was invalid; the
    browser gets the same 400 either way.
    """
    state, _live = state_of(
        session.get(_VERIFIED_REDIRECTS_SESSION_KEY),
        request_digest(saml_request_b64, relay_state),
    )
    if state is VerificationState.VERIFIED:
        # Continuing the flow keeps it alive: a login can take several
        # screens (two-step, then a TOTP code).
        _remember_verified_redirect(saml_request_b64, relay_state)
        return None
    # The refusal writes nothing: a browser that had no session gets no
    # cookie for having been refused, and the expired entry stays there, so
    # a second attempt is told it expired rather than that it never
    # happened. The next verification prunes it.
    expired = state is VerificationState.EXPIRED
    reason = (
        "the verified Redirect AuthnRequest expired"
        if expired
        else "no matching verified Redirect AuthnRequest for this browser"
    )
    audit_event(
        "saml_request",
        "failed",
        endpoint="/saml/sso",
        details={"reason": reason},
    )
    logger.info("Redirect-binding login continuation refused: %s", reason)
    return abort(
        400,
        description=(
            "the verified Redirect AuthnRequest has expired, please start again"
            if expired
            else "Redirect-binding login continuation does not match a "
            "signature-verified request of this browser"
        ),
    )


def _sso_authenticate_inline(
    config: Any, saml_request_b64: str, relay_state: str
) -> tuple[Optional[str], Optional[ResponseReturnValue]]:
    """The inline-login leg: (username, None) once authenticated, or
    (None, login-page response) while not.

    Login happens inline (no redirect) to preserve the original binding
    context. Persona mode authenticates by identity selection only;
    password mode is unchanged. Two-step (#322/#323) collects username and
    password on separate screens, stateless like /authorize and /login: a
    request carries no "username"/"password" form fields at all when it is
    a fresh SAMLRequest (GET redirect binding, or the SP's own POST
    binding) rather than a resubmission of one of nanoidp's own login
    forms - only the latter ever posts those field names - so that
    distinguishes "nothing submitted yet" from "submitted blank" without
    needing request.method.
    """
    username = session.get("user")
    if username:
        return username, None

    loaded = request_config()
    persona_mode = loaded.settings.persona_mode_enabled
    two_step_login = loaded.settings.two_step_login_active
    login_error = None

    username_submitted = "username" in request.form
    form_username = request.form.get("username", "").strip()
    password_submitted = "password" in request.form
    form_password = request.form.get("password", "")

    def render_login(
        error: Optional[str],
        login_username: str,
        *,
        pending_second_factor: str = "",
    ) -> ResponseReturnValue:
        # The screen must carry the verb of the request that ENTERED the
        # flow, not the verb of the request that is rendering it (#323
        # review round 2, blocking): a GET's compressed SAMLRequest is
        # still compressed on the username-only step's POST and on the
        # password screen it renders in turn - only the very first render
        # of this flow has request.method equal to that original verb, so
        # every subsequent render must forward the value the prior screen
        # already carried, exactly like saml_request and relay_state do.
        # Whitelisted here rather than left to _sso_parse_request, which
        # only runs once authentication succeeds: without this, a tampered
        # value rides along through every intermediate screen and is only
        # rejected after the user has typed credentials (#322/#323 review
        # round 3, before-merge 5).
        form_verb = request.form.get("saml_original_verb")
        if form_verb and form_verb.upper() not in ("GET", "POST"):
            return abort(400, description="invalid saml_original_verb")
        original_verb = (form_verb or request.method).upper()
        # A pending second factor (#373) renders the code screen. no_store
        # applied here, not by each caller (#348 review, cleanup): the one
        # place that knows the code screen is being rendered.
        totp_step = bool(pending_second_factor)
        response = render_template(
            "login.html",
            error=error,
            saml_request=saml_request_b64,
            relay_state=relay_state,
            original_verb=original_verb,
            users=identities_for(config, request_config()).persona_picker_entries(),
            persona_mode=persona_mode,
            two_step_login=two_step_login,
            login_username=login_username,
            totp_step=totp_step,
            pending_second_factor=pending_second_factor,
        )
        return no_store(response) if totp_step else response

    # The context a pending second factor belongs to (#373): the SAML
    # request in flight, exactly as this form carries it. An invalid verb is
    # refused by render_login before any record is created or used.
    form_verb = request.form.get("saml_original_verb") or request.method
    second_factor_context = {
        "SAMLRequest": saml_request_b64,
        "RelayState": relay_state,
        "saml_original_verb": form_verb.upper(),
    }
    if form_verb.upper() not in ("GET", "POST"):
        return None, render_login(None, "")

    if "change_username" in request.form:
        discard_pending_second_factor(purpose="saml_sso", context=second_factor_context)
        return None, render_login(None, "")

    if request.form.get(PENDING_SECOND_FACTOR_FIELD) and not password_submitted:
        continuation = continue_second_factor(
            config, request_config(), purpose="saml_sso", context=second_factor_context
        )
        if continuation.error is not None:
            audit_event(
                "login",
                "failed",
                endpoint="/saml/sso",
                username=continuation.username,
                details={"reason": continuation.reason},
            )
            return None, render_login(continuation.error, "")
        assert continuation.login is not None and continuation.username is not None
        if continuation.pending is not None:
            if continuation.login.phase is SecondFactorPhase.CODE_INVALID:
                audit_event(
                    "login",
                    "failed",
                    endpoint="/saml/sso",
                    username=continuation.username,
                    details={"reason": continuation.login.phase.error},
                )
            return None, render_login(
                continuation.login.phase.error,
                continuation.username,
                pending_second_factor=continuation.pending.id,
            )
        establish_login_session(continuation.username, method=continuation.login.method)
        audit_event("login", "success", endpoint="/saml/sso", username=continuation.username)
        return continuation.username, None

    # Step detection is shared with every other password-form surface
    # (#323 review round 2, before-merge 5); username_submitted is what
    # distinguishes a fresh, field-less SAMLRequest (GET or POST binding)
    # from a resubmission of nanoidp's own login form - see
    # two_step_phase's docstring.
    phase = two_step_phase(
        two_step_active=two_step_login,
        username=form_username,
        password=form_password,
        password_submitted=password_submitted,
        username_submitted=username_submitted,
    )
    if phase is TwoStepPhase.USERNAME_REQUIRED:
        return None, render_login("Username is required", "")
    if phase is TwoStepPhase.PASSWORD_REQUIRED:
        # The password screen was resubmitted with a blank password.
        return None, render_login("Password is required", form_username)
    if phase is TwoStepPhase.USERNAME_STEP:
        # Either a fresh SAMLRequest (nothing submitted yet) or the
        # username-only step just completed: either way, nothing to
        # authenticate, render the next screen with no error.
        return None, render_login(None, form_username)

    # Declarative TOTP second factor (#348): the code screen is a further
    # phase. The verified password is recorded as a pending second factor
    # bound to this SAML request (#373); the screen carries only its id. A
    # POST carrying the password and the code together completes both here,
    # statelessly, as before.
    login = authenticate_interactively(config, request_config(), username=form_username, password=form_password)

    if login.phase.pending:
        if login.phase is SecondFactorPhase.CODE_INVALID:
            audit_event(
                "login",
                "failed",
                endpoint="/saml/sso",
                username=form_username,
                details={"reason": login.phase.error},
            )
        pending_id = begin_second_factor(
            purpose="saml_sso", context=second_factor_context, username=form_username
        )
        if pending_id is None:
            return None, render_login(SECOND_FACTOR_STORE_FULL, "")
        return None, render_login(
            login.phase.error, form_username, pending_second_factor=pending_id
        )

    if login.user:
        # Single writer for the login session (#301); it records how this
        # session authenticated so _sso_success_response can pick the
        # matching AuthnContextClassRef.
        establish_login_session(form_username, method=login.method)
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

    # Still not authenticated - show login form.
    return None, render_login(login_error, form_username if two_step_login else "")


def _sso_parse_request(
    loaded: ConfigSnapshot, saml_request_b64: str
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[ResponseReturnValue]]:
    """Parse the SAMLRequest: (acs_url, in_response_to, sp_issuer, None) or
    (None, None, None, error).

    ``sp_issuer`` is the requesting service provider's identifier, the
    AuthnRequest's Issuer (SAML Profiles §4.1.4.1), which the assertion's
    Audience must name (§4.1.4.2, #443); None when the request carries none.

    Signature verification (when enabled) already happened in
    _verify_authn_request_signature (#69); without the opt-in,
    Signature/SigAlg query params are accepted and ignored, as before.

    Uses the original HTTP verb from the form if set (inline login case: an
    original GET's compressed SAMLRequest is POSTed back after the login
    form submission). Normalized to uppercase and validated.
    """
    form_verb = request.form.get("saml_original_verb")
    if form_verb and form_verb.upper() not in ("GET", "POST"):
        return None, None, None, abort(400, description="invalid saml_original_verb")
    original_verb = (form_verb or request.method or "POST").upper()
    saml_info = _parse_saml_request(
        saml_request_b64, http_verb=original_verb, strict=loaded.settings.strict_saml_binding
    )

    requested_acs = saml_info.get("acs_url") if saml_info else None
    acs_url = requested_acs or loaded.settings.default_acs_url
    in_response_to = saml_info.get("id") if saml_info else None
    sp_issuer = (saml_info.get("issuer") if saml_info else None) or None
    return acs_url, in_response_to, sp_issuer, None


def _sso_success_response(
    user: Any,
    username: str,
    acs_url: str,
    in_response_to: Optional[str],
    sp_issuer: Optional[str],
    relay_state: str,
) -> ResponseReturnValue:
    """Build, audit and auto-submit the SAML Response for an authenticated user."""
    # Shared resolver (#302); the SSO assertion never carries source_acl -
    # a login assertion is not a backend authorization lookup (deliberate,
    # see services/saml_attributes.py and the saml.md divergence table).
    loaded = request_config()
    saml_attrs = resolve_saml_attributes(loaded.settings, user, include_source_acl=False)

    name_id = user.email or f"{username}@example.org"

    # AuthnContextClassRef must reflect how THIS session actually
    # authenticated, not the current server-wide setting - the session may
    # have been authenticated earlier (e.g. via the nanoidp dashboard's own
    # /login) and is only being reused here. The reader and its
    # absent-means-password default live in _auth (#301, extended #348).
    authn_context = session_auth_method().saml_context

    # The Audience is the requesting service provider (SAML Profiles
    # §4.1.4.2, #443): the AuthnRequest's Issuer. A request that names none
    # is outside the profile; it is answered as before, with oauth.audience.
    audience = sp_issuer or loaded.settings.audience

    # Generate SAML Response
    xml = _build_saml_response(
        loaded,
        acs_url=acs_url,
        issuer=effective_saml_entity_id(loaded.settings),
        audience=audience,
        name_id=name_id,
        attributes={k: v for k, v in saml_attrs.items() if v is not None},
        in_response_to=in_response_to,
        sign=loaded.settings.saml_sign_responses,
        authn_context=authn_context,
    )
    saml_b64 = b64encode(xml).decode("ascii")

    audit_event(
        "saml_request",
        "success",
        endpoint="/saml/sso",
        username=username,
        # Both the Issuer received and the Audience issued: with the
        # fallback the second is not implied by the first
        details={"acs_url": acs_url, "sp_issuer": sp_issuer, "audience": audience},
    )

    if loaded.settings.log_saml_requests:
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
    # The configuration this request began with (#406).
    loaded = request_config()

    saml_request_b64 = request.form.get("SAMLRequest") or request.args.get("SAMLRequest")
    relay_state = request.form.get("RelayState") or request.args.get("RelayState", "")

    if not saml_request_b64:
        return abort(400, description="missing SAMLRequest")

    rejected = _verify_authn_request_signature(loaded, saml_request_b64, relay_state)
    if rejected is not None:
        return rejected

    username, login_page = _sso_authenticate_inline(config, saml_request_b64, relay_state)
    if login_page is not None:
        if loaded.settings.saml_want_authn_requests_signed and request.method == "GET":
            # A verified Redirect request is remembered here, where it is
            # known that this browser has a login to continue (#375).
            _remember_verified_redirect(saml_request_b64, relay_state)
        return login_page
    assert username is not None  # _sso_authenticate_inline returns one or the other

    user = identities_for(config, request_config()).get_user(username)
    if not user:
        audit_event(
            "saml_request",
            "failed",
            endpoint="/saml/sso",
            username=username,
            details={"reason": "User not found"},
        )
        return abort(401, description=f"user '{username}' not found")

    acs_url, in_response_to, sp_issuer, invalid = _sso_parse_request(loaded, saml_request_b64)
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

    return _sso_success_response(user, username, acs_url, in_response_to, sp_issuer, relay_state)


def _build_attribute_query_error_response(request_id: str, issuer_url: str) -> str:
    """A SAML error Response for an AttributeQuery naming an unknown principal.

    Top-level status Requester with subordinate UnknownPrincipal (SAML 2.0
    Core §3.2.2.2), no assertion. Until #275 an unknown NameID got a SIGNED
    assertion with fabricated attributes (email `<user>@example.org`-style,
    default entitlements) - a trap for the SP under test, which would pass
    with data nanoidp made up about a principal that does not exist.
    """
    now = datetime.now(timezone.utc)
    # Same envelope as the success builder below, and no assertion at all:
    # the whole answer is the status (#317).
    response = build_response_envelope(
        issuer=issuer_url,
        issued_at=now,
        extra_attributes={"InResponseTo": request_id},
        response_id=f"_{uuid.uuid4().hex}",
    )
    append_status(response, value=STATUS_REQUESTER, subordinate=STATUS_UNKNOWN_PRINCIPAL)
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

    # The shared core (#317). InResponseTo is always present here: an
    # attribute query is never unsolicited, unlike an SSO login.
    response = build_response_envelope(
        issuer=issuer_url,
        issued_at=now,
        extra_attributes={"InResponseTo": request_id},
        response_id=f"_{uuid.uuid4().hex}",
    )
    append_status(response, value=STATUS_SUCCESS)
    assertion, _subject = build_assertion_core(
        response,
        issuer=issuer_url,
        issued_at=now,
        name_id=user_id,
        assertion_id=f"_{uuid.uuid4().hex}",
    )

    # Conditions: one hour, against the five minutes of a login assertion.
    # Deliberately NOT shared (#317): the two windows have never been
    # decided to be one policy, and the difference is declared in
    # book/src/reference/saml.md rather than hidden behind an argument.
    conditions = etree.SubElement(assertion, f"{{{SAML2_NS}}}Conditions")
    not_after = now + timedelta(hours=1)
    conditions.set("NotBefore", saml_instant(now))
    conditions.set("NotOnOrAfter", saml_instant(not_after))

    # One shared emission path for both builders (#302): strings are never
    # comma-split (the #134 rule the old loop here contradicted), lists are
    # one AttributeValue per entry.
    append_attribute_statement(assertion, attributes)

    return etree.tostring(response, encoding="unicode", pretty_print=True)


def _sign_attribute_query_response(
    loaded: ConfigSnapshot,response_xml: str, sign: bool = True) -> str:
    """Sign a SAML Response for AttributeQuery using signxml."""
    if not sign:
        return response_xml
    if not SIGNXML_AVAILABLE:
        logger.warning("signxml not available, returning unsigned response")
        return response_xml

    try:
        settings = loaded.settings
        crypto = get_crypto_service()

        root = secure_fromstring(response_xml.encode("utf-8"))

        # The published service's certificate, the one for the key it signs
        # with (#358), not the idp-cert.pem file re-read per request; both
        # taken at once (#420).
        keys = crypto.keys
        cert_pem = keys.cert_pem

        c14n_algo = _get_c14n_algorithm(settings.saml_c14n_algorithm)
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm=c14n_algo,
        )

        signed_root = signer.sign(root, key=keys.priv_pem, cert=cert_pem.decode("ascii"))
        return etree.tostring(signed_root, encoding="unicode", pretty_print=True)

    except Exception as e:
        logger.warning(f"Cannot sign SAML Response: {e}")
        return response_xml


def _soap_fault(message: str, *, client_fault: bool = True) -> "ResponseReturnValue":
    """A SOAP 1.1 Fault for the attribute-query endpoint (#287).

    SOAP 1.1 §6.2: a SOAP error MUST be issued as HTTP 500, with faultcode
    Client vs Server saying whose fault it is - the previous bare
    ``return "text", 400`` answered a SOAP caller in a shape no SOAP stack
    parses. Message content stays operator-facing plain text inside
    faultstring.
    """
    code = "soap:Client" if client_fault else "soap:Server"
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <soap:Fault>
            <faultcode>{code}</faultcode>
            <faultstring>{message}</faultstring>
        </soap:Fault>
    </soap:Body>
</soap:Envelope>"""
    return Response(body, status=500, mimetype="text/xml")


def _query_id_of(root: Optional[Any]) -> Optional[str]:
    """The ``ID`` of the AttributeQuery in this body, as early as the body
    allows (#309).

    A request that is refused before the query is located is exactly the one
    a log cannot attribute to a sender, so the id is read from whatever
    shape arrived: the enveloped query, or a bare ``AttributeQuery`` posted
    without the SOAP envelope, which is what the unexplained 500 of #309
    was. ``None`` when the body says nothing about it, which is the honest
    answer rather than a guess.
    """
    if root is None:
        return None
    query = root.find(".//saml2p:AttributeQuery", _SAML_QUERY_NAMESPACES)
    if query is None and etree.QName(root).text == (
        f"{{{_SAML_QUERY_NAMESPACES['saml2p']}}}AttributeQuery"
    ):
        # A bare query, posted without the SOAP envelope. The namespace is
        # part of the match: an element that merely shares the local name is
        # not a query, and naming it would be the guess this refuses to make.
        query = root
    return query.get("ID") if query is not None else None


# The id is chosen by an unauthenticated caller and kept in the audit ring,
# so as EVIDENCE it is bounded: enough to match a sender, never enough to
# fill the log with. This is a diagnostic shortening and nothing else: the
# value the protocol carries back in InResponseTo is the id as it arrived.
MAX_REQUEST_ID_CHARS = 128


def _bounded_request_id(request_id: Optional[str]) -> Optional[str]:
    """The id as it goes into an audit entry or a log line, never into a
    SAML Response."""
    if request_id is None:
        return None
    if len(request_id) <= MAX_REQUEST_ID_CHARS:
        return request_id
    return request_id[:MAX_REQUEST_ID_CHARS] + "...(truncated)"


def _audit_attribute_query(
    status: str,
    *,
    request_id: Optional[str],
    reason: str,
    size: int,
    username: Optional[str] = None,
) -> None:
    """One audit entry per AttributeQuery outcome, the early refusals
    included (#309): before this, a request refused for its shape wrote
    nothing, so the only trace of it was a log line no sender could be
    matched to."""
    audit_event(
        "saml_attribute_query",
        status,
        endpoint="/saml/attribute-query",
        username=username,
        details={
            "reason": reason,
            "request_id": _bounded_request_id(request_id),
            # The bytes read, not the declared Content-Length: a header can
            # overstate the body, and a chunked request declares none.
            "content_length": size,
        },
    )


def _attribute_query_fault(
    message: str,
    *,
    request_id: Optional[str],
    body: bytes = b"",
    detail: Optional[str] = None,
) -> ResponseReturnValue:
    """Refuse a malformed AttributeQuery: audited, logged once, and answered
    with the SOAP fault the caller has always got."""
    _audit_attribute_query("failed", request_id=request_id, reason=message, size=len(body))
    logger.warning(
        "%s (request_id=%s, %d bytes)%s",
        message,
        _bounded_request_id(request_id),
        len(body),
        f": {detail}" if detail else "",
    )
    if body and request_config().settings.verbose_logging:
        # The body names a principal, so it is operator-only material.
        logger.debug("AttributeQuery body: %r", body[:2000])
    return _soap_fault(message)


_SAML_QUERY_NAMESPACES = {
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
}


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
    # The configuration this request began with (#406).
    loaded = request_config()

    try:
        # Parse SOAP request body (using defusedxml to prevent XXE attacks).
        # Syntactically broken XML is the CLIENT's fault (#295 review): catch
        # it here rather than letting it fall to the catch-all, which answers
        # soap:Server for nanoidp-side failures.
        soap_body = request.data
        try:
            root = secure_fromstring(soap_body)
        except Exception as parse_error:
            # Nothing in this body can be attributed to a sender (#309), so
            # the parser's own complaint is the only clue there is.
            return _attribute_query_fault(
                "Request body is not well-formed XML",
                request_id=None,
                body=soap_body,
                detail=str(parse_error),
            )

        namespaces = _SAML_QUERY_NAMESPACES
        # Read who sent this before deciding anything about it (#309).
        request_id = _query_id_of(root)

        # Extract AttributeQuery from SOAP body
        attr_query = root.find(".//saml2p:AttributeQuery", namespaces)
        if attr_query is None:
            return _attribute_query_fault(
                "Invalid AttributeQuery: AttributeQuery element not found",
                request_id=request_id,
                body=soap_body,
            )

        # Extract Subject/NameID (user identifier)
        subject = attr_query.find(".//saml2:Subject", namespaces)
        if subject is None:
            return _attribute_query_fault(
                "Invalid AttributeQuery: Subject not found",
                request_id=request_id,
                body=soap_body,
            )

        name_id_el = subject.find(".//saml2:NameID", namespaces)
        if name_id_el is None:
            return _attribute_query_fault(
                "Invalid AttributeQuery: NameID not found",
                request_id=request_id,
                body=soap_body,
            )

        user_id = name_id_el.text
        # The id as it arrived: it travels back in InResponseTo, so it is
        # not the shortened one the audit keeps. An ID="" stays "", as it
        # always has; only an absent one becomes "_unknown".
        request_id = request_id if request_id is not None else "_unknown"

        logger.info(
            "AttributeQuery for user: %s (request_id=%s)",
            user_id,
            _bounded_request_id(request_id),
        )

        # Get user from config
        user = identities_for(config, request_config()).get_user(user_id)

        if user:
            # Shared resolver (#302). Two behavior changes vs the old inline
            # block, each finishing an existing rule: no fabricated
            # <user>@example.com when the user has no email (#275 - never
            # invent facts about a principal), and custom list attributes
            # reach the XML per-value instead of ",".join-then-resplit
            # (#134). source_acl IS exported here - this surface exists for
            # backend authorization lookups (deliberate divergence from SSO).
            attributes = resolve_saml_attributes(
                loaded.settings, user, include_source_acl=True
            )
        else:
            # Unknown principal (#275): a SAML error status, not a signed
            # assertion full of invented attributes - the SP under test must
            # see the miss, not silently pass on data nanoidp made up.
            logger.warning(f"AttributeQuery for unknown user '{user_id}'")
            error_xml = _build_attribute_query_error_response(
                request_id=request_id,
                issuer_url=effective_saml_entity_id(loaded.settings),
            )
            # Same signing path as the success response (#289 review): with
            # saml_sign_responses on, an SP validating signatures must never
            # meet the one response shape nanoidp forgot to sign.
            error_xml = _sign_attribute_query_response(
                loaded, error_xml, loaded.settings.saml_sign_responses
            )
            _audit_attribute_query(
                "failed",
                request_id=request_id,
                reason="unknown principal",
                size=len(soap_body),
                username=user_id,
            )
            soap_error = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        {error_xml}
    </soap:Body>
</soap:Envelope>"""
            return Response(soap_error, mimetype="text/xml")

        # Build SAML Response
        issuer_url = effective_saml_entity_id(loaded.settings)
        response_xml = _build_attribute_query_response(
            user_id=user_id,
            attributes=attributes,
            request_id=request_id,
            issuer_url=issuer_url,
        )

        # Sign the response (if configured)
        signed_response = _sign_attribute_query_response(
            loaded, response_xml, loaded.settings.saml_sign_responses
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
            details={
                "attributes_count": len(attributes),
                "request_id": _bounded_request_id(request_id),
                "content_length": len(soap_body),
            },
        )

        logger.info(
            f"AttributeQuery response issued for user '{user_id}' with {len(attributes)} attributes"
        )

        return Response(soap_response, mimetype="text/xml")

    except Exception as e:
        logger.exception(f"AttributeQuery error: {e}")

        audit_event(
            "saml_attribute_query",
            "failed",
            endpoint="/saml/attribute-query",
            details={
                "error": str(e),
                "request_id": _bounded_request_id(locals().get("request_id")),
                "content_length": len(request.get_data() or b""),
            },
        )

        return _soap_fault("AttributeQuery failed", client_fault=False)
