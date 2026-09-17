"""Every AttributeQuery outcome is attributable to its sender (#309).

The flake this serves has not been reproduced; what stopped the last two
occurrences from being diagnosed is that a refused query left no audit
entry, and that the query's own id was read only after the request had
already been accepted as well-formed. So: one audit entry per outcome, each
carrying the id the sender chose, read as early as the body allows.
"""

import pytest

from nanoidp.services import get_audit_log

_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body>{inner}</soap:Body></soap:Envelope>"
)
_QUERY = (
    '<saml2p:AttributeQuery xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"'
    ' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}"'
    ' Version="2.0" IssueInstant="2025-01-01T00:00:00Z">'
    "<saml2:Issuer>sp</saml2:Issuer>{subject}</saml2p:AttributeQuery>"
)
_SUBJECT = "<saml2:Subject><saml2:NameID>{user}</saml2:NameID></saml2:Subject>"


def _post(client, body):
    return client.post("/saml/attribute-query", data=body, content_type="text/xml")


def _entries(app):
    with app.app_context():
        return get_audit_log().get_entries(event_type="saml_attribute_query")


def _details(app):
    return [entry.get("details") or {} for entry in _entries(app)]


class TestEveryOutcomeIsAudited:
    def test_a_successful_query(self, app, client):
        _post(client, _ENVELOPE.format(inner=_QUERY.format(
            request_id="_aq-run-query-valid", subject=_SUBJECT.format(user="admin")
        )))

        (details,) = _details(app)
        assert details["request_id"] == "_aq-run-query-valid"
        assert details["content_length"] > 0
        assert _entries(app)[0]["status"] == "success"

    def test_an_unknown_principal(self, app, client):
        _post(client, _ENVELOPE.format(inner=_QUERY.format(
            request_id="_aq-run-query-unknown", subject=_SUBJECT.format(user="nobody")
        )))

        (details,) = _details(app)
        assert details["request_id"] == "_aq-run-query-unknown"
        assert details["reason"] == "unknown principal"

    @pytest.mark.parametrize(
        ("body", "request_id", "reason"),
        [
            (
                _ENVELOPE.format(inner=_QUERY.format(request_id="_aq-run-query-nosub", subject="")),
                "_aq-run-query-nosub",
                "Invalid AttributeQuery: Subject not found",
            ),
            (
                _ENVELOPE.format(
                    inner=_QUERY.format(
                        request_id="_aq-run-query-noname",
                        subject="<saml2:Subject/>",
                    )
                ),
                "_aq-run-query-noname",
                "Invalid AttributeQuery: NameID not found",
            ),
            (
                _ENVELOPE.format(inner="<other/>"),
                None,
                "Invalid AttributeQuery: AttributeQuery element not found",
            ),
            (
                "<not-xml",
                None,
                "Request body is not well-formed XML",
            ),
        ],
        ids=("no-subject", "no-nameid", "no-query", "not-xml"),
    )
    def test_a_refused_query_is_audited_with_what_could_be_read(
        self, app, client, body, request_id, reason
    ):
        """Before #309 these wrote no audit entry at all, so a refused
        request could not be matched to a sender."""
        response = _post(client, body)

        assert response.status_code == 500
        (details,) = _details(app)
        assert details["request_id"] == request_id
        assert details["reason"] == reason
        assert details["content_length"] == len(body.encode())


class TestTheIdIsReadAsEarlyAsTheBodyAllows:
    def test_a_bare_query_is_refused_but_still_named(self, app, client):
        """A query posted without the SOAP envelope is the shape of the
        unexplained 500 of #309: it is still refused, and now the audit says
        which query it was, which is what identifies the sender."""
        response = _post(client, _QUERY.format(
            request_id="_aq-somebody-else", subject=_SUBJECT.format(user="admin")
        ))

        assert response.status_code == 500
        assert b"AttributeQuery element not found" in response.data
        (details,) = _details(app)
        assert details["request_id"] == "_aq-somebody-else"
        assert details["reason"] == "Invalid AttributeQuery: AttributeQuery element not found"

    @pytest.mark.parametrize(
        "body",
        [
            "<samlp:Something xmlns:samlp='urn:x' ID='_not-a-query'/>",
            # The local name alone is not a query: this one is in the
            # assertion namespace, and this one in none at all.
            '<saml2:AttributeQuery xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_wrong-ns"/>',
            '<AttributeQuery ID="_no-ns"/>',
        ],
        ids=("other-element", "assertion-namespace", "no-namespace"),
    )
    def test_a_body_that_is_not_a_query_is_not_named(self, app, client, body):
        """Nothing is invented: a body that says nothing about a query id
        records None rather than a guess."""
        _post(client, body)

        (details,) = _details(app)
        assert details["request_id"] is None

    def test_an_oversized_id_is_kept_as_evidence_not_as_storage(self, app, client):
        """The id comes from an unauthenticated caller and is kept in the
        audit ring: enough of it to match a sender, no more."""
        from nanoidp.routes.saml import MAX_REQUEST_ID_CHARS

        huge = "_" + "a" * 10_000
        _post(client, _ENVELOPE.format(inner=_QUERY.format(
            request_id=huge, subject=_SUBJECT.format(user="admin")
        )))

        (details,) = _details(app)
        assert details["request_id"].startswith("_" + "a" * 50)
        assert len(details["request_id"]) <= MAX_REQUEST_ID_CHARS + len("...(truncated)")

    @pytest.mark.parametrize("subject", ["admin", None], ids=("accepted", "refused"))
    def test_the_size_recorded_is_the_body_actually_read(self, app, client, subject):
        """A declared Content-Length can overstate the body, and a chunked
        request declares none: the evidence is what arrived. Holds on the
        accepted path and on a refusal alike."""
        body = _ENVELOPE.format(inner=_QUERY.format(
            request_id="_aq-run-query-chunked",
            subject=_SUBJECT.format(user=subject) if subject else "",
        ))
        import io

        client.post(
            "/saml/attribute-query",
            input_stream=io.BytesIO(body.encode()),
            content_type="text/xml",
            environ_overrides={
                "wsgi.input_terminated": True,
                "HTTP_TRANSFER_ENCODING": "chunked",
            },
        )

        (details,) = _details(app)
        assert details["content_length"] == len(body.encode())


class TestTheBodyStaysOutOfTheLogUnlessAsked:
    @pytest.mark.parametrize("verbose", [False, True])
    def test_the_body_is_logged_only_under_verbose_logging(
        self, app, client, caplog, verbose
    ):
        """The body carries the NameID, so it is operator-only material."""
        from nanoidp.config import get_config

        with app.app_context():
            get_config().settings.verbose_logging = verbose
        body = _QUERY.format(
            request_id="_aq-run-query-bare", subject=_SUBJECT.format(user="admin")
        )

        with caplog.at_level("DEBUG", logger="nanoidp.routes.saml"):
            _post(client, body)

        logged = "\n".join(record.getMessage() for record in caplog.records)
        assert ("AttributeQuery body:" in logged) is verbose
        # The refusal itself is always logged, with the id and the size.
        assert "_aq-run-query-bare" in logged

    def test_a_refused_request_is_logged_once(self, app, client, caplog):
        """One warning per refused request: the parser's own complaint rides
        in that line instead of adding a second."""
        with caplog.at_level("WARNING", logger="nanoidp.routes.saml"):
            _post(client, "<not-xml")

        warnings = [
            r
            for r in caplog.records
            if r.levelname == "WARNING" and r.name == "nanoidp.routes.saml"
        ]
        assert len(warnings) == 1
        assert "Request body is not well-formed XML" in warnings[0].getMessage()
