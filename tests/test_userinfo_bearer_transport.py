"""
Issue #465: how /userinfo reads the bearer token, RFC 6750. Three channels
are recognised by presence - the Authorization header (scheme compared
case-insensitively), the access_token parameter of a form-encoded POST body
(2.2), and access_token in the query string (2.3) - and what a channel
carries is judged after its presence: the query string is refused whatever
else the request carries (RFC 9700 4.3.2, NanoIDP's policy), two channels
are refused even with one token (section 2), a channel present but
malformed is refused and a valid header beside it is not fallen back on,
and no channel at all is the challenge alone. Every error answer carries
WWW-Authenticate: Bearer with the realm (section 3); the request without
credentials has no error code and no body (3.1).
"""

import json

import pytest

CHALLENGE = 'Bearer realm="userinfo"'


def _failed_userinfo_events(app):
    with app.app_context():
        from nanoidp.services import get_audit_log

        entries = get_audit_log().get_entries(event_type="userinfo_request")
    return [entry for entry in entries if entry["status"] == "failed"]


def _refusal(resp, status, error):
    """The shape every error answer shares: status, the challenge naming the
    error, and the JSON body a client reads."""
    assert resp.status_code == status
    challenge = resp.headers["WWW-Authenticate"]
    assert challenge.startswith(f'{CHALLENGE}, error="{error}", error_description="')
    body = json.loads(resp.data)
    assert body["error"] == error
    assert f'error_description="{body["error_description"]}"' in challenge
    return body["error_description"]


class TestOneChannelWellFormed:
    def test_the_suite_shape_a_form_encoded_post_body(self, client, access_token):
        """What oidcc-userinfo-post-body sends: POST, form-encoded body,
        no Authorization header."""
        resp = client.post("/userinfo", data={"access_token": access_token})
        assert resp.status_code == 200
        assert json.loads(resp.data)["sub"] == "admin"

    def test_the_header_on_get_and_post(self, client, bearer_header):
        for method in (client.get, client.post):
            resp = method("/userinfo", headers=bearer_header)
            assert resp.status_code == 200
            assert json.loads(resp.data)["sub"] == "admin"

    def test_whitespace_after_the_scheme_as_at_token(self, client, access_token):
        """RFC 7235 asks for one space; the header is read leniently on a
        space or a tab, by the same parser the Basic attempt detection at
        /token uses, so a tab does not turn an attempt into "no
        credentials" (review)."""
        resp = client.get("/userinfo", headers={"Authorization": "Bearer\t" + access_token})
        assert resp.status_code == 200

    def test_other_whitespace_is_not_a_separator(self, client, access_token):
        """RFC 7235 names SP; HTAB is accepted leniently; a no-break space
        (latin-1, reachable in a header) is part of the scheme token."""
        resp = client.get("/userinfo", headers={"Authorization": "Bearer\xa0" + access_token})
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == CHALLENGE

    def test_the_scheme_is_case_insensitive(self, client, access_token):
        """RFC 7235: the scheme is a case-insensitive token, as the Basic
        scheme already is at /token."""
        resp = client.get("/userinfo", headers={"Authorization": "bearer " + access_token})
        assert resp.status_code == 200


class TestTheQueryStringIsRefused:
    def test_alone(self, client, access_token):
        resp = client.get("/userinfo", query_string={"access_token": access_token})
        assert "query string" in _refusal(resp, 400, "invalid_request")

    def test_even_beside_a_valid_header(self, client, bearer_header, access_token):
        """Policy, not a fallback: a client that sent it in the query string
        is told so, whatever else it sent."""
        resp = client.get(
            "/userinfo", headers=bearer_header, query_string={"access_token": access_token}
        )
        assert "query string" in _refusal(resp, 400, "invalid_request")


class TestMoreThanOneMethod:
    def test_header_and_body_with_the_same_token(self, client, bearer_header, access_token):
        resp = client.post("/userinfo", headers=bearer_header, data={"access_token": access_token})
        assert "more than one method" in _refusal(resp, 400, "invalid_request")

    def test_header_and_an_empty_body_parameter(self, client, bearer_header):
        """The body channel is present although empty; the header is not
        fallen back on."""
        resp = client.post("/userinfo", headers=bearer_header, data={"access_token": ""})
        _refusal(resp, 400, "invalid_request")


class TestAChannelPresentButMalformed:
    def test_a_bare_bearer_header(self, client):
        resp = client.get("/userinfo", headers={"Authorization": "Bearer"})
        assert "carries no token" in _refusal(resp, 400, "invalid_request")

    def test_an_empty_access_token_in_the_body(self, client):
        resp = client.post("/userinfo", data={"access_token": ""})
        assert "empty" in _refusal(resp, 400, "invalid_request")

    def test_a_body_the_parser_cannot_decode(self, client, bearer_header):
        """RFC 6750 2.2 wants ASCII; werkzeug drops a form it cannot decode.
        The channel was used, badly: refused, and a valid header beside it
        is not fallen back on (review round 2)."""
        for body in (b"access_token=\xff\xfe", b"access%5Ftoken=\xff", b"access_token=caf%C3%A9"):
            resp = client.post(
                "/userinfo", data=body, content_type="application/x-www-form-urlencoded"
            )
            assert "not ASCII" in _refusal(resp, 400, "invalid_request"), body
            resp = client.post(
                "/userinfo",
                headers=bearer_header,
                data=body,
                content_type="application/x-www-form-urlencoded",
            )
            assert "more than one method" in _refusal(resp, 400, "invalid_request"), body

    @pytest.mark.parametrize(
        "body", [b"foo=bar", b"&", b"&&", b"=", b"access_token_hint=x", b"note=caf\xc3\xa9"]
    )
    def test_a_decodable_form_without_the_parameter_is_no_channel(
        self, client, bearer_header, body
    ):
        resp = client.post(
            "/userinfo",
            headers=bearer_header,
            data=body,
            content_type="application/x-www-form-urlencoded",
        )
        assert resp.status_code == 200

    def test_the_body_is_read_up_to_the_limit_and_one_byte(self, app):
        """What makes the reader safe is how much it reads, which no answer
        shows: the stream sees one read of limit + 1 bytes, never a read
        of the whole body."""
        import io

        from nanoidp.routes.oauth import _form_access_token

        class Recording(io.BytesIO):
            # werkzeug's LimitedStream reads through readinto.
            def __init__(self, data):
                super().__init__(data)
                self.sizes: list = []

            def readinto(self, buffer):
                self.sizes.append(len(buffer))
                return super().readinto(buffer)

        app.config["MAX_FORM_MEMORY_SIZE"] = 64
        stream = Recording(b"access_token=" + b"a" * 1000)
        with app.test_request_context(
            "/userinfo",
            method="POST",
            input_stream=stream,
            content_length=1013,
            content_type="application/x-www-form-urlencoded",
        ):
            _form_access_token()
        assert stream.sizes == [65]

    def test_a_small_declared_body_is_read_without_a_buffer_of_the_limit(self, app):
        """A declared length bounds the read further: a 20-byte body asks
        the stream for 21 bytes, not for the whole limit (review round 7)."""
        import io

        from nanoidp.routes.oauth import _form_access_token, _FormToken

        class Recording(io.BytesIO):
            # A raw stream is read through read(); the ask is its argument.
            def __init__(self, data):
                super().__init__(data)
                self.sizes: list = []

            def read(self, size=-1):
                self.sizes.append(size)
                return super().read(size)

        body = b"access_token=abcdefg"
        stream = Recording(body)
        with app.test_request_context(
            "/userinfo",
            method="POST",
            input_stream=stream,
            content_type="application/x-www-form-urlencoded",
            # A terminated input is handed over raw, so the stream sees
            # the reader's own ask rather than werkzeug's capped one.
            environ_overrides={"wsgi.input_terminated": True},
        ):
            assert _form_access_token() == _FormToken(present=True, value="abcdefg")
        assert stream.sizes[0] == len(body) + 1

    def test_a_short_reading_input_is_read_to_the_end(self, app, access_token):
        """A WSGI input may answer a read with fewer bytes than asked; the
        reader loops until the limit or the end, so the token arrives
        whole (review round 6)."""
        import io

        from nanoidp.routes.oauth import _form_access_token, _FormToken

        class Dribbling(io.BytesIO):
            def readinto(self, buffer):
                return super().readinto(memoryview(buffer)[:7])

        body = b"access_token=" + access_token.encode()
        with app.test_request_context(
            "/userinfo",
            method="POST",
            input_stream=Dribbling(body),
            content_length=len(body),
            content_type="application/x-www-form-urlencoded",
        ):
            assert _form_access_token() == _FormToken(present=True, value=access_token)

    def test_a_body_that_ends_before_its_declared_length(self, app):
        """werkzeug raises ClientDisconnected when the input ends before
        the declared length (its test environ does not detect it, so the
        stream raises here); it is a body that used the channel badly,
        answered in the endpoint's own shape rather than a bare 400
        (review round 6)."""
        import io

        from werkzeug.exceptions import ClientDisconnected

        from nanoidp.routes.oauth import _form_access_token

        class Disconnecting(io.BytesIO):
            def readinto(self, buffer):
                raise ClientDisconnected()

        with app.test_request_context(
            "/userinfo",
            method="POST",
            input_stream=Disconnecting(b"access_token=abc"),
            content_length=200,
            content_type="application/x-www-form-urlencoded",
        ):
            form = _form_access_token()
        assert (form.present, form.value) == (True, None)
        assert form.malformed[0] == "form body ended early"

    def test_a_short_body_from_a_server_that_returns_short(self, app):
        """A server that terminates the input itself returns the short body
        without raising; the declared length says it ended early."""
        import io

        from nanoidp.routes.oauth import _form_access_token

        with app.test_request_context(
            "/userinfo",
            method="POST",
            input_stream=io.BytesIO(b"access_token=abc"),
            content_type="application/x-www-form-urlencoded",
            # The builder derives CONTENT_LENGTH from the stream; the
            # declared length is overridden to say more than arrives, and
            # the input is marked terminated, as gunicorn or uwsgi do, so
            # werkzeug hands the raw stream over and raises nothing.
            environ_overrides={"CONTENT_LENGTH": "200", "wsgi.input_terminated": True},
        ):
            form = _form_access_token()
        assert (form.present, form.value) == (True, None)
        assert form.malformed[0] == "form body ended early"

    def test_a_declared_length_past_max_content_length(self, client, app):
        """werkzeug refuses the stream itself for MAX_CONTENT_LENGTH; the
        answer keeps this endpoint's shape instead of a bare 413."""
        app.config["MAX_CONTENT_LENGTH"] = 32
        resp = client.post(
            "/userinfo",
            data=b"access_token=" + b"a" * 100,
            content_type="application/x-www-form-urlencoded",
        )
        assert "size limit" in _refusal(resp, 400, "invalid_request")

    def test_a_complete_body_exactly_at_max_content_length(self, app):
        """The extra byte asked past a complete body makes a terminated
        input raise werkzeug's 413 at MAX_CONTENT_LENGTH; a body received
        in full is a body, not a refusal (review round 8)."""
        import io

        from nanoidp.routes.oauth import _form_access_token, _FormToken

        body = b"access_token=abcdefg"
        app.config["MAX_CONTENT_LENGTH"] = len(body)
        with app.test_request_context(
            "/userinfo",
            method="POST",
            input_stream=io.BytesIO(body),
            content_type="application/x-www-form-urlencoded",
            environ_overrides={"wsgi.input_terminated": True},
        ):
            assert _form_access_token() == _FormToken(present=True, value="abcdefg")

    def test_a_body_past_the_form_size_limit(self, client, bearer_header, app):
        """The read is bounded by werkzeug's own form limit; past it the
        body is a malformed channel, never a bare 413 and never a fallback
        to the header. The limit is lowered for the test."""
        app.config["MAX_FORM_MEMORY_SIZE"] = 64
        body = b"access_token=" + b"a" * 64
        resp = client.post(
            "/userinfo",
            headers=bearer_header,
            data=body,
            content_type="application/x-www-form-urlencoded",
        )
        assert "more than one method" in _refusal(resp, 400, "invalid_request")
        resp = client.post("/userinfo", data=body, content_type="application/x-www-form-urlencoded")
        assert "size limit" in _refusal(resp, 400, "invalid_request")
        assert resp.headers["Cache-Control"] == "no-store"

    def test_a_repeated_access_token_in_the_body(self, client, access_token):
        resp = client.post(
            "/userinfo",
            data=f"access_token={access_token}&access_token={access_token}",
            content_type="application/x-www-form-urlencoded",
        )
        assert "repeated" in _refusal(resp, 400, "invalid_request")

    def test_refusals_are_audited_with_a_fixed_reason(self, client, access_token, app):
        before = len(_failed_userinfo_events(app))
        client.get("/userinfo", query_string={"access_token": access_token})
        client.post("/userinfo", data={"access_token": ""})
        events = _failed_userinfo_events(app)
        assert len(events) == before + 2
        assert [e["details"]["reason"] for e in events[:2]] == [
            "access_token empty",
            "access_token in the query string",
        ]
        assert access_token not in json.dumps(events)


class TestNoCredentials:
    """The challenge alone: no error code, no body, and no audit event
    (section 3.1; a probe without credentials is not a client's mistake)."""

    @pytest.mark.parametrize(
        "shape",
        [
            pytest.param({}, id="nothing"),
            pytest.param({"headers": {"Authorization": "Basic Zm9vOmJhcg=="}}, id="Basic header"),
            pytest.param(
                {"data": "access_token=x", "content_type": "text/plain"}, id="body of another type"
            ),
            pytest.param({"json": {"access_token": "x"}}, id="JSON body"),
            pytest.param(
                {"data": {"access_token": "x"}, "content_type": "multipart/form-data"},
                id="multipart body",
            ),
        ],
    )
    def test_the_challenge_alone(self, client, app, shape):
        before = len(_failed_userinfo_events(app))
        resp = client.post("/userinfo", **shape)
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == CHALLENGE
        assert resp.data == b""
        assert "Content-Type" not in resp.headers
        assert len(_failed_userinfo_events(app)) == before

    def test_a_form_body_on_a_get_is_not_a_channel(self, client, access_token):
        """RFC 6750 2.2: the GET method MUST NOT be used for the body
        parameter, so the body of a GET is not read."""
        resp = client.get("/userinfo", data={"access_token": access_token})
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == CHALLENGE


class TestAPresentedTokenThatFails:
    def test_invalid_token_carries_the_challenge(self, client):
        resp = client.get("/userinfo", headers={"Authorization": "Bearer not.a.jwt"})
        assert _refusal(resp, 401, "invalid_token") == "Token validation failed"

    def test_through_the_body_too(self, client):
        resp = client.post("/userinfo", data={"access_token": "not.a.jwt"})
        _refusal(resp, 401, "invalid_token")

    def test_a_refresh_token_is_not_an_access_token(self, client, auth_header):
        """The token_use check (#34): a refresh token verifies against the
        resource audience and is refused for what it is. An ID token never
        gets that far, its audience is the client (#32)."""
        token = json.loads(
            client.post(
                "/token",
                data={
                    "grant_type": "password",
                    "username": "admin",
                    "password": "admin",
                    "scope": "openid offline_access",
                },
                headers=auth_header,
            ).data
        )["refresh_token"]
        resp = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert _refusal(resp, 401, "invalid_token") == "An access token is required"

    def test_a_revoked_token(self, client, access_token, auth_header, app):
        assert (
            client.post("/revoke", data={"token": access_token}, headers=auth_header).status_code
            == 200
        )
        before = len(_failed_userinfo_events(app))
        resp = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
        assert _refusal(resp, 401, "invalid_token") == "Token has been revoked"
        events = _failed_userinfo_events(app)
        assert len(events) == before + 1
        assert events[0]["details"]["reason"] == "Token has been revoked"


class TestEveryAnswerIsNoStore:
    def test_the_challenge_and_the_refusals(self, client, access_token):
        for resp in (
            client.post("/userinfo"),
            client.get("/userinfo", query_string={"access_token": access_token}),
            client.post("/userinfo", data={"access_token": access_token}),
        ):
            assert resp.headers["Cache-Control"] == "no-store"


class TestTheChallengeBuilder:
    """One builder for every Bearer challenge of the server (RFC 6750 3)."""

    def test_needs_at_least_one_parameter(self):
        from nanoidp.routes._oauth_error import bearer_challenge

        with pytest.raises(ValueError):
            bearer_challenge()

    def test_values_are_quoted_strings(self):
        from nanoidp.routes._oauth_error import bearer_challenge

        assert (
            bearer_challenge(realm="r", error="invalid_token", description='say "no" \\ yes')
            == 'Bearer realm="r", error="invalid_token", error_description="say \\"no\\" \\\\ yes"'
        )

    @pytest.mark.parametrize("value", ["line\r\nbreak", "caf\u00e9", "\u2603"])
    def test_fails_closed_outside_printable_ascii(self, value):
        """Descriptions are fixed text; a value the header could not carry
        is a programming error, not something to clean quietly while the
        JSON body keeps the full text."""
        from nanoidp.routes._oauth_error import bearer_challenge

        with pytest.raises(ValueError):
            bearer_challenge(realm="r", error="invalid_token", description=value)
