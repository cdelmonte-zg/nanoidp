"""
Four settings.yaml keys that used to load and do nothing now do what they
say, and two that never could are reported like any unknown key (#441).

Supported, each with a default equal to the behaviour that was hardcoded:
``oauth.refresh_token_expiry_minutes`` (7 days), ``device_flow.
code_expiry_seconds`` (600) and ``device_flow.polling_interval`` (5), and
``cors_allowed_origins`` (absent: the security profile decides). Reported:
``logging.format`` and ``session.permanent``.

Each test sets a non-default value and observes the effect on the surface a
client sees, not on the Settings object alone: a setting that loads into
Settings and changes nothing is exactly what #441 was about.
"""

import json
import logging
import time

import jwt
import pytest
import yaml

from nanoidp.app import create_app
from nanoidp.config import ConfigManager

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _set(config_dir, **top_level):
    """Merge keys into the per-test copy of the repo's settings.yaml."""
    path = config_dir / "settings.yaml"
    document = yaml.safe_load(path.read_text())
    for key, value in top_level.items():
        if isinstance(value, dict) and isinstance(document.get(key), dict):
            document[key].update(value)
        else:
            document[key] = value
    path.write_text(yaml.safe_dump(document))


def _client(config_dir, **top_level):
    _set(config_dir, **top_level)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _write(tmp_path, settings):
    (tmp_path / "settings.yaml").write_text(yaml.safe_dump(settings))
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({"users": {}}))
    return str(tmp_path)


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


class TestRefreshTokenLifetime:
    def test_the_default_is_the_seven_days_it_always_was(self, client, auth_header):
        tokens = client.post("/token", headers=auth_header, data={
            "grant_type": "password", "username": "admin", "password": "admin",
            "scope": "openid offline_access",
        }).get_json()
        claims = _claims(tokens["refresh_token"])
        assert claims["exp"] - claims["iat"] == 7 * 24 * 60 * 60

    def test_a_configured_lifetime_is_the_refresh_tokens(self, isolated_repo_config, auth_header):
        client = _client(isolated_repo_config, oauth={"refresh_token_expiry_minutes": 90})
        tokens = client.post("/token", headers=auth_header, data={
            "grant_type": "password", "username": "admin", "password": "admin",
            "scope": "openid offline_access",
        }).get_json()
        claims = _claims(tokens["refresh_token"])
        assert claims["exp"] - claims["iat"] == 90 * 60
        # and the access token keeps its own lifetime
        access = _claims(tokens["access_token"])
        assert access["exp"] - access["iat"] != 90 * 60

    def test_a_rotated_refresh_token_gets_the_configured_lifetime_too(
        self, isolated_repo_config, auth_header
    ):
        client = _client(isolated_repo_config, oauth={
            "refresh_token_expiry_minutes": 90, "refresh_token_rotation": True,
        })
        first = client.post("/token", headers=auth_header, data={
            "grant_type": "password", "username": "admin", "password": "admin",
            "scope": "openid offline_access",
        }).get_json()
        rotated = client.post("/token", headers=auth_header, data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"],
        }).get_json()
        claims = _claims(rotated["refresh_token"])
        assert claims["exp"] - claims["iat"] == 90 * 60


class TestDeviceFlowTiming:
    def test_the_defaults_are_the_ones_that_were_hardcoded(self, client, auth_header):
        answer = client.post("/device_authorization", headers=auth_header).get_json()
        assert answer["expires_in"] == 600
        assert answer["interval"] == 5

    def test_the_stores_own_defaults_are_the_settings_defaults(self):
        from nanoidp.models import Settings
        from nanoidp.services.device_code import DEVICE_CODE_EXPIRES_IN, DEVICE_POLL_INTERVAL

        assert Settings().device_code_expiry_seconds == DEVICE_CODE_EXPIRES_IN
        assert Settings().device_polling_interval == DEVICE_POLL_INTERVAL

    def test_the_configured_values_are_announced(self, isolated_repo_config, auth_header):
        client = _client(isolated_repo_config, device_flow={
            "code_expiry_seconds": 120, "polling_interval": 2,
        })
        answer = client.post("/device_authorization", headers=auth_header).get_json()
        assert answer["expires_in"] == 120
        assert answer["interval"] == 2

    def test_a_full_store_says_come_back_after_the_configured_interval(
        self, isolated_repo_config, auth_header, monkeypatch
    ):
        from nanoidp.services import device_code

        monkeypatch.setattr(device_code, "MAX_PENDING_DEVICE_CODES", 1)
        client = _client(isolated_repo_config, device_flow={"polling_interval": 2})
        assert client.post("/device_authorization", headers=auth_header).status_code == 200
        full = client.post("/device_authorization", headers=auth_header)
        assert full.status_code == 503
        assert full.headers["Retry-After"] == "2"

    def test_a_code_expires_after_the_configured_seconds(self, isolated_repo_config, auth_header):
        client = _client(isolated_repo_config, device_flow={"code_expiry_seconds": 1})
        answer = client.post("/device_authorization", headers=auth_header).get_json()
        time.sleep(1.2)
        poll = client.post("/token", headers=auth_header, data={
            "grant_type": DEVICE_GRANT, "device_code": answer["device_code"],
        })
        assert poll.status_code == 400
        assert poll.get_json()["error"] == "expired_token"


class TestCorsAllowedOrigins:
    def _allowed(self, client, origin):
        response = client.get("/.well-known/openid-configuration", headers={"Origin": origin})
        return response.headers.get("Access-Control-Allow-Origin")

    def test_absent_leaves_the_dev_profile_open(self, client):
        assert self._allowed(client, "http://anywhere.test") in ("*", "http://anywhere.test")

    def test_a_list_restricts_the_dev_profile(self, isolated_repo_config):
        client = _client(isolated_repo_config, cors_allowed_origins=["http://app.test:3000"])
        assert self._allowed(client, "http://app.test:3000") == "http://app.test:3000"
        assert self._allowed(client, "http://other.test") is None

    def test_a_list_replaces_the_stricter_dev_default(self, isolated_repo_config):
        client = _client(
            isolated_repo_config,
            security_profile="stricter-dev",
            cors_allowed_origins=["http://app.test:3000"],
        )
        assert self._allowed(client, "http://app.test:3000") == "http://app.test:3000"
        # localhost is the profile's default, not added to an explicit list
        assert self._allowed(client, "http://localhost:5173") is None

    def test_a_star_under_stricter_dev_opens_cors_and_says_so(self, isolated_repo_config, caplog):
        with caplog.at_level(logging.WARNING, logger="nanoidp.app"):
            client = _client(
                isolated_repo_config, security_profile="stricter-dev", cors_allowed_origins=["*"]
            )
        assert self._allowed(client, "http://other.test") in ("*", "http://other.test")
        assert "every origin may call nanoidp" in caplog.text

    def test_no_warning_for_a_list_without_a_star(self, isolated_repo_config, caplog):
        with caplog.at_level(logging.WARNING, logger="nanoidp.app"):
            _client(
                isolated_repo_config,
                security_profile="stricter-dev",
                cors_allowed_origins=["http://app.test"],
            )
        assert "every origin may call nanoidp" not in caplog.text

    def test_absent_keeps_the_stricter_dev_default(self, isolated_repo_config):
        client = _client(isolated_repo_config, security_profile="stricter-dev")
        assert self._allowed(client, "http://localhost:5173") == "http://localhost:5173"
        assert self._allowed(client, "http://other.test") is None

    @pytest.mark.parametrize("origin, allowed", [
        ("http://localhost", True),
        ("http://localhost:5173", True),
        ("http://127.0.0.1:8080", True),
        # flask-cors matches a pattern with re.match, anchored at the start
        # only: "http://localhost:*" used to admit all of these
        ("http://localhost.evil.test", False),
        ("http://localhost:5173.evil.test", False),
        ("http://127.0.0.1.nip.io", False),
        ("http://127a0b0c1.test", False),
        # only the dots differ: an unescaped "." in the pattern admits it
        ("http://127a0a0a1:8080", False),
        ("https://localhost.evil.test", False),
    ])
    def test_the_stricter_dev_default_is_localhost_and_nothing_that_starts_like_it(
        self, isolated_repo_config, origin, allowed
    ):
        client = _client(isolated_repo_config, security_profile="stricter-dev")
        assert (self._allowed(client, origin) == origin) is allowed

    def test_an_ipv6_origin_is_matched_literally(self, isolated_repo_config):
        """[::1] is an origin, and to flask-cors also a regex character
        class: passed as is, it would not match itself and would match
        http://1:3000 (#450 review)."""
        client = _client(isolated_repo_config, cors_allowed_origins=["http://[::1]:3000"])
        assert self._allowed(client, "http://[::1]:3000") == "http://[::1]:3000"
        # reported as the origin it is, not as the pattern that matches it
        assert client.get("/api/config").get_json()["cors_applied_origins"] == ["http://[::1]:3000"]
        assert self._allowed(client, "http://1:3000") is None
        assert self._allowed(client, "http://[::2]:3000") is None
        assert self._allowed(client, "http://[::1]:3001") is None

    def test_mixed_case_entries_admit_the_origin_a_browser_sends(self, isolated_repo_config):
        """Accepted at load because the server compares ignoring case, which
        is checked here on the server and not only at load (#450 review)."""
        client = _client(
            isolated_repo_config,
            cors_allowed_origins=["HTTP://App.Test:3000", "HTTP://[::1]:3000"],
        )
        assert self._allowed(client, "http://app.test:3000") == "http://app.test:3000"
        assert self._allowed(client, "http://[::1]:3000") == "http://[::1]:3000"
        assert self._allowed(client, "http://other.test") is None

    def test_a_declared_list_answers_only_requests_that_carry_an_origin(self, isolated_repo_config):
        """No Access-Control-Allow-Origin without an Origin header, for any
        declared entry: flask-cors's always_send would otherwise pick one of
        them, depending on how the entry is written (#450 review)."""
        client = _client(
            isolated_repo_config, cors_allowed_origins=["http://b.test", "http://a.test", "http://[::1]:3000"],
        )
        response = client.get("/.well-known/openid-configuration")
        assert response.headers.get("Access-Control-Allow-Origin") is None
        # and says it depends on the Origin, so that a cache does not serve
        # this response to a browser that sends one (#450 review, round 5)
        assert "Origin" in response.headers.get("Vary", "")
        with_origin = client.get("/.well-known/openid-configuration", headers={"Origin": "http://a.test"})
        assert with_origin.headers.getlist("Vary") == ["Origin"]

    def test_a_declared_star_behaves_as_the_permissive_default(self, isolated_repo_config):
        declared = _client(isolated_repo_config, cors_allowed_origins=["*"])
        _set(isolated_repo_config, cors_allowed_origins=None)
        document = yaml.safe_load((isolated_repo_config / "settings.yaml").read_text())
        document.pop("cors_allowed_origins")
        (isolated_repo_config / "settings.yaml").write_text(yaml.safe_dump(document))
        absent = _client(isolated_repo_config)
        for headers in ({}, {"Origin": "http://any.test"}):
            got = [
                client.get("/.well-known/openid-configuration", headers=headers).headers.get(
                    "Access-Control-Allow-Origin"
                )
                for client in (declared, absent)
            ]
            assert got[0] == got[1] and got[0] is not None, (headers, got)

    def test_an_empty_list_allows_no_origin(self, isolated_repo_config):
        client = _client(isolated_repo_config, cors_allowed_origins=[])
        assert self._allowed(client, "http://localhost:5173") is None


class TestOneDefaultPerSetting:
    """The defaults are written in the document model and in Settings; a
    file that says nothing must land on Settings' own defaults."""

    def test_the_document_defaults_are_the_domain_defaults(self):
        from nanoidp.config_documents import SettingsDocument
        from nanoidp.models import Settings

        loaded, domain = SettingsDocument().to_settings(), Settings()
        for field in (
            "refresh_token_expiry_minutes",
            "device_code_expiry_seconds",
            "device_polling_interval",
            "cors_allowed_origins",
        ):
            assert getattr(loaded, field) == getattr(domain, field), field


class TestInvalidValuesAreErrors:
    """The keys used to load with any value; now they are validated like
    every other key, so a value that means nothing refuses to load."""

    @pytest.mark.parametrize("settings, path", [
        ({"oauth": {"refresh_token_expiry_minutes": "soon"}}, "oauth.refresh_token_expiry_minutes"),
        ({"oauth": {"refresh_token_expiry_minutes": 0}}, "refresh_token_expiry_minutes"),
        ({"oauth": {"refresh_token_expiry_minutes": 43201}}, "refresh_token_expiry_minutes"),
        ({"device_flow": {"code_expiry_seconds": 0}}, "code_expiry_seconds"),
        ({"device_flow": {"code_expiry_seconds": 3601}}, "code_expiry_seconds"),
        ({"device_flow": {"polling_interval": 0}}, "polling_interval"),
        ({"device_flow": {"polling_interval": 61}}, "polling_interval"),
        ({"device_flow": "whatever"}, "device_flow"),
        # A bare `device_flow:` line: null is not an empty section, the rule
        # every section but login follows (#197 review)
        ({"device_flow": None}, "device_flow"),
        ({"cors_allowed_origins": "*"}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://ok.test", ""]}, "cors_allowed_origins"),
        # a pattern would be matched at the start only (#441 review)
        ({"cors_allowed_origins": ["http://localhost:*"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://*.example.test"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["^http://a.test$"]}, "cors_allowed_origins"),
        # not an origin: scheme://host[:port] and nothing else (#450 review)
        ({"cors_allowed_origins": ["not an origin"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["https://app.example/path"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["https://app.example/"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["https://app.example?x=1"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["https://user@app.example"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["ftp://app.example"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://app.example:99999"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://[not-ipv6]:3000"]}, "cors_allowed_origins"),
        # accepted by urlsplit (an IPvFuture literal), not an IPv6 address
        ({"cors_allowed_origins": ["http://[v1.fe]:3000"]}, "cors_allowed_origins"),
        # characters urlsplit drops silently (#450 review, round 2)
        ({"cors_allowed_origins": ["http://loc\talhost:3000"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://a.exa\nmple"]}, "cors_allowed_origins"),
        # forms a browser never sends: the origin would never match
        ({"cors_allowed_origins": ["https://app.example:443"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://app.example:80"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://[0::1]:3000"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://[::ffff:127.0.0.1]"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://[fe80::1%25eth0]:3000"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://127.1"]}, "cors_allowed_origins"),
        ({"cors_allowed_origins": ["http://app.example:"]}, "cors_allowed_origins"),
        # lowercases to ASCII (KELVIN SIGN), but no browser sends it
        ({"cors_allowed_origins": ["http://\u212a.example"]}, "cors_allowed_origins"),
    ])
    def test_refused(self, tmp_path, settings, path):
        with pytest.raises(ValueError, match=path.replace(".", r"\.")):
            ConfigManager(_write(tmp_path, settings))

    def test_the_bounds_themselves_load(self, tmp_path):
        settings = ConfigManager(_write(tmp_path, {
            "oauth": {"refresh_token_expiry_minutes": 43200},
            "device_flow": {"code_expiry_seconds": 3600, "polling_interval": 60},
            "cors_allowed_origins": ["*"],
        })).settings
        assert settings.refresh_token_expiry_minutes == 43200
        assert settings.device_code_expiry_seconds == 3600
        assert settings.device_polling_interval == 60
        assert settings.cors_allowed_origins == ["*"]
        accepted = [
            "http://localhost:3000", "https://app.example", "http://[::1]:3000", "http://127.0.0.1",
            # Compose-style service names, which browsers do send
            "http://web_app:3000",
            "http://[::ffff:7f00:1]",
            "https://app.example:8443",
            # flask-cors compares origins case-insensitively
            "HTTP://App.Example",
        ]
        assert ConfigManager(
            _write(tmp_path, {"cors_allowed_origins": accepted})
        ).settings.cors_allowed_origins == accepted

    @pytest.mark.parametrize("entry", [
        "https://app.example/callback",
        "https://app.example?x=1",
        "http://user:pw@app.example",
        "http://loc\talhost:3000",
    ])
    def test_what_is_more_than_an_origin_is_not_rewritten_into_one(self, tmp_path, entry):
        """A path or credentials are not a formatting slip: the message says
        the entry is not an origin, instead of offering a wider one."""
        with pytest.raises(ValueError, match="is not an origin") as refused:
            ConfigManager(_write(tmp_path, {"cors_allowed_origins": [entry]}))
        assert "write it as" not in str(refused.value)

    def test_the_ipv6_form_is_the_browsers_whatever_the_python(self):
        """WHATWG serialization, which browsers use for the Origin header;
        Python 3.13 changed ipaddress's compressed form of IPv4-mapped
        addresses to ::ffff:127.0.0.1 (#450 review)."""
        from nanoidp.models import canonical_cors_origin

        for written, browser in [
            ("http://[::ffff:127.0.0.1]", "http://[::ffff:7f00:1]"),
            ("http://[0:0:0:0:0:0:0:1]:3000", "http://[::1]:3000"),
            ("http://[2001:DB8:0:0:1:0:0:1]", "http://[2001:db8::1:0:0:1]"),
            ("http://[1:0:0:2:0:0:0:3]", "http://[1:0:0:2::3]"),
            ("http://[1:0:2:3:4:5:6:7]", "http://[1:0:2:3:4:5:6:7]"),
        ]:
            assert canonical_cors_origin(written) == browser, written

    @pytest.mark.parametrize("entry", [
        "https://bücher.example",
        # Python's idna codec (IDNA2003) maps this to fass.de, a different
        # host from the xn--fa-hia.de a browser sends (UTS #46): nothing may
        # suggest it (#450 review)
        "https://faß.de",
        # lowercases to "k", which no browser sends for it either
        "http://\u212a.example",
    ])
    def test_a_non_ascii_host_is_refused_without_a_rewrite(self, tmp_path, entry):
        """The form a browser sends for an internationalised host is its
        UTS #46 ASCII form; the entry has to be written that way, and no
        other conversion is offered in its place."""
        with pytest.raises(ValueError, match="ASCII") as refused:
            ConfigManager(_write(tmp_path, {"cors_allowed_origins": [entry]}))
        assert "write it as" not in str(refused.value)
        assert "fass.de" not in str(refused.value)
        # nor does the helper compute a form any other caller could offer
        from nanoidp.models import canonical_cors_origin

        assert canonical_cors_origin(entry) is None

    def test_the_ascii_form_of_an_internationalised_host_is_accepted(self, tmp_path):
        for entry in ("https://xn--bcher-kva.example", "https://xn--fa-hia.de"):
            assert ConfigManager(
                _write(tmp_path, {"cors_allowed_origins": [entry]})
            ).settings.cors_allowed_origins == [entry]

    def test_a_trailing_slash_gets_the_form_to_write(self, tmp_path):
        """The slash an address bar adds carries nothing: a slip to correct,
        not a path (#450 review, round 4)."""
        with pytest.raises(ValueError, match="write it as 'https://app.example'"):
            ConfigManager(_write(tmp_path, {"cors_allowed_origins": ["https://app.example/"]}))

    def test_a_non_canonical_origin_is_refused_with_the_form_to_write(self, tmp_path):
        with pytest.raises(ValueError, match="write it as 'https://app.example'"):
            ConfigManager(_write(tmp_path, {"cors_allowed_origins": ["https://app.example:443"]}))
        with pytest.raises(ValueError, match=r"write it as 'http://\[::1\]:3000'"):
            ConfigManager(_write(tmp_path, {"cors_allowed_origins": ["http://[0::1]:3000"]}))


class TestTheTwoKeysNothingReads:
    @pytest.mark.parametrize("settings, path", [
        ({"logging": {"format": "%(message)s"}}, "logging.format"),
        ({"session": {"permanent": True}}, "session.permanent"),
    ])
    def test_warned_about_by_default(self, tmp_path, caplog, settings, path):
        with caplog.at_level(logging.WARNING):
            ConfigManager(_write(tmp_path, settings))
        assert f"unknown key {path} (ignored)" in caplog.text

    @pytest.mark.parametrize("settings, path", [
        ({"logging": {"format": "%(message)s"}}, "logging.format"),
        ({"session": {"permanent": True}}, "session.permanent"),
    ])
    def test_refused_under_strict(self, tmp_path, settings, path):
        with pytest.raises(ValueError, match=f"unknown key {path.replace('.', '[.]')}"):
            ConfigManager(_write(tmp_path, {**settings, "config_validation": "strict"}))

    def test_the_shipped_default_config_carries_neither(self, tmp_path, caplog):
        from pathlib import Path

        shipped = Path(__file__).resolve().parent.parent / "config"
        with caplog.at_level(logging.WARNING):
            ConfigManager(str(shipped), strict_config=True)
        assert "unknown key" not in caplog.text


class TestReportedWhereTheNeighboursAre:
    def test_api_config(self, isolated_repo_config, auth_header):
        client = _client(
            isolated_repo_config,
            oauth={"refresh_token_expiry_minutes": 90},
            device_flow={"code_expiry_seconds": 120, "polling_interval": 2},
            cors_allowed_origins=["http://app.test"],
        )
        config = client.get("/api/config").get_json()
        assert config["oauth"]["refresh_token_expiry_minutes"] == 90
        assert config["device_flow"] == {"code_expiry_seconds": 120, "polling_interval": 2}
        assert config["cors_allowed_origins"] == ["http://app.test"]
        assert config["cors_applied_origins"] == ["http://app.test"]

    def test_api_config_reports_the_origins_in_force_not_only_the_file(self, isolated_repo_config):
        """CORS is set up at startup; a reload changes the declared list but
        not what the server applies, so the report names both (#441 review)."""
        client = _client(isolated_repo_config)
        _set(isolated_repo_config, cors_allowed_origins=["http://app.test"])
        assert client.post("/api/config/reload").status_code == 200
        config = client.get("/api/config").get_json()
        assert config["cors_allowed_origins"] == ["http://app.test"]
        assert config["cors_applied_origins"] == ["*"]
        # and that is what a browser meets
        response = client.get(
            "/.well-known/openid-configuration", headers={"Origin": "http://other.test"}
        )
        assert response.headers.get("Access-Control-Allow-Origin") in ("*", "http://other.test")

    def test_api_config_says_when_cors_is_left_to_the_profile(self, client):
        config = client.get("/api/config").get_json()
        assert config["cors_allowed_origins"] is None
        assert config["cors_applied_origins"] == ["*"]

    @pytest.mark.asyncio
    async def test_mcp_get_settings(self, isolated_repo_config, mcp_call_tool, monkeypatch):
        _set(
            isolated_repo_config,
            oauth={"refresh_token_expiry_minutes": 90},
            device_flow={"code_expiry_seconds": 120, "polling_interval": 2},
            cors_allowed_origins=["http://app.test"],
        )
        monkeypatch.setattr("nanoidp.config._config", ConfigManager(str(isolated_repo_config)))
        result = await mcp_call_tool("get_settings", {})
        assert result.is_error is not True, result.content[0].text
        settings = json.loads(result.content[0].text)
        assert settings["refresh_token_expiry_minutes"] == 90
        assert settings["device_code_expiry_seconds"] == 120
        assert settings["device_polling_interval"] == 2
        assert settings["cors_allowed_origins"] == ["http://app.test"]


class TestWrittenOnlyWhileNotAtTheDefault:
    """Files that never set these keys must not gain them on the next save:
    they are written while they differ from the default and removed when
    they return to it, like the login keys (#319)."""

    def _document(self, config_dir):
        return yaml.safe_load((config_dir / "settings.yaml").read_text())

    def test_a_config_save_at_the_defaults_adds_nothing(self, isolated_repo_config):
        config = ConfigManager(str(isolated_repo_config))
        config.settings.verbose_logging = not config.settings.verbose_logging
        config.save()
        document = self._document(isolated_repo_config)
        assert "refresh_token_expiry_minutes" not in document["oauth"]
        assert "device_flow" not in document

    def test_a_config_save_writes_a_changed_value_and_removes_it_at_the_default(
        self, isolated_repo_config
    ):
        config = ConfigManager(str(isolated_repo_config))
        config.settings.refresh_token_expiry_minutes = 90
        config.settings.device_code_expiry_seconds = 30
        config.save()
        document = self._document(isolated_repo_config)
        assert document["oauth"]["refresh_token_expiry_minutes"] == 90
        assert document["device_flow"] == {"code_expiry_seconds": 30}

        config = ConfigManager(str(isolated_repo_config))
        config.settings.refresh_token_expiry_minutes = 10080
        config.settings.device_code_expiry_seconds = 600
        config.save()
        document = self._document(isolated_repo_config)
        assert "refresh_token_expiry_minutes" not in document["oauth"]
        assert "device_flow" not in document

    def test_the_settings_form_writer(self, isolated_repo_config):
        from nanoidp.services.yaml_writer import YamlWriter

        writer = YamlWriter(str(isolated_repo_config))
        writer.update_oauth_settings(refresh_token_expiry_minutes=10080)
        assert "refresh_token_expiry_minutes" not in self._document(isolated_repo_config)["oauth"]
        writer.update_oauth_settings(refresh_token_expiry_minutes=90)
        assert self._document(isolated_repo_config)["oauth"]["refresh_token_expiry_minutes"] == 90
        writer.update_oauth_settings(refresh_token_expiry_minutes=10080)
        assert "refresh_token_expiry_minutes" not in self._document(isolated_repo_config)["oauth"]

    def test_a_return_to_the_default_does_not_drop_the_fields_saved_with_it(self, isolated_repo_config):
        """The key back at its default can be the last one of its section,
        and removing it removes the section: the fields written after it in
        the same save must still reach the file (#450 review)."""
        path = isolated_repo_config / "settings.yaml"
        document = yaml.safe_load(path.read_text())
        # the only key of its section: removing it removes the section
        document["oauth"] = {"refresh_token_expiry_minutes": 90}
        path.write_text(yaml.safe_dump(document))

        from nanoidp.services.yaml_writer import YamlWriter

        YamlWriter(str(isolated_repo_config)).update_oauth_settings(
            refresh_token_expiry_minutes=10080, require_pkce=True, refresh_token_rotation=True,
        )
        oauth = self._document(isolated_repo_config)["oauth"]
        assert oauth == {"require_pkce": True, "refresh_token_rotation": True}

    def test_the_section_keeps_its_place_and_its_comment(self, tmp_path):
        """Writing the other fields first means the key returned to its
        default is never the section's last when anything else is written:
        the section is not removed and re-created at the end of the file,
        away from its comment (#450 review, round 2)."""
        from nanoidp.services.yaml_writer import YamlWriter

        (tmp_path / "users.yaml").write_text("users: {}\n")
        (tmp_path / "settings.yaml").write_text(
            "server:\n  port: 8000\n# the OAuth block\noauth:\n  refresh_token_expiry_minutes: 90\n"
            "saml:\n  sign_responses: true\n"
        )
        YamlWriter(str(tmp_path)).update_oauth_settings(
            refresh_token_expiry_minutes=10080, require_pkce=True,
        )
        text = (tmp_path / "settings.yaml").read_text()
        assert text.index("# the OAuth block") < text.index("oauth:") < text.index("saml:")
        assert "require_pkce: true" in text and "refresh_token_expiry_minutes" not in text

    @pytest.mark.parametrize("with_clients", [False, True])
    def test_the_same_through_a_partial_settings_form(self, isolated_repo_config, with_clients):
        path = isolated_repo_config / "settings.yaml"
        document = yaml.safe_load(path.read_text())
        oauth = {"refresh_token_expiry_minutes": 90}
        if with_clients:
            oauth["clients"] = document["oauth"]["clients"]
        document["oauth"] = oauth
        path.write_text(yaml.safe_dump(document))
        client = create_app().test_client()

        page = client.post("/settings", data={
            "refresh_token_expiry_minutes": "10080",
            "require_pkce": "true", "require_pkce__on_form": "1",
            "refresh_token_rotation": "true", "refresh_token_rotation__on_form": "1",
        }, follow_redirects=True)
        assert b"Settings updated successfully" in page.data
        saved = self._document(isolated_repo_config)["oauth"]
        assert saved.get("require_pkce") is True
        assert saved.get("refresh_token_rotation") is True
        assert "refresh_token_expiry_minutes" not in saved
        assert ("clients" in saved) is with_clients

    def _commented_file(self, tmp_path, block):
        (tmp_path / "users.yaml").write_text("users: {}\n")
        (tmp_path / "settings.yaml").write_text(
            "server:\n  port: 8000\n# the block\n" + block + "saml:\n  sign_responses: true\n"
        )

    def _assert_in_place(self, tmp_path, section):
        text = (tmp_path / "settings.yaml").read_text()
        assert text.index("# the block") < text.index(f"{section}:") < text.index("saml:"), text

    def test_a_form_save_that_empties_the_section_removes_it(self, isolated_repo_config):
        """Nothing else of the save to write: the emptied section goes, as
        it did before a later write could re-create it (#319)."""
        from nanoidp.services.yaml_writer import YamlWriter

        path = isolated_repo_config / "settings.yaml"
        document = yaml.safe_load(path.read_text())
        document["oauth"] = {"refresh_token_expiry_minutes": 90}
        path.write_text(yaml.safe_dump(document))
        YamlWriter(str(isolated_repo_config)).update_oauth_settings(refresh_token_expiry_minutes=10080)
        assert "oauth" not in self._document(isolated_repo_config)

    def test_login_keeps_its_place_when_one_key_goes_and_another_comes(self, tmp_path):
        """Two defaults-dependent keys in one section: removing the first
        emptied the section, which was dropped at once and created again by
        the second at the end of the file (on main too, since #319; #450
        review). A section left empty is now dropped once the whole save is
        written."""
        from nanoidp.services.yaml_writer import YamlWriter

        self._commented_file(tmp_path, "login:\n  two_step: true\n")
        YamlWriter(str(tmp_path)).update_login_settings(two_step=False, totp=True)
        self._assert_in_place(tmp_path, "login")
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["login"] == {"totp": True}

    def test_device_flow_keeps_its_place_through_a_config_save(self, tmp_path):
        self._commented_file(tmp_path, "device_flow:\n  code_expiry_seconds: 900\n")
        config = ConfigManager(str(tmp_path))
        config.settings.device_code_expiry_seconds = 600
        config.settings.device_polling_interval = 10
        config.save()
        self._assert_in_place(tmp_path, "device_flow")
        assert yaml.safe_load((tmp_path / "settings.yaml").read_text())["device_flow"] == {
            "polling_interval": 10
        }

    def test_a_section_the_save_leaves_empty_is_still_removed(self, tmp_path):
        from nanoidp.services.yaml_writer import YamlWriter

        self._commented_file(tmp_path, "login:\n  two_step: true\n")
        YamlWriter(str(tmp_path)).update_login_settings(two_step=False)
        assert "login" not in yaml.safe_load((tmp_path / "settings.yaml").read_text())

        self._commented_file(tmp_path, "device_flow:\n  code_expiry_seconds: 900\n")
        config = ConfigManager(str(tmp_path))
        config.settings.device_code_expiry_seconds = 600
        config.save()
        assert "device_flow" not in yaml.safe_load((tmp_path / "settings.yaml").read_text())

    def test_the_settings_page_round_trip(self, isolated_repo_config, client):
        page = client.get("/settings")
        assert b'name="refresh_token_expiry_minutes"' in page.data
        assert b'value="10080"' in page.data

    @pytest.mark.asyncio
    async def test_mcp_update_then_save_reaches_the_file(
        self, isolated_repo_config, mcp_call_tool, monkeypatch
    ):
        import nanoidp.mcp_server as mcp

        config = ConfigManager(str(isolated_repo_config))
        monkeypatch.setattr("nanoidp.config._config", config)
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)
        monkeypatch.delenv("NANOIDP_MANAGEMENT_SECRET", raising=False)

        updated = await mcp_call_tool("update_settings", {
            "refresh_token_expiry_minutes": 90,
            "device_code_expiry_seconds": 30,
            "device_polling_interval": 2,
        })
        assert updated.is_error is not True, updated.content[0].text
        saved = await mcp_call_tool("save_config", {})
        assert saved.is_error is not True, saved.content[0].text

        reloaded = ConfigManager(str(isolated_repo_config)).settings
        assert reloaded.refresh_token_expiry_minutes == 90
        assert reloaded.device_code_expiry_seconds == 30
        assert reloaded.device_polling_interval == 2

    @pytest.mark.asyncio
    async def test_mcp_refuses_a_value_out_of_bounds(
        self, isolated_repo_config, mcp_call_tool, monkeypatch
    ):
        import nanoidp.mcp_server as mcp

        config = ConfigManager(str(isolated_repo_config))
        monkeypatch.setattr("nanoidp.config._config", config)
        monkeypatch.setattr(mcp, "_readonly_mode", False)
        monkeypatch.delenv("NANOIDP_MCP_ADMIN_SECRET", raising=False)

        result = await mcp_call_tool("update_settings", {"device_code_expiry_seconds": 0})
        payload = json.loads(result.content[0].text)
        assert payload["code"] == "MCP_INVALID_ARGUMENTS"
        assert config.settings.device_code_expiry_seconds == 600
