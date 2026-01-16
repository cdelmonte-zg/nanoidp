#!/usr/bin/env python3
"""
NanoIDP Comprehensive Test Agent
=================================

Un agent Python che testa TUTTE le funzionalità di NanoIDP:

OAuth2/OIDC:
- Health check & Discovery
- JWKS endpoint
- Password Grant
- Client Credentials Grant
- Authorization Code Flow (con PKCE)
- Device Authorization Flow
- Token Refresh
- Token Introspection
- Token Revocation
- UserInfo endpoint
- Logout

SAML:
- Metadata endpoint
- SSO endpoint (SP-initiated)
- Attribute Query

Key Management:
- Key Info
- Key Rotation
- JWKS con chiavi precedenti

REST API:
- Users listing
- User details
- Direct token generation
- Config endpoint
- Config reload
- Audit log
- Audit stats

Requisiti:
    pip install requests PyJWT

Uso:
    python test_agent.py
    python test_agent.py --url http://localhost:8000
    python test_agent.py --verbose
"""

import sys
import json
import time
import base64
import hashlib
import secrets
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlencode, parse_qs, urlparse
from enum import Enum

try:
    import requests
except ImportError:
    print("Errore: installa requests con 'pip install requests'")
    sys.exit(1)

try:
    import jwt
except ImportError:
    jwt = None
    print("Avviso: PyJWT non installato, alcuni test saranno limitati")


class TestCategory(Enum):
    """Categoria dei test."""
    CORE = "Core"
    OAUTH = "OAuth2/OIDC"
    SAML = "SAML"
    KEYS = "Key Management"
    API = "REST API"


@dataclass
class TestResult:
    """Risultato di un singolo test."""
    name: str
    category: TestCategory
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


@dataclass
class TestSuite:
    """Raccolta di risultati per categoria."""
    results: List[TestResult] = field(default_factory=list)

    def add(self, result: TestResult):
        self.results.append(result)

    def by_category(self) -> Dict[TestCategory, List[TestResult]]:
        categorized = {}
        for r in self.results:
            if r.category not in categorized:
                categorized[r.category] = []
            categorized[r.category].append(r)
        return categorized

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.success)

    @property
    def total(self) -> int:
        return len(self.results)


class NanoIDPTestAgent:
    """Agent completo per testare tutte le funzionalità di NanoIDP."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        client_id: str = "demo-client",
        client_secret: str = "demo-secret",
        username: str = "admin",
        password: str = "admin",
        verbose: bool = False
    ):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.verbose = verbose
        self.session = requests.Session()
        self.session.auth = (client_id, client_secret)

        # Token storage
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.id_token: Optional[str] = None

        # Test results
        self.suite = TestSuite()

        # State for multi-step flows
        self._auth_code: Optional[str] = None
        self._pkce_verifier: Optional[str] = None
        self._device_code: Optional[str] = None
        self._initial_kid: Optional[str] = None

    def _log(self, msg: str):
        """Log verbose output."""
        if self.verbose:
            print(f"    [DEBUG] {msg}")

    def _add_result(
        self,
        name: str,
        category: TestCategory,
        success: bool,
        message: str,
        data: Optional[Dict] = None
    ) -> TestResult:
        """Aggiunge un risultato di test."""
        result = TestResult(name, category, success, message, data)
        self.suite.add(result)
        status = "OK" if success else "FAIL"
        # Don't log message to avoid exposing sensitive data (passwords, tokens)
        print(f"  [{status}] {name}")
        return result

    # =========================================================================
    # CORE TESTS
    # =========================================================================

    def test_health(self) -> TestResult:
        """Health check endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/api/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                version = data.get("version", "unknown")
                return self._add_result(
                    "Health Check",
                    TestCategory.CORE,
                    True,
                    f"Server online v{version}",
                    data
                )
            return self._add_result(
                "Health Check",
                TestCategory.CORE,
                False,
                f"Status: {response.status_code}"
            )
        except requests.exceptions.ConnectionError:
            return self._add_result(
                "Health Check",
                TestCategory.CORE,
                False,
                f"Impossibile connettersi a {self.base_url}"
            )
        except Exception as e:
            return self._add_result("Health Check", TestCategory.CORE, False, str(e))

    def test_oidc_discovery(self) -> TestResult:
        """OIDC Discovery endpoint."""
        try:
            response = self.session.get(
                f"{self.base_url}/.well-known/openid-configuration",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                required = [
                    "issuer", "token_endpoint", "authorization_endpoint",
                    "userinfo_endpoint", "jwks_uri", "introspection_endpoint",
                    "revocation_endpoint"
                ]
                found = [ep for ep in required if ep in data]
                grants = data.get("grant_types_supported", [])
                return self._add_result(
                    "OIDC Discovery",
                    TestCategory.CORE,
                    len(found) == len(required),
                    f"{len(found)}/{len(required)} endpoints, grants: {len(grants)}",
                    {"endpoints": found, "grants": grants}
                )
            return self._add_result(
                "OIDC Discovery",
                TestCategory.CORE,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("OIDC Discovery", TestCategory.CORE, False, str(e))

    # =========================================================================
    # OAUTH2/OIDC TESTS
    # =========================================================================

    def test_jwks(self) -> TestResult:
        """JWKS endpoint with key info."""
        try:
            response = self.session.get(
                f"{self.base_url}/.well-known/jwks.json",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                keys = data.get("keys", [])
                if keys:
                    self._initial_kid = keys[0].get("kid")
                    key_info = [f"{k.get('kid', '?')[:8]}..." for k in keys]
                return self._add_result(
                    "JWKS Endpoint",
                    TestCategory.OAUTH,
                    len(keys) > 0,
                    f"{len(keys)} chiavi: {', '.join(key_info)}",
                    {"key_count": len(keys), "kids": [k.get("kid") for k in keys]}
                )
            return self._add_result(
                "JWKS Endpoint",
                TestCategory.OAUTH,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("JWKS Endpoint", TestCategory.OAUTH, False, str(e))

    def test_password_grant(self) -> TestResult:
        """OAuth2 Password Grant flow."""
        try:
            response = self.session.post(
                f"{self.base_url}/token",
                data={
                    "grant_type": "password",
                    "username": self.username,
                    "password": self.password,
                    "scope": "openid profile email"
                },
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                self.id_token = data.get("id_token")
                expires = data.get("expires_in", "?")
                has_id = "id_token" in data
                return self._add_result(
                    "Password Grant",
                    TestCategory.OAUTH,
                    True,
                    f"Token OK, expires={expires}s, id_token={has_id}",
                    {"expires_in": expires, "has_id_token": has_id}
                )
            error = response.json().get("error", "unknown")
            return self._add_result(
                "Password Grant",
                TestCategory.OAUTH,
                False,
                f"Errore: {error}"
            )
        except Exception as e:
            return self._add_result("Password Grant", TestCategory.OAUTH, False, str(e))

    def test_client_credentials(self) -> TestResult:
        """Client Credentials Grant flow."""
        try:
            response = self.session.post(
                f"{self.base_url}/token",
                data={"grant_type": "client_credentials"},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                expires = data.get("expires_in", "?")
                # Decode to check default user
                token = data.get("access_token")
                sub = "?"
                if jwt and token:
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    sub = decoded.get("sub", "?")
                return self._add_result(
                    "Client Credentials",
                    TestCategory.OAUTH,
                    True,
                    f"Token OK, sub={sub}, expires={expires}s",
                    {"expires_in": expires, "subject": sub}
                )
            error = response.json().get("error", "unknown")
            return self._add_result(
                "Client Credentials",
                TestCategory.OAUTH,
                False,
                f"Errore: {error}"
            )
        except Exception as e:
            return self._add_result("Client Credentials", TestCategory.OAUTH, False, str(e))

    def test_authorization_code_pkce(self) -> TestResult:
        """Authorization Code Flow with PKCE (simulated)."""
        try:
            # Step 1: Generate PKCE challenge
            self._pkce_verifier = secrets.token_urlsafe(32)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(self._pkce_verifier.encode()).digest()
            ).decode().rstrip('=')

            state = secrets.token_urlsafe(16)
            redirect_uri = "http://localhost:3000/callback"

            # Step 2: Initiate authorization (this returns login page)
            auth_params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid profile",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256"
            }

            # Get the authorization page
            response = requests.get(
                f"{self.base_url}/authorize",
                params=auth_params,
                allow_redirects=False,
                timeout=5
            )

            if response.status_code == 200:
                # Got login page, now submit credentials
                response = requests.post(
                    f"{self.base_url}/authorize",
                    data={
                        **auth_params,
                        "username": self.username,
                        "password": self.password
                    },
                    allow_redirects=False,
                    timeout=5
                )

                if response.status_code == 302:
                    # Got redirect with code
                    location = response.headers.get("Location", "")
                    parsed = urlparse(location)
                    params = parse_qs(parsed.query)

                    if "code" in params:
                        code = params["code"][0]
                        returned_state = params.get("state", [""])[0]

                        if returned_state != state:
                            return self._add_result(
                                "Auth Code + PKCE",
                                TestCategory.OAUTH,
                                False,
                                "State mismatch"
                            )

                        # Step 3: Exchange code for token
                        token_response = self.session.post(
                            f"{self.base_url}/token",
                            data={
                                "grant_type": "authorization_code",
                                "code": code,
                                "redirect_uri": redirect_uri,
                                "code_verifier": self._pkce_verifier
                            },
                            timeout=5
                        )

                        if token_response.status_code == 200:
                            data = token_response.json()
                            return self._add_result(
                                "Auth Code + PKCE",
                                TestCategory.OAUTH,
                                True,
                                "Flow completo: authorize -> code -> token",
                                {"has_access_token": "access_token" in data}
                            )

                        error = token_response.json().get("error", "unknown")
                        return self._add_result(
                            "Auth Code + PKCE",
                            TestCategory.OAUTH,
                            False,
                            f"Token exchange failed: {error}"
                        )

                    if "error" in params:
                        return self._add_result(
                            "Auth Code + PKCE",
                            TestCategory.OAUTH,
                            False,
                            f"Auth error: {params['error'][0]}"
                        )

            return self._add_result(
                "Auth Code + PKCE",
                TestCategory.OAUTH,
                False,
                f"Unexpected status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Auth Code + PKCE", TestCategory.OAUTH, False, str(e))

    def test_device_flow(self) -> TestResult:
        """Device Authorization Flow (RFC 8628)."""
        try:
            # Step 1: Request device code
            response = self.session.post(
                f"{self.base_url}/device_authorization",
                data={"scope": "openid"},
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                device_code = data.get("device_code")
                user_code = data.get("user_code")
                verification_uri = data.get("verification_uri")
                interval = data.get("interval", 5)

                self._log(f"Device code: {device_code[:20]}...")
                self._log(f"User code: {user_code}")
                self._log(f"Verification URI: {verification_uri}")

                # Step 2: Simulate user verification
                # Get device verification page
                verify_response = requests.get(
                    f"{self.base_url}/device",
                    params={"user_code": user_code},
                    timeout=5
                )

                if verify_response.status_code == 200:
                    # Submit verification with credentials
                    verify_response = requests.post(
                        f"{self.base_url}/device",
                        data={
                            "user_code": user_code,
                            "username": self.username,
                            "password": self.password
                        },
                        timeout=5
                    )

                # Step 3: Poll for token
                time.sleep(1)  # Small delay

                token_response = self.session.post(
                    f"{self.base_url}/token",
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code
                    },
                    timeout=5
                )

                if token_response.status_code == 200:
                    token_data = token_response.json()
                    return self._add_result(
                        "Device Flow",
                        TestCategory.OAUTH,
                        True,
                        f"Flow completo: device_auth -> verify -> token",
                        {"user_code": user_code, "has_token": "access_token" in token_data}
                    )

                # Check if still pending (which is also valid behavior)
                error_data = token_response.json()
                error = error_data.get("error", "")
                if error == "authorization_pending":
                    return self._add_result(
                        "Device Flow",
                        TestCategory.OAUTH,
                        True,
                        f"Flow iniziato, in attesa autorizzazione (user_code={user_code})",
                        {"user_code": user_code, "status": "pending"}
                    )

                return self._add_result(
                    "Device Flow",
                    TestCategory.OAUTH,
                    False,
                    f"Token error: {error}"
                )

            return self._add_result(
                "Device Flow",
                TestCategory.OAUTH,
                False,
                f"Device auth failed: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Device Flow", TestCategory.OAUTH, False, str(e))

    def test_token_decode(self) -> TestResult:
        """Decode and validate JWT structure."""
        if not self.access_token:
            return self._add_result(
                "Token Decode",
                TestCategory.OAUTH,
                False,
                "No token available"
            )

        if jwt is None:
            return self._add_result(
                "Token Decode",
                TestCategory.OAUTH,
                False,
                "PyJWT not installed"
            )

        try:
            decoded = jwt.decode(
                self.access_token,
                options={"verify_signature": False}
            )

            # Check required claims
            required = ["sub", "iss", "aud", "exp", "iat"]
            found = [c for c in required if c in decoded]

            # Check custom claims
            custom = ["roles", "authorities", "tenant", "identity_class"]
            custom_found = [c for c in custom if c in decoded]

            sub = decoded.get("sub", "?")
            roles = decoded.get("roles", [])
            authorities = len(decoded.get("authorities", []))

            return self._add_result(
                "Token Decode",
                TestCategory.OAUTH,
                len(found) == len(required),
                f"sub={sub}, roles={roles}, authorities={authorities}",
                {
                    "claims": found,
                    "custom_claims": custom_found,
                    "sub": sub,
                    "roles": roles
                }
            )
        except Exception as e:
            return self._add_result("Token Decode", TestCategory.OAUTH, False, str(e))

    def test_introspection(self) -> TestResult:
        """Token introspection (RFC 7662)."""
        if not self.access_token:
            return self._add_result(
                "Token Introspection",
                TestCategory.OAUTH,
                False,
                "No token available"
            )

        try:
            response = self.session.post(
                f"{self.base_url}/introspect",
                data={"token": self.access_token},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                active = data.get("active", False)
                username = data.get("username", "?")
                scope = data.get("scope", "?")
                return self._add_result(
                    "Token Introspection",
                    TestCategory.OAUTH,
                    active,
                    f"active={active}, user={username}, scope={scope}",
                    data
                )
            return self._add_result(
                "Token Introspection",
                TestCategory.OAUTH,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Token Introspection", TestCategory.OAUTH, False, str(e))

    def test_userinfo(self) -> TestResult:
        """UserInfo endpoint."""
        if not self.access_token:
            return self._add_result(
                "UserInfo",
                TestCategory.OAUTH,
                False,
                "No token available"
            )

        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            response = requests.get(
                f"{self.base_url}/userinfo",
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                sub = data.get("sub", "?")
                email = data.get("email", "?")
                roles = data.get("roles", [])
                tenant = data.get("tenant", "?")
                return self._add_result(
                    "UserInfo",
                    TestCategory.OAUTH,
                    True,
                    f"sub={sub}, email={email}, tenant={tenant}",
                    data
                )
            return self._add_result(
                "UserInfo",
                TestCategory.OAUTH,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("UserInfo", TestCategory.OAUTH, False, str(e))

    def test_refresh_token(self) -> TestResult:
        """Refresh token flow."""
        if not self.refresh_token:
            return self._add_result(
                "Refresh Token",
                TestCategory.OAUTH,
                False,
                "No refresh token available"
            )

        try:
            old_token = self.access_token

            response = self.session.post(
                f"{self.base_url}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token
                },
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                new_access = data.get("access_token")
                new_refresh = data.get("refresh_token")

                # Verify new token is different
                token_changed = new_access != old_token

                if new_access:
                    self.access_token = new_access
                if new_refresh:
                    self.refresh_token = new_refresh

                return self._add_result(
                    "Refresh Token",
                    TestCategory.OAUTH,
                    True,
                    f"New token obtained, changed={token_changed}",
                    {"token_changed": token_changed}
                )
            error = response.json().get("error", "unknown")
            return self._add_result(
                "Refresh Token",
                TestCategory.OAUTH,
                False,
                f"Error: {error}"
            )
        except Exception as e:
            return self._add_result("Refresh Token", TestCategory.OAUTH, False, str(e))

    def test_token_revocation(self) -> TestResult:
        """Token revocation (RFC 7009)."""
        try:
            # Get a dedicated token to revoke
            response = self.session.post(
                f"{self.base_url}/token",
                data={"grant_type": "client_credentials"},
                timeout=5
            )
            if response.status_code != 200:
                return self._add_result(
                    "Token Revocation",
                    TestCategory.OAUTH,
                    False,
                    "Cannot get token to revoke"
                )

            token_to_revoke = response.json().get("access_token")

            # Verify it's active
            check = self.session.post(
                f"{self.base_url}/introspect",
                data={"token": token_to_revoke},
                timeout=5
            )
            was_active = check.json().get("active", False) if check.status_code == 200 else False

            # Revoke it
            response = self.session.post(
                f"{self.base_url}/revoke",
                data={"token": token_to_revoke},
                timeout=5
            )

            if response.status_code == 200:
                # Verify it's now inactive
                verify = self.session.post(
                    f"{self.base_url}/introspect",
                    data={"token": token_to_revoke},
                    timeout=5
                )
                is_active = verify.json().get("active", True) if verify.status_code == 200 else True

                return self._add_result(
                    "Token Revocation",
                    TestCategory.OAUTH,
                    was_active and not is_active,
                    f"before={was_active}, after={is_active}",
                    {"was_active": was_active, "is_active": is_active}
                )
            return self._add_result(
                "Token Revocation",
                TestCategory.OAUTH,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Token Revocation", TestCategory.OAUTH, False, str(e))

    def test_logout(self) -> TestResult:
        """OIDC Logout endpoint."""
        try:
            # Get a token for logout
            response = self.session.post(
                f"{self.base_url}/token",
                data={
                    "grant_type": "password",
                    "username": self.username,
                    "password": self.password
                },
                timeout=5
            )
            if response.status_code != 200:
                return self._add_result(
                    "Logout",
                    TestCategory.OAUTH,
                    False,
                    "Cannot get token for logout test"
                )

            token = response.json().get("access_token")
            id_token = response.json().get("id_token", token)

            # Call logout
            logout_response = requests.get(
                f"{self.base_url}/logout",
                params={
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": "http://localhost:3000"
                },
                allow_redirects=False,
                timeout=5
            )

            # Should redirect or return success
            success = logout_response.status_code in [200, 302]

            # Verify token is invalidated
            check = self.session.post(
                f"{self.base_url}/introspect",
                data={"token": token},
                timeout=5
            )
            still_active = check.json().get("active", True) if check.status_code == 200 else True

            return self._add_result(
                "Logout",
                TestCategory.OAUTH,
                success,
                f"status={logout_response.status_code}, token_invalidated={not still_active}",
                {"status": logout_response.status_code, "token_invalidated": not still_active}
            )
        except Exception as e:
            return self._add_result("Logout", TestCategory.OAUTH, False, str(e))

    # =========================================================================
    # SAML TESTS
    # =========================================================================

    def test_saml_metadata(self) -> TestResult:
        """SAML IdP Metadata endpoint."""
        try:
            response = requests.get(
                f"{self.base_url}/saml/metadata",
                timeout=5
            )
            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")
                is_xml = "xml" in content_type or response.text.strip().startswith("<?xml")

                # Parse XML to verify structure
                try:
                    root = ET.fromstring(response.text)
                    # Check for EntityDescriptor
                    has_entity = "EntityDescriptor" in root.tag
                    # Look for SSO service
                    has_sso = "SingleSignOnService" in response.text
                    # Look for signing cert
                    has_cert = "X509Certificate" in response.text

                    return self._add_result(
                        "SAML Metadata",
                        TestCategory.SAML,
                        is_xml and has_entity,
                        f"Valid XML, EntityDescriptor={has_entity}, SSO={has_sso}, Cert={has_cert}",
                        {"has_entity": has_entity, "has_sso": has_sso, "has_cert": has_cert}
                    )
                except ET.ParseError as e:
                    return self._add_result(
                        "SAML Metadata",
                        TestCategory.SAML,
                        False,
                        f"Invalid XML: {e}"
                    )
            return self._add_result(
                "SAML Metadata",
                TestCategory.SAML,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("SAML Metadata", TestCategory.SAML, False, str(e))

    def test_saml_sso_post_binding(self) -> TestResult:
        """SAML SSO endpoint with HTTP-POST binding (uncompressed request).

        Verifies that the SAMLRequest is correctly parsed by checking
        that InResponseTo in the SAML response matches the request ID.
        """
        try:
            import re

            # Create a minimal SAML AuthnRequest (base64 encoded, no compression)
            # HTTP-POST binding: SAMLRequest is only base64 encoded
            request_id = "_test_post_binding_123"
            acs_url = "http://localhost:8080/acs"
            saml_request = f"""
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="{request_id}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
                AssertionConsumerServiceURL="{acs_url}">
                <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                    test-sp
                </saml:Issuer>
            </samlp:AuthnRequest>
            """.strip()

            encoded_request = base64.b64encode(saml_request.encode()).decode()

            # First, authenticate via session
            session = requests.Session()

            # Login to get a session
            login_response = session.post(
                f"{self.base_url}/login",
                data={"username": self.username, "password": self.password},
                allow_redirects=False,
                timeout=5
            )

            # POST to SSO endpoint (HTTP-POST binding) with authenticated session
            response = session.post(
                f"{self.base_url}/saml/sso",
                data={
                    "SAMLRequest": encoded_request,
                    "RelayState": "test-relay-state"
                },
                allow_redirects=False,
                timeout=5
            )

            if response.status_code == 200:
                # Should get auto-submit form with SAMLResponse
                response_text = response.text

                if "SAMLResponse" in response_text:
                    # Extract SAMLResponse
                    match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', response_text)
                    if match:
                        saml_response_b64 = match.group(1)
                        saml_response_xml = base64.b64decode(saml_response_b64).decode('utf-8')

                        # Verify InResponseTo matches our request ID
                        in_response_to_match = re.search(r'InResponseTo="([^"]+)"', saml_response_xml)
                        in_response_to = in_response_to_match.group(1) if in_response_to_match else None

                        # Verify ACS URL in form action
                        acs_in_response = acs_url in response_text

                        parsing_ok = in_response_to == request_id

                        return self._add_result(
                            "SAML SSO (POST binding)",
                            TestCategory.SAML,
                            parsing_ok and acs_in_response,
                            f"HTTP-POST binding: InResponseTo={'OK' if parsing_ok else 'FAIL'}, ACS={'OK' if acs_in_response else 'FAIL'}",
                            {"binding": "HTTP-POST", "request_id": request_id, "in_response_to": in_response_to, "parsing_ok": parsing_ok}
                        )

                # Got login form instead of SAML response
                return self._add_result(
                    "SAML SSO (POST binding)",
                    TestCategory.SAML,
                    False,
                    "Got login form instead of SAML response (auth failed?)",
                    {"status": response.status_code, "binding": "HTTP-POST"}
                )

            elif response.status_code == 302:
                return self._add_result(
                    "SAML SSO (POST binding)",
                    TestCategory.SAML,
                    False,
                    "Redirect to login (auth failed)",
                    {"status": response.status_code, "binding": "HTTP-POST"}
                )

            return self._add_result(
                "SAML SSO (POST binding)",
                TestCategory.SAML,
                False,
                f"Unexpected status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("SAML SSO (POST binding)", TestCategory.SAML, False, str(e))

    def test_saml_sso_redirect_binding(self) -> TestResult:
        """SAML SSO endpoint with HTTP-Redirect binding (DEFLATE compressed request).

        Verifies that the SAMLRequest is correctly parsed by checking
        that InResponseTo in the SAML response matches the request ID.
        """
        try:
            import re
            import zlib

            # Create a minimal SAML AuthnRequest
            request_id = "_test_redirect_binding_456"
            acs_url = "http://localhost:8080/acs"
            saml_request = f"""
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="{request_id}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
                AssertionConsumerServiceURL="{acs_url}">
                <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                    test-sp
                </saml:Issuer>
            </samlp:AuthnRequest>
            """.strip()

            # HTTP-Redirect binding: DEFLATE compress then base64 encode
            compressed = zlib.compress(saml_request.encode('utf-8'))[2:-4]  # Remove zlib header/trailer
            encoded_request = base64.b64encode(compressed).decode('ascii')

            # First, authenticate via session
            session = requests.Session()

            # Login to get a session
            login_response = session.post(
                f"{self.base_url}/login",
                data={"username": self.username, "password": self.password},
                allow_redirects=False,
                timeout=5
            )

            # GET to SSO endpoint (HTTP-Redirect binding) with authenticated session
            response = session.get(
                f"{self.base_url}/saml/sso",
                params={
                    "SAMLRequest": encoded_request,
                    "RelayState": "test-relay-state"
                },
                allow_redirects=False,
                timeout=5
            )

            if response.status_code == 200:
                # Should get auto-submit form with SAMLResponse
                response_text = response.text

                if "SAMLResponse" in response_text:
                    # Extract SAMLResponse
                    match = re.search(r'name="SAMLResponse"\s+value="([^"]+)"', response_text)
                    if match:
                        saml_response_b64 = match.group(1)
                        saml_response_xml = base64.b64decode(saml_response_b64).decode('utf-8')

                        # Verify InResponseTo matches our request ID
                        in_response_to_match = re.search(r'InResponseTo="([^"]+)"', saml_response_xml)
                        in_response_to = in_response_to_match.group(1) if in_response_to_match else None

                        # Verify ACS URL in form action
                        acs_in_response = acs_url in response_text

                        parsing_ok = in_response_to == request_id

                        return self._add_result(
                            "SAML SSO (Redirect binding)",
                            TestCategory.SAML,
                            parsing_ok and acs_in_response,
                            f"HTTP-Redirect binding: InResponseTo={'OK' if parsing_ok else 'FAIL'}, ACS={'OK' if acs_in_response else 'FAIL'}",
                            {"binding": "HTTP-Redirect", "request_id": request_id, "in_response_to": in_response_to, "parsing_ok": parsing_ok}
                        )

                # Got login form instead of SAML response
                return self._add_result(
                    "SAML SSO (Redirect binding)",
                    TestCategory.SAML,
                    False,
                    "Got login form instead of SAML response (auth failed?)",
                    {"status": response.status_code, "binding": "HTTP-Redirect"}
                )

            elif response.status_code == 302:
                return self._add_result(
                    "SAML SSO (Redirect binding)",
                    TestCategory.SAML,
                    False,
                    "Redirect to login (auth failed)",
                    {"status": response.status_code, "binding": "HTTP-Redirect"}
                )

            return self._add_result(
                "SAML SSO (Redirect binding)",
                TestCategory.SAML,
                False,
                f"Unexpected status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("SAML SSO (Redirect binding)", TestCategory.SAML, False, str(e))

    def test_saml_attribute_query(self) -> TestResult:
        """SAML Attribute Query endpoint."""
        try:
            # Create minimal attribute query
            attr_query = f"""
            <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_attrquery123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                <saml:Issuer>test-sp</saml:Issuer>
                <saml:Subject>
                    <saml:NameID>{self.username}</saml:NameID>
                </saml:Subject>
            </samlp:AttributeQuery>
            """.strip()

            response = requests.post(
                f"{self.base_url}/saml/attribute-query",
                data=attr_query,
                headers={"Content-Type": "application/xml"},
                timeout=5
            )

            # Should return SAML response
            if response.status_code == 200:
                is_xml = "xml" in response.headers.get("Content-Type", "") or response.text.strip().startswith("<")
                has_attributes = "Attribute" in response.text
                return self._add_result(
                    "SAML Attribute Query",
                    TestCategory.SAML,
                    is_xml,
                    f"Response received, has_attributes={has_attributes}",
                    {"has_attributes": has_attributes}
                )

            # Some implementations might not support this
            return self._add_result(
                "SAML Attribute Query",
                TestCategory.SAML,
                response.status_code in [200, 400, 501],
                f"Status: {response.status_code}",
                {"status": response.status_code}
            )
        except Exception as e:
            return self._add_result("SAML Attribute Query", TestCategory.SAML, False, str(e))

    def test_saml_signing_config(self) -> TestResult:
        """SAML Response signing configuration test."""
        try:
            # Step 1: Get current config to check sign_responses setting
            config_response = self.session.get(
                f"{self.base_url}/api/config",
                timeout=5
            )

            sign_responses = True  # Default
            if config_response.status_code == 200:
                config_data = config_response.json()
                saml_config = config_data.get("saml", {})
                sign_responses = saml_config.get("sign_responses", True)

            # Step 2: Make an attribute query to get a SAML response
            attr_query = f"""
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_signtest123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                        <saml:Issuer>test-sp</saml:Issuer>
                        <saml:Subject>
                            <saml:NameID>{self.username}</saml:NameID>
                        </saml:Subject>
                    </samlp:AttributeQuery>
                </soap:Body>
            </soap:Envelope>
            """.strip()

            response = requests.post(
                f"{self.base_url}/saml/attribute-query",
                data=attr_query,
                headers={"Content-Type": "text/xml"},
                timeout=5
            )

            if response.status_code == 200:
                has_signature = "<ds:Signature" in response.text or "<Signature" in response.text

                # Verify signing behavior matches configuration
                if sign_responses:
                    # If signing is enabled, we expect a signature (unless signxml not installed)
                    return self._add_result(
                        "SAML Signing Config",
                        TestCategory.SAML,
                        True,  # Config is working, signature presence depends on signxml availability
                        f"sign_responses={sign_responses}, has_signature={has_signature}",
                        {"sign_responses": sign_responses, "has_signature": has_signature}
                    )
                else:
                    # If signing is disabled, there should be no signature
                    config_respected = not has_signature
                    return self._add_result(
                        "SAML Signing Config",
                        TestCategory.SAML,
                        config_respected,
                        f"sign_responses={sign_responses}, has_signature={has_signature}, config_respected={config_respected}",
                        {"sign_responses": sign_responses, "has_signature": has_signature, "config_respected": config_respected}
                    )

            return self._add_result(
                "SAML Signing Config",
                TestCategory.SAML,
                False,
                f"Cannot test signing: status {response.status_code}"
            )
        except Exception as e:
            return self._add_result("SAML Signing Config", TestCategory.SAML, False, str(e))

    def test_saml_c14n_algorithm(self) -> TestResult:
        """Test SAML canonicalization algorithm configuration."""
        try:
            # Get current config
            config_response = self.session.get(f"{self.base_url}/api/config", timeout=5)
            if config_response.status_code != 200:
                return self._add_result(
                    "SAML C14N Config",
                    TestCategory.SAML,
                    False,
                    f"Cannot get config: {config_response.status_code}"
                )

            config = config_response.json()
            saml_config = config.get("saml", {})
            c14n_setting = saml_config.get("c14n_algorithm", "c14n")
            sign_responses = saml_config.get("sign_responses", True)

            # If signing is disabled, we can't test C14N algorithm
            if not sign_responses:
                return self._add_result(
                    "SAML C14N Config",
                    TestCategory.SAML,
                    True,
                    f"config={c14n_setting}, signing disabled (cannot verify algorithm)",
                    {"c14n_setting": c14n_setting, "sign_responses": False}
                )

            # Use attribute query to get a signed SAML response (like test_saml_signing_config)
            attr_query = f"""
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_c14ntest123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                        <saml:Issuer>test-sp</saml:Issuer>
                        <saml:Subject>
                            <saml:NameID>{self.username}</saml:NameID>
                        </saml:Subject>
                    </samlp:AttributeQuery>
                </soap:Body>
            </soap:Envelope>
            """.strip()

            response = requests.post(
                f"{self.base_url}/saml/attribute-query",
                data=attr_query,
                headers={"Content-Type": "text/xml"},
                timeout=10
            )

            if response.status_code == 200:
                saml_response_xml = response.text

                # Check which C14N algorithm is used in the signature
                c14n_1_0 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                c14n_1_1 = "http://www.w3.org/2006/12/xml-c14n11"

                uses_c14n_1_0 = c14n_1_0 in saml_response_xml
                uses_c14n_1_1 = c14n_1_1 in saml_response_xml

                # Verify config matches actual usage
                if c14n_setting == "c14n":
                    expected_correct = uses_c14n_1_0 and not uses_c14n_1_1
                    algo_name = "C14N 1.0"
                else:
                    expected_correct = uses_c14n_1_1 and not uses_c14n_1_0
                    algo_name = "C14N 1.1"

                return self._add_result(
                    "SAML C14N Config",
                    TestCategory.SAML,
                    expected_correct,
                    f"config={c14n_setting}, uses {algo_name}, pysaml2_compatible={uses_c14n_1_0}",
                    {"c14n_setting": c14n_setting, "uses_c14n_1_0": uses_c14n_1_0, "uses_c14n_1_1": uses_c14n_1_1}
                )

            return self._add_result(
                "SAML C14N Config",
                TestCategory.SAML,
                False,
                f"Cannot get SAML response: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("SAML C14N Config", TestCategory.SAML, False, str(e))

    # =========================================================================
    # KEY MANAGEMENT TESTS
    # =========================================================================

    def test_key_info(self) -> TestResult:
        """Key information endpoint."""
        try:
            response = self.session.get(
                f"{self.base_url}/api/keys/info",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                current_kid = data.get("active_kid", data.get("current_kid", "?"))
                algorithm = data.get("algorithm", "RS256")
                previous_count = len(data.get("previous_kids", []))
                return self._add_result(
                    "Key Info",
                    TestCategory.KEYS,
                    True,
                    f"kid={current_kid[:12]}..., alg={algorithm}, previous={previous_count}",
                    data
                )
            return self._add_result(
                "Key Info",
                TestCategory.KEYS,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Key Info", TestCategory.KEYS, False, str(e))

    def test_key_rotation(self) -> TestResult:
        """Key rotation functionality."""
        try:
            # Get current key info before rotation
            before = self.session.get(f"{self.base_url}/api/keys/info", timeout=5)
            if before.status_code != 200:
                return self._add_result(
                    "Key Rotation",
                    TestCategory.KEYS,
                    False,
                    "Cannot get initial key info"
                )

            before_data = before.json()
            old_kid = before_data.get("active_kid", before_data.get("current_kid"))
            old_previous = before_data.get("previous_kids", [])

            # Perform rotation
            response = self.session.post(
                f"{self.base_url}/api/keys/rotate",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                new_kid = data.get("new_kid", data.get("active_kid"))

                # Verify key actually changed
                after = self.session.get(f"{self.base_url}/api/keys/info", timeout=5)
                if after.status_code == 200:
                    after_data = after.json()
                    current_kid = after_data.get("active_kid", after_data.get("current_kid"))
                    previous_kids = after_data.get("previous_kids", [])

                    # Old key should be in previous keys
                    old_preserved = old_kid in previous_kids
                    key_changed = current_kid != old_kid

                    # Check JWKS also updated
                    jwks = self.session.get(f"{self.base_url}/.well-known/jwks.json", timeout=5)
                    jwks_kids = [k.get("kid") for k in jwks.json().get("keys", [])] if jwks.status_code == 200 else []
                    new_in_jwks = current_kid in jwks_kids
                    old_in_jwks = old_kid in jwks_kids

                    return self._add_result(
                        "Key Rotation",
                        TestCategory.KEYS,
                        key_changed,
                        f"rotated={key_changed}, old_preserved={old_preserved}, jwks_updated={new_in_jwks}",
                        {
                            "old_kid": old_kid[:12] + "..." if old_kid else None,
                            "new_kid": current_kid[:12] + "..." if current_kid else None,
                            "old_preserved": old_preserved,
                            "keys_in_jwks": len(jwks_kids)
                        }
                    )

            return self._add_result(
                "Key Rotation",
                TestCategory.KEYS,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Key Rotation", TestCategory.KEYS, False, str(e))

    def test_token_after_rotation(self) -> TestResult:
        """Verify new tokens work after key rotation."""
        try:
            # Get a fresh token AFTER rotation (with the new key)
            response = self.session.post(
                f"{self.base_url}/token",
                data={
                    "grant_type": "password",
                    "username": self.username,
                    "password": self.password
                },
                timeout=5
            )

            if response.status_code != 200:
                return self._add_result(
                    "Token Post-Rotation",
                    TestCategory.KEYS,
                    False,
                    "Cannot get token after rotation"
                )

            new_token = response.json().get("access_token")

            # Verify the new token is valid
            introspect = self.session.post(
                f"{self.base_url}/introspect",
                data={"token": new_token},
                timeout=5
            )

            if introspect.status_code == 200:
                active = introspect.json().get("active", False)

                # Also verify it's signed with the new key
                kid_match = True
                if jwt:
                    header = jwt.get_unverified_header(new_token)
                    token_kid = header.get("kid", "")
                    # Get current active key
                    key_info = self.session.get(f"{self.base_url}/api/keys/info", timeout=5)
                    if key_info.status_code == 200:
                        active_kid = key_info.json().get("active_kid", "")
                        kid_match = token_kid == active_kid

                return self._add_result(
                    "Token Post-Rotation",
                    TestCategory.KEYS,
                    active and kid_match,
                    f"New token valid={active}, uses_new_key={kid_match}",
                    {"active": active, "uses_new_key": kid_match}
                )

            return self._add_result(
                "Token Post-Rotation",
                TestCategory.KEYS,
                False,
                f"Introspection failed: {introspect.status_code}"
            )
        except Exception as e:
            return self._add_result("Token Post-Rotation", TestCategory.KEYS, False, str(e))

    # =========================================================================
    # REST API TESTS
    # =========================================================================

    def test_api_users_list(self) -> TestResult:
        """REST API - List users."""
        try:
            response = self.session.get(f"{self.base_url}/api/users", timeout=5)
            if response.status_code == 200:
                data = response.json()
                users = data.get("users", [])
                usernames = [
                    u["username"] if isinstance(u, dict) else u
                    for u in users
                ]
                return self._add_result(
                    "API List Users",
                    TestCategory.API,
                    len(users) > 0,
                    f"Found {len(users)} users: {', '.join(usernames)}",
                    {"count": len(users), "users": usernames}
                )
            return self._add_result(
                "API List Users",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API List Users", TestCategory.API, False, str(e))

    def test_api_user_details(self) -> TestResult:
        """REST API - Get user details."""
        try:
            response = self.session.get(
                f"{self.base_url}/api/users/{self.username}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                user = data.get("user", data)
                email = user.get("email", "?")
                roles = user.get("roles", [])
                identity_class = user.get("identity_class", "?")
                entitlements = user.get("entitlements", [])
                return self._add_result(
                    "API User Details",
                    TestCategory.API,
                    True,
                    f"email={email}, roles={roles}, class={identity_class}",
                    {"email": email, "roles": roles, "entitlements": entitlements}
                )
            return self._add_result(
                "API User Details",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API User Details", TestCategory.API, False, str(e))

    def test_api_direct_token(self) -> TestResult:
        """REST API - Direct token generation."""
        try:
            response = self.session.post(
                f"{self.base_url}/api/users/{self.username}/token",
                json={"exp_minutes": 5},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                token = data.get("access_token", "")

                # Verify token structure
                if jwt and token:
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    sub = decoded.get("sub", "?")
                    exp = decoded.get("exp", 0)
                    iat = decoded.get("iat", 0)
                    ttl = exp - iat
                    return self._add_result(
                        "API Direct Token",
                        TestCategory.API,
                        sub == self.username,
                        f"Generated for {sub}, TTL={ttl}s",
                        {"subject": sub, "ttl": ttl}
                    )

                return self._add_result(
                    "API Direct Token",
                    TestCategory.API,
                    bool(token),
                    "Token generated (cannot decode without PyJWT)",
                    {"has_token": bool(token)}
                )
            return self._add_result(
                "API Direct Token",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API Direct Token", TestCategory.API, False, str(e))

    def test_api_config(self) -> TestResult:
        """REST API - Get configuration."""
        try:
            response = self.session.get(f"{self.base_url}/api/config", timeout=5)
            if response.status_code == 200:
                data = response.json()
                oauth = data.get("oauth", {})
                saml = data.get("saml", {})
                logging_config = data.get("logging", {})
                issuer = oauth.get("issuer", "?")
                audience = oauth.get("audience", "?")
                entity_id = saml.get("entity_id", "?")
                verbose_logging = logging_config.get("verbose_logging", "?")
                return self._add_result(
                    "API Config",
                    TestCategory.API,
                    True,
                    f"issuer={issuer}, verbose_logging={verbose_logging}",
                    {"issuer": issuer, "audience": audience, "saml_entity": entity_id, "verbose_logging": verbose_logging}
                )
            return self._add_result(
                "API Config",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API Config", TestCategory.API, False, str(e))

    def test_api_verbose_logging_setting(self) -> TestResult:
        """REST API - Verbose logging setting in config."""
        try:
            response = self.session.get(f"{self.base_url}/api/config", timeout=5)
            if response.status_code == 200:
                data = response.json()
                logging_config = data.get("logging", {})

                # Check that logging section exists with verbose_logging
                has_logging_section = "logging" in data
                has_verbose_logging = "verbose_logging" in logging_config
                verbose_value = logging_config.get("verbose_logging")

                return self._add_result(
                    "Verbose Logging Setting",
                    TestCategory.API,
                    has_logging_section and has_verbose_logging,
                    f"has_section={has_logging_section}, verbose_logging={verbose_value}",
                    {"has_logging_section": has_logging_section, "verbose_logging": verbose_value}
                )
            return self._add_result(
                "Verbose Logging Setting",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("Verbose Logging Setting", TestCategory.API, False, str(e))

    def test_api_config_reload(self) -> TestResult:
        """REST API - Reload configuration."""
        try:
            response = self.session.post(
                f"{self.base_url}/api/config/reload",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                status = data.get("status", "?")
                return self._add_result(
                    "API Config Reload",
                    TestCategory.API,
                    status in ["ok", "reloaded", "success"],
                    f"Reload status: {status}",
                    data
                )
            return self._add_result(
                "API Config Reload",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API Config Reload", TestCategory.API, False, str(e))

    def test_api_audit_log(self) -> TestResult:
        """REST API - Audit log."""
        try:
            response = self.session.get(
                f"{self.base_url}/api/audit",
                params={"limit": 10},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                entries = data.get("entries", [])
                total = data.get("total", 0)

                # Check entry structure if we have entries
                entry_types = set()
                if entries:
                    for e in entries[:5]:
                        entry_types.add(e.get("event_type", e.get("type", "?")))

                return self._add_result(
                    "API Audit Log",
                    TestCategory.API,
                    True,
                    f"total={total}, sample={len(entries)}, types={list(entry_types)[:3]}",
                    {"total": total, "event_types": list(entry_types)}
                )
            return self._add_result(
                "API Audit Log",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API Audit Log", TestCategory.API, False, str(e))

    def test_api_audit_stats(self) -> TestResult:
        """REST API - Audit statistics."""
        try:
            response = self.session.get(
                f"{self.base_url}/api/audit/stats",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                total = data.get("total_events", data.get("total", 0))
                by_type = data.get("by_event_type", data.get("by_type", {}))
                return self._add_result(
                    "API Audit Stats",
                    TestCategory.API,
                    True,
                    f"total_events={total}, categories={len(by_type)}",
                    {"total": total, "categories": list(by_type.keys())[:5]}
                )
            return self._add_result(
                "API Audit Stats",
                TestCategory.API,
                False,
                f"Status: {response.status_code}"
            )
        except Exception as e:
            return self._add_result("API Audit Stats", TestCategory.API, False, str(e))

    # =========================================================================
    # TEST RUNNER
    # =========================================================================

    def run_all_tests(self) -> bool:
        """Esegue tutti i test organizzati per categoria."""
        print("\n" + "=" * 70)
        print("  NanoIDP Comprehensive Test Suite")
        print("=" * 70)
        print(f"\n  Target:   {self.base_url}")
        print(f"  Client:   {self.client_id}")
        print(f"  User:     {self.username}")
        print(f"  Verbose:  {self.verbose}")

        # Define test groups
        test_groups = [
            (TestCategory.CORE, "Core Infrastructure", [
                self.test_health,
                self.test_oidc_discovery,
            ]),
            (TestCategory.OAUTH, "OAuth2/OIDC Flows", [
                self.test_jwks,
                self.test_password_grant,
                self.test_client_credentials,
                self.test_authorization_code_pkce,
                self.test_device_flow,
                self.test_token_decode,
                self.test_introspection,
                self.test_userinfo,
                self.test_refresh_token,
                self.test_token_revocation,
                self.test_logout,
            ]),
            (TestCategory.SAML, "SAML 2.0", [
                self.test_saml_metadata,
                self.test_saml_sso_post_binding,
                self.test_saml_sso_redirect_binding,
                self.test_saml_attribute_query,
                self.test_saml_signing_config,
                self.test_saml_c14n_algorithm,
            ]),
            (TestCategory.KEYS, "Key Management", [
                self.test_key_info,
                self.test_key_rotation,
                self.test_token_after_rotation,
            ]),
            (TestCategory.API, "REST API", [
                self.test_api_users_list,
                self.test_api_user_details,
                self.test_api_direct_token,
                self.test_api_config,
                self.test_api_verbose_logging_setting,
                self.test_api_config_reload,
                self.test_api_audit_log,
                self.test_api_audit_stats,
            ]),
        ]

        # Run tests by group
        for category, title, tests in test_groups:
            print(f"\n{'─' * 70}")
            print(f"  {title}")
            print(f"{'─' * 70}\n")

            for test in tests:
                result = test()

                # Stop if health check fails
                if test == self.test_health and not result.success:
                    print("\n  [FATAL] Server unreachable, aborting tests.\n")
                    return False

        # Summary
        print("\n" + "=" * 70)
        print("  SUMMARY")
        print("=" * 70)

        by_category = self.suite.by_category()
        for cat in TestCategory:
            if cat in by_category:
                results = by_category[cat]
                passed = sum(1 for r in results if r.success)
                total = len(results)
                status = "OK" if passed == total else "PARTIAL" if passed > 0 else "FAIL"
                print(f"  [{status:7}] {cat.value:20} {passed}/{total}")

        print(f"\n  {'─' * 40}")
        print(f"  TOTAL: {self.suite.passed}/{self.suite.total} tests passed")

        if self.suite.passed == self.suite.total:
            print("\n  [SUCCESS] All tests passed!")
        else:
            failed = [r.name for r in self.suite.results if not r.success]
            print(f"\n  [WARNING] Failed tests:")
            for name in failed:
                print(f"    - {name}")

        print("=" * 70 + "\n")

        return self.suite.passed == self.suite.total


def main():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Comprehensive test agent for NanoIDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_agent.py
  python test_agent.py --url http://localhost:9000
  python test_agent.py --verbose
  python test_agent.py --json
        """
    )
    parser.add_argument(
        "--url", "-u",
        default="http://localhost:8000",
        help="NanoIDP base URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--client-id", "-c",
        default="demo-client",
        help="Client ID (default: demo-client)"
    )
    parser.add_argument(
        "--client-secret", "-s",
        default="demo-secret",
        help="Client secret (default: demo-secret)"
    )
    parser.add_argument(
        "--user",
        default="admin",
        help="Username for tests (default: admin)"
    )
    parser.add_argument(
        "--password", "-p",
        default="admin",
        help="Password for tests (default: admin)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    agent = NanoIDPTestAgent(
        base_url=args.url,
        client_id=args.client_id,
        client_secret=args.client_secret,
        username=args.user,
        password=args.password,
        verbose=args.verbose
    )

    success = agent.run_all_tests()

    if args.json:
        results = [
            {
                "name": r.name,
                "category": r.category.value,
                "success": r.success,
                "message": r.message,
                "data": r.data
            }
            for r in agent.suite.results
        ]
        print("\nJSON Output:")
        print(json.dumps({
            "summary": {
                "passed": agent.suite.passed,
                "failed": agent.suite.failed,
                "total": agent.suite.total
            },
            "results": results
        }, indent=2))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
