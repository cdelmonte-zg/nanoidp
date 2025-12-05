# Mock IdP - Implementation Guide

## Table of Contents
1. [What We Solved](#what-we-solved)
2. [Key Concepts](#key-concepts)
3. [SAML 2.0 Flow](#saml-20-flow)
4. [JWT/OAuth Flow](#jwtoauth-flow)
5. [Session Management](#session-management)
6. [Security Features](#security-features)
7. [Testing Guide](#testing-guide)
8. [Best Practices](#best-practices)

---

## What We Solved

The original Mock IdP had a **critical flaw**: it generated SAML and JWT tokens **without authenticating the user**. This violated security protocols and prevented testing realistic flows.

### Core Issues Fixed
1. **No Authentication** - Tokens were issued without verifying user identity
2. **Missing Sessions** - No way to track authenticated users
3. **Invalid SAML Flow** - Did not follow SAML 2.0 specifications
4. **Insecure JWT** - Password grant didn't validate credentials

---

## Key Concepts

### Authentication vs Authorization

**Authentication** - "Who are you?" - Verifies user identity
```python
# ✅ AFTER: Authentication implemented
username = request.form.get("username")
password = request.form.get("password")

user_data = USERS.get(username)
if user_data and user_data["password"] == password:
    session["user"] = username  # User authenticated!
else:
    return abort(401, "Invalid credentials")
```

**Authorization** - "What can you do?" - Verifies permissions
```python
# JWT contains roles/permissions
{
  "sub": "christian",
  "roles": ["search", "read"],  # Authorization
  "tenant": "acme"
}
```

### Why Session Management Matters

Sessions allow the IdP to remember who is logged in across multiple requests. This is essential for SAML SSO flows where:
1. User logs in once at the IdP
2. IdP generates SAMLResponse with authenticated user's data
3. User can access multiple applications without logging in again

---

## SAML 2.0 Flow

### Components
- **SP (Service Provider)**: The application (e.g., Spring Boot)
- **IdP (Identity Provider)**: The mock that authenticates users
- **User**: The end user (browser)

### Complete Step-by-Step Flow

#### 1️⃣ SP Initiates Flow
```
User visits: http://localhost:8080/protected
SP sees: user not authenticated
SP generates: AuthnRequest (signed XML)
SP sends: redirect to IdP SSO endpoint
```

#### 2️⃣ IdP Receives AuthnRequest
```python
@app.post("/saml/sso")
def saml_sso_post():
    saml_request = request.form.get("SAMLRequest")

    # ✅ Check if user is authenticated
    if "user" not in session:
        # ⚠️ Not authenticated → redirect to login
        return redirect(url_for("login_page", SAMLRequest=saml_request))
```

#### 3️⃣ User Authenticates
```
User sees: login page (/login)
User enters: username + password
IdP validates: credentials against database/USERS
IdP creates: session["user"] = "christian"
```

#### 4️⃣ IdP Generates SAMLResponse
```python
# Now the user is authenticated!
username = session["user"]
user_data = USERS[username]

# Extract info from AuthnRequest
saml_info = parse_saml_request(saml_request_b64)
in_response_to = saml_info["id"]  # ✅ Important!
acs_url = saml_info["acs_url"]

# Generate signed response
xml = build_saml_response_xml(
    acs_url=acs_url,
    name_id=user_data["email"],
    attributes={...},
    in_response_to=in_response_to,  # ✅ Links request → response
    sign=True
)
```

#### 5️⃣ Browser Sends SAMLResponse to SP
```html
<!-- Auto-submit form -->
<form method="post" action="http://localhost:8080/acs">
  <input name="SAMLResponse" value="base64_encoded_xml"/>
</form>
<script>document.forms[0].submit()</script>
```

#### 6️⃣ SP Validates and Authenticates
```
SP receives: SAMLResponse
SP verifies: digital signature (with IdP cert)
SP validates: InResponseTo matches the request
SP extracts: user attributes (email, roles, etc.)
SP creates: authentication context
SP redirects: /protected (now accessible)
```

---

## JWT/OAuth Flow

### Grant Type: Password (Resource Owner Password Credentials)

#### 1️⃣ Client Requests Token
```bash
curl -u demo-client:demo-secret -X POST /token \
  -d grant_type=password \
  -d username=christian \
  -d password=password
```

#### 2️⃣ IdP Validates (2 levels!)
```python
# Level 1: Client authentication (basic auth)
if not check_basic_auth(request):
    return abort(401)  # Client not authorized

# Level 2: User authentication (username+password)
user_data = USERS.get(username)
if not user_data or user_data["password"] != password:
    return abort(401)  # User not authenticated
```

#### 3️⃣ IdP Generates JWT
```python
# ✅ Token contains real user info
payload = {
    "iss": "http://localhost:8000",
    "sub": "christian",  # Authenticated username
    "aud": "fusion",
    "iat": now,
    "exp": now + 3600,
    "roles": ["search", "read"],  # From user profile
    "tenant": "acme",
    # ... other attributes
}

token = jwt.encode(payload, private_key, algorithm="RS256")
```

#### 4️⃣ Client Uses Token
```bash
curl -H "Authorization: Bearer eyJ..." http://localhost:8080/api/data
```

---

## Session Management

### How Flask Sessions Work

```python
# 1. Configuration
app.secret_key = "secret-key-for-signing"

# 2. After login
session["user"] = "christian"
session.permanent = True  # Persist across browser restart

# 3. Check in other endpoints
username = session.get("user")
if username:
    print(f"Authenticated user: {username}")
```

### Signed Cookie
```
Set-Cookie: session=eyJ1c2VyIjoiY2hyaXN0aWFuIn0.abc123.def456; HttpOnly; Path=/
                   ^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^
                   Payload (base64)       Signature (HMAC)
```

- **Payload**: session data (base64)
- **Signature**: HMAC with `secret_key`
- Browser cannot modify without invalidating signature

### Decorator for Protection
```python
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

@app.get("/me")
@login_required  # ✅ Requires authentication
def me():
    username = session["user"]  # Guaranteed present
    return jsonify({"username": username})
```

---

## Security Features

### InResponseTo - Prevents Replay Attacks

**Problem: Replay Attack**
```
❌ Without InResponseTo:
1. Attacker intercepts valid SAMLResponse
2. Attacker resends it to SP later
3. SP accepts (doesn't know it's old)
4. Attacker gains access!
```

**Solution: InResponseTo**
```
✅ With InResponseTo:
1. SP generates AuthnRequest with ID=abc123
2. IdP responds with InResponseTo=abc123
3. SP verifies abc123 matches
4. SP invalidates ID after use (one-time only)
5. Replay doesn't work (ID already used)
```

**Implementation**
```python
# IdP extracts ID from AuthnRequest
def parse_saml_request(saml_request_b64):
    # Decompress and parse XML
    root = etree.fromstring(saml_xml)
    request_id = root.get("ID")  # e.g. "_abc123..."
    return {"id": request_id}

# IdP includes in response
xml = build_saml_response_xml(
    in_response_to=request_id,  # ✅ Links request → response
    # ...
)

# In SAML XML:
<saml2p:Response InResponseTo="_abc123...">
  <saml2:Assertion>
    <saml2:Subject>
      <saml2:SubjectConfirmationData InResponseTo="_abc123..." />
    </saml2:Subject>
  </saml2:Assertion>
</saml2p:Response>
```

### Digital Signature (SAML)

**Why Sign?**
- **Integrity**: verify message hasn't been modified
- **Authenticity**: verify it comes from legitimate IdP
- **Non-repudiation**: IdP cannot deny issuing the response

**How It Works**
```python
# 1. IdP loads private key
with open("keys/rsa_private.pem", "rb") as f:
    private_key = f.read()

# 2. IdP signs the Assertion (part of XML)
from signxml import XMLSigner
signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256")
signed_assertion = signer.sign(assertion, key=private_key, cert=cert_pem)

# 3. Signed XML contains <Signature>
<saml2:Assertion ID="_xyz789">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#_xyz789">
        <ds:DigestValue>abc123...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>def456...</ds:SignatureValue>
  </ds:Signature>
  <saml2:Subject>...</saml2:Subject>
</saml2:Assertion>
```

### JWT Signature (RS256)

**Asymmetric Signing**
```
IdP:
  PRIVATE KEY → signs JWT
  PUBLIC KEY → exposes via JWKS

Client/API:
  Downloads PUBLIC KEY from JWKS
  Verifies JWT signature
  ✅ Cannot create fake JWTs (no private key)
```

**JWT Structure**
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.
eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwMDAiLCJzdWIiOiJjaH...
PGRsUXlZN0xCQ0RucVBqSVJLRXRkd3FPV0pUVmNISDRoMkJTQ0FEVGc...
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Header (base64url)

                                                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                   Payload (base64url)

                                                                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                                                                      Signature (RS256)
```

---

## Testing Guide

### Test JWT Token
```bash
# Get token
TOKEN=$(curl -s -u demo-client:demo-secret \
  -X POST http://localhost:8000/token \
  -d grant_type=password \
  -d username=christian \
  -d password=password | jq -r '.access_token')

# Decode payload
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq
```

### Test SAML Login Flow
```bash
# View login page
open http://localhost:8000/login

# Login credentials
# Username: christian
# Password: password
```

### Test Session Management
```bash
# Login
curl -c cookies.txt -X POST http://localhost:8000/login \
  -d username=christian \
  -d password=password

# Check session
curl -b cookies.txt http://localhost:8000/me

# Logout
curl -b cookies.txt http://localhost:8000/logout
```

---

## Best Practices

### ✅ 1. Separate Client/User Auth
```python
# Client authentication (who is calling the API)
if not check_basic_auth(request):  # demo-client:demo-secret
    return abort(401)

# User authentication (on behalf of whom)
if grant_type == "password":
    if not verify_user_credentials(username, password):
        return abort(401)
```

### ✅ 2. Session Management
```python
# Login
session["user"] = username
session.permanent = True

# Logout
session.clear()

# Check
if "user" not in session:
    return redirect("/login")
```

### ✅ 3. Secure Redirect After Login
```python
# Save original URL
if "user" not in session:
    session["next"] = request.url
    return redirect("/login")

# After login, return there
next_url = session.pop("next", None)
if next_url:
    return redirect(next_url)
```

### ✅ 4. Input Validation
```python
# Username/password required
if not username or not password:
    return abort(400, "username and password required")

# Verify format
if not username.isalnum():
    return abort(400, "invalid username format")
```

---

## Production Enhancements

### 1. Password Hashing
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
valid = bcrypt.checkpw(password.encode(), hashed)
```

### 2. Rate Limiting
```python
from flask_limiter import Limiter
limiter = Limiter(app)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # Max 5 login attempts per minute
```

### 3. Audit Logging
```python
import logging

def log_auth_attempt(username, success, ip):
    logging.info(f"Auth: user={username}, success={success}, ip={ip}")
```

### 4. HTTPS Only
```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

---

## Glossary

| Term           | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| **IdP**        | Identity Provider - authenticates users                |
| **SP**         | Service Provider - the application using the IdP       |
| **SSO**        | Single Sign-On - log in once, access multiple apps     |
| **SAML**       | Security Assertion Markup Language - XML protocol      |
| **JWT**        | JSON Web Token - compact self-contained token          |
| **JWKS**       | JSON Web Key Set - endpoint with public keys           |
| **ACS**        | Assertion Consumer Service - SP endpoint for SAMLResponse |
| **InResponseTo** | SAML field linking response to request               |
| **NameID**     | User identifier in SAML (e.g., email)                  |
| **Assertion**  | Signed statement from IdP (contains user attributes)   |
| **RS256**      | RSA Signature with SHA-256 - JWT signing algorithm     |
| **Grant Type** | OAuth flow type (password, client_credentials, etc.)   |
| **Basic Auth** | HTTP authentication with username:password in header   |
| **Session**    | Persistent state between HTTP requests                 |
| **Cookie**     | Small file saved by browser (contains session ID)      |

---

## Compliance Checklist

### SAML 2.0
- [x] IdP metadata exposed
- [x] SSO endpoint (HTTP-POST binding)
- [x] User authentication required
- [x] Signed SAMLResponse
- [x] Correct InResponseTo
- [x] Validated ACS URL
- [x] Complete AttributeStatement
- [x] Valid timestamps

### OAuth 2.0 / OIDC
- [x] Token endpoint
- [x] JWKS endpoint
- [x] Grant type: password
- [x] Grant type: client_credentials
- [x] JWT signed RS256
- [x] Standard claims (iss, sub, aud, exp)
- [x] Client authentication

### Security
- [x] Password validation
- [x] Session management
- [x] CSRF protection (Flask default)
- [x] Functional logout
- [ ] Password hashing (TODO)
- [ ] Rate limiting (TODO)
- [ ] Audit logging (TODO)
- [ ] HTTPS enforced (TODO)

---

**The Mock IdP is now compliant with SAML 2.0 and OAuth 2.0/OIDC protocols!**
