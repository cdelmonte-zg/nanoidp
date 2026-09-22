#!/usr/bin/env python3
"""Two NanoIDP processes over one SQLite runtime store (#354, step 5).

Every other end-to-end suite here drives a single server. This one drives
two, started from different working directories over one configuration
directory and one store, and asserts what sharing the store is for: what one
process records, the other serves, and it is consumed once for both.

    1. a runtime user created at A logs in at B;
    2. an authorization code issued at A is redeemed at B, once;
    3. a token revoked at A is refused at B;
    4. a user promoted at A is declared for B;
    5. the audit of both reads as one.

The servers are started by the caller (the `shared-store-e2e` job, or by
hand as e2e/README.md says), as with the other suites here.

Usage:
    python e2e/shared_store_e2e.py --a http://localhost:8007 --b http://localhost:8008

Exit code 0 on success, 1 on any failure.
"""

import argparse
import base64
import hashlib
import secrets
import sys
from typing import Callable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests

TIMEOUT = 10
CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-secret"
REDIRECT_URI = "http://localhost:3000/callback"


class Failure(Exception):
    """An assertion of this suite that did not hold."""


def check(condition: bool, what: str) -> None:
    if not condition:
        raise Failure(what)


def code_from(server: str, username: str, password: str) -> Tuple[str, str]:
    """An authorization code issued by ``server``, with its PKCE verifier:
    the browser leg is that server's, the redemption need not be."""
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    browser = requests.Session()
    page = browser.get(
        f"{server}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile",
            "state": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    check(page.status_code == 200, f"GET /authorize at {server} answered {page.status_code}")
    login = browser.post(
        f"{server}/authorize",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    check(login.status_code in (302, 303), f"the login at {server} answered {login.status_code}")
    code = parse_qs(urlparse(login.headers.get("Location", "")).query).get("code", [None])[0]
    check(code is not None, f"no authorization code in the redirect from {server}")
    return str(code), verifier


def redeem(server: str, code: str, verifier: str) -> requests.Response:
    # The demo client authenticates with HTTP Basic, and refuses a secret in
    # the body; the same goes for /revoke and /introspect below.
    return requests.post(
        f"{server}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=TIMEOUT,
    )


def audit_events(server: str, event_type: str) -> List[dict]:
    answer = requests.get(
        f"{server}/api/audit", params={"event_type": event_type, "limit": 200}, timeout=TIMEOUT
    )
    check(answer.status_code == 200, f"GET /api/audit at {server} answered {answer.status_code}")
    return list(answer.json()["entries"])


# ---- the scenarios ----------------------------------------------------------

def a_runtime_user_of_one_logs_in_at_the_other(a: str, b: str) -> str:
    name = f"shared-{secrets.token_hex(4)}"
    created = requests.post(
        f"{a}/api/runtime/users",
        json={"username": name, "password": "pw", "email": f"{name}@example.org"},
        timeout=TIMEOUT,
    )
    check(created.status_code == 201, f"POST /api/runtime/users at A answered {created.status_code}")

    seen = requests.get(f"{b}/api/runtime/users/{name}", timeout=TIMEOUT)
    check(seen.status_code == 200, f"B does not serve the runtime user A created ({seen.status_code})")

    code, verifier = code_from(b, name, "pw")
    token = redeem(b, code, verifier)
    check(token.status_code == 200, f"the user A created cannot log in at B ({token.status_code})")
    return name


def a_code_of_one_is_redeemed_once_at_the_other(a: str, b: str, username: str) -> None:
    code, verifier = code_from(a, username, "pw")

    first = redeem(b, code, verifier)
    check(first.status_code == 200, f"B refused the code A issued ({first.status_code}: {first.text[:200]})")
    check("access_token" in first.json(), "B's answer carries no access token")

    for server, which in ((b, "B"), (a, "A")):
        again = redeem(server, code, verifier)
        check(again.status_code == 400, f"the code was redeemable a second time at {which} ({again.status_code})")
        check(
            again.json().get("error") == "invalid_grant",
            f"a spent code at {which} is {again.json().get('error')!r}, not invalid_grant",
        )


def a_token_revoked_at_one_is_refused_by_the_other(a: str, b: str, username: str) -> None:
    code, verifier = code_from(a, username, "pw")
    token = redeem(a, code, verifier).json()
    access = token["access_token"]

    served = requests.get(f"{b}/userinfo", headers={"Authorization": f"Bearer {access}"}, timeout=TIMEOUT)
    check(served.status_code == 200, f"B does not serve /userinfo for A's token ({served.status_code})")

    revoked = requests.post(
        f"{a}/revoke",
        data={"token": access},
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=TIMEOUT,
    )
    check(revoked.status_code == 200, f"POST /revoke at A answered {revoked.status_code}")

    refused = requests.get(f"{b}/userinfo", headers={"Authorization": f"Bearer {access}"}, timeout=TIMEOUT)
    check(refused.status_code == 401, f"B still serves a token A revoked ({refused.status_code})")

    introspected = requests.post(
        f"{b}/introspect",
        data={"token": access},
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=TIMEOUT,
    )
    check(introspected.status_code == 200, f"POST /introspect at B answered {introspected.status_code}")
    check(introspected.json().get("active") is False, "B introspects a revoked token as active")


def a_promotion_at_one_is_declared_for_the_other(a: str, b: str, username: str) -> None:
    promoted = requests.post(f"{a}/api/runtime/users/{username}/promote", timeout=TIMEOUT)
    check(promoted.status_code == 200, f"the promotion at A answered {promoted.status_code}: {promoted.text[:200]}")

    runtime = requests.get(f"{b}/api/runtime/users/{username}", timeout=TIMEOUT)
    check(runtime.status_code == 404, f"B still holds the promoted user as runtime ({runtime.status_code})")

    declared = requests.get(f"{b}/api/users", timeout=TIMEOUT)
    check(declared.status_code == 200, f"GET /api/users at B answered {declared.status_code}")
    names = [user.get("username") for user in declared.json().get("users", [])]
    check(username in names, f"B does not declare the user A promoted (has {len(names)} users)")

    code, verifier = code_from(b, username, "pw")
    check(redeem(b, code, verifier).status_code == 200, "the promoted user cannot log in at B")


def the_audit_of_both_reads_as_one(a: str, b: str) -> None:
    at_a = f"audit-a-{secrets.token_hex(4)}"
    at_b = f"audit-b-{secrets.token_hex(4)}"
    for server, name in ((a, at_a), (b, at_b)):
        made = requests.post(
            f"{server}/api/runtime/users", json={"username": name, "password": "pw"}, timeout=TIMEOUT
        )
        check(made.status_code == 201, f"POST /api/runtime/users at {server} answered {made.status_code}")

    for reader, which in ((b, "B"), (a, "A")):
        recorded = [entry.get("details", {}).get("name") for entry in audit_events(reader, "runtime_identity_created")]
        check(at_a in recorded, f"{which} does not read the event the other process recorded ({at_a})")
        check(at_b in recorded, f"{which} does not read its own event ({at_b})")


# ---- the run ----------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", default="http://localhost:8007", help="the first server")
    parser.add_argument("--b", default="http://localhost:8008", help="the second server")
    args = parser.parse_args()
    a, b = args.a.rstrip("/"), args.b.rstrip("/")

    for server in (a, b):
        health = requests.get(f"{server}/api/health", timeout=TIMEOUT)
        check(health.status_code == 200, f"{server} is not healthy ({health.status_code})")

    username: Optional[str] = None

    def first() -> None:
        nonlocal username
        username = a_runtime_user_of_one_logs_in_at_the_other(a, b)

    scenarios: List[Tuple[str, Callable[[], None]]] = [
        ("a runtime user created at A logs in at B", first),
        ("an authorization code issued at A is redeemed at B, once", lambda: a_code_of_one_is_redeemed_once_at_the_other(a, b, str(username))),
        ("a token revoked at A is refused at B", lambda: a_token_revoked_at_one_is_refused_by_the_other(a, b, str(username))),
        ("a user promoted at A is declared for B", lambda: a_promotion_at_one_is_declared_for_the_other(a, b, str(username))),
        ("the audit of both reads as one", lambda: the_audit_of_both_reads_as_one(a, b)),
    ]

    failures = 0
    for what, scenario in scenarios:
        try:
            scenario()
        except (Failure, requests.RequestException, KeyError, ValueError) as failure:
            failures += 1
            print(f"[FAIL] {what}: {failure}")
        else:
            print(f"[OK] {what}")

    print(f"\n{len(scenarios) - failures}/{len(scenarios)} scenarios passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
