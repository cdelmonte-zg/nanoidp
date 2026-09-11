#!/usr/bin/env python3
"""n8n end-to-end (#194, path 1): MCP Client node -> mock MCP server -> nanoidp.

Drives the stack in examples/agentic-stack/docker-compose.yml headless, as a
real MCP host would use nanoidp: n8n's own OAuth2 credential flow (PKCE,
public client, RFC 8707 ``resource``) against nanoidp, then an n8n workflow
whose MCP Client node calls a tool on the RFC 9728 mock resource server with
the token n8n obtained. No LLM is involved: the node is the deterministic
"step" MCP Client, not the AI Agent tool.

What it asserts, in order:

  1. n8n bootstraps headless (owner, login, API key) and the two
     credentials import (``n8n import:credentials``: the public API refuses an
     empty clientSecret for mcpOAuth2Api, and a real MCP client has none).
  2. The OAuth authorization n8n initiates completes without a browser: the
     URL n8n builds carries PKCE and ``resource``, nanoidp's login POST on that
     URL redirects to n8n's callback, and the callback, called with n8n's own
     session cookie (n8n requires it), stores the token.
  3. A workflow's MCP Client node calls ``read_document`` and gets the
     document back; the execution is recorded as success.
  4. Negative, scope: ``delete_document`` with a token holding only
     documents:read fails in the node with the mock server's
     insufficient_scope message.
  5. Negative, audience: a credential whose ``resourceUrl`` names another
     resource obtains a token nanoidp happily binds to it, and the mock server
     rejects that token (wrong ``aud``), so the node fails.

Two n8n facts the script encodes, measured on 2.38.7: n8n sends ``resource``
only when the credential's ``resourceUrl`` is explicit (discovery alone does
not make it send one), and the OAuth callback needs the logged-in session.

Usage (from the repository root, stack already up):

    docker compose -f examples/agentic-stack/docker-compose.yml up --build --wait
    python e2e/n8n_e2e.py

Exit code 0 on success, 1 on any failure. The script talks to the published
ports on localhost; the OAuth URL n8n builds names nanoidp by its Compose
service name, so the script rewrites that origin to the published one before
following it (nanoidp does not check the Host header). Re-runs against the
same stack work: bootstrap is idempotent, and workflows, their webhook paths
and the API key are created fresh with a per-run suffix.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit, urlunsplit

import requests

OWNER = {
    "email": "owner@example.org",
    "firstName": "E2E",
    "lastName": "Owner",
    "password": "E2eOwnerPassw0rd!",
}
NANOIDP_USER = ("admin", "admin")

CRED_OK = "n8ne2emcp0000001"  # examples/agentic-stack/n8n-import/credentials.json
CRED_WRONG_AUD = "n8ne2emcp0000002"

MCP_NODE_TYPE = "@n8n/n8n-nodes-langchain.mcpClient"


class Failure(Exception):
    """A check failed; the message is the evidence."""


def wait_http(url: str, timeout: float) -> None:
    """Wait for a 200. n8n's /healthz answers seconds before its REST routes
    are mounted (they 404 meanwhile), so readiness is /rest/settings, not
    /healthz."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return
            last = f"HTTP {r.status_code}"
        except requests.RequestException as exc:  # noqa: PERF203
            last = str(exc)
        time.sleep(2)
    raise Failure(f"{url} not reachable within {timeout:.0f}s: {last}")


class N8n:
    """The two n8n surfaces the flow needs: the internal REST (session
    cookie: owner setup, login, API keys, the OAuth credential dance) and the
    public API (API key: credentials, workflows, executions)."""

    def __init__(self, base: str, compose_file: str) -> None:
        self.base = base.rstrip("/")
        self.compose_file = compose_file
        self.session = requests.Session()
        self.api_key: Optional[str] = None

    # -- internal REST --------------------------------------------------

    def rest(self, method: str, path: str, **kw: Any) -> requests.Response:
        return self.session.request(method, f"{self.base}/rest{path}", timeout=30, **kw)

    def bootstrap(self) -> None:
        setup = self.rest("POST", "/owner/setup", json=OWNER)
        if setup.status_code not in (200, 400):
            raise Failure(f"owner setup: HTTP {setup.status_code} {setup.text[:200]}")
        login = self.rest(
            "POST",
            "/login",
            json={"emailOrLdapLoginId": OWNER["email"], "password": OWNER["password"]},
        )
        if login.status_code != 200:
            raise Failure(f"login: HTTP {login.status_code} {login.text[:200]}")
        scopes = self.rest("GET", "/api-keys/scopes").json().get("data", [])
        # n8n refuses a second key with the same label, and never shows a raw
        # key again after creating it: a fresh, uniquely labelled key per run.
        created = self.rest(
            "POST",
            "/api-keys",
            json={"label": f"e2e-{int(time.time())}", "expiresAt": None, "scopes": scopes},
        )
        if created.status_code != 200:
            raise Failure(f"api key: HTTP {created.status_code} {created.text[:200]}")
        self.api_key = created.json()["data"]["rawApiKey"]

    def import_credentials(self) -> None:
        cmd = [
            "docker", "compose", "-f", self.compose_file,
            "exec", "-T", "n8n",
            "n8n", "import:credentials", "--input", "/import/credentials.json",
        ]
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if done.returncode != 0 or "Successfully imported" not in done.stdout + done.stderr:
            raise Failure(f"import:credentials: rc={done.returncode}\n{done.stdout}\n{done.stderr}")

    def authorize(self, cred_id: str, nanoidp_public: str) -> Dict[str, List[str]]:
        """Run n8n's OAuth2 credential flow without a browser and return the
        query parameters of the authorization URL n8n built."""
        r = self.rest("GET", "/oauth2-credential/auth", params={"id": cred_id})
        if r.status_code != 200 or not isinstance(r.json().get("data"), str):
            raise Failure(f"auth URL for {cred_id}: HTTP {r.status_code} {r.text[:300]}")
        auth_url = r.json()["data"]
        parts = urlsplit(auth_url)
        public = urlsplit(nanoidp_public)
        rewritten = urlunsplit((public.scheme, public.netloc, parts.path, parts.query, ""))

        idp = requests.Session()
        page = idp.get(rewritten, allow_redirects=False, timeout=10)
        if page.status_code != 200:
            raise Failure(f"nanoidp GET /authorize: HTTP {page.status_code} {page.text[:200]}")
        login = idp.post(
            rewritten,
            data={"username": NANOIDP_USER[0], "password": NANOIDP_USER[1]},
            allow_redirects=False,
            timeout=10,
        )
        location = login.headers.get("Location", "")
        if login.status_code != 302 or "/rest/oauth2-credential/callback" not in location:
            raise Failure(f"nanoidp POST /authorize: HTTP {login.status_code} Location={location[:200]}")
        cb = self.session.get(location, timeout=30)
        if cb.status_code != 200 or "Error" in cb.text:
            raise Failure(f"n8n callback: HTTP {cb.status_code} {cb.text[:300]}")
        return parse_qs(parts.query)

    # -- public API -----------------------------------------------------

    def api(self, method: str, path: str, **kw: Any) -> requests.Response:
        headers = {"X-N8N-API-KEY": self.api_key or ""}
        return requests.request(method, f"{self.base}/api/v1{path}", headers=headers, timeout=30, **kw)

    def create_workflow(self, name: str, path: str, tool: str, cred_id: str, endpoint: str) -> str:
        body = {
            "name": name,
            "nodes": [
                {
                    "parameters": {"httpMethod": "POST", "path": path, "responseMode": "lastNode", "options": {}},
                    "id": "trigger", "name": "Webhook", "type": "n8n-nodes-base.webhook",
                    "typeVersion": 2, "position": [0, 0], "webhookId": path,
                },
                {
                    "parameters": {
                        "serverTransport": "httpStreamable",
                        "endpointUrl": endpoint,
                        "authentication": "mcpOAuth2Api",
                        "tool": {"__rl": True, "mode": "id", "value": tool},
                        "inputMode": "json",
                        "jsonInput": "={{ JSON.stringify($json.body) }}",
                        "options": {},
                    },
                    "id": "mcp", "name": "MCP Client", "type": MCP_NODE_TYPE,
                    "typeVersion": 1.1, "position": [300, 0],
                    "credentials": {"mcpOAuth2Api": {"id": cred_id, "name": cred_id}},
                },
            ],
            "connections": {"Webhook": {"main": [[{"node": "MCP Client", "type": "main", "index": 0}]]}},
            "settings": {"executionOrder": "v1"},
        }
        created = self.api("POST", "/workflows", json=body)
        if created.status_code not in (200, 201):
            raise Failure(f"create workflow {name}: HTTP {created.status_code} {created.text[:300]}")
        wf_id = created.json()["id"]
        activated = self.api("POST", f"/workflows/{wf_id}/activate")
        if activated.status_code != 200 or not activated.json().get("active"):
            raise Failure(f"activate workflow {name}: HTTP {activated.status_code} {activated.text[:300]}")
        time.sleep(2)  # webhook registration is asynchronous
        return wf_id

    def trigger(self, path: str, body: Dict[str, Any]) -> requests.Response:
        return requests.post(f"{self.base}/webhook/{path}", json=body, timeout=60)

    def last_execution(self, wf_id: str) -> Dict[str, Any]:
        for _ in range(15):
            r = self.api("GET", "/executions", params={"workflowId": wf_id, "includeData": "true", "limit": 1})
            data = r.json().get("data", [])
            if data and data[0].get("status") in ("success", "error"):
                return data[0]
            time.sleep(1)
        raise Failure(f"no finished execution for workflow {wf_id}")


def node_error(execution: Dict[str, Any], node: str) -> str:
    run_data = ((execution.get("data") or {}).get("resultData") or {}).get("runData") or {}
    for run in run_data.get(node, []):
        err = run.get("error")
        if err:
            return err.get("description") or err.get("message") or json.dumps(err)
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--n8n", default="http://localhost:5678")
    parser.add_argument("--nanoidp", default="http://localhost:8000")
    parser.add_argument("--mcp-endpoint", default="http://mcp:9100/mcp",
                        help="the MCP server URL as n8n reaches it, on the Compose network")
    parser.add_argument("--compose-file", default="examples/agentic-stack/docker-compose.yml")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()

    results: List[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))
        print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""))

    n8n = N8n(args.n8n, args.compose_file)
    # Workflows and their webhook paths are created fresh on every run; a
    # path already registered by an earlier run's workflow makes activation
    # fail with 409, so each run gets its own suffix.
    run_id = str(int(time.time()))
    try:
        print("nanoidp, mock MCP server, n8n")
        wait_http(f"{args.nanoidp}/api/health", args.timeout)
        wait_http(f"{args.n8n}/rest/settings", args.timeout)
        check("stack reachable", True)

        n8n.bootstrap()
        n8n.import_credentials()
        check("n8n bootstrap and credential import", True)

        params = n8n.authorize(CRED_OK, args.nanoidp)
        check(
            "authorization URL carries PKCE S256 and the resource",
            params.get("code_challenge_method") == ["S256"]
            and params.get("resource") == [args.mcp_endpoint]
            and params.get("client_id") == ["n8n-public"],
            json.dumps({k: params.get(k) for k in ("code_challenge_method", "resource", "client_id")}),
        )
        check("OAuth flow completed headless and n8n stored the token", True)

        wf_ok = n8n.create_workflow(f"e2e {run_id}: read_document", f"e2e-read-{run_id}", "read_document", CRED_OK, args.mcp_endpoint)
        resp = n8n.trigger(f"e2e-read-{run_id}", {"document_id": "doc-42"})
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        text = (body.get("structuredContent") or {}).get("result", "")
        execution = n8n.last_execution(wf_ok)
        check(
            "read_document via the MCP Client node",
            resp.status_code == 200 and text == "contents of document 'doc-42'" and execution.get("status") == "success",
            f"HTTP {resp.status_code} result={text!r} status={execution.get('status')} {node_error(execution, 'MCP Client')[:200]}",
        )

        wf_scope = n8n.create_workflow(f"e2e {run_id}: delete_document (insufficient scope)", f"e2e-delete-{run_id}", "delete_document", CRED_OK, args.mcp_endpoint)
        resp = n8n.trigger(f"e2e-delete-{run_id}", {"document_id": "doc-42"})
        execution = n8n.last_execution(wf_scope)
        err = node_error(execution, "MCP Client")
        check(
            "delete_document refused: insufficient_scope surfaces as the node error",
            resp.status_code >= 400 and execution.get("status") == "error"
            and "insufficient_scope" in err and "documents:write" in err,
            f"HTTP {resp.status_code} status={execution.get('status')} error={err[:200]}",
        )

        params = n8n.authorize(CRED_WRONG_AUD, args.nanoidp)
        wf_aud = n8n.create_workflow(f"e2e {run_id}: wrong audience", f"e2e-aud-{run_id}", "read_document", CRED_WRONG_AUD, args.mcp_endpoint)
        resp = n8n.trigger(f"e2e-aud-{run_id}", {"document_id": "doc-42"})
        execution = n8n.last_execution(wf_aud)
        err = node_error(execution, "MCP Client")
        check(
            "a token bound to another resource is rejected by the MCP server",
            params.get("resource") == [f"{args.mcp_endpoint.rsplit('/', 1)[0]}/other"]
            and execution.get("status") == "error" and "invalid_token" in err,
            f"resource={params.get('resource')} status={execution.get('status')} error={err[:200]}",
        )
    except Failure as exc:
        check("setup", False, str(exc))
    except requests.RequestException as exc:
        check("setup", False, f"request failed: {exc}")

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\nTOTAL: {passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
