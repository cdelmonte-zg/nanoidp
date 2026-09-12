#!/usr/bin/env python3
"""n8n end-to-end (#194): n8n -> mock MCP server -> nanoidp, on two paths.

Drives the stack in examples/agentic-stack/docker-compose.yml headless, as a
real MCP host would use nanoidp: n8n's own OAuth2 credential flow (PKCE,
public client, RFC 8707 ``resource``) against nanoidp, then n8n workflows that
call a tool on the RFC 9728 mock resource server with the token n8n obtained.

Path 1 is the deterministic "step" MCP Client node. Path 2 is the AI Agent
with the MCP Client Tool node inside its tool-calling loop; the agent's
"model" is e2e/mock_chat_model.py, a fixture that always asks for the MCP
tool and then quotes the tool's answer, so no LLM is involved in either path.
Path 2 tests that n8n propagates the OAuth-protected MCP tools into the
agent, and that the resource server's decisions come back through it; the
OAuth itself is path 1's business and is not repeated.

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
  6. Path 2: an AI Agent whose model is the mock and whose one tool node is
     the MCP Client Tool with the good credential is asked to read a document.
     The model is offered the three tools the MCP server lists (the token's
     scope decides at call time, not at listing), it calls ``read_document``,
     and the agent's final answer quotes the document.
  7. Negative, scope inside the loop: asked to delete, the model calls
     ``delete_document``, the resource server refuses it (insufficient_scope),
     and that refusal is what the agent hands back to the model and quotes in
     its answer: the authorization decision reaches the loop as a tool result,
     not as a crash.
  8. Negative, audience inside the loop: the MCP Client Tool with the
     wrong-audience credential cannot even list tools (401 invalid_token), so
     the agent fails before calling the model.

Three n8n facts the script encodes, measured on 2.38.7: n8n sends ``resource``
only when the credential's ``resourceUrl`` is explicit (discovery alone does
not make it send one), the OAuth callback needs the logged-in session, and
the MCP Client Tool node offers the model every tool under the node's name as
a prefix (``MCP_Client_Tool_read_document``).

Usage (from the repository root, stack already up):

    docker compose -f examples/agentic-stack/docker-compose.yml up --build --wait
    python e2e/n8n_e2e.py

Exit code 0 on success, 1 on any failure. The script talks to the published
ports on localhost (n8n, nanoidp, the mock chat model's request log); the
OAuth URL n8n builds names nanoidp by its Compose service name, so the script
rewrites that origin to the published one before following it (nanoidp does
not check the Host header). Re-runs against the
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
CRED_CHAT = "n8ne2echat000001"  # the openAiApi credential pointing at the mock chat model

MCP_NODE_TYPE = "@n8n/n8n-nodes-langchain.mcpClient"
AGENT_NODE_TYPE = "@n8n/n8n-nodes-langchain.agent"
CHAT_MODEL_NODE_TYPE = "@n8n/n8n-nodes-langchain.lmChatOpenAi"
MCP_TOOL_NODE_TYPE = "@n8n/n8n-nodes-langchain.mcpClientTool"
MCP_TOOL_NODE_NAME = "MCP Client Tool"
MOCK_MODEL = "mock-tool-caller"  # e2e/mock_chat_model.py
MOCK_FINAL_PREFIX = "The tool answered: "  # e2e/mock_chat_model.py FINAL_ANSWER


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

    @staticmethod
    def _webhook_node(path: str) -> Dict[str, Any]:
        return {
            "parameters": {"httpMethod": "POST", "path": path, "responseMode": "lastNode", "options": {}},
            "id": "trigger", "name": "Webhook", "type": "n8n-nodes-base.webhook",
            "typeVersion": 2, "position": [0, 0], "webhookId": path,
        }

    def create_workflow(self, name: str, path: str, tool: str, cred_id: str, endpoint: str) -> str:
        """Path 1: Webhook -> MCP Client (step) node calling one named tool."""
        body = {
            "name": name,
            "nodes": [
                self._webhook_node(path),
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
        return self._create_and_activate(name, body)

    def create_agent_workflow(self, name: str, path: str, cred_id: str, endpoint: str) -> str:
        """Path 2: Webhook -> AI Agent, with the mock chat model as its model
        and the MCP Client Tool (all tools, OAuth credential) as its one tool.
        Streaming is off (the webhook answers with the last node's output),
        the Responses API is off (the mock speaks chat completions), and the
        iteration cap keeps a misbehaving loop short."""
        body = {
            "name": name,
            "nodes": [
                self._webhook_node(path),
                {
                    "parameters": {
                        "promptType": "define",
                        "text": "={{ $json.body.prompt }}",
                        "options": {"maxIterations": 3, "enableStreaming": False, "returnIntermediateSteps": True},
                    },
                    "id": "agent", "name": "AI Agent", "type": AGENT_NODE_TYPE,
                    "typeVersion": 3.1, "position": [300, 0],
                },
                {
                    "parameters": {
                        "model": {"__rl": True, "mode": "id", "value": MOCK_MODEL},
                        "responsesApiEnabled": False,
                        "options": {},
                    },
                    "id": "model", "name": "Mock Chat Model", "type": CHAT_MODEL_NODE_TYPE,
                    "typeVersion": 1.3, "position": [200, 200],
                    "credentials": {"openAiApi": {"id": CRED_CHAT, "name": CRED_CHAT}},
                },
                {
                    "parameters": {
                        "endpointUrl": endpoint,
                        "serverTransport": "httpStreamable",
                        "authentication": "mcpOAuth2Api",
                        "include": "all",
                        "options": {},
                    },
                    "id": "mcptool", "name": MCP_TOOL_NODE_NAME, "type": MCP_TOOL_NODE_TYPE,
                    "typeVersion": 1.4, "position": [420, 200],
                    "credentials": {"mcpOAuth2Api": {"id": cred_id, "name": cred_id}},
                },
            ],
            "connections": {
                "Webhook": {"main": [[{"node": "AI Agent", "type": "main", "index": 0}]]},
                "Mock Chat Model": {"ai_languageModel": [[{"node": "AI Agent", "type": "ai_languageModel", "index": 0}]]},
                MCP_TOOL_NODE_NAME: {"ai_tool": [[{"node": "AI Agent", "type": "ai_tool", "index": 0}]]},
            },
            "settings": {"executionOrder": "v1"},
        }
        return self._create_and_activate(name, body)

    def _create_and_activate(self, name: str, body: Dict[str, Any]) -> str:
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


def run_data(execution: Dict[str, Any]) -> Dict[str, Any]:
    return ((execution.get("data") or {}).get("resultData") or {}).get("runData") or {}


def node_error(execution: Dict[str, Any], node: str) -> str:
    for run in run_data(execution).get(node, []):
        err = run.get("error")
        if err:
            return err.get("description") or err.get("message") or json.dumps(err)
    return ""


def execution_error(execution: Dict[str, Any]) -> str:
    """The execution-level error (a sub-node failing during the agent's setup
    lands here, attributed to the agent), else the first node error."""
    err = ((execution.get("data") or {}).get("resultData") or {}).get("error") or {}
    if err:
        return err.get("description") or err.get("message") or json.dumps(err)
    for node in run_data(execution):
        found = node_error(execution, node)
        if found:
            return found
    return ""


class MockChat:
    """The request log of e2e/mock_chat_model.py, on its published port."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def clear(self) -> None:
        requests.delete(f"{self.base}/requests", timeout=10)

    def requests(self) -> List[Dict[str, Any]]:
        return [entry["body"] for entry in requests.get(f"{self.base}/requests", timeout=10).json()]


def offered_tools(chat_request: Dict[str, Any]) -> List[str]:
    return [t.get("function", {}).get("name", "") for t in chat_request.get("tools") or []]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--n8n", default="http://localhost:5678")
    parser.add_argument("--nanoidp", default="http://localhost:8000")
    parser.add_argument("--chat", default="http://localhost:9200",
                        help="the mock chat model as published on the host (its request log)")
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
    chat = MockChat(args.chat)
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

        # Path 2: the same credential (its token is already stored) inside an
        # AI Agent's tool-calling loop, with the mock chat model as the model.
        print("AI Agent -> MCP Client Tool -> mock MCP server")
        chat.clear()
        wf_agent = n8n.create_agent_workflow(f"e2e {run_id}: agent read_document", f"e2e-agent-read-{run_id}", CRED_OK, args.mcp_endpoint)
        resp = n8n.trigger(f"e2e-agent-read-{run_id}", {"prompt": "Read doc-42 for me."})
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        output = body.get("output", "") if isinstance(body, dict) else ""
        execution = n8n.last_execution(wf_agent)
        seen = chat.requests()
        first_tools = offered_tools(seen[0]) if seen else []
        fed_back = [m for r in seen for m in r.get("messages") or [] if m.get("role") == "tool"]
        check(
            "the agent offers the model the MCP server's tools, prefixed with the node name",
            len(seen) >= 2 and sorted(first_tools) == sorted(
                f"MCP_Client_Tool_{t}" for t in ("read_document", "delete_document", "admin_operation")
            ),
            f"requests={len(seen)} tools={first_tools}",
        )
        check(
            "the agent calls read_document with the model's arguments and quotes the document",
            resp.status_code == 200 and execution.get("status") == "success"
            and output.startswith(MOCK_FINAL_PREFIX) and "contents of document 'doc-42'" in output
            and any("doc-42" in str(m.get("content")) for m in fed_back),
            f"HTTP {resp.status_code} status={execution.get('status')} output={output[:200]!r} "
            f"fed_back={[str(m.get('content'))[:80] for m in fed_back]} {execution_error(execution)[:200]}",
        )

        chat.clear()
        wf_agent_scope = n8n.create_agent_workflow(f"e2e {run_id}: agent delete_document (insufficient scope)", f"e2e-agent-delete-{run_id}", CRED_OK, args.mcp_endpoint)
        resp = n8n.trigger(f"e2e-agent-delete-{run_id}", {"prompt": "Delete doc-42."})
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        output = body.get("output", "") if isinstance(body, dict) else ""
        execution = n8n.last_execution(wf_agent_scope)
        seen = chat.requests()
        fed_back = [m for r in seen for m in r.get("messages") or [] if m.get("role") == "tool"]
        check(
            "insufficient_scope from the MCP server comes back to the model as the tool result",
            any("insufficient_scope" in str(m.get("content")) and "documents:write" in str(m.get("content")) for m in fed_back)
            and output.startswith(MOCK_FINAL_PREFIX) and "insufficient_scope" in output,
            f"HTTP {resp.status_code} status={execution.get('status')} output={output[:200]!r} "
            f"fed_back={[str(m.get('content'))[:120] for m in fed_back]} {execution_error(execution)[:200]}",
        )

        chat.clear()
        wf_agent_aud = n8n.create_agent_workflow(f"e2e {run_id}: agent wrong audience", f"e2e-agent-aud-{run_id}", CRED_WRONG_AUD, args.mcp_endpoint)
        resp = n8n.trigger(f"e2e-agent-aud-{run_id}", {"prompt": "Read doc-42 for me."})
        execution = n8n.last_execution(wf_agent_aud)
        # n8n reports the sub-node's failure at execution level with its own
        # wording; the resource server's 401 body is the tool node's error.
        err = execution_error(execution)
        tool_err = node_error(execution, MCP_TOOL_NODE_NAME)
        check(
            "a wrong-audience token stops the agent before the model is called",
            execution.get("status") == "error" and "Authentication failed" in err
            and "invalid_token" in tool_err and not chat.requests(),
            f"HTTP {resp.status_code} status={execution.get('status')} error={err[:120]} "
            f"tool_error={tool_err[:200]} chat_requests={len(chat.requests())}",
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
