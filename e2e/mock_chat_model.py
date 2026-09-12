#!/usr/bin/env python3
"""Mock OpenAI-compatible chat model: an e2e fixture for issue #194 (path 2).

This is a FIXTURE, not a product, and deliberately a stupid one. It exists so
n8n's AI Agent can run a tool-calling loop in CI without an LLM: the agent
asks this "model" what to do, the model always answers "call the MCP tool",
the agent calls it (through the MCP Client Tool node, with the token n8n
obtained from nanoidp), feeds the result back, and the model turns the tool's
answer into a final message. What the run proves is that n8n propagates the
OAuth-protected MCP tools into the agent's loop, and that the resource
server's authorization decisions come back through it. It proves nothing
about language models.

Two endpoints, the minimum the pinned n8n version needs from an OpenAI-style
base URL (chat completions, not the Responses API):

    GET  /v1/models            -> one model, "mock-tool-caller"
    POST /v1/chat/completions  -> the two-state machine below

The machine is stateless; it decides from the conversation it is handed:

  1. The last message is a ``tool`` result -> final answer, a fixed sentence
     that quotes the tool's output verbatim (the e2e asserts on that quote).
  2. Otherwise, ``tools`` were offered -> one ``tool_calls`` entry. The tool
     is chosen from the user's words ("delete" -> delete_document, "admin" ->
     admin_operation, anything else -> read_document) and must be among the
     offered ones, matched on the suffix, because n8n's MCP Client Tool node
     prefixes every tool with the node's name (``MCP_Client_Tool_read_document``)
     and the call goes back under that prefixed name. The arguments follow
     the mock MCP server's signatures: ``document_id`` (the first ``doc-...``
     token in the user message, ``doc-42`` if none) for read_document and
     delete_document, ``action`` for admin_operation.
  3. No tools at all -> a plain text answer saying so.

Every request is kept in memory and served back on ``GET /requests`` so a
test can check what the agent sent (which tools it advertised, what tool
result it fed back). Streaming is not implemented: n8n's agent calls the
model with ``stream: false`` on this path, and a ``stream: true`` request is
answered with 400 so the gap is visible rather than silent.

Run:
    python e2e/mock_chat_model.py --host 127.0.0.1 --port 9200
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

MODEL_ID = "mock-tool-caller"
FINAL_ANSWER = "The tool answered: {result}"
NO_TOOLS_ANSWER = "No tools were offered, so there is nothing to call."
DOC_ID = re.compile(r"\bdoc-[A-Za-z0-9_-]+\b")

_requests: List[Dict[str, Any]] = []
_lock = threading.Lock()


def _text(content: Any) -> str:
    """Message content as plain text: a string, or the text parts of a list."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"
        )
    return "" if content is None else str(content)


def _last_user_text(messages: List[Dict[str, Any]]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return _text(msg.get("content"))
    return ""


def _pick_tool(user_text: str, offered: List[str]) -> Optional[str]:
    """The offered tool name to call, as offered (n8n prefixes it), or None."""
    lowered = user_text.lower()
    if "delete" in lowered:
        wanted = "delete_document"
    elif "admin" in lowered:
        wanted = "admin_operation"
    else:
        wanted = "read_document"
    for name in offered:
        if name == wanted or name.endswith("_" + wanted):
            return name
    return None


def _arguments_for(tool: str, user_text: str) -> Dict[str, str]:
    """The arguments e2e/mock_mcp_server.py's tool takes: read_document and
    delete_document want ``document_id``, admin_operation wants ``action``."""
    if tool.endswith("admin_operation"):
        return {"action": "audit"}
    match = DOC_ID.search(user_text)
    return {"document_id": match.group(0) if match else "doc-42"}


def decide(body: Dict[str, Any]) -> Dict[str, Any]:
    """The two-state machine: a chat completion ``message`` and its finish reason."""
    messages = body.get("messages") or []
    last = messages[-1] if messages else {}
    if last.get("role") == "tool":
        return {
            "message": {"role": "assistant", "content": FINAL_ANSWER.format(result=_text(last.get("content")))},
            "finish_reason": "stop",
        }

    offered = [
        t.get("function", {}).get("name")
        for t in body.get("tools") or []
        if isinstance(t, dict) and t.get("type") == "function"
    ]
    tool = _pick_tool(_last_user_text(messages), [name for name in offered if name])
    if tool is None:
        return {
            "message": {"role": "assistant", "content": NO_TOOLS_ANSWER},
            "finish_reason": "stop",
        }
    return {
        "message": {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"call_{uuid.uuid4().hex[:24]}",
                    "type": "function",
                    "function": {"name": tool, "arguments": json.dumps(_arguments_for(tool, _last_user_text(messages)))},
                }
            ],
        },
        "finish_reason": "tool_calls",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-chat-model/1"

    def _json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/v1/models", "/models"):
            self._json(200, {"object": "list", "data": [{"id": MODEL_ID, "object": "model", "owned_by": "nanoidp-e2e"}]})
        elif self.path.rstrip("/") == "/requests":
            with _lock:
                self._json(200, list(_requests))
        elif self.path.rstrip("/") == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": {"message": f"no route for GET {self.path}", "type": "invalid_request_error"}})

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/requests":
            with _lock:
                _requests.clear()
            self._json(200, {"cleared": True})
        else:
            self._json(404, {"error": {"message": f"no route for DELETE {self.path}", "type": "invalid_request_error"}})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            self._json(404, {"error": {"message": f"no route for POST {self.path}", "type": "invalid_request_error"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": {"message": "body is not JSON", "type": "invalid_request_error"}})
            return
        with _lock:
            _requests.append({"received_at": time.time(), "body": body})
        if body.get("stream"):
            self._json(400, {"error": {"message": "this fixture does not stream", "type": "invalid_request_error"}})
            return
        choice = decide(body)
        self._json(
            200,
            {
                "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": body.get("model") or MODEL_ID,
                "choices": [{"index": 0, "message": choice["message"], "finish_reason": choice["finish_reason"], "logprobs": None}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102
        print(f"{self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9200)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock chat model on http://{args.host}:{args.port}/v1 (model {MODEL_ID})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
