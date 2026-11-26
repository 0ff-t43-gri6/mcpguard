"""Streamable HTTP MCP server for tests.

use_sse       answer with text/event-stream instead of JSON
token         require this bearer token
expire_after  after this many requests in a session, answer 404 once (session expired)
"""

import itertools
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def start(use_sse=False, token=None, expire_after=None):
    calls = []
    sessions = itertools.count(1)
    state = {"session": None, "count": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self, code, body=None, headers=None):
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_DELETE(self):
            self._reply(200)

        def do_POST(self):
            body_in = self.rfile.read(int(self.headers["Content-Length"]))  # read it first: on Windows, closing
            if token and self.headers.get("Authorization") != f"Bearer {token}":  # with unread data resets the socket
                return self._reply(401)
            msg = json.loads(body_in)
            calls.append((msg, dict(self.headers)))
            method = msg.get("method")
            if method != "initialize" and self.headers.get("Mcp-Session-Id") != state["session"]:
                return self._reply(404)
            if "id" not in msg:
                return self._reply(202)
            if method == "initialize":
                state["session"], state["count"] = f"sess-{next(sessions) * 123}", 0
                result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "httpfake"}}
            else:
                state["count"] += 1
                if expire_after and state["count"] == expire_after:
                    state["session"] = None
                    return self._reply(404)
                result = ({"tools": [{"name": "hello", "description": "Say hello.", "inputSchema": {"type": "object"}}]}
                          if method == "tools/list" else
                          {"content": [{"type": "text", "text": "hello from http"}]} if method == "tools/call" else {})
            body = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
            if use_sse:
                self.send_response(200)
                self.send_header("Mcp-Session-Id", state["session"])
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
                self.wfile.write(f"data: {json.dumps(note)}\n\n".encode())
                self.wfile.write(f"event: message\ndata: {json.dumps(body)}\n\n".encode())
            else:
                self._reply(200, body, {"Mcp-Session-Id": state["session"]})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", calls
