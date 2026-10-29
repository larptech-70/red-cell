import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.adapters.base import BaseTargetAdapter
from redcell.adapters.http_adapter import HTTPTargetAdapter


class MockHTTPServer(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        len_h = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(len_h) if len_h else b"{}")
        msg = body.get("message", "")
        reply = f"Echo: {msg}"
        tools = [{"cmd": "uptime", "risk": "safe", "why": "allowlist"}]
        resp = json.dumps({"reply": reply, "tool_calls": tools}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def test_http_target_adapter():
    server = HTTPServer(("127.0.0.1", 0), MockHTTPServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/chat"

    adapter = HTTPTargetAdapter(url, target_id="test-http-bot")
    assert adapter.health_check() is True
    res = adapter.send("hello server")

    assert res["reply"] == "Echo: hello server"
    assert len(res["tool_calls"]) == 1
    assert res["tool_calls"][0]["cmd"] == "uptime"
    server.shutdown()


def test_http_allowlist_host_from_env(monkeypatch):
    monkeypatch.setenv("REDCELL_ALLOW", "agent.mycompany.internal")
    adapter = HTTPTargetAdapter("https://agent.mycompany.internal/chat")
    assert adapter.endpoint_url.startswith("https://agent.mycompany.internal")


def test_http_allowlist_refuses_unlisted_host(monkeypatch):
    monkeypatch.delenv("REDCELL_ALLOW", raising=False)
    with pytest.raises(PermissionError, match="not on the allowlist"):
        HTTPTargetAdapter("https://someone-elses-bot.example.com/chat")


def test_http_allowlist_ignores_spoofed_target_id(monkeypatch):
    # The guard is on the URL's host; naming the target "orbitops-demo" must not get it through.
    monkeypatch.delenv("REDCELL_ALLOW", raising=False)
    with pytest.raises(PermissionError):
        HTTPTargetAdapter("https://someone-elses-bot.example.com/chat", target_id="orbitops-demo")
    with pytest.raises(PermissionError):  # reset_url is a network destination too
        HTTPTargetAdapter("http://127.0.0.1:9/chat", reset_url="https://evil.example.com/reset")
