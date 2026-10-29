import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.adapters.base import BaseTargetAdapter
from redcell.adapters.http_adapter import HTTPTargetAdapter
from redcell.target.docker_sandbox import DockerSandbox


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


def test_docker_sandbox_fallback():
    # Force fallback to ensure consistent non-docker test execution
    sandbox = DockerSandbox(force_fallback=True)
    sandbox.start()
    assert sandbox.has_docker is False
    out = sandbox.run("df -h")
    assert "Filesystem" in out or "Filesystem" in sandbox.run("df")
    assert len(sandbox.log) >= 1
    sandbox.teardown()
