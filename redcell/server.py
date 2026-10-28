"""RedCell dashboard server (stdlib only).

  GET  /                     dashboard
  GET  /events?hardened=0|1  run a session and stream events (Server-Sent Events)
  GET  /report.md|.json      last report
  POST /target/chat          chat with the demo target (this is what garak scans)
"""
from __future__ import annotations

import json
import os
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .attacks.goals import GOALS
from .core.llm import Ledger, TokenFactory
from .core.session import LiveBrain, MockBrain, run_session
from .reporting import report as rpt
from .target.devops_agent import DevOpsAgent

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATIC = ROOT / "web" / "static"
PLANNER = os.environ.get("REDCELL_PLANNER_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b")
TARGET_M = os.environ.get("REDCELL_TARGET_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
JUDGE_M = os.environ.get("REDCELL_JUDGE_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")

STATE = {"report": None, "running": False}
CHAT_AGENT = DevOpsAgent(llm=TokenFactory(), model=TARGET_M)  # long-lived target for garak
CHAT_LOCK = threading.Lock()


def make_session(hardened: bool):
    llm = TokenFactory(ledger=Ledger(float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))))
    live = llm.live
    target = DevOpsAgent(llm=llm, model=TARGET_M, hardened=hardened, mock=not live)
    brain = LiveBrain(llm, PLANNER, JUDGE_M) if live else MockBrain()
    return llm, target, brain, "nemotron-live" if live else "mock"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes())
        if u.path == "/events":
            return self._events(parse_qs(u.query))
        if u.path in ("/report.md", "/report.json") and STATE["report"]:
            r = STATE["report"]
            return self._send(200, rpt.to_markdown(r) if u.path.endswith("md") else json.dumps(r, indent=2),
                              "text/markdown; charset=utf-8" if u.path.endswith("md") else "application/json")
        if u.path == "/api/info":
            return self._send(200, json.dumps({"live": TokenFactory().live, "goals": [{"id": g.id, "title": g.title, "owasp": g.owasp} for g in GOALS.values()]}), "application/json")
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        if urlparse(self.path).path != "/target/chat":
            return self._send(404, "not found", "text/plain")
        try:
            msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}").get("message", "")
        except ValueError:
            return self._send(400, '{"error":"bad json"}', "application/json")
        with CHAT_LOCK:
            out = CHAT_AGENT.send(str(msg)[:4000])
        self._send(200, json.dumps({"reply": out["reply"]}), "application/json")

    def _events(self, q):
        if STATE["running"]:
            return self._send(409, "A run is already in progress.", "text/plain")
        STATE["running"] = True
        hardened = q.get("hardened", ["0"])[0] == "1"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def emit(e):
            self.wfile.write(f"data: {json.dumps(e)}\n\n".encode())
            self.wfile.flush()
            if e["type"] in ("attack", "reply", "verdict"):
                time.sleep(0.55 if not make_session.__dict__.get("fast") else 0)

        try:
            llm, target, brain, mode = make_session(hardened)
            emit({"type": "start", "mode": mode, "hardened": hardened, "goals": [{"id": g.id, "title": g.title, "owasp": g.owasp} for g in GOALS.values()]})
            results = run_session(target, brain, list(GOALS), emit=emit)
            rep = rpt.build(results, llm.ledger.snapshot(), target_name="OrbitOps (demo DevOps bot)", hardened=hardened, mode=mode)
            STATE["report"] = rep
            emit({"type": "done", "report": rep})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # surface errors to the UI instead of hanging
            try:
                emit({"type": "error", "text": f"{type(e).__name__}: {e}"})
            except OSError:
                pass
        finally:
            STATE["running"] = False


def main(port: int = 8765):
    print(f"RedCell dashboard: http://127.0.0.1:{port}  ({'live Token Factory' if TokenFactory().live else 'offline mock mode: set NEBIUS_API_KEY for live Nemotron'})")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    main()
