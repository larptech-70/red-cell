"""RedCell dashboard server (stdlib only).

  GET  /                     dashboard
  GET  /events?hardened=0|1  run a session and stream events (Server-Sent Events)
  GET  /api/info             mode, goals, live runs left for this visitor
  GET  /api/last             last LIVE weak + hardened reports (no new spend)
  POST /api/unlock           {"code": ...} -> sets an HttpOnly cookie that allows live runs (public mode)
  GET  /report.md|.json      report of the last run here (or the last live report)
  POST /target/chat          chat with the demo target (this is what garak scans)
  GET  /target/usage         spend of the /target/chat endpoint

Public deployment (REDCELL_PUBLIC=1): each visitor gets REDCELL_RUNS_PER_VISITOR live runs per UTC
day, all live runs share a REDCELL_DAILY_BUDGET_USD cap, and /target/chat is off unless
REDCELL_ENABLE_TARGET_CHAT=1, so a public URL cannot drain credits. Bind with REDCELL_HOST / PORT.
Live runs in public mode also need a judge code: REDCELL_RUN_CODE, set only as a host secret. With no code
set, public live runs are disabled; visitors always see the saved live run.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import threading
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .attacks.goals import CORE_GOAL_IDS, GOALS
from .core.llm import Ledger, TokenFactory
from .core.session import LiveBrain, MockBrain, run_session
from .intel import tavily_intel
from .reporting import garak_baseline
from .reporting import report as rpt
from .target.devops_agent import DevOpsAgent

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATIC = ROOT / "web" / "static"
LAST_LIVE_DIR = ROOT / "web" / "last-live"   # committed snapshot of the last live runs, served to judges
REPORTS = ROOT / "reports"
PLANNER = os.environ.get("REDCELL_PLANNER_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b")
TARGET_M = os.environ.get("REDCELL_TARGET_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
JUDGE_M = os.environ.get("REDCELL_JUDGE_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")

PUBLIC = os.environ.get("REDCELL_PUBLIC") == "1"
RUNS_PER_VISITOR = int(os.environ.get("REDCELL_RUNS_PER_VISITOR", "2"))
DAILY_BUDGET_USD = float(os.environ.get("REDCELL_DAILY_BUDGET_USD", "0.50"))
RUN_BUDGET_USD = float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))
MIN_RUN_USD = 0.05  # don't start a live run with less than this left in today's budget
GOAL_IDS = list(GOALS) if os.environ.get("REDCELL_ALL_GOALS") == "1" else CORE_GOAL_IDS

COOKIE = "redcell_run"
MAX_UNLOCK_FAILS = 10  # per visitor per process, against guessing

STATE = {"report": None}
UNLOCK_FAILS: dict[str, int] = {}
RUN_LOCK = threading.Lock()  # one run at a time
# Long-lived target for garak. Its own budget (garak sends many prompts) and the per-request
# reset below keep each probe an independent, cheap, single-turn exchange. No retries: a failed
# upstream call answers "(target unavailable ...)" at once instead of spending more.
CHAT_AGENT = DevOpsAgent(llm=TokenFactory(ledger=Ledger(float(os.environ.get("REDCELL_CHAT_BUDGET_USD", "0.25"))), attempts=1), model=TARGET_M)
CHAT_LOCK = threading.Lock()


class Guard:
    """Per-visitor live-run limit (public mode) and a global daily spend cap (always), per UTC day.
    Spend is persisted so a restart does not reset the cap."""

    def __init__(self, path: pathlib.Path = REPORTS / "daily_spend.json"):
        self.path, self.lock = path, threading.Lock()
        self.day, self.spent, self.visits = "", 0.0, {}
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            self.day, self.spent = d.get("day", ""), float(d.get("usd", 0.0))
        except (OSError, ValueError):
            pass

    def _roll(self) -> None:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if self.day != today:
            self.day, self.spent, self.visits = today, 0.0, {}

    def runs_left(self, visitor: str) -> int | None:
        with self.lock:
            self._roll()
            return max(0, RUNS_PER_VISITOR - self.visits.get(visitor, 0)) if PUBLIC else None

    def admit(self, visitor: str) -> tuple[bool, str, float]:
        """Returns (ok, reason, budget for this run)."""
        with self.lock:
            self._roll()
            if PUBLIC and self.visits.get(visitor, 0) >= RUNS_PER_VISITOR:
                return False, f"You've used your {RUNS_PER_VISITOR} live runs for today. The last live results are shown instead.", 0.0
            remaining = DAILY_BUDGET_USD - self.spent
            if remaining < MIN_RUN_USD:
                return False, "Today's shared live-run budget is used up. The last live results are shown instead.", 0.0
            self.visits[visitor] = self.visits.get(visitor, 0) + 1
            return True, "", min(RUN_BUDGET_USD, remaining)

    def record(self, usd: float) -> None:
        with self.lock:
            self._roll()
            self.spent += usd
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(json.dumps({"day": self.day, "usd": round(self.spent, 5)}), encoding="utf-8")
            except OSError:
                pass


GUARD = Guard()


def _run_code() -> str:
    return os.environ.get("REDCELL_RUN_CODE", "")


def _token(code: str) -> str:
    """Cookie value: an HMAC of the code, so the code itself never sits in the browser."""
    return hmac.new(code.encode(), b"redcell-live-run", hashlib.sha256).hexdigest()


def code_matches(candidate: str) -> bool:
    code = _run_code()
    return bool(code) and hmac.compare_digest(candidate.encode(), code.encode())  # constant time


def run_allowed(cookie_header: str | None) -> tuple[bool, str]:
    """Judge-code gate for live runs in public mode. Local (non-public) runs are not gated."""
    if not PUBLIC:
        return True, ""
    code = _run_code()
    if not code:
        return False, "Live runs are turned off on this public demo. The saved live run is shown instead."
    try:
        morsel = SimpleCookie(cookie_header or "").get(COOKIE)
    except CookieError:
        morsel = None
    if morsel and hmac.compare_digest(morsel.value.encode(), _token(code).encode()):
        return True, ""
    return False, ("Live runs need a judge code (judges: see the Devpost testing instructions). "
                   "The saved live run is shown instead.")


def _load_last_live() -> dict:
    """Last live weak/hardened reports: the committed snapshot first, else live reports in reports/."""
    out = {}
    for kind, name in (("weak", "report.json"), ("hardened", "report-hardened.json")):
        for d in (LAST_LIVE_DIR, REPORTS):
            try:
                rep = json.loads((d / name).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if rep.get("brain") == "nemotron-live":
                out[kind] = rep
                break
    return out


LAST_LIVE = _load_last_live()


def make_session(hardened: bool, budget: float = RUN_BUDGET_USD):
    llm = TokenFactory(ledger=Ledger(budget))
    live = llm.live
    target = DevOpsAgent(llm=llm, model=TARGET_M, hardened=hardened, mock=not live)
    brain = LiveBrain(llm, PLANNER, JUDGE_M) if live else MockBrain()
    return llm, target, brain, "nemotron-live" if live else "mock"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _visitor(self) -> str:
        if os.environ.get("REDCELL_TRUST_PROXY") == "1":  # only behind a proxy you control
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[0].strip()
        return self.client_address[0]

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes())
        if u.path == "/events":
            return self._events(q)
        if u.path in ("/report.md", "/report.json"):
            kind = q.get("kind", [""])[0]
            r = LAST_LIVE.get(kind) if kind else (STATE["report"] or LAST_LIVE.get("weak"))
            if r:
                return self._send(200, rpt.to_markdown(r) if u.path.endswith("md") else json.dumps(r, indent=2),
                                  "text/markdown; charset=utf-8" if u.path.endswith("md") else "application/json")
        if u.path == "/api/last":
            return self._send(200, json.dumps(LAST_LIVE), "application/json")
        if u.path == "/target/usage":  # spend of the garak-facing /target/chat endpoint
            return self._send(200, json.dumps(CHAT_AGENT.llm.ledger.snapshot()), "application/json")
        if u.path == "/api/info":
            live = TokenFactory().live
            return self._send(200, json.dumps({
                "live": live, "public": PUBLIC, "runs_left": GUARD.runs_left(self._visitor()) if live else None,
                "needs_code": PUBLIC and live, "live_runs_enabled": live and (not PUBLIC or bool(_run_code())),
                "unlocked": live and run_allowed(self.headers.get("Cookie"))[0],
                "goals": [{"id": GOALS[g].id, "title": GOALS[g].title, "owasp": GOALS[g].owasp} for g in GOAL_IDS]}), "application/json")
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        if urlparse(self.path).path == "/api/unlock":
            return self._unlock()
        if urlparse(self.path).path != "/target/chat":
            return self._send(404, "not found", "text/plain")
        if PUBLIC and os.environ.get("REDCELL_ENABLE_TARGET_CHAT") != "1":
            return self._send(403, '{"error":"/target/chat is disabled on the public demo"}', "application/json")
        try:
            msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}").get("message", "")
        except ValueError:
            return self._send(400, '{"error":"bad json"}', "application/json")
        try:
            with CHAT_LOCK:
                CHAT_AGENT.reset()  # each /target/chat is an independent single-turn exchange (garak is single-turn)
                out = CHAT_AGENT.send(str(msg)[:4000])
            reply = out["reply"]
        except Exception as e:  # always answer -- a hang here would stall a whole garak scan
            reply = f"(target unavailable: {type(e).__name__})"
        self._send(200, json.dumps({"reply": reply}), "application/json")

    def _unlock(self):
        visitor = self._visitor()
        if UNLOCK_FAILS.get(visitor, 0) >= MAX_UNLOCK_FAILS:
            return self._send(429, '{"ok":false,"error":"too many attempts"}', "application/json")
        try:
            code = str(json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 1024)) or b"{}").get("code", ""))
        except (ValueError, AttributeError):
            return self._send(400, '{"ok":false,"error":"bad json"}', "application/json")
        if not code_matches(code):
            UNLOCK_FAILS[visitor] = UNLOCK_FAILS.get(visitor, 0) + 1
            return self._send(403, '{"ok":false,"error":"wrong or disabled code"}', "application/json")
        b = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Set-Cookie", f"{COOKIE}={_token(_run_code())}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=172800")
        self.end_headers()
        self.wfile.write(b)

    def _events(self, q):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def emit(e):
            self.wfile.write(f"data: {json.dumps(e)}\n\n".encode())
            self.wfile.flush()
            if e["type"] in ("attack", "reply", "verdict"):
                time.sleep(0.55)

        if not RUN_LOCK.acquire(blocking=False):
            return emit({"type": "refused", "text": "Another run is in progress. Try again in a few minutes."})
        llm = None
        try:
            hardened = q.get("hardened", ["0"])[0] == "1"
            budget = RUN_BUDGET_USD
            if TokenFactory().live:
                ok, reason = run_allowed(self.headers.get("Cookie"))  # layer 1: judge code (public mode)
                if not ok:
                    return emit({"type": "refused", "text": reason})
                ok, reason, budget = GUARD.admit(self._visitor())  # layer 2: per-visitor limit + daily cap
                if not ok:
                    return emit({"type": "refused", "text": reason})
            llm, target, brain, mode = make_session(hardened, budget)
            goals = [GOALS[g] for g in GOAL_IDS]
            emit({"type": "start", "mode": mode, "hardened": hardened, "goals": [{"id": g.id, "title": g.title, "owasp": g.owasp} for g in goals]})
            intel = tavily_intel.gather(goals, emit=emit)
            if isinstance(brain, LiveBrain):
                brain.intel = intel
            results = run_session(target, brain, GOAL_IDS, emit=emit)
            rep = rpt.build(results, llm.ledger.snapshot(), target_name="OrbitOps (demo DevOps bot)", hardened=hardened, mode=mode, intel=intel, garak=garak_baseline.load())
            STATE["report"] = rep
            if mode == "nemotron-live":
                LAST_LIVE["hardened" if hardened else "weak"] = rep
            emit({"type": "done", "report": rep})
        except (BrokenPipeError, ConnectionResetError):
            pass  # visitor left: the run stops here, so spend stops too
        except Exception as e:  # surface errors to the UI instead of hanging
            try:
                emit({"type": "error", "text": f"{type(e).__name__}: {e}"})
            except OSError:
                pass
        finally:
            if llm is not None and llm.live:
                GUARD.record(llm.ledger.cost_usd)
            RUN_LOCK.release()


def main():
    host = os.environ.get("REDCELL_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT") or os.environ.get("REDCELL_PORT") or 8765)
    mode = "live Token Factory" if TokenFactory().live else "offline mock mode: set NEBIUS_API_KEY for live Nemotron"
    extra = f", public: {RUNS_PER_VISITOR} runs/visitor/day, ${DAILY_BUDGET_USD:.2f}/day cap" if PUBLIC else ""
    print(f"RedCell dashboard: http://{host}:{port}  ({mode}{extra})", flush=True)
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    main()
