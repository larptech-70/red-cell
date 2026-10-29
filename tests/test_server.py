"""Public-demo guards: per-visitor run limit, global daily budget, /target/chat lockdown, last live report."""
import json, os, sys, threading, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from redcell import server


def test_per_visitor_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "PUBLIC", True)
    monkeypatch.setattr(server, "RUNS_PER_VISITOR", 2)
    g = server.Guard(tmp_path / "spend.json")
    assert g.admit("1.1.1.1")[0] and g.admit("1.1.1.1")[0]
    ok, reason, _ = g.admit("1.1.1.1")
    assert not ok and "live runs" in reason
    assert g.admit("2.2.2.2")[0]                       # another visitor still gets runs
    assert g.runs_left("1.1.1.1") == 0


def test_daily_budget_cap_persists(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DAILY_BUDGET_USD", 1.00)
    monkeypatch.setattr(server, "RUN_BUDGET_USD", 1.50)
    g = server.Guard(tmp_path / "spend.json")
    ok, _, budget = g.admit("x")
    assert ok and budget == 1.00                       # a run never gets more than what's left today
    g.record(0.97)
    assert server.Guard(tmp_path / "spend.json").spent == pytest.approx(0.97)  # survives a restart
    ok, reason, _ = g.admit("y")
    assert not ok and "budget" in reason


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_public_mode_locks_target_chat(monkeypatch):
    monkeypatch.setattr(server, "PUBLIC", True)
    monkeypatch.delenv("REDCELL_ENABLE_TARGET_CHAT", raising=False)
    srv, base = _serve()
    req = urllib.request.Request(base + "/target/chat", data=b'{"message":"hi"}', headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 403
    srv.shutdown()


def test_last_live_only_serves_live_reports(tmp_path, monkeypatch):
    (tmp_path / "report.json").write_text(json.dumps({"brain": "mock", "goals_broken": 4}))
    (tmp_path / "report-hardened.json").write_text(json.dumps({"brain": "nemotron-live", "goals_broken": 0}))
    monkeypatch.setattr(server, "LAST_LIVE_DIR", tmp_path)
    monkeypatch.setattr(server, "REPORTS", tmp_path / "none")
    last = server._load_last_live()
    assert "weak" not in last and last["hardened"]["goals_broken"] == 0


# --- judge run-code gate (public mode) ---------------------------------------------------

def _post(base, path, body, cookie=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {})})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        return e.code, ""


def _events(base, cookie=None):
    req = urllib.request.Request(base + "/events?hardened=1", headers={"Cookie": cookie} if cookie else {})
    return urllib.request.urlopen(req, timeout=5).read().decode()


@pytest.fixture
def public_gate(monkeypatch):
    monkeypatch.setattr(server, "PUBLIC", True)
    monkeypatch.setenv("NEBIUS_API_KEY", "test-not-a-real-key")   # "live" mode; nothing below reaches the API
    monkeypatch.setattr(server, "UNLOCK_FAILS", {})
    # Layer 2 stub: proves the code gate let the request through, and stops before any model call.
    monkeypatch.setattr(server.GUARD, "admit", lambda visitor: (False, "GUARD-REACHED", 0.0))
    srv, base = _serve()
    yield base
    srv.shutdown()


def test_no_code_set_disables_live_runs(public_gate, monkeypatch):
    monkeypatch.delenv("REDCELL_RUN_CODE", raising=False)
    ok, reason = server.run_allowed(None)
    assert not ok and "turned off" in reason
    assert _post(public_gate, "/api/unlock", {"code": ""})[0] == 403
    assert _post(public_gate, "/api/unlock", {"code": "anything"})[0] == 403
    out = _events(public_gate)
    assert '"refused"' in out and "turned off" in out and "GUARD-REACHED" not in out


def test_wrong_code_is_refused(public_gate, monkeypatch):
    monkeypatch.setenv("REDCELL_RUN_CODE", "correct-horse")
    status, cookie = _post(public_gate, "/api/unlock", {"code": "wrong-horse"})
    assert status == 403 and not cookie
    for bad in (None, "redcell_run=forged", "redcell_run=" + server._token("wrong-horse")):
        out = _events(public_gate, bad)
        assert "judge code" in out and "GUARD-REACHED" not in out


def test_right_code_unlocks_then_daily_limits_still_apply(public_gate, monkeypatch):
    monkeypatch.setenv("REDCELL_RUN_CODE", "correct-horse")
    status, set_cookie = _post(public_gate, "/api/unlock", {"code": "correct-horse"})
    assert status == 200 and "HttpOnly" in set_cookie and "correct-horse" not in set_cookie  # code never in the cookie
    cookie = set_cookie.split(";")[0]
    assert server.run_allowed(cookie)[0]
    assert "GUARD-REACHED" in _events(public_gate, cookie)          # layer 2 (visitor limit + cap) still runs


def test_code_compare_is_constant_time(monkeypatch):
    calls = []
    real = server.hmac.compare_digest
    monkeypatch.setattr(server.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    monkeypatch.setenv("REDCELL_RUN_CODE", "correct-horse")
    assert server.code_matches("correct-horse") and not server.code_matches("nope")
    assert len(calls) == 2


def test_unlock_guessing_is_limited(public_gate, monkeypatch):
    monkeypatch.setenv("REDCELL_RUN_CODE", "correct-horse")
    for _ in range(server.MAX_UNLOCK_FAILS):
        assert _post(public_gate, "/api/unlock", {"code": "guess"})[0] == 403
    assert _post(public_gate, "/api/unlock", {"code": "correct-horse"})[0] == 429


def test_local_mode_is_not_gated(monkeypatch):
    monkeypatch.setattr(server, "PUBLIC", False)
    monkeypatch.delenv("REDCELL_RUN_CODE", raising=False)
    assert server.run_allowed(None) == (True, "")
