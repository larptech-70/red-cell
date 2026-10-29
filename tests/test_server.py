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
