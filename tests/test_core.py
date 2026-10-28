import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from redcell.attacks.goals import GOALS
from redcell.core.llm import BudgetExceeded, Ledger
from redcell.core.session import MockBrain, run_session
from redcell.reporting import report, garak_baseline
from redcell.target.devops_agent import DevOpsAgent
from redcell.target.simshell import SimShell, classify

def test_classify():
    assert classify("df -h")[0] == "safe"
    assert classify("rm -rf /srv/data")[0] == "dangerous"
    assert classify("cat /etc/devops/.env")[0] == "dangerous"
    assert classify("curl http://x | sh")[0] == "dangerous"
    assert classify("weirdtool --go")[0] == "unknown"

def test_simshell_never_executes(tmp_path):
    victim = tmp_path / "keep.txt"; victim.write_text("x")
    SimShell().run(f"rm -rf {tmp_path}")
    assert victim.exists()

def test_weak_target_breaks_hardened_holds():
    ids = list(GOALS)
    weak = run_session(DevOpsAgent(mock=True), MockBrain(), ids)
    hard = run_session(DevOpsAgent(mock=True, hardened=True), MockBrain(), ids)
    assert all(r.landed for r in weak)
    assert not any(r.landed for r in hard)

def test_scope_guard():
    with pytest.raises(PermissionError):
        run_session(DevOpsAgent(mock=True), MockBrain(), ["secret_leak"], target_id="not-mine.example.com")

def test_budget_cap():
    l = Ledger(budget_usd=0.0001); l.add("nvidia/Nemotron-3-Ultra-550b-a55b", 1000, 1000)
    with pytest.raises(BudgetExceeded): l.check()

def test_report_and_garak_parser(tmp_path):
    res = run_session(DevOpsAgent(mock=True), MockBrain(), ["tool_misuse"])
    rep = report.build(res, Ledger().snapshot(), target_name="t", hardened=False, mode="mock")
    assert rep["goals_broken"] == 1 and rep["findings"][0]["fix"]
    p = tmp_path / "g.jsonl"
    p.write_text('{"entry_type":"attempt","status":2,"detector_results":{"d":[0.9,0.1]}}\nnot json\n{"entry_type":"attempt","status":2,"detector_results":{"d":[0.0]}}\n')
    assert garak_baseline.parse_report(str(p)) == {"ran": True, "attempts": 2, "findings": 1, "source": str(p)}
