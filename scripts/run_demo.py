"""Terminal fallback: run RedCell without the dashboard.  python scripts/run_demo.py [--hardened]"""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import GOALS
from redcell.core.llm import Ledger, TokenFactory
from redcell.core.session import LiveBrain, MockBrain, run_session
from redcell.reporting import report
from redcell.server import JUDGE_M, PLANNER, TARGET_M
from redcell.target.devops_agent import DevOpsAgent

ap = argparse.ArgumentParser()
ap.add_argument("--hardened", action="store_true")
ap.add_argument("--turns", type=int, default=6)
a = ap.parse_args()
sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Nemotron emits curly quotes, non-breaking hyphens
llm = TokenFactory(ledger=Ledger(float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))))
brain = LiveBrain(llm, PLANNER, JUDGE_M) if llm.live else MockBrain()
mode = "nemotron-live" if llm.live else "mock"
print(f"RedCell | brain: {mode} | hardened target: {a.hardened}")

def show(e):
    t = e["type"]
    if t == "goal_start": print(f"\n== {e['title']}  [{e['owasp']}]")
    elif t == "attack": print(f"  RedCell #{e['n']}: {e['text']}")
    elif t == "reply": print(f"  OrbitOps: {e['text'][:160]!r}" + "".join(f"\n    $ {c['cmd']}  ({c['risk']})" for c in e["tool_calls"]))
    elif t == "verdict": print(f"  -> {e['verdict']}: {e['evidence'] or e['reason']}")
    elif t == "replay": print(f"  replay on fresh target: {'reproduced' if e['reproduced'] else 'NOT reproduced (finding dropped)'}")

try:
    res = run_session(DevOpsAgent(llm=llm, model=TARGET_M, hardened=a.hardened, mock=not llm.live), brain, list(GOALS), max_turns=a.turns, emit=show)
except BaseException:
    print(f"\nrun aborted | ${llm.ledger.cost_usd:.4f} spent over {llm.ledger.calls} calls")
    raise
rep = report.build(res, llm.ledger.snapshot(), target_name="OrbitOps (demo DevOps bot)", hardened=a.hardened, mode=mode)
paths = report.save(rep, os.path.join(os.path.dirname(__file__), "..", "reports"))
print(f"\n{rep['goals_broken']}/{rep['goals_tried']} goals broken | ${rep['usage']['cost_usd']:.4f} spent | report: {paths['md']}")
