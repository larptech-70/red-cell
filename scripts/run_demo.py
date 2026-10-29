"""Terminal runner: execute RedCell evaluation against weak or hardened agents."""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import CORE_GOAL_IDS, GOALS
from redcell.core.llm import Ledger, TokenFactory
from redcell.core.session import LiveBrain, MockBrain, run_session
from redcell.intel import tavily_intel
from redcell.reporting import garak_baseline, report
from redcell.server import JUDGE_M, PLANNER, TARGET_M
from redcell.target.devops_agent import DevOpsAgent

ap = argparse.ArgumentParser()
ap.add_argument("--hardened", action="store_true", help="Test hardened target with defense mitigations applied")
ap.add_argument("--all-owasp", action="store_true", help="Run full 10-goal OWASP LLM Top 10 suite (default: core 4 goals)")
ap.add_argument("--turns", type=int, default=6, help="Maximum adversarial turns per goal")
a = ap.parse_args()
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

llm = TokenFactory(ledger=Ledger(float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))))
brain = LiveBrain(llm, PLANNER, JUDGE_M) if llm.live else MockBrain()
mode = "nemotron-live" if llm.live else "mock"
active_goal_ids = list(GOALS) if a.all_owasp else CORE_GOAL_IDS

print(f"RedCell | brain: {mode} | hardened target: {a.hardened} | goals: {len(active_goal_ids)}")

def show(e):
    t = e["type"]
    if t == "intel": print(f"Threat intel: {e['sources']} current source(s) via Tavily" + (" [cached]" if e.get("cached") else "") if e["ran"] else f"Threat intel: offline ({e.get('reason','no Tavily key')})")
    elif t == "goal_start": print(f"\n== {e['title']}  [{e['owasp']}]")
    elif t == "attack": print(f"  RedCell #{e['n']}: {e['text']}")
    elif t == "reply": print(f"  OrbitOps: {e['text'][:160]!r}" + "".join(f"\n    $ {c['cmd']}  ({c['risk']})" for c in e["tool_calls"]))
    elif t == "reask": print(f"  (planner refused as itself; re-asking once) {e['text'][:80]!r}")
    elif t == "verdict": print(f"  -> {e['verdict']}: {e['evidence'] or e['reason']}")
    elif t == "replay": print(f"  replay on fresh target: {'reproduced' if e['reproduced'] else 'NOT reproduced (finding dropped)'}")

target_goals = [GOALS[gid] for gid in active_goal_ids]
intel = tavily_intel.gather(target_goals, emit=show)
if isinstance(brain, LiveBrain):
    brain.intel = intel

try:
    res = run_session(DevOpsAgent(llm=llm, model=TARGET_M, hardened=a.hardened, mock=not llm.live), brain, active_goal_ids, max_turns=a.turns, emit=show)
except BaseException:
    print(f"\nrun aborted | ${llm.ledger.cost_usd:.4f} spent over {llm.ledger.calls} calls")
    raise
rep = report.build(res, llm.ledger.snapshot(), target_name="OrbitOps (demo DevOps bot)", hardened=a.hardened, mode=mode, intel=intel, garak=garak_baseline.load())
paths = report.save(rep, os.path.join(os.path.dirname(__file__), "..", "reports"))
print(f"\n{rep['goals_broken']}/{rep['goals_tried']} goals broken | ${rep['usage']['cost_usd']:.4f} spent | report: {paths['md']} | sarif: {paths['sarif']}")
