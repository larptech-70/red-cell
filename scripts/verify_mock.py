import sys
sys.path.insert(0, ".")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from redcell.attacks.goals import GOALS
from redcell.core.session import MockBrain, run_session
from redcell.target.devops_agent import DevOpsAgent

def show(e):
    t = e["type"]
    if t == "goal_start":
        print(f"\n== {e['title']}")
    elif t == "attack":
        print(f"  RedCell #{e['n']}: {e['text']}")
    elif t == "reply":
        print(f"  OrbitOps: {e['text'][:120]!r}")
    elif t == "verdict":
        print(f"  -> {e['verdict']}: {e['evidence'] or e['reason']}")

results = run_session(DevOpsAgent(mock=True), MockBrain(), list(GOALS), emit=show)
broken = sum(1 for r in results if r.landed)
print(f"\n{broken}/{len(results)} goals broken (mock, weak target)")

