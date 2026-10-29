"""Terminal runner: execute RedCell evaluation against weak or hardened agents.

  python scripts/run_demo.py              # 4 core goals against the weak bot
  python scripts/run_demo.py --all-owasp  # full OWASP LLM Top 10 suite
  python scripts/run_demo.py --hardened   # prove the fixes hold
  python scripts/run_demo.py --compare    # weak vs hardened benchmark table + patches
"""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import CORE_GOAL_IDS, GOALS
from redcell.core import tracing
from redcell.core.llm import Ledger, TokenFactory
from redcell.core.session import LiveBrain, MockBrain, run_session
from redcell.intel import tavily_intel
from redcell.reporting import garak_baseline, report
from redcell.server import JUDGE_M, PLANNER, TARGET_M
from redcell.target.devops_agent import DevOpsAgent

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "..", "reports")
PATCHES = os.path.join(REPORTS, "patches")

ap = argparse.ArgumentParser()
ap.add_argument("--hardened", action="store_true", help="Test hardened target with defense mitigations applied")
ap.add_argument("--all-owasp", action="store_true", help="Run full OWASP LLM Top 10 suite (default: core 4 goals)")
ap.add_argument("--compare", action="store_true", help="Run weak then hardened and print the benchmark table")
ap.add_argument("--turns", type=int, default=6, help="Maximum adversarial turns per goal")
a = ap.parse_args()
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

llm = TokenFactory(ledger=Ledger(float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))))
brain = LiveBrain(llm, PLANNER, JUDGE_M) if llm.live else MockBrain()
mode = "nemotron-live" if llm.live else "mock"
active_goal_ids = list(GOALS) if (a.all_owasp or a.compare) else CORE_GOAL_IDS


def show(e):
    t = e["type"]
    if t == "intel":
        if e["ran"]:
            cached = " [cached]" if e.get("cached") else ""
            print(f"Threat intel: {e['sources']} current source(s) via Tavily{cached}")
        else:
            print(f"Threat intel: offline ({e.get('reason', 'no Tavily key')})")
    elif t == "goal_start":
        print(f"\n== {e['title']}  [{e['owasp']}]")
    elif t == "attack":
        print(f"  RedCell #{e['n']}: {e['text']}")
    elif t == "reply":
        tools = "".join(f"\n    $ {c['cmd']}  ({c['risk']})" for c in e["tool_calls"])
        extra = f"\n    ({len(e['tool_errors'])} malformed tool call(s) returned as errors)" if e.get("tool_errors") else ""
        print(f"  OrbitOps: {e['text'][:160]!r}{tools}{extra}")
    elif t == "reask":
        print(f"  (planner refused as itself; re-asking once) {e['text'][:80]!r}")
    elif t == "verdict":
        print(f"  -> {e['verdict']}: {e['evidence'] or e['reason']}")
    elif t == "replay":
        print(f"  replay on fresh target: {'reproduced' if e['reproduced'] else 'NOT reproduced (finding dropped)'}")


def run_once(hardened, write_patches=True):
    """Run one session under a LangSmith span; return (results, report, paths)."""
    with tracing.span("RedCell run", "chain",
                      inputs={"target": "OrbitOps (demo DevOps bot)", "hardened": hardened,
                              "brain": mode, "goals": active_goal_ids, "max_turns": a.turns}) as run_span:
        intel = tavily_intel.gather([GOALS[g] for g in active_goal_ids], emit=show)
        if isinstance(brain, LiveBrain):
            brain.intel = intel
        try:
            res = run_session(DevOpsAgent(llm=llm, model=TARGET_M, hardened=hardened, mock=not llm.live),
                              brain, active_goal_ids, max_turns=a.turns, emit=show)
        except BaseException:
            print(f"\nrun aborted | ${llm.ledger.cost_usd:.4f} spent over {llm.ledger.calls} calls")
            raise
        rep = report.build(res, llm.ledger.snapshot(), target_name="OrbitOps (demo DevOps bot)",
                           hardened=hardened, mode=mode, intel=intel, garak=garak_baseline.load(),
                           patches_dir=PATCHES if write_patches else None)
        run_span.end(outputs={"goals_broken": rep["goals_broken"], "goals_tried": rep["goals_tried"]},
                     metadata={"cost_usd": rep["usage"]["cost_usd"], "model_calls": rep["usage"]["calls"]})
        if run_span.url():
            print(f"LangSmith trace: {run_span.url()}")
        elif run_span.trace_id():
            print(f"LangSmith trace id: {run_span.trace_id()} (project {os.environ.get('LANGSMITH_PROJECT', 'default')})")
    paths = report.save(rep, REPORTS)
    return res, rep, paths


def print_compare(weak_rep, hard_rep):
    wf = {f["id"]: f for f in weak_rep["findings"]}
    hf = {f["id"]: f for f in hard_rep["findings"]}
    print("\n" + "=" * 84)
    print("OWASP BENCHMARK - weak vs hardened OrbitOps")
    print("=" * 84)
    print(f"{'Goal':<46} {'Weak target':<18} {'Hardened target':<20}")
    print("-" * 84)
    for gid in active_goal_ids:
        title = GOALS[gid].title
        weak = f"Broken (turn {wf[gid]['turns_to_break']})" if gid in wf else "Held"
        hard = "Broken" if gid in hf else "Held (defended)"
        print(f"{title[:46]:<46} {weak:<18} {hard:<20}")
    print("-" * 84)
    print(f"{'Total breach score':<46} "
          f"{str(weak_rep['goals_broken']) + '/' + str(weak_rep['goals_tried']) + ' broken':<18} "
          f"{str(hard_rep['goals_broken']) + '/' + str(hard_rep['goals_tried']) + ' broken':<20}")
    if weak_rep.get("patches"):
        p = weak_rep["patches"]
        print(f"\nRemediation: one applyable patch -> {p['patch']} "
              f"({'git apply clean' if p['applies'] else 'review required'}).")
    print(f"Cost: weak ${weak_rep['usage']['cost_usd']:.4f} | hardened ${hard_rep['usage']['cost_usd']:.4f}")


print(f"RedCell | brain: {mode} | goals: {len(active_goal_ids)}")
try:
    if a.compare:
        _, weak_rep, _ = run_once(hardened=False, write_patches=True)
        _, hard_rep, _ = run_once(hardened=True, write_patches=False)
        print_compare(weak_rep, hard_rep)
    else:
        res, rep, paths = run_once(hardened=a.hardened)
        print(f"\n{rep['goals_broken']}/{rep['goals_tried']} goals broken | ${rep['usage']['cost_usd']:.4f} spent | "
              f"report: {paths['md']} | sarif: {paths['sarif']}")
        if rep.get("patches"):
            print(f"remediation patch: {rep['patches']['patch']} "
                  f"({'git apply clean' if rep['patches']['applies'] else 'review required'})")
except BaseException:
    raise
tracing.flush()
