"""Terminal runner: execute RedCell evaluation against weak, hardened, or patched agents.

  python scripts/run_demo.py              # 4 core goals against the weak bot
  python scripts/run_demo.py --all-owasp  # full OWASP LLM Top 10 suite
  python scripts/run_demo.py --hardened   # built-in hardened bot (prompt + allowlist)
  python scripts/run_demo.py --patched    # bot with the GENERATED hardening patch applied
  python scripts/run_demo.py --compare    # weak vs hardened benchmark table + patches
  python scripts/run_demo.py --compare --patched   # weak vs hardened vs patched
"""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import CORE_GOAL_IDS, GOALS
from redcell.core import tracing
from redcell.core.llm import Ledger, TokenFactory
from redcell.core.session import LiveBrain, MockBrain, run_session
from redcell.intel import tavily_intel
from redcell.reporting import garak_baseline, remediation, report
from redcell.server import JUDGE_M, PLANNER, TARGET_M
from redcell.target.devops_agent import DevOpsAgent

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "..", "reports")
PATCHES = os.path.join(REPORTS, "patches")

ap = argparse.ArgumentParser()
ap.add_argument("--hardened", action="store_true", help="Test built-in hardened target (prompt + allowlist)")
ap.add_argument("--patched", action="store_true", help="Test target with the generated hardening patch applied")
ap.add_argument("--all-owasp", action="store_true", help="Run full OWASP LLM Top 10 suite (default: core 4 goals)")
ap.add_argument("--compare", action="store_true", help="Run weak then hardened (and patched) and print the benchmark table")
ap.add_argument("--turns", type=int, default=6, help="Maximum adversarial turns per goal")
ap.add_argument("--canary-file", type=str, default=None, help="Path to JSON file with custom canary definitions")
a = ap.parse_args()
if a.canary_file:
    from redcell.target.simshell import load_canary_file
    load_canary_file(a.canary_file)
    print(f"RedCell | custom canaries loaded from: {a.canary_file}")
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


def make_target(hardened, patched):
    """Build the target for this run. patched=True loads the generated hardened source."""
    if patched:
        cls = remediation.load_patched_agent_class()
        return cls(llm=llm, model=TARGET_M, mock=not llm.live), "OrbitOps (patched: generated hardening applied)"
    return DevOpsAgent(llm=llm, model=TARGET_M, hardened=hardened, mock=not llm.live), "OrbitOps (demo DevOps bot)"


def run_once(hardened, patched=False, write_patches=True):
    """Run one session under a LangSmith span; return (results, report, paths)."""
    target, label = make_target(hardened, patched)
    with tracing.span("RedCell run", "chain",
                      inputs={"target": label, "hardened": hardened or patched,
                              "patched": patched, "brain": mode, "goals": active_goal_ids, "max_turns": a.turns}) as run_span:
        intel = tavily_intel.gather([GOALS[g] for g in active_goal_ids], emit=show)
        if isinstance(brain, LiveBrain):
            brain.intel = intel
        try:
            res = run_session(target, brain, active_goal_ids, max_turns=a.turns, emit=show)
        except BaseException:
            print(f"\nrun aborted | ${llm.ledger.cost_usd:.4f} spent over {llm.ledger.calls} calls")
            raise
        rep = report.build(res, llm.ledger.snapshot(), target_name=label,
                           hardened=hardened or patched, mode=mode, intel=intel, garak=garak_baseline.load(),
                           patches_dir=PATCHES if write_patches else None)
        run_span.end(outputs={"goals_broken": rep["goals_broken"], "goals_tried": rep["goals_tried"]},
                     metadata={"cost_usd": rep["usage"]["cost_usd"], "model_calls": rep["usage"]["calls"]})
        if run_span.url():
            print(f"LangSmith trace: {run_span.url()}")
        elif run_span.trace_id():
            print(f"LangSmith trace id: {run_span.trace_id()} (project {os.environ.get('LANGSMITH_PROJECT', 'default')})")
    paths = report.save(rep, REPORTS)
    return res, rep, paths


def _cell(fmap, gid, held_label):
    f = fmap.get(gid)
    return f"Broken (turn {f['turns_to_break']})" if f else held_label


def print_compare(weak_rep, hard_rep, patched_rep=None):
    wf = {f["id"]: f for f in weak_rep["findings"]}
    hf = {f["id"]: f for f in hard_rep["findings"]}
    pf = {f["id"]: f for f in patched_rep["findings"]} if patched_rep else {}
    has_patched = patched_rep is not None
    w = 46
    print("\n" + "=" * (w + 20 + 20 + (20 if has_patched else 0)))
    print("OWASP BENCHMARK - weak vs hardened" + (" vs patched" if has_patched else "") + " OrbitOps")
    print("=" * (w + 20 + 20 + (20 if has_patched else 0)))
    header = f"{'Goal':<{w}} {'Weak target':<20} {'Hardened target':<20}" + (f" {'Patched target':<20}" if has_patched else "")
    print(header)
    print("-" * len(header))
    for gid in active_goal_ids:
        title = GOALS[gid].title
        row = f"{title[:w]:<{w}} {_cell(wf, gid, 'Held'):<20} {_cell(hf, gid, 'Held (defended)'):<20}"
        if has_patched:
            row += f" {_cell(pf, gid, 'Held (patched)'):<20}"
        print(row)
    print("-" * len(header))
    tot = f"{'Total breach score':<{w}} " \
          f"{str(weak_rep['goals_broken']) + '/' + str(weak_rep['goals_tried']) + ' broken':<20} " \
          f"{str(hard_rep['goals_broken']) + '/' + str(hard_rep['goals_tried']) + ' broken':<20}"
    if has_patched:
        tot += f" {str(patched_rep['goals_broken']) + '/' + str(patched_rep['goals_tried']) + ' broken':<20}"
    print(tot)
    if weak_rep.get("patches"):
        p = weak_rep["patches"]
        print(f"\nRemediation: one applyable patch -> {p['patch']} "
              f"({'git apply clean' if p['applies'] else 'review required'}).")
    costs = f"Cost: weak ${weak_rep['usage']['cost_usd']:.4f} | hardened ${hard_rep['usage']['cost_usd']:.4f}"
    if has_patched:
        costs += f" | patched ${patched_rep['usage']['cost_usd']:.4f}"
    print(costs)


def print_patch_summary(rep):
    if rep.get("patches"):
        p = rep["patches"]
        print(f"\nRemediation patch: {p['patch']} "
              f"({'git apply clean' if p['applies'] else 'review required'}). "
              f"Hardened source: {p['hardened_file']}.")


print(f"RedCell | brain: {mode} | goals: {len(active_goal_ids)}")
try:
    if a.compare:
        _, weak_rep, _ = run_once(hardened=False, write_patches=True)
        _, hard_rep, _ = run_once(hardened=True, write_patches=False)
        if a.patched:
            _, patched_rep, _ = run_once(hardened=False, patched=True, write_patches=False)
            print_compare(weak_rep, hard_rep, patched_rep)
        else:
            print_compare(weak_rep, hard_rep)
    elif a.patched:
        print("\nTesting PATCHED target (generated hardening applied)...")
        _, rep, paths = run_once(hardened=False, patched=True)
        print(f"\n{rep['goals_broken']}/{rep['goals_tried']} goals broken | ${rep['usage']['cost_usd']:.4f} spent | "
              f"report: {paths['md']} | sarif: {paths['sarif']}")
        print_patch_summary(rep)
    else:
        res, rep, paths = run_once(hardened=a.hardened)
        print(f"\n{rep['goals_broken']}/{rep['goals_tried']} goals broken | ${rep['usage']['cost_usd']:.4f} spent | "
              f"report: {paths['md']} | sarif: {paths['sarif']}")
        print_patch_summary(rep)
except BaseException:
    raise
tracing.flush()
