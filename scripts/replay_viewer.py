"""Terminal Attack Screencast Replayer for RedCell.

Loads recorded or live JSON reports and provides an interactive or automated
terminal walkthrough of the multi-turn adversarial exchange:
- Attacker prompt formulation and pretext escalation tactics
- Target agent replies and internal simulated shell tool executions
- Deterministic ground-truth verification and judge decisions
- Clean-room exploit replay verification status
- Actionable code remediation and live threat intelligence citations
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"


def box(title: str, text: str, color: str = CYAN, border_char: str = "─") -> str:
    lines = text.strip().splitlines()
    width = min(80, max(len(l) for l in lines + [title]) + 4) if lines else 40
    top = f"{color}┌─ {BOLD}{title}{RESET}{color} {border_char * max(0, width - len(title) - 4)}┐{RESET}"
    bottom = f"{color}└{border_char * (width - 1)}┘{RESET}"
    body = "\n".join(f"{color}│{RESET} {line:<{width - 3}} {color}│{RESET}" for line in lines)
    return f"{top}\n{body}\n{bottom}"


def render_banner(target: str, generated: str, mode: str, broken: int, tried: int):
    status_color = RED if broken > 0 else GREEN
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                     REDCELL ATTACK REPLAY VIEWER                           ║{RESET}")
    print(f"{BOLD}{CYAN}║    Multi-Turn Adversarial Screencast & Incident Investigation Tool         ║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f" Target: {BOLD}{target}{RESET}  |  Generated: {DIM}{generated}{RESET}  |  Mode: {CYAN}{mode}{RESET}")
    print(f" Result: {status_color}{BOLD}{broken} of {tried} Goals Broken{RESET}\n")


def replay_goal(goal_data: dict, finding_data: dict | None, auto: bool = False, delay: float = 1.0):
    title = goal_data.get("title", goal_data.get("goal", "Goal"))
    owasp = goal_data.get("owasp", "")
    landed = goal_data.get("landed", False)
    turns = goal_data.get("turns", [])

    status_tag = f"{RED}{BOLD}[COMPROMISED]{RESET}" if landed else f"{GREEN}{BOLD}[DEFENDED]{RESET}"
    print(f"\n{BOLD}{'='*80}{RESET}")
    print(f" {status_tag} {BOLD}{WHITE}{title}{RESET}  ({DIM}{owasp}{RESET})")
    print(f" Total Turns: {len(turns)}  |  Landed: {'Yes' if landed else 'No'}")
    print(f"{BOLD}{'='*80}{RESET}\n")

    for t in turns:
        n = t.get("n", 1)
        verdict = t.get("verdict", "blocked")
        v_color = RED if verdict == "landed" else (YELLOW if verdict == "partial" else GREEN)

        print(f"\n{BOLD}{MAGENTA}───▶ TURN {n} / {len(turns)} ───{RESET}")

        # 1. Attacker Box
        attack_text = t.get("attack", "").strip()
        print(f"\n{BOLD}{RED}[ATTACKER - Nemotron Ultra 550B]{RESET}")
        print(f"  {WHITE}{attack_text}{RESET}")

        # 2. Target Agent Box
        reply_text = t.get("reply", "").strip()
        tool_calls = t.get("tool_calls", [])
        print(f"\n{BOLD}{BLUE}[TARGET AGENT - OrbitOps]{RESET}")
        if tool_calls:
            print(f"  {CYAN}{BOLD}Tool Invocations Executed in Sandbox:{RESET}")
            for tc in tool_calls:
                risk = tc.get("risk", "unknown")
                r_color = RED if risk == "dangerous" else (GREEN if risk == "safe" else YELLOW)
                print(f"    {BOLD}${RESET} {tc.get('cmd', '')}  {r_color}[{risk.upper()}]{RESET}")
        print(f"  {DIM}Reply text:{RESET} \"{reply_text[:300]}{'...' if len(reply_text) > 300 else ''}\"")

        # 3. Judge Evaluation
        reason = t.get("reason", "")
        ev = t.get("evidence", "")
        print(f"\n{BOLD}{YELLOW}[EVALUATOR & GROUND TRUTH JUDGE]{RESET}")
        print(f"  Verdict: {v_color}{BOLD}{verdict.upper()}{RESET}")
        if reason:
            print(f"  Reason:  {DIM}{reason}{RESET}")
        if ev:
            print(f"  {RED}{BOLD}Fact Proof:{RESET} {WHITE}{ev}{RESET}")

        if not auto and sys.stdin.isatty():
            try:
                input(f"\n{DIM}[Press Enter for next turn...]{RESET}")
            except (KeyboardInterrupt, EOFError):
                print("\nReplay paused.")
                return
        elif auto and delay > 0:
            time.sleep(delay)

    # Goal Conclusion Summary
    if landed and finding_data:
        print(f"\n{BOLD}{GREEN}✓ Clean-Room Replay Verification:{RESET} {WHITE}100% REPRODUCED ON FRESH INSTANCE{RESET}")
        if finding_data.get("fix"):
            print(f"{BOLD}{CYAN}🛡️ Strategic Fix:{RESET} {finding_data['fix']}")
        if finding_data.get("reference"):
            ref = finding_data["reference"]
            print(f"{BOLD}{BLUE}🔗 Threat Intel Reference:{RESET} {ref.get('title', '')} ({ref.get('url', '')})")
    elif not landed:
        print(f"\n{BOLD}{GREEN}🛡️ Defenses Held:{RESET} Agent resisted all adversarial escalation attempts.")


def run_screencast(
    report_path: str | None = None,
    goal_filter: str | None = None,
    auto: bool = False,
    delay: float = 0.8,
):
    # Locate report file
    if not report_path:
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "reports", "report.json"),
            os.path.join(os.path.dirname(__file__), "..", "web", "last-live", "report.json"),
        ]
        for c in candidates:
            if os.path.exists(c):
                report_path = c
                break

    if not report_path or not os.path.exists(report_path):
        print(f"{RED}Error: Report file not found.{RESET} Run a scan first with: python scripts/run_demo.py", file=sys.stderr)
        return 1

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"{RED}Error parsing report JSON ({report_path}): {e}{RESET}", file=sys.stderr)
        return 1

    target = data.get("target", "Demo Target")
    generated = data.get("generated", "")
    mode = data.get("brain", "mock")
    broken = data.get("goals_broken", 0)
    tried = data.get("goals_tried", 0)
    transcript = data.get("transcript", [])
    findings_by_id = {f.get("id"): f for f in data.get("findings", [])}

    render_banner(target, generated, mode, broken, tried)

    if not transcript:
        print(f"{YELLOW}No transcript records found in report.{RESET}")
        return 0

    goals_to_replay = transcript
    if goal_filter:
        goals_to_replay = [g for g in transcript if g.get("goal") == goal_filter or goal_filter.lower() in g.get("title", "").lower()]
        if not goals_to_replay:
            print(f"{YELLOW}No goals matched filter: '{goal_filter}'{RESET}")
            return 1

    for idx, g in enumerate(goals_to_replay, 1):
        finding = findings_by_id.get(g.get("goal"))
        replay_goal(g, finding, auto=auto, delay=delay)
        if idx < len(goals_to_replay) and not auto and sys.stdin.isatty():
            try:
                input(f"\n{BOLD}{CYAN}=== Press Enter to view next goal ({idx+1}/{len(goals_to_replay)}) ==={RESET}")
            except (KeyboardInterrupt, EOFError):
                break

    print(f"\n{BOLD}{GREEN}✓ Replay screencast completed.{RESET}\n")
    return 0


def main():
    ap = argparse.ArgumentParser(description="RedCell Terminal Attack Screencast Replayer")
    ap.add_argument("--report", type=str, default=None, help="Path to report.json file")
    ap.add_argument("--goal", type=str, default=None, help="Filter playback to specific goal ID (e.g. secret_leak, tool_misuse)")
    ap.add_argument("--auto", action="store_true", help="Auto-advance through turns without waiting for Enter key")
    ap.add_argument("--delay", type=float, default=0.6, help="Delay in seconds between steps when --auto is set")
    args = ap.parse_args()

    sys.exit(run_screencast(
        report_path=args.report,
        goal_filter=args.goal,
        auto=args.auto,
        delay=args.delay,
    ))


if __name__ == "__main__":
    main()
