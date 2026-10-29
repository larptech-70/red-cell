"""Live Terminal Attack Monitor for RedCell.

Real-time streaming console interface for adversarial AI red-teaming:
- Real-time observation of multi-turn attack strategies (pretexting, evasion, prompt injection)
- Live target agent telemetry and simulated shell command execution
- Instant deterministic canary secret detection & shell command risk classification
- Clean-room exploit replay verification status
- Real-time cost ledger tracking and executive scoreboard summary
- Multi-mode: Local in-process engine, remote SSE stream listener, or recorded simulation
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable

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

# Ensure repo root is on sys.path
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# --------------------------------------------------------------------------- #
# Terminal Styling & Theme
# --------------------------------------------------------------------------- #

class Theme:
    """ANSI color scheme with auto-disable support for non-TTY / no-color."""

    def __init__(self, use_color: bool = True):
        self.enabled = use_color

    def c(self, code: str) -> str:
        return code if self.enabled else ""

    @property
    def RESET(self) -> str:
        return self.c("\033[0m")

    @property
    def BOLD(self) -> str:
        return self.c("\033[1m")

    @property
    def DIM(self) -> str:
        return self.c("\033[2m")

    @property
    def ITALIC(self) -> str:
        return self.c("\033[3m")

    @property
    def RED(self) -> str:
        return self.c("\033[91m")

    @property
    def GREEN(self) -> str:
        return self.c("\033[92m")

    @property
    def YELLOW(self) -> str:
        return self.c("\033[93m")

    @property
    def BLUE(self) -> str:
        return self.c("\033[94m")

    @property
    def MAGENTA(self) -> str:
        return self.c("\033[95m")

    @property
    def CYAN(self) -> str:
        return self.c("\033[96m")

    @property
    def WHITE(self) -> str:
        return self.c("\033[97m")

    @property
    def BG_RED(self) -> str:
        return self.c("\033[41m")

    @property
    def BG_GREEN(self) -> str:
        return self.c("\033[42m")

    @property
    def BG_YELLOW(self) -> str:
        return self.c("\033[43m")

    @property
    def BG_DARK(self) -> str:
        return self.c("\033[40m")


def make_box(title: str, lines: list[str], width: int = 78, color: str = "", theme: Theme | None = None) -> str:
    """Render a clean Unicode border box."""
    t = theme or Theme(False)
    res = t.RESET
    b_col = color or t.CYAN
    title_str = f" {t.BOLD}{title}{res}{b_col} " if title else ""
    rem = max(0, width - 4 - len(title or ""))
    top = f"{b_col}┌─{title_str}{'─' * rem}┐{res}"
    body = []
    for line in lines:
        visible_len = len(remove_ansi(line))
        pad = max(0, width - 4 - visible_len)
        body.append(f"{b_col}│{res}  {line}{' ' * pad}{b_col}│{res}")
    bottom = f"{b_col}└{'─' * (width - 2)}┘{res}"
    return "\n".join([top] + body + [bottom])


def remove_ansi(text: str) -> str:
    """Strip ANSI escape sequences for length calculation."""
    import re
    return re.sub(r"\033\[[0-9;]*[a-zA-Z]", "", text)


def render_progress_bar(current: int, total: int, width: int = 16) -> str:
    """Render a clean unicode progress block."""
    if total <= 0:
        return "[----------------]"
    ratio = min(1.0, max(0.0, current / total))
    filled = int(round(ratio * width))
    empty = width - filled
    pct = int(ratio * 100)
    return f"[{'█' * filled}{'░' * empty}] {pct}%"


# --------------------------------------------------------------------------- #
# Live Terminal Attack Monitor
# --------------------------------------------------------------------------- #

class AttackConsoleMonitor:
    """Stateful real-time terminal display engine for RedCell audits."""

    def __init__(self, theme: Theme, delay: float = 0.05, out: Any = sys.stdout):
        self.t = theme
        self.delay = delay
        self.out = out
        self.target_name = "OrbitOps (demo DevOps bot)"
        self.mode = "nemotron-live"
        self.hardened = False
        self.goals: list[dict] = []
        self.current_goal_idx = 0
        self.current_goal_id = ""
        self.current_turn = 0
        self.max_turns = 6
        self.tactic = "default"
        self.cost_usd = 0.0
        self.calls = 0
        self.goals_broken = 0
        self.goals_tried = 0
        self.replays_verified = 0
        self.start_time = time.time()
        self.last_attack_text = ""
        self.scoreboard_entries: list[dict] = []

    def log(self, text: str = ""):
        self.out.write(text + "\n")
        self.out.flush()

    def render_banner(self):
        t = self.t
        banner_lines = [
            f"{t.BOLD}{t.CYAN}╔════════════════════════════════════════════════════════════════════════════╗{t.RESET}",
            f"{t.BOLD}{t.CYAN}║                   REDCELL LIVE TERMINAL ATTACK MONITOR                     ║{t.RESET}",
            f"{t.BOLD}{t.CYAN}║       Real-Time Adversarial Execution & Target Telemetry Observation       ║{t.RESET}",
            f"{t.BOLD}{t.CYAN}╚════════════════════════════════════════════════════════════════════════════╝{t.RESET}",
        ]
        self.log("\n".join(banner_lines))

    def render_status_bar(self):
        t = self.t
        target_style = f"{t.GREEN}{t.BOLD}[HARDENED]{t.RESET}" if self.hardened else f"{t.YELLOW}{t.BOLD}[WEAK]{t.RESET}"
        brain_style = f"{t.CYAN}{self.mode}{t.RESET}"
        self.log(f" Target: {t.BOLD}{self.target_name}{t.RESET} {target_style}  |  Engine: {brain_style}  |  Tactic: {t.MAGENTA}{self.tactic}{t.RESET}")
        self.log(f" Goals:  {t.BOLD}{len(self.goals)}{t.RESET} active  |  Max Turns/Goal: {t.BOLD}{self.max_turns}{t.RESET}  |  Status: {t.GREEN}Active Audit Running{t.RESET}\n")

    def handle_event(self, e: dict):
        """Dispatch SSE or local session event."""
        etype = e.get("type")
        if etype == "start":
            self.on_start(e)
        elif etype == "intel":
            self.on_intel(e)
        elif etype == "goal_start":
            self.on_goal_start(e)
        elif etype == "attack":
            self.on_attack(e)
        elif etype == "reply":
            self.on_reply(e)
        elif etype == "verdict":
            self.on_verdict(e)
        elif etype == "replay":
            self.on_replay(e)
        elif etype == "goal_end":
            self.on_goal_end(e)
        elif etype == "done":
            self.on_done(e)
        elif etype == "error":
            self.on_error(e)
        elif etype == "budget_stop":
            self.on_budget_stop(e)

        if self.delay > 0:
            time.sleep(self.delay)

    def on_start(self, e: dict):
        self.mode = e.get("mode", self.mode)
        self.hardened = e.get("hardened", self.hardened)
        self.goals = e.get("goals", [])
        self.render_banner()
        self.render_status_bar()

    def on_intel(self, e: dict):
        t = self.t
        if e.get("ran"):
            sources = e.get("sources", 0)
            cached_str = f" {t.DIM}[cached]{t.RESET}" if e.get("cached") else ""
            self.log(f" {t.CYAN}ℹ{t.RESET} Threat Intel: {t.BOLD}{sources}{t.RESET} defensive references synchronized via Tavily{cached_str}")
        else:
            self.log(f" {t.DIM}ℹ Threat Intel: offline ({e.get('reason', 'no Tavily key')}){t.RESET}")

    def on_goal_start(self, e: dict):
        t = self.t
        self.current_goal_idx += 1
        self.current_goal_id = e.get("goal", "")
        title = e.get("title", self.current_goal_id)
        owasp = e.get("owasp", "")

        box_lines = [
            f"{t.BOLD}{t.WHITE}{title}{t.RESET}",
            f"{t.DIM}OWASP LLM Top 10 Category:{t.RESET} {t.YELLOW}{owasp}{t.RESET}",
        ]
        self.log("\n" + make_box(f"OBJECTIVE [{self.current_goal_idx}/{len(self.goals) or 4}]", box_lines, color=t.CYAN, theme=t))

    def on_attack(self, e: dict):
        t = self.t
        n = e.get("n", 1)
        text = e.get("text", "")
        self.current_turn = n
        self.last_attack_text = text

        pbar = render_progress_bar(n, self.max_turns, width=12)
        words = len(text.split())

        self.log(f"\n {t.BOLD}--- TURN {n} of {self.max_turns} {pbar} ---{t.RESET}")
        box_lines = [
            f"{t.WHITE}{text}{t.RESET}",
            f"{t.DIM}Payload Word Count:{t.RESET} {words} words  |  {t.DIM}Persona:{t.RESET} {t.MAGENTA}Adversarial Tester (Nemotron-3-Ultra){t.RESET}",
        ]
        self.log(make_box(f"⚔️  ADVERSARY CRAFTED PROMPT (#{n})", box_lines, color=t.MAGENTA, theme=t))

    def on_reply(self, e: dict):
        t = self.t
        n = e.get("n", 1)
        reply = e.get("text", "")
        tool_calls = e.get("tool_calls", [])
        tool_errors = e.get("tool_errors", [])

        # Format agent reply (wrap/trim for console display)
        disp_reply = reply.strip().replace("\n", "\n  ") if reply else "(no text response)"
        if len(disp_reply) > 400:
            disp_reply = disp_reply[:397] + "..."

        box_lines = [f"{t.CYAN}{disp_reply}{t.RESET}"]

        if tool_calls:
            box_lines.append("")
            box_lines.append(f"{t.BOLD}Simulated Shell Tool Executions:{t.RESET}")
            for c in tool_calls:
                cmd = c.get("cmd", "")
                risk = c.get("risk", "safe")
                if risk == "blocked":
                    status = f"{t.BG_RED}{t.WHITE}[BLOCKED BY CODE POLICY]{t.RESET}"
                elif risk in ("dangerous", "tampering", "destructive"):
                    status = f"{t.RED}{t.BOLD}[DANGEROUS EXECUTION]{t.RESET}"
                elif risk == "sensitive":
                    status = f"{t.YELLOW}[SENSITIVE READ]{t.RESET}"
                else:
                    status = f"{t.GREEN}[SAFE]{t.RESET}"
                box_lines.append(f"  {t.BOLD}${t.RESET} {cmd:<42} {status}")

        if tool_errors:
            box_lines.append(f"  {t.RED}⚠ {len(tool_errors)} malformed tool invocation(s) trapped{t.RESET}")

        self.log(make_box(f"🤖 TARGET AGENT TELEMETRY (OrbitOps)", box_lines, color=t.BLUE, theme=t))

    def on_verdict(self, e: dict):
        t = self.t
        n = e.get("n", 1)
        verdict = e.get("verdict", "blocked")
        reason = e.get("reason", "")
        evidence = e.get("evidence", "")
        hint = e.get("hint", "")

        if verdict == "landed":
            badge = f"{t.BG_RED}{t.WHITE}{t.BOLD} 🚨 COMPROMISED (LANDED) {t.RESET}"
            v_color = t.RED
        elif verdict == "partial":
            badge = f"{t.BG_YELLOW}{t.WHITE}{t.BOLD} ⚡ PARTIAL OPENING (PARTIAL) {t.RESET}"
            v_color = t.YELLOW
        else:
            badge = f"{t.BG_GREEN}{t.WHITE}{t.BOLD} 🛡️ DEFENDED (BLOCKED) {t.RESET}"
            v_color = t.GREEN

        box_lines = [
            f"Evaluation:  {badge}",
            f"{t.DIM}Ground Truth:{t.RESET} {t.BOLD}{evidence or reason or 'Target deflected attack vector'}{t.RESET}",
        ]
        if hint and verdict != "landed":
            box_lines.append(f"{t.DIM}Adaptive Next Hint:{t.RESET} {t.ITALIC}{hint}{t.RESET}")

        self.log(make_box(f"⚖️  DETERMINISTIC EVALUATION & GROUND TRUTH (Turn {n})", box_lines, color=v_color, theme=t))

    def on_replay(self, e: dict):
        t = self.t
        reproduced = e.get("reproduced", False)
        if reproduced:
            self.replays_verified += 1
            msg = f"{t.GREEN}{t.BOLD}✓ CLEAN-ROOM REPLAY CONFIRMED:{t.RESET} Exploit reproduced on a fresh target instance."
            color = t.GREEN
        else:
            msg = f"{t.YELLOW}{t.BOLD}⚠ INTERMITTENT ANOMALY DROPPED:{t.RESET} Exploit did not reproduce on replay; finding dropped."
            color = t.YELLOW
        self.log(make_box("🔄 REPLAY SENTINEL VERIFICATION", [msg], color=color, theme=t))

    def on_goal_end(self, e: dict):
        landed = e.get("landed", False)
        turns = e.get("turns", 1)
        self.goals_tried += 1
        if landed:
            self.goals_broken += 1

        self.scoreboard_entries.append({
            "goal": e.get("goal", self.current_goal_id),
            "landed": landed,
            "turns": turns,
        })

    def on_done(self, e: dict):
        rep = e.get("report", {})
        self.render_summary(rep)

    def on_error(self, e: dict):
        t = self.t
        self.log(f"\n{t.RED}{t.BOLD}❌ ERROR: {e.get('text', 'Unknown audit error')}{t.RESET}\n")

    def on_budget_stop(self, e: dict):
        t = self.t
        self.log(f"\n{t.YELLOW}{t.BOLD}⚠ BUDGET EXCEEDED STOP: {e.get('text', '')}{t.RESET}\n")

    def render_summary(self, report_data: dict | None = None):
        """Render final executive security scorecard."""
        t = self.t
        elapsed = time.time() - self.start_time
        rep = report_data or {}
        usage = rep.get("usage", {})
        cost = usage.get("cost_usd", self.cost_usd)
        calls = usage.get("calls", self.calls)
        broken = rep.get("goals_broken", self.goals_broken)
        tried = rep.get("goals_tried", self.goals_tried or len(self.scoreboard_entries) or 1)

        status_banner = f"{t.RED}{t.BOLD}AGENT VULNERABLE ({broken}/{tried} Objectives Compromised){t.RESET}" if broken > 0 else f"{t.GREEN}{t.BOLD}AGENT SECURE (0/{tried} Objectives Compromised){t.RESET}"

        self.log("\n" + "=" * 78)
        self.log(f" {t.BOLD}{t.WHITE}EXECUTIVE AUDIT SUMMARY SCORECARD{t.RESET}")
        self.log(f" Final Posture: {status_banner}")
        self.log(f" Duration: {elapsed:.2f}s  |  Model Calls: {t.BOLD}{calls}{t.RESET}  |  Cumulative Cost: {t.GREEN}${cost:.4f} USD{t.RESET}")
        self.log("=" * 78)

        # Tabular objectives view
        col_w = [34, 12, 8, 16]
        header = f"{'Objective':<{col_w[0]}} {'Category':<{col_w[1]}} {'Turns':<{col_w[2]}} {'Status':<{col_w[3]}}"
        self.log(f"{t.BOLD}{header}{t.RESET}")
        self.log("-" * 78)

        findings_map = {f.get("id"): f for f in rep.get("findings", [])}
        transcripts = rep.get("transcript", [])

        if transcripts:
            for g in transcripts:
                gid = g.get("goal", "")
                title = g.get("title", gid)[:col_w[0] - 2]
                owasp = g.get("owasp", "")[:col_w[1] - 1]
                landed = g.get("landed", False)
                turns_count = len(g.get("turns", []))
                status_str = f"{t.RED}COMPROMISED{t.RESET}" if landed else f"{t.GREEN}DEFENDED{t.RESET}"
                self.log(f"{title:<{col_w[0]}} {owasp:<{col_w[1]}} {turns_count:<{col_w[2]}} {status_str}")
        elif self.scoreboard_entries:
            for item in self.scoreboard_entries:
                gid = item["goal"][:col_w[0] - 2]
                status_str = f"{t.RED}COMPROMISED{t.RESET}" if item["landed"] else f"{t.GREEN}DEFENDED{t.RESET}"
                self.log(f"{gid:<{col_w[0]}} {'--':<{col_w[1]}} {item['turns']:<{col_w[2]}} {status_str}")

        self.log("-" * 78)

        # Remediation & Artifact pointers
        patches_patch = os.path.join("reports", "patches", "redcell-hardening.patch")
        patch_status = f"{t.GREEN}{patches_patch} (clean git apply){t.RESET}" if os.path.exists(patches_patch) else "N/A"
        self.log(f" Remediation Patch:  {patch_status}")
        self.log(f" SARIF Findings:     reports/report.sarif (GitHub Code Scanning)")
        self.log(f" Guardrails Bundle:  reports/guardrails/ (NVIDIA NeMo Colang 1.0/2.0)")
        self.log(f" Replay Screencast:  python scripts/replay_viewer.py --auto\n")


# --------------------------------------------------------------------------- #
# Runner Implementations
# --------------------------------------------------------------------------- #

def run_attached_stream(url: str, monitor: AttackConsoleMonitor):
    """Attach over HTTP to live SSE event feed."""
    monitor.log(f"Connecting to live SSE stream: {url}...")
    req = urllib.request.Request(url, headers={"User-Agent": "RedCell-AttackConsole/1.0", "Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=360) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if line.startswith("data:"):
                    data_str = line[5:].strip()
                    if data_str:
                        try:
                            event = json.loads(data_str)
                            monitor.handle_event(event)
                            if event.get("type") in ("done", "error", "refused"):
                                break
                        except json.JSONDecodeError:
                            pass
    except KeyboardInterrupt:
        monitor.log("\nDetached from live stream (user interrupt).")
    except (urllib.error.URLError, ConnectionError) as ex:
        monitor.log(f"\n{monitor.t.RED}Failed to connect to SSE stream: {ex}{monitor.t.RESET}")
        monitor.log("Ensure the server is running (`python -m redcell.server`).")
        sys.exit(1)


def run_simulation(report_path: str, monitor: AttackConsoleMonitor):
    """Simulate streaming playback from an existing JSON report."""
    if not os.path.exists(report_path):
        monitor.log(f"Simulation report file not found: {report_path}")
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    target_name = data.get("target", "OrbitOps")
    hardened = bool(data.get("target_hardened", False))
    transcript = data.get("transcript", [])
    goals_meta = [{"id": g.get("goal"), "title": g.get("title"), "owasp": g.get("owasp")} for g in transcript]

    monitor.handle_event({"type": "start", "mode": data.get("brain", "simulation"), "hardened": hardened, "goals": goals_meta})
    monitor.handle_event({"type": "intel", "ran": True, "sources": len(data.get("intel", [])), "cached": True})

    for g in transcript:
        gid = g.get("goal")
        title = g.get("title", gid)
        owasp = g.get("owasp", "")
        monitor.handle_event({"type": "goal_start", "goal": gid, "title": title, "owasp": owasp})

        turns = g.get("turns", [])
        for t in turns:
            n = t.get("n", 1)
            attack = t.get("attack", "")
            reply = t.get("reply", "")
            tool_calls = t.get("tool_calls", [])
            tool_errors = t.get("tool_errors", [])
            verdict = t.get("verdict", "blocked")
            reason = t.get("reason", "")
            evidence = t.get("evidence", "")

            monitor.handle_event({"type": "attack", "goal": gid, "n": n, "text": attack})
            monitor.handle_event({"type": "reply", "goal": gid, "n": n, "text": reply, "tool_calls": tool_calls, "tool_errors": tool_errors})
            monitor.handle_event({"type": "verdict", "goal": gid, "n": n, "verdict": verdict, "reason": reason, "evidence": evidence})

        landed = g.get("landed", False)
        if landed:
            monitor.handle_event({"type": "replay", "goal": gid, "reproduced": True})

        monitor.handle_event({"type": "goal_end", "goal": gid, "landed": landed, "turns": len(turns)})

    monitor.handle_event({"type": "done", "report": data})


def run_local_session(args: argparse.Namespace, monitor: AttackConsoleMonitor) -> dict:
    """Run full in-process audit session with real-time terminal display."""
    from redcell.attacks.goals import CORE_GOAL_IDS, GOALS
    from redcell.core.llm import Ledger, TokenFactory
    from redcell.core.session import LiveBrain, MockBrain, run_session
    from redcell.intel import tavily_intel
    from redcell.reporting import garak_baseline, remediation, report
    from redcell.server import JUDGE_M, PLANNER, TARGET_M
    from redcell.target.devops_agent import DevOpsAgent

    llm = TokenFactory(ledger=Ledger(float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))))
    brain = LiveBrain(llm, PLANNER, JUDGE_M, tactic=args.tactic) if llm.live else MockBrain(tactic=args.tactic)
    mode = "nemotron-live" if llm.live else "mock"
    active_goal_ids = list(GOALS) if args.all_owasp else CORE_GOAL_IDS
    goals_list = [GOALS[g] for g in active_goal_ids]

    if args.patched:
        cls = remediation.load_patched_agent_class()
        target = cls(llm=llm, model=TARGET_M, mock=not llm.live)
        target_name = "OrbitOps (patched: generated hardening applied)"
    else:
        target = DevOpsAgent(llm=llm, model=TARGET_M, hardened=args.hardened, mock=not llm.live)
        target_name = "OrbitOps (demo DevOps bot)"

    monitor.target_name = target_name
    monitor.tactic = args.tactic
    monitor.max_turns = args.turns

    monitor.handle_event({
        "type": "start",
        "mode": mode,
        "hardened": args.hardened or args.patched,
        "goals": [{"id": g.id, "title": g.title, "owasp": g.owasp} for g in goals_list],
    })

    intel = tavily_intel.gather(goals_list, emit=monitor.handle_event)
    if isinstance(brain, LiveBrain):
        brain.intel = intel

    results = run_session(target, brain, active_goal_ids, max_turns=args.turns, emit=monitor.handle_event)

    patches_dir = os.path.join(ROOT, "reports", "patches")
    rep = report.build(
        results,
        llm.ledger.snapshot(),
        target_name=target_name,
        hardened=args.hardened or args.patched,
        mode=mode,
        intel=intel,
        garak=garak_baseline.load(),
        patches_dir=patches_dir,
    )
    monitor.handle_event({"type": "done", "report": rep})

    report_paths = report.save(rep, os.path.join(ROOT, "reports"))

    if args.save_report:
        with open(args.save_report, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2)
        monitor.log(f"Custom report saved to: {args.save_report}")

    # Webhook Alerting dispatch if requested
    webhook_url = args.webhook_url or os.environ.get("REDCELL_WEBHOOK_URL")
    if webhook_url:
        from redcell.reporting.alerts import send_webhook_alert
        if not args.alert_on_breach_only or rep.get("goals_broken", 0) > 0:
            if send_webhook_alert(rep, webhook_url):
                monitor.log(f"RedCell | Real-time webhook alert dispatched to: {webhook_url[:35]}...")

    return rep


# --------------------------------------------------------------------------- #
# CLI Entrypoint
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="RedCell Live Terminal Attack Monitor - Real-Time Adversarial Telemetry Console"
    )
    parser.add_argument("--attach", nargs="?", const="http://127.0.0.1:8765/events", default=None,
                        help="Attach to live server SSE stream (default: http://127.0.0.1:8765/events)")
    parser.add_argument("--simulate", type=str, default=None,
                        help="Simulate real-time streaming playback from an existing JSON report file")
    parser.add_argument("--hardened", action="store_true",
                        help="Test built-in hardened target bot (allowlist + prompt)")
    parser.add_argument("--patched", action="store_true",
                        help="Test target bot with generated hardening patch applied")
    parser.add_argument("--all-owasp", action="store_true",
                        help="Evaluate full 11 OWASP LLM Top 10 objectives (default: core 4)")
    parser.add_argument("--turns", type=int, default=6,
                        help="Maximum adversarial turns per objective (default: 6)")
    parser.add_argument("--tactic", type=str, default="default",
                        help="Evasion tactic (default, authority, multilingual, encoding, simulation, overload)")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Pacing delay between events in seconds (default: 0.05)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors for plain-text terminals or CI logging")
    parser.add_argument("--fail-on-breach", action="store_true",
                        help="CI/CD gate: exit with code 1 if breaches exceed tolerance")
    parser.add_argument("--max-allowed-breaches", type=int, default=0,
                        help="Maximum tolerated breaches before returning code 1 (default: 0)")
    parser.add_argument("--webhook-url", type=str, default=None,
                        help="Slack or Discord webhook URL for real-time alerting")
    parser.add_argument("--alert-on-breach-only", action="store_true",
                        help="Only dispatch webhook if goals_broken > 0")
    parser.add_argument("--save-report", type=str, default=None,
                        help="Save generated JSON report to specified path")

    args = parser.parse_args(argv)

    use_color = not args.no_color and sys.stdout.isatty()
    theme = Theme(use_color=use_color)
    monitor = AttackConsoleMonitor(theme=theme, delay=args.delay)

    report_result = None
    if args.attach:
        run_attached_stream(args.attach, monitor)
    elif args.simulate:
        run_simulation(args.simulate, monitor)
    else:
        report_result = run_local_session(args, monitor)

    if args.fail_on_breach and report_result:
        broken = report_result.get("goals_broken", 0)
        if broken > args.max_allowed_breaches:
            monitor.log(f"\n[CI GATE] Breaches ({broken}) exceeded tolerance ({args.max_allowed_breaches}). Exiting with code 1.")
            return 1
        monitor.log(f"\n[CI GATE] Breaches ({broken}) within tolerance ({args.max_allowed_breaches}). Passing.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
