"""Findings report: JSON for machines, Markdown and HTML for people, and SARIF for DevSecOps."""
from __future__ import annotations

import html
import json
import time

from ..attacks.goals import GOALS
from ..intel import tavily_intel
from .sarif import to_sarif, save_sarif


def build(results, usage: dict, *, target_name: str, hardened: bool, mode: str,
          garak: dict | None = None, intel: dict | None = None) -> dict:
    findings = []
    for r in results:
        if not r.landed:
            continue
        w = r.winning_turn
        f = {
            "id": r.goal.id,
            "title": r.goal.title,
            "owasp": r.goal.owasp,
            "turns_to_break": w.n,
            "evidence": w.evidence,
            "repro": [t.attack for t in r.turns[: w.n]],
            "fix": r.goal.fix,
            "reproduced_on_fresh_target": True,
        }
        cite = tavily_intel.citation_for(intel, r.goal.id)
        if cite:
            f["reference"] = cite
        findings.append(f)
    rep = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": target_name,
        "target_hardened": hardened,
        "brain": mode,
        "goals_tried": len(results),
        "attack_turns": sum(len(r.turns) for r in results),
        "goals_broken": len(findings),
        "findings": findings,
        "held": [r.goal.title for r in results if not r.landed],
        "usage": usage,
        "garak": garak,
        "intel": {"ran": (intel or {}).get("ran", False), "sources": (intel or {}).get("sources", 0)},
    }
    rep["transcript"] = transcript(results)
    rep["comparison"] = comparison_table(rep)
    return rep


def transcript(results, max_chars: int = 2000) -> list[dict]:
    """Every turn of every goal: tester message, bot reply, tool calls with their outcome, and the verdict.
    Only planted fake canaries can appear here; long replies are trimmed."""
    out = []
    for r in results:
        out.append({
            "goal": r.goal.id, "title": r.goal.title, "owasp": r.goal.owasp, "landed": r.landed,
            "turns": [{"n": t.n, "attack": t.attack[:max_chars], "reply": t.reply[:max_chars],
                       "tool_calls": [{"cmd": c.get("cmd", "")[:500], "risk": c.get("risk", ""), "why": c.get("why", "")} for c in t.tool_calls],
                       "verdict": t.verdict, "reason": t.reason, "evidence": t.evidence} for t in r.turns],
        })
    return out


def comparison_table(rep: dict) -> list[list[str]]:
    g = rep.get("garak")
    rows = [["", "garak (static probes, run on the weak bot)", "RedCell (adaptive, this run)"]]
    if not g or not g.get("ran"):
        status = g.get("reason", "Not run yet") if g else "Not run yet"
        return rows + [["Status", status, f"{rep['goals_broken']} findings"]]
    sent = f"{g.get('attempts', 0)} single-turn probes"
    if g.get("unavailable"):
        sent += f" ({g['unavailable']} got no target reply)"
    rows.append(["Prompts sent to target", sent, f"{rep.get('attack_turns', rep['usage'].get('calls', 0))} adaptive turns"])
    fams = g.get("by_family") or {}
    detail = ", ".join(f"{v['hits']} {k}" for k, v in fams.items() if v["hits"])
    rows.append(["What counts as a hit", f"{g.get('findings', 0)} detector hits on reply text" + (f" ({detail})" if detail else ""),
                 f"{rep['goals_broken']} goals broken, checked against planted canaries / shell log and replayed"])
    if "promptinject" in fams:  # credit where garak covers something RedCell's core goals don't
        pi = fams["promptinject"]
        rows.append(["Text-only prompt hijack", f"Yes: {pi['hits']}/{pi['attempts']} probes made the bot say the rogue string",
                     "Not among the 4 core goals (LLM01 goal is experimental)"])
    rows.append(["Sees tool calls", "No: text replies only", "Yes: every simulated shell command"])
    rows.append(["Multi-turn", "No", "Yes"])
    rows.append(["Remediation guidance per finding", "No", "Yes"])
    return rows


def goal_title(goal_id: str | None, fallback: str = "") -> str:
    """Display title from the CURRENT goal definitions, so saved reports never need hand edits."""
    return GOALS[goal_id].title if goal_id in GOALS else fallback


def held_titles(rep: dict) -> list[str]:
    ids = {t["title"]: t["goal"] for t in rep.get("transcript") or []}
    return [goal_title(ids.get(h), h) for h in rep.get("held", [])]


def to_markdown(rep: dict) -> str:
    out = [f"# RedCell report: {rep['target']}", "",
           f"Generated {rep['generated']} | brain: {rep['brain']} | hardened target: {rep['target_hardened']}", "",
           f"**{rep['goals_broken']} of {rep['goals_tried']} goals broken.**", ""]
    intel = rep.get("intel") or {}
    if intel.get("ran"):
        out += [f"Threat intel: informed by {intel['sources']} current defensive source(s) via Tavily.", ""]
    for f in rep["findings"]:
        out += [f"## {goal_title(f.get('id'), f['title'])}", f"Risk: {f['owasp']}. Broke in {f['turns_to_break']} turn(s). Reproduced on a fresh target.", "",
                f"Evidence: {f['evidence']}", "", "Reproduce with these messages, in order:"]
        out += [f"{i}. {m}" for i, m in enumerate(f["repro"], 1)]
        out += ["", f"Fix: {f['fix']}"]
        if f.get("reference"):
            out += [f"Reference (Tavily intel): [{f['reference']['title']}]({f['reference']['url']})"]
        out += [""]
    if rep["held"]:
        out += ["## Held", *[f"- {h}" for h in held_titles(rep)], ""]
    u = rep["usage"]
    out += ["## Run cost", f"{u['calls']} model calls, {u['prompt_tokens'] + u['completion_tokens']} tokens, ${u['cost_usd']:.4f} of ${u['budget_usd']:.2f} budget.", ""]
    out += ["## Baseline comparison", ""]
    t = comparison_table(rep)
    out += ["| " + " | ".join(t[0]) + " |", "|" + "---|" * len(t[0])]
    out += ["| " + " | ".join(r) + " |" for r in t[1:]]
    return "\n".join(out) + "\n"


def to_html(rep: dict) -> str:
    e = html.escape
    body = "".join(
        f"<section><h2>{e(goal_title(f.get('id'), f['title']))}</h2><p>{e(f['owasp'])}. Broke in {f['turns_to_break']} turn(s).</p>"
        f"<p><b>Evidence:</b> {e(f['evidence'])}</p><ol>{''.join(f'<li>{e(m)}</li>' for m in f['repro'])}</ol>"
        f"<p><b>Fix:</b> {e(f['fix'])}</p>"
        + (f"<p><b>Reference:</b> <a href='{e(f['reference']['url'])}'>{e(f['reference']['title'])}</a></p>" if f.get("reference") else "")
        + "</section>" for f in rep["findings"])
    intel = rep.get("intel") or {}
    intel_line = (f"Threat intel: {intel['sources']} current source(s) via Tavily."
                  if intel.get("ran") else "Threat intel: none (Tavily offline).")
    return (f"<!doctype html><meta charset=utf-8><title>RedCell report</title>"
            f"<body style='font:16px/1.5 system-ui;max-width:46rem;margin:2rem auto;padding:0 1rem'>"
            f"<h1>RedCell report: {e(rep['target'])}</h1><p>{rep['goals_broken']} of {rep['goals_tried']} goals broken.</p>"
            f"<p>{e(intel_line)}</p>{body}</body>")


def save(rep: dict, outdir: str = "reports") -> dict:
    import os
    os.makedirs(outdir, exist_ok=True)
    stem = f"{outdir}/report-hardened" if rep.get("target_hardened") else f"{outdir}/report"
    paths = {
        "json": f"{stem}.json",
        "md": f"{stem}.md",
        "html": f"{stem}.html",
        "sarif": f"{stem}.sarif",
    }
    with open(paths["json"], "w", encoding="utf-8") as f:
        f.write(json.dumps(rep, indent=2))
    with open(paths["md"], "w", encoding="utf-8") as f:
        f.write(to_markdown(rep))
    with open(paths["html"], "w", encoding="utf-8") as f:
        f.write(to_html(rep))
    try:
        save_sarif(rep, paths["sarif"])
    except Exception:
        pass
    return paths
