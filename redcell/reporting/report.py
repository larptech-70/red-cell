"""Findings report: JSON for machines, Markdown and HTML for people, and SARIF for DevSecOps."""
from __future__ import annotations

import html
import json
import time

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
        "target": target_name,
        "target_hardened": hardened,
        "brain": mode,
        "goals_tried": len(results),
        "goals_broken": len(findings),
        "findings": findings,
        "held": [r.goal.title for r in results if not r.landed],
        "usage": usage,
        "garak": garak,
        "intel": {"ran": (intel or {}).get("ran", False), "sources": (intel or {}).get("sources", 0)},
    }
    rep["comparison"] = comparison_table(rep)
    return rep


def comparison_table(rep: dict) -> list[list[str]]:
    g = rep.get("garak")
    rows = [["", "garak (static probes)", "RedCell (adaptive)"]]
    if not g or not g.get("ran"):
        status = g.get("reason", "Not run yet") if g else "Not run yet"
        return rows + [["Status", status, f"{rep['goals_broken']} findings"]]
    rows.append(["Probe attempts / turns", str(g.get("attempts", 0)), str(rep["usage"].get("calls", 0))])
    rows.append(["Findings", str(g.get("findings", 0)), str(rep["goals_broken"])])
    rows.append(["Tool-misuse tested", "No (text only)", "Yes (shell log checked)"])
    rows.append(["Multi-turn attacks", "No", "Yes"])
    rows.append(["Fix per finding", "No", "Yes"])
    return rows


def to_markdown(rep: dict) -> str:
    out = [f"# RedCell report: {rep['target']}", "",
           f"Generated {rep['generated']} | brain: {rep['brain']} | hardened target: {rep['target_hardened']}", "",
           f"**{rep['goals_broken']} of {rep['goals_tried']} goals broken.**", ""]
    intel = rep.get("intel") or {}
    if intel.get("ran"):
        out += [f"Threat intel: informed by {intel['sources']} current defensive source(s) via Tavily.", ""]
    for f in rep["findings"]:
        out += [f"## {f['title']}", f"Risk: {f['owasp']}. Broke in {f['turns_to_break']} turn(s). Reproduced on a fresh target.", "",
                f"Evidence: {f['evidence']}", "", "Reproduce with these messages, in order:"]
        out += [f"{i}. {m}" for i, m in enumerate(f["repro"], 1)]
        out += ["", f"Fix: {f['fix']}"]
        if f.get("reference"):
            out += [f"Reference (Tavily intel): [{f['reference']['title']}]({f['reference']['url']})"]
        out += [""]
    if rep["held"]:
        out += ["## Held", *[f"- {h}" for h in rep["held"]], ""]
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
        f"<section><h2>{e(f['title'])}</h2><p>{e(f['owasp'])}. Broke in {f['turns_to_break']} turn(s).</p>"
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
