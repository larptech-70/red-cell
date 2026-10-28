"""Findings report: JSON for machines, Markdown and HTML for people."""
from __future__ import annotations

import html
import json
import time


def build(results, usage: dict, *, target_name: str, hardened: bool, mode: str, garak: dict | None = None) -> dict:
    findings = []
    for r in results:
        if not r.landed:
            continue
        w = r.winning_turn
        findings.append({
            "id": r.goal.id,
            "title": r.goal.title,
            "owasp": r.goal.owasp,
            "turns_to_break": w.n,
            "evidence": w.evidence,
            "repro": [t.attack for t in r.turns[: w.n]],
            "fix": r.goal.fix,
            "reproduced_on_fresh_target": True,
        })
    return {
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
    }


def comparison_table(rep: dict) -> list[list[str]]:
    g = rep.get("garak")
    rows = [["", "garak (static probes)", "RedCell (adaptive)"]]
    if not g:
        return rows + [["Status", "Not run yet", f"{rep['goals_broken']} findings"]]
    rows.append(["Findings", str(g.get("findings", 0)), str(rep["goals_broken"])])
    rows.append(["Tool-misuse tested", "No (text only)", "Yes (shell log checked)"])
    rows.append(["Multi-turn attacks", "No", "Yes"])
    rows.append(["Fix per finding", "No", "Yes"])
    return rows


def to_markdown(rep: dict) -> str:
    out = [f"# RedCell report: {rep['target']}", "",
           f"Generated {rep['generated']} | brain: {rep['brain']} | hardened target: {rep['target_hardened']}", "",
           f"**{rep['goals_broken']} of {rep['goals_tried']} goals broken.**", ""]
    for f in rep["findings"]:
        out += [f"## {f['title']}", f"Risk: {f['owasp']}. Broke in {f['turns_to_break']} turn(s). Reproduced on a fresh target.", "",
                f"Evidence: {f['evidence']}", "", "Reproduce with these messages, in order:"]
        out += [f"{i}. {m}" for i, m in enumerate(f["repro"], 1)]
        out += ["", f"Fix: {f['fix']}", ""]
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
        f"<p><b>Fix:</b> {e(f['fix'])}</p></section>" for f in rep["findings"])
    return (f"<!doctype html><meta charset=utf-8><title>RedCell report</title>"
            f"<body style='font:16px/1.5 system-ui;max-width:46rem;margin:2rem auto;padding:0 1rem'>"
            f"<h1>RedCell report: {e(rep['target'])}</h1><p>{rep['goals_broken']} of {rep['goals_tried']} goals broken.</p>{body}</body>")


def save(rep: dict, outdir: str = "reports") -> dict:
    import os
    os.makedirs(outdir, exist_ok=True)
    stem = f"{outdir}/report-hardened" if rep.get("target_hardened") else f"{outdir}/report"
    paths = {"json": f"{stem}.json", "md": f"{stem}.md", "html": f"{stem}.html"}
    open(paths["json"], "w").write(json.dumps(rep, indent=2))
    open(paths["md"], "w").write(to_markdown(rep))
    open(paths["html"], "w").write(to_html(rep))
    return paths
