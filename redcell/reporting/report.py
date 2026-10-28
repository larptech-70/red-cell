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
    }
    rep["comparison"] = comparison_table(rep)
    return rep


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
        f"<section style='margin-bottom:1.5rem;padding:1rem 1.25rem;background:#f8fafc;border-left:4px solid #d9002b;border-radius:6px;border:1px solid #e2e8f0;border-left-width:4px'>"
        f"<h2 style='margin:0 0 0.5rem;font-size:1.15rem'>{e(f['title'])}</h2>"
        f"<p style='color:#64748b;margin:0 0 0.5rem'><b>Risk:</b> {e(f['owasp'])} | <b>Broke in:</b> {f['turns_to_break']} turn(s)</p>"
        f"<p style='margin:0 0 0.5rem'><b>Evidence:</b> <code style='background:#f1f5f9;padding:2px 6px;border-radius:4px'>{e(f['evidence'])}</code></p>"
        f"<p style='margin:0 0 0.25rem'><b>Reproduction sequence:</b></p><ol style='margin:0 0 0.75rem;padding-left:1.5rem'>{''.join(f'<li>{e(m)}</li>' for m in f['repro'])}</ol>"
        f"<p style='color:#166534;margin:0'><b>Fix:</b> {e(f['fix'])}</p></section>" for f in rep["findings"])
    
    cmp_rows = "".join(f"<tr>{''.join(f'<td style=\"padding:8px 12px;border-bottom:1px solid #e2e8f0\">{e(c)}</td>' for c in row)}</tr>" for row in rep.get("comparison", []))
    cmp_html = (f"<h2 style='margin-top:2rem'>Baseline Comparison</h2>"
                f"<table style='width:100%;border-collapse:collapse;font-size:0.9rem;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden'>{cmp_rows}</table>") if cmp_rows else ""

    u = rep.get("usage", {})
    cost_line = f"<p style='color:#64748b'>{u.get('calls', 0)} model calls, {u.get('prompt_tokens', 0) + u.get('completion_tokens', 0)} tokens, ${u.get('cost_usd', 0):.4f} USD.</p>" if u else ""

    return (f"<!doctype html><meta charset=utf-8><title>RedCell report: {e(rep['target'])}</title>"
            f"<body style='font:16px/1.5 system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1.5rem;color:#0f172a'>"
            f"<h1 style='margin-bottom:0.25rem'>RedCell Report: {e(rep['target'])}</h1>"
            f"<p style='color:#64748b;margin-top:0'>Generated {e(rep.get('generated', ''))} | Brain: {e(rep.get('brain', ''))} | Hardened: {rep.get('target_hardened')}</p>"
            f"<p style='font-size:1.1rem'><b>{rep['goals_broken']} of {rep['goals_tried']} goals broken.</b></p>"
            f"{cost_line}{body}{cmp_html}</body>")


def save(rep: dict, outdir: str = "reports") -> dict:
    import os
    os.makedirs(outdir, exist_ok=True)
    stem = f"{outdir}/report-hardened" if rep.get("target_hardened") else f"{outdir}/report"
    paths = {"json": f"{stem}.json", "md": f"{stem}.md", "html": f"{stem}.html"}
    with open(paths["json"], "w", encoding="utf-8") as f:
        f.write(json.dumps(rep, indent=2))
    with open(paths["md"], "w", encoding="utf-8") as f:
        f.write(to_markdown(rep))
    with open(paths["html"], "w", encoding="utf-8") as f:
        f.write(to_html(rep))
    return paths
