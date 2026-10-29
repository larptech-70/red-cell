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
    """Goals that held. A goal that landed once but was dropped on replay is NOT listed as held (see dropped_landings)."""
    ids = {t["title"]: t["goal"] for t in rep.get("transcript") or []}
    dropped = {title for title, _ in dropped_landings(rep)}
    return [t for t in (goal_title(ids.get(h), h) for h in rep.get("held", [])) if t not in dropped]


def score_line(rep: dict) -> str:
    n, m = rep.get("goals_broken", 0), rep.get("goals_tried", 0)
    return f"{n} of {m} goals broken, all confirmed by replay on a fresh agent." if n else "0 confirmed findings."


def generated_label(rep: dict) -> str:
    """'2026-10-29 10:04 UTC' from generated_utc; older reports fall back to their local time string."""
    g = rep.get("generated_utc") or ""
    return f"{g[:10]} {g[11:16]} UTC" if len(g) >= 16 else rep.get("generated", "")


def dropped_landings(rep: dict) -> list[tuple[str, int]]:
    """Goals that landed on some turn but did not reproduce on the fresh-agent replay (so no finding)."""
    found = {f["id"] for f in rep.get("findings", [])}
    out = []
    for t in rep.get("transcript") or []:
        hit = next((x for x in t["turns"] if x["verdict"] == "landed"), None)
        if hit and t["goal"] not in found:
            out.append((goal_title(t["goal"], t["title"]), hit["n"]))
    return out


def to_markdown(rep: dict) -> str:
    out = [f"# RedCell report: {rep['target']}", "",
           f"Generated {generated_label(rep)} | brain: {rep['brain']} | hardened target: {rep['target_hardened']}", "",
           f"**{score_line(rep)}**", ""]
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
    for title, n in dropped_landings(rep):
        out += [f"Note: {title} landed on turn {n} but did not reproduce on the fresh-agent replay, so it was dropped.", ""]
    u = rep["usage"]
    out += ["## Run cost", f"{u['calls']} model calls, {u['prompt_tokens'] + u['completion_tokens']} tokens, ${u['cost_usd']:.4f} of ${u['budget_usd']:.2f} budget.", ""]
    out += ["## Baseline comparison", ""]
    t = comparison_table(rep)
    out += ["| " + " | ".join(t[0]) + " |", "|" + "---|" * len(t[0])]
    out += ["| " + " | ".join(r) + " |" for r in t[1:]]
    return "\n".join(out) + "\n"


PRINT_CSS = """
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#121826;max-width:48rem;margin:2rem auto;padding:0 1rem}
h1{font-size:1.6rem;margin:0 0 .2rem} h2{font-size:1.15rem;margin:1.6rem 0 .4rem;border-bottom:1px solid #d6dbe3;padding-bottom:.2rem}
.meta{color:#586174;font-size:.9rem} .score{font-size:1.25rem;font-weight:700;margin:.8rem 0}
.finding{border-left:4px solid #c8102e;padding:.1rem 0 .1rem .9rem;margin:1rem 0;break-inside:avoid}
.finding h3{margin:.2rem 0;font-size:1.05rem} .ok{color:#1c7a3c;font-weight:600} .note{color:#9a5800}
ol{padding-left:1.4rem} li{margin:.15rem 0} code,.cmd{font-family:ui-monospace,Consolas,monospace;font-size:.88em}
table{width:100%;border-collapse:collapse;font-size:.88rem;margin-top:.4rem} th,td{text-align:left;vertical-align:top;border-bottom:1px solid #d6dbe3;padding:.35rem .4rem}
.foot{margin-top:2rem;color:#586174;font-size:.82rem}
@page{margin:16mm 14mm} @media print{body{margin:0;max-width:none}a{color:inherit}a[href]::after{content:" (" attr(href) ")";font-size:.8em;color:#586174;word-break:break-all}.noprint{display:none}}
"""


def to_html(rep: dict, autoprint: bool = False) -> str:
    """Self-contained, print-ready report (the browser's "Save as PDF" turns it into a PDF).
    With autoprint, the print dialog opens as soon as the page loads."""
    e = html.escape
    parts = [f"<h1>RedCell report: {e(rep['target'])}</h1>",
             f"<p class=meta>Generated {e(generated_label(rep))} &middot; brain: {e(str(rep['brain']))} &middot; "
             f"hardened target: {e(str(rep['target_hardened']))}</p>",
             f"<p class=score>{e(score_line(rep))}</p>"]
    intel = rep.get("intel") or {}
    parts.append(f"<p>{'Threat intel: informed by ' + str(intel['sources']) + ' current defensive source(s) via Tavily.' if intel.get('ran') else 'Threat intel: none (Tavily offline).'}</p>")
    for f in rep["findings"]:
        ref = f.get("reference")
        parts.append(
            f"<section class=finding><h3>{e(goal_title(f.get('id'), f['title']))}</h3>"
            f"<p class=meta>{e(f['owasp'])} &middot; broke in {f['turns_to_break']} turn(s) &middot; "
            f"<span class=ok>{'replay verified' if f.get('reproduced_on_fresh_target') else 'not replay verified'}</span></p>"
            f"<p><b>Evidence:</b> {e(f['evidence'])}</p><p><b>Reproduce with these messages, in order:</b></p>"
            f"<ol>{''.join(f'<li>{e(m)}</li>' for m in f['repro'])}</ol><p><b>Fix:</b> {e(f['fix'])}</p>"
            + (f"<p><b>Reference (Tavily intel):</b> <a href='{e(ref['url'])}'>{e(ref['title'])}</a></p>" if ref else "")
            + "</section>")
    if rep["held"]:
        parts.append("<h2>Held</h2><ul>" + "".join(f"<li>{e(h)}</li>" for h in held_titles(rep)) + "</ul>")
    for title, n in dropped_landings(rep):
        parts.append(f"<p class=note>Note: {e(title)} landed on turn {n} but did not reproduce on the fresh-agent replay, so it was dropped.</p>")
    u = rep["usage"]
    parts.append(f"<h2>Run cost</h2><p>{u['calls']} model calls, {u['prompt_tokens'] + u['completion_tokens']} tokens, "
                 f"${u['cost_usd']:.4f} of ${u['budget_usd']:.2f} budget.</p>")
    t = comparison_table(rep)
    parts.append("<h2>Baseline comparison</h2><table><tr>" + "".join(f"<th>{e(c)}</th>" for c in t[0]) + "</tr>"
                 + "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in t[1:]) + "</table>"
                 + "<p class=meta>garak is single-turn and text-only; it cannot observe tool calls. A fair baseline, not a weak tool.</p>")
    parts.append("<p class=foot>Everything was simulated: the bot's shell never runs real commands, and the secrets are planted fake canaries.</p>")
    script = "<script>addEventListener('load',()=>setTimeout(()=>print(),150))</script>" if autoprint else ""
    return (f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>RedCell report - {e(rep['target'])} - {e(generated_label(rep))}</title><style>{PRINT_CSS}</style>"
            f"<body>{''.join(parts)}{script}</body></html>")


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
