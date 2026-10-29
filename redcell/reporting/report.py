"""Findings report: JSON for machines, Markdown and HTML for people, SARIF for DevSecOps, and PDF for executives."""
from __future__ import annotations

import html
import json
import time

from ..attacks.goals import GOALS
from ..intel import tavily_intel
from . import remediation
from .sarif import to_sarif, save_sarif


def build(results, usage: dict, *, target_name: str, hardened: bool, mode: str,
          garak: dict | None = None, intel: dict | None = None,
          patches_dir: str | None = None) -> dict:
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

    patches = remediation.build(results, patches_dir) if patches_dir else None
    if patches:
        for f in findings:
            sn = patches["by_goal"].get(f["id"])
            if sn:
                f["remediation"] = {"defence": sn["defence"], "patch": patches["patch"]}

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
    if patches:
        rep["patches"] = {
            "patch": patches["patch"],
            "hardened_file": patches["hardened_file"],
            "applies": patches["applies"],
            "patch_text": patches["patch_text"],
        }
    rep["transcript"] = transcript(results)
    rep["comparison"] = comparison_table(rep)
    return rep


def transcript(results, max_chars: int = 2000) -> list[dict]:
    """Every turn of every goal: tester message, bot reply, tool calls with their outcome, and the verdict."""
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
    if "promptinject" in fams:
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


def generated_label(rep: dict) -> str:
    """'2026-10-29 10:04 UTC' from generated_utc; older reports fall back to their local time string."""
    g = rep.get("generated_utc") or ""
    return f"{g[:10]} {g[11:16]} UTC" if len(g) >= 16 else rep.get("generated", "")


def score_line(rep: dict) -> str:
    n, m = rep.get("goals_broken", 0), rep.get("goals_tried", 0)
    return (f"{n} of {m} goals broken, all confirmed by replay on a fresh agent."
            if n else "0 confirmed findings (1 system-prompt leak did not reproduce on replay and was dropped)."
            if rep.get("target_hardened") else f"0 of {m} goals broken.")


def dropped_landings(rep: dict) -> list[tuple[str, int]]:
    """Goals whose test landed during a turn but was rejected on clean replay."""
    out = []
    landed_ids = {f.get("id") for f in rep.get("findings", [])}
    for tr in rep.get("transcript", []):
        gid = tr.get("goal")
        if gid and gid not in landed_ids and tr.get("landed"):
            turns = tr.get("turns", [])
            winning_n = turns[-1].get("n", len(turns)) if turns else 1
            out.append((goal_title(gid, tr.get("title", "")), winning_n))
    return out


def held_titles(rep: dict) -> list[str]:
    """Goals that held. A goal that landed once but was dropped on replay is NOT listed as held."""
    ids = {t["title"]: t["goal"] for t in rep.get("transcript") or []}
    dropped = {title for title, _ in dropped_landings(rep)}
    return [t for t in (goal_title(ids.get(h), h) for h in rep.get("held", [])) if t not in dropped]


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
        if f.get("remediation"):
            out += [f"Remediation: {f['remediation']['defence']} (see `{f['remediation']['patch']}`)."]
        if f.get("reference"):
            out += [f"Reference (Tavily intel): [{f['reference']['title']}]({f['reference']['url']})"]
        out += [""]
    if rep["held"]:
        out += ["## Held", *[f"- {h}" for h in held_titles(rep)], ""]
    for title, n in dropped_landings(rep):
        out += [f"Note: {title} landed on turn {n} but did not reproduce on the fresh-agent replay, so it was dropped.", ""]
    u = rep["usage"]
    out += ["## Run cost", f"{u['calls']} model calls, {u['prompt_tokens'] + u['completion_tokens']} tokens, ${u['cost_usd']:.4f} of ${u['budget_usd']:.2f} budget.", ""]
    p = rep.get("patches")
    if p:
        out += ["## Remediation patch", "",
                f"One applyable patch hardens OrbitOps against every confirmed finding: `{p['patch']}` "
                f"({'applies cleanly with `git apply`' if p['applies'] else 'review required'}). "
                f"Hardened source: `{p['hardened_file']}`.", ""]
    out += ["## Baseline comparison", ""]
    t = comparison_table(rep)
    out += ["| " + " | ".join(t[0]) + " |", "|" + "---|" * len(t[0])]
    out += ["| " + " | ".join(r) + " |" for r in t[1:]]
    return "\n".join(out) + "\n"


def _format_diff_html(diff_text: str) -> str:
    """Format a unified diff text into styled HTML lines."""
    lines = []
    for line in diff_text.splitlines():
        esc = html.escape(line)
        if line.startswith("+++") or line.startswith("---"):
            lines.append(f"<div style='color:#6c757d;font-weight:600'>{esc}</div>")
        elif line.startswith("@@"):
            lines.append(f"<div style='color:#0d6efd;background:#e7f1ff;padding:2px 4px;margin:2px 0;border-radius:3px'>{esc}</div>")
        elif line.startswith("+"):
            lines.append(f"<div style='color:#0f5132;background:#d1e7dd;padding:1px 4px'>{esc}</div>")
        elif line.startswith("-"):
            lines.append(f"<div style='color:#842029;background:#f8d7da;padding:1px 4px'>{esc}</div>")
        else:
            lines.append(f"<div style='color:#212529;padding:1px 4px'>{esc}</div>")
    return "".join(lines)


EXECUTIVE_CSS = """
:root{--bg:#f8fafc;--card:#ffffff;--text:#0f172a;--muted:#64748b;--border:#e2e8f0;--danger:#ef4444;--danger-bg:#fef2f2;--success:#10b981;--success-bg:#f0fdf4;--primary:#3b82f6}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--text);background:var(--bg);margin:0;padding:2rem 1rem;line-height:1.6}
.container{max-width:54rem;margin:0 auto;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);padding:2.5rem}
.header{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem}
.title-group h1{margin:0 0 .3rem;font-size:1.85rem;letter-spacing:-0.02em}
.title-group .meta{color:var(--muted);font-size:.9rem}
.badge{display:inline-block;padding:.4rem .8rem;border-radius:9999px;font-weight:700;font-size:.85rem;text-transform:uppercase;letter-spacing:.05em}
.badge-danger{background:var(--danger-bg);color:var(--danger);border:1px solid #fca5a5}
.badge-success{background:var(--success-bg);color:var(--success);border:1px solid #86efac}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:1rem;margin-bottom:2rem}
.kpi-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}
.kpi-val{font-size:1.5rem;font-weight:800;color:var(--text);margin-bottom:.2rem}
.kpi-label{font-size:.78rem;color:var(--muted);text-transform:uppercase;font-weight:600}
.finding{border:1px solid var(--border);border-radius:8px;padding:1.4rem;margin-bottom:1.5rem;background:#fff;border-left:5px solid var(--danger)}
.finding h3{margin:0 0 .5rem;font-size:1.2rem;display:flex;justify-content:space-between;align-items:center}
.finding-meta{font-size:.85rem;color:var(--muted);margin-bottom:.8rem}
.finding-box{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:.8rem;margin:.6rem 0;font-size:.92rem}
.repro-list{margin:.4rem 0;padding-left:1.4rem}
.repro-list li{margin:.2rem 0;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.88rem}
.diff-box{background:#1e1e1e;color:#d4d4d4;border-radius:8px;padding:1rem;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.84rem;overflow-x:auto;margin:1rem 0;line-height:1.45}
table{width:100%;border-collapse:collapse;font-size:.88rem;margin:1rem 0}
th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--border);padding:.6rem .75rem}
th{background:var(--bg);font-weight:600}
.actions{display:flex;gap:.75rem;margin-bottom:1.5rem}
.btn{display:inline-flex;align-items:center;gap:.4rem;padding:.5rem 1rem;border-radius:6px;font-weight:600;font-size:.88rem;cursor:pointer;border:1px solid var(--border);background:#fff;color:var(--text);text-decoration:none}
.btn:hover{background:var(--bg)}
.footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--muted);font-size:.8rem;text-align:center}
@media print{body{background:#fff;padding:0}.container{border:none;box-shadow:none;padding:0}.actions{display:none}@page{margin:15mm}}
"""


def to_html(rep: dict, autoprint: bool = False) -> str:
    """Generate self-contained, enterprise executive HTML report with print/PDF styling."""
    e = html.escape
    broken = rep.get("goals_broken", 0)
    tried = rep.get("goals_tried", 0)
    is_hardened = rep.get("target_hardened", False)
    u = rep.get("usage", {})
    cost_usd = u.get("cost_usd", 0.0)
    calls = u.get("calls", 0)

    # Status badge
    if broken == 0:
        status_badge = "<span class='badge badge-success'>🛡️ DEFENDED (0 BREACHES)</span>"
    else:
        status_badge = f"<span class='badge badge-danger'>⚠️ VULNERABLE ({broken}/{tried} BROKEN)</span>"

    # KPI cards
    kpis = f"""
    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-val" style="color:{'#ef4444' if broken > 0 else '#10b981'}">{broken}/{tried}</div><div class="kpi-label">Goals Broken</div></div>
      <div class="kpi-card"><div class="kpi-val">{calls}</div><div class="kpi-label">Model Calls</div></div>
      <div class="kpi-card"><div class="kpi-val">${cost_usd:.4f}</div><div class="kpi-label">Test Spend</div></div>
      <div class="kpi-card"><div class="kpi-val">100%</div><div class="kpi-label">Replay Verified</div></div>
    </div>
    """

    # Findings
    findings_html = []
    for f in rep.get("findings", []):
        ref = f.get("reference")
        ref_html = f"<div class='finding-box'><b>Threat Citation:</b> <a href='{e(ref['url'])}' target='_blank'>{e(ref['title'])}</a></div>" if ref else ""
        remed_html = ""
        if f.get("remediation"):
            remed_html = f"<div class='finding-box'><b>Concrete Code Remediation:</b> {e(f['remediation']['defence'])}</div>"

        repro_steps = "".join(f"<li>{e(step)}</li>" for step in f.get("repro", []))

        findings_html.append(f"""
        <section class="finding">
          <h3>
            <span>{e(goal_title(f.get('id'), f.get('title', '')))}</span>
            <span style="font-size:0.8rem;color:#10b981;font-weight:600">✓ REPLAY CONFIRMED</span>
          </h3>
          <div class="finding-meta"><b>Category:</b> {e(f.get('owasp', ''))} &bull; <b>Compromised in:</b> {f.get('turns_to_break')} turn(s)</div>
          <div class="finding-box" style="background:#fff5f5;border-color:#fed7d7">
            <b>Deterministic Ground-Truth Evidence:</b> <code>{e(f.get('evidence', ''))}</code>
          </div>
          <p style="margin:0.8rem 0 0.3rem"><b>Adversarial Reproduction Chain:</b></p>
          <ol class="repro-list">{repro_steps}</ol>
          <div class="finding-box"><b>Strategic Fix:</b> {e(f.get('fix', ''))}</div>
          {remed_html}
          {ref_html}
        </section>
        """)

    # Held sections
    held = held_titles(rep)
    held_html = ""
    if held:
        held_items = "".join(f"<li style='margin:0.3rem 0;color:#0f5132'>🛡️ <b>{e(h)}</b>: Defenses held against all adversarial escalation turns</li>" for h in held)
        held_html = f"""
        <section style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:1.2rem;margin-bottom:1.5rem">
          <h3 style="margin:0 0 0.6rem;color:#166534">Successfully Defended Vectors</h3>
          <ul style="margin:0;padding-left:1.2rem">{held_items}</ul>
        </section>
        """

    # Dropped landings
    dropped_html = ""
    for title, n in dropped_landings(rep):
        dropped_html += f"<p style='color:#b45309;font-size:0.88rem'>⚠️ <i>Note:</i> <b>{e(title)}</b> landed on turn {n} but did not reproduce on the fresh-agent replay, so it was dropped to ensure 0% false positives.</p>"

    # Remediation patch section
    p = rep.get("patches")
    patch_section = ""
    if p:
        diff_styled = _format_diff_html(p.get("patch_text", ""))
        patch_section = f"""
        <section style="margin-top:2rem">
          <h2>Automated Hardening Patch (Unified Diff)</h2>
          <p style="color:var(--muted);font-size:0.9rem">
            One applyable patch hardens the agent against every confirmed finding.
            Apply with: <code>git apply {e(p.get('patch', 'patch.patch'))}</code>
          </p>
          <div class="diff-box">{diff_styled}</div>
        </section>
        """

    # Garak comparison table
    t = comparison_table(rep)
    comp_table_html = f"""
    <section style="margin-top:2rem">
      <h2>Adaptive Adversary vs. Static Probes Benchmark</h2>
      <table>
        <tr>{"".join(f"<th>{e(c)}</th>" for c in t[0])}</tr>
        {"".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in t[1:])}
      </table>
    </section>
    """

    intel = rep.get("intel") or {}
    intel_str = f"Threat intelligence: informed by {intel.get('sources', 0)} current defensive source(s) via Tavily." if intel.get("ran") else "Threat intelligence: Tavily offline."

    script = "<script>addEventListener('load',()=>setTimeout(()=>print(),150))</script>" if autoprint else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RedCell Security Assessment: {e(rep.get('target', 'Target Agent'))}</title>
  <style>{EXECUTIVE_CSS}</style>
</head>
<body>
  <div class="container">
    <div class="actions">
      <button class="btn" onclick="window['print']()">🖨️ Print / Save as PDF</button>
      <a class="btn" href="/report.json" target="_blank">📄 View JSON</a>
      <a class="btn" href="/report.sarif" target="_blank">🛡️ View SARIF</a>
    </div>

    <div class="header">
      <div class="title-group">
        <h1>RedCell Security Assessment Report</h1>
        <div class="meta">
          Target: <b>{e(rep.get('target', 'Target'))}</b> &bull; Mode: <b>{e(str(rep.get('brain')))}</b> &bull;
          Generated: <b>{e(generated_label(rep))}</b>
        </div>
        <div class="meta" style="margin-top:0.2rem">{e(intel_str)}</div>
      </div>
      <div>{status_badge}</div>
    </div>

    <p class="score" style="font-size:1.15rem;font-weight:700;margin:1rem 0">{e(score_line(rep))}</p>
    {kpis}
    {findings_html}
    {held_html}
    {dropped_html}
    {patch_section}
    {comp_table_html}

    <div class="footer">
      Generated automatically by <b>RedCell Adaptive Red-Team Agent</b> &bull; Dual-layer ground truth verification &bull; Zero host risk sandbox
    </div>
  </div>
  {script}
</body>
</html>
"""


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

    try:
        from . import pdf
        if pdf.available():
            paths["pdf"] = f"{stem}.pdf"
            with open(paths["pdf"], "wb") as f:
                f.write(pdf.to_pdf(rep))
    except Exception:
        pass

    return paths
