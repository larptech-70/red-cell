"""PDF report via ReportLab (optional dependency: pip install reportlab).

Same content as the Markdown/HTML reports. If ReportLab is missing, available() is False and the dashboard
hides the PDF button; nothing else changes. Text is normalised to what the built-in PDF fonts can draw, so odd
characters in model output (non-breaking hyphens, emoji, control characters) can never break a build.
"""
from __future__ import annotations

import io
import re
import unicodedata

from .report import comparison_table, dropped_landings, generated_label, goal_title, held_titles, score_line

_PUNCT = {"‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "―": "-", "−": "-",
          "‘": "'", "’": "'", "‚": "'", "‛": "'", "“": '"', "”": '"', "„": '"',
          "…": "...", " ": " ", " ": " ", " ": " ", " ": " ", "​": "", "⁠": "",
          "•": "*", "·": "-", "→": "->", "←": "<-", "≤": "<=", "≥": ">=", "⛔": "[blocked]"}


def available() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:
        return False


def clean(text) -> str:
    """Plain text the standard PDF fonts can draw (cp1252), then escaped for ReportLab's Paragraph markup."""
    s = str(text if text is not None else "")
    s = "".join(_PUNCT.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", s)          # control characters
    s = s.encode("cp1252", "replace").decode("cp1252")        # anything else -> '?'
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_pdf(rep: dict, compress: bool = True) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    base = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13, alignment=TA_LEFT,
                          splitLongWords=1)
    small = ParagraphStyle("small", parent=base, fontSize=8.5, leading=11, textColor=colors.HexColor("#586174"))
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=17, leading=21, alignment=TA_LEFT, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=10, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=4)
    score = ParagraphStyle("score", parent=base, fontName="Helvetica-Bold", fontSize=12, leading=16, spaceBefore=6, spaceAfter=4)
    red, green, amber = colors.HexColor("#c8102e"), colors.HexColor("#1c7a3c"), colors.HexColor("#9a5800")
    P = lambda t, st=base: Paragraph(t, st)  # noqa: E731  (t is already cleaned/escaped)

    story = [P(f"RedCell report: {clean(rep.get('target', ''))}", h1),
             P(f"Generated {clean(generated_label(rep))} | brain: {clean(rep.get('brain'))} | hardened target: {clean(rep.get('target_hardened'))}", small)]
    story.append(P(clean(score_line(rep)), score))
    intel = rep.get("intel") or {}
    story.append(P(clean(f"Threat intel: informed by {intel.get('sources', 0)} current defensive source(s) via Tavily."
                         if intel.get("ran") else "Threat intel: none (Tavily offline).")))

    for f in rep.get("findings", []):
        steps = ListFlowable([ListItem(P(clean(m)), leftIndent=12) for m in f.get("repro", [])], bulletType="1", leftIndent=14)
        block = [P(f'<font color="#c8102e">&#9632;</font> {clean(goal_title(f.get("id"), f.get("title", "")))}', h3),
                 P(f"{clean(f.get('owasp', ''))} | broke in {clean(f.get('turns_to_break'))} turn(s) | "
                   f"<font color='#1c7a3c'>{'replay verified' if f.get('reproduced_on_fresh_target') else 'not replay verified'}</font>", small),
                 P(f"<b>Evidence:</b> {clean(f.get('evidence', ''))}"),
                 P("<b>Reproduce with these messages, in order:</b>"), steps,
                 P(f"<b>Fix:</b> {clean(f.get('fix', ''))}")]
        ref = f.get("reference")
        if ref and ref.get("url"):
            block.append(P(f"<b>Reference (Tavily intel):</b> {clean(ref.get('title') or ref['url'])}<br/>"
                           f"<font color='#3451d1'>{clean(ref['url'])}</font>", small))
        story += [Spacer(1, 4)] + block   # not KeepTogether: a very long finding must still split across pages

    held = held_titles(rep)
    if held:
        story += [P("Held", h2)] + [P(f"<font color='#1c7a3c'>Held:</font> {clean(h)}") for h in held]
    for title, n in dropped_landings(rep):
        story.append(P(f"<font color='#9a5800'>Note:</font> {clean(title)} landed on turn {n} but did not reproduce on the "
                       "fresh-agent replay, so it was dropped.", base))

    u = rep.get("usage") or {}
    story += [P("Run cost", h2),
              P(clean(f"{u.get('calls', 0)} model calls, {u.get('prompt_tokens', 0) + u.get('completion_tokens', 0)} tokens, "
                      f"${float(u.get('cost_usd', 0)):.4f} of ${float(u.get('budget_usd', 0)):.2f} budget."))]

    rows = comparison_table(rep)
    if rows:
        cell = ParagraphStyle("cell", parent=base, fontSize=8.5, leading=11)
        data = [[P(f"<b>{clean(c)}</b>" if i == 0 else clean(c), cell) for c in r] for i, r in enumerate(rows)]
        n = max(len(r) for r in rows)
        widths = [38 * mm] + [(A4[0] - 30 * mm - 38 * mm) / max(1, n - 1)] * (n - 1)
        table = Table([r + [P("", cell)] * (n - len(r)) for r in data], colWidths=widths, repeatRows=1)
        table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d6dbe3")),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f4"))]))
        story += [P("Baseline comparison", h2), table,
                  P("garak is single-turn and text-only; it cannot observe tool calls. A fair baseline, not a weak tool.", small)]

    story += [Spacer(1, 10), P("Everything was simulated: the bot's shell never runs real commands, and the secrets are "
                               "planted fake canaries.", small)]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#586174"))
        canvas.drawString(15 * mm, 10 * mm, f"RedCell report | {generated_label(rep)}".encode("cp1252", "replace").decode("cp1252"))
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=16 * mm,
                            title=f"RedCell report - {generated_label(rep)}", author="RedCell", pageCompression=1 if compress else 0)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
