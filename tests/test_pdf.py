"""PDF report (optional ReportLab) and the /report.pdf|.html routes: valid output, odd input, no crashes."""
import copy, json, os, sys, threading, urllib.error, urllib.request
from http.server import ThreadingHTTPServer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from redcell import server
from redcell.reporting import pdf, report

SNAP = os.path.join(os.path.dirname(__file__), "..", "web", "last-live")
WEAK = json.load(open(os.path.join(SNAP, "report.json"), encoding="utf-8"))
HARD = json.load(open(os.path.join(SNAP, "report-hardened.json"), encoding="utf-8"))
needs_reportlab = pytest.mark.skipif(not pdf.available(), reason="reportlab not installed (optional)")


def _valid(b: bytes):
    assert b.startswith(b"%PDF-") and b.rstrip().endswith(b"%%EOF") and len(b) > 1000


@needs_reportlab
def test_pdf_from_both_snapshots_has_the_right_content():
    for rep in (WEAK, HARD):
        _valid(pdf.to_pdf(rep))
    weak = pdf.to_pdf(WEAK, compress=False)
    assert b"forbidden command" in weak and b"Trigger a destructive" not in weak     # current title, by id
    assert b"10:04 UTC" in weak and b"replay verified" in weak
    hard = pdf.to_pdf(HARD, compress=False)
    assert b"0 confirmed findings" in hard and b"did not reproduce" in hard          # the dropped leak is reported


@needs_reportlab
def test_pdf_survives_hostile_and_huge_input():
    rep = copy.deepcopy(WEAK)
    nasty = "‑ “quoted” \U0001F600 中文 <b>unclosed & <script>alert(1)</script> \x00\x07\x1b " + "A" * 6000
    f = rep["findings"][0]
    f["evidence"], f["fix"], f["title"] = nasty, nasty, nasty
    f["repro"] = [nasty[:300] + str(i) for i in range(150)]          # forces many pages
    f["reference"] = {"title": nasty[:200], "url": "https://example.org/" + "x" * 500}
    rep["held"] = [nasty[:100]]
    _valid(pdf.to_pdf(rep))


@needs_reportlab
def test_pdf_with_minimal_report_fields():
    _valid(pdf.to_pdf({"target": "t", "findings": [], "held": [], "goals_broken": 0, "goals_tried": 0,
                       "brain": "mock", "target_hardened": False, "usage": {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}}))


def test_clean_makes_text_safe_for_the_pdf_fonts():
    out = pdf.clean("a‑b “q” \U0001F600 <x> & \x07")
    assert out == "a-b \"q\" ? &lt;x&gt; &amp;  "
    out.encode("cp1252")                                               # always drawable by the standard fonts


def test_html_report_is_print_ready_and_escaped():
    h = report.to_html(WEAK)
    assert "@media print" in h and "10:04 UTC" in h and "forbidden command" in h and "print()" not in h
    assert "print()" in report.to_html(WEAK, autoprint=True)
    rep = copy.deepcopy(WEAK); rep["findings"][0]["evidence"] = "<script>alert(1)</script>"
    assert "<script>alert(1)" not in report.to_html(rep)


# --- server routes ----------------------------------------------------------------------------

def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def _get(url):
    try:
        r = urllib.request.urlopen(url, timeout=10)
        return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


@needs_reportlab
def test_report_pdf_route_serves_a_download(monkeypatch):
    monkeypatch.setattr(server, "LAST_LIVE", {"weak": WEAK, "hardened": HARD})
    srv, base = _serve()
    for kind in ("weak", "hardened"):
        status, headers, body = _get(f"{base}/report.pdf?kind={kind}")
        assert status == 200 and headers["Content-Type"] == "application/pdf"
        assert f"redcell-report-{kind}-2026-10-29.pdf" in headers["Content-Disposition"]
        _valid(body)
    status, headers, body = _get(f"{base}/report.html?kind=hardened")
    assert status == 200 and b"0 confirmed findings" in body
    srv.shutdown()


def test_report_pdf_route_never_crashes(monkeypatch):
    monkeypatch.setattr(server, "LAST_LIVE", {"weak": WEAK})
    srv, base = _serve()
    monkeypatch.setattr(server.pdf_report, "available", lambda: False)           # reportlab missing
    status, _, body = _get(f"{base}/report.pdf?kind=weak")
    assert status == 501 and b"not installed" in body
    monkeypatch.setattr(server.pdf_report, "available", lambda: True)
    def boom(rep):
        raise RuntimeError("layout exploded")
    monkeypatch.setattr(server.pdf_report, "to_pdf", boom)                       # reportlab fails mid-build
    status, _, body = _get(f"{base}/report.pdf?kind=weak")
    assert status == 500 and b"Markdown report still works" in body
    assert _get(f"{base}/api/info")[0] == 200                                    # server still up
    monkeypatch.setattr(server, "LAST_LIVE", {})
    monkeypatch.setattr(server, "STATE", {"report": None})
    assert _get(f"{base}/report.pdf")[0] == 404                                  # nothing to export yet
    srv.shutdown()


def test_api_info_reports_pdf_support(monkeypatch):
    srv, base = _serve()
    monkeypatch.setattr(server.pdf_report, "available", lambda: False)
    assert json.loads(_get(f"{base}/api/info")[2])["pdf"] is False
    srv.shutdown()
