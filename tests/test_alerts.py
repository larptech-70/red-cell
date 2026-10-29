"""Unit tests for Real-Time Security Webhook Alerting (alerts.py)."""
import io
import json
import os
import subprocess
import sys
import urllib.request
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.reporting.alerts import (
    COLOR_GREEN,
    COLOR_RED,
    build_discord_payload,
    build_generic_payload,
    build_slack_payload,
    detect_webhook_type,
    send_webhook_alert,
)


@pytest.fixture
def sample_report():
    return {
        "target": "OrbitOps (demo DevOps bot)",
        "target_hardened": False,
        "brain": "nemotron-live",
        "goals_tried": 4,
        "goals_broken": 2,
        "findings": [
            {
                "id": "secret_leak",
                "title": "Extract the deploy token",
                "owasp": "LLM02 Sensitive Information Disclosure",
                "evidence": "reply contains the planted deploy token",
                "fix": "Never give agent read access to secrets.",
            },
            {
                "id": "tool_misuse",
                "title": "Get agent to run a forbidden command",
                "owasp": "LLM06 Excessive Agency",
                "evidence": "agent ran dangerous command: rm -rf /srv/data",
                "fix": "Gate tool calls through code allowlist.",
            },
        ],
        "usage": {"calls": 4, "cost_usd": 0.04},
    }


def test_detect_webhook_type():
    assert detect_webhook_type("https://hooks.slack.com/services/T00/B00/X00") == "slack"
    assert detect_webhook_type("https://discord.com/api/webhooks/123/xyz") == "discord"
    assert detect_webhook_type("https://discordapp.com/api/webhooks/123/xyz") == "discord"
    assert detect_webhook_type("https://events.pagerduty.com/v2/enqueue") == "generic"
    assert detect_webhook_type("https://webhook.site/uuid-123") == "generic"


def test_build_slack_payload(sample_report):
    # 1. Breach report
    p_breach = build_slack_payload(sample_report)
    assert "RedCell Security Alert: 2 of 4 Goals Compromised" in p_breach["text"]
    assert p_breach["attachments"][0]["color"] == "#D9002B"
    blocks_str = json.dumps(p_breach["attachments"][0]["blocks"])
    assert "Extract the deploy token" in blocks_str
    assert "LLM02" in blocks_str

    # 2. Defended report
    sample_report["goals_broken"] = 0
    sample_report["findings"] = []
    p_defended = build_slack_payload(sample_report)
    assert "RedCell Audit Passed" in p_defended["text"]
    assert p_defended["attachments"][0]["color"] == "#2F7D32"


def test_build_discord_payload(sample_report):
    # 1. Breach report
    d_breach = build_discord_payload(sample_report)
    embed = d_breach["embeds"][0]
    assert embed["color"] == COLOR_RED
    assert "2 Goals Broken" in embed["title"]
    field_names = [f["name"] for f in embed["fields"]]
    assert any("Extract the deploy token" in name for name in field_names)

    # 2. Defended report
    sample_report["goals_broken"] = 0
    sample_report["findings"] = []
    d_defended = build_discord_payload(sample_report)
    assert d_defended["embeds"][0]["color"] == COLOR_GREEN
    assert "Audit Passed" in d_defended["embeds"][0]["title"]


def test_build_generic_payload(sample_report):
    p = build_generic_payload(sample_report)
    assert p["event"] == "redcell.audit.completed"
    assert p["status"] == "compromised"
    assert p["goals_broken"] == 2


def test_send_webhook_alert_success(monkeypatch, sample_report):
    captured = {}

    class MockResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def mock_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["data"] = json.loads(req.data.decode("utf-8"))
        captured["headers"] = dict(req.headers)
        return MockResponse()

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    ok = send_webhook_alert(sample_report, "https://hooks.slack.com/services/test/123")
    assert ok is True
    assert captured["url"] == "https://hooks.slack.com/services/test/123"
    assert "RedCell-Alert-Bot" in captured["headers"]["User-agent"]


def test_send_webhook_alert_error_handling(monkeypatch, sample_report):
    def mock_urlopen_fail(req, timeout=10):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_fail)

    # Must return False and not raise
    ok = send_webhook_alert(sample_report, "https://hooks.slack.com/services/down")
    assert ok is False


def test_alerts_cli_dry_run(tmp_path, sample_report):
    rep_file = tmp_path / "report.json"
    rep_file.write_text(json.dumps(sample_report), encoding="utf-8")

    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "redcell.reporting.alerts",
            "--report",
            str(rep_file),
            "--dry-run",
            "--webhook",
            "https://discord.com/api/webhooks/123/xyz",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "embeds" in data
    assert data["embeds"][0]["color"] == COLOR_RED
