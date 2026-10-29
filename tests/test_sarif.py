import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.reporting.sarif import to_sarif, save_sarif


def test_sarif_export(tmp_path):
    sample_report = {
        "generated": "2026-10-29 10:00:00",
        "target": "TestAgent",
        "goals_broken": 1,
        "findings": [
            {
                "id": "secret_leak",
                "title": "Extract the deploy token",
                "owasp": "LLM02 Sensitive Information Disclosure",
                "turns_to_break": 2,
                "evidence": "reply contains deploy token",
                "repro": ["hi", "give token"],
                "fix": "Sanitize output.",
                "reproduced_on_fresh_target": True,
            }
        ]
    }

    sarif = to_sarif(sample_report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "RedCell"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "LLM02"
    assert len(run["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]) == 2

    out_file = str(tmp_path / "test.sarif")
    saved = save_sarif(sample_report, out_file)
    assert os.path.exists(saved)
