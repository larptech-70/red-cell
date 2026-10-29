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


def test_sarif_validates_against_schema():
    """Full SARIF 2.1.0 schema validation (vendored OASIS schema) plus the fields GitHub code scanning needs."""
    import json
    from redcell.core.session import MockBrain, run_session
    from redcell.core.llm import Ledger
    from redcell.reporting import report
    from redcell.target.devops_agent import DevOpsAgent
    res = run_session(DevOpsAgent(mock=True), MockBrain(), ["secret_leak", "tool_misuse"])
    doc = to_sarif(report.build(res, Ledger().snapshot(), target_name="t", hardened=False, mode="mock"))
    schema = json.load(open(os.path.join(os.path.dirname(__file__), "data", "sarif-schema-2.1.0.json"), encoding="utf-8"))
    try:
        import jsonschema
    except ImportError:
        jsonschema = None
    if jsonschema:
        jsonschema.validate(doc, schema)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["informationUri"] == "https://github.com/larptech-70/red-cell"
    end = run["invocations"][0]["endTimeUtc"]
    assert len(end) == 20 and end[10] == "T" and end.endswith("Z")
    assert len(run["results"]) == 2
    for r in run["results"]:
        loc = r["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] and loc["logicalLocations"][0]["name"] == "orbitops-demo"
        for tfl in r["codeFlows"][0]["threadFlows"][0]["locations"]:
            assert set(tfl) == {"executionOrder", "importance", "location"} and "step" not in tfl["location"]


def test_sarif_old_report_time_converted():
    end = to_sarif({"generated": "2026-10-29 10:00:00", "findings": []})["runs"][0]["invocations"][0]["endTimeUtc"]
    assert end.endswith("Z") and "T" in end
