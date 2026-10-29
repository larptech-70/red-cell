"""OASIS SARIF v2.1.0 Exporter for RedCell.

Translates RedCell findings into the Static Analysis Results Interchange Format (SARIF)
for native ingestion by GitHub Code Scanning, GitLab Security Dashboards, and DevSecOps gates.
"""
from __future__ import annotations

import json
import time
from typing import Any

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
REPO_URI = "https://github.com/larptech-70/red-cell"
# Where a finding "lives": the practice target's prompt + tool gate. GitHub code scanning needs a file location.
DEFAULT_TARGET_CONFIG = "redcell/target/devops_agent.py"
DEFAULT_TARGET_ID = "orbitops-demo"


def _utc(report_data: dict[str, Any]) -> str:
    """ISO 8601 UTC with a Z, as SARIF requires."""
    if report_data.get("generated_utc"):
        return report_data["generated_utc"]
    try:  # older reports carry only local "YYYY-MM-DD HH:MM:SS"
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.mktime(time.strptime(report_data["generated"], "%Y-%m-%d %H:%M:%S"))))
    except (KeyError, ValueError, OverflowError):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

OWASP_CWE_MAPPING = {
    "LLM01": {"cwe": "CWE-77", "name": "Prompt Injection / Command Injection"},
    "LLM02": {"cwe": "CWE-200", "name": "Information Disclosure / Secret Leakage"},
    "LLM03": {"cwe": "CWE-829", "name": "Inclusion of Functionality from Untrusted Sphere"},
    "LLM04": {"cwe": "CWE-471", "name": "Modification of Assumed-Immutable Data (Data Poisoning)"},
    "LLM05": {"cwe": "CWE-79", "name": "Improper Output Handling (Cross-Site Scripting)"},
    "LLM06": {"cwe": "CWE-863", "name": "Incorrect Authorization / Excessive Agency"},
    "LLM07": {"cwe": "CWE-200", "name": "Exposure of Sensitive Information (System Prompt Leakage)"},
    "LLM08": {"cwe": "CWE-285", "name": "Improper Authorization (Vector & Embedding Access)"},
    "LLM09": {"cwe": "CWE-345", "name": "Insufficient Verification of Data Authenticity"},
    "LLM10": {"cwe": "CWE-400", "name": "Uncontrolled Resource Consumption"},
}


def to_sarif(report_data: dict[str, Any]) -> dict[str, Any]:
    """Convert RedCell JSON report into valid SARIF v2.1.0 dictionary."""
    findings = report_data.get("findings", [])
    target_config = report_data.get("target_config", DEFAULT_TARGET_CONFIG)
    target_id = report_data.get("target_id", DEFAULT_TARGET_ID)
    from .report import goal_title  # titles from the current goal definitions, by id
    rules = []
    results = []

    seen_rules = set()
    for f in findings:
        owasp_raw = f.get("owasp", "LLM02")
        rule_key = owasp_raw.split()[0] if owasp_raw else "LLM02"
        cwe_info = OWASP_CWE_MAPPING.get(rule_key, {"cwe": "CWE-200", "name": "AI Security Weakness"})

        if rule_key not in seen_rules:
            seen_rules.add(rule_key)
            rules.append({
                "id": rule_key,
                "name": cwe_info["name"],
                "shortDescription": {"text": goal_title(f.get("id"), f.get("title", rule_key))},
                "fullDescription": {"text": f"{owasp_raw}: {cwe_info['name']}"},
                "help": {
                    "text": f"Remediation: {f.get('fix', '')}",
                    "markdown": f"### Remediation\n{f.get('fix', '')}\n\n**OWASP Risk:** {owasp_raw} ({cwe_info['cwe']})",
                },
                "properties": {
                    "tags": ["security", "ai-security", rule_key.lower(), cwe_info["cwe"].lower()],
                    "precision": "high",
                },
            })

        # Build execution flow representing the multi-turn exploit chain
        thread_flow_steps = []
        for idx, prompt_text in enumerate(f.get("repro", []), start=1):
            thread_flow_steps.append({
                "executionOrder": idx,
                "importance": "essential",
                "location": {"message": {"text": f"Turn {idx} Adversarial Prompt: {prompt_text}"}},
            })

        results.append({
            "ruleId": rule_key,
            "level": "error",
            "message": {
                "text": f"Vulnerability confirmed: {goal_title(f.get('id'), f.get('title'))}. Evidence: {f.get('evidence')}. Broke in {f.get('turns_to_break')} turn(s).",
            },
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": target_config}, "region": {"startLine": 1}},
                "logicalLocations": [{"name": target_id, "kind": "module"}],
            }],
            "codeFlows": [
                {
                    "message": {"text": "Multi-turn conversational attack trace"},
                    "threadFlows": [{"locations": thread_flow_steps}],
                }
            ],
            "properties": {
                "reproduced_on_fresh_target": f.get("reproduced_on_fresh_target", True),
                "turns_to_break": f.get("turns_to_break", 1),
            },
        })

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RedCell",
                        "organization": "RedCell Security",
                        "semanticVersion": "1.0.0",
                        "informationUri": REPO_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": _utc(report_data),
                    }
                ],
                "results": results,
            }
        ],
    }
    return sarif_doc


def save_sarif(report_data: dict[str, Any], filepath: str = "reports/report.sarif") -> str:
    """Save report as formatted SARIF JSON file."""
    doc = to_sarif(report_data)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return filepath
