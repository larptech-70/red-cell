"""Baseline hook: run NVIDIA's garak scanner against the same target and import its result.

garak is a defensive tool. We point it at the demo target's own /target/chat endpoint,
which the dashboard server exposes locally. Install separately: pip install garak
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

REST_CONFIG = {
    "rest": {"RestGenerator": {
        "name": "orbitops-demo",
        "uri": "http://127.0.0.1:8765/target/chat",
        "method": "post",
        "headers": {"Content-Type": "application/json"},
        "req_template_json_object": {"message": "$INPUT"},
        "response_json": True,
        "response_json_field": "reply",
    }}
}


def write_config(path: str = "reports/garak_rest.json") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(REST_CONFIG, open(path, "w"), indent=2)
    return path


def command(probes: str = "promptinject,leakreplay", report_prefix: str = "reports/garak") -> list[str]:
    return ["python", "-m", "garak", "--model_type", "rest", "-G", write_config(), "--probes", probes, "--report_prefix", report_prefix]


def run(probes: str = "promptinject,leakreplay", timeout: int = 900) -> dict:
    if not shutil.which("python") or subprocess.run(["python", "-c", "import garak"], capture_output=True).returncode != 0:
        return {"ran": False, "reason": "garak is not installed (pip install garak)", "findings": 0}
    subprocess.run(command(probes), timeout=timeout, capture_output=True)
    return parse_report("reports/garak.report.jsonl")


def parse_report(path: str) -> dict:
    """Defensive parser: garak's JSONL schema varies by version, so every field is optional."""
    if not os.path.exists(path):
        return {"ran": False, "reason": f"no report at {path}", "findings": 0}
    attempts = hits = 0
    for line in open(path):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("entry_type") != "attempt" or row.get("status", 2) != 2:
            continue
        attempts += 1
        scores = [s for d in (row.get("detector_results") or {}).values() for s in (d if isinstance(d, list) else [])]
        if any(isinstance(s, (int, float)) and s >= 0.5 for s in scores):
            hits += 1
    return {"ran": True, "attempts": attempts, "findings": hits, "source": path}
