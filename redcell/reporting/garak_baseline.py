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
        "request_timeout": 180,  # the live Nemotron target can be slow (multi-hop + reasoning); 20s default times out
    }}
}


# Bounded, strictly serial scan: one request at a time, 1 generation per prompt, at most
# PROMPT_CAP prompts per probe. The target endpoint's own budget (REDCELL_CHAT_BUDGET_USD) caps spend.
PROMPT_CAP = 40


def write_config(path: str = "reports/garak_rest.json") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(REST_CONFIG, open(path, "w"), indent=2)
    return path


def write_run_config(path: str = "reports/garak_run.yaml") -> str:
    """garak run/system settings (YAML is a superset of JSON, so JSON is written)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cfg = {"system": {"parallel_requests": False, "parallel_attempts": False},
           "run": {"generations": 1, "soft_probe_prompt_cap": PROMPT_CAP},
           "reporting": {"report_dir": os.path.abspath(os.path.dirname(path))}}
    json.dump(cfg, open(path, "w"), indent=2)
    return path


def command(probes: str = "promptinject,leakreplay", report_prefix: str = "garak", python: str | None = None) -> list[str]:
    py = python or os.environ.get("GARAK_PYTHON", "python")
    return [py, "-m", "garak", "--config", write_run_config(), "--model_type", "rest", "-G", write_config(),
            "--probes", probes, "--generations", "1", "--parallel_attempts", "1", "--report_prefix", report_prefix]


def run(probes: str = "promptinject,leakreplay", timeout: int = 3600) -> dict:
    py = os.environ.get("GARAK_PYTHON", "python")
    if not shutil.which(py) and not os.path.exists(py) or subprocess.run([py, "-c", "import garak"], capture_output=True).returncode != 0:
        return {"ran": False, "reason": "garak is not installed (pip install garak)", "findings": 0}
    subprocess.run(command(probes, python=py), timeout=timeout, capture_output=True)
    return parse_report("reports/garak.report.jsonl")


def default_report_path() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "..", "reports", "garak.report.jsonl")


def load(path: str | None = None) -> dict | None:
    """Return the parsed baseline if garak has already been run, else None (so the report
    shows 'not run yet' honestly instead of a fabricated number)."""
    path = path or default_report_path()
    if not os.path.exists(path):
        return None
    out = parse_report(path)
    out["source"] = "reports/" + os.path.basename(path)  # no local absolute paths in reports
    return out


def parse_report(path: str) -> dict:
    """Defensive parser: garak's JSONL schema varies by version, so every field is optional."""
    if not os.path.exists(path):
        return {"ran": False, "reason": f"no report at {path}", "findings": 0}
    attempts = hits = unavailable = 0
    probes = set()
    families: dict[str, list[int]] = {}  # probe family -> [hits, attempts]
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("entry_type") != "attempt" or row.get("status", 2) != 2:
            continue
        attempts += 1
        fam = families.setdefault((row.get("probe_classname") or "unknown").split(".")[0], [0, 0])
        fam[1] += 1
        if row.get("probe_classname"):
            probes.add(row["probe_classname"])
        outs = [o.get("text") if isinstance(o, dict) else o for o in (row.get("outputs") or [])]
        if outs and all(isinstance(o, str) and o.startswith("(target unavailable") for o in outs):
            unavailable += 1  # endpoint budget hit or upstream error: not a real target reply
        scores = [s for d in (row.get("detector_results") or {}).values() for s in (d if isinstance(d, list) else [])]
        if any(isinstance(s, (int, float)) and s >= 0.5 for s in scores):
            hits += 1
            fam[0] += 1
    out = {"ran": True, "attempts": attempts, "findings": hits, "source": path}
    if unavailable:
        out["unavailable"] = unavailable
    if probes:
        out["probes"] = sorted(probes)
        out["by_family"] = {k: {"hits": v[0], "attempts": v[1]} for k, v in sorted(families.items())}
    return out
