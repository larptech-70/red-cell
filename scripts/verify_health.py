"""Pre-Flight Healthcheck Diagnostic Tool for RedCell.

Verifies end-to-end environment readiness:
1. Python runtime & dependencies (core + optional ReportLab, LangSmith, pytest)
2. Environment variables & API credentials (.env, Nebius, Tavily, LangSmith, Run Code)
3. Live API connectivity & latency checks
4. Simulated Shell (SimShell) isolation and canary integrity
5. Dashboard server availability
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.core import llm, tracing
from redcell.reporting import pdf
from redcell.target.simshell import SimShell


GREEN = "\033[92m"
RED = "\033[91m"
AMBER = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def check(title: str, ok: bool, detail: str = "", warn: bool = False) -> None:
    if ok:
        badge = f"{GREEN}[PASS]{RESET}"
    elif warn:
        badge = f"{AMBER}[WARN]{RESET}"
    else:
        badge = f"{RED}[FAIL]{RESET}"
    det_str = f" - {detail}" if detail else ""
    print(f"  {badge} {BOLD}{title}{RESET}{det_str}")


def header(title: str) -> None:
    print(f"\n{CYAN}{BOLD}=== {title} ==={RESET}")


def run_diagnostics():
    print(f"\n{BOLD}RedCell Pre-Flight Health Diagnostic{RESET}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

    # 1. Runtime & Dependencies
    header("1. Runtime & Optional Packages")
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    check(f"Python Version ({py_ver})", sys.version_info >= (3, 10), "Requires Python >= 3.10")

    # Optional reportlab
    has_pdf = pdf.available()
    check("ReportLab (PDF Generation)", has_pdf, "Installed and ready for PDF export" if has_pdf else "Not installed (pip install reportlab)", warn=not has_pdf)

    # Optional langsmith
    has_langsmith = tracing.enabled()
    check("LangSmith (Cloud Tracing)", has_langsmith, "Active and streaming" if has_langsmith else "Off or missing credentials (optional)", warn=not has_langsmith)

    # 2. Configuration & Credentials
    header("2. Environment Configuration")
    env_exists = os.path.exists(os.path.join(os.path.dirname(__file__), "..", ".env"))
    check(".env File Presence", env_exists, "Found repo .env" if env_exists else "No .env found (falling back to shell environment)", warn=not env_exists)

    nebius_key = os.environ.get("NEBIUS_API_KEY", "")
    has_nebius = bool(nebius_key and not nebius_key.startswith("your_"))
    check("Nebius Token Factory Key", has_nebius, "Live Nemotron model routing active" if has_nebius else "Offline mock brain mode", warn=not has_nebius)

    tavily_key = os.environ.get("TAVILY_API_KEY", "")
    has_tavily = bool(tavily_key and not tavily_key.startswith("your_"))
    check("Tavily Threat Intel Key", has_tavily, "Live search citations enabled" if has_tavily else "Offline threat intel fallback", warn=not has_tavily)

    run_code = os.environ.get("REDCELL_RUN_CODE", "")
    is_public = os.environ.get("REDCELL_PUBLIC") == "1"
    check("Judge Run Code Gate", bool(run_code), f"Code configured (public mode: {is_public})" if run_code else "No code configured", warn=not run_code)

    budget = float(os.environ.get("REDCELL_BUDGET_USD", "1.50"))
    check("Spend Budget Circuit Breaker", budget > 0, f"${budget:.2f} max USD per session")

    # 3. Live Connectivity
    header("3. API Connectivity & Latency")
    if has_nebius:
        t0 = time.time()
        base_url = os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
        models_url = base_url.rstrip("/") + "/models"
        try:
            req = urllib.request.Request(models_url, headers={"Authorization": f"Bearer {nebius_key}"})
            with urllib.request.urlopen(req, timeout=8) as res:
                ms = int((time.time() - t0) * 1000)
                check("Nebius Token Factory Ping", res.status == 200, f"HTTP {res.status} ({ms} ms)")
        except Exception as e:
            check("Nebius Token Factory Ping", False, str(e), warn=True)
    else:
        print("  - Nebius ping skipped (mock mode active)")

    if has_tavily:
        cache_file = os.path.join(os.path.dirname(__file__), "..", "reports", "intel.json")
        has_cache = os.path.exists(cache_file)
        check("Tavily Cache File", has_cache, "Local disk cache available" if has_cache else "No cache file found", warn=not has_cache)

    # 4. SimShell Sandbox Integrity
    header("4. SimShell Isolation & Canaries")
    sh = SimShell()
    res = sh.run("cat /etc/devops/.env")
    has_canary = "FLAG-DEPLOY-" in res
    check("Planted Canary Secrets", has_canary, "Canary tokens present in isolated memory")

    rm_res = sh.run("rm -rf /srv/data")
    check("Host Safety Sandbox", "(simulated)" in rm_res, "Zero execution on host machine verified")

    # 5. Local Server Status
    header("5. Local Dashboard Server")
    s = socket.socket()
    port = int(os.environ.get("PORT", "8765"))
    is_open = s.connect_ex(("127.0.0.1", port)) == 0
    s.close()
    check(f"Dashboard Server (127.0.0.1:{port})", is_open, "Server is listening" if is_open else "Not running (start with: python -m redcell.server)", warn=not is_open)

    print(f"\n{BOLD}Diagnostic check completed.{RESET}\n")


if __name__ == "__main__":
    run_diagnostics()

