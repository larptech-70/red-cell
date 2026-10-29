"""Unit tests for DevSecOps CI/CD security gate exit code enforcement."""
import os
import subprocess
import sys


def test_gate_passes_on_hardened_target():
    env = dict(os.environ, NEBIUS_API_KEY="", TAVILY_API_KEY="", LANGSMITH_TRACING="false")
    res = subprocess.run(
        [sys.executable, "scripts/run_demo.py", "--hardened", "--fail-on-breach"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "[CI/CD SECURITY GATE PASSED]" in res.stdout


def test_gate_fails_on_weak_target_with_flag():
    env = dict(os.environ, NEBIUS_API_KEY="", TAVILY_API_KEY="", LANGSMITH_TRACING="false")
    res = subprocess.run(
        [sys.executable, "scripts/run_demo.py", "--fail-on-breach"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "[CI/CD SECURITY GATE FAILED]" in res.stderr


def test_gate_tolerates_threshold():
    env = dict(os.environ, NEBIUS_API_KEY="", TAVILY_API_KEY="", LANGSMITH_TRACING="false")
    # Even if 4 goals break, threshold of 10 permits passing
    res = subprocess.run(
        [sys.executable, "scripts/run_demo.py", "--fail-on-breach", "--max-allowed-breaches", "10"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "[CI/CD SECURITY GATE PASSED]" in res.stdout


def test_default_does_not_fail_without_flag():
    env = dict(os.environ, NEBIUS_API_KEY="", TAVILY_API_KEY="", LANGSMITH_TRACING="false")
    res = subprocess.run(
        [sys.executable, "scripts/run_demo.py"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0

