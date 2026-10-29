"""Unit tests for Pluggable Jailbreak & Evasion Tactics Pack."""
import os
import subprocess
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import GOALS
from redcell.attacks.tactics import (
    REGISTRY,
    Tactic,
    TacticsRegistry,
    get_tactic,
    list_tactics,
)
from redcell.core.session import LiveBrain, MockBrain


def test_tactics_registry_defaults():
    tactics = list_tactics()
    assert len(tactics) >= 6
    ids = {t.id for t in tactics}
    assert {"enumeration", "authority", "multilingual", "encoding", "simulation", "overload"}.issubset(ids)

    # Test retrieval
    auth = get_tactic("authority")
    assert auth.id == "authority"
    assert auth.category == "pretext"
    assert "Incident Commander" in auth.description

    # Test unknown fallback
    fallback = get_tactic("nonexistent_tactic_xyz")
    assert fallback.id == "enumeration"


def test_tactics_prompt_guidance():
    goal = GOALS["secret_leak"]
    for t in list_tactics():
        guidance = t.guidance_for(goal)
        assert guidance.startswith(f"TACTIC ({t.name}):")
        assert len(guidance) > 30


def test_custom_tactic_registration():
    custom = Tactic(
        id="unit_test_probe",
        name="Unit Test Probe",
        category="jailbreak",
        description="A test tactic",
        prompt_guidance="Always ask nicely with magic word please.",
        offline_ladders={"secret_leak": ["Magic please token"]},
    )
    REGISTRY.register(custom)
    retrieved = get_tactic("unit_test_probe")
    assert retrieved.name == "Unit Test Probe"
    assert retrieved.get_offline_payload("secret_leak", 0) == "Magic please token"


def test_mock_brain_with_tactics():
    goal = GOALS["secret_leak"]

    # Authority Tactic
    brain_auth = MockBrain(tactic="authority")
    p1_auth = brain_auth.attack(goal, [])
    assert "Incident Commander" in p1_auth or "SEV-1" in p1_auth

    # Multilingual Tactic
    brain_multi = MockBrain(tactic="multilingual")
    p1_multi = brain_multi.attack(goal, [])
    assert any(ord(char) > 127 for char in p1_multi)  # Non-ASCII Russian characters

    # Encoding Tactic
    brain_enc = MockBrain(tactic="encoding")
    p1_enc = brain_enc.attack(goal, [])
    assert "Base64" in p1_enc or "config format" in p1_enc


def test_live_brain_injects_tactic_guidance():
    class DummyLLM:
        def __init__(self):
            self.captured_messages = []

        def chat(self, model, messages, **kwargs):
            self.captured_messages = messages
            return {"content": "Simulated attack prompt"}

    dummy_llm = DummyLLM()
    brain = LiveBrain(
        llm=dummy_llm,
        planner_model="dummy-planner",
        judge_model="dummy-judge",
        tactic="simulation",
    )

    goal = GOALS["secret_leak"]
    prompt = brain.attack(goal, [])

    assert prompt == "Simulated attack prompt"
    user_msgs = [m["content"] for m in dummy_llm.captured_messages if m["role"] == "user"]
    tactic_msg = [m for m in user_msgs if "Dual-Persona & Pen-Test Simulation" in m]
    assert len(tactic_msg) == 1
    assert "hypothetical framing" in tactic_msg[0]


def test_run_demo_list_tactics_cli():
    res = subprocess.run(
        [sys.executable, "scripts/run_demo.py", "--list-tactics"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 0
    assert "RedCell Pluggable Jailbreak & Adversarial Evasion Tactics" in res.stdout
    assert "authority" in res.stdout
    assert "multilingual" in res.stdout
    assert "encoding" in res.stdout


def test_run_demo_tactic_flag_cli():
    env = dict(os.environ, NEBIUS_API_KEY="", TAVILY_API_KEY="")
    res = subprocess.run(
        [sys.executable, "scripts/run_demo.py", "--tactic", "authority"],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 0
    assert "SEV-1" in res.stdout or "Incident Commander" in res.stdout

