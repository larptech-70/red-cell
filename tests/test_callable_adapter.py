"""Unit tests for Universal CallableTargetAdapter."""
import asyncio
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.adapters import CallableTargetAdapter
from redcell.attacks.goals import GOALS
from redcell.core.session import MockBrain, _run_goal, verify_replay
from redcell.target.simshell import CANARY_SECRET


def test_callable_simple_function():
    def agent(prompt: str) -> str:
        return f"Agent response to {prompt}"

    adapter = CallableTargetAdapter(agent, name="SimpleEchoBot")
    assert adapter.name == "SimpleEchoBot"
    assert adapter.health_check() is True

    turn = adapter.send("check status")
    assert turn["reply"] == "Agent response to check status"
    assert turn["tool_calls"] == []
    assert turn["tool_errors"] == []
    assert turn["latency_ms"] >= 0


def test_callable_dict_return_and_auto_classification():
    def tool_agent(prompt: str) -> dict:
        return {
            "output": "Simulated disk cleanup",
            "tool_calls": [
                {"cmd": "rm -rf /srv/data"},
                {"cmd": "df -h", "risk": "safe", "why": "whitelisted"},
            ],
        }

    adapter = CallableTargetAdapter(tool_agent)
    turn = adapter.send("clean disk")

    assert turn["reply"] == "Simulated disk cleanup"
    assert len(turn["tool_calls"]) == 2

    # Verify auto-classification of dangerous command
    dangerous_call = turn["tool_calls"][0]
    assert dangerous_call["cmd"] == "rm -rf /srv/data"
    assert dangerous_call["risk"] == "dangerous"

    # Verify pre-labeled safe call preserved
    safe_call = turn["tool_calls"][1]
    assert safe_call["cmd"] == "df -h"
    assert safe_call["risk"] == "safe"


def test_callable_object_methods():
    class ChatBot:
        def __init__(self):
            self.history = []

        def chat(self, prompt: str) -> str:
            self.history.append(prompt)
            return f"Chatted {len(self.history)} times"

    bot = ChatBot()
    adapter = CallableTargetAdapter(bot)

    turn1 = adapter.send("one")
    assert turn1["reply"] == "Chatted 1 times"

    turn2 = adapter.send("two")
    assert turn2["reply"] == "Chatted 2 times"


def test_callable_explicit_custom_method():
    class MultiMethodAgent:
        def query(self, prompt: str) -> str:
            return "From query"

        def special_act(self, prompt: str) -> str:
            return f"Special: {prompt}"

    agent = MultiMethodAgent()
    adapter = CallableTargetAdapter(agent, method="special_act")
    turn = adapter.send("hello")
    assert turn["reply"] == "Special: hello"


def test_callable_async_function():
    async def async_bot(prompt: str) -> str:
        await asyncio.sleep(0.01)
        return f"Async response: {prompt}"

    adapter = CallableTargetAdapter(async_bot)
    turn = adapter.send("ping")
    assert turn["reply"] == "Async response: ping"


def test_callable_generator_streaming():
    def stream_bot(prompt: str):
        yield "Streaming: "
        yield prompt
        yield " finished."

    adapter = CallableTargetAdapter(stream_bot)
    turn = adapter.send("work")
    assert turn["reply"] == "Streaming: work finished."


def test_callable_reset_mechanisms():
    reset_called = False

    def on_reset():
        nonlocal reset_called
        reset_called = True

    class StatefulAgent:
        def __init__(self):
            self.count = 0

        def reset(self):
            self.count = 0

        def run(self, prompt: str) -> str:
            self.count += 1
            return str(self.count)

    # 1. Custom reset_fn
    adapter_fn = CallableTargetAdapter(lambda p: "ok", reset_fn=on_reset)
    adapter_fn.reset()
    assert reset_called is True

    # 2. Target with .reset()
    stateful = StatefulAgent()
    adapter_obj = CallableTargetAdapter(stateful)
    adapter_obj.send("a")
    adapter_obj.send("b")
    assert stateful.count == 2
    adapter_obj.reset()
    assert stateful.count == 0

    # 3. Agent factory re-instantiation
    created = 0

    def make_agent():
        nonlocal created
        created += 1
        return StatefulAgent()

    adapter_factory = CallableTargetAdapter(agent_factory=make_agent)
    assert created == 1
    adapter_factory.reset()
    assert created == 2


def test_callable_manual_tool_recording():
    adapter = CallableTargetAdapter(lambda p: "I ran a check")

    # Simulate an external callback or tool runner recording a call
    adapter.record_tool_call("cat /var/log/syslog", tool="file_reader")
    turn = adapter.send("check logs")

    assert len(turn["tool_calls"]) == 1
    call = turn["tool_calls"][0]
    assert call["cmd"] == "cat /var/log/syslog"
    assert call["tool"] == "file_reader"
    assert call["risk"] == "safe"


def test_callable_object_tool_log_tracking():
    class AgentWithLog:
        def __init__(self):
            self.tool_log = []

        def __call__(self, prompt: str) -> str:
            if "delete" in prompt:
                self.tool_log.append({"cmd": "rm -rf /tmp/data"})
            return "Done"

    agent = AgentWithLog()
    adapter = CallableTargetAdapter(agent)

    # Turn 1: safe turn, no tools
    t1 = adapter.send("hello")
    assert t1["tool_calls"] == []

    # Turn 2: triggers tool call
    t2 = adapter.send("please delete")
    assert len(t2["tool_calls"]) == 1
    assert t2["tool_calls"][0]["cmd"] == "rm -rf /tmp/data"

    # Turn 3: safe turn, should not re-include turn 2 tool call
    t3 = adapter.send("status")
    assert t3["tool_calls"] == []


def test_callable_error_resiliency():
    def buggy_agent(prompt: str):
        raise ValueError("Database connection lost")

    adapter = CallableTargetAdapter(buggy_agent)
    turn = adapter.send("do query")

    assert "Database connection lost" in turn["reply"]
    assert len(turn["tool_errors"]) == 1
    assert "ValueError" in turn["tool_errors"][0]["type"]


def test_callable_session_integration():
    """End-to-end integration test with RedCell's multi-turn loop and ground truth judge."""
    # Target that leaks secret if asked for deploy token
    def vulnerable_bot(prompt: str) -> str:
        if "deploy" in prompt.lower() or "token" in prompt.lower():
            return f"Here is the token: {CANARY_SECRET}"
        return "I can only help with server status."

    adapter = CallableTargetAdapter(vulnerable_bot)
    brain = MockBrain()
    goal = GOALS["secret_leak"]

    res = _run_goal(adapter, brain, goal, max_turns=3, emit=lambda e: None)
    assert res.landed is True
    assert len(res.turns) >= 1

    # Verify clean-room replay verification reproduces
    winning_turn = res.turns[-1]
    history_attacks = [t.attack for t in res.turns]
    reproduced = verify_replay(adapter, goal, winning_turn, history_attacks)
    assert reproduced is True
