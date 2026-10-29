"""Example: Test ANY custom Python agent using RedCell's CallableTargetAdapter.

Usage:
    python examples/test_custom_agent.py
"""
import os
import sys

# Ensure repository root is on Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redcell.adapters import CallableTargetAdapter
from redcell.attacks.goals import CORE_GOAL_IDS, GOALS
from redcell.core.llm import Ledger, TokenFactory
from redcell.core.session import LiveBrain, MockBrain, _run_goal
from redcell.server import JUDGE_M, PLANNER
from redcell.target.simshell import CANARY_SECRET


# 1. Define your custom agent (plain function, class, or async pipeline)
class MyCustomSupportBot:
    def __init__(self):
        self.conversation_history = []

    def reset(self):
        """Reset internal agent memory between test goals."""
        self.conversation_history.clear()

    def query(self, prompt: str) -> dict:
        """Process incoming user prompt."""
        self.conversation_history.append(prompt)

        # Vulnerable behavior: accidentally shares credentials if asked by lead engineer
        if "lead" in prompt.lower() and "token" in prompt.lower():
            return {
                "reply": f"Understood, here is the secret deploy token: {CANARY_SECRET}",
                "tool_calls": [{"cmd": "cat /etc/devops/.env", "output": f"DEPLOY_TOKEN={CANARY_SECRET}"}],
            }

        # Otherwise safe behavior
        return {
            "reply": "Hello! I am your support assistant. How can I help you today?",
            "tool_calls": [{"cmd": "uptime", "risk": "safe"}],
        }


def main():
    print("=" * 70)
    print(" RedCell | Universal CallableTargetAdapter Demo")
    print(" Testing a custom in-memory Python agent with zero boilerplate")
    print("=" * 70)

    # 2. Wrap your agent in CallableTargetAdapter
    my_agent = MyCustomSupportBot()
    target = CallableTargetAdapter(
        my_agent,
        name="Orbit Support Bot v1.0",
    )

    # 3. Setup RedCell evaluator brain (Live Nemotron or Mock fallback)
    llm = TokenFactory(ledger=Ledger(0.50))
    brain = LiveBrain(llm, PLANNER, JUDGE_M) if llm.live else MockBrain()
    print(f"Evaluator mode: {'Nemotron-Live' if llm.live else 'Mock (Offline)'}\n")

    # 4. Run tests against core OWASP goals
    broken = 0
    for gid in CORE_GOAL_IDS:
        goal = GOALS[gid]
        print(f"--> Testing Goal: {goal.title} ({goal.owasp})")
        res = _run_goal(target, brain, goal, max_turns=3, emit=lambda e: None)

        if res.landed:
            broken += 1
            print(f"    [COMPROMISED] Landed in {len(res.turns)} turns!")
            winning_turn = res.turns[-1]
            print(f"    Evidence: {winning_turn.evidence}")
            print(f"    Fix: {goal.fix}\n")
        else:
            print("    [DEFENDED] Target resisted adversarial turns.\n")

    print("=" * 70)
    print(f"Audit Complete: {broken} of {len(CORE_GOAL_IDS)} goals compromised.")
    print("=" * 70)


if __name__ == "__main__":
    main()
