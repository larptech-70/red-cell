"""LangChain / LangGraph Target Adapter.

Allows RedCell to test LangChain AgentExecutors, LCEL chains, or LangGraph state
graphs, extracting tool invocations directly from execution intermediate steps.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from .base import BaseTargetAdapter


class LangChainTargetAdapter(BaseTargetAdapter):
    """Adapter for testing LangChain agents in-process."""

    def __init__(
        self,
        agent_executor: Any,
        *,
        target_id: str = "langchain-agent",
        name: str = "LangChain Agent",
        reset_fn: Callable[[], None] | None = None,
    ):
        super().__init__(target_id, name)
        self.agent_executor = agent_executor
        self.reset_fn = reset_fn
        self.history: list[dict[str, str]] = []

    def reset(self) -> None:
        self.history.clear()
        if self.reset_fn:
            self.reset_fn()
        elif hasattr(self.agent_executor, "memory") and getattr(self.agent_executor, "memory"):
            try:
                self.agent_executor.memory.clear()
            except Exception:
                pass

    def send(self, prompt: str) -> dict[str, Any]:
        t0 = time.time()
        tool_calls = []

        try:
            # LangChain AgentExecutor invoke pattern
            if hasattr(self.agent_executor, "invoke"):
                result = self.agent_executor.invoke({"input": prompt})
            elif callable(self.agent_executor):
                result = self.agent_executor(prompt)
            else:
                return {"reply": "Unsupported LangChain agent type", "tool_calls": []}

            # Extract reply text
            if isinstance(result, dict):
                reply = result.get("output") or result.get("result") or str(result)
                # Parse intermediate steps if present
                steps = result.get("intermediate_steps") or []
                for action, observation in steps:
                    tool_name = getattr(action, "tool", "unknown")
                    tool_input = getattr(action, "tool_input", "")
                    tool_calls.append({
                        "tool": tool_name,
                        "cmd": str(tool_input),
                        "output": str(observation)[:300],
                        "risk": "unknown",
                        "why": f"Invoked {tool_name}",
                    })
            else:
                reply = str(result)

        except Exception as e:
            reply = f"LangChain Execution Error: {e}"

        return {
            "reply": reply,
            "tool_calls": tool_calls,
            "latency_ms": int((time.time() - t0) * 1000),
        }
