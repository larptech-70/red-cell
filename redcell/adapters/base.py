"""Universal Target Adapter Interface for RedCell.

Allows RedCell to test any autonomous AI agent regardless of framework:
- Local in-memory agents (OrbitOps)
- Remote REST / HTTP agent endpoints
- Model Context Protocol (MCP) servers
- LangChain / LangGraph agents
- CrewAI / AutoGen multi-agent workflows
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TypedDict


class ToolCallRecord(TypedDict, total=False):
    cmd: str
    tool: str
    args: dict[str, Any]
    output: str
    risk: str  # "safe" | "dangerous" | "unknown"
    why: str


class TurnResult(TypedDict):
    reply: str
    tool_calls: list[ToolCallRecord]
    latency_ms: int
    metadata: dict[str, Any]


class BaseTargetAdapter(ABC):
    """Abstract base adapter for all target systems tested by RedCell."""

    def __init__(self, target_id: str, name: str = ""):
        self.target_id = target_id
        self.name = name or target_id

    @abstractmethod
    def reset(self) -> None:
        """Reset agent conversational state, memory buffers, and sandboxes."""
        pass

    @abstractmethod
    def send(self, prompt: str) -> dict[str, Any]:
        """Send attack message; execute target turn; return standardized turn result.

        Must return a dict matching at least:
        {"reply": str, "tool_calls": list[dict]}
        """
        pass

    def health_check(self) -> bool:
        """Check if target agent and its tools/sandboxes are alive."""
        return True

    def teardown(self) -> None:
        """Release network connections, docker containers, or subprocesses."""
        pass
