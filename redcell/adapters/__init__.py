"""RedCell Universal Target Adapters."""
from .base import BaseTargetAdapter, ToolCallRecord, TurnResult
from .callable_adapter import CallableTargetAdapter
from .http_adapter import HTTPTargetAdapter
from .langchain_adapter import LangChainTargetAdapter
from .mcp_adapter import MCPTargetAdapter

__all__ = [
    "BaseTargetAdapter",
    "ToolCallRecord",
    "TurnResult",
    "CallableTargetAdapter",
    "HTTPTargetAdapter",
    "MCPTargetAdapter",
    "LangChainTargetAdapter",
]
