"""Model Context Protocol (MCP) Target Adapter.

Allows RedCell to test agents running against MCP servers (or agents exposing
an MCP interface), monitoring tools invoked through standard MCP JSON-RPC.
"""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from .base import BaseTargetAdapter


class MCPTargetAdapter(BaseTargetAdapter):
    """Adapter for Model Context Protocol (MCP) servers via stdio JSON-RPC."""

    def __init__(
        self,
        command: list[str],
        *,
        target_id: str = "mcp-agent",
        name: str = "MCP Target Agent",
        env: dict[str, str] | None = None,
    ):
        super().__init__(target_id, name)
        self.command = command
        self.env = env
        self.proc: subprocess.Popen | None = None
        self._req_id = 0
        self.tool_log: list[dict[str, Any]] = []

    def reset(self) -> None:
        """Restart the MCP subprocess to reset state cleanly."""
        self.teardown()
        self.tool_log.clear()
        self._req_id = 0
        try:
            self.proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env,
            )
            # Initialize handshake
            self._rpc_call("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "RedCell", "version": "1.0.0"},
            })
        except Exception as e:
            self.proc = None

    def send(self, prompt: str) -> dict[str, Any]:
        """Send a prompt or tool call over MCP JSON-RPC."""
        t0 = time.time()
        if not self.proc:
            self.reset()
        if not self.proc:
            return {"reply": "Failed to start MCP server process", "tool_calls": []}

        # Issue sample query or call
        resp = self._rpc_call("sampling/createMessage", {
            "messages": [{"role": "user", "content": {"type": "text", "text": prompt}}],
            "maxTokens": 1000,
        })

        reply = ""
        if resp and "result" in resp:
            content = resp["result"].get("content", {})
            reply = content.get("text", "") if isinstance(content, dict) else str(content)

        return {
            "reply": reply,
            "tool_calls": list(self.tool_log),
            "latency_ms": int((time.time() - t0) * 1000),
        }

    def _rpc_call(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            return None
        self._req_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params,
        }
        try:
            line = json.dumps(payload) + "\n"
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
            out = self.proc.stdout.readline()
            if out:
                return json.loads(out)
        except Exception:
            pass
        return None

    def teardown(self) -> None:
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
