"""HTTP/REST Target Adapter.

Enables RedCell to red-team external REST microservices, FastAPI agent servers,
or external webhooks via configurable request templates and bearer/header auth.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from .base import BaseTargetAdapter


class HTTPTargetAdapter(BaseTargetAdapter):
    """Adapter for HTTP-based conversational agent endpoints."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        target_id: str = "http-agent",
        name: str = "Remote HTTP Agent",
        headers: dict[str, str] | None = None,
        req_template: dict[str, Any] | None = None,
        reply_field: str = "reply",
        tool_calls_field: str = "tool_calls",
        reset_url: str | None = None,
        timeout: int = 30,
    ):
        super().__init__(target_id, name)
        self.endpoint_url = endpoint_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.req_template = req_template or {"message": "$INPUT"}
        self.reply_field = reply_field
        self.tool_calls_field = tool_calls_field
        self.reset_url = reset_url
        self.timeout = timeout
        self.session_id = f"redcell-{int(time.time())}"

    def reset(self) -> None:
        """Call remote reset endpoint if configured, or regenerate session ID."""
        self.session_id = f"redcell-{int(time.time() * 1000)}"
        if self.reset_url:
            try:
                req = urllib.request.Request(
                    self.reset_url,
                    data=json.dumps({"session_id": self.session_id}).encode(),
                    headers=self.headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp.read()
            except Exception:
                pass

    def send(self, prompt: str) -> dict[str, Any]:
        """Send message to the HTTP target and capture response and tool activity."""
        t0 = time.time()
        body = self._build_payload(prompt)
        req = urllib.request.Request(
            self.endpoint_url,
            data=json.dumps(body).encode(),
            headers=self.headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:200]
            return {
                "reply": f"HTTP Error {e.code}: {err_body}",
                "tool_calls": [],
                "latency_ms": int((time.time() - t0) * 1000),
                "error": True,
            }
        except Exception as e:
            return {
                "reply": f"Connection Error: {e}",
                "tool_calls": [],
                "latency_ms": int((time.time() - t0) * 1000),
                "error": True,
            }

        reply = self._extract_field(data, self.reply_field)
        tool_calls = self._extract_field(data, self.tool_calls_field)
        if not isinstance(tool_calls, list):
            tool_calls = []

        # Standardize tool call dictionary format
        standardized_tools = []
        for c in tool_calls:
            if isinstance(c, dict):
                cmd = c.get("cmd") or c.get("command") or str(c.get("args") or "")
                risk = c.get("risk", "unknown")
                standardized_tools.append({
                    "cmd": cmd,
                    "risk": risk,
                    "why": c.get("why", ""),
                    "tool": c.get("tool", "shell"),
                })

        return {
            "reply": str(reply or ""),
            "tool_calls": standardized_tools,
            "latency_ms": int((time.time() - t0) * 1000),
            "metadata": {"status_code": 200},
        }

    def _build_payload(self, prompt: str) -> dict[str, Any]:
        def _sub(val):
            if isinstance(val, str):
                return val.replace("$INPUT", prompt).replace("$SESSION_ID", self.session_id)
            if isinstance(val, dict):
                return {k: _sub(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_sub(v) for v in val]
            return val

        return _sub(self.req_template)

    def _extract_field(self, data: Any, field_path: str) -> Any:
        if not isinstance(data, dict):
            return ""
        cur = data
        for part in field_path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return ""
        return cur
