"""Universal Callable Target Adapter for RedCell.

Allows RedCell to test any Python agent or conversational pipeline:
- Plain Python functions: `def agent(prompt: str) -> str | dict:`
- Objects with `.chat()`, `.query()`, `.run()`, `.generate()`, `.invoke()`, or `.__call__()`
- Async agents and functions (`async def`)
- Streaming generators / iterators (`yield chunk`)
- Custom reset routines and agent factory functions
- Automatic tool call extraction and shell risk classification
"""
from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Callable, Sequence

from .base import BaseTargetAdapter, ToolCallRecord

try:
    from ..target.simshell import classify
except ImportError:
    classify = None


class CallableTargetAdapter(BaseTargetAdapter):
    """Universal adapter wrapping any Python callable, object, or factory into a RedCell target.

    Features:
    - Auto-invokes functions, methods, async callables, or generators.
    - Inspects returned strings, dictionaries, or objects for replies and tool calls.
    - Captures tool calls via return values, internal object logs, or explicit `record_tool_call()`.
    - Automatically classifies tool command risks with RedCell's deterministic security classifier.
    - Resets conversation state via `reset_fn`, `agent_factory`, or introspecting `.reset()`, `.clear()`.
    """

    def __init__(
        self,
        target: Any | None = None,
        *,
        agent_factory: Callable[[], Any] | None = None,
        method: str | None = None,
        reset_fn: Callable[[], None] | None = None,
        reply_extractor: Callable[[Any], str] | None = None,
        tool_extractor: Callable[[Any], list[dict[str, Any]]] | None = None,
        tool_calls_accessor: Callable[[], list[dict[str, Any]]] | None = None,
        input_mode: str = "prompt",  # "prompt" | "messages" | "dict"
        target_id: str = "orbitops-demo",
        name: str = "Callable Python Agent",
    ):
        """Initialize the Universal Callable Target Adapter.

        Args:
            target: The agent callable, instance, or object to test. Can be None if agent_factory is supplied.
            agent_factory: Optional 0-arg function returning a fresh agent instance upon reset.
            method: Specific method name to invoke on target (e.g. "chat", "query", "run", "invoke").
            reset_fn: Custom reset function called between attack goals and replay verifications.
            reply_extractor: Custom function mapping agent return value to a reply string.
            tool_extractor: Custom function mapping agent return value to a list of tool call dicts.
            tool_calls_accessor: Custom 0-arg function returning in-flight tool calls executed by the target.
            input_mode: Mode to pass prompt:
                - "prompt": passes `prompt: str`
                - "messages": passes `list[dict]` conversation history
                - "dict": passes `{"input": prompt}`
            target_id: Target identifier for scope authorization (defaults to "orbitops-demo").
            name: Human-readable target name.
        """
        super().__init__(target_id, name)
        self.agent_factory = agent_factory
        self.target = target if target is not None else (agent_factory() if agent_factory else None)
        self.method = method
        self.reset_fn = reset_fn
        self.reply_extractor = reply_extractor
        self.tool_extractor = tool_extractor
        self.tool_calls_accessor = tool_calls_accessor
        self.input_mode = input_mode

        self.messages: list[dict[str, str]] = []
        self.manual_tool_calls: list[dict[str, Any]] = []
        self.tool_errors: list[dict[str, Any]] = []

    # -- Public RedCell Target Interface --------------------------------------

    def reset(self) -> None:
        """Reset agent conversation memory, internal state, and tool logs."""
        self.messages.clear()
        self.manual_tool_calls.clear()
        self.tool_errors.clear()

        # 1. User supplied reset function
        if self.reset_fn:
            try:
                self.reset_fn()
                return
            except Exception as e:
                self.tool_errors.append({"error": f"reset_fn failed: {e}"})

        # 2. Agent factory re-creation
        if self.agent_factory:
            try:
                self.target = self.agent_factory()
                return
            except Exception as e:
                self.tool_errors.append({"error": f"agent_factory failed: {e}"})

        # 3. Target introspection for common reset/clear methods
        if self.target is not None:
            for method_name in ("reset", "clear", "reset_conversation", "clear_history"):
                fn = getattr(self.target, method_name, None)
                if callable(fn):
                    try:
                        fn()
                        return
                    except Exception as e:
                        self.tool_errors.append({"error": f"{method_name}() failed: {e}"})

            # Check memory attribute (e.g. LangChain / custom memory)
            mem = getattr(self.target, "memory", None)
            if mem and hasattr(mem, "clear") and callable(mem.clear):
                try:
                    mem.clear()
                    return
                except Exception:
                    pass

    def send(self, prompt: str) -> dict[str, Any]:
        """Send attack turn message to target agent and return standardized result dict."""
        t0 = time.time()
        self.messages.append({"role": "user", "content": prompt})
        start_obj_tools = self._get_target_tool_log_len()

        reply = ""
        extracted_tools: list[dict[str, Any]] = []

        try:
            raw_output = self._invoke(prompt)
            reply = self._extract_reply(raw_output)
            extracted_tools = self._extract_tools(raw_output)
        except Exception as e:
            reply = f"Target Execution Error: {e}"
            self.tool_errors.append({"error": str(e), "type": type(e).__name__})

        # Collect tools from all available channels
        all_tool_calls = []

        # 1. Extracted from return value
        all_tool_calls.extend(extracted_tools)

        # 2. Manually recorded via record_tool_call() during this turn
        all_tool_calls.extend(self.manual_tool_calls)
        self.manual_tool_calls = []

        # 3. Object-level tool log slices (e.g. target.tool_log or target.shell.log)
        obj_slice = self._slice_target_tool_log(start_obj_tools)
        all_tool_calls.extend(obj_slice)

        # 4. Custom accessor if defined
        if self.tool_calls_accessor:
            try:
                accessor_tools = self.tool_calls_accessor()
                if isinstance(accessor_tools, list):
                    all_tool_calls.extend(accessor_tools)
            except Exception as e:
                self.tool_errors.append({"error": f"tool_calls_accessor failed: {e}"})

        # Normalize and classify all tool calls
        normalized_tools = [self._normalize_tool_call(tc) for tc in all_tool_calls]

        latency_ms = int((time.time() - t0) * 1000)
        self.messages.append({"role": "assistant", "content": reply})

        return {
            "reply": reply,
            "tool_calls": normalized_tools,
            "tool_errors": list(self.tool_errors),
            "latency_ms": latency_ms,
        }

    def record_tool_call(
        self,
        cmd: str,
        *,
        tool: str = "shell",
        args: dict[str, Any] | None = None,
        output: str = "",
        risk: str = "unknown",
        why: str = "",
    ) -> None:
        """Manually record a tool call executed during the current turn."""
        self.manual_tool_calls.append({
            "cmd": cmd,
            "tool": tool,
            "args": args or {},
            "output": output,
            "risk": risk,
            "why": why,
        })

    # -- Internal Invocation & Extraction Helpers -----------------------------

    def _invoke(self, prompt: str) -> Any:
        callable_target = self._resolve_callable()
        arg = self._prepare_input(prompt, callable_target)

        # Detect async coroutine functions
        if inspect.iscoroutinefunction(callable_target):
            res = self._run_async(callable_target(arg))
        else:
            res = callable_target(arg)
            # Handle function returning a coroutine
            if inspect.iscoroutine(res):
                res = self._run_async(res)

        # Handle generators / iterators
        if inspect.isgenerator(res) or hasattr(res, "__next__"):
            chunks = []
            for chunk in res:
                chunks.append(str(chunk))
            return "".join(chunks)

        return res

    def _resolve_callable(self) -> Callable:
        if self.method and hasattr(self.target, self.method):
            fn = getattr(self.target, self.method)
            if callable(fn):
                return fn

        if callable(self.target):
            return self.target

        # Introspect common method names
        for m in ("chat", "query", "run", "respond", "generate", "predict", "send", "step", "invoke"):
            fn = getattr(self.target, m, None)
            if callable(fn):
                return fn

        raise TypeError(
            f"Target {type(self.target).__name__} is not callable and has no recognized chat/query method. "
            f"Specify method='...' or pass a callable."
        )

    def _prepare_input(self, prompt: str, fn: Callable) -> Any:
        if self.input_mode == "messages":
            return list(self.messages)
        elif self.input_mode == "dict":
            return {"input": prompt, "prompt": prompt}

        # Check signature for single argument vs kwargs
        try:
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            if len(params) == 1:
                p_name = params[0].name.lower()
                if p_name in ("messages", "history"):
                    return list(self.messages)
        except Exception:
            pass

        return prompt

    def _run_async(self, coro) -> Any:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If called inside an existing running event loop in the same thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    def _extract_reply(self, raw: Any) -> str:
        if self.reply_extractor:
            try:
                return str(self.reply_extractor(raw))
            except Exception as e:
                return f"Extractor Error: {e}"

        if raw is None:
            return ""

        if isinstance(raw, str):
            return raw

        if isinstance(raw, dict):
            for k in ("reply", "output", "response", "content", "text", "message", "answer", "result"):
                if k in raw and raw[k] is not None:
                    val = raw[k]
                    if isinstance(val, str):
                        return val
                    if isinstance(val, dict) and "content" in val:
                        return str(val["content"])
                    return str(val)
            return str(raw)

        # Check object attributes
        for attr in ("content", "text", "reply", "response", "output", "message", "answer"):
            if hasattr(raw, attr):
                val = getattr(raw, attr)
                if val is not None and not callable(val):
                    return str(val)

        return str(raw)

    def _extract_tools(self, raw: Any) -> list[dict[str, Any]]:
        if self.tool_extractor:
            try:
                res = self.tool_extractor(raw)
                return list(res) if isinstance(res, list) else []
            except Exception:
                return []

        if isinstance(raw, dict):
            for k in ("tool_calls", "tools", "actions", "intermediate_steps", "steps", "calls"):
                if k in raw and isinstance(raw[k], list):
                    return raw[k]

        for attr in ("tool_calls", "tools", "actions", "intermediate_steps"):
            if hasattr(raw, attr):
                val = getattr(raw, attr)
                if isinstance(val, list):
                    return val

        return []

    def _get_target_tool_log_len(self) -> int:
        if self.target is None:
            return 0
        for attr in ("tool_calls", "tool_log", "tools_executed", "log"):
            val = getattr(self.target, attr, None)
            if isinstance(val, list):
                return len(val)
        # Check target.shell.log (like SimShell)
        shell = getattr(self.target, "shell", None)
        if shell and hasattr(shell, "log") and isinstance(shell.log, list):
            return len(shell.log)
        return 0

    def _slice_target_tool_log(self, start: int) -> list[dict[str, Any]]:
        if self.target is None:
            return []
        for attr in ("tool_calls", "tool_log", "tools_executed", "log"):
            val = getattr(self.target, attr, None)
            if isinstance(val, list) and len(val) > start:
                return val[start:]
        shell = getattr(self.target, "shell", None)
        if shell and hasattr(shell, "log") and isinstance(shell.log, list) and len(shell.log) > start:
            return shell.log[start:]
        return []

    def _normalize_tool_call(self, tc: Any) -> ToolCallRecord:
        """Normalize various tool call formats into RedCell's ToolCallRecord."""
        res: ToolCallRecord = {
            "cmd": "",
            "tool": "unknown",
            "args": {},
            "output": "",
            "risk": "unknown",
            "why": "",
        }

        if isinstance(tc, dict):
            cmd = tc.get("cmd") or tc.get("command") or tc.get("input") or ""
            tool = tc.get("tool") or tc.get("name") or "unknown"
            args = tc.get("args") or tc.get("parameters") or {}
            output = tc.get("output") or tc.get("result") or tc.get("observation") or ""
            risk = tc.get("risk") or "unknown"
            why = tc.get("why") or ""

            if not cmd and args:
                if isinstance(args, dict):
                    cmd = args.get("command") or args.get("cmd") or str(args)
                else:
                    cmd = str(args)

            res["cmd"] = str(cmd)
            res["tool"] = str(tool)
            res["args"] = args if isinstance(args, dict) else {"raw": str(args)}
            res["output"] = str(output)[:300]
            res["risk"] = str(risk)
            res["why"] = str(why)

        elif isinstance(tc, tuple) and len(tc) == 2:
            # (action, observation) tuple e.g. from LangChain intermediate steps
            action, observation = tc
            tool = getattr(action, "tool", "unknown")
            cmd = getattr(action, "tool_input", str(action))
            res["cmd"] = str(cmd)
            res["tool"] = str(tool)
            res["output"] = str(observation)[:300]

        elif hasattr(tc, "function"):
            # OpenAI / LangChain ToolCall object with function.name and function.arguments
            func = tc.function
            res["tool"] = getattr(func, "name", "unknown")
            args = getattr(func, "arguments", "")
            res["cmd"] = str(args)
            res["output"] = ""

        # Auto-classify command risk if unknown
        if res["cmd"] and (not res["risk"] or res["risk"] == "unknown") and classify:
            risk, why = classify(res["cmd"])
            res["risk"] = risk
            if why and not res["why"]:
                res["why"] = why

        return res
