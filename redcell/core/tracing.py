"""Optional LangSmith tracing.

Off unless all three hold: the `langsmith` package is installed, LANGSMITH_API_KEY is set, and
LANGSMITH_TRACING is true. Otherwise every call here is a no-op and RedCell behaves exactly as without it.
Any tracing error is swallowed, so tracing can never change, slow down on failure, or stop a run.

Only run data goes into traces (model names, messages with fake canaries, token counts, cost, verdicts).
Never API keys, request headers or the judge run code.
"""
from __future__ import annotations

import contextlib
import os

MAX_CHARS = 2000  # per message / output in a trace

# Tests can inject a stand-in for `langsmith.trace` (same call signature, returns a context manager).
_factory = None


def enabled() -> bool:
    if _factory is not None:
        return True
    if not os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGSMITH_TRACING", "").strip().lower() not in ("true", "1", "yes"):
        return False
    try:
        import langsmith  # noqa: F401
    except ImportError:
        return False
    return True


class Span:
    """Handle for one traced step. All methods are safe no-ops when tracing is off or fails."""

    def __init__(self, run=None):
        self.run = run

    def end(self, outputs: dict | None = None, metadata: dict | None = None) -> None:
        if self.run is None:
            return
        try:
            if metadata:
                self.run.add_metadata(metadata)
            self.run.end(outputs=outputs or {})
        except Exception:
            pass

    def url(self) -> str:
        """Trace URL. Needs read access, so it is "" with a write-only (tracing-only) key; use trace_id() then."""
        try:
            return self.run.get_url() if self.run is not None else ""
        except Exception:
            return ""

    def trace_id(self) -> str:
        try:
            return str(getattr(self.run, "trace_id", None) or getattr(self.run, "id", "") or "") if self.run is not None else ""
        except Exception:
            return ""


@contextlib.contextmanager
def span(name: str, run_type: str = "chain", inputs: dict | None = None, metadata: dict | None = None):
    """`with span("goal: x", "chain", metadata={...}) as s: ...; s.end(outputs=..., metadata=...)`.
    Nests under whatever span is active. Errors in the traced code are re-raised unchanged."""
    if not enabled():
        yield Span()
        return
    try:
        if _factory is not None:
            cm = _factory(name, run_type, inputs=inputs or {}, metadata=metadata or {})
        else:
            import langsmith
            cm = langsmith.trace(name, run_type, inputs=inputs or {}, metadata=metadata or {})
        run = cm.__enter__()
    except Exception:
        yield Span()
        return
    exc = (None, None, None)
    try:
        yield Span(run)
    except BaseException as e:
        exc = (type(e), e, e.__traceback__)
        raise
    finally:
        try:
            cm.__exit__(*exc)
        except Exception:
            pass


def messages_for_trace(messages: list[dict]) -> list[dict]:
    """Role + trimmed content only (no tool-call internals, nothing else from the request)."""
    return [{"role": m.get("role", ""), "content": str(m.get("content") or "")[:MAX_CHARS]} for m in messages]


def flush() -> None:
    """Send queued traces before a script exits."""
    if not enabled() or _factory is not None:
        return
    try:
        from langsmith.run_trees import get_cached_client
        get_cached_client().flush()
    except Exception:
        pass
