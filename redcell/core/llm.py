"""Token Factory client (OpenAI-compatible) with a cost ledger and a hard budget cap.

Stdlib only. Set NEBIUS_API_KEY for live use; without it, callers fall back to the
offline mock brain so the whole pipeline can be tested for free.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


def load_env(path: str = os.path.join(os.path.dirname(__file__), "..", "..", ".env")) -> None:
    """Load KEY=VALUE lines from the repo's .env. Variables already set in the shell win."""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return
    for line in lines:
        k, sep, v = line.strip().partition("=")
        if sep and k and not k.startswith("#"):
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


load_env()

# USD per 1M tokens (input, output). Check tokenfactory.nebius.com/pricing; edit if it changes.
PRICES = {
    "nvidia/Nemotron-3-Ultra-550b-a55b": (1.00, 3.00),
    "nvidia/nemotron-3-super-120b-a12b": (0.30, 0.90),
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": (0.06, 0.24),
    "nvidia/Nemotron-3_5-Lightning": (0.06, 0.24),
}
DEFAULT_PRICE = (0.30, 0.90)

# Turns Nemotron 3 reasoning off for a call (documented on NVIDIA's Nemotron-3-Nano model card and
# verified on Token Factory). Used on the Nano target and judge so hidden reasoning tokens cannot
# eat max_tokens and leave an empty reply; the Ultra planner keeps reasoning on.
NO_THINK = {"chat_template_kwargs": {"enable_thinking": False}}


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Ledger:
    budget_usd: float = 1.50
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    by_model: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, model: str, pt: int, ct: int) -> None:
        pin, pout = PRICES.get(model, DEFAULT_PRICE)
        cost = pt / 1e6 * pin + ct / 1e6 * pout
        with self._lock:
            self.calls += 1
            self.prompt_tokens += pt
            self.completion_tokens += ct
            self.cost_usd += cost
            m = self.by_model.setdefault(model, {"calls": 0, "prompt": 0, "completion": 0, "usd": 0.0})
            m["calls"] += 1
            m["prompt"] += pt
            m["completion"] += ct
            m["usd"] += cost

    def check(self) -> None:
        if self.cost_usd >= self.budget_usd:
            raise BudgetExceeded(f"Budget cap ${self.budget_usd:.2f} reached (spent ${self.cost_usd:.4f}).")

    def snapshot(self) -> dict:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": round(self.cost_usd, 5),
            "budget_usd": self.budget_usd,
            "by_model": {k: {**v, "usd": round(v["usd"], 5)} for k, v in self.by_model.items()},
        }


class TokenFactory:
    def __init__(self, api_key: str | None = None, base_url: str | None = None, ledger: Ledger | None = None, timeout: int = 90,
                 attempts: int = 3):
        self.api_key = api_key or os.environ.get("NEBIUS_API_KEY", "")
        self.base_url = (base_url or os.environ.get("NEBIUS_BASE_URL") or "https://api.tokenfactory.nebius.com/v1/").rstrip("/") + "/"
        self.ledger = ledger or Ledger(float(os.environ.get("REDCELL_BUDGET_USD", "1.50")))
        self.timeout = timeout
        self.attempts = max(1, attempts)  # 1 = never retry (used for the garak-facing endpoint)
        self.last_latency_ms = 0

    @property
    def live(self) -> bool:
        return bool(self.api_key)

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        last = None
        for attempt in range(self.attempts):
            try:
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    out = json.loads(r.read())
                self.last_latency_ms = int((time.time() - t0) * 1000)
                return out
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:300]
                last = RuntimeError(f"Token Factory HTTP {e.code}: {detail}")
                if e.code not in (429, 500, 502, 503, 504):
                    raise last
            except urllib.error.URLError as e:
                last = RuntimeError(f"Token Factory unreachable: {e.reason}")
            if attempt + 1 < self.attempts:
                time.sleep(1.5 * (attempt + 1))
        raise last  # type: ignore[misc]

    def chat(self, model: str, messages: list[dict], *, tools: list | None = None, temperature: float = 0.7, max_tokens: int = 700,
             extra: dict | None = None) -> dict:
        """Returns the first choice's message dict ({'content', 'tool_calls'?}). `extra` is merged into the request body."""
        self.ledger.check()
        body = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens, **(extra or {})}
        if tools:
            body["tools"] = tools
        out = self._post("chat/completions", body)
        u = out.get("usage") or {}
        self.ledger.add(model, int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0)))
        choice = out["choices"][0]
        return {**choice["message"], "finish_reason": choice.get("finish_reason")}

    def models(self) -> list[str]:
        req = urllib.request.Request(self.base_url + "models", headers={"Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return sorted(m["id"] for m in json.loads(r.read()).get("data", []))
