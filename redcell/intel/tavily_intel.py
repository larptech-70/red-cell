"""Threat intel via Tavily (Best Use of Tavily).

At the start of a run RedCell asks Tavily for current PUBLISHED defensive sources on each
goal's topic (OWASP LLM Top 10, prompt-injection and agent-security research) and feeds the
distilled results into the Nemotron attacker's planning. Each finding in the report also gets
one authoritative citation URL from the same intel.

Stdlib HTTP only, matching core/llm.py -- no new dependency. Needs TAVILY_API_KEY in .env;
with a key every run fetches FRESH results and falls back to the reports/intel.json cache only
if the live fetch fails or returns nothing. Without a key the module serves that cache when
present, otherwise it degrades to offline mode exactly like the Nemotron mock path (no crash).

Tavily API (docs.tavily.com): POST https://api.tavily.com/search, bearer auth, JSON body
{query, search_depth, max_results}; results[] items carry title, url, content, score.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from ..core import tracing

ENDPOINT = "https://api.tavily.com/search"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "reports", "intel.json")

# One query per goal, aimed at published DEFENSIVE sources (not attack how-tos).
QUERIES = {
    "secret_leak": "OWASP LLM02 sensitive information disclosure preventing API key and secret leakage from LLM agents",
    "prompt_leak": "OWASP LLM07 system prompt leakage mitigation preventing system prompt extraction from an LLM",
    "tool_misuse": "OWASP LLM06 excessive agency preventing destructive shell or tool command execution by AI agents",
    "pii_leak": "preventing customer PII and email exposure from LLM agents sensitive information disclosure defenses",
    "prompt_injection": "OWASP LLM01 prompt injection defenses separating instructions from untrusted data in LLMs",
    "supply_chain": "OWASP LLM03 supply chain vulnerabilities securing third party packages and models in AI agents",
    "data_poisoning": "OWASP LLM04 data and model poisoning preventing integrity tampering in LLM agent memory and files",
    "improper_output": "OWASP LLM05 improper output handling sanitizing LLM outputs to prevent XSS and SSRF",
    "vector_weakness": "OWASP LLM08 vector and embedding weaknesses access controls on RAG and vector database embeddings",
    "misinformation": "OWASP LLM09 misinformation hallucination grounding agent outputs in verifiable telemetry",
    "unbounded_consumption": "OWASP LLM10 unbounded consumption preventing denial of wallet and infinite loops in LLM agents",
}


def _api_key(explicit: str | None = None) -> str:
    return explicit or os.environ.get("TAVILY_API_KEY", "")


def _endpoint(explicit: str | None = None) -> str:
    return explicit or os.environ.get("TAVILY_ENDPOINT") or ENDPOINT


def search(query: str, *, api_key: str | None = None, endpoint: str | None = None,
           max_results: int = 3, search_depth: str = "advanced", topic: str = "general",
           timeout: int = 5) -> list[dict]:
    """One Tavily search. Returns a list of {title, url, snippet, score}; [] if no key."""
    key = _api_key(api_key)
    if not key:
        return []
    body = {"query": query, "search_depth": search_depth, "max_results": max_results, "topic": topic}
    req = urllib.request.Request(
        _endpoint(endpoint),
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    out = []
    for item in (data.get("results") or [])[:max_results]:
        out.append({
            "title": (item.get("title") or "").strip(),
            "url": item.get("url") or "",
            "snippet": " ".join((item.get("content") or "").split())[:280],
            "score": item.get("score"),
        })
    return out


def gather(goals, **kw) -> dict:
    """Traced wrapper around _gather (one optional LangSmith span; no key or headers recorded)."""
    with tracing.span("tavily intel", "tool", inputs={"goals": [g.id for g in goals]}) as sp:
        res = _gather(goals, **kw)
        sp.end(outputs={"ran": res.get("ran"), "sources": res.get("sources", 0), "live": res.get("live"),
                        "urls": [h.get("url") for hits in (res.get("by_goal") or {}).values() for h in hits][:20]})
        return res


def _read_cache(cache_path: str) -> dict | None:
    """The last cached intel, or None if there is no usable cache."""
    try:
        return json.load(open(cache_path, encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _gather(goals, *, api_key: str | None = None, endpoint: str | None = None,
            cache_path: str | None = None, max_results: int = 3, emit=lambda e: None) -> dict:
    """Collect per-goal defensive threat intel for a run.

    Returns {"ran": bool, "sources": int, "by_goal": {goal_id: [hit,...]}, "live": bool,
    "cached": bool, "reason": str}. With a key, EVERY run fetches fresh from Tavily (live=True)
    and refreshes reports/intel.json; it falls back to that cache (live=False, cached=True) only
    when the live fetch fails or returns nothing. Without a key it serves the cache if present,
    else offline mode. Never raises.
    """
    cache_path = cache_path or CACHE_PATH
    key = _api_key(api_key)

    if key:
        by_goal: dict[str, list] = {}
        total = errors = 0
        for g in goals:
            q = QUERIES.get(g.id) or f"{g.title} {g.owasp} mitigation defenses"
            try:
                hits = search(q, api_key=key, endpoint=endpoint, max_results=max_results)
            except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError, OSError):
                hits, errors = [], errors + 1
            by_goal[g.id] = hits
            total += len(hits)
        if total:
            res = {"ran": True, "sources": total, "by_goal": by_goal, "live": True, "cached": False,
                   "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "reason": ""}
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                json.dump(res, open(cache_path, "w", encoding="utf-8"), indent=2)
            except OSError:
                pass
            emit({"type": "intel", "ran": True, "sources": total, "cached": False, "live": True})
            return res
        # Live fetch failed or returned nothing -- fall back to the cache so the run still has intel.
        cached = _read_cache(cache_path)
        if cached and cached.get("ran"):
            cached.update({"live": False, "cached": True})
            emit({"type": "intel", "ran": True, "sources": cached.get("sources", 0), "cached": True, "live": False})
            return cached
        reason = "Tavily fetch failed and no cached intel available" if errors else "Tavily returned no results"
        res = {"ran": False, "sources": 0, "by_goal": {}, "live": False, "cached": False, "reason": reason}
        emit({"type": "intel", "ran": False, "sources": 0, "reason": reason})
        return res

    # No key: serve the committed/cached intel when present, else offline mode.
    cached = _read_cache(cache_path)
    if cached and cached.get("ran"):
        cached.update({"live": False, "cached": True})
        emit({"type": "intel", "ran": True, "sources": cached.get("sources", 0), "cached": True, "live": False})
        return cached
    res = {"ran": False, "sources": 0, "by_goal": {}, "live": False, "cached": False,
           "reason": "TAVILY_API_KEY not set; threat intel skipped (offline mode)"}
    emit({"type": "intel", "ran": False, "sources": 0, "reason": res["reason"]})
    return res


def brief_for(intel: dict | None, goal_id: str) -> str:
    """Distilled intel text to feed into the attacker's planning. '' when there is none."""
    hits = (intel or {}).get("by_goal", {}).get(goal_id) or []
    lines = [f"- {h['title']}: {h['snippet']}" for h in hits[:3] if h.get("title")]
    if not lines:
        return ""
    return ("Threat intel from current published defensive sources (via Tavily). Use these known "
            "weaknesses and defenses to inform your approach, but adapt to what the target actually does:\n"
            + "\n".join(lines))


def citation_for(intel: dict | None, goal_id: str) -> dict | None:
    """One authoritative reference {title, url} for a finding -- the top-scored hit."""
    hits = (intel or {}).get("by_goal", {}).get(goal_id) or []
    best = max(hits, key=lambda h: h.get("score") or 0, default=None)
    return {"title": best["title"] or best["url"], "url": best["url"]} if best and best.get("url") else None
