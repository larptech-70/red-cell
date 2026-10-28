"""Exercises the Tavily threat-intel path against a local stub of the Tavily API.

Mirrors test_live_stub.py: a throwaway HTTP server stands in for api.tavily.com, so the
real request/response shape and the parsing, caching, planning-brief and citation code all
run with no real key and no network.
"""
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import GOALS
from redcell.intel import tavily_intel


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body["query"] and body["search_depth"] and body["max_results"]  # Tavily request shape
        assert self.headers.get("Authorization", "").startswith("Bearer ")
        out = {"query": body["query"], "results": [
            {"title": "OWASP LLM Top 10", "url": "https://owasp.org/llm", "content": "Defensive guidance.", "score": 0.9},
            {"title": "Agent security research", "url": "https://example.org/paper", "content": "Mitigations.", "score": 0.6},
        ]}
        b = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)


def _stub():
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/search"


def test_gather_parses_and_feeds_planner(tmp_path):
    srv, url = _stub()
    cache = str(tmp_path / "intel.json")
    intel = tavily_intel.gather(list(GOALS.values()), api_key="k", endpoint=url, cache_path=cache, force=True)
    srv.shutdown()
    assert intel["ran"] and intel["sources"] == 2 * len(GOALS)      # two hits per goal
    assert os.path.exists(cache)                                    # cached for a fast demo re-run
    brief = tavily_intel.brief_for(intel, "secret_leak")
    assert "OWASP LLM Top 10" in brief and brief.startswith("Threat intel")
    cite = tavily_intel.citation_for(intel, "secret_leak")
    assert cite["url"] == "https://owasp.org/llm"                   # top-scored source wins


def test_cache_is_reused_without_network(tmp_path):
    cache = str(tmp_path / "intel.json")
    json.dump({"ran": True, "sources": 3, "by_goal": {}}, open(cache, "w"))
    # No endpoint/key: if it tried the network it would fail; the cache must satisfy it.
    intel = tavily_intel.gather(list(GOALS.values()), api_key="k", endpoint="http://127.0.0.1:1/search", cache_path=cache)
    assert intel["ran"] and intel["sources"] == 3


def test_offline_degrades_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)             # simulate no key anywhere
    intel = tavily_intel.gather(list(GOALS.values()), api_key="", cache_path=str(tmp_path / "none.json"))
    assert intel["ran"] is False and intel["sources"] == 0          # no crash, no intel
    assert tavily_intel.brief_for(intel, "secret_leak") == ""
    assert tavily_intel.citation_for(intel, "secret_leak") is None
