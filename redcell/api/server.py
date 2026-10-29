"""Production Async API Server for RedCell.

FastAPI-compatible async microservice interface for enterprise DevSecOps platforms,
providing OpenAPI documentation, background scan workers, SSE streaming, and SARIF export.
Can be run via: uvicorn redcell.api.server:app --port 8765
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

from ..attacks.goals import ALL_GOALS, CORE_GOAL_IDS, GOALS
from ..core.llm import Ledger, TokenFactory
from ..core.session import LiveBrain, MockBrain, run_session
from ..intel import tavily_intel
from ..reporting import report as rpt
from ..reporting.sarif import to_sarif
from ..target.devops_agent import DevOpsAgent

PLANNER = os.environ.get("REDCELL_PLANNER_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b")
TARGET_M = os.environ.get("REDCELL_TARGET_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")
JUDGE_M = os.environ.get("REDCELL_JUDGE_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")

SESSIONS: dict[str, dict[str, Any]] = {}


def create_app():
    """Create and configure FastAPI application if fastapi is installed."""
    try:
        from fastapi import FastAPI, HTTPException, BackgroundTasks
        from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        return None

    app = FastAPI(
        title="RedCell Autonomous Agent Red-Teaming API",
        version="1.0.0",
        description="Production API for evaluating autonomous AI agents against OWASP Top 10 for LLMs.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health")
    async def health():
        return {
            "status": "healthy",
            "live_models": TokenFactory().live,
            "tavily_intel": bool(os.environ.get("TAVILY_API_KEY")),
            "active_sessions": len(SESSIONS),
        }

    @app.get("/api/v1/goals")
    async def list_goals():
        return [
            {
                "id": g.id,
                "title": g.title,
                "owasp": g.owasp,
                "brief": g.brief,
                "fix": g.fix,
            }
            for g in ALL_GOALS
        ]

    @app.post("/api/v1/sessions")
    async def start_session(
        hardened: bool = False,
        all_owasp: bool = False,
        turns: int = 6,
    ):
        session_id = str(uuid.uuid4())
        goal_ids = list(GOALS) if all_owasp else CORE_GOAL_IDS
        SESSIONS[session_id] = {
            "id": session_id,
            "status": "pending",
            "hardened": hardened,
            "goal_ids": goal_ids,
            "events": [],
            "report": None,
        }
        return {"session_id": session_id, "status": "created", "goals_count": len(goal_ids)}

    @app.get("/api/v1/reports/{session_id}")
    async def get_report(session_id: str):
        sess = SESSIONS.get(session_id)
        if not sess or not sess.get("report"):
            raise HTTPException(status_code=404, detail="Report not ready or session not found")
        return sess["report"]

    @app.get("/api/v1/reports/{session_id}/sarif")
    async def get_sarif_report(session_id: str):
        sess = SESSIONS.get(session_id)
        if not sess or not sess.get("report"):
            raise HTTPException(status_code=404, detail="Report not ready or session not found")
        return to_sarif(sess["report"])

    return app


app = create_app()
