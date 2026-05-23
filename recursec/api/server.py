"""RecurSec API server — REST API for the autonomous security agent.

Provides endpoints for:
1. Session management (create, start, pause, cancel)
2. Assessment execution (scan, assess)
3. Model management (list, add, remove, configure)
4. Tool management (list available, check status)
5. Finding retrieval and export
6. Agent status monitoring
7. Configuration management
8. Memory and knowledge graph queries
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class APIRequest:
    """Incoming API request."""
    method: str = "GET"
    path: str = "/"
    params: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class APIResponse:
    """Outgoing API response."""
    status: int = 200
    body: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=lambda: {
        "Content-Type": "application/json",
    })

    def to_json(self) -> str:
        return json.dumps(self.body, default=str)


class RecurSecAPI:
    """REST API for RecurSec.

    Can be mounted on any ASGI/WSGI server.
    Provides the complete API surface.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="api")
        self._start_time = time.time()
        self._request_count = 0

        # Lazy-loaded components
        self._session_manager = None
        self._settings = None
        self._tool_pipeline = None
        self._agent = None
        self._memory = None

    def _get_session_manager(self) -> Any:
        if self._session_manager is None:
            from recursec.agents.session_manager import SessionManager
            self._session_manager = SessionManager()
        return self._session_manager

    def _get_settings(self) -> Any:
        if self._settings is None:
            from recursec.config.settings import Settings
            self._settings = Settings()
        return self._settings

    def _get_tool_pipeline(self) -> Any:
        if self._tool_pipeline is None:
            from recursec.agents.tool_pipeline import ToolPipeline
            self._tool_pipeline = ToolPipeline()
        return self._tool_pipeline

    def _get_agent(self) -> Any:
        if self._agent is None:
            from recursec.agents.recursec_agent import RecurSecAgent
            self._agent = RecurSecAgent()
        return self._agent

    def _get_memory(self) -> Any:
        if self._memory is None:
            from recursec.agents.agent_memory import AgentMemory
            self._memory = AgentMemory()
        return self._memory

    async def handle(self, request: APIRequest) -> APIResponse:
        """Route and handle an API request."""
        self._request_count += 1

        path = request.path.rstrip("/")
        method = request.method.upper()

        # Route to handler
        routes: dict[str, dict[str, Any]] = {
            "/api/health": {"GET": self._health},
            "/api/status": {"GET": self._status},
            "/api/sessions": {
                "GET": self._list_sessions,
                "POST": self._create_session,
            },
            "/api/models": {
                "GET": self._list_models,
                "POST": self._add_model,
            },
            "/api/tools": {"GET": self._list_tools},
            "/api/scan": {"POST": self._start_scan},
            "/api/assess": {"POST": self._start_assess},
            "/api/config": {
                "GET": self._get_config,
                "PUT": self._update_config,
            },
            "/api/memory/search": {"POST": self._search_memory},
            "/api/findings": {"GET": self._list_findings},
        }

        route = routes.get(path)
        if not route:
            # Try parameterized routes
            return await self._handle_parameterized(method, path, request)

        handler = route.get(method)
        if not handler:
            return APIResponse(status=405, body={"error": "Method not allowed"})

        try:
            return await handler(request)
        except Exception as e:
            self._log.error("api_error", path=path, error=str(e))
            return APIResponse(status=500, body={"error": str(e)[:200]})

    async def _handle_parameterized(
        self,
        method: str,
        path: str,
        request: APIRequest,
    ) -> APIResponse:
        """Handle parameterized routes like /api/sessions/{id}."""
        parts = path.split("/")

        if len(parts) == 4 and parts[1] == "api" and parts[2] == "sessions":
            session_id = parts[3]
            if method == "GET":
                return await self._get_session(request, session_id)
            elif method == "DELETE":
                return await self._cancel_session(request, session_id)

        if len(parts) == 5 and parts[1] == "api" and parts[2] == "sessions" and parts[4] == "events":
            session_id = parts[3]
            return await self._get_session_events(request, session_id)

        if len(parts) == 4 and parts[1] == "api" and parts[2] == "models":
            model_name = parts[3]
            if method == "DELETE":
                return await self._remove_model(request, model_name)

        return APIResponse(status=404, body={"error": "Not found"})

    # ── Health & Status ──────────────────────────────────

    async def _health(self, request: APIRequest) -> APIResponse:
        return APIResponse(body={
            "status": "ok",
            "uptime_s": round(time.time() - self._start_time, 1),
            "requests": self._request_count,
        })

    async def _status(self, request: APIRequest) -> APIResponse:
        settings = self._get_settings()
        tools = self._get_tool_pipeline()
        sessions = self._get_session_manager()

        return APIResponse(body={
            "status": "running",
            "models": len(settings.models),
            "models_enabled": sum(1 for m in settings.models.values() if m.enabled),
            "tools": tools.get_stats(),
            "sessions": sessions.get_stats(),
            "uptime_s": round(time.time() - self._start_time, 1),
        })

    # ── Sessions ─────────────────────────────────────────

    async def _list_sessions(self, request: APIRequest) -> APIResponse:
        mgr = self._get_session_manager()
        sessions = mgr.get_all_sessions()
        return APIResponse(body={
            "sessions": [s.to_dict() for s in sessions[-50:]],
        })

    async def _create_session(self, request: APIRequest) -> APIResponse:
        mgr = self._get_session_manager()
        target = request.body.get("target", "")
        goal = request.body.get("goal", "")
        name = request.body.get("name", "")

        if not target:
            return APIResponse(status=400, body={"error": "target is required"})

        session = mgr.create_session(target=target, goal=goal, name=name)
        return APIResponse(status=201, body={"session": session.to_dict()})

    async def _get_session(self, request: APIRequest, session_id: str) -> APIResponse:
        mgr = self._get_session_manager()
        session = mgr.get_session(session_id)
        if not session:
            return APIResponse(status=404, body={"error": "Session not found"})
        return APIResponse(body={"session": session.to_dict()})

    async def _cancel_session(self, request: APIRequest, session_id: str) -> APIResponse:
        mgr = self._get_session_manager()
        if mgr.cancel_session(session_id):
            return APIResponse(body={"status": "cancelled"})
        return APIResponse(status=404, body={"error": "Session not found"})

    async def _get_session_events(self, request: APIRequest, session_id: str) -> APIResponse:
        mgr = self._get_session_manager()
        events = mgr.get_events(session_id)
        return APIResponse(body={"events": events})

    # ── Scan & Assess ────────────────────────────────────

    async def _start_scan(self, request: APIRequest) -> APIResponse:
        target = request.body.get("target", "")
        if not target:
            return APIResponse(status=400, body={"error": "target is required"})

        mgr = self._get_session_manager()
        session = mgr.create_session(target=target, goal=f"Quick scan of {target}")
        mgr.start_session(session.session_id)

        # Run scan in background
        agent = self._get_agent()
        asyncio.create_task(self._run_scan(agent, session.session_id, target))

        return APIResponse(status=202, body={
            "session": session.to_dict(),
            "message": "Scan started",
        })

    async def _start_assess(self, request: APIRequest) -> APIResponse:
        target = request.body.get("target", "")
        goal = request.body.get("goal", "")
        deep = request.body.get("deep", False)

        if not target:
            return APIResponse(status=400, body={"error": "target is required"})

        mgr = self._get_session_manager()
        session = mgr.create_session(target=target, goal=goal)
        mgr.start_session(session.session_id)

        agent = self._get_agent()
        asyncio.create_task(self._run_assess(agent, session.session_id, target, goal, deep))

        return APIResponse(status=202, body={
            "session": session.to_dict(),
            "message": "Assessment started",
        })

    async def _run_scan(self, agent: Any, session_id: str, target: str) -> None:
        mgr = self._get_session_manager()
        try:
            result = await agent.quick_scan(target)
            mgr.complete_session(
                session_id,
                findings=result.findings,
                validated=result.validated_findings,
            )
        except Exception as e:
            mgr.fail_session(session_id, str(e))

    async def _run_assess(
        self,
        agent: Any,
        session_id: str,
        target: str,
        goal: str,
        deep: bool,
    ) -> None:
        from recursec.agents.recursec_agent import AssessmentConfig

        mgr = self._get_session_manager()
        try:
            config = AssessmentConfig(
                target=target,
                goal=goal or f"Security assessment of {target}",
                max_time_s=3600.0 if deep else 1800.0,
                max_agents=30 if deep else 20,
            )
            result = await agent.assess(config)
            mgr.complete_session(
                session_id,
                findings=result.findings,
                validated=result.validated_findings,
            )
        except Exception as e:
            mgr.fail_session(session_id, str(e))

    # ── Models ───────────────────────────────────────────

    async def _list_models(self, request: APIRequest) -> APIResponse:
        settings = self._get_settings()
        models = [m.to_dict() for m in settings.models.values()]
        return APIResponse(body={"models": models})

    async def _add_model(self, request: APIRequest) -> APIResponse:
        from recursec.config.settings import ModelConfig

        settings = self._get_settings()
        name = request.body.get("name", "")
        port = request.body.get("port", 0)

        if not name or not port:
            return APIResponse(status=400, body={"error": "name and port required"})

        model = ModelConfig(
            name=name,
            port=port,
            capabilities=request.body.get("capabilities", []),
            weight=request.body.get("weight", 1.0),
            context_length=request.body.get("context_length", 4096),
            system_prompt=request.body.get("system_prompt", ""),
        )

        settings.add_model(model)
        return APIResponse(status=201, body={"model": model.to_dict()})

    async def _remove_model(self, request: APIRequest, model_name: str) -> APIResponse:
        settings = self._get_settings()
        if settings.remove_model(model_name):
            return APIResponse(body={"status": "removed"})
        return APIResponse(status=404, body={"error": "Model not found"})

    # ── Tools ────────────────────────────────────────────

    async def _list_tools(self, request: APIRequest) -> APIResponse:
        pipeline = self._get_tool_pipeline()
        available = pipeline.get_available_tools()
        return APIResponse(body={
            "tools": [t.to_dict() for t in available],
            "stats": pipeline.get_stats(),
        })

    # ── Config ───────────────────────────────────────────

    async def _get_config(self, request: APIRequest) -> APIResponse:
        settings = self._get_settings()
        return APIResponse(body={"config": settings.to_dict()})

    async def _update_config(self, request: APIRequest) -> APIResponse:
        settings = self._get_settings()
        config_data = request.body

        if "agent" in config_data:
            for key, value in config_data["agent"].items():
                if hasattr(settings.agent, key):
                    setattr(settings.agent, key, value)

        if "safety" in config_data:
            for key, value in config_data["safety"].items():
                if hasattr(settings.safety, key):
                    setattr(settings.safety, key, value)

        settings.save()
        return APIResponse(body={"config": settings.to_dict()})

    # ── Memory ───────────────────────────────────────────

    async def _search_memory(self, request: APIRequest) -> APIResponse:
        memory = self._get_memory()
        query = request.body.get("query", "")
        tags = request.body.get("tags", [])
        limit = request.body.get("limit", 10)

        results = memory.search(query=query, tags=tags, limit=limit)
        return APIResponse(body={
            "results": [m.to_dict() for m in results],
        })

    # ── Findings ─────────────────────────────────────────

    async def _list_findings(self, request: APIRequest) -> APIResponse:
        mgr = self._get_session_manager()
        all_findings = []
        for session in mgr.get_all_sessions():
            all_findings.extend(session.findings)

        severity = request.params.get("severity")
        if severity:
            all_findings = [f for f in all_findings if f.get("severity") == severity]

        return APIResponse(body={
            "findings": all_findings[-100:],
            "total": len(all_findings),
        })
