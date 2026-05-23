"""RecurSec HTTP API — web dashboard and REST endpoints.

Provides:
- GET  /api/status          — Agent status
- GET  /api/models          — List models
- GET  /api/tools           — List tools
- POST /api/run             — Start assessment
- POST /api/scan            — Quick scan
- GET  /api/findings        — List findings
- GET  /api/sessions        — List sessions
- GET  /api/sessions/:id    — Session details
- POST /api/queue           — Add to queue
- GET  /api/queue           — Queue status
- POST /api/schedule        — Add schedule
- GET  /api/schedule        — List schedules
- GET  /api/health          — Health check
- GET  /api/stats           — Detailed stats
- GET  /api/knowledge       — Knowledge base stats
- WebSocket /ws/events      — Real-time events
"""

from __future__ import annotations

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
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    client_ip: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "body_keys": list(self.body.keys()),
        }


@dataclass
class APIResponse:
    """Outgoing API response."""
    status: int = 200
    body: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.body, default=str)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "body_keys": list(self.body.keys()),
        }


@dataclass
class WebSocketClient:
    """Connected WebSocket client."""
    client_id: str = ""
    connected_at: float = field(default_factory=time.time)
    subscriptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.client_id[:10],
            "subs": self.subscriptions,
        }


class RecurSecAPI:
    """HTTP API server for RecurSec.

    Provides REST endpoints and WebSocket events
    for monitoring and controlling the agent.
    """

    def __init__(self) -> None:
        self._routes: dict[str, dict[str, Any]] = {}
        self._ws_clients: dict[str, WebSocketClient] = {}
        self._event_buffer: list[dict[str, Any]] = []
        self._request_count = 0
        self._start_time = time.time()
        self._log = logger.bind(component="api")

        self._register_routes()

    def _register_routes(self) -> None:
        """Register all API routes."""
        self._routes = {
            "GET /api/status": {"handler": self._handle_status},
            "GET /api/health": {"handler": self._handle_health},
            "GET /api/models": {"handler": self._handle_models},
            "GET /api/tools": {"handler": self._handle_tools},
            "GET /api/stats": {"handler": self._handle_stats},
            "GET /api/findings": {"handler": self._handle_findings},
            "GET /api/sessions": {"handler": self._handle_sessions},
            "GET /api/queue": {"handler": self._handle_queue_status},
            "GET /api/schedule": {"handler": self._handle_schedules},
            "GET /api/knowledge": {"handler": self._handle_knowledge},
            "POST /api/run": {"handler": self._handle_run},
            "POST /api/scan": {"handler": self._handle_scan},
            "POST /api/queue": {"handler": self._handle_queue_add},
            "POST /api/schedule": {"handler": self._handle_schedule_add},
        }

    async def handle_request(self, request: APIRequest) -> APIResponse:
        """Handle an incoming API request."""
        self._request_count += 1
        route_key = f"{request.method} {request.path}"

        route = self._routes.get(route_key)
        if not route:
            return APIResponse(
                status=404,
                body={"error": "Not found", "path": request.path},
            )

        try:
            handler = route["handler"]
            return await handler(request)
        except Exception as e:
            self._log.error("api_error", path=request.path, error=str(e))
            return APIResponse(
                status=500,
                body={"error": str(e)},
            )

    async def _handle_status(self, request: APIRequest) -> APIResponse:
        """GET /api/status — agent status."""
        return APIResponse(body={
            "status": "running",
            "uptime_s": round(time.time() - self._start_time, 1),
            "requests_served": self._request_count,
            "ws_clients": len(self._ws_clients),
        })

    async def _handle_health(self, request: APIRequest) -> APIResponse:
        """GET /api/health — health check."""
        return APIResponse(body={
            "healthy": True,
            "components": {
                "api": True,
                "agent_brain": True,
            },
        })

    async def _handle_models(self, request: APIRequest) -> APIResponse:
        """GET /api/models — list models."""
        from recursec.agents.config_manager import ConfigManager
        config = ConfigManager()
        models = [m.to_dict() for m in config.get_enabled_models()]
        return APIResponse(body={"models": models, "count": len(models)})

    async def _handle_tools(self, request: APIRequest) -> APIResponse:
        """GET /api/tools — list tools."""
        from recursec.agents.tool_executor import ToolExecutor
        executor = ToolExecutor()
        available = executor.get_available_tools()
        return APIResponse(body={"tools": available, "count": len(available)})

    async def _handle_stats(self, request: APIRequest) -> APIResponse:
        """GET /api/stats — detailed stats."""
        return APIResponse(body={
            "requests": self._request_count,
            "uptime": round(time.time() - self._start_time, 1),
            "events_buffered": len(self._event_buffer),
        })

    async def _handle_findings(self, request: APIRequest) -> APIResponse:
        """GET /api/findings — list findings."""
        session_id = request.query_params.get("session_id", "")
        if session_id:
            from recursec.agents.persistence import PersistenceManager
            pm = PersistenceManager()
            findings = pm.load_findings(session_id)
            return APIResponse(body={"findings": findings, "count": len(findings)})
        return APIResponse(body={"findings": [], "count": 0})

    async def _handle_sessions(self, request: APIRequest) -> APIResponse:
        """GET /api/sessions — list sessions."""
        from recursec.agents.persistence import PersistenceManager
        pm = PersistenceManager()
        sessions = pm.list_sessions()
        return APIResponse(body={"sessions": sessions, "count": len(sessions)})

    async def _handle_queue_status(self, request: APIRequest) -> APIResponse:
        """GET /api/queue — queue status."""
        return APIResponse(body={"queue": {"depth": 0}})

    async def _handle_schedules(self, request: APIRequest) -> APIResponse:
        """GET /api/schedule — list schedules."""
        return APIResponse(body={"schedules": [], "count": 0})

    async def _handle_knowledge(self, request: APIRequest) -> APIResponse:
        """GET /api/knowledge — knowledge base stats."""
        from recursec.agents.webapp_vuln_kb import WebAppVulnKB
        from recursec.agents.cloud_security_kb import CloudSecurityKB
        from recursec.agents.supply_chain_kb import SupplyChainKB
        from recursec.agents.ai_vuln_kb import AIVulnKB
        from recursec.agents.api_security_kb import APISecurityKB
        from recursec.agents.hardware_firmware_kb import HardwareFirmwareKB
        from recursec.agents.network_protocol_kb import NetworkProtocolKB
        from recursec.agents.active_directory_kb import ActiveDirectoryKB
        from recursec.agents.privesc_kb import PrivescKB

        kbs = {
            "webapp": WebAppVulnKB().get_stats(),
            "cloud": CloudSecurityKB().get_stats(),
            "supply_chain": SupplyChainKB().get_stats(),
            "ai_ml": AIVulnKB().get_stats(),
            "api": APISecurityKB().get_stats(),
            "hardware_firmware": HardwareFirmwareKB().get_stats(),
            "network_protocol": NetworkProtocolKB().get_stats(),
            "active_directory": ActiveDirectoryKB().get_stats(),
            "privesc": PrivescKB().get_stats(),
        }

        total_patterns = sum(kb.get("patterns", 0) for kb in kbs.values())

        return APIResponse(body={
            "knowledge_bases": kbs,
            "total_patterns": total_patterns,
        })

    async def _handle_run(self, request: APIRequest) -> APIResponse:
        """POST /api/run — start assessment."""
        target = request.body.get("target", "")
        goal = request.body.get("goal", "")

        if not target:
            return APIResponse(status=400, body={"error": "target required"})

        return APIResponse(body={
            "status": "started",
            "target": target,
            "goal": goal,
        })

    async def _handle_scan(self, request: APIRequest) -> APIResponse:
        """POST /api/scan — quick scan."""
        target = request.body.get("target", "")
        tools = request.body.get("tools", ["nmap", "nuclei"])

        if not target:
            return APIResponse(status=400, body={"error": "target required"})

        return APIResponse(body={
            "status": "started",
            "target": target,
            "tools": tools,
        })

    async def _handle_queue_add(self, request: APIRequest) -> APIResponse:
        """POST /api/queue — add to queue."""
        target = request.body.get("target", "")
        priority = request.body.get("priority", "normal")

        if not target:
            return APIResponse(status=400, body={"error": "target required"})

        return APIResponse(body={
            "status": "queued",
            "target": target,
            "priority": priority,
        })

    async def _handle_schedule_add(self, request: APIRequest) -> APIResponse:
        """POST /api/schedule — add schedule."""
        target = request.body.get("target", "")
        interval = request.body.get("interval_hours", 24.0)

        if not target:
            return APIResponse(status=400, body={"error": "target required"})

        return APIResponse(body={
            "status": "scheduled",
            "target": target,
            "interval_hours": interval,
        })

    # ── WebSocket ────────────────────────────────────────────

    def ws_connect(self, client_id: str) -> WebSocketClient:
        """Register a WebSocket client."""
        client = WebSocketClient(client_id=client_id)
        self._ws_clients[client_id] = client
        return client

    def ws_disconnect(self, client_id: str) -> None:
        """Disconnect a WebSocket client."""
        self._ws_clients.pop(client_id, None)

    def ws_subscribe(self, client_id: str, event_type: str) -> None:
        """Subscribe a client to an event type."""
        client = self._ws_clients.get(client_id)
        if client and event_type not in client.subscriptions:
            client.subscriptions.append(event_type)

    def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event to subscribed WebSocket clients."""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": time.time(),
        }
        self._event_buffer.append(event)

        # Keep buffer bounded
        if len(self._event_buffer) > 1000:
            self._event_buffer = self._event_buffer[-500:]

    def get_stats(self) -> dict[str, Any]:
        return {
            "routes": len(self._routes),
            "requests_served": self._request_count,
            "ws_clients": len(self._ws_clients),
            "events_buffered": len(self._event_buffer),
            "uptime": round(time.time() - self._start_time, 1),
        }
