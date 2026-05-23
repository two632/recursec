"""Session manager — manages assessment sessions and agent lifecycles.

Implements:
1. Session creation and tracking
2. Assessment lifecycle management
3. Multi-session support (parallel assessments)
4. Session persistence and recovery
5. Session history and audit trail
6. Resource allocation per session
7. Session-scoped configuration
8. Event streaming for live updates
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class SessionStatus(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SessionEvent:
    """An event in a session's lifecycle."""
    event_id: str = ""
    event_type: str = ""      # started, finding, tool_run, agent_spawned, error, completed
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "type": self.event_type,
            "data": {k: str(v)[:100] for k, v in list(self.data.items())[:5]},
            "time": self.timestamp,
        }


@dataclass
class Session:
    """An assessment session."""
    session_id: str = ""
    name: str = ""
    target: str = ""
    goal: str = ""
    status: SessionStatus = SessionStatus.CREATED
    config: dict[str, Any] = field(default_factory=dict)

    # Resources
    agents_active: int = 0
    agents_total: int = 0
    tokens_used: int = 0
    tools_used: list[str] = field(default_factory=list)

    # Results
    findings: list[dict[str, Any]] = field(default_factory=list)
    validated_findings: list[dict[str, Any]] = field(default_factory=list)

    # History
    events: list[SessionEvent] = field(default_factory=list)

    # Timing
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id,
            "name": self.name[:80],
            "target": self.target,
            "status": self.status.value,
            "agents": f"{self.agents_active}/{self.agents_total}",
            "findings": len(self.findings),
            "validated": len(self.validated_findings),
            "tokens": self.tokens_used,
            "duration_s": round(self.duration_s, 1),
        }


class SessionManager:
    """Manages assessment sessions.

    Creates, tracks, and persists sessions with
    full event history and audit trail.
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        persistence_dir: str = "data/sessions",
    ) -> None:
        self._max_concurrent = max_concurrent
        self._sessions: dict[str, Session] = {}
        self._session_counter = 0
        self._event_counter = 0
        self._persistence_dir = Path(persistence_dir)
        self._persistence_dir.mkdir(parents=True, exist_ok=True)
        self._listeners: list[Any] = []
        self._log = logger.bind(component="session_manager")

        self._load_sessions()

    def create_session(
        self,
        target: str,
        goal: str = "",
        name: str = "",
        config: dict[str, Any] | None = None,
    ) -> Session:
        """Create a new assessment session."""
        active = sum(
            1 for s in self._sessions.values()
            if s.status == SessionStatus.RUNNING
        )
        if active >= self._max_concurrent:
            self._log.warning("max_concurrent_reached", active=active)

        self._session_counter += 1
        session_id = f"session-{self._session_counter}"

        session = Session(
            session_id=session_id,
            name=name or f"Assessment of {target}",
            target=target,
            goal=goal or f"Security assessment of {target}",
            config=config or {},
        )

        self._sessions[session_id] = session
        self._add_event(session_id, "created", {"target": target})

        return session

    def start_session(self, session_id: str) -> bool:
        """Start a session."""
        session = self._sessions.get(session_id)
        if not session or session.status != SessionStatus.CREATED:
            return False

        session.status = SessionStatus.RUNNING
        session.started_at = time.time()
        self._add_event(session_id, "started", {})
        return True

    def pause_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session or session.status != SessionStatus.RUNNING:
            return False
        session.status = SessionStatus.PAUSED
        self._add_event(session_id, "paused", {})
        return True

    def resume_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session or session.status != SessionStatus.PAUSED:
            return False
        session.status = SessionStatus.RUNNING
        self._add_event(session_id, "resumed", {})
        return True

    def complete_session(
        self,
        session_id: str,
        findings: list[dict[str, Any]] | None = None,
        validated: list[dict[str, Any]] | None = None,
    ) -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.status = SessionStatus.COMPLETED
        session.completed_at = time.time()
        if findings:
            session.findings = findings
        if validated:
            session.validated_findings = validated

        self._add_event(session_id, "completed", {
            "findings": len(session.findings),
            "validated": len(session.validated_findings),
            "duration_s": session.duration_s,
        })

        self._save_session(session)
        return True

    def fail_session(self, session_id: str, error: str = "") -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.status = SessionStatus.FAILED
        session.completed_at = time.time()
        self._add_event(session_id, "failed", {"error": error[:200]})
        self._save_session(session)
        return True

    def cancel_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.status = SessionStatus.CANCELLED
        session.completed_at = time.time()
        self._add_event(session_id, "cancelled", {})
        self._save_session(session)
        return True

    def add_finding(self, session_id: str, finding: dict[str, Any]) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.findings.append(finding)
            self._add_event(session_id, "finding", {
                "title": finding.get("title", "")[:80],
                "severity": finding.get("severity", ""),
            })

    def record_tool_use(self, session_id: str, tool: str) -> None:
        session = self._sessions.get(session_id)
        if session and tool not in session.tools_used:
            session.tools_used.append(tool)

    def record_agent(self, session_id: str, active: int, total: int) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.agents_active = active
            session.agents_total = total

    def record_tokens(self, session_id: str, tokens: int) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.tokens_used += tokens

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def get_all_sessions(self) -> list[Session]:
        return list(self._sessions.values())

    def get_active_sessions(self) -> list[Session]:
        return [
            s for s in self._sessions.values()
            if s.status == SessionStatus.RUNNING
        ]

    def get_events(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        session = self._sessions.get(session_id)
        if not session:
            return []
        return [e.to_dict() for e in session.events[-limit:]]

    # ── Internal ─────────────────────────────────────────

    def _add_event(
        self,
        session_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Add an event to a session."""
        self._event_counter += 1
        event = SessionEvent(
            event_id=f"ev-{self._event_counter}",
            event_type=event_type,
            data=data,
        )

        session = self._sessions.get(session_id)
        if session:
            session.events.append(event)
            # Keep events bounded
            if len(session.events) > 200:
                session.events = session.events[-200:]

    def _save_session(self, session: Session) -> None:
        """Persist a session to disk."""
        try:
            path = self._persistence_dir / f"{session.session_id}.json"
            data = session.to_dict()
            data["events"] = [e.to_dict() for e in session.events[-50:]]
            data["findings_data"] = session.findings[:100]
            path.write_text(json.dumps(data))
        except OSError:
            pass

    def _load_sessions(self) -> None:
        """Load persisted sessions."""
        try:
            for path in self._persistence_dir.glob("session-*.json"):
                data = json.loads(path.read_text())
                session_id = data.get("id", "")
                if session_id and session_id not in self._sessions:
                    session = Session(
                        session_id=session_id,
                        name=data.get("name", ""),
                        target=data.get("target", ""),
                        status=SessionStatus.COMPLETED,
                        findings=data.get("findings_data", []),
                    )
                    self._sessions[session_id] = session
        except (json.JSONDecodeError, OSError):
            pass

    def get_stats(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        for session in self._sessions.values():
            by_status.setdefault(session.status.value, 0)
            by_status[session.status.value] += 1

        return {
            "total": len(self._sessions),
            "by_status": by_status,
            "active": len(self.get_active_sessions()),
        }
