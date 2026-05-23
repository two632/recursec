"""Session manager — manages assessment session lifecycle.

Implements:
1. Session creation and configuration
2. Session state persistence
3. Session resume from checkpoint
4. Session metrics tracking
5. Multi-session management
6. Session export and import
7. Session comparison
8. Session cleanup
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SessionConfig:
    """Configuration for a session."""
    target: str = ""
    target_type: str = "web_app"
    stealth_mode: bool = False
    validate_findings: bool = True
    deep_mode: bool = False
    max_time_s: float = 3600.0
    token_budget: int = 5_000_000
    max_agents: int = 20
    custom_config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:40], "type": self.target_type,
            "stealth": self.stealth_mode,
            "validate": self.validate_findings,
            "deep": self.deep_mode,
            "max_time_s": self.max_time_s,
            "budget": self.token_budget,
        }


@dataclass
class SessionMetrics:
    """Metrics for a session."""
    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    tools_run: int = 0
    agents_spawned: int = 0
    tokens_used: int = 0
    models_used: set[str] = field(default_factory=set)
    errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings_total,
            "critical": self.findings_critical,
            "high": self.findings_high,
            "medium": self.findings_medium,
            "low": self.findings_low,
            "tools": self.tools_run,
            "agents": self.agents_spawned,
            "tokens": self.tokens_used,
            "models": len(self.models_used),
            "errors": self.errors,
        }


@dataclass
class Session:
    """An assessment session."""
    session_id: str = ""
    config: SessionConfig = field(default_factory=SessionConfig)
    status: str = "created"        # created, running, paused, completed, failed
    metrics: SessionMetrics = field(default_factory=SessionMetrics)
    findings: list[dict[str, Any]] = field(default_factory=list)
    phase: str = ""                # Current phase
    checkpoint: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    tags: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id,
            "target": self.config.target[:40],
            "status": self.status,
            "phase": self.phase[:20],
            "findings": self.metrics.findings_total,
            "duration_s": round(self.duration_s, 0),
        }


class SessionManager:
    """Manages assessment session lifecycle.

    Creates, tracks, persists, and resumes
    security assessment sessions.
    """

    def __init__(self, data_dir: str = "data/sessions") -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, Session] = {}
        self._session_counter = 0
        self._active_session: str = ""
        self._log = logger.bind(component="session_manager")

    def create(
        self,
        target: str,
        target_type: str = "web_app",
        config: SessionConfig | None = None,
        tags: list[str] | None = None,
    ) -> Session:
        """Create a new session."""
        self._session_counter += 1
        session_id = f"session-{self._session_counter}"

        if config is None:
            config = SessionConfig(target=target, target_type=target_type)
        else:
            config.target = target
            config.target_type = target_type

        session = Session(
            session_id=session_id,
            config=config,
            tags=tags or [],
        )

        self._sessions[session_id] = session
        return session

    def start(self, session_id: str) -> bool:
        """Start a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.status = "running"
        session.started_at = time.time()
        self._active_session = session_id
        return True

    def pause(self, session_id: str) -> bool:
        """Pause a session."""
        session = self._sessions.get(session_id)
        if not session or session.status != "running":
            return False

        session.status = "paused"
        self._save_checkpoint(session)
        return True

    def resume(self, session_id: str) -> bool:
        """Resume a paused session."""
        session = self._sessions.get(session_id)
        if not session or session.status != "paused":
            return False

        session.status = "running"
        self._active_session = session_id
        return True

    def complete(self, session_id: str) -> bool:
        """Complete a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.status = "completed"
        session.completed_at = time.time()
        self._save_session(session)

        if self._active_session == session_id:
            self._active_session = ""

        return True

    def fail(self, session_id: str, error: str = "") -> bool:
        """Mark a session as failed."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.status = "failed"
        session.completed_at = time.time()
        session.checkpoint["error"] = error
        self._save_session(session)
        return True

    def add_finding(
        self,
        session_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add a finding to a session."""
        session = self._sessions.get(session_id)
        if not session:
            return

        session.findings.append(finding)
        session.metrics.findings_total += 1

        severity = finding.get("severity", "info")
        if severity == "critical":
            session.metrics.findings_critical += 1
        elif severity == "high":
            session.metrics.findings_high += 1
        elif severity == "medium":
            session.metrics.findings_medium += 1
        elif severity == "low":
            session.metrics.findings_low += 1

    def record_tool_run(
        self,
        session_id: str,
        tool: str = "",
        tokens: int = 0,
        model: str = "",
    ) -> None:
        """Record a tool run in the session."""
        session = self._sessions.get(session_id)
        if not session:
            return

        session.metrics.tools_run += 1
        session.metrics.tokens_used += tokens
        if model:
            session.metrics.models_used.add(model)

    def set_phase(self, session_id: str, phase: str) -> None:
        """Set the current phase of a session."""
        session = self._sessions.get(session_id)
        if session:
            session.phase = phase

    def get_active(self) -> Session | None:
        """Get the currently active session."""
        if self._active_session:
            return self._sessions.get(self._active_session)
        return None

    def _save_checkpoint(self, session: Session) -> None:
        """Save a session checkpoint."""
        session.checkpoint = {
            "phase": session.phase,
            "findings_count": session.metrics.findings_total,
            "timestamp": time.time(),
        }
        self._save_session(session)

    def _save_session(self, session: Session) -> None:
        """Save session to disk."""
        try:
            path = self._data_dir / f"{session.session_id}.json"
            data = {
                "id": session.session_id,
                "config": session.config.to_dict(),
                "status": session.status,
                "metrics": session.metrics.to_dict(),
                "findings_count": len(session.findings),
                "phase": session.phase,
                "checkpoint": session.checkpoint,
                "created_at": session.created_at,
                "started_at": session.started_at,
                "completed_at": session.completed_at,
                "tags": session.tags,
            }
            path.write_text(json.dumps(data, indent=2, default=str))
        except OSError:
            pass

    def load_session(self, session_id: str) -> Session | None:
        """Load a session from disk."""
        path = self._data_dir / f"{session_id}.json"
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text())
            session = Session(
                session_id=data["id"],
                status=data.get("status", "completed"),
                phase=data.get("phase", ""),
                checkpoint=data.get("checkpoint", {}),
                created_at=data.get("created_at", 0),
                started_at=data.get("started_at", 0),
                completed_at=data.get("completed_at", 0),
                tags=data.get("tags", []),
            )
            self._sessions[session_id] = session
            return session
        except (json.JSONDecodeError, OSError, KeyError):
            return None

    def compare(
        self,
        session_id_1: str,
        session_id_2: str,
    ) -> dict[str, Any]:
        """Compare two sessions."""
        s1 = self._sessions.get(session_id_1)
        s2 = self._sessions.get(session_id_2)

        if not s1 or not s2:
            return {"error": "session_not_found"}

        return {
            "session_1": s1.to_dict(),
            "session_2": s2.to_dict(),
            "findings_diff": s1.metrics.findings_total - s2.metrics.findings_total,
            "critical_diff": s1.metrics.findings_critical - s2.metrics.findings_critical,
            "duration_diff": round(s1.duration_s - s2.duration_s, 0),
            "token_diff": s1.metrics.tokens_used - s2.metrics.tokens_used,
        }

    def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        return [s.to_dict() for s in list(self._sessions.values())[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for session in self._sessions.values():
            status_counts[session.status] += 1

        return {
            "total": len(self._sessions),
            "active": self._active_session or "none",
            "status": dict(status_counts),
        }


