"""Session manager — assessment session lifecycle.

Implements:
1. Session creation and tracking
2. Session state machine
3. Findings aggregation
4. Session export (JSON/JSONL)
5. Session comparison
6. Session templates
7. Session metrics
8. Multi-target session management
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SessionState(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETING = "completing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A security finding."""
    finding_id: str = ""
    title: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    category: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    target: str = ""
    tool: str = ""
    model: str = ""
    confidence: float = 0.8
    confirmed: bool = False
    cwe: str = ""
    cvss: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "title": self.title[:40],
            "severity": self.severity.value,
            "category": self.category[:15],
            "confidence": round(self.confidence, 2),
            "confirmed": self.confirmed,
            "cwe": self.cwe[:10],
            "cvss": self.cvss,
        }


@dataclass
class SessionTarget:
    """A target within a session."""
    target: str = ""
    target_type: str = ""        # ip, domain, url, cidr
    findings_count: int = 0
    tools_used: list[str] = field(default_factory=list)
    scan_start: float = 0.0
    scan_end: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:30],
            "type": self.target_type[:8],
            "findings": self.findings_count,
            "tools": len(self.tools_used),
        }


@dataclass
class Session:
    """A security assessment session."""
    session_id: str = ""
    name: str = ""
    state: SessionState = SessionState.CREATED
    targets: list[SessionTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    goal: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    total_tokens: int = 0
    total_tool_calls: int = 0
    total_llm_calls: int = 0
    agents_spawned: int = 0
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        if self.started_at > 0 and self.completed_at > 0:
            return self.completed_at - self.started_at
        if self.started_at > 0:
            return time.time() - self.started_at
        return 0.0

    @property
    def finding_counts(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity.value] += 1
        return dict(counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:12],
            "state": self.state.value,
            "targets": len(self.targets),
            "findings": len(self.findings),
            "by_severity": self.finding_counts,
            "duration_s": round(self.duration_s, 1),
            "tokens": self.total_tokens,
            "tool_calls": self.total_tool_calls,
            "agents": self.agents_spawned,
        }


class SessionManager:
    """Manages security assessment sessions.

    Tracks session lifecycle, aggregates findings,
    and provides session export capabilities.
    """

    def __init__(self, data_dir: str = "") -> None:
        self._sessions: dict[str, Session] = {}
        self._counter = 0
        self._data_dir = data_dir or os.path.expanduser("~/.recursec/sessions")
        self._log = logger.bind(component="session_manager")

    def create(
        self,
        targets: list[str],
        goal: str = "",
        name: str = "",
        config: dict[str, Any] | None = None,
    ) -> Session:
        """Create a new session."""
        self._counter += 1
        ts = int(time.time())

        target_hash = hashlib.md5(",".join(targets).encode()).hexdigest()[:6]
        session_id = f"sess-{ts}-{target_hash}"

        session = Session(
            session_id=session_id,
            name=name or f"Assessment {self._counter}",
            goal=goal,
            targets=[SessionTarget(target=t) for t in targets],
            config=config or {},
        )

        self._sessions[session_id] = session
        return session

    def start(self, session_id: str) -> bool:
        """Start a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        session.state = SessionState.RUNNING
        session.started_at = time.time()
        return True

    def pause(self, session_id: str) -> bool:
        """Pause a session."""
        session = self._sessions.get(session_id)
        if not session or session.state != SessionState.RUNNING:
            return False
        session.state = SessionState.PAUSED
        return True

    def resume(self, session_id: str) -> bool:
        """Resume a paused session."""
        session = self._sessions.get(session_id)
        if not session or session.state != SessionState.PAUSED:
            return False
        session.state = SessionState.RUNNING
        return True

    def complete(self, session_id: str) -> bool:
        """Mark a session as complete."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.state = SessionState.COMPLETE
        session.completed_at = time.time()
        return True

    def fail(self, session_id: str, reason: str = "") -> bool:
        """Mark a session as failed."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.state = SessionState.FAILED
        session.completed_at = time.time()
        return True

    def add_finding(
        self,
        session_id: str,
        title: str,
        severity: FindingSeverity,
        category: str = "",
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        target: str = "",
        tool: str = "",
        model: str = "",
        confidence: float = 0.8,
        confirmed: bool = False,
        cwe: str = "",
        cvss: float = 0.0,
    ) -> Finding | None:
        """Add a finding to a session."""
        session = self._sessions.get(session_id)
        if not session:
            return None

        self._counter += 1
        finding = Finding(
            finding_id=f"find-{self._counter}",
            title=title,
            severity=severity,
            category=category,
            description=description,
            evidence=evidence,
            remediation=remediation,
            target=target,
            tool=tool,
            model=model,
            confidence=confidence,
            confirmed=confirmed,
            cwe=cwe,
            cvss=cvss,
        )

        session.findings.append(finding)

        # Update target findings count
        for st in session.targets:
            if st.target == target:
                st.findings_count += 1
                break

        return finding

    def update_metrics(
        self,
        session_id: str,
        tokens: int = 0,
        tool_calls: int = 0,
        llm_calls: int = 0,
        agents: int = 0,
    ) -> None:
        """Update session metrics."""
        session = self._sessions.get(session_id)
        if not session:
            return
        session.total_tokens += tokens
        session.total_tool_calls += tool_calls
        session.total_llm_calls += llm_calls
        session.agents_spawned += agents

    def export_json(self, session_id: str) -> str:
        """Export session as JSON."""
        session = self._sessions.get(session_id)
        if not session:
            return "{}"

        data = {
            "session": session.to_dict(),
            "targets": [t.to_dict() for t in session.targets],
            "findings": [f.to_dict() for f in session.findings],
            "goal": session.goal,
            "config": session.config,
        }
        return json.dumps(data, indent=2)

    def export_findings_jsonl(self, session_id: str) -> str:
        """Export findings as JSONL (one JSON per line)."""
        session = self._sessions.get(session_id)
        if not session:
            return ""

        lines = []
        for f in session.findings:
            lines.append(json.dumps(f.to_dict()))
        return "\n".join(lines)

    def compare_sessions(
        self,
        session_id_a: str,
        session_id_b: str,
    ) -> dict[str, Any]:
        """Compare two sessions."""
        a = self._sessions.get(session_id_a)
        b = self._sessions.get(session_id_b)
        if not a or not b:
            return {"error": "Session not found"}

        a_titles = {f.title for f in a.findings}
        b_titles = {f.title for f in b.findings}

        return {
            "session_a": session_id_a,
            "session_b": session_id_b,
            "findings_a": len(a.findings),
            "findings_b": len(b.findings),
            "common": len(a_titles & b_titles),
            "only_a": len(a_titles - b_titles),
            "only_b": len(b_titles - a_titles),
            "new_in_b": list(b_titles - a_titles)[:10],
            "resolved_in_b": list(a_titles - b_titles)[:10],
        }

    def get_session(self, session_id: str) -> Session | None:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all sessions."""
        return [s.to_dict() for s in self._sessions.values()]

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = defaultdict(int)
        total_findings = 0
        for s in self._sessions.values():
            state_counts[s.state.value] += 1
            total_findings += len(s.findings)

        return {
            "sessions": len(self._sessions),
            "total_findings": total_findings,
            "by_state": dict(state_counts),
        }
