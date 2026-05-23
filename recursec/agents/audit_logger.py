"""Audit logger — comprehensive audit trail of all agent decisions and actions.

Implements:
1. Structured audit event recording
2. Agent decision logging
3. Tool execution logging
4. LLM inference logging
5. Finding lifecycle tracking
6. Access control logging
7. Audit log search and filtering
8. Audit log persistence and rotation
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class AuditEventType(str, Enum):
    AGENT_SPAWN = "agent_spawn"
    AGENT_COMPLETE = "agent_complete"
    AGENT_FAIL = "agent_fail"
    TOOL_EXECUTE = "tool_execute"
    TOOL_RESULT = "tool_result"
    LLM_INFERENCE = "llm_inference"
    LLM_RESPONSE = "llm_response"
    FINDING_NEW = "finding_new"
    FINDING_VALIDATED = "finding_validated"
    FINDING_REJECTED = "finding_rejected"
    DECISION_MADE = "decision_made"
    SCOPE_CHECK = "scope_check"
    SCOPE_VIOLATION = "scope_violation"
    SAFETY_CHECK = "safety_check"
    SAFETY_BLOCK = "safety_block"
    GOAL_SET = "goal_set"
    GOAL_ACHIEVED = "goal_achieved"
    PHASE_CHANGE = "phase_change"
    ERROR = "error"
    CONFIG_CHANGE = "config_change"


class AuditSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """A single audit event."""
    event_id: str = ""
    event_type: AuditEventType = AuditEventType.AGENT_SPAWN
    severity: AuditSeverity = AuditSeverity.INFO
    agent_id: str = ""
    session_id: str = ""
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    target: str = ""
    tool: str = ""
    model: str = ""
    tokens: int = 0
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.event_id,
            "type": self.event_type.value,
            "severity": self.severity.value,
            "desc": self.description[:60],
            "ts": self.timestamp,
        }
        if self.agent_id:
            result["agent"] = self.agent_id[:15]
        if self.tool:
            result["tool"] = self.tool[:20]
        if self.model:
            result["model"] = self.model[:20]
        if self.tokens:
            result["tokens"] = self.tokens
        return result

    def to_json_line(self) -> str:
        """Serialize to a single JSON line."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Comprehensive audit trail of all agent decisions and actions.

    Records every significant event for accountability,
    debugging, and learning.
    """

    def __init__(
        self,
        data_dir: str = "data/audit",
        max_memory_events: int = 5000,
        rotation_size: int = 10000,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._events: list[AuditEvent] = []
        self._event_counter = 0
        self._max_memory = max_memory_events
        self._rotation_size = rotation_size
        self._current_log_file: Path | None = None
        self._written_count = 0
        self._type_counts: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="audit_logger")

    def log(
        self,
        event_type: AuditEventType,
        description: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        agent_id: str = "",
        session_id: str = "",
        details: dict[str, Any] | None = None,
        target: str = "",
        tool: str = "",
        model: str = "",
        tokens: int = 0,
        duration_s: float = 0.0,
    ) -> str:
        """Log an audit event."""
        self._event_counter += 1
        event_id = f"audit-{self._event_counter}"

        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            severity=severity,
            agent_id=agent_id,
            session_id=session_id,
            description=description,
            details=details or {},
            target=target,
            tool=tool,
            model=model,
            tokens=tokens,
            duration_s=duration_s,
        )

        self._events.append(event)
        self._type_counts[event_type.value] += 1

        # Persist to file
        self._write_event(event)

        # Memory management
        if len(self._events) > self._max_memory:
            self._events = self._events[-self._max_memory:]

        return event_id

    # ── Convenience methods ────────────────────────────────────

    def log_agent_spawn(
        self,
        agent_id: str,
        role: str,
        model: str = "",
        parent_id: str = "",
    ) -> str:
        return self.log(
            AuditEventType.AGENT_SPAWN,
            f"Agent spawned: {role}",
            agent_id=agent_id,
            model=model,
            details={"role": role, "parent": parent_id},
        )

    def log_tool_execute(
        self,
        agent_id: str,
        tool: str,
        target: str = "",
        args: list[str] | None = None,
    ) -> str:
        return self.log(
            AuditEventType.TOOL_EXECUTE,
            f"Tool: {tool}",
            agent_id=agent_id,
            tool=tool,
            target=target,
            details={"args": (args or [])[:5]},
        )

    def log_inference(
        self,
        agent_id: str,
        model: str,
        tokens: int = 0,
        duration_s: float = 0.0,
    ) -> str:
        return self.log(
            AuditEventType.LLM_INFERENCE,
            f"Inference: {model}",
            agent_id=agent_id,
            model=model,
            tokens=tokens,
            duration_s=duration_s,
        )

    def log_finding(
        self,
        agent_id: str,
        title: str,
        severity: str = "medium",
        target: str = "",
    ) -> str:
        audit_sev = AuditSeverity.WARNING
        if severity in ("critical", "high"):
            audit_sev = AuditSeverity.CRITICAL

        return self.log(
            AuditEventType.FINDING_NEW,
            f"Finding: {title[:40]}",
            severity=audit_sev,
            agent_id=agent_id,
            target=target,
            details={"severity": severity},
        )

    def log_safety_block(
        self,
        agent_id: str,
        reason: str,
    ) -> str:
        return self.log(
            AuditEventType.SAFETY_BLOCK,
            f"Safety blocked: {reason[:40]}",
            severity=AuditSeverity.WARNING,
            agent_id=agent_id,
        )

    def log_error(
        self,
        agent_id: str,
        error: str,
    ) -> str:
        return self.log(
            AuditEventType.ERROR,
            f"Error: {error[:60]}",
            severity=AuditSeverity.CRITICAL,
            agent_id=agent_id,
        )

    # ── Query methods ──────────────────────────────────────────

    def search(
        self,
        event_type: AuditEventType | None = None,
        agent_id: str = "",
        severity: AuditSeverity | None = None,
        since: float = 0.0,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Search audit events."""
        results = []

        for event in reversed(self._events):
            if event_type and event.event_type != event_type:
                continue
            if agent_id and event.agent_id != agent_id:
                continue
            if severity and event.severity != severity:
                continue
            if since and event.timestamp < since:
                continue

            results.append(event.to_dict())
            if len(results) >= limit:
                break

        return results

    def get_agent_trail(self, agent_id: str) -> list[dict[str, Any]]:
        """Get the complete audit trail for an agent."""
        return [
            e.to_dict() for e in self._events
            if e.agent_id == agent_id
        ]

    # ── Persistence ────────────────────────────────────────────

    def _write_event(self, event: AuditEvent) -> None:
        """Write an event to the log file."""
        if not self._current_log_file or self._written_count >= self._rotation_size:
            self._rotate_log()

        try:
            with open(self._current_log_file, "a") as f:
                f.write(event.to_json_line() + "\n")
            self._written_count += 1
        except OSError:
            pass

    def _rotate_log(self) -> None:
        """Rotate to a new log file."""
        timestamp = int(time.time())
        self._current_log_file = self._data_dir / f"audit_{timestamp}.jsonl"
        self._written_count = 0

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_events": self._event_counter,
            "in_memory": len(self._events),
            "type_counts": dict(self._type_counts),
        }
