"""Agent introspection — real-time monitoring and analysis of agent behavior.

Provides visibility into:
1. Agent decision-making process
2. Resource consumption patterns
3. Communication patterns between agents
4. Performance bottlenecks
5. Anomaly detection in agent behavior
6. Execution timeline and gantt visualization data
7. Agent health metrics

Used for:
- Debugging agent behavior
- Optimizing performance
- Detecting stuck or looping agents
- Understanding multi-agent dynamics
- Generating execution reports
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    AGENT_ERROR = "agent_error"
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    TASK_FAIL = "task_fail"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    FINDING_ADDED = "finding_added"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    STATE_CHANGE = "state_change"
    DECISION = "decision"
    BUDGET_ALERT = "budget_alert"
    SPAWN_AGENT = "spawn_agent"
    COLLECT_RESULT = "collect_result"


@dataclass
class IntrospectionEvent:
    """A single event in the agent execution timeline."""
    event_id: str = ""
    event_type: EventType = EventType.AGENT_START
    agent_id: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)
    parent_event_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "type": self.event_type.value,
            "agent": self.agent_id,
            "time": self.timestamp,
            "duration_ms": round(self.duration_ms, 1),
            "data": {k: str(v)[:200] for k, v in list(self.data.items())[:5]},
        }


@dataclass
class AgentProfile:
    """Performance profile for a single agent."""
    agent_id: str = ""
    agent_role: str = ""
    total_events: int = 0
    total_llm_calls: int = 0
    total_tool_calls: int = 0
    total_findings: int = 0
    total_messages_sent: int = 0
    total_messages_received: int = 0
    total_tokens_used: int = 0
    total_time_ms: float = 0.0
    avg_llm_latency_ms: float = 0.0
    avg_tool_latency_ms: float = 0.0
    error_count: int = 0
    state_transitions: list[str] = field(default_factory=list)
    decisions_made: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id,
            "role": self.agent_role,
            "events": self.total_events,
            "llm_calls": self.total_llm_calls,
            "tool_calls": self.total_tool_calls,
            "findings": self.total_findings,
            "tokens": self.total_tokens_used,
            "time_ms": round(self.total_time_ms, 1),
            "errors": self.error_count,
        }


@dataclass
class AnomalyAlert:
    """An anomaly detected in agent behavior."""
    alert_id: str = ""
    agent_id: str = ""
    anomaly_type: str = ""  # stuck_loop, excessive_tokens, no_progress, etc.
    description: str = ""
    severity: str = "warning"  # info, warning, critical
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alert_id,
            "agent": self.agent_id,
            "type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description[:200],
        }


class AgentIntrospection:
    """Real-time monitoring and analysis of agent behavior.

    Collects events from all agents and provides:
    - Timeline visualization data
    - Performance profiling
    - Anomaly detection
    - Communication graph
    """

    def __init__(self, max_events: int = 10000) -> None:
        self._events: deque[IntrospectionEvent] = deque(maxlen=max_events)
        self._profiles: dict[str, AgentProfile] = {}
        self._anomalies: list[AnomalyAlert] = []
        self._event_counter = 0

        # Anomaly detection state
        self._agent_action_counts: dict[str, int] = defaultdict(int)
        self._agent_last_finding: dict[str, float] = {}
        self._agent_repeated_actions: dict[str, list[str]] = defaultdict(list)

        self._log = logger.bind(component="introspection")

    def record(
        self,
        event_type: EventType,
        agent_id: str,
        data: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
        parent_event_id: str = "",
    ) -> str:
        """Record an event."""
        self._event_counter += 1
        event = IntrospectionEvent(
            event_id=f"evt-{self._event_counter}",
            event_type=event_type,
            agent_id=agent_id,
            duration_ms=duration_ms,
            data=data or {},
            parent_event_id=parent_event_id,
        )

        self._events.append(event)
        self._update_profile(event)
        self._check_anomalies(event)

        return event.event_id

    def get_profile(self, agent_id: str) -> AgentProfile | None:
        return self._profiles.get(agent_id)

    def get_all_profiles(self) -> dict[str, dict[str, Any]]:
        return {aid: p.to_dict() for aid, p in self._profiles.items()}

    def get_timeline(
        self,
        agent_id: str = "",
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get event timeline, optionally filtered."""
        events = list(self._events)
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in events[-limit:]]

    def get_communication_graph(self) -> dict[str, Any]:
        """Get the inter-agent communication graph."""
        edges: dict[str, int] = defaultdict(int)
        for event in self._events:
            if event.event_type == EventType.MESSAGE_SENT:
                sender = event.agent_id
                receiver = event.data.get("to", "")
                if receiver:
                    edges[f"{sender}->{receiver}"] += 1

        nodes = list(self._profiles.keys())
        return {
            "nodes": nodes,
            "edges": [
                {"from": e.split("->")[0], "to": e.split("->")[1], "count": c}
                for e, c in edges.items()
            ],
        }

    def get_gantt_data(self, agent_id: str = "") -> list[dict[str, Any]]:
        """Get Gantt chart data for execution timeline."""
        tasks = []
        for event in self._events:
            if agent_id and event.agent_id != agent_id:
                continue
            if event.event_type in (EventType.TASK_START, EventType.TOOL_CALL, EventType.LLM_REQUEST):
                tasks.append({
                    "agent": event.agent_id,
                    "type": event.event_type.value,
                    "start": event.timestamp,
                    "duration_ms": event.duration_ms,
                    "label": event.data.get("name", event.data.get("tool", ""))[:50],
                })
        return tasks

    def get_anomalies(self, limit: int = 20) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._anomalies[-limit:]]

    # ── Performance Analysis ─────────────────────────────

    def get_bottlenecks(self) -> list[dict[str, Any]]:
        """Identify performance bottlenecks."""
        bottlenecks = []

        for agent_id, profile in self._profiles.items():
            # Slow LLM calls
            if profile.avg_llm_latency_ms > 5000:
                bottlenecks.append({
                    "agent": agent_id,
                    "type": "slow_llm",
                    "avg_latency_ms": round(profile.avg_llm_latency_ms, 1),
                })

            # Too many errors
            if profile.error_count > 5:
                bottlenecks.append({
                    "agent": agent_id,
                    "type": "high_error_rate",
                    "errors": profile.error_count,
                })

            # Excessive tokens
            if profile.total_tokens_used > 100000:
                bottlenecks.append({
                    "agent": agent_id,
                    "type": "excessive_tokens",
                    "tokens": profile.total_tokens_used,
                })

        return bottlenecks

    def get_summary(self) -> dict[str, Any]:
        """Get overall execution summary."""
        total_events = len(self._events)
        total_findings = sum(p.total_findings for p in self._profiles.values())
        total_tokens = sum(p.total_tokens_used for p in self._profiles.values())
        total_errors = sum(p.error_count for p in self._profiles.values())

        events_by_type: dict[str, int] = defaultdict(int)
        for event in self._events:
            events_by_type[event.event_type.value] += 1

        return {
            "total_events": total_events,
            "total_agents": len(self._profiles),
            "total_findings": total_findings,
            "total_tokens": total_tokens,
            "total_errors": total_errors,
            "total_anomalies": len(self._anomalies),
            "events_by_type": dict(events_by_type),
            "bottlenecks": len(self.get_bottlenecks()),
        }

    # ── Internal ─────────────────────────────────────────

    def _update_profile(self, event: IntrospectionEvent) -> None:
        """Update agent profile from event."""
        agent_id = event.agent_id
        if agent_id not in self._profiles:
            self._profiles[agent_id] = AgentProfile(
                agent_id=agent_id,
                agent_role=event.data.get("role", ""),
            )

        profile = self._profiles[agent_id]
        profile.total_events += 1

        if event.event_type == EventType.LLM_REQUEST:
            profile.total_llm_calls += 1
            if event.duration_ms > 0:
                n = profile.total_llm_calls
                profile.avg_llm_latency_ms = (
                    profile.avg_llm_latency_ms * (n - 1) + event.duration_ms
                ) / n
            profile.total_tokens_used += event.data.get("tokens", 0)

        elif event.event_type == EventType.TOOL_CALL:
            profile.total_tool_calls += 1
            if event.duration_ms > 0:
                n = profile.total_tool_calls
                profile.avg_tool_latency_ms = (
                    profile.avg_tool_latency_ms * (n - 1) + event.duration_ms
                ) / n

        elif event.event_type == EventType.FINDING_ADDED:
            profile.total_findings += 1
            self._agent_last_finding[agent_id] = time.time()

        elif event.event_type == EventType.AGENT_ERROR:
            profile.error_count += 1

        elif event.event_type == EventType.MESSAGE_SENT:
            profile.total_messages_sent += 1

        elif event.event_type == EventType.MESSAGE_RECEIVED:
            profile.total_messages_received += 1

        elif event.event_type == EventType.STATE_CHANGE:
            profile.state_transitions.append(event.data.get("state", ""))

        elif event.event_type == EventType.DECISION:
            profile.decisions_made.append({
                "decision": event.data.get("decision", ""),
                "reasoning": event.data.get("reasoning", "")[:100],
            })
            if len(profile.decisions_made) > 50:
                profile.decisions_made = profile.decisions_made[-50:]

    def _check_anomalies(self, event: IntrospectionEvent) -> None:
        """Check for behavioral anomalies."""
        agent_id = event.agent_id

        # Track action repetition
        action_key = f"{event.event_type.value}:{event.data.get('name', '')}"
        self._agent_repeated_actions[agent_id].append(action_key)
        recent = self._agent_repeated_actions[agent_id][-10:]

        # Stuck loop detection: same action repeated 5+ times
        if len(recent) >= 5 and len(set(recent[-5:])) == 1:
            self._add_anomaly(
                agent_id=agent_id,
                anomaly_type="stuck_loop",
                description=f"Agent repeating same action: {recent[-1][:50]}",
                severity="warning",
            )

        # No progress detection
        self._agent_action_counts[agent_id] += 1
        if self._agent_action_counts[agent_id] > 50:
            last_finding = self._agent_last_finding.get(agent_id, 0)
            if time.time() - last_finding > 300:  # 5 min without finding
                self._add_anomaly(
                    agent_id=agent_id,
                    anomaly_type="no_progress",
                    description="Agent has performed 50+ actions with no findings in 5 minutes",
                    severity="warning",
                )
                self._agent_action_counts[agent_id] = 0

        # Trim stored actions
        if len(self._agent_repeated_actions[agent_id]) > 100:
            self._agent_repeated_actions[agent_id] = self._agent_repeated_actions[agent_id][-100:]

    def _add_anomaly(
        self,
        agent_id: str,
        anomaly_type: str,
        description: str,
        severity: str = "warning",
    ) -> None:
        """Add an anomaly alert."""
        alert = AnomalyAlert(
            alert_id=f"anomaly-{len(self._anomalies)}",
            agent_id=agent_id,
            anomaly_type=anomaly_type,
            description=description,
            severity=severity,
        )
        self._anomalies.append(alert)
        self._log.warning(
            "anomaly_detected",
            agent=agent_id,
            type=anomaly_type,
            severity=severity,
        )
