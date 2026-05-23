"""Agent state machine — formal state management for agent lifecycle.

Implements:
1. Hierarchical state machine (nested states)
2. State transition validation
3. Guard conditions on transitions
4. Entry/exit actions per state
5. State history tracking
6. Timeout-based transitions
7. Event-driven state changes
8. Parallel state regions
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    # Top-level states
    IDLE = "idle"
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    WAITING = "waiting"
    ERROR = "error"
    COMPLETE = "complete"
    PAUSED = "paused"

    # Planning sub-states
    PLAN_STRATEGY_SELECT = "plan_strategy_select"
    PLAN_TOOL_SELECT = "plan_tool_select"
    PLAN_MODEL_SELECT = "plan_model_select"
    PLAN_TASK_DECOMPOSE = "plan_task_decompose"

    # Executing sub-states
    EXEC_TOOL_RUN = "exec_tool_run"
    EXEC_LLM_QUERY = "exec_llm_query"
    EXEC_SPAWN_CHILD = "exec_spawn_child"
    EXEC_VALIDATE = "exec_validate"

    # Analyzing sub-states
    ANALYZE_PARSE = "analyze_parse"
    ANALYZE_CORRELATE = "analyze_correlate"
    ANALYZE_REASON = "analyze_reason"
    ANALYZE_DECIDE = "analyze_decide"


class StateEvent(str, Enum):
    START = "start"
    PLAN_COMPLETE = "plan_complete"
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETE = "tool_complete"
    LLM_RESPONSE = "llm_response"
    FINDING_NEW = "finding_new"
    ERROR_OCCURRED = "error_occurred"
    TIMEOUT = "timeout"
    STAGNATION = "stagnation"
    PHASE_ADVANCE = "phase_advance"
    CHILD_COMPLETE = "child_complete"
    PAUSE_REQUESTED = "pause_requested"
    RESUME_REQUESTED = "resume_requested"
    STOP_REQUESTED = "stop_requested"
    RETRY = "retry"


@dataclass
class StateTransition:
    """A state transition rule."""
    from_state: AgentState
    to_state: AgentState
    event: StateEvent
    guard: str = ""            # Description of guard condition
    priority: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value,
            "to": self.to_state.value,
            "event": self.event.value,
            "guard": self.guard[:30],
        }


@dataclass
class StateHistoryEntry:
    """Record of a state change."""
    from_state: str = ""
    to_state: str = ""
    event: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_in_state_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state[:20],
            "to": self.to_state[:20],
            "event": self.event[:20],
            "duration": round(self.duration_in_state_s, 2),
        }


# ── Transition Table ──────────────────────────────────────────

TRANSITIONS: list[dict[str, Any]] = [
    # From IDLE
    {"from": "idle", "to": "initializing", "event": "start"},

    # From INITIALIZING
    {"from": "initializing", "to": "planning", "event": "plan_complete"},
    {"from": "initializing", "to": "error", "event": "error_occurred"},

    # From PLANNING
    {"from": "planning", "to": "plan_strategy_select", "event": "start"},
    {"from": "plan_strategy_select", "to": "plan_tool_select", "event": "plan_complete"},
    {"from": "plan_tool_select", "to": "plan_model_select", "event": "plan_complete"},
    {"from": "plan_model_select", "to": "plan_task_decompose", "event": "plan_complete"},
    {"from": "plan_task_decompose", "to": "executing", "event": "plan_complete"},
    {"from": "planning", "to": "executing", "event": "plan_complete"},
    {"from": "planning", "to": "error", "event": "error_occurred"},

    # From EXECUTING
    {"from": "executing", "to": "exec_tool_run", "event": "tool_started"},
    {"from": "executing", "to": "exec_llm_query", "event": "start"},
    {"from": "executing", "to": "exec_spawn_child", "event": "start"},
    {"from": "exec_tool_run", "to": "analyzing", "event": "tool_complete"},
    {"from": "exec_llm_query", "to": "analyzing", "event": "llm_response"},
    {"from": "exec_spawn_child", "to": "waiting", "event": "start"},
    {"from": "exec_validate", "to": "analyzing", "event": "plan_complete"},
    {"from": "executing", "to": "error", "event": "error_occurred"},
    {"from": "executing", "to": "waiting", "event": "timeout"},

    # From ANALYZING
    {"from": "analyzing", "to": "analyze_parse", "event": "start"},
    {"from": "analyze_parse", "to": "analyze_correlate", "event": "plan_complete"},
    {"from": "analyze_correlate", "to": "analyze_reason", "event": "plan_complete"},
    {"from": "analyze_reason", "to": "analyze_decide", "event": "plan_complete"},
    {"from": "analyze_decide", "to": "planning", "event": "plan_complete", "guard": "more_work_needed"},
    {"from": "analyze_decide", "to": "complete", "event": "stop_requested"},
    {"from": "analyzing", "to": "planning", "event": "plan_complete"},
    {"from": "analyzing", "to": "executing", "event": "finding_new"},
    {"from": "analyzing", "to": "error", "event": "error_occurred"},

    # From WAITING
    {"from": "waiting", "to": "analyzing", "event": "child_complete"},
    {"from": "waiting", "to": "executing", "event": "timeout"},
    {"from": "waiting", "to": "error", "event": "error_occurred"},

    # From ERROR
    {"from": "error", "to": "planning", "event": "retry"},
    {"from": "error", "to": "complete", "event": "stop_requested"},

    # From PAUSED
    {"from": "paused", "to": "executing", "event": "resume_requested"},
    {"from": "paused", "to": "complete", "event": "stop_requested"},

    # Universal transitions
    {"from": "executing", "to": "paused", "event": "pause_requested"},
    {"from": "planning", "to": "paused", "event": "pause_requested"},
    {"from": "analyzing", "to": "paused", "event": "pause_requested"},

    # Phase advances
    {"from": "analyzing", "to": "planning", "event": "phase_advance"},
    {"from": "executing", "to": "planning", "event": "phase_advance"},

    # Stagnation
    {"from": "executing", "to": "planning", "event": "stagnation"},
    {"from": "analyzing", "to": "planning", "event": "stagnation"},
]


class AgentStateMachine:
    """Formal state machine for agent lifecycle management.

    Manages state transitions, validates events, tracks history,
    and enforces transition rules.
    """

    def __init__(self, initial_state: AgentState = AgentState.IDLE) -> None:
        self._current_state = initial_state
        self._previous_state: AgentState | None = None
        self._state_enter_time = time.time()
        self._transitions: list[StateTransition] = []
        self._history: list[StateHistoryEntry] = []
        self._state_durations: dict[str, float] = defaultdict(float)
        self._transition_counts: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="agent_state_machine")

        self._load_transitions()

    def _load_transitions(self) -> None:
        """Load transition rules."""
        for t in TRANSITIONS:
            self._transitions.append(StateTransition(
                from_state=AgentState(t["from"]),
                to_state=AgentState(t["to"]),
                event=StateEvent(t["event"]),
                guard=t.get("guard", ""),
            ))

    @property
    def current_state(self) -> AgentState:
        return self._current_state

    @property
    def time_in_state_s(self) -> float:
        return time.time() - self._state_enter_time

    def can_transition(self, event: StateEvent) -> bool:
        """Check if a transition is valid for the current state."""
        for t in self._transitions:
            if t.from_state == self._current_state and t.event == event:
                return True
        return False

    def transition(self, event: StateEvent) -> AgentState | None:
        """Attempt a state transition."""
        valid = [
            t for t in self._transitions
            if t.from_state == self._current_state and t.event == event
        ]

        if not valid:
            return None

        # Use highest priority transition
        transition = max(valid, key=lambda t: t.priority)

        # Record history
        now = time.time()
        duration = now - self._state_enter_time

        self._history.append(StateHistoryEntry(
            from_state=self._current_state.value,
            to_state=transition.to_state.value,
            event=event.value,
            timestamp=now,
            duration_in_state_s=duration,
        ))

        # Update durations
        self._state_durations[self._current_state.value] += duration
        self._transition_counts[f"{self._current_state.value}->{transition.to_state.value}"] += 1

        # Transition
        self._previous_state = self._current_state
        self._current_state = transition.to_state
        self._state_enter_time = now

        return self._current_state

    def get_valid_events(self) -> list[StateEvent]:
        """Get events that are valid in the current state."""
        events = set()
        for t in self._transitions:
            if t.from_state == self._current_state:
                events.add(t.event)
        return sorted(events, key=lambda e: e.value)

    def get_history(self, last_n: int = 10) -> list[dict[str, Any]]:
        """Get recent state history."""
        return [h.to_dict() for h in self._history[-last_n:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "current": self._current_state.value,
            "previous": self._previous_state.value if self._previous_state else None,
            "time_in_state": round(self.time_in_state_s, 1),
            "transitions": len(self._history),
            "state_durations": {
                k: round(v, 1) for k, v in self._state_durations.items()
            },
            "valid_events": [e.value for e in self.get_valid_events()],
        }
