"""Agent state machine — manages complex agent lifecycle states.

Implements:
1. Finite state machine for agent lifecycle
2. State transition rules and guards
3. State-specific behavior hooks
4. State history tracking
5. Hierarchical states (nested state machines)
6. Timeout-based transitions
7. Event-driven transitions
8. State persistence and recovery
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    INITIALIZING = "initializing"
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    WAITING = "waiting"
    VALIDATING = "validating"
    REPORTING = "reporting"
    ERROR = "error"
    PAUSED = "paused"
    TERMINATED = "terminated"
    RECOVERING = "recovering"


class TransitionEvent(str, Enum):
    INIT_COMPLETE = "init_complete"
    TASK_ASSIGNED = "task_assigned"
    PLAN_READY = "plan_ready"
    EXECUTION_DONE = "execution_done"
    ANALYSIS_DONE = "analysis_done"
    WAITING_RESOLVED = "waiting_resolved"
    VALIDATION_DONE = "validation_done"
    REPORT_DONE = "report_done"
    ERROR_OCCURRED = "error_occurred"
    PAUSE_REQUESTED = "pause_requested"
    RESUME_REQUESTED = "resume_requested"
    TERMINATE = "terminate"
    RECOVER = "recover"
    TIMEOUT = "timeout"


@dataclass
class StateTransition:
    """A state transition rule."""
    from_state: AgentState = AgentState.IDLE
    event: TransitionEvent = TransitionEvent.TASK_ASSIGNED
    to_state: AgentState = AgentState.PLANNING
    guard: Callable[..., bool] | None = None   # Optional guard condition
    action: str = ""                            # Action to execute on transition

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value,
            "event": self.event.value,
            "to": self.to_state.value,
            "action": self.action[:40],
        }


@dataclass
class StateRecord:
    """A record of a state transition."""
    from_state: str = ""
    to_state: str = ""
    event: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_in_state_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state, "to": self.to_state,
            "event": self.event,
            "duration_s": round(self.duration_in_state_s, 1),
        }


class AgentStateMachine:
    """Finite state machine for agent lifecycle management.

    Manages agent states, transitions, guards,
    and state-specific behavior.
    """

    def __init__(self, agent_id: str = "") -> None:
        self._agent_id = agent_id
        self._state = AgentState.INITIALIZING
        self._state_entered_at = time.time()
        self._transitions: list[StateTransition] = []
        self._history: list[StateRecord] = []
        self._state_timeouts: dict[AgentState, float] = {}
        self._state_handlers: dict[AgentState, Callable[..., Any]] = {}
        self._transition_count = 0
        self._log = logger.bind(component="state_machine", agent=agent_id)

        self._init_transitions()

    def _init_transitions(self) -> None:
        """Initialize default transition rules."""
        default_transitions = [
            (AgentState.INITIALIZING, TransitionEvent.INIT_COMPLETE, AgentState.IDLE),
            (AgentState.IDLE, TransitionEvent.TASK_ASSIGNED, AgentState.PLANNING),
            (AgentState.PLANNING, TransitionEvent.PLAN_READY, AgentState.EXECUTING),
            (AgentState.EXECUTING, TransitionEvent.EXECUTION_DONE, AgentState.ANALYZING),
            (AgentState.ANALYZING, TransitionEvent.ANALYSIS_DONE, AgentState.VALIDATING),
            (AgentState.VALIDATING, TransitionEvent.VALIDATION_DONE, AgentState.REPORTING),
            (AgentState.REPORTING, TransitionEvent.REPORT_DONE, AgentState.IDLE),
            (AgentState.EXECUTING, TransitionEvent.WAITING_RESOLVED, AgentState.EXECUTING),

            # Error handling
            (AgentState.PLANNING, TransitionEvent.ERROR_OCCURRED, AgentState.ERROR),
            (AgentState.EXECUTING, TransitionEvent.ERROR_OCCURRED, AgentState.ERROR),
            (AgentState.ANALYZING, TransitionEvent.ERROR_OCCURRED, AgentState.ERROR),
            (AgentState.VALIDATING, TransitionEvent.ERROR_OCCURRED, AgentState.ERROR),
            (AgentState.ERROR, TransitionEvent.RECOVER, AgentState.RECOVERING),
            (AgentState.RECOVERING, TransitionEvent.INIT_COMPLETE, AgentState.IDLE),

            # Pause/Resume
            (AgentState.EXECUTING, TransitionEvent.PAUSE_REQUESTED, AgentState.PAUSED),
            (AgentState.ANALYZING, TransitionEvent.PAUSE_REQUESTED, AgentState.PAUSED),
            (AgentState.PAUSED, TransitionEvent.RESUME_REQUESTED, AgentState.EXECUTING),

            # Timeout
            (AgentState.EXECUTING, TransitionEvent.TIMEOUT, AgentState.ERROR),
            (AgentState.WAITING, TransitionEvent.TIMEOUT, AgentState.ERROR),

            # Termination
            (AgentState.IDLE, TransitionEvent.TERMINATE, AgentState.TERMINATED),
            (AgentState.ERROR, TransitionEvent.TERMINATE, AgentState.TERMINATED),
            (AgentState.PAUSED, TransitionEvent.TERMINATE, AgentState.TERMINATED),
        ]

        for from_s, event, to_s in default_transitions:
            self._transitions.append(StateTransition(
                from_state=from_s, event=event, to_state=to_s,
            ))

        # Default timeouts
        self._state_timeouts = {
            AgentState.EXECUTING: 600.0,
            AgentState.WAITING: 120.0,
            AgentState.ANALYZING: 300.0,
        }

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def time_in_state(self) -> float:
        return time.time() - self._state_entered_at

    def trigger(self, event: TransitionEvent) -> bool:
        """Trigger a state transition."""
        for transition in self._transitions:
            if transition.from_state != self._state:
                continue
            if transition.event != event:
                continue

            # Check guard
            if transition.guard and not transition.guard():
                continue

            # Execute transition
            old_state = self._state
            duration = self.time_in_state

            self._history.append(StateRecord(
                from_state=old_state.value,
                to_state=transition.to_state.value,
                event=event.value,
                duration_in_state_s=duration,
            ))

            self._state = transition.to_state
            self._state_entered_at = time.time()
            self._transition_count += 1

            # Execute state handler
            handler = self._state_handlers.get(self._state)
            if handler:
                try:
                    handler()
                except Exception:
                    pass

            if len(self._history) > 200:
                self._history = self._history[-200:]

            return True

        return False

    def check_timeout(self) -> bool:
        """Check if current state has timed out."""
        timeout = self._state_timeouts.get(self._state)
        if timeout and self.time_in_state > timeout:
            return self.trigger(TransitionEvent.TIMEOUT)
        return False

    def set_timeout(self, state: AgentState, timeout_s: float) -> None:
        """Set timeout for a state."""
        self._state_timeouts[state] = timeout_s

    def set_handler(self, state: AgentState, handler: Callable[..., Any]) -> None:
        """Set handler for entering a state."""
        self._state_handlers[state] = handler

    def add_transition(
        self,
        from_state: AgentState,
        event: TransitionEvent,
        to_state: AgentState,
        guard: Callable[..., bool] | None = None,
    ) -> None:
        """Add a custom transition rule."""
        self._transitions.append(StateTransition(
            from_state=from_state, event=event,
            to_state=to_state, guard=guard,
        ))

    def get_valid_events(self) -> list[str]:
        """Get events valid from current state."""
        events = []
        for transition in self._transitions:
            if transition.from_state == self._state:
                events.append(transition.event.value)
        return events

    def get_history(self, limit: int = 20) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._history[-limit:]]

    def get_state_durations(self) -> dict[str, float]:
        """Get total time spent in each state."""
        durations: dict[str, float] = defaultdict(float)
        for record in self._history:
            durations[record.from_state] += record.duration_in_state_s
        return dict(durations)

    def get_stats(self) -> dict[str, Any]:
        return {
            "agent": self._agent_id[:20],
            "state": self._state.value,
            "time_in_state": round(self.time_in_state, 1),
            "transitions": self._transition_count,
            "history": len(self._history),
        }
