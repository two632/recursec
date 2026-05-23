"""Agent state machine — manages complex multi-phase operations.

Implements:
1. Finite state machine for agent workflows
2. State transitions with guards/conditions
3. Hierarchical state machines (substates)
4. Event-driven transitions
5. State persistence and recovery
6. Timeout-based transitions
7. State history for debugging
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StateType(str, Enum):
    INITIAL = "initial"
    INTERMEDIATE = "intermediate"
    FINAL = "final"
    ERROR = "error"


class TransitionTrigger(str, Enum):
    EVENT = "event"
    CONDITION = "condition"
    TIMEOUT = "timeout"
    MANUAL = "manual"
    AUTO = "auto"


@dataclass
class State:
    """A state in the state machine."""
    state_id: str = ""
    name: str = ""
    state_type: StateType = StateType.INTERMEDIATE
    description: str = ""
    timeout_s: float = 0.0
    on_enter_actions: list[str] = field(default_factory=list)
    on_exit_actions: list[str] = field(default_factory=list)
    substates: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.state_id[:10],
            "name": self.name[:20],
            "type": self.state_type.value,
            "timeout": self.timeout_s,
            "substates": len(self.substates),
        }


@dataclass
class Transition:
    """A transition between states."""
    transition_id: str = ""
    from_state: str = ""
    to_state: str = ""
    trigger: TransitionTrigger = TransitionTrigger.EVENT
    event_name: str = ""
    guard_condition: str = ""
    priority: int = 5
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.transition_id[:10],
            "from": self.from_state[:10],
            "to": self.to_state[:10],
            "trigger": self.trigger.value,
        }


@dataclass
class StateEntry:
    """A state history entry."""
    state_id: str = ""
    entered_at: float = field(default_factory=time.time)
    exited_at: float = 0.0
    event: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        if self.exited_at > 0:
            return self.exited_at - self.entered_at
        return time.time() - self.entered_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state_id[:10],
            "duration": round(self.duration_s, 1),
            "event": self.event[:15],
        }


# ── Pre-built agent workflow state machines ───────────────────

SECURITY_ASSESSMENT_STATES: list[dict[str, Any]] = [
    {"id": "idle", "name": "Idle", "type": "initial", "desc": "Waiting for task"},
    {"id": "initializing", "name": "Initializing", "type": "intermediate", "desc": "Setting up assessment", "timeout": 30},
    {"id": "recon", "name": "Reconnaissance", "type": "intermediate", "desc": "Gathering information", "timeout": 300},
    {"id": "scanning", "name": "Scanning", "type": "intermediate", "desc": "Running vulnerability scans", "timeout": 600},
    {"id": "analyzing", "name": "Analyzing", "type": "intermediate", "desc": "Analyzing scan results", "timeout": 120},
    {"id": "exploiting", "name": "Exploiting", "type": "intermediate", "desc": "Attempting exploitation", "timeout": 600},
    {"id": "validating", "name": "Validating", "type": "intermediate", "desc": "Validating findings", "timeout": 300},
    {"id": "reporting", "name": "Reporting", "type": "intermediate", "desc": "Generating report", "timeout": 120},
    {"id": "complete", "name": "Complete", "type": "final", "desc": "Assessment complete"},
    {"id": "error", "name": "Error", "type": "error", "desc": "Error occurred"},
    {"id": "paused", "name": "Paused", "type": "intermediate", "desc": "Paused by user"},
]

SECURITY_ASSESSMENT_TRANSITIONS: list[dict[str, Any]] = [
    {"from": "idle", "to": "initializing", "trigger": "event", "event": "start"},
    {"from": "initializing", "to": "recon", "trigger": "auto"},
    {"from": "recon", "to": "scanning", "trigger": "event", "event": "recon_complete"},
    {"from": "recon", "to": "error", "trigger": "event", "event": "error"},
    {"from": "scanning", "to": "analyzing", "trigger": "event", "event": "scan_complete"},
    {"from": "scanning", "to": "error", "trigger": "event", "event": "error"},
    {"from": "analyzing", "to": "exploiting", "trigger": "condition", "guard": "findings_found"},
    {"from": "analyzing", "to": "reporting", "trigger": "condition", "guard": "no_findings"},
    {"from": "exploiting", "to": "validating", "trigger": "event", "event": "exploit_complete"},
    {"from": "exploiting", "to": "error", "trigger": "event", "event": "error"},
    {"from": "validating", "to": "reporting", "trigger": "event", "event": "validation_complete"},
    {"from": "reporting", "to": "complete", "trigger": "auto"},
    {"from": "error", "to": "idle", "trigger": "event", "event": "reset"},
    # Timeout transitions
    {"from": "recon", "to": "scanning", "trigger": "timeout"},
    {"from": "scanning", "to": "analyzing", "trigger": "timeout"},
    {"from": "exploiting", "to": "validating", "trigger": "timeout"},
    # Pause/resume
    {"from": "recon", "to": "paused", "trigger": "event", "event": "pause"},
    {"from": "scanning", "to": "paused", "trigger": "event", "event": "pause"},
    {"from": "exploiting", "to": "paused", "trigger": "event", "event": "pause"},
    {"from": "paused", "to": "recon", "trigger": "event", "event": "resume_recon"},
    {"from": "paused", "to": "scanning", "trigger": "event", "event": "resume_scan"},
    {"from": "paused", "to": "exploiting", "trigger": "event", "event": "resume_exploit"},
]


class AgentStateMachine:
    """Finite state machine for agent workflows.

    Manages complex multi-phase security assessment
    operations with event-driven transitions.
    """

    def __init__(self) -> None:
        self._states: dict[str, State] = {}
        self._transitions: list[Transition] = []
        self._current_state: str = ""
        self._history: list[StateEntry] = []
        self._context: dict[str, Any] = {}
        self._counter = 0
        self._log = logger.bind(component="state_machine")

    def load_workflow(
        self,
        states: list[dict[str, Any]],
        transitions: list[dict[str, Any]],
    ) -> None:
        """Load a workflow definition."""
        for s_data in states:
            state = State(
                state_id=s_data["id"],
                name=s_data.get("name", s_data["id"]),
                state_type=StateType(s_data.get("type", "intermediate")),
                description=s_data.get("desc", ""),
                timeout_s=s_data.get("timeout", 0),
            )
            self._states[state.state_id] = state
            if state.state_type == StateType.INITIAL and not self._current_state:
                self._current_state = state.state_id

        for t_data in transitions:
            self._counter += 1
            transition = Transition(
                transition_id=f"tr-{self._counter}",
                from_state=t_data["from"],
                to_state=t_data["to"],
                trigger=TransitionTrigger(t_data.get("trigger", "event")),
                event_name=t_data.get("event", ""),
                guard_condition=t_data.get("guard", ""),
                priority=t_data.get("priority", 5),
            )
            self._transitions.append(transition)

    def load_security_assessment(self) -> None:
        """Load the pre-built security assessment workflow."""
        self.load_workflow(
            SECURITY_ASSESSMENT_STATES,
            SECURITY_ASSESSMENT_TRANSITIONS,
        )

    def send_event(
        self,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> str | None:
        """Send an event to trigger a transition."""
        # Find matching transition
        for transition in self._transitions:
            if transition.from_state != self._current_state:
                continue
            if transition.trigger == TransitionTrigger.EVENT and transition.event_name == event:
                return self._execute_transition(transition, event, data)

        return None

    def check_conditions(
        self,
        conditions: dict[str, bool],
    ) -> str | None:
        """Check condition-based transitions."""
        for transition in self._transitions:
            if transition.from_state != self._current_state:
                continue
            if transition.trigger == TransitionTrigger.CONDITION:
                if conditions.get(transition.guard_condition, False):
                    return self._execute_transition(transition, transition.guard_condition)

        return None

    def check_timeout(self) -> str | None:
        """Check if current state has timed out."""
        current = self._states.get(self._current_state)
        if not current or current.timeout_s <= 0:
            return None

        if not self._history:
            return None

        last_entry = self._history[-1]
        if last_entry.duration_s >= current.timeout_s:
            # Find timeout transition
            for transition in self._transitions:
                if (transition.from_state == self._current_state and
                        transition.trigger == TransitionTrigger.TIMEOUT):
                    return self._execute_transition(transition, "timeout")

        return None

    def _execute_transition(
        self,
        transition: Transition,
        event: str,
        data: dict[str, Any] | None = None,
    ) -> str:
        """Execute a state transition."""
        old_state = self._current_state

        # Exit old state
        if self._history:
            self._history[-1].exited_at = time.time()

        # Enter new state
        self._current_state = transition.to_state
        entry = StateEntry(
            state_id=transition.to_state,
            event=event,
            data=data or {},
        )
        self._history.append(entry)

        self._log.info(
            "state_transition",
            old=old_state,
            new=self._current_state,
            event=event,
        )

        return self._current_state

    @property
    def current_state(self) -> str:
        return self._current_state

    @property
    def is_final(self) -> bool:
        state = self._states.get(self._current_state)
        return state.state_type == StateType.FINAL if state else False

    @property
    def is_error(self) -> bool:
        state = self._states.get(self._current_state)
        return state.state_type == StateType.ERROR if state else False

    def get_available_events(self) -> list[str]:
        """Get events that can trigger transitions from current state."""
        events = []
        for transition in self._transitions:
            if transition.from_state == self._current_state:
                if transition.event_name:
                    events.append(transition.event_name)
        return events

    def get_state_info(self) -> dict[str, Any]:
        """Get current state information."""
        state = self._states.get(self._current_state)
        if not state:
            return {}
        return {
            "state": state.name,
            "type": state.state_type.value,
            "description": state.description,
            "available_events": self.get_available_events(),
        }

    def get_stats(self) -> dict[str, Any]:
        state_durations: dict[str, float] = defaultdict(float)
        for entry in self._history:
            state_durations[entry.state_id] += entry.duration_s

        return {
            "states": len(self._states),
            "transitions": len(self._transitions),
            "current": self._current_state,
            "history_len": len(self._history),
            "state_durations": {k: round(v, 1) for k, v in state_durations.items()},
        }
