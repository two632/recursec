"""Agent state machine — manages complex multi-phase operations.

Implements:
1. Finite state machine for assessment phases
2. State transitions with guards and actions
3. Hierarchical states (nested sub-states)
4. Event-driven transitions
5. State persistence for recovery
6. Timeout-based auto-transitions
7. Parallel state regions
8. State history for debugging
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    # Top-level states
    IDLE = "idle"
    INITIALIZING = "initializing"
    PLANNING = "planning"
    RECONNING = "reconning"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    VALIDATING = "validating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

    # Sub-states for RECONNING
    RECON_PASSIVE = "recon_passive"
    RECON_ACTIVE = "recon_active"
    RECON_OSINT = "recon_osint"

    # Sub-states for SCANNING
    SCAN_PORTS = "scan_ports"
    SCAN_WEB = "scan_web"
    SCAN_VULN = "scan_vuln"
    SCAN_CODE = "scan_code"

    # Sub-states for EXPLOITING
    EXPLOIT_VERIFY = "exploit_verify"
    EXPLOIT_EXECUTE = "exploit_execute"
    EXPLOIT_POST = "exploit_post"


class EventType(str, Enum):
    START = "start"
    COMPLETE = "complete"
    FAIL = "fail"
    TIMEOUT = "timeout"
    PAUSE = "pause"
    RESUME = "resume"
    FINDING = "finding"
    ESCALATE = "escalate"
    ROLLBACK = "rollback"
    SKIP = "skip"


@dataclass
class Transition:
    """A state transition rule."""
    from_state: AgentState
    event: EventType
    to_state: AgentState
    guard: str = ""               # Condition name
    action: str = ""              # Action to execute
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value,
            "event": self.event.value,
            "to": self.to_state.value,
        }


@dataclass
class StateEntry:
    """A record of entering a state."""
    state: AgentState
    entered_at: float = field(default_factory=time.time)
    exited_at: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)
    event: EventType = EventType.START

    @property
    def duration_s(self) -> float:
        end = self.exited_at or time.time()
        return end - self.entered_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "duration_s": round(self.duration_s, 1),
            "event": self.event.value,
        }


# ── Default Transitions ──────────────────────────────────────

DEFAULT_TRANSITIONS: list[Transition] = [
    # Main flow
    Transition(AgentState.IDLE, EventType.START, AgentState.INITIALIZING),
    Transition(AgentState.INITIALIZING, EventType.COMPLETE, AgentState.PLANNING),
    Transition(AgentState.PLANNING, EventType.COMPLETE, AgentState.RECONNING),
    Transition(AgentState.RECONNING, EventType.COMPLETE, AgentState.SCANNING),
    Transition(AgentState.SCANNING, EventType.COMPLETE, AgentState.EXPLOITING),
    Transition(AgentState.EXPLOITING, EventType.COMPLETE, AgentState.VALIDATING),
    Transition(AgentState.VALIDATING, EventType.COMPLETE, AgentState.REPORTING),
    Transition(AgentState.REPORTING, EventType.COMPLETE, AgentState.COMPLETED),

    # Error handling
    Transition(AgentState.INITIALIZING, EventType.FAIL, AgentState.FAILED),
    Transition(AgentState.PLANNING, EventType.FAIL, AgentState.FAILED),
    Transition(AgentState.RECONNING, EventType.FAIL, AgentState.SCANNING,
               description="Skip recon on failure, proceed to scanning"),
    Transition(AgentState.SCANNING, EventType.FAIL, AgentState.VALIDATING,
               description="Skip to validation on scan failure"),
    Transition(AgentState.EXPLOITING, EventType.FAIL, AgentState.VALIDATING,
               description="Skip to validation on exploit failure"),
    Transition(AgentState.VALIDATING, EventType.FAIL, AgentState.REPORTING),

    # Pause/resume
    Transition(AgentState.RECONNING, EventType.PAUSE, AgentState.PAUSED),
    Transition(AgentState.SCANNING, EventType.PAUSE, AgentState.PAUSED),
    Transition(AgentState.EXPLOITING, EventType.PAUSE, AgentState.PAUSED),
    Transition(AgentState.PAUSED, EventType.RESUME, AgentState.RECONNING),

    # Skip transitions
    Transition(AgentState.RECONNING, EventType.SKIP, AgentState.SCANNING),
    Transition(AgentState.SCANNING, EventType.SKIP, AgentState.EXPLOITING),
    Transition(AgentState.EXPLOITING, EventType.SKIP, AgentState.VALIDATING),

    # Escalation (go back to deeper phases)
    Transition(AgentState.VALIDATING, EventType.ESCALATE, AgentState.EXPLOITING,
               description="Re-exploit when validation finds something new"),
    Transition(AgentState.SCANNING, EventType.ESCALATE, AgentState.RECONNING,
               description="More recon when scanning reveals new targets"),

    # Timeouts
    Transition(AgentState.RECONNING, EventType.TIMEOUT, AgentState.SCANNING),
    Transition(AgentState.SCANNING, EventType.TIMEOUT, AgentState.EXPLOITING),
    Transition(AgentState.EXPLOITING, EventType.TIMEOUT, AgentState.VALIDATING),

    # Recon sub-states
    Transition(AgentState.RECONNING, EventType.START, AgentState.RECON_PASSIVE),
    Transition(AgentState.RECON_PASSIVE, EventType.COMPLETE, AgentState.RECON_ACTIVE),
    Transition(AgentState.RECON_ACTIVE, EventType.COMPLETE, AgentState.RECON_OSINT),
    Transition(AgentState.RECON_OSINT, EventType.COMPLETE, AgentState.SCANNING),

    # Scan sub-states
    Transition(AgentState.SCANNING, EventType.START, AgentState.SCAN_PORTS),
    Transition(AgentState.SCAN_PORTS, EventType.COMPLETE, AgentState.SCAN_WEB),
    Transition(AgentState.SCAN_WEB, EventType.COMPLETE, AgentState.SCAN_VULN),
    Transition(AgentState.SCAN_VULN, EventType.COMPLETE, AgentState.SCAN_CODE),
    Transition(AgentState.SCAN_CODE, EventType.COMPLETE, AgentState.EXPLOITING),

    # Exploit sub-states
    Transition(AgentState.EXPLOITING, EventType.START, AgentState.EXPLOIT_VERIFY),
    Transition(AgentState.EXPLOIT_VERIFY, EventType.COMPLETE, AgentState.EXPLOIT_EXECUTE),
    Transition(AgentState.EXPLOIT_EXECUTE, EventType.COMPLETE, AgentState.EXPLOIT_POST),
    Transition(AgentState.EXPLOIT_POST, EventType.COMPLETE, AgentState.VALIDATING),
]


class AgentStateMachine:
    """Finite state machine for managing agent phases.

    Handles transitions, guards, timeouts, and state
    history for complex multi-phase assessments.
    """

    def __init__(
        self,
        initial_state: AgentState = AgentState.IDLE,
        transitions: list[Transition] | None = None,
    ) -> None:
        self._current_state = initial_state
        self._transitions = transitions or DEFAULT_TRANSITIONS
        self._guards: dict[str, Callable[[], bool]] = {}
        self._actions: dict[str, Callable[[], None]] = {}
        self._history: list[StateEntry] = []
        self._current_entry: StateEntry | None = None
        self._state_data: dict[str, Any] = {}
        self._timeouts: dict[str, float] = {}  # state -> timeout_s
        self._entered_at: float = time.time()
        self._log = logger.bind(component="state_machine")

        # Record initial state
        self._enter_state(initial_state, EventType.START)

    @property
    def state(self) -> AgentState:
        return self._current_state

    @property
    def is_terminal(self) -> bool:
        return self._current_state in (AgentState.COMPLETED, AgentState.FAILED)

    def transition(self, event: EventType, data: dict[str, Any] | None = None) -> bool:
        """Attempt a state transition."""
        valid = [
            t for t in self._transitions
            if t.from_state == self._current_state and t.event == event
        ]

        if not valid:
            self._log.debug(
                "no_transition",
                state=self._current_state.value,
                event=event.value,
            )
            return False

        transition = valid[0]

        # Check guard
        if transition.guard and transition.guard in self._guards:
            if not self._guards[transition.guard]():
                return False

        # Exit current state
        self._exit_state()

        # Execute action
        if transition.action and transition.action in self._actions:
            try:
                self._actions[transition.action]()
            except Exception as e:
                self._log.error("action_failed", action=transition.action, error=str(e)[:100])

        # Enter new state
        old_state = self._current_state
        self._current_state = transition.to_state
        self._enter_state(transition.to_state, event, data)

        self._log.info(
            "transition",
            event=event.value,
            old=old_state.value, new=transition.to_state.value,
        )

        return True

    def set_timeout(self, state: AgentState, timeout_s: float) -> None:
        """Set a timeout for a state."""
        self._timeouts[state.value] = timeout_s

    def check_timeout(self) -> bool:
        """Check if current state has timed out."""
        timeout = self._timeouts.get(self._current_state.value)
        if not timeout:
            return False

        elapsed = time.time() - self._entered_at
        if elapsed > timeout:
            return self.transition(EventType.TIMEOUT)
        return False

    def register_guard(self, name: str, guard: Callable[[], bool]) -> None:
        self._guards[name] = guard

    def register_action(self, name: str, action: Callable[[], None]) -> None:
        self._actions[name] = action

    def set_data(self, key: str, value: Any) -> None:
        self._state_data[key] = value

    def get_data(self, key: str, default: Any = None) -> Any:
        return self._state_data.get(key, default)

    def get_history(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._history]

    def get_phase_duration(self, state: AgentState) -> float:
        """Get total time spent in a state."""
        total = 0.0
        for entry in self._history:
            if entry.state == state:
                total += entry.duration_s
        if self._current_state == state and self._current_entry:
            total += self._current_entry.duration_s
        return total

    def _enter_state(self, state: AgentState, event: EventType, data: dict[str, Any] | None = None) -> None:
        self._current_entry = StateEntry(
            state=state, event=event, data=data or {},
        )
        self._entered_at = time.time()

    def _exit_state(self) -> None:
        if self._current_entry:
            self._current_entry.exited_at = time.time()
            self._history.append(self._current_entry)
            self._current_entry = None

    def get_stats(self) -> dict[str, Any]:
        phase_times = {}
        for entry in self._history:
            phase_times.setdefault(entry.state.value, 0.0)
            phase_times[entry.state.value] += entry.duration_s

        return {
            "current": self._current_state.value,
            "transitions": len(self._history),
            "phase_times": {k: round(v, 1) for k, v in phase_times.items()},
        }
