"""Agent state machine — FSM governing agent lifecycle.

Implements:
1. 14-state finite state machine
2. Valid transition rules
3. State entry/exit hooks
4. Transition guards (conditions)
5. State history for debugging
6. State prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    REFLECTING = "reflecting"
    SPAWNING_CHILD = "spawning_child"
    WAITING_CHILD = "waiting_child"
    AGGREGATING = "aggregating"
    VALIDATING = "validating"
    REPLANNING = "replanning"
    ESCALATING = "escalating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


# Valid transitions: source → set of valid targets
VALID_TRANSITIONS: dict[AgentState, set[AgentState]] = {
    AgentState.INITIALIZING: {AgentState.PLANNING, AgentState.FAILED},
    AgentState.PLANNING: {
        AgentState.EXECUTING,
        AgentState.SPAWNING_CHILD,
        AgentState.FAILED,
    },
    AgentState.EXECUTING: {
        AgentState.ANALYZING,
        AgentState.FAILED,
        AgentState.ESCALATING,
    },
    AgentState.ANALYZING: {
        AgentState.REFLECTING,
        AgentState.EXECUTING,     # Continue execution
        AgentState.REPLANNING,
        AgentState.SPAWNING_CHILD,
        AgentState.VALIDATING,
    },
    AgentState.REFLECTING: {
        AgentState.PLANNING,       # Re-plan with insights
        AgentState.EXECUTING,      # Continue with adjustments
        AgentState.REPORTING,      # Done
        AgentState.REPLANNING,     # Major strategy change
    },
    AgentState.SPAWNING_CHILD: {
        AgentState.WAITING_CHILD,
        AgentState.FAILED,
    },
    AgentState.WAITING_CHILD: {
        AgentState.AGGREGATING,
        AgentState.FAILED,         # Child timeout
        AgentState.ESCALATING,     # Child stuck
    },
    AgentState.AGGREGATING: {
        AgentState.ANALYZING,
        AgentState.VALIDATING,
        AgentState.REPORTING,
    },
    AgentState.VALIDATING: {
        AgentState.REPORTING,      # Validated, done
        AgentState.EXECUTING,      # Need more evidence
        AgentState.REPLANNING,     # Invalid, retry
    },
    AgentState.REPLANNING: {
        AgentState.PLANNING,
        AgentState.ESCALATING,     # Can't find new plan
        AgentState.FAILED,
    },
    AgentState.ESCALATING: {
        AgentState.WAITING_CHILD,  # Escalated to parent
        AgentState.COMPLETED,      # Parent resolved it
        AgentState.FAILED,
    },
    AgentState.REPORTING: {
        AgentState.COMPLETED,
        AgentState.VALIDATING,     # Report review needed
    },
    AgentState.COMPLETED: set(),   # Terminal
    AgentState.FAILED: set(),      # Terminal
}


@dataclass
class StateTransition:
    """Record of a state transition."""
    from_state: AgentState = AgentState.INITIALIZING
    to_state: AgentState = AgentState.INITIALIZING
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_in_state_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value[:8],
            "to": self.to_state.value[:8],
            "reason": self.reason[:20],
        }


@dataclass
class StateContext:
    """Context maintained per state."""
    state: AgentState = AgentState.INITIALIZING
    entered_at: float = field(default_factory=time.time)
    step_count: int = 0
    tokens_in_state: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentStateMachine:
    """FSM governing agent lifecycle.

    Manages state transitions, enforces valid
    transition rules, maintains state history,
    and provides state-aware context to LLM.
    """

    def __init__(self, agent_id: str = "") -> None:
        self._agent_id = agent_id
        self._current = StateContext(state=AgentState.INITIALIZING)
        self._history: list[StateTransition] = []
        self._state_durations: dict[AgentState, float] = {}
        self._state_visits: dict[AgentState, int] = {}
        self._max_history = 100
        self._log = logger.bind(component="state_machine", agent=agent_id)

    @property
    def state(self) -> AgentState:
        return self._current.state

    @property
    def is_terminal(self) -> bool:
        return self.state in (AgentState.COMPLETED, AgentState.FAILED)

    def can_transition(self, target: AgentState) -> bool:
        """Check if a transition is valid."""
        return target in VALID_TRANSITIONS.get(self.state, set())

    def transition(self, target: AgentState, reason: str = "") -> bool:
        """Attempt a state transition."""
        if not self.can_transition(target):
            self._log.warning(
                "invalid_transition",
                current=self.state.value,
                target=target.value,
            )
            return False

        now = time.time()
        duration = now - self._current.entered_at

        # Record transition
        transition = StateTransition(
            from_state=self.state,
            to_state=target,
            reason=reason,
            duration_in_state_s=duration,
        )
        self._history.append(transition)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        # Track duration
        old_state = self.state
        self._state_durations[old_state] = (
            self._state_durations.get(old_state, 0.0) + duration
        )

        # Track visits
        self._state_visits[target] = self._state_visits.get(target, 0) + 1

        # Enter new state
        self._current = StateContext(
            state=target,
            entered_at=now,
        )

        return True

    def get_valid_transitions(self) -> list[AgentState]:
        """Get all valid transitions from current state."""
        return list(VALID_TRANSITIONS.get(self.state, set()))

    def get_state_duration(self) -> float:
        """Get duration in current state."""
        return time.time() - self._current.entered_at

    def increment_step(self, tokens: int = 0) -> None:
        """Increment step counter in current state."""
        self._current.step_count += 1
        self._current.tokens_in_state += tokens

    def get_recent_path(self, n: int = 5) -> list[str]:
        """Get recent state path."""
        recent = self._history[-n:]
        path = [t.from_state.value for t in recent]
        if recent:
            path.append(recent[-1].to_state.value)
        return path

    def detect_loops(self) -> list[str]:
        """Detect state loops in recent history."""
        path = self.get_recent_path(10)
        loops: list[str] = []

        for window in range(2, min(5, len(path) // 2)):
            for i in range(len(path) - window * 2 + 1):
                pattern = path[i:i + window]
                next_seg = path[i + window:i + window * 2]
                if pattern == next_seg:
                    loop_str = " → ".join(pattern)
                    if loop_str not in loops:
                        loops.append(loop_str)

        return loops

    def build_state_prompt(self) -> str:
        """Build state context for LLM."""
        lines = ["## Agent State\n"]

        lines.append(f"Current: {self.state.value}")
        lines.append(f"Time in state: {self.get_state_duration():.1f}s")
        lines.append(f"Steps in state: {self._current.step_count}")

        # Valid next states
        valid = self.get_valid_transitions()
        if valid:
            valid_names = [s.value for s in valid]
            lines.append(f"Valid transitions: {', '.join(valid_names)}")

        # Recent path
        path = self.get_recent_path(5)
        if path:
            lines.append(f"Recent path: {' → '.join(path)}")

        # Loops
        loops = self.detect_loops()
        if loops:
            lines.append(f"LOOPS DETECTED: {loops[0]}")

        # Most time spent
        if self._state_durations:
            sorted_durations = sorted(
                self._state_durations.items(),
                key=lambda x: x[1],
                reverse=True,
            )
            top = sorted_durations[0]
            lines.append(f"Most time in: {top[0].value} ({top[1]:.0f}s)")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "current": self.state.value,
            "transitions": len(self._history),
            "visits": dict(
                (s.value, c)
                for s, c in sorted(
                    self._state_visits.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            ),
            "loops": self.detect_loops(),
        }
