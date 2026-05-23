"""Agent state machine — formal FSM for agent lifecycle.

Implements:
1. Agent lifecycle states (init → planning → executing → reflecting → done)
2. Valid state transitions with guards
3. State entry/exit hooks
4. Hierarchical states (sub-states within execution)
5. State history for debugging
6. Timeout-based auto-transitions
7. State machine prompt for LLM context
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
    SELECTING_TOOL = "selecting_tool"
    EXECUTING = "executing"
    WAITING_RESULT = "waiting_result"
    ANALYZING = "analyzing"
    REFLECTING = "reflecting"
    SPAWNING_CHILD = "spawning_child"
    WAITING_CHILD = "waiting_child"
    VALIDATING = "validating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    TIMEOUT = "timeout"


class TransitionTrigger(str, Enum):
    PLAN_READY = "plan_ready"
    TOOL_SELECTED = "tool_selected"
    EXECUTE = "execute"
    RESULT_RECEIVED = "result_received"
    ANALYSIS_DONE = "analysis_done"
    NEED_MORE_INFO = "need_more_info"
    SPAWN_CHILD = "spawn_child"
    CHILD_DONE = "child_done"
    VALIDATE = "validate"
    REPORT = "report"
    COMPLETE = "complete"
    FAIL = "fail"
    PAUSE = "pause"
    RESUME = "resume"
    TIMEOUT_TRIGGER = "timeout"
    RETRY = "retry"


@dataclass
class StateTransition:
    """A recorded state transition."""
    from_state: AgentState
    to_state: AgentState
    trigger: TransitionTrigger
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value[:8],
            "to": self.to_state.value[:8],
            "trigger": self.trigger.value[:10],
        }


# ── Valid transitions ────────────────────────────────────────

VALID_TRANSITIONS: dict[AgentState, dict[TransitionTrigger, AgentState]] = {
    AgentState.INITIALIZING: {
        TransitionTrigger.PLAN_READY: AgentState.PLANNING,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.PLANNING: {
        TransitionTrigger.TOOL_SELECTED: AgentState.SELECTING_TOOL,
        TransitionTrigger.SPAWN_CHILD: AgentState.SPAWNING_CHILD,
        TransitionTrigger.COMPLETE: AgentState.COMPLETED,
        TransitionTrigger.FAIL: AgentState.FAILED,
        TransitionTrigger.PAUSE: AgentState.PAUSED,
    },
    AgentState.SELECTING_TOOL: {
        TransitionTrigger.EXECUTE: AgentState.EXECUTING,
        TransitionTrigger.NEED_MORE_INFO: AgentState.PLANNING,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.EXECUTING: {
        TransitionTrigger.RESULT_RECEIVED: AgentState.WAITING_RESULT,
        TransitionTrigger.TIMEOUT_TRIGGER: AgentState.TIMEOUT,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.WAITING_RESULT: {
        TransitionTrigger.ANALYSIS_DONE: AgentState.ANALYZING,
        TransitionTrigger.TIMEOUT_TRIGGER: AgentState.TIMEOUT,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.ANALYZING: {
        TransitionTrigger.NEED_MORE_INFO: AgentState.PLANNING,
        TransitionTrigger.VALIDATE: AgentState.VALIDATING,
        TransitionTrigger.SPAWN_CHILD: AgentState.SPAWNING_CHILD,
        TransitionTrigger.REPORT: AgentState.REPORTING,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.REFLECTING: {
        TransitionTrigger.NEED_MORE_INFO: AgentState.PLANNING,
        TransitionTrigger.COMPLETE: AgentState.COMPLETED,
        TransitionTrigger.REPORT: AgentState.REPORTING,
    },
    AgentState.SPAWNING_CHILD: {
        TransitionTrigger.CHILD_DONE: AgentState.WAITING_CHILD,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.WAITING_CHILD: {
        TransitionTrigger.RESULT_RECEIVED: AgentState.ANALYZING,
        TransitionTrigger.TIMEOUT_TRIGGER: AgentState.TIMEOUT,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.VALIDATING: {
        TransitionTrigger.ANALYSIS_DONE: AgentState.REFLECTING,
        TransitionTrigger.NEED_MORE_INFO: AgentState.PLANNING,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.REPORTING: {
        TransitionTrigger.COMPLETE: AgentState.COMPLETED,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.PAUSED: {
        TransitionTrigger.RESUME: AgentState.PLANNING,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
    AgentState.TIMEOUT: {
        TransitionTrigger.RETRY: AgentState.PLANNING,
        TransitionTrigger.FAIL: AgentState.FAILED,
    },
}

# State timeouts in seconds
STATE_TIMEOUTS: dict[AgentState, float] = {
    AgentState.EXECUTING: 300.0,       # 5 min tool execution
    AgentState.WAITING_RESULT: 120.0,   # 2 min waiting
    AgentState.WAITING_CHILD: 600.0,    # 10 min child agent
    AgentState.PLANNING: 60.0,          # 1 min planning
    AgentState.ANALYZING: 120.0,        # 2 min analysis
}


class AgentStateMachine:
    """Formal finite state machine for agent lifecycle.

    Manages agent states, transitions, guards,
    and timeout-based auto-transitions.
    """

    def __init__(
        self,
        agent_id: str = "",
        initial_state: AgentState = AgentState.INITIALIZING,
    ) -> None:
        self._agent_id = agent_id
        self._current_state = initial_state
        self._history: list[StateTransition] = []
        self._state_entered_at: float = time.time()
        self._max_retries: int = 3
        self._retry_count: int = 0
        self._log = logger.bind(component="agent_fsm", agent=agent_id)

    @property
    def state(self) -> AgentState:
        return self._current_state

    @property
    def is_terminal(self) -> bool:
        return self._current_state in (
            AgentState.COMPLETED,
            AgentState.FAILED,
        )

    @property
    def time_in_state(self) -> float:
        return time.time() - self._state_entered_at

    def transition(
        self,
        trigger: TransitionTrigger,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Attempt a state transition."""
        transitions = VALID_TRANSITIONS.get(self._current_state, {})
        new_state = transitions.get(trigger)

        if new_state is None:
            self._log.warning(
                "invalid_transition",
                current=self._current_state.value,
                trigger=trigger.value,
            )
            return False

        # Record transition
        trans = StateTransition(
            from_state=self._current_state,
            to_state=new_state,
            trigger=trigger,
            metadata=metadata or {},
        )
        self._history.append(trans)

        # Exit old state
        self._on_exit(self._current_state)

        # Enter new state
        self._current_state = new_state
        self._state_entered_at = time.time()
        self._on_enter(new_state)

        return True

    def check_timeout(self) -> bool:
        """Check if current state has timed out."""
        timeout = STATE_TIMEOUTS.get(self._current_state)
        if timeout and self.time_in_state > timeout:
            if self._retry_count < self._max_retries:
                self._retry_count += 1
                self.transition(TransitionTrigger.TIMEOUT_TRIGGER)
                return True
            else:
                self.transition(TransitionTrigger.FAIL, {"reason": "max_retries_exceeded"})
                return True
        return False

    def build_fsm_prompt(self) -> str:
        """Build state machine context for LLM."""
        lines = ["## Agent State\n"]

        lines.append(
            f"Current: {self._current_state.value} "
            f"({self.time_in_state:.0f}s)"
        )

        # Available transitions
        available = VALID_TRANSITIONS.get(self._current_state, {})
        if available:
            triggers = [t.value for t in available.keys()]
            lines.append(f"Available: {', '.join(triggers)}")

        # Check timeout
        timeout = STATE_TIMEOUTS.get(self._current_state)
        if timeout:
            remaining = max(0, timeout - self.time_in_state)
            lines.append(f"Timeout: {remaining:.0f}s remaining")

        # Recent history
        if self._history:
            lines.append(f"\nHistory ({len(self._history)} transitions):")
            for t in self._history[-5:]:
                lines.append(
                    f"  {t.from_state.value[:8]} → {t.to_state.value[:8]} "
                    f"({t.trigger.value})"
                )

        if self._retry_count > 0:
            lines.append(f"Retries: {self._retry_count}/{self._max_retries}")

        return "\n".join(lines)

    def _on_enter(self, state: AgentState) -> None:
        """Hook called when entering a state."""
        if state == AgentState.COMPLETED:
            self._retry_count = 0
        elif state == AgentState.TIMEOUT:
            pass

    def _on_exit(self, state: AgentState) -> None:
        """Hook called when exiting a state."""
        pass

    def get_stats(self) -> dict[str, Any]:
        state_durations: dict[str, float] = {}
        for i, t in enumerate(self._history):
            if i + 1 < len(self._history):
                duration = self._history[i + 1].timestamp - t.timestamp
            else:
                duration = time.time() - t.timestamp
            key = t.from_state.value
            state_durations[key] = state_durations.get(key, 0) + duration

        return {
            "current_state": self._current_state.value,
            "transitions": len(self._history),
            "retries": self._retry_count,
            "state_durations": state_durations,
        }
