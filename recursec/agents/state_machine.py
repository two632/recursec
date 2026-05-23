"""Agent state machine — complex state tracking and transition management.

Models agent lifecycle through well-defined states with guarded transitions,
rollback support, and state persistence. Enables complex multi-phase agent
behaviors with proper error recovery.

State graph:
  IDLE → INITIALIZING → PLANNING → EXECUTING → ANALYZING → REPORTING → COMPLETED
                    ↕           ↕           ↕           ↕
                  WAITING    WAITING    WAITING    WAITING
                    ↕           ↕           ↕           ↕
                  BLOCKED    BLOCKED    BLOCKED    BLOCKED
                    ↓           ↓           ↓           ↓
                  FAILED     FAILED     FAILED     FAILED
                    ↓           ↓           ↓           ↓
                  RECOVERING→ (back to previous state or FAILED)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    IDLE = "idle"
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"
    BLOCKED = "blocked"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    RECOVERING = "recovering"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    DELEGATING = "delegating"
    VALIDATING = "validating"


# Valid state transitions (from_state → set of to_states)
VALID_TRANSITIONS: dict[AgentState, set[AgentState]] = {
    AgentState.IDLE: {AgentState.INITIALIZING, AgentState.CANCELLED},
    AgentState.INITIALIZING: {
        AgentState.PLANNING, AgentState.FAILED, AgentState.CANCELLED,
    },
    AgentState.PLANNING: {
        AgentState.EXECUTING, AgentState.DELEGATING, AgentState.WAITING,
        AgentState.BLOCKED, AgentState.FAILED, AgentState.CANCELLED, AgentState.PAUSED,
    },
    AgentState.EXECUTING: {
        AgentState.ANALYZING, AgentState.WAITING, AgentState.BLOCKED,
        AgentState.DELEGATING, AgentState.VALIDATING, AgentState.PLANNING,
        AgentState.FAILED, AgentState.CANCELLED, AgentState.PAUSED, AgentState.COMPLETED,
    },
    AgentState.WAITING: {
        AgentState.EXECUTING, AgentState.PLANNING, AgentState.ANALYZING,
        AgentState.BLOCKED, AgentState.FAILED, AgentState.CANCELLED,
    },
    AgentState.BLOCKED: {
        AgentState.RECOVERING, AgentState.FAILED, AgentState.CANCELLED,
        AgentState.WAITING,
    },
    AgentState.ANALYZING: {
        AgentState.REPORTING, AgentState.EXECUTING, AgentState.PLANNING,
        AgentState.VALIDATING, AgentState.DELEGATING,
        AgentState.FAILED, AgentState.CANCELLED, AgentState.PAUSED, AgentState.COMPLETED,
    },
    AgentState.REPORTING: {
        AgentState.COMPLETED, AgentState.FAILED, AgentState.CANCELLED,
    },
    AgentState.RECOVERING: {
        AgentState.PLANNING, AgentState.EXECUTING, AgentState.ANALYZING,
        AgentState.FAILED, AgentState.CANCELLED,
    },
    AgentState.DELEGATING: {
        AgentState.WAITING, AgentState.EXECUTING, AgentState.ANALYZING,
        AgentState.FAILED, AgentState.CANCELLED,
    },
    AgentState.VALIDATING: {
        AgentState.ANALYZING, AgentState.EXECUTING, AgentState.REPORTING,
        AgentState.FAILED, AgentState.CANCELLED,
    },
    AgentState.PAUSED: {
        AgentState.PLANNING, AgentState.EXECUTING, AgentState.ANALYZING,
        AgentState.CANCELLED,
    },
    AgentState.COMPLETED: set(),
    AgentState.FAILED: {AgentState.RECOVERING},
    AgentState.CANCELLED: set(),
}


@dataclass
class StateTransition:
    """Record of a state transition."""
    from_state: AgentState
    to_state: AgentState
    timestamp: float = field(default_factory=time.time)
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_in_previous_s: float = 0.0


@dataclass
class StateCheckpoint:
    """Checkpoint of agent state for rollback support."""
    state: AgentState
    timestamp: float = field(default_factory=time.time)
    context: dict[str, Any] = field(default_factory=dict)
    findings_count: int = 0
    step_count: int = 0
    token_usage: int = 0


TransitionGuard = Callable[[AgentState, AgentState, dict[str, Any]], bool]
TransitionHook = Callable[[StateTransition], Coroutine[Any, Any, None]]


class AgentStateMachine:
    """Manages agent state with guarded transitions, hooks, and rollback.

    Features:
    - Validated transitions (only allowed state changes)
    - Guard functions (conditional transitions)
    - Entry/exit hooks per state
    - Transition history with timing
    - Checkpoint/rollback support
    - State duration tracking
    - Deadlock detection
    """

    def __init__(self, agent_id: str, initial_state: AgentState = AgentState.IDLE) -> None:
        self.agent_id = agent_id
        self._state = initial_state
        self._state_entered_at = time.time()
        self._history: list[StateTransition] = []
        self._checkpoints: list[StateCheckpoint] = []
        self._guards: list[TransitionGuard] = []
        self._entry_hooks: dict[AgentState, list[TransitionHook]] = defaultdict(list)
        self._exit_hooks: dict[AgentState, list[TransitionHook]] = defaultdict(list)
        self._transition_hooks: list[TransitionHook] = []
        self._state_durations: dict[str, float] = defaultdict(float)
        self._transition_counts: dict[str, int] = defaultdict(int)
        self._max_history = 500
        self._deadlock_threshold_s = 300.0  # 5 minutes in same state
        self._log = logger.bind(agent_id=agent_id)

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def is_terminal(self) -> bool:
        return self._state in (AgentState.COMPLETED, AgentState.FAILED, AgentState.CANCELLED)

    @property
    def is_active(self) -> bool:
        return self._state in (
            AgentState.PLANNING, AgentState.EXECUTING, AgentState.ANALYZING,
            AgentState.DELEGATING, AgentState.VALIDATING,
        )

    @property
    def time_in_current_state(self) -> float:
        return time.time() - self._state_entered_at

    def can_transition(self, to_state: AgentState) -> bool:
        """Check if transition is valid without performing it."""
        valid = VALID_TRANSITIONS.get(self._state, set())
        if to_state not in valid:
            return False
        return all(
            guard(self._state, to_state, {})
            for guard in self._guards
        )

    async def transition(
        self,
        to_state: AgentState,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Attempt a state transition. Returns True if successful."""
        from_state = self._state
        meta = metadata or {}

        # Validate
        valid = VALID_TRANSITIONS.get(from_state, set())
        if to_state not in valid:
            self._log.warning(
                "invalid_transition",
                from_state=from_state.value, to_state=to_state.value,
                valid=sorted(s.value for s in valid),
            )
            return False

        # Check guards
        for guard in self._guards:
            if not guard(from_state, to_state, meta):
                self._log.info("transition_blocked_by_guard", from_state=from_state.value, to_state=to_state.value)
                return False

        # Record timing
        duration = time.time() - self._state_entered_at
        self._state_durations[from_state.value] += duration

        # Create transition record
        transition = StateTransition(
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            metadata=meta,
            duration_in_previous_s=duration,
        )

        # Execute exit hooks for current state
        for hook in self._exit_hooks.get(from_state, []):
            try:
                await hook(transition)
            except Exception as e:
                self._log.error("exit_hook_error", state=from_state.value, error=str(e))

        # Perform transition
        self._state = to_state
        self._state_entered_at = time.time()
        self._history.append(transition)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        key = f"{from_state.value}→{to_state.value}"
        self._transition_counts[key] += 1

        # Execute entry hooks for new state
        for hook in self._entry_hooks.get(to_state, []):
            try:
                await hook(transition)
            except Exception as e:
                self._log.error("entry_hook_error", state=to_state.value, error=str(e))

        # Execute global transition hooks
        for hook in self._transition_hooks:
            try:
                await hook(transition)
            except Exception as e:
                self._log.error("transition_hook_error", error=str(e))

        self._log.info(
            "state_transition",
            from_state=from_state.value, to_state=to_state.value,
            reason=reason, duration_s=round(duration, 2),
        )

        return True

    def add_guard(self, guard: TransitionGuard) -> None:
        """Add a transition guard function."""
        self._guards.append(guard)

    def on_enter(self, state: AgentState, hook: TransitionHook) -> None:
        """Register a hook for entering a state."""
        self._entry_hooks[state].append(hook)

    def on_exit(self, state: AgentState, hook: TransitionHook) -> None:
        """Register a hook for exiting a state."""
        self._exit_hooks[state].append(hook)

    def on_transition(self, hook: TransitionHook) -> None:
        """Register a hook for any transition."""
        self._transition_hooks.append(hook)

    # ── Checkpoint / Rollback ──────────────────────────────

    def checkpoint(self, context: dict[str, Any] | None = None) -> int:
        """Create a checkpoint. Returns checkpoint index."""
        cp = StateCheckpoint(
            state=self._state,
            context=context or {},
        )
        self._checkpoints.append(cp)
        return len(self._checkpoints) - 1

    async def rollback(self, checkpoint_index: int = -1) -> bool:
        """Rollback to a checkpoint."""
        if not self._checkpoints:
            return False
        cp = self._checkpoints[checkpoint_index]
        return await self.transition(
            cp.state,
            reason=f"rollback to checkpoint {checkpoint_index}",
            metadata={"checkpoint": cp.context},
        )

    # ── Deadlock Detection ──────────────────────────────────

    def check_deadlock(self) -> bool:
        """Check if agent appears stuck."""
        if self.is_terminal:
            return False
        if self.time_in_current_state > self._deadlock_threshold_s:
            return True
        # Check for transition loops (same transitions repeated)
        if len(self._history) >= 6:
            recent = [
                (t.from_state.value, t.to_state.value)
                for t in self._history[-6:]
            ]
            if len(set(recent)) <= 2:
                return True
        return False

    # ── Reporting ───────────────────────────────────────────

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get transition history."""
        return [
            {
                "from": t.from_state.value, "to": t.to_state.value,
                "reason": t.reason, "timestamp": t.timestamp,
                "duration_s": round(t.duration_in_previous_s, 2),
            }
            for t in self._history[-limit:]
        ]

    def get_stats(self) -> dict[str, Any]:
        """Get state machine statistics."""
        return {
            "current_state": self._state.value,
            "time_in_state_s": round(self.time_in_current_state, 1),
            "total_transitions": len(self._history),
            "state_durations": {k: round(v, 1) for k, v in self._state_durations.items()},
            "transition_counts": dict(self._transition_counts),
            "checkpoints": len(self._checkpoints),
            "is_deadlocked": self.check_deadlock(),
        }


class MultiAgentStateTracker:
    """Tracks state of multiple agents for orchestration."""

    def __init__(self) -> None:
        self._machines: dict[str, AgentStateMachine] = {}
        self._dependencies: dict[str, set[str]] = defaultdict(set)

    def register(self, agent_id: str, machine: AgentStateMachine) -> None:
        self._machines[agent_id] = machine

    def unregister(self, agent_id: str) -> None:
        self._machines.pop(agent_id, None)
        self._dependencies.pop(agent_id, None)

    def add_dependency(self, agent_id: str, depends_on: str) -> None:
        """Agent depends on another agent completing first."""
        self._dependencies[agent_id].add(depends_on)

    def can_start(self, agent_id: str) -> bool:
        """Check if all dependencies are satisfied."""
        for dep in self._dependencies.get(agent_id, set()):
            dep_machine = self._machines.get(dep)
            if not dep_machine or dep_machine.state != AgentState.COMPLETED:
                return False
        return True

    def get_ready_agents(self) -> list[str]:
        """Get agents whose dependencies are all satisfied."""
        ready = []
        for agent_id, machine in self._machines.items():
            if machine.state == AgentState.IDLE and self.can_start(agent_id):
                ready.append(agent_id)
        return ready

    def get_blocked_agents(self) -> list[str]:
        """Get agents that are blocked."""
        return [
            aid for aid, m in self._machines.items()
            if m.state == AgentState.BLOCKED
        ]

    def get_deadlocked_agents(self) -> list[str]:
        """Get agents that appear deadlocked."""
        return [
            aid for aid, m in self._machines.items()
            if m.check_deadlock()
        ]

    def all_completed(self) -> bool:
        return all(m.is_terminal for m in self._machines.values())

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all agent states."""
        by_state: dict[str, list[str]] = defaultdict(list)
        for aid, m in self._machines.items():
            by_state[m.state.value].append(aid)
        return {
            "total": len(self._machines),
            "by_state": dict(by_state),
            "deadlocked": self.get_deadlocked_agents(),
            "ready": self.get_ready_agents(),
            "all_completed": self.all_completed(),
        }
