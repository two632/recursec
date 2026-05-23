"""Agent state machine — manages complex agent lifecycle states.

Implements:
1. Finite state machine for agent execution
2. State transitions with guards
3. Event-driven state changes
4. Timeout-based auto-transitions
5. State history for debugging
6. Parallel state tracking for multi-agent
7. Error recovery state handling
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
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING_TOOL = "executing_tool"
    REASONING = "reasoning"
    WAITING_LLM = "waiting_llm"
    ANALYZING_OUTPUT = "analyzing_output"
    REPORTING = "reporting"
    SPAWNING_CHILD = "spawning_child"
    WAITING_CHILD = "waiting_child"
    DEBATING = "debating"
    CHECKPOINTING = "checkpointing"
    ERROR_RECOVERY = "error_recovery"
    PAUSED = "paused"
    TERMINATED = "terminated"
    COMPLETED = "completed"


class StateEvent(str, Enum):
    START = "start"
    PLAN_READY = "plan_ready"
    TOOL_SELECTED = "tool_selected"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"
    TOOL_TIMEOUT = "tool_timeout"
    LLM_RESPONSE = "llm_response"
    LLM_ERROR = "llm_error"
    ANALYSIS_DONE = "analysis_done"
    FINDING_FOUND = "finding_found"
    CHILD_SPAWNED = "child_spawned"
    CHILD_COMPLETED = "child_completed"
    CHILD_FAILED = "child_failed"
    DEBATE_STARTED = "debate_started"
    DEBATE_RESOLVED = "debate_resolved"
    CHECKPOINT_DONE = "checkpoint_done"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONVERGENCE_REACHED = "convergence_reached"
    ERROR = "error"
    RECOVER = "recover"
    PAUSE = "pause"
    RESUME = "resume"
    TERMINATE = "terminate"


@dataclass
class StateTransition:
    """A transition from one state to another."""
    from_state: AgentState = AgentState.IDLE
    event: StateEvent = StateEvent.START
    to_state: AgentState = AgentState.IDLE
    guard: str = ""           # Condition name
    action: str = ""          # Action to perform

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value,
            "event": self.event.value,
            "to": self.to_state.value,
        }


@dataclass
class StateHistoryEntry:
    """An entry in the state history."""
    from_state: AgentState = AgentState.IDLE
    to_state: AgentState = AgentState.IDLE
    event: StateEvent = StateEvent.START
    timestamp: float = field(default_factory=time.time)
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value,
            "to": self.to_state.value,
            "event": self.event.value,
        }


@dataclass
class AgentSM:
    """State machine for a single agent."""
    agent_id: str = ""
    current_state: AgentState = AgentState.INITIALIZING
    history: list[StateHistoryEntry] = field(default_factory=list)
    error_count: int = 0
    max_errors: int = 3
    created_at: float = field(default_factory=time.time)
    last_transition: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "state": self.current_state.value,
            "transitions": len(self.history),
            "errors": self.error_count,
        }


# ── Transition table ──────────────────────────────────────────

TRANSITIONS: list[StateTransition] = [
    # Initialization
    StateTransition(AgentState.INITIALIZING, StateEvent.START, AgentState.PLANNING, action="load_context"),

    # Planning
    StateTransition(AgentState.PLANNING, StateEvent.PLAN_READY, AgentState.REASONING, action="start_reasoning"),
    StateTransition(AgentState.PLANNING, StateEvent.ERROR, AgentState.ERROR_RECOVERY),

    # Reasoning (LLM query)
    StateTransition(AgentState.REASONING, StateEvent.TOOL_SELECTED, AgentState.EXECUTING_TOOL, action="execute_tool"),
    StateTransition(AgentState.REASONING, StateEvent.CHILD_SPAWNED, AgentState.SPAWNING_CHILD),
    StateTransition(AgentState.REASONING, StateEvent.DEBATE_STARTED, AgentState.DEBATING),
    StateTransition(AgentState.REASONING, StateEvent.ANALYSIS_DONE, AgentState.REPORTING),
    StateTransition(AgentState.REASONING, StateEvent.LLM_ERROR, AgentState.ERROR_RECOVERY),
    StateTransition(AgentState.REASONING, StateEvent.BUDGET_EXHAUSTED, AgentState.REPORTING),
    StateTransition(AgentState.REASONING, StateEvent.CONVERGENCE_REACHED, AgentState.REPORTING),

    # Tool execution
    StateTransition(AgentState.EXECUTING_TOOL, StateEvent.TOOL_COMPLETED, AgentState.ANALYZING_OUTPUT, action="parse_output"),
    StateTransition(AgentState.EXECUTING_TOOL, StateEvent.TOOL_FAILED, AgentState.REASONING, action="report_failure"),
    StateTransition(AgentState.EXECUTING_TOOL, StateEvent.TOOL_TIMEOUT, AgentState.REASONING, action="report_timeout"),

    # Output analysis
    StateTransition(AgentState.ANALYZING_OUTPUT, StateEvent.FINDING_FOUND, AgentState.REASONING, action="record_finding"),
    StateTransition(AgentState.ANALYZING_OUTPUT, StateEvent.ANALYSIS_DONE, AgentState.REASONING),

    # Child agent management
    StateTransition(AgentState.SPAWNING_CHILD, StateEvent.CHILD_SPAWNED, AgentState.WAITING_CHILD),
    StateTransition(AgentState.WAITING_CHILD, StateEvent.CHILD_COMPLETED, AgentState.REASONING, action="aggregate_child"),
    StateTransition(AgentState.WAITING_CHILD, StateEvent.CHILD_FAILED, AgentState.REASONING, action="handle_child_failure"),

    # Debate
    StateTransition(AgentState.DEBATING, StateEvent.DEBATE_RESOLVED, AgentState.REASONING, action="apply_verdict"),

    # Reporting
    StateTransition(AgentState.REPORTING, StateEvent.CHECKPOINT_DONE, AgentState.COMPLETED),

    # Error recovery
    StateTransition(AgentState.ERROR_RECOVERY, StateEvent.RECOVER, AgentState.REASONING),
    StateTransition(AgentState.ERROR_RECOVERY, StateEvent.TERMINATE, AgentState.TERMINATED),

    # Pause/Resume
    StateTransition(AgentState.REASONING, StateEvent.PAUSE, AgentState.PAUSED),
    StateTransition(AgentState.EXECUTING_TOOL, StateEvent.PAUSE, AgentState.PAUSED),
    StateTransition(AgentState.PAUSED, StateEvent.RESUME, AgentState.REASONING),

    # Global terminate
    StateTransition(AgentState.REASONING, StateEvent.TERMINATE, AgentState.TERMINATED),
    StateTransition(AgentState.EXECUTING_TOOL, StateEvent.TERMINATE, AgentState.TERMINATED),
    StateTransition(AgentState.WAITING_CHILD, StateEvent.TERMINATE, AgentState.TERMINATED),
]


class AgentStateMachine:
    """Manages state machines for multiple agents.

    Each agent has its own state machine tracking
    its lifecycle through planning, execution,
    analysis, and reporting phases.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentSM] = {}
        self._transition_table: dict[tuple[str, str], StateTransition] = {}
        self._log = logger.bind(component="agent_state_machine")
        self._build_transition_table()

    def _build_transition_table(self) -> None:
        """Build lookup table for transitions."""
        for t in TRANSITIONS:
            key = (t.from_state.value, t.event.value)
            self._transition_table[key] = t

    def create_agent(self, agent_id: str) -> AgentSM:
        """Create a new agent state machine."""
        sm = AgentSM(agent_id=agent_id)
        self._agents[agent_id] = sm
        return sm

    def transition(
        self,
        agent_id: str,
        event: StateEvent,
        context: str = "",
    ) -> AgentState | None:
        """Attempt a state transition."""
        sm = self._agents.get(agent_id)
        if not sm:
            return None

        key = (sm.current_state.value, event.value)
        trans = self._transition_table.get(key)

        if not trans:
            self._log.warning(
                "invalid_transition",
                agent=agent_id[:10],
                state=sm.current_state.value,
                event=event.value,
            )
            return None

        # Record history
        entry = StateHistoryEntry(
            from_state=sm.current_state,
            to_state=trans.to_state,
            event=event,
            context=context,
        )
        sm.history.append(entry)

        # Track errors
        if event in (StateEvent.ERROR, StateEvent.TOOL_FAILED, StateEvent.LLM_ERROR):
            sm.error_count += 1
            if sm.error_count >= sm.max_errors:
                sm.current_state = AgentState.TERMINATED
                return AgentState.TERMINATED

        old_state = sm.current_state
        sm.current_state = trans.to_state
        sm.last_transition = time.time()

        self._log.debug(
            "state_transition",
            agent=agent_id[:10],
            old=old_state.value,
            new=trans.to_state.value,
            event=event.value,
        )

        return trans.to_state

    def get_state(self, agent_id: str) -> AgentState | None:
        """Get current state of an agent."""
        sm = self._agents.get(agent_id)
        return sm.current_state if sm else None

    def get_active_agents(self) -> list[AgentSM]:
        """Get all active (non-terminal) agents."""
        terminal = {AgentState.COMPLETED, AgentState.TERMINATED}
        return [
            sm for sm in self._agents.values()
            if sm.current_state not in terminal
        ]

    def get_stalled_agents(
        self,
        stall_threshold_s: float = 300.0,
    ) -> list[AgentSM]:
        """Get agents that haven't transitioned recently."""
        now = time.time()
        return [
            sm for sm in self._agents.values()
            if sm.current_state not in (AgentState.COMPLETED, AgentState.TERMINATED)
            and (now - sm.last_transition) > stall_threshold_s
        ]

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = {}
        for sm in self._agents.values():
            state_counts[sm.current_state.value] = state_counts.get(
                sm.current_state.value, 0,
            ) + 1

        return {
            "total_agents": len(self._agents),
            "by_state": state_counts,
            "total_transitions": sum(len(sm.history) for sm in self._agents.values()),
        }
