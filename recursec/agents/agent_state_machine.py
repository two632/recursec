"""Agent state machine — formal FSM for agent execution lifecycle.

Implements:
1. Assessment phase state machine
2. Agent execution state machine
3. Tool execution state machine
4. Transition guards and actions
5. State history tracking
6. Timeout enforcement
7. Error recovery states
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


# ── Assessment Phase FSM ─────────────────────────────────────

class AssessmentPhase(str, Enum):
    IDLE = "idle"
    INITIALIZING = "initializing"
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ABORTED = "aborted"


PHASE_TRANSITIONS: dict[str, list[str]] = {
    "idle": ["initializing"],
    "initializing": ["recon", "aborted"],
    "recon": ["scanning", "analysis", "aborted"],
    "scanning": ["analysis", "exploitation", "recon", "aborted"],
    "analysis": ["exploitation", "scanning", "validation", "reporting", "aborted"],
    "exploitation": ["post_exploit", "validation", "analysis", "aborted"],
    "post_exploit": ["validation", "analysis", "exploitation", "aborted"],
    "validation": ["reporting", "analysis", "exploitation", "aborted"],
    "reporting": ["completed", "analysis", "aborted"],
    "completed": ["idle"],
    "aborted": ["idle"],
}


# ── Agent Execution FSM ──────────────────────────────────────

class AgentState(str, Enum):
    CREATED = "created"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING_TOOL = "waiting_tool"
    ANALYZING = "analyzing"
    SPAWNING_CHILD = "spawning_child"
    WAITING_CHILD = "waiting_child"
    REFLECTING = "reflecting"
    BACKTRACKING = "backtracking"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


AGENT_TRANSITIONS: dict[str, list[str]] = {
    "created": ["planning"],
    "planning": ["executing", "spawning_child", "completed", "failed"],
    "executing": ["waiting_tool", "analyzing", "completed", "failed", "timed_out"],
    "waiting_tool": ["analyzing", "executing", "failed", "timed_out"],
    "analyzing": ["executing", "reflecting", "spawning_child", "completed", "backtracking"],
    "spawning_child": ["waiting_child", "failed"],
    "waiting_child": ["analyzing", "executing", "failed", "timed_out"],
    "reflecting": ["executing", "backtracking", "completed"],
    "backtracking": ["planning", "failed"],
    "completed": [],
    "failed": [],
    "timed_out": [],
}


# ── Tool Execution FSM ───────────────────────────────────────

class ToolState(str, Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    EXECUTING = "executing"
    PARSING = "parsing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


TOOL_TRANSITIONS: dict[str, list[str]] = {
    "queued": ["validating", "skipped"],
    "validating": ["executing", "skipped", "failed"],
    "executing": ["parsing", "failed", "timed_out"],
    "parsing": ["completed", "failed"],
    "completed": [],
    "failed": [],
    "timed_out": [],
    "skipped": [],
}


@dataclass
class StateTransition:
    """A recorded state transition."""
    from_state: str = ""
    to_state: str = ""
    trigger: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state,
            "to": self.to_state,
            "trigger": self.trigger[:20],
        }


@dataclass
class StateMachineInstance:
    """An instance of a state machine."""
    instance_id: str = ""
    machine_type: str = ""   # assessment, agent, tool
    current_state: str = ""
    history: list[StateTransition] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    timeout_s: float = 3600.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    @property
    def is_terminal(self) -> bool:
        transitions = _get_transitions(self.machine_type)
        return not transitions.get(self.current_state, [])

    @property
    def is_timed_out(self) -> bool:
        return self.age_s > self.timeout_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.instance_id[:10],
            "type": self.machine_type,
            "state": self.current_state,
            "age": round(self.age_s, 1),
            "transitions": len(self.history),
            "terminal": self.is_terminal,
        }


def _get_transitions(machine_type: str) -> dict[str, list[str]]:
    """Get transitions for a machine type."""
    if machine_type == "assessment":
        return PHASE_TRANSITIONS
    if machine_type == "agent":
        return AGENT_TRANSITIONS
    if machine_type == "tool":
        return TOOL_TRANSITIONS
    return {}


class AgentStateMachine:
    """Manages state machines for agents and assessments.

    Enforces valid transitions, tracks history,
    handles timeouts, and provides state context
    for LLM prompts.
    """

    def __init__(self) -> None:
        self._instances: dict[str, StateMachineInstance] = {}
        self._counter = 0
        self._log = logger.bind(component="agent_state_machine")

    def create_assessment(
        self,
        assessment_id: str = "",
        timeout_s: float = 14400.0,
    ) -> StateMachineInstance:
        """Create an assessment state machine."""
        return self._create(
            instance_id=assessment_id or self._next_id("asm"),
            machine_type="assessment",
            initial_state="idle",
            timeout_s=timeout_s,
        )

    def create_agent_sm(
        self,
        agent_id: str = "",
        timeout_s: float = 3600.0,
    ) -> StateMachineInstance:
        """Create an agent state machine."""
        return self._create(
            instance_id=agent_id or self._next_id("agt"),
            machine_type="agent",
            initial_state="created",
            timeout_s=timeout_s,
        )

    def create_tool_sm(
        self,
        tool_id: str = "",
        timeout_s: float = 300.0,
    ) -> StateMachineInstance:
        """Create a tool execution state machine."""
        return self._create(
            instance_id=tool_id or self._next_id("tl"),
            machine_type="tool",
            initial_state="queued",
            timeout_s=timeout_s,
        )

    def transition(
        self,
        instance_id: str,
        to_state: str,
        trigger: str = "",
    ) -> bool:
        """Transition a state machine."""
        instance = self._instances.get(instance_id)
        if not instance:
            return False

        transitions = _get_transitions(instance.machine_type)
        allowed = transitions.get(instance.current_state, [])

        if to_state not in allowed:
            self._log.warning(
                "invalid_transition",
                instance=instance_id[:10],
                current=instance.current_state,
                requested=to_state,
                allowed=allowed,
            )
            return False

        # Record transition
        transition = StateTransition(
            from_state=instance.current_state,
            to_state=to_state,
            trigger=trigger,
        )
        instance.history.append(transition)
        instance.current_state = to_state

        return True

    def check_timeouts(self) -> list[str]:
        """Check and enforce timeouts."""
        timed_out: list[str] = []
        for inst_id, inst in self._instances.items():
            if inst.is_timed_out and not inst.is_terminal:
                # Force to timed_out state if available
                transitions = _get_transitions(inst.machine_type)
                allowed = transitions.get(inst.current_state, [])
                if "timed_out" in allowed:
                    self.transition(inst_id, "timed_out", "timeout_enforcement")
                    timed_out.append(inst_id)
                elif "failed" in allowed:
                    self.transition(inst_id, "failed", "timeout_enforcement")
                    timed_out.append(inst_id)
                elif "aborted" in allowed:
                    self.transition(inst_id, "aborted", "timeout_enforcement")
                    timed_out.append(inst_id)
        return timed_out

    def get_state(self, instance_id: str) -> str:
        """Get current state."""
        instance = self._instances.get(instance_id)
        return instance.current_state if instance else ""

    def get_allowed(self, instance_id: str) -> list[str]:
        """Get allowed transitions."""
        instance = self._instances.get(instance_id)
        if not instance:
            return []
        transitions = _get_transitions(instance.machine_type)
        return transitions.get(instance.current_state, [])

    def build_state_prompt(self, instance_id: str = "") -> str:
        """Build state context for LLM."""
        lines = ["## State Machine Status\n"]

        if instance_id:
            inst = self._instances.get(instance_id)
            if inst:
                lines.append(f"Current state: {inst.current_state}")
                allowed = self.get_allowed(instance_id)
                lines.append(f"Allowed transitions: {', '.join(allowed)}")
                lines.append(f"Age: {inst.age_s:.0f}s / {inst.timeout_s:.0f}s timeout")
        else:
            # Show all active instances
            active = [
                i for i in self._instances.values()
                if not i.is_terminal
            ]
            for inst in active[:5]:
                lines.append(
                    f"  [{inst.machine_type}] {inst.instance_id[:10]}: "
                    f"{inst.current_state} ({inst.age_s:.0f}s)"
                )

        return "\n".join(lines)

    def _create(
        self,
        instance_id: str,
        machine_type: str,
        initial_state: str,
        timeout_s: float,
    ) -> StateMachineInstance:
        """Create a state machine instance."""
        instance = StateMachineInstance(
            instance_id=instance_id,
            machine_type=machine_type,
            current_state=initial_state,
            timeout_s=timeout_s,
        )
        self._instances[instance_id] = instance
        return instance

    def _next_id(self, prefix: str) -> str:
        """Generate next instance ID."""
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        terminal_count = 0
        for inst in self._instances.values():
            type_counts[inst.machine_type] = type_counts.get(inst.machine_type, 0) + 1
            if inst.is_terminal:
                terminal_count += 1

        return {
            "total_instances": len(self._instances),
            "by_type": type_counts,
            "terminal": terminal_count,
            "active": len(self._instances) - terminal_count,
        }
