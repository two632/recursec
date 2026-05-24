"""Agent state machine — FSM for assessment lifecycle.

Implements:
1. 14-state finite state machine
2. Valid transition enforcement
3. Loop detection
4. Transition history tracking
5. State-based action routing
6. State machine prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentState(str, Enum):
    IDLE = "idle"                   # Not started
    INITIALIZING = "initializing"   # Setting up
    PLANNING = "planning"           # Creating plan
    RECON = "recon"                 # Reconnaissance
    ENUMERATION = "enumeration"     # Service enumeration
    SCANNING = "scanning"           # Vulnerability scanning
    ANALYSIS = "analysis"           # Analyzing results
    EXPLOITATION = "exploitation"   # Exploiting vulns
    POST_EXPLOIT = "post_exploit"   # Post-exploitation
    VALIDATION = "validation"       # Validating findings
    REPORTING = "reporting"         # Generating report
    PAUSED = "paused"               # Temporarily paused
    ERROR = "error"                 # Error state
    COMPLETED = "completed"         # Assessment done


# Valid state transitions (from → list of allowed to)
TRANSITIONS: dict[AgentState, list[AgentState]] = {
    AgentState.IDLE: [AgentState.INITIALIZING],
    AgentState.INITIALIZING: [AgentState.PLANNING, AgentState.ERROR],
    AgentState.PLANNING: [AgentState.RECON, AgentState.ERROR, AgentState.PAUSED],
    AgentState.RECON: [AgentState.ENUMERATION, AgentState.ANALYSIS, AgentState.ERROR, AgentState.PAUSED],
    AgentState.ENUMERATION: [AgentState.SCANNING, AgentState.ANALYSIS, AgentState.ERROR, AgentState.PAUSED],
    AgentState.SCANNING: [AgentState.ANALYSIS, AgentState.EXPLOITATION, AgentState.ERROR, AgentState.PAUSED],
    AgentState.ANALYSIS: [AgentState.EXPLOITATION, AgentState.SCANNING, AgentState.RECON, AgentState.VALIDATION, AgentState.REPORTING, AgentState.ERROR, AgentState.PAUSED],
    AgentState.EXPLOITATION: [AgentState.POST_EXPLOIT, AgentState.ANALYSIS, AgentState.VALIDATION, AgentState.ERROR, AgentState.PAUSED],
    AgentState.POST_EXPLOIT: [AgentState.ANALYSIS, AgentState.VALIDATION, AgentState.REPORTING, AgentState.ERROR, AgentState.PAUSED],
    AgentState.VALIDATION: [AgentState.ANALYSIS, AgentState.REPORTING, AgentState.EXPLOITATION, AgentState.ERROR, AgentState.PAUSED],
    AgentState.REPORTING: [AgentState.COMPLETED, AgentState.ANALYSIS, AgentState.ERROR, AgentState.PAUSED],
    AgentState.PAUSED: [AgentState.PLANNING, AgentState.RECON, AgentState.ENUMERATION, AgentState.SCANNING, AgentState.ANALYSIS, AgentState.EXPLOITATION, AgentState.VALIDATION, AgentState.REPORTING],
    AgentState.ERROR: [AgentState.PLANNING, AgentState.PAUSED, AgentState.COMPLETED],
    AgentState.COMPLETED: [],
}

# Phase → recommended actions
STATE_ACTIONS: dict[AgentState, list[str]] = {
    AgentState.INITIALIZING: ["load_config", "verify_target", "check_scope"],
    AgentState.PLANNING: ["decompose_task", "select_tools", "allocate_budget"],
    AgentState.RECON: ["subdomain_enum", "dns_recon", "port_scan", "osint"],
    AgentState.ENUMERATION: ["service_detection", "version_scan", "dir_brute", "tech_fingerprint"],
    AgentState.SCANNING: ["vuln_scan", "web_scan", "config_audit", "ssl_check"],
    AgentState.ANALYSIS: ["correlate_findings", "prioritize_vulns", "identify_chains"],
    AgentState.EXPLOITATION: ["exploit_vuln", "verify_impact", "document_proof"],
    AgentState.POST_EXPLOIT: ["pivot", "escalate_privs", "extract_data", "persistence"],
    AgentState.VALIDATION: ["verify_finding", "reduce_fp", "cross_check"],
    AgentState.REPORTING: ["generate_report", "summarize_findings", "risk_rating"],
}


class StateEvent(str, Enum):
    START = "start"
    PLAN_COMPLETE = "plan_complete"
    EXECUTE = "execute"
    ANALYZE = "analyze"
    REPORT = "report"
    ERROR = "error"
    RETRY = "retry"
    DONE = "done"


@dataclass
class StateTransition:
    """A state transition record."""
    from_state: AgentState = AgentState.IDLE
    to_state: AgentState = AgentState.IDLE
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_state.value[:8],
            "to": self.to_state.value[:8],
        }


class AgentStateMachine:
    """Finite state machine for agent assessment lifecycle.

    Enforces valid transitions, detects loops,
    and provides state-based action routing.
    """

    def __init__(self, max_loop_count: int = 3) -> None:
        self._state = AgentState.IDLE
        self._history: list[StateTransition] = []
        self._state_counts: dict[AgentState, int] = {}
        self._max_loop = max_loop_count
        self._started_at = 0.0
        self._log = logger.bind(component="fsm")

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def is_terminal(self) -> bool:
        return self._state in (AgentState.COMPLETED, AgentState.ERROR)

    def can_transition(self, target: AgentState) -> bool:
        """Check if transition is valid."""
        allowed = TRANSITIONS.get(self._state, [])
        return target in allowed

    def transition(
        self,
        target: AgentState,
        reason: str = "",
    ) -> bool:
        """Attempt a state transition."""
        if not self.can_transition(target):
            self._log.warning(
                "invalid_transition",
                current=self._state.value,
                target=target.value,
            )
            return False

        record = StateTransition(
            from_state=self._state,
            to_state=target,
            reason=reason,
        )
        self._history.append(record)

        # Track state visits
        self._state_counts[target] = self._state_counts.get(target, 0) + 1

        old = self._state
        self._state = target

        if old == AgentState.IDLE:
            self._started_at = time.time()

        return True

    def detect_loop(self) -> bool:
        """Detect if the agent is in a loop."""
        if len(self._history) < 4:
            return False

        # Check for repeated state sequences
        recent = [t.to_state for t in self._history[-6:]]
        for state in set(recent):
            if recent.count(state) >= self._max_loop:
                return True

        return False

    def get_loop_states(self) -> list[AgentState]:
        """Get states involved in detected loops."""
        if len(self._history) < 4:
            return []

        recent = [t.to_state for t in self._history[-6:]]
        return [
            state for state in set(recent)
            if recent.count(state) >= self._max_loop
        ]

    def get_recommended_actions(self) -> list[str]:
        """Get recommended actions for current state."""
        return STATE_ACTIONS.get(self._state, [])

    def get_allowed_transitions(self) -> list[AgentState]:
        """Get allowed transitions from current state."""
        return TRANSITIONS.get(self._state, [])

    def get_phase_duration(self, state: AgentState) -> float:
        """Get total time spent in a state."""
        total = 0.0
        for i, record in enumerate(self._history):
            if record.to_state == state:
                # Time until next transition
                if i + 1 < len(self._history):
                    total += self._history[i + 1].timestamp - record.timestamp
                elif self._state == state:
                    total += time.time() - record.timestamp

        return total

    def build_fsm_prompt(self) -> str:
        """Build FSM context for LLM."""
        lines = ["## Assessment State\n"]
        lines.append(f"State: {self._state.value}")

        # Duration
        if self._started_at:
            elapsed = time.time() - self._started_at
            lines.append(f"Elapsed: {elapsed:.0f}s")

        # Allowed transitions
        allowed = self.get_allowed_transitions()
        if allowed:
            lines.append(f"Next: {', '.join(s.value[:8] for s in allowed)}")

        # Recommended actions
        actions = self.get_recommended_actions()
        if actions:
            lines.append(f"Actions: {', '.join(actions[:4])}")

        # Loop detection
        if self.detect_loop():
            loop_states = self.get_loop_states()
            lines.append(
                f"WARNING: Loop detected in {', '.join(s.value for s in loop_states)}"
            )

        # Recent transitions
        if self._history:
            lines.append("\nRecent:")
            for t in self._history[-3:]:
                lines.append(
                    f"  {t.from_state.value[:8]} → {t.to_state.value[:8]}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "transitions": len(self._history),
            "visits": {
                s.value: c for s, c in self._state_counts.items()
            },
            "loop_detected": self.detect_loop(),
        }
