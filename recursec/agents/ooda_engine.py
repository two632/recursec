"""OODA engine — Observe-Orient-Decide-Act loop for autonomous operation.

Implements:
1. Full OODA loop (Observe → Orient → Decide → Act)
2. Stagnation detection (no new findings in N cycles)
3. Strategy switching when stagnant
4. Depth-first vs breadth-first mode switching
5. Budget tracking and adaptive allocation
6. Phase transitions (recon → vuln discovery → exploitation → report)
7. Cycle history and progress tracking
8. LLM-driven decision making at each stage
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OODAPhase(str, Enum):
    OBSERVE = "observe"
    ORIENT = "orient"
    DECIDE = "decide"
    ACT = "act"


class AssessmentPhase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    VULN_DISCOVERY = "vuln_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    COMPLETE = "complete"


class SearchMode(str, Enum):
    BREADTH_FIRST = "breadth_first"    # Wide coverage
    DEPTH_FIRST = "depth_first"        # Deep investigation
    TARGETED = "targeted"               # Focus on specific finding
    EXPLORATORY = "exploratory"         # Try new strategies


class StagnationAction(str, Enum):
    SWITCH_STRATEGY = "switch_strategy"
    SWITCH_MODE = "switch_mode"
    ADVANCE_PHASE = "advance_phase"
    INCREASE_DEPTH = "increase_depth"
    TRY_DIFFERENT_MODEL = "try_different_model"
    RESET_AND_RETRY = "reset_and_retry"


@dataclass
class Observation:
    """What the agent observes in the current state."""
    observation_id: str = ""
    new_findings_count: int = 0
    total_findings: int = 0
    tools_output: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    targets_discovered: int = 0
    attack_surfaces_found: int = 0
    tokens_used: int = 0
    time_elapsed_s: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.observation_id,
            "new_findings": self.new_findings_count,
            "total_findings": self.total_findings,
            "errors": len(self.errors),
            "targets": self.targets_discovered,
            "tokens": self.tokens_used,
        }


@dataclass
class Orientation:
    """How the agent interprets the current situation."""
    orientation_id: str = ""
    current_phase: AssessmentPhase = AssessmentPhase.RECON
    current_mode: SearchMode = SearchMode.BREADTH_FIRST
    stagnation_cycles: int = 0
    progress_rate: float = 0.0     # Findings per cycle
    coverage_estimate: float = 0.0  # 0-1
    risk_findings: dict[str, int] = field(default_factory=dict)  # severity → count
    strategy_effectiveness: dict[str, float] = field(default_factory=dict)
    assessment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.orientation_id,
            "phase": self.current_phase.value,
            "mode": self.current_mode.value,
            "stagnation": self.stagnation_cycles,
            "progress_rate": round(self.progress_rate, 2),
            "coverage": round(self.coverage_estimate, 2),
        }


@dataclass
class Decision:
    """What the agent decides to do next."""
    decision_id: str = ""
    action_type: str = ""          # "run_tool", "spawn_agent", "switch_strategy"
    target: str = ""
    strategy: str = ""
    tool: str = ""
    model: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    estimated_tokens: int = 0
    priority: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id,
            "action": self.action_type[:20],
            "strategy": self.strategy[:20],
            "tool": self.tool[:15],
            "priority": round(self.priority, 2),
        }


@dataclass
class ActionResult:
    """Result of executing a decision."""
    result_id: str = ""
    decision_id: str = ""
    success: bool = False
    findings_produced: int = 0
    output_summary: str = ""
    tokens_used: int = 0
    duration_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.result_id,
            "decision": self.decision_id[:10],
            "success": self.success,
            "findings": self.findings_produced,
            "tokens": self.tokens_used,
        }


@dataclass
class OODACycle:
    """A complete OODA cycle."""
    cycle_num: int = 0
    observation: Observation | None = None
    orientation: Orientation | None = None
    decision: Decision | None = None
    action_result: ActionResult | None = None
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle": self.cycle_num,
            "duration": round(self.duration_s, 1),
            "findings": (
                self.action_result.findings_produced
                if self.action_result else 0
            ),
        }


# ── Phase Transition Rules ────────────────────────────────────

PHASE_TRANSITIONS: dict[str, dict[str, Any]] = {
    "recon": {
        "next": "scanning",
        "advance_when": {
            "min_cycles": 3,
            "min_targets": 1,
            "stagnation_threshold": 5,
        },
    },
    "scanning": {
        "next": "vuln_discovery",
        "advance_when": {
            "min_cycles": 5,
            "min_findings": 0,
            "stagnation_threshold": 4,
        },
    },
    "vuln_discovery": {
        "next": "exploitation",
        "advance_when": {
            "min_cycles": 5,
            "min_findings": 1,
            "stagnation_threshold": 6,
        },
    },
    "exploitation": {
        "next": "post_exploit",
        "advance_when": {
            "min_cycles": 3,
            "stagnation_threshold": 4,
        },
    },
    "post_exploit": {
        "next": "reporting",
        "advance_when": {
            "min_cycles": 2,
            "stagnation_threshold": 3,
        },
    },
    "reporting": {
        "next": "complete",
        "advance_when": {
            "min_cycles": 1,
        },
    },
}

# ── Stagnation Response Strategies ────────────────────────────

STAGNATION_RESPONSES: list[dict[str, Any]] = [
    {"threshold": 3, "action": "switch_strategy", "desc": "Try a different attack strategy"},
    {"threshold": 5, "action": "switch_mode", "desc": "Switch between breadth/depth search"},
    {"threshold": 7, "action": "try_different_model", "desc": "Use a different LLM for analysis"},
    {"threshold": 10, "action": "advance_phase", "desc": "Move to next assessment phase"},
    {"threshold": 15, "action": "reset_and_retry", "desc": "Reset approach completely"},
]


class OODAEngine:
    """Autonomous Observe-Orient-Decide-Act loop.

    Drives the agent's autonomous operation by cycling through
    observation, orientation, decision, and action phases.
    Detects stagnation and adapts strategy automatically.
    """

    def __init__(
        self,
        max_cycles: int = 100,
        stagnation_threshold: int = 5,
        token_budget: int = 500000,
    ) -> None:
        self._max_cycles = max_cycles
        self._stagnation_threshold = stagnation_threshold
        self._token_budget = token_budget
        self._tokens_used = 0
        self._cycles: list[OODACycle] = []
        self._current_phase = AssessmentPhase.RECON
        self._current_mode = SearchMode.BREADTH_FIRST
        self._current_strategy = ""
        self._stagnation_counter = 0
        self._total_findings = 0
        self._phase_findings: dict[str, int] = defaultdict(int)
        self._phase_cycles: dict[str, int] = defaultdict(int)
        self._obs_counter = 0
        self._orient_counter = 0
        self._decision_counter = 0
        self._result_counter = 0
        self._log = logger.bind(component="ooda_engine")

    @property
    def current_cycle(self) -> int:
        return len(self._cycles)

    @property
    def is_complete(self) -> bool:
        return (
            self._current_phase == AssessmentPhase.COMPLETE or
            self.current_cycle >= self._max_cycles or
            self._tokens_used >= self._token_budget
        )

    def observe(
        self,
        new_findings: int = 0,
        tool_outputs: list[str] | None = None,
        errors: list[str] | None = None,
        targets_discovered: int = 0,
        attack_surfaces: int = 0,
        tokens_used: int = 0,
    ) -> Observation:
        """Observe the current state."""
        self._obs_counter += 1
        self._total_findings += new_findings
        self._tokens_used += tokens_used

        obs = Observation(
            observation_id=f"obs-{self._obs_counter}",
            new_findings_count=new_findings,
            total_findings=self._total_findings,
            tools_output=tool_outputs or [],
            errors=errors or [],
            targets_discovered=targets_discovered,
            attack_surfaces_found=attack_surfaces,
            tokens_used=tokens_used,
        )

        # Track stagnation
        if new_findings == 0:
            self._stagnation_counter += 1
        else:
            self._stagnation_counter = 0

        return obs

    def orient(self, observation: Observation) -> Orientation:
        """Orient — interpret the current situation."""
        self._orient_counter += 1

        # Calculate progress rate (findings per cycle)
        recent_cycles = self._cycles[-5:] if self._cycles else []
        recent_findings = sum(
            c.action_result.findings_produced
            for c in recent_cycles
            if c.action_result
        )
        progress_rate = recent_findings / max(1, len(recent_cycles))

        # Estimate coverage
        coverage = min(1.0, self._total_findings / max(1, 50))

        # Check if phase should advance
        self._check_phase_transition(observation)

        orientation = Orientation(
            orientation_id=f"orient-{self._orient_counter}",
            current_phase=self._current_phase,
            current_mode=self._current_mode,
            stagnation_cycles=self._stagnation_counter,
            progress_rate=progress_rate,
            coverage_estimate=coverage,
        )

        return orientation

    def decide(self, orientation: Orientation) -> Decision:
        """Decide what to do next."""
        self._decision_counter += 1

        decision = Decision(
            decision_id=f"dec-{self._decision_counter}",
        )

        # Handle stagnation
        if self._stagnation_counter >= self._stagnation_threshold:
            stagnation_action = self._get_stagnation_response()
            decision.action_type = stagnation_action.value
            decision.rationale = f"Stagnant for {self._stagnation_counter} cycles"
            self._apply_stagnation_action(stagnation_action)
            return decision

        # Normal decision based on phase
        if self._current_phase == AssessmentPhase.RECON:
            decision.action_type = "run_tool"
            decision.strategy = "deep_infrastructure_fingerprint"
            decision.tool = "nmap"
            decision.rationale = "Reconnaissance phase: mapping infrastructure"

        elif self._current_phase == AssessmentPhase.SCANNING:
            decision.action_type = "run_tool"
            decision.strategy = "classic_vuln_scanning"
            decision.tool = "nuclei"
            decision.rationale = "Scanning phase: running vulnerability scans"

        elif self._current_phase == AssessmentPhase.VULN_DISCOVERY:
            decision.action_type = "spawn_agent"
            decision.strategy = self._current_strategy or "business_logic_analysis"
            decision.rationale = "Discovery phase: deep vulnerability analysis"

        elif self._current_phase == AssessmentPhase.EXPLOITATION:
            decision.action_type = "spawn_agent"
            decision.strategy = "safe_exploitation_validation"
            decision.rationale = "Exploitation phase: validating findings"

        elif self._current_phase == AssessmentPhase.POST_EXPLOIT:
            decision.action_type = "spawn_agent"
            decision.strategy = "lateral_movement_assessment"
            decision.rationale = "Post-exploit: assessing blast radius"

        elif self._current_phase == AssessmentPhase.REPORTING:
            decision.action_type = "generate_report"
            decision.rationale = "Generating final report"

        decision.priority = self._calculate_priority(orientation)

        return decision

    def act(
        self,
        decision: Decision,
        success: bool = False,
        findings_produced: int = 0,
        output_summary: str = "",
        tokens_used: int = 0,
        duration_s: float = 0.0,
        error: str = "",
    ) -> ActionResult:
        """Record the result of acting on a decision."""
        self._result_counter += 1

        result = ActionResult(
            result_id=f"act-{self._result_counter}",
            decision_id=decision.decision_id,
            success=success,
            findings_produced=findings_produced,
            output_summary=output_summary,
            tokens_used=tokens_used,
            duration_s=duration_s,
            error=error,
        )

        self._phase_findings[self._current_phase.value] += findings_produced
        self._phase_cycles[self._current_phase.value] += 1

        return result

    def complete_cycle(
        self,
        observation: Observation,
        orientation: Orientation,
        decision: Decision,
        action_result: ActionResult,
    ) -> OODACycle:
        """Record a complete OODA cycle."""
        cycle = OODACycle(
            cycle_num=len(self._cycles) + 1,
            observation=observation,
            orientation=orientation,
            decision=decision,
            action_result=action_result,
            completed_at=time.time(),
        )
        self._cycles.append(cycle)
        return cycle

    def _check_phase_transition(self, observation: Observation) -> None:
        """Check if we should advance to the next phase."""
        phase_key = self._current_phase.value
        transition = PHASE_TRANSITIONS.get(phase_key)
        if not transition:
            return

        advance_when = transition["advance_when"]
        phase_cycle_count = self._phase_cycles.get(phase_key, 0)
        phase_finding_count = self._phase_findings.get(phase_key, 0)

        min_cycles = advance_when.get("min_cycles", 0)
        stagnation_thresh = advance_when.get("stagnation_threshold", 999)

        if phase_cycle_count < min_cycles:
            return

        should_advance = False

        # Stagnation-based advance
        if self._stagnation_counter >= stagnation_thresh:
            should_advance = True

        # Findings-based advance
        min_findings = advance_when.get("min_findings")
        if min_findings is not None and phase_finding_count >= min_findings:
            if phase_cycle_count >= min_cycles:
                should_advance = True

        if should_advance:
            next_phase = transition["next"]
            self._current_phase = AssessmentPhase(next_phase)
            self._stagnation_counter = 0

    def _get_stagnation_response(self) -> StagnationAction:
        """Get the appropriate stagnation response."""
        for response in STAGNATION_RESPONSES:
            if self._stagnation_counter >= response["threshold"]:
                return StagnationAction(response["action"])

        return StagnationAction.SWITCH_STRATEGY

    def _apply_stagnation_action(self, action: StagnationAction) -> None:
        """Apply a stagnation response."""
        if action == StagnationAction.SWITCH_MODE:
            if self._current_mode == SearchMode.BREADTH_FIRST:
                self._current_mode = SearchMode.DEPTH_FIRST
            else:
                self._current_mode = SearchMode.BREADTH_FIRST

        elif action == StagnationAction.ADVANCE_PHASE:
            phase_key = self._current_phase.value
            transition = PHASE_TRANSITIONS.get(phase_key)
            if transition:
                self._current_phase = AssessmentPhase(transition["next"])
                self._stagnation_counter = 0

    @staticmethod
    def _calculate_priority(orientation: Orientation) -> float:
        """Calculate decision priority based on orientation."""
        priority = 0.5

        # Higher priority if stagnant (need to break out)
        if orientation.stagnation_cycles > 0:
            priority += min(0.3, orientation.stagnation_cycles * 0.05)

        # Higher priority in later phases (exploitation > recon)
        phase_weights = {
            AssessmentPhase.RECON: 0.0,
            AssessmentPhase.SCANNING: 0.05,
            AssessmentPhase.VULN_DISCOVERY: 0.1,
            AssessmentPhase.EXPLOITATION: 0.15,
            AssessmentPhase.POST_EXPLOIT: 0.1,
            AssessmentPhase.REPORTING: 0.05,
        }
        priority += phase_weights.get(orientation.current_phase, 0.0)

        return min(1.0, priority)

    def generate_ooda_prompt(self) -> str:
        """Generate an LLM prompt for OODA decision-making."""
        recent = self._cycles[-3:]
        history = ""
        for cycle in recent:
            if cycle.decision and cycle.action_result:
                history += (
                    f"  Cycle {cycle.cycle_num}: "
                    f"{cycle.decision.action_type} → "
                    f"{'success' if cycle.action_result.success else 'fail'} "
                    f"({cycle.action_result.findings_produced} findings)\n"
                )

        return (
            f"Assessment state:\n"
            f"  Phase: {self._current_phase.value}\n"
            f"  Mode: {self._current_mode.value}\n"
            f"  Cycle: {self.current_cycle}/{self._max_cycles}\n"
            f"  Total findings: {self._total_findings}\n"
            f"  Stagnation: {self._stagnation_counter} cycles\n"
            f"  Tokens: {self._tokens_used}/{self._token_budget}\n\n"
            f"Recent history:\n{history}\n"
            f"What should the next action be? Consider:\n"
            f"1. Are we making progress or stagnant?\n"
            f"2. Should we go deeper on current findings or explore new surfaces?\n"
            f"3. Are there advanced attack surfaces we haven't tried?\n"
            f"4. Should we advance to the next phase?\n"
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "cycles": len(self._cycles),
            "phase": self._current_phase.value,
            "mode": self._current_mode.value,
            "stagnation": self._stagnation_counter,
            "total_findings": self._total_findings,
            "tokens": f"{self._tokens_used}/{self._token_budget}",
            "by_phase": dict(self._phase_findings),
            "complete": self.is_complete,
        }
