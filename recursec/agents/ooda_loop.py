"""OODA loop engine — Observe-Orient-Decide-Act cycle.

Implements:
1. OODA phase management
2. Observation collection from tools/scans
3. Orientation (situation awareness, threat modeling)
4. Decision making with LLM reasoning
5. Action execution and feedback
6. Loop iteration with convergence tracking
7. Phase transition rules
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


class ObservationType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    SCAN_RESULT = "scan_result"
    NETWORK_STATE = "network_state"
    SERVICE_INFO = "service_info"
    VULN_INDICATOR = "vuln_indicator"
    ERROR_SIGNAL = "error_signal"
    FINDING = "finding"
    AGENT_REPORT = "agent_report"


class DecisionType(str, Enum):
    RUN_TOOL = "run_tool"
    SPAWN_AGENT = "spawn_agent"
    CHANGE_STRATEGY = "change_strategy"
    INVESTIGATE_DEEPER = "investigate_deeper"
    VALIDATE_FINDING = "validate_finding"
    REPORT_FINDING = "report_finding"
    SKIP = "skip"
    ESCALATE = "escalate"
    PIVOT = "pivot"


@dataclass
class Observation:
    """Data collected during observe phase."""
    obs_id: str = ""
    obs_type: ObservationType = ObservationType.TOOL_OUTPUT
    source: str = ""
    data: str = ""
    severity: str = "info"
    tags: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.obs_id[:10],
            "type": self.obs_type.value,
            "source": self.source[:15],
            "severity": self.severity,
        }


@dataclass
class Orientation:
    """Situational awareness from orient phase."""
    threats: list[str] = field(default_factory=list)
    opportunities: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    attack_surface_summary: str = ""
    current_hypothesis: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "threats": len(self.threats),
            "opportunities": len(self.opportunities),
            "unknowns": len(self.unknowns),
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Decision:
    """Decision from decide phase."""
    decision_type: DecisionType = DecisionType.RUN_TOOL
    action: str = ""
    tool: str = ""
    args: list[str] = field(default_factory=list)
    reasoning: str = ""
    priority: int = 0
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.decision_type.value,
            "action": self.action[:20],
            "priority": self.priority,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ActionResult:
    """Result from act phase."""
    decision: Decision = field(default_factory=Decision)
    success: bool = False
    output: str = ""
    new_observations: list[Observation] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "new_obs": len(self.new_observations),
            "findings": len(self.findings),
            "duration_s": round(self.duration_s, 2),
        }


@dataclass
class OODACycle:
    """A complete OODA cycle."""
    cycle_id: str = ""
    cycle_number: int = 0
    current_phase: OODAPhase = OODAPhase.OBSERVE
    observations: list[Observation] = field(default_factory=list)
    orientation: Orientation = field(default_factory=Orientation)
    decisions: list[Decision] = field(default_factory=list)
    results: list[ActionResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at == 0:
            return time.time() - self.started_at
        return self.completed_at - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cycle_id[:10],
            "cycle": self.cycle_number,
            "phase": self.current_phase.value,
            "obs": len(self.observations),
            "decisions": len(self.decisions),
        }


# ── Orientation templates ─────────────────────────────────────

ORIENTATION_PROMPTS: dict[str, str] = {
    "initial_recon": (
        "ORIENT PHASE — Initial Reconnaissance:\n"
        "Given the observations so far, analyze:\n"
        "1. What is the target's technology stack?\n"
        "2. What services are exposed?\n"
        "3. What are the most likely attack vectors?\n"
        "4. What information is still missing?\n"
        "5. What should we investigate next?"
    ),
    "vulnerability_analysis": (
        "ORIENT PHASE — Vulnerability Analysis:\n"
        "Given scan results, analyze:\n"
        "1. Which findings are most likely true positives?\n"
        "2. What is the exploitation difficulty for each?\n"
        "3. Can any findings be chained together?\n"
        "4. What additional scans should confirm findings?\n"
        "5. Priority ranking of findings?"
    ),
    "exploitation_planning": (
        "ORIENT PHASE — Exploitation Planning:\n"
        "Given confirmed vulnerabilities, analyze:\n"
        "1. Which vuln has highest impact with lowest risk?\n"
        "2. What exploitation technique is most appropriate?\n"
        "3. What tools and payloads are needed?\n"
        "4. What are the potential failure modes?\n"
        "5. How do we verify successful exploitation?"
    ),
    "post_exploitation": (
        "ORIENT PHASE — Post-Exploitation:\n"
        "Given successful exploitation, analyze:\n"
        "1. What access level was achieved?\n"
        "2. What lateral movement opportunities exist?\n"
        "3. What sensitive data is accessible?\n"
        "4. What privilege escalation paths are available?\n"
        "5. What evidence should be collected?"
    ),
}


# ── Decision templates ────────────────────────────────────────

DECISION_RULES: list[dict[str, Any]] = [
    {
        "condition": "no_observations",
        "decision": DecisionType.RUN_TOOL,
        "action": "Start reconnaissance with nmap and subfinder",
        "priority": 100,
    },
    {
        "condition": "open_ports_found",
        "decision": DecisionType.RUN_TOOL,
        "action": "Run service version detection and vulnerability scanning",
        "priority": 80,
    },
    {
        "condition": "web_service_found",
        "decision": DecisionType.SPAWN_AGENT,
        "action": "Spawn web scanning agent for deep analysis",
        "priority": 85,
    },
    {
        "condition": "vuln_indicator_found",
        "decision": DecisionType.VALIDATE_FINDING,
        "action": "Validate vulnerability with alternative tool/method",
        "priority": 90,
    },
    {
        "condition": "confirmed_vuln",
        "decision": DecisionType.INVESTIGATE_DEEPER,
        "action": "Attempt exploitation with controlled payload",
        "priority": 95,
    },
    {
        "condition": "stagnation_detected",
        "decision": DecisionType.PIVOT,
        "action": "Change strategy or move to next phase",
        "priority": 70,
    },
    {
        "condition": "budget_low",
        "decision": DecisionType.REPORT_FINDING,
        "action": "Compile findings and generate report",
        "priority": 60,
    },
]


class OODAEngine:
    """OODA loop execution engine.

    Manages observation collection, situation
    orientation, decision making, and action
    execution in a feedback loop.
    """

    def __init__(self, max_cycles: int = 50) -> None:
        self._cycles: list[OODACycle] = []
        self._current: OODACycle | None = None
        self._max_cycles = max_cycles
        self._counter = 0
        self._log = logger.bind(component="ooda_loop")

    def start_cycle(self) -> OODACycle:
        """Start a new OODA cycle."""
        self._counter += 1
        cycle = OODACycle(
            cycle_id=f"ooda-{self._counter}",
            cycle_number=self._counter,
            current_phase=OODAPhase.OBSERVE,
        )
        self._current = cycle
        return cycle

    def add_observation(
        self,
        obs_type: ObservationType,
        source: str,
        data: str,
        severity: str = "info",
        tags: list[str] | None = None,
    ) -> Observation:
        """Add an observation to current cycle."""
        if not self._current:
            self.start_cycle()

        obs = Observation(
            obs_id=f"obs-{self._counter}-{len(self._current.observations)}",
            obs_type=obs_type,
            source=source,
            data=data,
            severity=severity,
            tags=tags or [],
        )
        self._current.observations.append(obs)
        return obs

    def orient(
        self,
        threats: list[str] | None = None,
        opportunities: list[str] | None = None,
        unknowns: list[str] | None = None,
        hypothesis: str = "",
        confidence: float = 0.5,
    ) -> Orientation:
        """Set orientation for current cycle."""
        if not self._current:
            self.start_cycle()

        orientation = Orientation(
            threats=threats or [],
            opportunities=opportunities or [],
            unknowns=unknowns or [],
            current_hypothesis=hypothesis,
            confidence=confidence,
        )
        self._current.orientation = orientation
        self._current.current_phase = OODAPhase.ORIENT
        return orientation

    def decide(
        self,
        decision_type: DecisionType,
        action: str,
        tool: str = "",
        args: list[str] | None = None,
        reasoning: str = "",
        priority: int = 0,
        confidence: float = 0.5,
    ) -> Decision:
        """Add a decision to current cycle."""
        if not self._current:
            self.start_cycle()

        decision = Decision(
            decision_type=decision_type,
            action=action,
            tool=tool,
            args=args or [],
            reasoning=reasoning,
            priority=priority,
            confidence=confidence,
        )
        self._current.decisions.append(decision)
        self._current.current_phase = OODAPhase.DECIDE
        return decision

    def record_action_result(
        self,
        decision: Decision,
        success: bool,
        output: str = "",
        new_observations: list[Observation] | None = None,
        findings: list[dict[str, Any]] | None = None,
        duration_s: float = 0.0,
    ) -> ActionResult:
        """Record result of an action."""
        if not self._current:
            self.start_cycle()

        result = ActionResult(
            decision=decision,
            success=success,
            output=output,
            new_observations=new_observations or [],
            findings=findings or [],
            duration_s=duration_s,
        )
        self._current.results.append(result)
        self._current.current_phase = OODAPhase.ACT
        return result

    def complete_cycle(self) -> OODACycle | None:
        """Complete the current cycle."""
        if not self._current:
            return None

        self._current.completed_at = time.time()
        self._cycles.append(self._current)
        completed = self._current
        self._current = None
        return completed

    def should_continue(self) -> bool:
        """Check if more cycles should run."""
        return self._counter < self._max_cycles

    def build_ooda_prompt(
        self,
        phase: str = "initial_recon",
    ) -> str:
        """Build OODA-phase prompt for LLM."""
        lines = []

        orient_prompt = ORIENTATION_PROMPTS.get(phase, ORIENTATION_PROMPTS["initial_recon"])
        lines.append(orient_prompt)

        # Add recent observations
        if self._current and self._current.observations:
            lines.append("\n## Recent Observations:")
            for obs in self._current.observations[-5:]:
                lines.append(f"- [{obs.obs_type.value}] {obs.source}: {obs.data[:100]}")

        # Add cycle history summary
        if self._cycles:
            lines.append(f"\n## Completed Cycles: {len(self._cycles)}")
            total_findings = sum(
                len(r.findings)
                for cycle in self._cycles
                for r in cycle.results
            )
            lines.append(f"Total findings: {total_findings}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_obs = sum(len(c.observations) for c in self._cycles)
        total_decisions = sum(len(c.decisions) for c in self._cycles)
        total_findings = sum(
            len(r.findings)
            for c in self._cycles
            for r in c.results
        )

        phase_counts: dict[str, int] = defaultdict(int)
        for cycle in self._cycles:
            for decision in cycle.decisions:
                phase_counts[decision.decision_type.value] += 1

        return {
            "cycles": len(self._cycles),
            "total_observations": total_obs,
            "total_decisions": total_decisions,
            "total_findings": total_findings,
            "by_decision_type": dict(phase_counts),
        }
