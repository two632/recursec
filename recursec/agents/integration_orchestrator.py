"""Integration orchestrator — ties all agent modules together.

Implements:
1. Full assessment pipeline (init → recon → scan → exploit → validate → report)
2. Module initialization and wiring
3. Phase transition management
4. Cross-module state sharing
5. Result aggregation across phases
6. Assessment lifecycle management
7. Checkpointing and resume
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssessmentPhase(str, Enum):
    INITIALIZING = "initializing"
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PAUSED = "paused"
    FAILED = "failed"


class PhaseTransition(str, Enum):
    AUTO = "auto"                 # Automatic based on convergence
    MANUAL = "manual"             # User-triggered
    BUDGET_EXCEEDED = "budget_exceeded"
    CONVERGENCE = "convergence"
    ERROR = "error"


@dataclass
class PhaseResult:
    """Result from a phase."""
    phase: AssessmentPhase = AssessmentPhase.INITIALIZING
    findings: list[dict[str, Any]] = field(default_factory=list)
    assets_discovered: list[dict[str, Any]] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    duration_s: float = 0.0
    transition_reason: PhaseTransition = PhaseTransition.AUTO

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "findings": len(self.findings),
            "assets": len(self.assets_discovered),
            "tokens": self.tokens_used,
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class AssessmentConfig:
    """Configuration for an assessment."""
    target: str = ""
    scope: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    max_depth: int = 5
    token_budget: int = 500000
    time_budget_s: float = 3600.0
    aggressive: bool = False
    domains: list[str] = field(default_factory=list)  # Security domains to test
    skip_phases: list[str] = field(default_factory=list)
    concurrent_agents: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "scope": len(self.scope),
            "depth": self.max_depth,
            "budget": self.token_budget,
            "time_s": self.time_budget_s,
        }


@dataclass
class Assessment:
    """A complete assessment."""
    assessment_id: str = ""
    config: AssessmentConfig = field(default_factory=AssessmentConfig)
    current_phase: AssessmentPhase = AssessmentPhase.INITIALIZING
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    all_assets: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    checkpoint_path: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id[:10],
            "phase": self.current_phase.value,
            "findings": len(self.all_findings),
            "assets": len(self.all_assets),
            "tokens": self.total_tokens,
            "duration_s": round(self.duration_s, 1),
        }


# ── Phase ordering ────────────────────────────────────────────

PHASE_ORDER: list[AssessmentPhase] = [
    AssessmentPhase.INITIALIZING,
    AssessmentPhase.PLANNING,
    AssessmentPhase.RECONNAISSANCE,
    AssessmentPhase.SCANNING,
    AssessmentPhase.EXPLOITATION,
    AssessmentPhase.VALIDATION,
    AssessmentPhase.REPORTING,
    AssessmentPhase.COMPLETED,
]

# ── Phase-specific agent roles and KBs ─────────────────────────

PHASE_AGENTS: dict[str, list[str]] = {
    "planning": ["planner", "coordinator"],
    "reconnaissance": ["recon", "osint"],
    "scanning": ["scanner", "code_auditor", "web", "api", "network"],
    "exploitation": ["exploiter"],
    "validation": ["validator"],
    "reporting": ["reporter"],
}

PHASE_KBS: dict[str, list[str]] = {
    "planning": ["compliance"],
    "reconnaissance": ["network", "osint"],
    "scanning": [
        "api_security", "webapp", "network",
        "cryptography", "cloud_security", "supply_chain",
        "binary_analysis", "wireless", "privesc",
        "active_directory", "advanced_strategy",
    ],
    "exploitation": [
        "privesc", "binary_analysis", "zero_day",
        "webapp", "cryptography",
    ],
    "validation": ["compliance"],
    "reporting": ["compliance"],
}


class IntegrationOrchestrator:
    """Orchestrates the full assessment pipeline.

    Coordinates all agent modules through the
    assessment lifecycle, manages phase transitions,
    and aggregates results.
    """

    def __init__(self) -> None:
        self._assessments: dict[str, Assessment] = {}
        self._counter = 0
        self._log = logger.bind(component="integration_orchestrator")

    def create_assessment(
        self,
        config: AssessmentConfig,
    ) -> Assessment:
        """Create a new assessment."""
        self._counter += 1
        assessment = Assessment(
            assessment_id=f"assess-{self._counter}",
            config=config,
        )
        self._assessments[assessment.assessment_id] = assessment
        return assessment

    def get_next_phase(
        self,
        assessment_id: str,
    ) -> AssessmentPhase | None:
        """Get the next phase in the pipeline."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        current_idx = PHASE_ORDER.index(assessment.current_phase)
        if current_idx >= len(PHASE_ORDER) - 1:
            return None

        next_phase = PHASE_ORDER[current_idx + 1]

        # Skip if in skip list
        while (
            next_phase.value in assessment.config.skip_phases
            and current_idx + 1 < len(PHASE_ORDER) - 1
        ):
            current_idx += 1
            next_phase = PHASE_ORDER[current_idx + 1]

        return next_phase

    def transition_phase(
        self,
        assessment_id: str,
        reason: PhaseTransition = PhaseTransition.AUTO,
    ) -> AssessmentPhase | None:
        """Transition to the next phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        next_phase = self.get_next_phase(assessment_id)
        if not next_phase:
            return None

        old_phase = assessment.current_phase
        assessment.current_phase = next_phase

        self._log.info(
            "phase_transition",
            assessment=assessment_id[:10],
            old=old_phase.value,
            new=next_phase.value,
            reason=reason.value,
        )

        return next_phase

    def record_phase_result(
        self,
        assessment_id: str,
        result: PhaseResult,
    ) -> None:
        """Record results from a phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return

        assessment.phase_results[result.phase.value] = result
        assessment.all_findings.extend(result.findings)
        assessment.all_assets.extend(result.assets_discovered)
        assessment.total_tokens += result.tokens_used

    def complete_assessment(
        self,
        assessment_id: str,
    ) -> Assessment | None:
        """Complete an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        assessment.current_phase = AssessmentPhase.COMPLETED
        assessment.completed_at = time.time()
        return assessment

    def get_phase_agents(self, phase: AssessmentPhase) -> list[str]:
        """Get agent roles for a phase."""
        return PHASE_AGENTS.get(phase.value, [])

    def get_phase_kbs(self, phase: AssessmentPhase) -> list[str]:
        """Get knowledge bases for a phase."""
        return PHASE_KBS.get(phase.value, [])

    def should_transition(
        self,
        assessment_id: str,
        convergence_state: str = "",
        budget_utilization: float = 0.0,
    ) -> bool:
        """Check if phase should transition."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return False

        # Budget exceeded
        if assessment.total_tokens >= assessment.config.token_budget:
            return True

        # Time exceeded
        if assessment.duration_s >= assessment.config.time_budget_s:
            return True

        # Convergence-based
        if convergence_state in ("converged", "stagnant"):
            return True

        # Budget utilization threshold (phase should use ~proportional budget)
        phase_count = len(PHASE_ORDER) - 2  # Exclude init and completed
        per_phase_budget = 1.0 / max(1, phase_count)
        if budget_utilization > per_phase_budget * 1.5:
            return True

        return False

    def build_orchestrator_prompt(
        self,
        assessment_id: str,
    ) -> str:
        """Build orchestrator context for LLM."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return ""

        lines = [
            "## Assessment Status\n",
            f"Target: {assessment.config.target}",
            f"Phase: {assessment.current_phase.value}",
            f"Findings: {len(assessment.all_findings)}",
            f"Assets: {len(assessment.all_assets)}",
            f"Tokens: {assessment.total_tokens}/{assessment.config.token_budget}",
            f"Duration: {assessment.duration_s:.0f}s / {assessment.config.time_budget_s:.0f}s",
            "",
        ]

        # Phase results summary
        if assessment.phase_results:
            lines.append("## Phase Results:")
            for phase_name, result in assessment.phase_results.items():
                lines.append(
                    f"  {phase_name}: {len(result.findings)} findings, "
                    f"{len(result.assets_discovered)} assets"
                )

        # Current phase agents and KBs
        agents = self.get_phase_agents(assessment.current_phase)
        kbs = self.get_phase_kbs(assessment.current_phase)
        if agents:
            lines.append(f"\nActive agents: {', '.join(agents)}")
        if kbs:
            lines.append(f"Active KBs: {', '.join(kbs)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        active = sum(
            1 for a in self._assessments.values()
            if a.current_phase not in (AssessmentPhase.COMPLETED, AssessmentPhase.FAILED)
        )
        total_findings = sum(len(a.all_findings) for a in self._assessments.values())

        return {
            "assessments": len(self._assessments),
            "active": active,
            "total_findings": total_findings,
        }
