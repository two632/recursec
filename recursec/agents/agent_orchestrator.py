"""Agent orchestrator — top-level coordinator wiring all components.

Implements:
1. Assessment lifecycle (init → plan → execute → report)
2. Component wiring (router, spawner, context, budget, etc.)
3. Phase-based execution (recon → scan → exploit → validate)
4. Knowledge injection into agent prompts
5. Finding aggregation across agents
6. Assessment state machine
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssessmentPhase(str, Enum):
    INIT = "init"
    PLANNING = "planning"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


class AssessmentType(str, Enum):
    FULL = "full"                # Full assessment
    RECON_ONLY = "recon_only"
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    CODE_AUDIT = "code_audit"
    RED_TEAM = "red_team"
    CUSTOM = "custom"


@dataclass
class AssessmentTarget:
    """Target specification."""
    primary: str = ""          # IP, domain, URL
    scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    target_type: str = ""      # web, network, cloud, code
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary": self.primary[:20],
            "scope_size": len(self.scope),
            "type": self.target_type[:10],
        }


@dataclass
class AssessmentConfig:
    """Assessment configuration."""
    assessment_type: AssessmentType = AssessmentType.FULL
    max_depth: int = 5
    max_agents: int = 30
    token_budget: int = 200000
    time_budget_s: float = 7200.0
    tool_budget: int = 500
    knowledge_domains: list[str] = field(default_factory=list)
    skip_phases: list[str] = field(default_factory=list)
    aggressive: bool = False
    validate_findings: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.assessment_type.value[:8],
            "depth": self.max_depth,
            "agents": self.max_agents,
            "tokens": self.token_budget,
        }


@dataclass
class PhaseResult:
    """Result from a completed phase."""
    phase: AssessmentPhase = AssessmentPhase.INIT
    duration_s: float = 0.0
    agents_used: int = 0
    tokens_used: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    next_phase: AssessmentPhase = AssessmentPhase.INIT

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value[:8],
            "dur_s": round(self.duration_s, 1),
            "agents": self.agents_used,
            "findings": len(self.findings),
        }


@dataclass
class Assessment:
    """Full assessment state."""
    assessment_id: str = ""
    target: AssessmentTarget = field(default_factory=AssessmentTarget)
    config: AssessmentConfig = field(default_factory=AssessmentConfig)
    phase: AssessmentPhase = AssessmentPhase.INIT
    phase_results: list[PhaseResult] = field(default_factory=list)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_agents: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    error: str = ""

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id[:10],
            "target": self.target.primary[:15],
            "phase": self.phase.value[:8],
            "findings": len(self.all_findings),
            "agents": self.total_agents,
            "dur_s": round(self.duration_s, 1),
        }


# ── Phase execution order ────────────────────────────────────

PHASE_ORDER: list[AssessmentPhase] = [
    AssessmentPhase.INIT,
    AssessmentPhase.PLANNING,
    AssessmentPhase.RECON,
    AssessmentPhase.SCANNING,
    AssessmentPhase.EXPLOITATION,
    AssessmentPhase.POST_EXPLOIT,
    AssessmentPhase.VALIDATION,
    AssessmentPhase.REPORTING,
    AssessmentPhase.COMPLETE,
]

# ── Phase → knowledge domain mapping ────────────────────────

PHASE_KNOWLEDGE: dict[AssessmentPhase, list[str]] = {
    AssessmentPhase.RECON: ["osint", "threat_intel", "active_directory"],
    AssessmentPhase.SCANNING: ["web_security", "network", "cloud_security"],
    AssessmentPhase.EXPLOITATION: ["privilege_escalation", "zero_day", "advanced_strategy"],
    AssessmentPhase.POST_EXPLOIT: ["red_team", "forensics"],
    AssessmentPhase.VALIDATION: ["compliance"],
    AssessmentPhase.REPORTING: [],
}

# ── Phase → agent roles ─────────────────────────────────────

PHASE_ROLES: dict[AssessmentPhase, list[str]] = {
    AssessmentPhase.RECON: ["recon", "osint"],
    AssessmentPhase.SCANNING: ["vuln_scan", "web_audit", "network"],
    AssessmentPhase.EXPLOITATION: ["exploit", "code_audit"],
    AssessmentPhase.POST_EXPLOIT: ["exploit", "forensics"],
    AssessmentPhase.VALIDATION: ["validator"],
    AssessmentPhase.REPORTING: ["reporter"],
}


class AgentOrchestrator:
    """Top-level coordinator that manages assessments.

    Wires together all agent components:
    - Model router (which LLM to use)
    - Agent spawner (create specialized agents)
    - Context manager (multi-turn state)
    - Budget tracker (resource limits)
    - Knowledge aggregator (KB injection)
    - Attack chain builder (link findings)
    - Finding deduplicator (merge findings)
    - Reasoning engine (chain-of-thought)
    - Self-reflection (learn from tasks)
    """

    def __init__(self) -> None:
        self._assessments: dict[str, Assessment] = {}
        self._counter = 0
        self._log = logger.bind(component="orchestrator")

    def create_assessment(
        self,
        target: str,
        scope: list[str] | None = None,
        assessment_type: AssessmentType = AssessmentType.FULL,
        config: AssessmentConfig | None = None,
    ) -> Assessment:
        """Create a new assessment."""
        self._counter += 1

        tgt = AssessmentTarget(
            primary=target,
            scope=scope or [target],
            target_type=self._infer_target_type(target),
        )

        cfg = config or AssessmentConfig(assessment_type=assessment_type)

        assessment = Assessment(
            assessment_id=f"assess-{self._counter}",
            target=tgt,
            config=cfg,
        )

        self._assessments[assessment.assessment_id] = assessment
        return assessment

    def _infer_target_type(self, target: str) -> str:
        """Infer target type from target string."""
        if target.startswith(("http://", "https://")):
            return "web"
        if "/" in target and "." in target:
            return "network"
        if target.endswith((".com", ".org", ".net", ".io")):
            return "web"
        if target.count(".") == 3 and all(
            p.isdigit() for p in target.split(".")
        ):
            return "network"
        return "general"

    def advance_phase(self, assessment_id: str) -> AssessmentPhase | None:
        """Advance to the next phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        current_idx = PHASE_ORDER.index(assessment.phase)
        if current_idx >= len(PHASE_ORDER) - 1:
            return assessment.phase

        # Find next non-skipped phase
        for next_phase in PHASE_ORDER[current_idx + 1:]:
            if next_phase.value not in assessment.config.skip_phases:
                assessment.phase = next_phase
                return next_phase

        assessment.phase = AssessmentPhase.COMPLETE
        return AssessmentPhase.COMPLETE

    def record_phase_result(
        self,
        assessment_id: str,
        result: PhaseResult,
    ) -> None:
        """Record results from a completed phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return

        assessment.phase_results.append(result)
        assessment.all_findings.extend(result.findings)
        assessment.total_tokens += result.tokens_used
        assessment.total_agents += result.agents_used

    def get_phase_knowledge(self, phase: AssessmentPhase) -> list[str]:
        """Get relevant knowledge domains for a phase."""
        return PHASE_KNOWLEDGE.get(phase, [])

    def get_phase_roles(self, phase: AssessmentPhase) -> list[str]:
        """Get agent roles for a phase."""
        return PHASE_ROLES.get(phase, [])

    def build_orchestrator_prompt(self, assessment_id: str = "") -> str:
        """Build orchestrator context for LLM."""
        lines = ["## Assessment Orchestrator\n"]

        if assessment_id and assessment_id in self._assessments:
            a = self._assessments[assessment_id]
            lines.append(f"Target: {a.target.primary[:25]}")
            lines.append(f"Phase: {a.phase.value} | Type: {a.config.assessment_type.value}")
            lines.append(f"Findings: {len(a.all_findings)} | Agents: {a.total_agents}")
            lines.append(f"Duration: {a.duration_s:.0f}s | Tokens: {a.total_tokens}")

            # Phase results
            if a.phase_results:
                lines.append("\nPhase results:")
                for pr in a.phase_results:
                    lines.append(
                        f"  {pr.phase.value[:8]}: "
                        f"{len(pr.findings)} findings, "
                        f"{pr.agents_used} agents, "
                        f"{pr.duration_s:.0f}s"
                    )

            # Next steps
            knowledge = self.get_phase_knowledge(a.phase)
            roles = self.get_phase_roles(a.phase)
            if knowledge:
                lines.append(f"\nKnowledge for {a.phase.value}: {', '.join(knowledge[:3])}")
            if roles:
                lines.append(f"Roles needed: {', '.join(roles[:3])}")

        else:
            lines.append(f"Active assessments: {len(self._assessments)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = {}
        for a in self._assessments.values():
            p = a.phase.value
            phase_counts[p] = phase_counts.get(p, 0) + 1

        return {
            "total_assessments": len(self._assessments),
            "by_phase": phase_counts,
            "total_findings": sum(len(a.all_findings) for a in self._assessments.values()),
            "total_agents": sum(a.total_agents for a in self._assessments.values()),
        }
