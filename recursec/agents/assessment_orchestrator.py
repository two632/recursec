"""Assessment orchestrator — top-level coordinator for security assessments.

Implements:
1. Assessment lifecycle management (init → recon → scan → exploit → report)
2. Phase-based state machine with transitions
3. Agent coordination and task delegation
4. Progress tracking and status reporting
5. Finding aggregation across all agents
6. Dynamic phase adjustment based on progress
7. Assessment configuration and scope management
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
    SCOPE_DEFINITION = "scope_definition"
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    VULNERABILITY_SCAN = "vulnerability_scan"
    MANUAL_TESTING = "manual_testing"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScopeDefinition:
    """Assessment scope."""
    targets: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)  # empty = all
    excluded_ports: list[int] = field(default_factory=list)
    allow_exploitation: bool = True
    max_severity: str = "critical"
    time_limit_s: float = 14400.0   # 4 hours default
    token_limit: int = 1000000       # 1M tokens default

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": len(self.targets),
            "excluded": len(self.excluded_targets),
            "exploitation": self.allow_exploitation,
            "time_limit_s": self.time_limit_s,
        }


@dataclass
class AssessmentFinding:
    """A finding from the assessment."""
    finding_id: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    title: str = ""
    description: str = ""
    target: str = ""
    evidence: str = ""
    tool: str = ""
    agent_id: str = ""
    phase: AssessmentPhase = AssessmentPhase.VULNERABILITY_SCAN
    validated: bool = False
    false_positive: bool = False
    cvss_score: float = 0.0
    cwe_id: str = ""
    remediation: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "severity": self.severity.value,
            "title": self.title[:30],
            "target": self.target[:20],
            "validated": self.validated,
            "cvss": round(self.cvss_score, 1),
        }


@dataclass
class PhaseProgress:
    """Progress tracking for an assessment phase."""
    phase: AssessmentPhase = AssessmentPhase.INIT
    status: str = "pending"   # pending, running, completed, skipped
    started_at: float = 0.0
    completed_at: float = 0.0
    tasks_total: int = 0
    tasks_completed: int = 0
    agents_spawned: int = 0
    findings_count: int = 0
    tokens_used: int = 0

    @property
    def progress_pct(self) -> float:
        if self.tasks_total == 0:
            return 0.0
        return (self.tasks_completed / self.tasks_total) * 100

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "status": self.status,
            "progress": f"{self.progress_pct:.0f}%",
            "findings": self.findings_count,
            "agents": self.agents_spawned,
        }


# ── Phase transitions ────────────────────────────────────────

PHASE_ORDER: list[AssessmentPhase] = [
    AssessmentPhase.INIT,
    AssessmentPhase.SCOPE_DEFINITION,
    AssessmentPhase.PASSIVE_RECON,
    AssessmentPhase.ACTIVE_RECON,
    AssessmentPhase.VULNERABILITY_SCAN,
    AssessmentPhase.MANUAL_TESTING,
    AssessmentPhase.EXPLOITATION,
    AssessmentPhase.POST_EXPLOITATION,
    AssessmentPhase.REPORTING,
    AssessmentPhase.COMPLETED,
]


class AssessmentOrchestrator:
    """Orchestrates a complete security assessment.

    Manages the assessment lifecycle through
    phases, coordinates agents, tracks findings,
    and adapts strategy based on progress.
    """

    def __init__(self) -> None:
        self._assessment_id: str = ""
        self._status: AssessmentStatus = AssessmentStatus.PENDING
        self._current_phase: AssessmentPhase = AssessmentPhase.INIT
        self._scope: ScopeDefinition = ScopeDefinition()
        self._findings: list[AssessmentFinding] = []
        self._phases: dict[str, PhaseProgress] = {}
        self._started_at: float = 0.0
        self._completed_at: float = 0.0
        self._total_tokens: int = 0
        self._counter = 0
        self._log = logger.bind(component="assessment_orchestrator")

        # Initialize phase progress
        for phase in PHASE_ORDER:
            self._phases[phase.value] = PhaseProgress(phase=phase)

    def start_assessment(
        self,
        assessment_id: str,
        targets: list[str],
        scope: ScopeDefinition | None = None,
    ) -> None:
        """Start a new assessment."""
        self._assessment_id = assessment_id
        self._status = AssessmentStatus.RUNNING
        self._started_at = time.time()

        if scope:
            self._scope = scope
        self._scope.targets = targets

        self._advance_to_phase(AssessmentPhase.SCOPE_DEFINITION)

    def advance_phase(self) -> AssessmentPhase | None:
        """Advance to the next phase."""
        idx = PHASE_ORDER.index(self._current_phase)
        if idx >= len(PHASE_ORDER) - 1:
            self._complete_assessment()
            return None

        # Complete current phase
        current = self._phases[self._current_phase.value]
        current.status = "completed"
        current.completed_at = time.time()

        # Advance
        next_phase = PHASE_ORDER[idx + 1]
        self._advance_to_phase(next_phase)
        return next_phase

    def skip_phase(self, phase: AssessmentPhase) -> None:
        """Skip a phase."""
        progress = self._phases.get(phase.value)
        if progress:
            progress.status = "skipped"

    def add_finding(
        self,
        severity: FindingSeverity,
        title: str,
        description: str = "",
        target: str = "",
        evidence: str = "",
        tool: str = "",
        agent_id: str = "",
        cvss_score: float = 0.0,
        cwe_id: str = "",
        remediation: str = "",
    ) -> AssessmentFinding:
        """Add a finding to the assessment."""
        self._counter += 1
        finding = AssessmentFinding(
            finding_id=f"finding-{self._counter}",
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence=evidence,
            tool=tool,
            agent_id=agent_id,
            phase=self._current_phase,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            remediation=remediation,
        )
        self._findings.append(finding)

        # Update phase stats
        phase = self._phases.get(self._current_phase.value)
        if phase:
            phase.findings_count += 1

        return finding

    def validate_finding(self, finding_id: str, validated: bool = True) -> bool:
        """Mark a finding as validated."""
        for f in self._findings:
            if f.finding_id == finding_id:
                f.validated = validated
                return True
        return False

    def mark_false_positive(self, finding_id: str) -> bool:
        """Mark a finding as false positive."""
        for f in self._findings:
            if f.finding_id == finding_id:
                f.false_positive = True
                return True
        return False

    def get_findings_by_severity(self) -> dict[str, list[AssessmentFinding]]:
        """Get findings grouped by severity."""
        result: dict[str, list[AssessmentFinding]] = {}
        for f in self._findings:
            if not f.false_positive:
                result.setdefault(f.severity.value, []).append(f)
        return result

    def get_validated_findings(self) -> list[AssessmentFinding]:
        """Get validated non-false-positive findings."""
        return [f for f in self._findings if f.validated and not f.false_positive]

    def should_exploit(self) -> bool:
        """Determine if exploitation phase should proceed."""
        if not self._scope.allow_exploitation:
            return False
        # Need at least one high/critical finding to exploit
        high_findings = [
            f for f in self._findings
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
            and not f.false_positive
        ]
        return len(high_findings) > 0

    def build_orchestrator_prompt(self) -> str:
        """Build assessment context for LLM."""
        lines = ["## Assessment Status\n"]

        elapsed = time.time() - self._started_at if self._started_at else 0
        lines.append(
            f"Phase: {self._current_phase.value} | "
            f"Status: {self._status.value} | "
            f"Elapsed: {elapsed:.0f}s"
        )

        # Phase progress
        lines.append("\nPhases:")
        for phase in PHASE_ORDER:
            progress = self._phases[phase.value]
            icon = {
                "pending": "[ ]", "running": "[>]",
                "completed": "[x]", "skipped": "[-]",
            }.get(progress.status, "[ ]")
            extra = ""
            if progress.findings_count:
                extra = f" ({progress.findings_count} findings)"
            lines.append(f"  {icon} {phase.value}{extra}")

        # Finding summary
        by_sev = self.get_findings_by_severity()
        if by_sev:
            lines.append("\nFindings:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                findings = by_sev.get(sev, [])
                if findings:
                    lines.append(f"  {sev.upper()}: {len(findings)}")

        # Scope
        lines.append(f"\nTargets: {len(self._scope.targets)}")
        if self._scope.targets:
            for t in self._scope.targets[:3]:
                lines.append(f"  - {t}")

        return "\n".join(lines)

    def _advance_to_phase(self, phase: AssessmentPhase) -> None:
        """Start a new phase."""
        self._current_phase = phase
        progress = self._phases[phase.value]
        progress.status = "running"
        progress.started_at = time.time()

    def _complete_assessment(self) -> None:
        """Complete the assessment."""
        self._status = AssessmentStatus.COMPLETED
        self._completed_at = time.time()
        self._current_phase = AssessmentPhase.COMPLETED

    def get_stats(self) -> dict[str, Any]:
        by_sev = self.get_findings_by_severity()
        return {
            "assessment_id": self._assessment_id,
            "status": self._status.value,
            "phase": self._current_phase.value,
            "total_findings": len(self._findings),
            "validated": len(self.get_validated_findings()),
            "false_positives": sum(1 for f in self._findings if f.false_positive),
            "by_severity": {k: len(v) for k, v in by_sev.items()},
            "elapsed_s": time.time() - self._started_at if self._started_at else 0,
        }
