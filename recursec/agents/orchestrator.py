"""Assessment orchestrator — end-to-end autonomous assessment pipeline.

Implements:
1. Full assessment lifecycle management
2. Phase orchestration (recon→scan→exploit→validate→report)
3. Agent coordination and result aggregation
4. Dynamic strategy adaptation
5. Budget-aware execution
6. Convergence-driven phase transitions
7. Knowledge injection at each phase
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssessmentPhase(str, Enum):
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class OrchestratorMode(str, Enum):
    FULL_AUTO = "full_auto"         # Fully autonomous
    SEMI_AUTO = "semi_auto"          # Pause between phases
    MANUAL = "manual"                # Agent suggests, user decides
    RECON_ONLY = "recon_only"
    SCAN_ONLY = "scan_only"


@dataclass
class AssessmentConfig:
    """Configuration for an assessment."""
    target: str = ""
    scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    mode: OrchestratorMode = OrchestratorMode.FULL_AUTO
    max_time_s: float = 3600
    max_tokens: int = 1_000_000
    max_tool_calls: int = 500
    max_depth: int = 3
    budget_decay: float = 0.70
    phases: list[str] = field(default_factory=lambda: [
        "initialization", "reconnaissance", "scanning",
        "exploitation", "validation", "reporting",
    ])

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:25],
            "mode": self.mode.value,
            "max_time": self.max_time_s,
            "phases": len(self.phases),
        }


@dataclass
class PhaseResult:
    """Result of a phase execution."""
    phase: AssessmentPhase = AssessmentPhase.INITIALIZATION
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    agents_spawned: int = 0
    tools_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        if self.completed_at == 0:
            return time.time() - self.started_at
        return self.completed_at - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "findings": len(self.findings),
            "agents": self.agents_spawned,
            "tools": len(self.tools_used),
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class AssessmentState:
    """Full assessment state."""
    assessment_id: str = ""
    config: AssessmentConfig = field(default_factory=AssessmentConfig)
    current_phase: AssessmentPhase = AssessmentPhase.INITIALIZATION
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_tool_calls: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id[:10],
            "phase": self.current_phase.value,
            "findings": len(self.all_findings),
            "tokens": self.total_tokens,
            "elapsed_s": round(self.elapsed_s, 0),
        }


# ── Phase configurations ─────────────────────────────────────

PHASE_CONFIGS: dict[str, dict[str, Any]] = {
    "initialization": {
        "agent_role": "planner",
        "tools": [],
        "kbs": ["advanced_strategy"],
        "model": "deepseek-r1-7b",
        "budget_ratio": 0.05,
        "description": "Analyze target, plan assessment approach",
    },
    "reconnaissance": {
        "agent_role": "recon",
        "tools": ["nmap", "subfinder", "amass", "httpx", "whatweb", "dig", "whois", "dnsrecon"],
        "kbs": ["network_security"],
        "model": "mistral-7b",
        "budget_ratio": 0.20,
        "description": "Map attack surface: subdomains, ports, services, technologies",
    },
    "scanning": {
        "agent_role": "scanner",
        "tools": ["nuclei", "nikto", "testssl", "wpscan", "ffuf"],
        "kbs": ["web_vuln", "compliance", "api_security"],
        "model": "whiterabbitneo-7b",
        "budget_ratio": 0.25,
        "description": "Comprehensive vulnerability scanning",
    },
    "exploitation": {
        "agent_role": "exploiter",
        "tools": ["sqlmap", "dalfox", "hydra", "searchsploit"],
        "kbs": ["web_vuln", "privesc", "advanced_strategy", "timing_attack"],
        "model": "whiterabbitneo-7b",
        "budget_ratio": 0.25,
        "description": "Exploit confirmed vulnerabilities with minimal impact",
    },
    "validation": {
        "agent_role": "validator",
        "tools": ["nuclei", "curl", "httpx"],
        "kbs": ["web_vuln"],
        "model": "hermes-14b",
        "budget_ratio": 0.15,
        "description": "Cross-verify findings, eliminate false positives",
    },
    "reporting": {
        "agent_role": "coordinator",
        "tools": [],
        "kbs": ["compliance"],
        "model": "yi-9b-200k",
        "budget_ratio": 0.10,
        "description": "Generate assessment report",
    },
}


class Orchestrator:
    """Manages end-to-end autonomous security assessments.

    Orchestrates phases, coordinates agents, manages
    budgets, and adapts strategy based on findings
    and convergence signals.
    """

    def __init__(self) -> None:
        self._assessments: dict[str, AssessmentState] = {}
        self._counter = 0
        self._log = logger.bind(component="orchestrator")

    def create_assessment(
        self,
        target: str,
        mode: OrchestratorMode = OrchestratorMode.FULL_AUTO,
        max_time_s: float = 3600,
        max_tokens: int = 1_000_000,
        scope: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> AssessmentState:
        """Create a new assessment."""
        self._counter += 1

        config = AssessmentConfig(
            target=target,
            scope=scope or [target],
            exclude=exclude or [],
            mode=mode,
            max_time_s=max_time_s,
            max_tokens=max_tokens,
        )

        state = AssessmentState(
            assessment_id=f"assess-{self._counter}",
            config=config,
        )

        self._assessments[state.assessment_id] = state
        return state

    def get_phase_config(self, phase: str) -> dict[str, Any]:
        """Get configuration for a phase."""
        return PHASE_CONFIGS.get(phase, PHASE_CONFIGS["scanning"])

    def start_phase(
        self,
        assessment_id: str,
        phase: str,
    ) -> PhaseResult | None:
        """Start a new phase."""
        state = self._assessments.get(assessment_id)
        if not state:
            return None

        try:
            phase_enum = AssessmentPhase(phase)
        except ValueError:
            return None

        state.current_phase = phase_enum
        result = PhaseResult(phase=phase_enum)
        state.phase_results[phase] = result

        return result

    def complete_phase(
        self,
        assessment_id: str,
        phase: str,
        findings: list[dict[str, Any]] | None = None,
        tools_used: list[str] | None = None,
        tokens_used: int = 0,
    ) -> str:
        """Complete a phase and determine next phase."""
        state = self._assessments.get(assessment_id)
        if not state:
            return "failed"

        result = state.phase_results.get(phase)
        if result:
            result.completed_at = time.time()
            result.findings = findings or []
            result.tools_used = tools_used or []
            result.tokens_used = tokens_used

        # Add findings to global list
        state.all_findings.extend(findings or [])
        state.total_tokens += tokens_used

        # Determine next phase
        return self._get_next_phase(state, phase)

    def _get_next_phase(
        self,
        state: AssessmentState,
        current_phase: str,
    ) -> str:
        """Determine the next phase."""
        phase_order = state.config.phases

        try:
            idx = phase_order.index(current_phase)
        except ValueError:
            return "completed"

        # Check budget
        if state.total_tokens >= state.config.max_tokens:
            return "reporting"

        # Check time
        if state.elapsed_s >= state.config.max_time_s:
            return "reporting"

        # Check mode-specific limits
        if state.config.mode == OrchestratorMode.RECON_ONLY and current_phase == "reconnaissance":
            return "reporting"
        if state.config.mode == OrchestratorMode.SCAN_ONLY and current_phase == "scanning":
            return "reporting"

        # Next phase in order
        if idx + 1 < len(phase_order):
            return phase_order[idx + 1]

        return "completed"

    def add_finding(
        self,
        assessment_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add a finding to the assessment."""
        state = self._assessments.get(assessment_id)
        if state:
            state.all_findings.append(finding)

    def get_findings_summary(
        self,
        assessment_id: str,
    ) -> dict[str, Any]:
        """Get a summary of all findings."""
        state = self._assessments.get(assessment_id)
        if not state:
            return {}

        severity_counts: dict[str, int] = defaultdict(int)
        for finding in state.all_findings:
            sev = finding.get("severity", "medium")
            severity_counts[sev] += 1

        return {
            "total": len(state.all_findings),
            "by_severity": dict(severity_counts),
            "phases_completed": len(state.phase_results),
            "tokens_used": state.total_tokens,
            "elapsed_s": round(state.elapsed_s, 0),
        }

    def build_orchestrator_prompt(
        self,
        assessment_id: str,
    ) -> str:
        """Build a prompt describing assessment state."""
        state = self._assessments.get(assessment_id)
        if not state:
            return ""

        lines = [
            f"## Assessment: {state.config.target}\n",
            f"Phase: {state.current_phase.value}",
            f"Findings: {len(state.all_findings)}",
            f"Tokens: {state.total_tokens}/{state.config.max_tokens}",
            f"Time: {state.elapsed_s:.0f}s/{state.config.max_time_s:.0f}s",
        ]

        if state.all_findings:
            sev_counts = defaultdict(int)
            for f in state.all_findings:
                sev_counts[f.get("severity", "medium")] += 1
            lines.append(f"\nFindings: {dict(sev_counts)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_findings = sum(
            len(s.all_findings) for s in self._assessments.values()
        )
        return {
            "assessments": len(self._assessments),
            "total_findings": total_findings,
        }
