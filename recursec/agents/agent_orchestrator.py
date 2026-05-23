"""Agent orchestrator — top-level assessment coordinator.

Implements:
1. Full assessment pipeline management
2. Phase coordination (recon→scan→exploit→validate→report)
3. Agent spawning and task distribution
4. Result aggregation and deduplication
5. Budget management across phases
6. Dynamic strategy adaptation
7. Knowledge base integration
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
    COMPLETE = "complete"


class PhaseTransition(str, Enum):
    AUTOMATIC = "automatic"      # Move when phase criteria met
    MANUAL = "manual"            # Wait for explicit transition
    CONDITIONAL = "conditional"  # Move based on findings


@dataclass
class PhaseConfig:
    """Configuration for an assessment phase."""
    phase: AssessmentPhase = AssessmentPhase.RECONNAISSANCE
    agent_roles: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    max_duration_s: float = 600.0
    token_budget: int = 50000
    transition: PhaseTransition = PhaseTransition.AUTOMATIC
    min_findings_to_proceed: int = 0
    knowledge_bases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "roles": len(self.agent_roles),
            "tools": len(self.tools),
            "duration": self.max_duration_s,
            "budget": self.token_budget,
        }


@dataclass
class PhaseResult:
    """Result of a completed phase."""
    phase: AssessmentPhase = AssessmentPhase.RECONNAISSANCE
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    tokens_used: int = 0
    tools_used: list[str] = field(default_factory=list)
    agents_spawned: int = 0
    success: bool = True
    notes: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "findings": len(self.findings),
            "tokens": self.tokens_used,
            "duration": round(self.duration_s, 1),
            "agents": self.agents_spawned,
            "success": self.success,
        }


@dataclass
class Assessment:
    """A complete assessment orchestration."""
    assessment_id: str = ""
    target: str = ""
    target_type: str = ""        # web, network, api, cloud, code
    current_phase: AssessmentPhase = AssessmentPhase.INITIALIZATION
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_tool_calls: int = 0
    total_agents: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = defaultdict(int)
        for f in self.all_findings:
            sev_counts[f.get("severity", "unknown")] += 1
        return {
            "id": self.assessment_id[:10],
            "target": self.target[:20],
            "phase": self.current_phase.value,
            "findings": len(self.all_findings),
            "by_severity": dict(sev_counts),
            "tokens": self.total_tokens,
            "duration": round(self.duration_s, 1),
        }


# ── Default phase configurations ─────────────────────────────

DEFAULT_PHASES: list[dict[str, Any]] = [
    {
        "phase": "reconnaissance",
        "roles": ["recon", "osint"],
        "tools": ["nmap", "subfinder", "amass", "httpx", "wafw00f", "dnsrecon", "theHarvester"],
        "models": ["mistral-7b", "llama-3.1-8b"],
        "duration": 300,
        "tokens": 30000,
        "kbs": ["network_security", "api_security"],
    },
    {
        "phase": "scanning",
        "roles": ["scanner", "fuzzer"],
        "tools": ["nuclei", "nikto", "sqlmap", "dalfox", "wpscan", "ffuf", "gobuster"],
        "models": ["whiterabbitneo-7b", "qwen-coder-7b"],
        "duration": 600,
        "tokens": 50000,
        "kbs": ["web_vuln", "api_security"],
    },
    {
        "phase": "exploitation",
        "roles": ["exploiter"],
        "tools": ["sqlmap", "hydra", "metasploit", "searchsploit"],
        "models": ["whiterabbitneo-7b", "dolphin-8b"],
        "duration": 600,
        "tokens": 50000,
        "kbs": ["web_vuln", "privesc", "network_security"],
    },
    {
        "phase": "validation",
        "roles": ["validator"],
        "tools": ["curl", "httpx", "nmap"],
        "models": ["qwen-coder-14b", "hermes-14b", "deepseek-r1-7b"],
        "duration": 300,
        "tokens": 30000,
        "kbs": [],
    },
    {
        "phase": "reporting",
        "roles": ["reporter"],
        "tools": [],
        "models": ["hermes-14b", "llama-3.1-8b"],
        "duration": 120,
        "tokens": 20000,
        "kbs": [],
    },
]


class AgentOrchestrator:
    """Top-level assessment orchestrator.

    Coordinates the full assessment pipeline:
    Recon → Scan → Exploit → Validate → Report
    with dynamic strategy adaptation.
    """

    def __init__(self) -> None:
        self._assessments: dict[str, Assessment] = {}
        self._phase_configs: dict[str, PhaseConfig] = {}
        self._counter = 0
        self._log = logger.bind(component="orchestrator")
        self._load_default_phases()

    def _load_default_phases(self) -> None:
        """Load default phase configurations."""
        for phase_data in DEFAULT_PHASES:
            config = PhaseConfig(
                phase=AssessmentPhase(phase_data["phase"]),
                agent_roles=phase_data.get("roles", []),
                tools=phase_data.get("tools", []),
                models=phase_data.get("models", []),
                max_duration_s=phase_data.get("duration", 600),
                token_budget=phase_data.get("tokens", 50000),
                knowledge_bases=phase_data.get("kbs", []),
            )
            self._phase_configs[phase_data["phase"]] = config

    def create_assessment(
        self,
        target: str,
        target_type: str = "web",
        config: dict[str, Any] | None = None,
    ) -> Assessment:
        """Create a new assessment."""
        self._counter += 1
        assessment = Assessment(
            assessment_id=f"assess-{self._counter}",
            target=target,
            target_type=target_type,
            current_phase=AssessmentPhase.INITIALIZATION,
            config=config or {},
        )
        self._assessments[assessment.assessment_id] = assessment
        return assessment

    def start_phase(
        self,
        assessment_id: str,
        phase: AssessmentPhase,
    ) -> PhaseResult | None:
        """Start a new phase for an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        assessment.current_phase = phase
        result = PhaseResult(phase=phase)
        assessment.phase_results[phase.value] = result
        return result

    def complete_phase(
        self,
        assessment_id: str,
        phase: AssessmentPhase,
        findings: list[dict[str, Any]] | None = None,
        tokens_used: int = 0,
        tools_used: list[str] | None = None,
        agents_spawned: int = 0,
    ) -> PhaseResult | None:
        """Complete a phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        result = assessment.phase_results.get(phase.value)
        if not result:
            return None

        result.completed_at = time.time()
        result.tokens_used = tokens_used
        result.tools_used = tools_used or []
        result.agents_spawned = agents_spawned
        result.success = True

        if findings:
            result.findings = findings
            # Deduplicate and add to assessment
            existing_titles = {f.get("title", "") for f in assessment.all_findings}
            for f in findings:
                if f.get("title", "") not in existing_titles:
                    assessment.all_findings.append(f)
                    existing_titles.add(f.get("title", ""))

        assessment.total_tokens += tokens_used
        assessment.total_tool_calls += len(tools_used or [])
        assessment.total_agents += agents_spawned

        return result

    def get_next_phase(self, assessment_id: str) -> AssessmentPhase | None:
        """Determine the next phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        phase_order = [
            AssessmentPhase.INITIALIZATION,
            AssessmentPhase.RECONNAISSANCE,
            AssessmentPhase.SCANNING,
            AssessmentPhase.EXPLOITATION,
            AssessmentPhase.VALIDATION,
            AssessmentPhase.REPORTING,
            AssessmentPhase.COMPLETE,
        ]

        current_idx = -1
        for i, phase in enumerate(phase_order):
            if phase == assessment.current_phase:
                current_idx = i
                break

        if current_idx < 0 or current_idx >= len(phase_order) - 1:
            return None

        return phase_order[current_idx + 1]

    def complete_assessment(self, assessment_id: str) -> Assessment | None:
        """Complete an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        assessment.current_phase = AssessmentPhase.COMPLETE
        assessment.completed_at = time.time()
        return assessment

    def get_phase_config(self, phase: str) -> PhaseConfig | None:
        """Get configuration for a phase."""
        return self._phase_configs.get(phase)

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        """Get an assessment by ID."""
        return self._assessments.get(assessment_id)

    def build_phase_prompt(
        self,
        assessment_id: str,
        phase: AssessmentPhase,
    ) -> str:
        """Build a prompt for the current phase."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return ""

        config = self._phase_configs.get(phase.value)
        if not config:
            return ""

        lines = [f"## Assessment Phase: {phase.value.upper()}\n"]
        lines.append(f"Target: {assessment.target}")
        lines.append(f"Target Type: {assessment.target_type}")

        if config.tools:
            lines.append(f"\nAvailable tools: {', '.join(config.tools)}")

        # Include previous phase findings
        for prev_phase, result in assessment.phase_results.items():
            if result.findings:
                lines.append(f"\nFindings from {prev_phase}:")
                for f in result.findings[:5]:
                    lines.append(f"  [{f.get('severity', '?')}] {f.get('title', '')}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_findings = sum(len(a.all_findings) for a in self._assessments.values())
        phase_counts: dict[str, int] = defaultdict(int)
        for a in self._assessments.values():
            phase_counts[a.current_phase.value] += 1

        return {
            "assessments": len(self._assessments),
            "total_findings": total_findings,
            "by_phase": dict(phase_counts),
            "phase_configs": len(self._phase_configs),
        }
