"""Adaptive planner — dynamically adjusts assessment plan based on results.

Implements:
1. Initial plan generation based on target
2. Plan adaptation based on findings
3. Phase reordering based on results
4. Tool substitution when tools fail
5. Depth adjustment (go deeper on interesting targets)
6. Breadth adjustment (expand scope on promising areas)
7. Time reallocation across phases
8. Plan versioning and rollback
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    ADAPTED = "adapted"


class AdaptationReason(str, Enum):
    NEW_FINDING = "new_finding"
    TOOL_FAILURE = "tool_failure"
    TIME_PRESSURE = "time_pressure"
    HIGH_VALUE_TARGET = "high_value_target"
    COVERAGE_GAP = "coverage_gap"
    CONVERGENCE = "convergence"


@dataclass
class PlanPhase:
    """A phase in the assessment plan."""
    phase_id: str = ""
    name: str = ""
    description: str = ""
    tools: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    allocated_time_s: float = 600.0
    used_time_s: float = 0.0
    priority: int = 5
    status: PhaseStatus = PhaseStatus.PENDING
    findings_count: int = 0
    depth: int = 1                 # 1=shallow, 2=normal, 3=deep

    @property
    def remaining_time_s(self) -> float:
        return max(0.0, self.allocated_time_s - self.used_time_s)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.phase_id, "name": self.name[:40],
            "tools": self.tools[:5], "priority": self.priority,
            "status": self.status.value,
            "findings": self.findings_count,
            "remaining_s": round(self.remaining_time_s, 0),
        }


@dataclass
class PlanAdaptation:
    """A recorded adaptation to the plan."""
    adaptation_id: str = ""
    reason: AdaptationReason = AdaptationReason.NEW_FINDING
    description: str = ""
    affected_phases: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.adaptation_id,
            "reason": self.reason.value,
            "description": self.description[:60],
            "phases": self.affected_phases,
        }


@dataclass
class AssessmentPlan:
    """A complete assessment plan."""
    plan_id: str = ""
    target: str = ""
    target_type: str = ""
    phases: list[PlanPhase] = field(default_factory=list)
    total_time_s: float = 3600.0
    version: int = 1
    adaptations: list[PlanAdaptation] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id, "target": self.target[:60],
            "type": self.target_type, "version": self.version,
            "phases": len(self.phases),
            "adaptations": len(self.adaptations),
        }


# ── Plan Templates ────────────────────────────────────────────

WEB_PLAN_PHASES = [
    {"name": "Reconnaissance", "tools": ["subfinder", "httpx", "whatweb", "dig", "whois"],
     "time": 300, "priority": 1},
    {"name": "Directory Discovery", "tools": ["ffuf", "gobuster"],
     "time": 300, "priority": 2},
    {"name": "Vulnerability Scanning", "tools": ["nuclei", "nikto"],
     "time": 600, "priority": 2},
    {"name": "Web Testing", "tools": ["sqlmap", "dalfox", "commix"],
     "time": 600, "priority": 3, "depends": ["Vulnerability Scanning"]},
    {"name": "SSL Analysis", "tools": ["sslscan", "testssl.sh"],
     "time": 120, "priority": 4},
    {"name": "Authentication Testing", "tools": ["hydra"],
     "time": 300, "priority": 4, "depends": ["Reconnaissance"]},
    {"name": "Code Analysis", "tools": ["semgrep", "gitleaks"],
     "time": 300, "priority": 5},
    {"name": "Validation", "tools": [],
     "time": 300, "priority": 6, "depends": ["Web Testing"]},
]

NETWORK_PLAN_PHASES = [
    {"name": "Host Discovery", "tools": ["nmap", "masscan"],
     "time": 300, "priority": 1},
    {"name": "Service Enumeration", "tools": ["nmap"],
     "time": 600, "priority": 2, "depends": ["Host Discovery"]},
    {"name": "Vulnerability Scanning", "tools": ["nuclei", "nmap"],
     "time": 600, "priority": 2},
    {"name": "Credential Testing", "tools": ["hydra"],
     "time": 300, "priority": 3, "depends": ["Service Enumeration"]},
    {"name": "Exploitation", "tools": [],
     "time": 600, "priority": 4, "depends": ["Vulnerability Scanning"]},
    {"name": "Validation", "tools": [],
     "time": 300, "priority": 5},
]

API_PLAN_PHASES = [
    {"name": "Endpoint Discovery", "tools": ["ffuf", "httpx"],
     "time": 300, "priority": 1},
    {"name": "Authentication Analysis", "tools": [],
     "time": 300, "priority": 2},
    {"name": "API Fuzzing", "tools": ["ffuf"],
     "time": 600, "priority": 2},
    {"name": "Injection Testing", "tools": ["sqlmap", "commix"],
     "time": 600, "priority": 3, "depends": ["Endpoint Discovery"]},
    {"name": "Authorization Testing", "tools": [],
     "time": 300, "priority": 3},
    {"name": "Validation", "tools": [],
     "time": 300, "priority": 4},
]


class AdaptivePlanner:
    """Dynamically adjusts assessment plans based on results.

    Generates initial plans from templates and adapts
    them in real-time based on findings and progress.
    """

    def __init__(self) -> None:
        self._plans: dict[str, AssessmentPlan] = {}
        self._plan_counter = 0
        self._adaptation_counter = 0
        self._log = logger.bind(component="adaptive_planner")

    def create_plan(
        self,
        target: str,
        target_type: str = "web_app",
        total_time_s: float = 3600.0,
    ) -> AssessmentPlan:
        """Create an assessment plan."""
        self._plan_counter += 1
        plan_id = f"plan-{self._plan_counter}"

        template_map = {
            "web_app": WEB_PLAN_PHASES,
            "api": API_PLAN_PHASES,
            "network": NETWORK_PLAN_PHASES,
            "host": NETWORK_PLAN_PHASES,
        }

        template = template_map.get(target_type, WEB_PLAN_PHASES)

        # Scale time allocation
        total_template_time = sum(p["time"] for p in template)
        scale = total_time_s / max(1, total_template_time)

        phases = []
        for i, phase_data in enumerate(template):
            phase = PlanPhase(
                phase_id=f"{plan_id}-p{i + 1}",
                name=phase_data["name"],
                tools=phase_data["tools"],
                dependencies=phase_data.get("depends", []),
                allocated_time_s=phase_data["time"] * scale,
                priority=phase_data.get("priority", 5),
            )
            phases.append(phase)

        plan = AssessmentPlan(
            plan_id=plan_id,
            target=target,
            target_type=target_type,
            phases=phases,
            total_time_s=total_time_s,
        )

        self._plans[plan_id] = plan
        return plan

    def adapt(
        self,
        plan_id: str,
        reason: AdaptationReason,
        context: dict[str, Any] | None = None,
    ) -> PlanAdaptation:
        """Adapt a plan based on new information."""
        plan = self._plans.get(plan_id)
        if not plan:
            return PlanAdaptation()

        self._adaptation_counter += 1
        adaptation = PlanAdaptation(
            adaptation_id=f"adapt-{self._adaptation_counter}",
            reason=reason,
        )

        context = context or {}

        if reason == AdaptationReason.NEW_FINDING:
            adaptation = self._adapt_for_finding(plan, adaptation, context)

        elif reason == AdaptationReason.TOOL_FAILURE:
            adaptation = self._adapt_for_tool_failure(plan, adaptation, context)

        elif reason == AdaptationReason.TIME_PRESSURE:
            adaptation = self._adapt_for_time(plan, adaptation)

        elif reason == AdaptationReason.HIGH_VALUE_TARGET:
            adaptation = self._adapt_for_high_value(plan, adaptation, context)

        elif reason == AdaptationReason.CONVERGENCE:
            adaptation = self._adapt_for_convergence(plan, adaptation)

        plan.version += 1
        plan.adaptations.append(adaptation)
        return adaptation

    def _adapt_for_finding(
        self,
        plan: AssessmentPlan,
        adaptation: PlanAdaptation,
        context: dict[str, Any],
    ) -> PlanAdaptation:
        """Adapt plan when a new finding is discovered."""
        severity = context.get("severity", "info")
        finding_type = context.get("type", "")

        if severity in ("critical", "high"):
            # Allocate more time to exploitation/validation
            for phase in plan.phases:
                if "exploit" in phase.name.lower() or "validation" in phase.name.lower():
                    phase.allocated_time_s *= 1.5
                    phase.depth = 3
                    adaptation.affected_phases.append(phase.phase_id)

            adaptation.description = f"Deep dive on {severity} finding: {finding_type}"

        elif "injection" in finding_type.lower():
            # Add injection-specific tools
            for phase in plan.phases:
                if "web" in phase.name.lower() or "injection" in phase.name.lower():
                    if "sqlmap" not in phase.tools:
                        phase.tools.append("sqlmap")
                    adaptation.affected_phases.append(phase.phase_id)

            adaptation.description = "Added injection tools"

        return adaptation

    def _adapt_for_tool_failure(
        self,
        plan: AssessmentPlan,
        adaptation: PlanAdaptation,
        context: dict[str, Any],
    ) -> PlanAdaptation:
        """Adapt plan when a tool fails."""
        failed_tool = context.get("tool", "")

        substitutions = {
            "nuclei": "nikto",
            "nikto": "nuclei",
            "ffuf": "gobuster",
            "gobuster": "ffuf",
            "subfinder": "amass",
            "amass": "subfinder",
            "nmap": "masscan",
        }

        substitute = substitutions.get(failed_tool)
        if substitute:
            for phase in plan.phases:
                if failed_tool in phase.tools:
                    phase.tools.remove(failed_tool)
                    phase.tools.append(substitute)
                    adaptation.affected_phases.append(phase.phase_id)

            adaptation.description = f"Substituted {failed_tool} → {substitute}"

        return adaptation

    def _adapt_for_time(
        self,
        plan: AssessmentPlan,
        adaptation: PlanAdaptation,
    ) -> PlanAdaptation:
        """Adapt plan under time pressure."""
        # Skip low-priority phases
        for phase in plan.phases:
            if phase.priority >= 5 and phase.status == PhaseStatus.PENDING:
                phase.status = PhaseStatus.SKIPPED
                adaptation.affected_phases.append(phase.phase_id)

        # Reduce depth on remaining phases
        for phase in plan.phases:
            if phase.status == PhaseStatus.PENDING:
                phase.depth = 1
                phase.allocated_time_s *= 0.5

        adaptation.description = "Reduced scope due to time pressure"
        return adaptation

    def _adapt_for_high_value(
        self,
        plan: AssessmentPlan,
        adaptation: PlanAdaptation,
        context: dict[str, Any],
    ) -> PlanAdaptation:
        """Adapt plan for high-value target area."""
        area = context.get("area", "")

        for phase in plan.phases:
            if area.lower() in phase.name.lower():
                phase.depth = 3
                phase.allocated_time_s *= 2.0
                phase.priority = max(1, phase.priority - 2)
                adaptation.affected_phases.append(phase.phase_id)

        adaptation.description = f"Prioritized high-value area: {area}"
        return adaptation

    def _adapt_for_convergence(
        self,
        plan: AssessmentPlan,
        adaptation: PlanAdaptation,
    ) -> PlanAdaptation:
        """Adapt plan when convergence is detected."""
        for phase in plan.phases:
            if phase.status == PhaseStatus.PENDING:
                phase.status = PhaseStatus.SKIPPED
                adaptation.affected_phases.append(phase.phase_id)

        adaptation.description = "Skipped remaining phases — assessment converged"
        return adaptation

    def get_next_phase(self, plan_id: str) -> PlanPhase | None:
        """Get the next phase to execute."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        pending = [
            p for p in plan.phases
            if p.status == PhaseStatus.PENDING
        ]

        if not pending:
            return None

        # Check dependencies
        completed = {p.name for p in plan.phases if p.status == PhaseStatus.COMPLETED}

        for phase in sorted(pending, key=lambda p: p.priority):
            deps_met = all(d in completed for d in phase.dependencies)
            if deps_met:
                return phase

        return None

    def get_stats(self) -> dict[str, Any]:
        return {
            "plans": len(self._plans),
            "adaptations": self._adaptation_counter,
        }
