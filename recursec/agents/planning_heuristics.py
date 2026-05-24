"""Planning heuristics — intelligent task planning.

Implements:
1. Assessment scope estimation
2. Phase ordering heuristics
3. Tool selection heuristics
4. Time allocation estimation
5. Complexity scoring
6. Planning prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetComplexity(str, Enum):
    TRIVIAL = "trivial"       # Single endpoint/service
    SIMPLE = "simple"         # Small app, few services
    MODERATE = "moderate"     # Medium app, multiple services
    COMPLEX = "complex"       # Large app, many services
    MASSIVE = "massive"       # Enterprise, thousands of assets


class PhaseOrder(str, Enum):
    STANDARD = "standard"     # Recon → Scan → Analyze → Exploit
    QUICK = "quick"           # Scan → Analyze (skip deep recon)
    DEEP = "deep"             # Extended recon → Deep scan → ...
    TARGETED = "targeted"     # Focus on specific vuln type
    STEALTH = "stealth"       # Low-noise, passive first


# Phase time estimates (minutes) by complexity
PHASE_TIME_ESTIMATES: dict[str, dict[TargetComplexity, int]] = {
    "recon": {
        TargetComplexity.TRIVIAL: 2,
        TargetComplexity.SIMPLE: 5,
        TargetComplexity.MODERATE: 15,
        TargetComplexity.COMPLEX: 30,
        TargetComplexity.MASSIVE: 60,
    },
    "enumeration": {
        TargetComplexity.TRIVIAL: 2,
        TargetComplexity.SIMPLE: 5,
        TargetComplexity.MODERATE: 10,
        TargetComplexity.COMPLEX: 25,
        TargetComplexity.MASSIVE: 45,
    },
    "scanning": {
        TargetComplexity.TRIVIAL: 3,
        TargetComplexity.SIMPLE: 10,
        TargetComplexity.MODERATE: 20,
        TargetComplexity.COMPLEX: 40,
        TargetComplexity.MASSIVE: 90,
    },
    "analysis": {
        TargetComplexity.TRIVIAL: 1,
        TargetComplexity.SIMPLE: 3,
        TargetComplexity.MODERATE: 8,
        TargetComplexity.COMPLEX: 15,
        TargetComplexity.MASSIVE: 30,
    },
    "exploitation": {
        TargetComplexity.TRIVIAL: 2,
        TargetComplexity.SIMPLE: 5,
        TargetComplexity.MODERATE: 15,
        TargetComplexity.COMPLEX: 30,
        TargetComplexity.MASSIVE: 60,
    },
    "validation": {
        TargetComplexity.TRIVIAL: 1,
        TargetComplexity.SIMPLE: 3,
        TargetComplexity.MODERATE: 8,
        TargetComplexity.COMPLEX: 15,
        TargetComplexity.MASSIVE: 30,
    },
    "reporting": {
        TargetComplexity.TRIVIAL: 1,
        TargetComplexity.SIMPLE: 2,
        TargetComplexity.MODERATE: 5,
        TargetComplexity.COMPLEX: 10,
        TargetComplexity.MASSIVE: 20,
    },
}

# Target type → recommended tools
TOOL_HEURISTICS: dict[str, list[str]] = {
    "web_app": ["nuclei", "sqlmap", "ffuf", "nikto", "wappalyzer", "burp"],
    "api": ["nuclei", "ffuf", "postman", "arjun", "jwt_tool"],
    "network": ["nmap", "masscan", "netcat", "responder"],
    "cloud_aws": ["prowler", "scoutsuite", "pacu", "cloudfox"],
    "cloud_azure": ["scoutsuite", "azurehound", "roadtools"],
    "cloud_gcp": ["scoutsuite", "gcp_scanner"],
    "active_directory": ["bloodhound", "impacket", "crackmapexec", "rubeus"],
    "container": ["trivy", "grype", "deepce", "kube-bench"],
    "wireless": ["aircrack-ng", "bettercap", "wifite"],
    "mobile_android": ["apktool", "jadx", "frida", "drozer"],
    "mobile_ios": ["frida", "objection", "class-dump"],
    "iot": ["binwalk", "firmwalker", "nmap"],
    "code_audit": ["semgrep", "bandit", "codeql", "sonarqube"],
}


@dataclass
class AssessmentPlan:
    """A generated assessment plan."""
    plan_id: str = ""
    target: str = ""
    target_type: str = ""
    complexity: TargetComplexity = TargetComplexity.MODERATE
    phase_order: PhaseOrder = PhaseOrder.STANDARD
    phases: list[str] = field(default_factory=list)
    tools_per_phase: dict[str, list[str]] = field(default_factory=dict)
    time_estimate_min: int = 0
    agents_needed: int = 1
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "complexity": self.complexity.value[:8],
            "phases": len(self.phases),
            "time": f"{self.time_estimate_min}m",
        }


class PlanningHeuristics:
    """Intelligent task planning heuristics.

    Generates assessment plans based on
    target analysis and heuristic rules.
    """

    def __init__(self) -> None:
        self._plans: dict[str, AssessmentPlan] = {}
        self._plan_counter = 0
        self._log = logger.bind(component="planner")

    def estimate_complexity(
        self,
        target: str,
        services_count: int = 0,
        endpoints_count: int = 0,
        subdomains_count: int = 0,
    ) -> TargetComplexity:
        """Estimate target complexity."""
        score = 0
        score += min(5, services_count)
        score += min(5, endpoints_count // 10)
        score += min(5, subdomains_count // 5)

        if score <= 2:
            return TargetComplexity.TRIVIAL
        elif score <= 5:
            return TargetComplexity.SIMPLE
        elif score <= 10:
            return TargetComplexity.MODERATE
        elif score <= 15:
            return TargetComplexity.COMPLEX
        else:
            return TargetComplexity.MASSIVE

    def select_phase_order(
        self,
        target_type: str,
        time_budget_min: int = 0,
        stealth: bool = False,
    ) -> PhaseOrder:
        """Select optimal phase ordering."""
        if stealth:
            return PhaseOrder.STEALTH

        if time_budget_min > 0 and time_budget_min < 30:
            return PhaseOrder.QUICK

        if target_type in ("active_directory", "network"):
            return PhaseOrder.DEEP

        if target_type in ("web_app", "api"):
            return PhaseOrder.STANDARD

        return PhaseOrder.STANDARD

    def get_phase_sequence(self, order: PhaseOrder) -> list[str]:
        """Get phase sequence for an ordering."""
        sequences = {
            PhaseOrder.STANDARD: [
                "recon", "enumeration", "scanning",
                "analysis", "exploitation", "validation",
                "reporting",
            ],
            PhaseOrder.QUICK: [
                "scanning", "analysis", "exploitation",
                "validation", "reporting",
            ],
            PhaseOrder.DEEP: [
                "recon", "enumeration", "recon",
                "scanning", "analysis", "exploitation",
                "validation", "reporting",
            ],
            PhaseOrder.TARGETED: [
                "scanning", "analysis", "exploitation",
                "validation", "reporting",
            ],
            PhaseOrder.STEALTH: [
                "recon", "analysis", "scanning",
                "analysis", "exploitation", "validation",
                "reporting",
            ],
        }
        return sequences.get(order, sequences[PhaseOrder.STANDARD])

    def select_tools(
        self,
        target_type: str,
        phase: str,
    ) -> list[str]:
        """Select tools for a phase and target type."""
        base_tools = TOOL_HEURISTICS.get(target_type, [])

        # Phase-specific filtering
        phase_tools = {
            "recon": ["nmap", "masscan", "amass", "subfinder", "dnsx"],
            "enumeration": ["ffuf", "gobuster", "wappalyzer", "whatweb"],
            "scanning": ["nuclei", "nikto", "nessus", "trivy"],
            "exploitation": ["sqlmap", "metasploit", "burp"],
            "validation": ["nuclei", "curl", "httpx"],
        }

        recommended = phase_tools.get(phase, [])
        combined = list(set(base_tools + recommended))
        return combined[:8]

    def estimate_time(
        self,
        complexity: TargetComplexity,
        phases: list[str],
    ) -> int:
        """Estimate total time in minutes."""
        total = 0
        for phase in phases:
            phase_estimates = PHASE_TIME_ESTIMATES.get(phase, {})
            total += phase_estimates.get(complexity, 10)
        return total

    def estimate_agents(
        self,
        complexity: TargetComplexity,
    ) -> int:
        """Estimate number of agents needed."""
        return {
            TargetComplexity.TRIVIAL: 1,
            TargetComplexity.SIMPLE: 2,
            TargetComplexity.MODERATE: 3,
            TargetComplexity.COMPLEX: 5,
            TargetComplexity.MASSIVE: 8,
        }.get(complexity, 3)

    def generate_plan(
        self,
        target: str,
        target_type: str = "web_app",
        services_count: int = 0,
        endpoints_count: int = 0,
        time_budget_min: int = 0,
        stealth: bool = False,
    ) -> AssessmentPlan:
        """Generate a complete assessment plan."""
        self._plan_counter += 1

        complexity = self.estimate_complexity(
            target, services_count, endpoints_count,
        )
        phase_order = self.select_phase_order(
            target_type, time_budget_min, stealth,
        )
        phases = self.get_phase_sequence(phase_order)
        time_estimate = self.estimate_time(complexity, phases)
        agents_needed = self.estimate_agents(complexity)

        tools_per_phase: dict[str, list[str]] = {}
        for phase in set(phases):
            tools_per_phase[phase] = self.select_tools(target_type, phase)

        plan = AssessmentPlan(
            plan_id=f"plan-{self._plan_counter}",
            target=target,
            target_type=target_type,
            complexity=complexity,
            phase_order=phase_order,
            phases=phases,
            tools_per_phase=tools_per_phase,
            time_estimate_min=time_estimate,
            agents_needed=agents_needed,
        )
        self._plans[plan.plan_id] = plan
        return plan

    def build_planning_prompt(self, plan_id: str = "") -> str:
        """Build planning context for LLM."""
        if plan_id and plan_id in self._plans:
            plan = self._plans[plan_id]
            lines = [f"## Plan: {plan.target[:20]}\n"]
            lines.append(f"Complexity: {plan.complexity.value}")
            lines.append(f"Phases: {' → '.join(plan.phases[:5])}")
            lines.append(f"Time: ~{plan.time_estimate_min}m")
            lines.append(f"Agents: {plan.agents_needed}")

            for phase, tools in list(plan.tools_per_phase.items())[:4]:
                lines.append(
                    f"  {phase[:8]}: {', '.join(tools[:4])}"
                )
            return "\n".join(lines)

        lines = ["## Planning\n"]
        lines.append(f"Plans: {len(self._plans)}")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "plans": len(self._plans),
            "complexity_counts": {
                c.value: sum(
                    1 for p in self._plans.values()
                    if p.complexity == c
                )
                for c in TargetComplexity
            },
        }
