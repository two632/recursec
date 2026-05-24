"""Agent planning engine — generates multi-step execution plans.

This is the PLANNING brain of the agent. Given a goal and context,
it generates structured plans that the execution engine follows:
1. Goal analysis (classify intent, extract entities, identify constraints)
2. Plan generation (select strategy, order tools, allocate resources)
3. Plan optimization (remove redundant steps, parallelize where possible)
4. Plan validation (check feasibility, verify tool availability)
5. Plan adaptation (modify plan based on intermediate results)
6. Contingency planning (fallback plans for common failures)

The plan is what bridges "find vulns in X" → actual tool executions.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PlanStatus(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ADAPTED = "adapted"


class StepType(str, Enum):
    TOOL_EXECUTION = "tool_execution"
    LLM_QUERY = "llm_query"
    ANALYSIS = "analysis"
    DECISION = "decision"
    SPAWN_AGENT = "spawn_agent"
    WAIT_RESULT = "wait_result"
    AGGREGATE = "aggregate"
    VALIDATE = "validate"


class ExecutionMode(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"


@dataclass
class PlanStep:
    """A single step in an execution plan."""
    step_id: int = 0
    step_type: StepType = StepType.TOOL_EXECUTION
    description: str = ""
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    model_id: str = ""
    prompt_template: str = ""
    agent_role: str = ""
    expected_output: str = ""
    execution_mode: ExecutionMode = ExecutionMode.SEQUENTIAL
    dependencies: list[int] = field(default_factory=list)
    timeout_s: int = 300
    retries: int = 1
    fallback_step: int | None = None
    condition: str = ""
    output_key: str = ""
    status: str = "pending"
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_id,
            "type": self.step_type.value[:10],
            "desc": self.description[:30],
            "tool": self.tool_name[:15] if self.tool_name else "",
            "mode": self.execution_mode.value[:6],
            "deps": self.dependencies,
            "status": self.status[:8],
        }


@dataclass
class ExecutionPlan:
    """A complete execution plan."""
    plan_id: str = ""
    goal: str = ""
    target: str = ""
    steps: list[PlanStep] = field(default_factory=list)
    status: PlanStatus = PlanStatus.DRAFT
    strategy: str = ""
    estimated_duration_s: int = 0
    token_budget: int = 10000
    created_at: float = field(default_factory=time.time)
    adaptations: int = 0

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    @property
    def completed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == "completed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id[:8],
            "goal": self.goal[:30],
            "steps": self.total_steps,
            "done": self.completed_steps,
            "strategy": self.strategy[:15],
            "status": self.status.value[:8],
        }


@dataclass
class GoalAnalysis:
    """Structured analysis of a user goal."""
    original_goal: str = ""
    intent: str = ""
    target_type: str = ""
    target_value: str = ""
    scope: str = ""
    constraints: list[str] = field(default_factory=list)
    entities: dict[str, str] = field(default_factory=dict)
    urgency: str = "normal"
    requires_stealth: bool = False
    max_depth: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent[:15],
            "target": f"{self.target_type}:{self.target_value[:15]}",
            "scope": self.scope[:10],
            "urgency": self.urgency[:8],
        }


# Pre-built plan templates
PLAN_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_pentest": [
        {"type": StepType.TOOL_EXECUTION, "desc": "Subdomain enumeration", "tool": "subfinder", "mode": ExecutionMode.PARALLEL, "timeout": 300},
        {"type": StepType.TOOL_EXECUTION, "desc": "DNS resolution and live host check", "tool": "httpx", "mode": ExecutionMode.PARALLEL, "timeout": 300, "deps": [0]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Port scanning on live hosts", "tool": "nmap", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [1]},
        {"type": StepType.LLM_QUERY, "desc": "Analyze recon results and plan attack", "model": "deepseek-r1", "mode": ExecutionMode.SEQUENTIAL, "deps": [1, 2]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Web vulnerability scanning", "tool": "nuclei", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [1]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Directory and file bruting", "tool": "ffuf", "mode": ExecutionMode.PARALLEL, "timeout": 300, "deps": [1]},
        {"type": StepType.TOOL_EXECUTION, "desc": "SQL injection testing", "tool": "sqlmap", "mode": ExecutionMode.SEQUENTIAL, "timeout": 600, "deps": [4, 5]},
        {"type": StepType.LLM_QUERY, "desc": "Analyze all findings", "model": "whiterabbit", "mode": ExecutionMode.SEQUENTIAL, "deps": [4, 5, 6]},
        {"type": StepType.VALIDATE, "desc": "Cross-validate critical findings", "mode": ExecutionMode.SEQUENTIAL, "deps": [7]},
        {"type": StepType.AGGREGATE, "desc": "Generate final report", "mode": ExecutionMode.SEQUENTIAL, "deps": [8]},
    ],
    "web_scan": [
        {"type": StepType.TOOL_EXECUTION, "desc": "HTTP probe and tech detection", "tool": "httpx", "mode": ExecutionMode.PARALLEL, "timeout": 120},
        {"type": StepType.TOOL_EXECUTION, "desc": "Web content discovery", "tool": "ffuf", "mode": ExecutionMode.PARALLEL, "timeout": 300, "deps": [0]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Vulnerability scanning", "tool": "nuclei", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [0]},
        {"type": StepType.TOOL_EXECUTION, "desc": "XSS testing", "tool": "dalfox", "mode": ExecutionMode.SEQUENTIAL, "timeout": 300, "deps": [1]},
        {"type": StepType.LLM_QUERY, "desc": "Analyze web findings", "model": "whiterabbit", "mode": ExecutionMode.SEQUENTIAL, "deps": [1, 2, 3]},
        {"type": StepType.AGGREGATE, "desc": "Compile web assessment report", "mode": ExecutionMode.SEQUENTIAL, "deps": [4]},
    ],
    "recon_only": [
        {"type": StepType.TOOL_EXECUTION, "desc": "Subdomain enumeration", "tool": "subfinder", "mode": ExecutionMode.PARALLEL, "timeout": 300},
        {"type": StepType.TOOL_EXECUTION, "desc": "Alternative subdomain enum", "tool": "amass", "mode": ExecutionMode.PARALLEL, "timeout": 600},
        {"type": StepType.TOOL_EXECUTION, "desc": "Live host detection", "tool": "httpx", "mode": ExecutionMode.PARALLEL, "timeout": 300, "deps": [0, 1]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Port scanning", "tool": "nmap", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [2]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Technology detection", "tool": "httpx", "mode": ExecutionMode.PARALLEL, "timeout": 120, "deps": [2]},
        {"type": StepType.LLM_QUERY, "desc": "Analyze recon data and identify attack surface", "model": "deepseek-r1", "mode": ExecutionMode.SEQUENTIAL, "deps": [2, 3, 4]},
    ],
    "code_audit": [
        {"type": StepType.TOOL_EXECUTION, "desc": "Static analysis", "tool": "semgrep", "mode": ExecutionMode.PARALLEL, "timeout": 300},
        {"type": StepType.TOOL_EXECUTION, "desc": "Python security audit", "tool": "bandit", "mode": ExecutionMode.PARALLEL, "timeout": 300},
        {"type": StepType.TOOL_EXECUTION, "desc": "Secret detection", "tool": "gitleaks", "mode": ExecutionMode.PARALLEL, "timeout": 120},
        {"type": StepType.TOOL_EXECUTION, "desc": "Dependency vulnerability check", "tool": "trivy", "mode": ExecutionMode.PARALLEL, "timeout": 120},
        {"type": StepType.LLM_QUERY, "desc": "Deep code review with long context", "model": "yi-9b-200k", "mode": ExecutionMode.SEQUENTIAL, "deps": [0, 1]},
        {"type": StepType.LLM_QUERY, "desc": "Analyze security findings", "model": "qwen-coder-14b", "mode": ExecutionMode.SEQUENTIAL, "deps": [0, 1, 2, 3, 4]},
        {"type": StepType.AGGREGATE, "desc": "Compile code audit report", "mode": ExecutionMode.SEQUENTIAL, "deps": [5]},
    ],
    "network_scan": [
        {"type": StepType.TOOL_EXECUTION, "desc": "Host discovery", "tool": "nmap", "mode": ExecutionMode.PARALLEL, "timeout": 300},
        {"type": StepType.TOOL_EXECUTION, "desc": "Full port scan", "tool": "masscan", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [0]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Service version detection", "tool": "nmap", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [1]},
        {"type": StepType.TOOL_EXECUTION, "desc": "Vulnerability scanning", "tool": "nuclei", "mode": ExecutionMode.PARALLEL, "timeout": 600, "deps": [2]},
        {"type": StepType.LLM_QUERY, "desc": "Analyze network topology and vulns", "model": "whiterabbit", "mode": ExecutionMode.SEQUENTIAL, "deps": [2, 3]},
        {"type": StepType.AGGREGATE, "desc": "Network assessment summary", "mode": ExecutionMode.SEQUENTIAL, "deps": [4]},
    ],
}

# Intent → template mapping
INTENT_TEMPLATE_MAP: dict[str, str] = {
    "full_assessment": "full_pentest",
    "pentest": "full_pentest",
    "vulnerability_scan": "web_scan",
    "web_scan": "web_scan",
    "web_test": "web_scan",
    "recon": "recon_only",
    "reconnaissance": "recon_only",
    "enumerate": "recon_only",
    "code_review": "code_audit",
    "code_audit": "code_audit",
    "static_analysis": "code_audit",
    "network_scan": "network_scan",
    "port_scan": "network_scan",
    "infrastructure": "network_scan",
}

# Intent keywords
INTENT_KEYWORDS: dict[str, list[str]] = {
    "full_assessment": ["full", "comprehensive", "complete", "everything", "pentest", "penetration test"],
    "web_scan": ["web", "website", "webapp", "http", "url", "application"],
    "recon": ["recon", "enumerate", "discover", "subdomain", "find", "scope"],
    "code_audit": ["code", "source", "review", "audit", "static", "sast"],
    "network_scan": ["network", "port", "infrastructure", "hosts", "scan", "ip range"],
}


class AgentPlanningEngine:
    """Generates and manages execution plans for the agent."""

    def __init__(self) -> None:
        self._plans: dict[str, ExecutionPlan] = {}
        self._plan_counter = 0
        self._log = logger.bind(component="planning_engine")

    def analyze_goal(self, goal: str, target: str = "") -> GoalAnalysis:
        """Analyze a user goal into structured components."""
        goal_lower = goal.lower()

        # Classify intent
        intent = "full_assessment"
        best_score = 0
        for intent_name, keywords in INTENT_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in goal_lower)
            if score > best_score:
                best_score = score
                intent = intent_name

        # Extract target type
        target_type = "unknown"
        if any(kw in goal_lower for kw in ["website", "web", "http", "url"]):
            target_type = "web"
        elif any(kw in goal_lower for kw in ["network", "ip", "range", "subnet"]):
            target_type = "network"
        elif any(kw in goal_lower for kw in ["code", "source", "repository", "repo"]):
            target_type = "code"
        elif any(kw in goal_lower for kw in ["cloud", "aws", "azure", "gcp"]):
            target_type = "cloud"

        # Extract constraints
        constraints = []
        if "stealth" in goal_lower or "quiet" in goal_lower:
            constraints.append("stealth_mode")
        if "fast" in goal_lower or "quick" in goal_lower:
            constraints.append("speed_priority")
        if "thorough" in goal_lower or "deep" in goal_lower:
            constraints.append("thoroughness_priority")

        return GoalAnalysis(
            original_goal=goal,
            intent=intent,
            target_type=target_type,
            target_value=target,
            scope="external" if "external" in goal_lower else "full",
            constraints=constraints,
            urgency="high" if "urgent" in goal_lower or "critical" in goal_lower else "normal",
            requires_stealth="stealth_mode" in constraints,
        )

    def generate_plan(self, goal: str, target: str = "") -> ExecutionPlan:
        """Generate an execution plan from a goal."""
        analysis = self.analyze_goal(goal, target)
        self._plan_counter += 1

        template_key = INTENT_TEMPLATE_MAP.get(analysis.intent, "full_pentest")
        template = PLAN_TEMPLATES.get(template_key, PLAN_TEMPLATES["full_pentest"])

        steps = []
        for i, step_tmpl in enumerate(template):
            step = PlanStep(
                step_id=i,
                step_type=step_tmpl["type"],
                description=step_tmpl["desc"],
                tool_name=step_tmpl.get("tool", ""),
                model_id=step_tmpl.get("model", ""),
                execution_mode=step_tmpl.get("mode", ExecutionMode.SEQUENTIAL),
                dependencies=step_tmpl.get("deps", []),
                timeout_s=step_tmpl.get("timeout", 300),
                output_key=f"step_{i}_output",
            )
            steps.append(step)

        plan = ExecutionPlan(
            plan_id=f"plan-{self._plan_counter}",
            goal=goal,
            target=target,
            steps=steps,
            status=PlanStatus.DRAFT,
            strategy=template_key,
            estimated_duration_s=sum(s.timeout_s for s in steps),
        )

        # Validate
        plan = self._validate_plan(plan)

        self._plans[plan.plan_id] = plan
        return plan

    def _validate_plan(self, plan: ExecutionPlan) -> ExecutionPlan:
        """Validate plan feasibility."""
        # Check dependency graph is acyclic — remove forward deps
        for step in plan.steps:
            for dep in step.dependencies:
                if dep >= step.step_id:
                    step.dependencies.remove(dep)

        plan.status = PlanStatus.VALIDATED
        return plan

    def adapt_plan(self, plan_id: str, step_id: int, new_steps: list[dict[str, Any]]) -> ExecutionPlan:
        """Adapt a plan based on intermediate results."""
        plan = self._plans.get(plan_id)
        if not plan:
            return ExecutionPlan()

        # Insert new steps after the given step
        new_plan_steps = []
        max_id = max(s.step_id for s in plan.steps) if plan.steps else 0
        for i, ns in enumerate(new_steps):
            new_plan_steps.append(PlanStep(
                step_id=max_id + i + 1,
                step_type=ns.get("type", StepType.TOOL_EXECUTION),
                description=ns.get("desc", ""),
                tool_name=ns.get("tool", ""),
                dependencies=[step_id],
            ))

        plan.steps.extend(new_plan_steps)
        plan.adaptations += 1
        plan.status = PlanStatus.ADAPTED

        return plan

    def get_parallel_groups(self, plan_id: str) -> list[list[int]]:
        """Identify groups of steps that can run in parallel."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        groups: list[list[int]] = []
        completed: set[int] = set()

        while len(completed) < len(plan.steps):
            ready = []
            for step in plan.steps:
                if step.step_id in completed:
                    continue
                if all(d in completed for d in step.dependencies):
                    ready.append(step.step_id)

            if not ready:
                break

            groups.append(ready)
            completed.update(ready)

        return groups

    def build_plan_prompt(self, plan_id: str) -> str:
        """Build LLM prompt with plan details."""
        plan = self._plans.get(plan_id)
        if not plan:
            return ""

        lines = [f"## Execution Plan: {plan.goal[:50]}"]
        lines.append(f"Strategy: {plan.strategy}, Status: {plan.status.value}")
        lines.append(f"Steps: {plan.total_steps}, Completed: {plan.completed_steps}")

        groups = self.get_parallel_groups(plan_id)
        for i, group in enumerate(groups):
            lines.append(f"\nPhase {i + 1} (parallel):")
            for step_id in group:
                step = plan.steps[step_id] if step_id < len(plan.steps) else None
                if step:
                    tool = f" [{step.tool_name}]" if step.tool_name else ""
                    lines.append(f"  Step {step.step_id}: {step.description}{tool}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_plans": len(self._plans),
            "active": sum(1 for p in self._plans.values() if p.status == PlanStatus.EXECUTING),
            "completed": sum(1 for p in self._plans.values() if p.status == PlanStatus.COMPLETED),
        }
