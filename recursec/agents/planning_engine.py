"""Planning engine — hierarchical task planning with replanning capabilities.

Goes beyond goal decomposition to implement full planning:
1. HTN (Hierarchical Task Network) planning
2. Plan repair when actions fail
3. Contingency planning (plan B/C)
4. Resource-aware planning (token budgets)
5. Temporal planning (ordering constraints)
6. Plan monitoring and execution
7. Plan quality assessment
8. Opportunistic replanning
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PlanStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    EXECUTING = "executing"
    REPLANNING = "replanning"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class ActionStatus(str, Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ActionType(str, Enum):
    RECON = "recon"
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    REPORT = "report"
    DELEGATE = "delegate"
    THINK = "think"


@dataclass
class PlanAction:
    """A single action in a plan."""
    action_id: str = ""
    action_type: ActionType = ActionType.RECON
    description: str = ""
    tool: str = ""
    model: str = ""
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)
    effects: list[str] = field(default_factory=list)
    status: ActionStatus = ActionStatus.PENDING
    estimated_tokens: int = 500
    estimated_time_s: float = 30.0
    actual_tokens: int = 0
    actual_time_s: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    contingency_action_id: str = ""

    @property
    def is_ready(self) -> bool:
        return self.status == ActionStatus.PENDING and not self.preconditions

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.action_id,
            "type": self.action_type.value,
            "desc": self.description[:40],
            "tool": self.tool[:15],
            "status": self.status.value,
            "est_tokens": self.estimated_tokens,
        }


@dataclass
class Plan:
    """A hierarchical plan."""
    plan_id: str = ""
    goal: str = ""
    target: str = ""
    actions: list[PlanAction] = field(default_factory=list)
    contingencies: dict[str, str] = field(default_factory=dict)
    status: PlanStatus = PlanStatus.DRAFT
    token_budget: int = 50000
    tokens_used: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    replan_count: int = 0

    @property
    def progress(self) -> float:
        if not self.actions:
            return 0.0
        completed = sum(1 for a in self.actions if a.status == ActionStatus.COMPLETED)
        return completed / len(self.actions)

    @property
    def budget_remaining(self) -> float:
        if self.token_budget == 0:
            return 0.0
        return max(0.0, 1.0 - self.tokens_used / self.token_budget)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id,
            "goal": self.goal[:40],
            "target": self.target[:25],
            "status": self.status.value,
            "actions": len(self.actions),
            "progress": round(self.progress, 2),
            "budget": round(self.budget_remaining, 2),
            "replans": self.replan_count,
        }


# ── Plan Templates ────────────────────────────────────────────

PLAN_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_assessment": [
        {"type": "recon", "desc": "Subdomain enumeration", "tool": "subfinder", "est_tokens": 200},
        {"type": "recon", "desc": "Port scanning", "tool": "nmap", "est_tokens": 300},
        {"type": "recon", "desc": "HTTP probing", "tool": "httpx", "est_tokens": 200},
        {"type": "recon", "desc": "Technology fingerprinting", "tool": "whatweb", "est_tokens": 200},
        {"type": "scan", "desc": "Directory bruteforce", "tool": "ffuf", "est_tokens": 300},
        {"type": "scan", "desc": "Vulnerability scanning", "tool": "nuclei", "est_tokens": 500},
        {"type": "analyze", "desc": "Analyze scan results", "model": "hermes-14b", "est_tokens": 2000},
        {"type": "exploit", "desc": "Verify top findings", "model": "whiterabbitneo-7b", "est_tokens": 3000},
        {"type": "validate", "desc": "Cross-validate findings", "model": "qwen-coder-14b", "est_tokens": 2000},
        {"type": "report", "desc": "Generate report", "model": "hermes-14b", "est_tokens": 1500},
    ],
    "network_assessment": [
        {"type": "recon", "desc": "Fast port sweep", "tool": "masscan", "est_tokens": 200},
        {"type": "recon", "desc": "Service detection", "tool": "nmap", "est_tokens": 500},
        {"type": "scan", "desc": "Vulnerability scanning", "tool": "nuclei", "est_tokens": 500},
        {"type": "analyze", "desc": "Network analysis", "model": "deepseek-r1-7b", "est_tokens": 3000},
        {"type": "exploit", "desc": "Verify findings", "model": "whiterabbitneo-7b", "est_tokens": 3000},
        {"type": "validate", "desc": "Validate findings", "model": "hermes-14b", "est_tokens": 2000},
        {"type": "report", "desc": "Generate report", "model": "hermes-14b", "est_tokens": 1500},
    ],
    "code_audit": [
        {"type": "scan", "desc": "Static analysis with semgrep", "tool": "semgrep", "est_tokens": 300},
        {"type": "scan", "desc": "Dependency audit", "tool": "trivy", "est_tokens": 200},
        {"type": "analyze", "desc": "Code review", "model": "qwen-coder-14b", "est_tokens": 5000},
        {"type": "analyze", "desc": "Deep code analysis", "model": "yi-9b-200k", "est_tokens": 8000},
        {"type": "validate", "desc": "Validate findings", "model": "qwen-coder-7b", "est_tokens": 3000},
        {"type": "report", "desc": "Generate report", "model": "hermes-14b", "est_tokens": 1500},
    ],
}


class PlanningEngine:
    """Hierarchical task planning with replanning capabilities.

    Creates, monitors, and repairs plans for security assessments.
    """

    def __init__(self) -> None:
        self._plans: dict[str, Plan] = {}
        self._plan_counter = 0
        self._action_counter = 0
        self._log = logger.bind(component="planning_engine")

    def create_plan(
        self,
        goal: str,
        target: str = "",
        template: str = "",
        token_budget: int = 50000,
    ) -> Plan:
        """Create a new plan."""
        self._plan_counter += 1
        plan = Plan(
            plan_id=f"plan-{self._plan_counter}",
            goal=goal,
            target=target,
            token_budget=token_budget,
        )

        # Use template if provided
        if template and template in PLAN_TEMPLATES:
            for action_data in PLAN_TEMPLATES[template]:
                self._action_counter += 1
                action = PlanAction(
                    action_id=f"act-{self._action_counter}",
                    action_type=ActionType(action_data["type"]),
                    description=action_data["desc"],
                    tool=action_data.get("tool", ""),
                    model=action_data.get("model", ""),
                    target=target,
                    estimated_tokens=action_data.get("est_tokens", 500),
                )
                plan.actions.append(action)

            # Set dependencies (sequential)
            for i in range(1, len(plan.actions)):
                plan.actions[i].dependencies.append(plan.actions[i - 1].action_id)

        plan.status = PlanStatus.READY
        self._plans[plan.plan_id] = plan
        return plan

    def add_action(
        self,
        plan_id: str,
        action_type: ActionType,
        description: str,
        tool: str = "",
        model: str = "",
        target: str = "",
        estimated_tokens: int = 500,
        dependencies: list[str] | None = None,
    ) -> PlanAction | None:
        """Add an action to a plan."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        self._action_counter += 1
        action = PlanAction(
            action_id=f"act-{self._action_counter}",
            action_type=action_type,
            description=description,
            tool=tool,
            model=model,
            target=target or plan.target,
            estimated_tokens=estimated_tokens,
            dependencies=dependencies or [],
        )

        plan.actions.append(action)
        return action

    def get_next_action(self, plan_id: str) -> PlanAction | None:
        """Get the next executable action."""
        plan = self._plans.get(plan_id)
        if not plan or plan.status not in (PlanStatus.READY, PlanStatus.EXECUTING):
            return None

        plan.status = PlanStatus.EXECUTING
        if not plan.started_at:
            plan.started_at = time.time()

        for action in plan.actions:
            if action.status != ActionStatus.PENDING:
                continue

            # Check dependencies
            deps_met = True
            for dep_id in action.dependencies:
                dep = next(
                    (a for a in plan.actions if a.action_id == dep_id), None,
                )
                if dep and dep.status != ActionStatus.COMPLETED:
                    deps_met = False
                    break

            if deps_met:
                action.status = ActionStatus.EXECUTING
                return action

        return None

    def complete_action(
        self,
        plan_id: str,
        action_id: str,
        result: dict[str, Any],
        tokens_used: int = 0,
        success: bool = True,
    ) -> None:
        """Mark an action as completed."""
        plan = self._plans.get(plan_id)
        if not plan:
            return

        for action in plan.actions:
            if action.action_id == action_id:
                if success:
                    action.status = ActionStatus.COMPLETED
                else:
                    action.status = ActionStatus.FAILED
                action.result = result
                action.actual_tokens = tokens_used
                plan.tokens_used += tokens_used
                break

        # Check if plan is complete
        all_done = all(
            a.status in (ActionStatus.COMPLETED, ActionStatus.SKIPPED, ActionStatus.FAILED)
            for a in plan.actions
        )
        if all_done:
            plan.status = PlanStatus.COMPLETED
            plan.completed_at = time.time()

    def replan(
        self,
        plan_id: str,
        failed_action_id: str,
    ) -> Plan | None:
        """Replan after a failure."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        plan.replan_count += 1
        plan.status = PlanStatus.REPLANNING

        # Find failed action
        failed = next(
            (a for a in plan.actions if a.action_id == failed_action_id),
            None,
        )
        if not failed:
            return plan

        # Strategy 1: Use contingency
        if failed.contingency_action_id:
            contingency = next(
                (a for a in plan.actions if a.action_id == failed.contingency_action_id),
                None,
            )
            if contingency:
                contingency.status = ActionStatus.PENDING
                plan.status = PlanStatus.EXECUTING
                return plan

        # Strategy 2: Skip and continue
        failed.status = ActionStatus.SKIPPED
        plan.status = PlanStatus.EXECUTING

        # Unblock dependent actions
        for action in plan.actions:
            if failed_action_id in action.dependencies:
                action.dependencies.remove(failed_action_id)

        return plan

    def assess_quality(self, plan_id: str) -> dict[str, Any]:
        """Assess plan quality."""
        plan = self._plans.get(plan_id)
        if not plan:
            return {"error": "Plan not found"}

        coverage = set()
        for action in plan.actions:
            coverage.add(action.action_type.value)

        expected_coverage = {"recon", "scan", "analyze", "validate"}
        coverage_score = len(coverage & expected_coverage) / len(expected_coverage)

        total_estimated = sum(a.estimated_tokens for a in plan.actions)
        budget_fit = 1.0 - abs(total_estimated - plan.token_budget * 0.8) / plan.token_budget

        return {
            "coverage_score": round(coverage_score, 2),
            "budget_fit": round(max(0, budget_fit), 2),
            "action_count": len(plan.actions),
            "has_validation": any(a.action_type == ActionType.VALIDATE for a in plan.actions),
            "has_contingencies": len(plan.contingencies) > 0,
        }

    def get_stats(self) -> dict[str, Any]:
        statuses: dict[str, int] = defaultdict(int)
        for plan in self._plans.values():
            statuses[plan.status.value] += 1
        return {
            "total_plans": len(self._plans),
            "statuses": dict(statuses),
            "total_actions": self._action_counter,
        }
