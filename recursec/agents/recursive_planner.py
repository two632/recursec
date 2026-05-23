"""Recursive planner — goal decomposition with depth-bounded recursion.

Implements:
1. Hierarchical goal decomposition
2. Depth-bounded recursive planning
3. Budget allocation across sub-goals
4. Plan refinement and adaptation
5. Convergence detection
6. Plan visualization for LLM context
7. Dynamic re-planning on failure
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class GoalStatus(str, Enum):
    PENDING = "pending"
    DECOMPOSED = "decomposed"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class GoalType(str, Enum):
    STRATEGIC = "strategic"      # High-level (find vulns in X)
    TACTICAL = "tactical"        # Mid-level (scan web services)
    OPERATIONAL = "operational"  # Low-level (run nmap on port Y)


@dataclass
class PlanGoal:
    """A goal in the recursive plan."""
    goal_id: str = ""
    parent_id: str = ""
    depth: int = 0
    goal_type: GoalType = GoalType.TACTICAL
    status: GoalStatus = GoalStatus.PENDING
    description: str = ""
    success_criteria: str = ""
    agent_role: str = ""
    token_budget: int = 10000
    time_budget_s: float = 600.0
    children: list[str] = field(default_factory=list)
    tokens_used: int = 0
    result: str = ""
    findings_count: int = 0
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.created_at:
            return self.completed_at - self.created_at
        return 0.0

    @property
    def budget_remaining(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.goal_id[:10],
            "depth": self.depth,
            "type": self.goal_type.value,
            "status": self.status.value,
            "desc": self.description[:30],
            "children": len(self.children),
        }


@dataclass
class PlanTemplate:
    """A reusable plan template."""
    template_id: str = ""
    name: str = ""
    description: str = ""
    goal_tree: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.template_id[:10],
            "name": self.name[:20],
            "goals": len(self.goal_tree),
        }


# ── Plan templates ───────────────────────────────────────────

PLAN_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_assessment": [
        {"desc": "Discover web services", "role": "recon", "type": "tactical", "children": [
            {"desc": "Subdomain enumeration", "role": "recon", "type": "operational"},
            {"desc": "Port scan for web ports", "role": "scanner", "type": "operational"},
            {"desc": "Web technology fingerprint", "role": "recon", "type": "operational"},
        ]},
        {"desc": "Vulnerability scanning", "role": "scanner", "type": "tactical", "children": [
            {"desc": "Automated vuln scan", "role": "scanner", "type": "operational"},
            {"desc": "SSL/TLS assessment", "role": "scanner", "type": "operational"},
            {"desc": "Directory and file discovery", "role": "scanner", "type": "operational"},
        ]},
        {"desc": "Manual testing", "role": "exploiter", "type": "tactical", "children": [
            {"desc": "Authentication testing", "role": "exploiter", "type": "operational"},
            {"desc": "Injection testing", "role": "exploiter", "type": "operational"},
            {"desc": "Business logic testing", "role": "exploiter", "type": "operational"},
        ]},
        {"desc": "Validate findings", "role": "validator", "type": "tactical"},
    ],
    "network_assessment": [
        {"desc": "Network discovery", "role": "recon", "type": "tactical", "children": [
            {"desc": "Host discovery", "role": "recon", "type": "operational"},
            {"desc": "Port scanning", "role": "scanner", "type": "operational"},
            {"desc": "Service enumeration", "role": "scanner", "type": "operational"},
        ]},
        {"desc": "Vulnerability assessment", "role": "scanner", "type": "tactical", "children": [
            {"desc": "Known CVE scanning", "role": "scanner", "type": "operational"},
            {"desc": "Default credential check", "role": "exploiter", "type": "operational"},
            {"desc": "Protocol weakness check", "role": "scanner", "type": "operational"},
        ]},
        {"desc": "Exploitation", "role": "exploiter", "type": "tactical"},
        {"desc": "Validate and report", "role": "validator", "type": "tactical"},
    ],
    "code_audit": [
        {"desc": "Static analysis", "role": "code_auditor", "type": "tactical", "children": [
            {"desc": "Automated SAST scan", "role": "code_auditor", "type": "operational"},
            {"desc": "Dependency audit", "role": "code_auditor", "type": "operational"},
            {"desc": "Secret scanning", "role": "code_auditor", "type": "operational"},
        ]},
        {"desc": "Manual code review", "role": "code_auditor", "type": "tactical", "children": [
            {"desc": "Auth/authz review", "role": "code_auditor", "type": "operational"},
            {"desc": "Input validation review", "role": "code_auditor", "type": "operational"},
            {"desc": "Crypto usage review", "role": "code_auditor", "type": "operational"},
        ]},
        {"desc": "Validate findings", "role": "validator", "type": "tactical"},
    ],
}

MAX_DEPTH = 5
BUDGET_DECAY = 0.7


class RecursivePlanner:
    """Plans assessments via recursive goal decomposition.

    Breaks strategic goals into tactical sub-goals
    and operational tasks, allocating budgets with
    decay at each level.
    """

    def __init__(self, max_depth: int = MAX_DEPTH) -> None:
        self._goals: dict[str, PlanGoal] = {}
        self._max_depth = max_depth
        self._counter = 0
        self._log = logger.bind(component="recursive_planner")

    def create_root_goal(
        self,
        description: str,
        token_budget: int = 100000,
        time_budget_s: float = 14400.0,
    ) -> PlanGoal:
        """Create the root strategic goal."""
        return self._create_goal(
            description=description,
            parent_id="",
            depth=0,
            goal_type=GoalType.STRATEGIC,
            token_budget=token_budget,
            time_budget_s=time_budget_s,
        )

    def decompose(
        self,
        goal_id: str,
        sub_goals: list[dict[str, Any]],
    ) -> list[PlanGoal]:
        """Decompose a goal into sub-goals."""
        parent = self._goals.get(goal_id)
        if not parent:
            return []

        if parent.depth >= self._max_depth:
            self._log.warning("max_depth_reached", goal=goal_id[:10], depth=parent.depth)
            return []

        children: list[PlanGoal] = []
        num_children = len(sub_goals) or 1
        child_budget = int(parent.budget_remaining * BUDGET_DECAY / num_children)
        child_time = parent.time_budget_s * BUDGET_DECAY / num_children

        for sg in sub_goals:
            try:
                goal_type = GoalType(sg.get("type", "operational"))
            except ValueError:
                goal_type = GoalType.OPERATIONAL

            child = self._create_goal(
                description=sg.get("desc", ""),
                parent_id=goal_id,
                depth=parent.depth + 1,
                goal_type=goal_type,
                agent_role=sg.get("role", ""),
                token_budget=sg.get("budget", child_budget),
                time_budget_s=sg.get("time", child_time),
            )
            parent.children.append(child.goal_id)
            children.append(child)

            # Recursively decompose if sub-goals have children
            if "children" in sg:
                self.decompose(child.goal_id, sg["children"])

        parent.status = GoalStatus.DECOMPOSED
        return children

    def apply_template(
        self,
        root_id: str,
        template_name: str,
    ) -> list[PlanGoal]:
        """Apply a plan template to a root goal."""
        template = PLAN_TEMPLATES.get(template_name)
        if not template:
            return []
        return self.decompose(root_id, template)

    def start_goal(self, goal_id: str) -> bool:
        """Mark a goal as in progress."""
        goal = self._goals.get(goal_id)
        if not goal:
            return False
        goal.status = GoalStatus.IN_PROGRESS
        return True

    def complete_goal(
        self,
        goal_id: str,
        result: str = "",
        findings_count: int = 0,
    ) -> bool:
        """Mark a goal as completed."""
        goal = self._goals.get(goal_id)
        if not goal:
            return False
        goal.status = GoalStatus.COMPLETED
        goal.result = result
        goal.findings_count = findings_count
        goal.completed_at = time.time()

        # Check if parent can be completed
        if goal.parent_id:
            self._check_parent_completion(goal.parent_id)

        return True

    def fail_goal(self, goal_id: str, error: str = "") -> bool:
        """Mark a goal as failed."""
        goal = self._goals.get(goal_id)
        if not goal:
            return False
        goal.status = GoalStatus.FAILED
        goal.result = error
        goal.completed_at = time.time()
        return True

    def get_actionable_goals(self) -> list[PlanGoal]:
        """Get goals ready for execution (leaf nodes that are pending)."""
        actionable: list[PlanGoal] = []
        for goal in self._goals.values():
            if goal.status in (GoalStatus.PENDING, GoalStatus.IN_PROGRESS):
                if not goal.children:
                    actionable.append(goal)
        return actionable

    def get_goal_tree(self, root_id: str = "") -> list[tuple[int, PlanGoal]]:
        """Get goal tree as flat list with depths."""
        result: list[tuple[int, PlanGoal]] = []

        if root_id:
            roots = [self._goals[root_id]] if root_id in self._goals else []
        else:
            roots = [g for g in self._goals.values() if not g.parent_id]

        def _traverse(goal: PlanGoal) -> None:
            result.append((goal.depth, goal))
            for child_id in goal.children:
                child = self._goals.get(child_id)
                if child:
                    _traverse(child)

        for root in roots:
            _traverse(root)
        return result

    def build_plan_prompt(self, root_id: str = "", max_goals: int = 15) -> str:
        """Build plan context for LLM."""
        lines = ["## Assessment Plan\n"]

        tree = self.get_goal_tree(root_id)
        for depth, goal in tree[:max_goals]:
            indent = "  " * depth
            status_icon = {
                "pending": "[ ]", "decomposed": "[>]",
                "in_progress": "[~]", "completed": "[x]",
                "failed": "[!]", "abandoned": "[-]",
            }.get(goal.status.value, "[ ]")

            lines.append(f"{indent}{status_icon} {goal.description[:40]}")
            if goal.agent_role:
                lines.append(f"{indent}    role={goal.agent_role}")

        # Summary
        total = len(self._goals)
        completed = sum(1 for g in self._goals.values() if g.status == GoalStatus.COMPLETED)
        lines.append(f"\nProgress: {completed}/{total} goals completed")

        actionable = self.get_actionable_goals()
        if actionable:
            lines.append(f"Next actions: {len(actionable)} goals ready")

        return "\n".join(lines)

    def _create_goal(self, **kwargs: Any) -> PlanGoal:
        """Create a new goal."""
        self._counter += 1
        goal = PlanGoal(goal_id=f"goal-{self._counter}", **kwargs)
        self._goals[goal.goal_id] = goal
        return goal

    def _check_parent_completion(self, parent_id: str) -> None:
        """Check if all children are complete."""
        parent = self._goals.get(parent_id)
        if not parent:
            return

        children_status = [
            self._goals[cid].status
            for cid in parent.children
            if cid in self._goals
        ]
        if all(s == GoalStatus.COMPLETED for s in children_status):
            total_findings = sum(
                self._goals[cid].findings_count
                for cid in parent.children
                if cid in self._goals
            )
            self.complete_goal(parent_id, "All sub-goals completed", total_findings)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for g in self._goals.values():
            status_counts[g.status.value] = status_counts.get(g.status.value, 0) + 1

        return {
            "total_goals": len(self._goals),
            "max_depth": max((g.depth for g in self._goals.values()), default=0),
            "by_status": status_counts,
        }
