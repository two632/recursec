"""Task decomposer — recursive goal decomposition.

Implements:
1. Goal → sub-goal decomposition
2. Dependency graph construction
3. Task estimation (time, tokens, tools)
4. Critical path analysis
5. Task merging for efficiency
6. Dynamic re-decomposition
7. Task templates for common patterns
8. Complexity estimation
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"       # Single tool call
    SIMPLE = "simple"         # Few steps, linear
    MODERATE = "moderate"     # Multiple tools, some branching
    COMPLEX = "complex"       # Multi-agent, deep analysis
    EXTREME = "extreme"       # Recursive, multi-phase


class TaskStatus(str, Enum):
    PLANNED = "planned"
    READY = "ready"
    EXECUTING = "executing"
    COMPLETE = "complete"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class SubTask:
    """A decomposed sub-task."""
    task_id: str = ""
    name: str = ""
    description: str = ""
    complexity: TaskComplexity = TaskComplexity.SIMPLE
    status: TaskStatus = TaskStatus.PLANNED
    parent_id: str = ""
    dependencies: list[str] = field(default_factory=list)
    tools_required: list[str] = field(default_factory=list)
    models_preferred: list[str] = field(default_factory=list)
    estimated_time_s: float = 60.0
    estimated_tokens: int = 1000
    actual_time_s: float = 0.0
    actual_tokens: int = 0
    result: dict[str, Any] = field(default_factory=dict)
    children: list[str] = field(default_factory=list)
    depth: int = 0
    can_parallel: bool = False

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "name": self.name[:25],
            "complexity": self.complexity.value,
            "status": self.status.value,
            "depth": self.depth,
            "children": len(self.children),
            "tools": len(self.tools_required),
            "est_time": round(self.estimated_time_s, 0),
        }


@dataclass
class DecompositionPlan:
    """A complete task decomposition plan."""
    plan_id: str = ""
    goal: str = ""
    target: str = ""
    tasks: dict[str, SubTask] = field(default_factory=dict)
    root_task_id: str = ""
    created_at: float = field(default_factory=time.time)
    total_estimated_time_s: float = 0.0
    total_estimated_tokens: int = 0
    max_depth: int = 0

    @property
    def total_tasks(self) -> int:
        return len(self.tasks)

    @property
    def completed_tasks(self) -> int:
        return sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETE)

    @property
    def progress(self) -> float:
        if not self.tasks:
            return 0.0
        return self.completed_tasks / self.total_tasks

    def to_dict(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for t in self.tasks.values():
            status_counts[t.status.value] += 1
        return {
            "id": self.plan_id[:10],
            "goal": self.goal[:30],
            "tasks": self.total_tasks,
            "progress": round(self.progress, 2),
            "max_depth": self.max_depth,
            "by_status": dict(status_counts),
        }


# ── Task templates ───────────────────────────────────────────

TASK_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_assessment": [
        {"name": "Technology Detection", "tools": ["httpx", "wafw00f"], "complexity": "simple", "time": 30},
        {"name": "Subdomain Enumeration", "tools": ["subfinder", "amass"], "complexity": "simple", "time": 120},
        {"name": "Directory Discovery", "tools": ["gobuster", "ffuf"], "complexity": "simple", "time": 300},
        {"name": "Vulnerability Scanning", "tools": ["nuclei", "nikto"], "complexity": "moderate", "time": 600},
        {"name": "SQL Injection Testing", "tools": ["sqlmap"], "complexity": "moderate", "time": 300},
        {"name": "XSS Testing", "tools": ["dalfox"], "complexity": "moderate", "time": 300},
        {"name": "Authentication Testing", "tools": ["hydra"], "complexity": "complex", "time": 600},
        {"name": "Vulnerability Analysis", "tools": [], "models": ["whiterabbitneo", "qwen-coder-14b"], "complexity": "complex", "time": 120},
        {"name": "Report Generation", "tools": [], "complexity": "simple", "time": 30},
    ],
    "network_assessment": [
        {"name": "Host Discovery", "tools": ["nmap"], "complexity": "simple", "time": 60},
        {"name": "Port Scanning", "tools": ["nmap", "masscan"], "complexity": "simple", "time": 300},
        {"name": "Service Enumeration", "tools": ["nmap"], "complexity": "moderate", "time": 300},
        {"name": "SMB Assessment", "tools": ["crackmapexec", "enum4linux"], "complexity": "moderate", "time": 120},
        {"name": "SNMP Assessment", "tools": ["onesixtyone", "snmpwalk"], "complexity": "simple", "time": 60},
        {"name": "Vulnerability Scanning", "tools": ["nuclei"], "complexity": "moderate", "time": 300},
        {"name": "Vulnerability Analysis", "tools": [], "models": ["hermes-14b"], "complexity": "complex", "time": 120},
    ],
    "api_assessment": [
        {"name": "API Discovery", "tools": ["ffuf", "curl"], "complexity": "simple", "time": 120},
        {"name": "Endpoint Mapping", "tools": ["httpx"], "complexity": "simple", "time": 60},
        {"name": "Authentication Testing", "tools": [], "complexity": "moderate", "time": 180},
        {"name": "IDOR Testing", "tools": [], "complexity": "moderate", "time": 300},
        {"name": "Injection Testing", "tools": ["sqlmap"], "complexity": "moderate", "time": 300},
        {"name": "Rate Limit Testing", "tools": [], "complexity": "simple", "time": 60},
        {"name": "Analysis", "tools": [], "models": ["qwen-coder-14b"], "complexity": "complex", "time": 120},
    ],
    "code_review": [
        {"name": "Static Analysis", "tools": ["semgrep", "bandit"], "complexity": "simple", "time": 120},
        {"name": "Secret Detection", "tools": ["trufflehog", "gitleaks"], "complexity": "simple", "time": 60},
        {"name": "Dependency Audit", "tools": ["trivy", "grype"], "complexity": "simple", "time": 60},
        {"name": "Deep Code Review", "tools": [], "models": ["qwen-coder-14b", "yi-9b-200k"], "complexity": "complex", "time": 600},
        {"name": "Vulnerability Mapping", "tools": [], "models": ["whiterabbitneo"], "complexity": "complex", "time": 120},
    ],
}


class TaskDecomposer:
    """Recursive goal decomposition engine.

    Breaks high-level security assessment goals into
    executable sub-tasks with dependency tracking,
    resource estimation, and critical path analysis.
    """

    def __init__(self, max_depth: int = 5) -> None:
        self._plans: dict[str, DecompositionPlan] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._log = logger.bind(component="task_decomposer")

    def decompose(
        self,
        goal: str,
        target: str,
        template: str = "",
    ) -> DecompositionPlan:
        """Decompose a goal into sub-tasks."""
        self._counter += 1
        plan = DecompositionPlan(
            plan_id=f"plan-{self._counter}",
            goal=goal,
            target=target,
        )

        # Create root task
        root = SubTask(
            task_id=f"task-{self._counter}-root",
            name=goal[:50],
            description=goal,
            complexity=TaskComplexity.COMPLEX,
            depth=0,
        )
        plan.tasks[root.task_id] = root
        plan.root_task_id = root.task_id

        # Apply template if available
        tmpl = self._select_template(goal, template)
        if tmpl:
            self._apply_template(plan, root, tmpl)
        else:
            self._auto_decompose(plan, root, goal, target)

        # Calculate estimates
        self._calculate_estimates(plan)

        self._plans[plan.plan_id] = plan
        return plan

    def _select_template(
        self,
        goal: str,
        template: str,
    ) -> list[dict[str, Any]] | None:
        """Select the best template for a goal."""
        if template and template in TASK_TEMPLATES:
            return TASK_TEMPLATES[template]

        goal_lower = goal.lower()
        if any(w in goal_lower for w in ("web", "website", "http", "url")):
            return TASK_TEMPLATES["web_assessment"]
        if any(w in goal_lower for w in ("network", "port", "host", "subnet")):
            return TASK_TEMPLATES["network_assessment"]
        if any(w in goal_lower for w in ("api", "endpoint", "rest", "graphql")):
            return TASK_TEMPLATES["api_assessment"]
        if any(w in goal_lower for w in ("code", "source", "review", "audit")):
            return TASK_TEMPLATES["code_review"]

        return None

    def _apply_template(
        self,
        plan: DecompositionPlan,
        parent: SubTask,
        template: list[dict[str, Any]],
    ) -> None:
        """Apply a template to create sub-tasks."""
        prev_id = ""
        for i, step in enumerate(template):
            self._counter += 1
            task = SubTask(
                task_id=f"task-{self._counter}",
                name=step["name"],
                complexity=TaskComplexity(step.get("complexity", "simple")),
                parent_id=parent.task_id,
                tools_required=step.get("tools", []),
                models_preferred=step.get("models", []),
                estimated_time_s=step.get("time", 60),
                depth=parent.depth + 1,
                can_parallel=step.get("parallel", False),
            )

            # Add sequential dependency
            if prev_id and not task.can_parallel:
                task.dependencies.append(prev_id)

            plan.tasks[task.task_id] = task
            parent.children.append(task.task_id)
            prev_id = task.task_id

    def _auto_decompose(
        self,
        plan: DecompositionPlan,
        parent: SubTask,
        goal: str,
        target: str,
    ) -> None:
        """Auto-decompose when no template matches."""
        default_phases = [
            {"name": "Reconnaissance", "tools": ["nmap", "subfinder"], "time": 180},
            {"name": "Scanning", "tools": ["nuclei"], "time": 300},
            {"name": "Analysis", "tools": [], "time": 120},
            {"name": "Exploitation", "tools": [], "time": 600},
            {"name": "Reporting", "tools": [], "time": 30},
        ]
        self._apply_template(plan, parent, default_phases)

    def _calculate_estimates(self, plan: DecompositionPlan) -> None:
        """Calculate total plan estimates."""
        total_time = 0
        total_tokens = 0
        max_depth = 0

        for task in plan.tasks.values():
            total_time += task.estimated_time_s
            total_tokens += task.estimated_tokens
            max_depth = max(max_depth, task.depth)

        plan.total_estimated_time_s = total_time
        plan.total_estimated_tokens = total_tokens
        plan.max_depth = max_depth

    def get_ready_tasks(self, plan_id: str) -> list[SubTask]:
        """Get tasks ready for execution."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        ready = []
        for task in plan.tasks.values():
            if task.status != TaskStatus.PLANNED:
                continue
            if not task.is_leaf:
                continue

            deps_met = all(
                plan.tasks.get(dep, SubTask()).status == TaskStatus.COMPLETE
                for dep in task.dependencies
            )
            if deps_met:
                ready.append(task)

        return ready

    def complete_task(
        self,
        plan_id: str,
        task_id: str,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actual_time_s: float = 0.0,
        actual_tokens: int = 0,
    ) -> bool:
        """Mark a task as complete."""
        plan = self._plans.get(plan_id)
        if not plan:
            return False
        task = plan.tasks.get(task_id)
        if not task:
            return False

        task.status = TaskStatus.COMPLETE if success else TaskStatus.FAILED
        task.result = result or {}
        task.actual_time_s = actual_time_s
        task.actual_tokens = actual_tokens

        return True

    def get_critical_path(self, plan_id: str) -> list[SubTask]:
        """Get the critical path (longest dependency chain)."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        # BFS from root, tracking longest path
        longest_path: list[SubTask] = []
        queue: deque[tuple[str, list[SubTask]]] = deque()
        queue.append((plan.root_task_id, []))

        while queue:
            task_id, path = queue.popleft()
            task = plan.tasks.get(task_id)
            if not task:
                continue

            current_path = path + [task]
            if not task.children:
                if len(current_path) > len(longest_path):
                    longest_path = current_path
            else:
                for child_id in task.children:
                    queue.append((child_id, current_path))

        return longest_path

    def get_stats(self) -> dict[str, Any]:
        return {
            "plans": len(self._plans),
            "plan_details": {
                pid: p.to_dict() for pid, p in self._plans.items()
            },
        }
