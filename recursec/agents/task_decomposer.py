"""Task decomposer — breaks complex tasks into executable sub-tasks.

Implements:
1. Recursive task decomposition
2. Dependency graph between sub-tasks
3. Topological sort for execution order
4. Parallel task identification
5. Task estimation (tokens, time, complexity)
6. Template-based decomposition for common patterns
7. LLM-assisted decomposition for novel tasks
8. Budget allocation across sub-tasks
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"        # All dependencies met
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SubTask:
    """A sub-task in the decomposition."""
    task_id: str = ""
    name: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    depends_on: list[str] = field(default_factory=list)
    tool: str = ""
    model: str = ""
    strategy: str = ""
    target: str = ""
    estimated_tokens: int = 1000
    estimated_time_s: float = 60.0
    actual_tokens: int = 0
    actual_time_s: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def is_ready(self) -> bool:
        return self.status in (TaskStatus.PENDING, TaskStatus.READY)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id,
            "name": self.name[:30],
            "status": self.status.value,
            "priority": self.priority.value,
            "deps": len(self.depends_on),
            "children": len(self.children),
            "depth": self.depth,
        }


@dataclass
class TaskPlan:
    """A complete task decomposition plan."""
    plan_id: str = ""
    objective: str = ""
    tasks: list[SubTask] = field(default_factory=list)
    execution_order: list[list[str]] = field(default_factory=list)  # Batches of parallel tasks
    total_estimated_tokens: int = 0
    total_estimated_time_s: float = 0.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id,
            "objective": self.objective[:40],
            "tasks": len(self.tasks),
            "batches": len(self.execution_order),
            "est_tokens": self.total_estimated_tokens,
        }


# ── Decomposition Templates ──────────────────────────────────

DECOMPOSITION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"name": "dns_recon", "tool": "subfinder", "priority": "high", "deps": [], "tokens": 500, "time": 30},
        {"name": "port_scan", "tool": "nmap", "priority": "high", "deps": [], "tokens": 1000, "time": 60},
        {"name": "tech_detect", "tool": "httpx", "priority": "high", "deps": ["dns_recon"], "tokens": 500, "time": 30},
        {"name": "dir_scan", "tool": "gobuster", "priority": "medium", "deps": ["tech_detect"], "tokens": 500, "time": 120},
        {"name": "vuln_scan", "tool": "nuclei", "priority": "high", "deps": ["tech_detect"], "tokens": 2000, "time": 180},
        {"name": "tls_check", "tool": "testssl", "priority": "medium", "deps": ["port_scan"], "tokens": 500, "time": 30},
        {"name": "web_vuln_check", "strategy": "business_logic_analysis", "priority": "high", "deps": ["dir_scan", "vuln_scan"], "tokens": 5000, "time": 300},
        {"name": "analyze_results", "model": "qwen-coder-14b", "priority": "high", "deps": ["web_vuln_check", "tls_check"], "tokens": 3000, "time": 60},
        {"name": "validate_findings", "model": "deepseek-r1", "priority": "critical", "deps": ["analyze_results"], "tokens": 2000, "time": 60},
    ],
    "web_app_scan": [
        {"name": "tech_fingerprint", "tool": "httpx", "priority": "high", "deps": [], "tokens": 500, "time": 20},
        {"name": "dir_brute", "tool": "gobuster", "priority": "medium", "deps": ["tech_fingerprint"], "tokens": 500, "time": 120},
        {"name": "api_discovery", "tool": "ffuf", "priority": "medium", "deps": ["tech_fingerprint"], "tokens": 500, "time": 120},
        {"name": "vuln_scan", "tool": "nuclei", "priority": "high", "deps": ["tech_fingerprint"], "tokens": 2000, "time": 120},
        {"name": "sqli_check", "tool": "sqlmap", "priority": "high", "deps": ["dir_brute", "api_discovery"], "tokens": 2000, "time": 300},
        {"name": "xss_check", "strategy": "classic_vuln_scanning", "priority": "medium", "deps": ["dir_brute"], "tokens": 1000, "time": 120},
        {"name": "business_logic", "strategy": "business_logic_analysis", "priority": "high", "deps": ["vuln_scan"], "tokens": 5000, "time": 300},
    ],
    "network_scan": [
        {"name": "host_discovery", "tool": "nmap", "priority": "critical", "deps": [], "tokens": 500, "time": 60},
        {"name": "port_scan_tcp", "tool": "nmap", "priority": "high", "deps": ["host_discovery"], "tokens": 1000, "time": 120},
        {"name": "port_scan_udp", "tool": "nmap", "priority": "medium", "deps": ["host_discovery"], "tokens": 1000, "time": 300},
        {"name": "service_enum", "tool": "nmap", "priority": "high", "deps": ["port_scan_tcp"], "tokens": 1000, "time": 120},
        {"name": "vuln_scan", "tool": "nuclei", "priority": "high", "deps": ["service_enum"], "tokens": 2000, "time": 180},
        {"name": "brute_force", "tool": "hydra", "priority": "medium", "deps": ["service_enum"], "tokens": 500, "time": 600},
        {"name": "smb_enum", "tool": "crackmapexec", "priority": "medium", "deps": ["service_enum"], "tokens": 500, "time": 60},
    ],
    "api_assessment": [
        {"name": "schema_discovery", "strategy": "hidden_attack_surface_discovery", "priority": "high", "deps": [], "tokens": 2000, "time": 60},
        {"name": "auth_test", "strategy": "business_logic_analysis", "priority": "critical", "deps": ["schema_discovery"], "tokens": 3000, "time": 120},
        {"name": "injection_test", "tool": "sqlmap", "priority": "high", "deps": ["schema_discovery"], "tokens": 2000, "time": 180},
        {"name": "rate_limit_test", "strategy": "timing_race_condition_testing", "priority": "medium", "deps": ["schema_discovery"], "tokens": 1000, "time": 60},
        {"name": "bola_idor_test", "strategy": "business_logic_analysis", "priority": "critical", "deps": ["auth_test"], "tokens": 3000, "time": 120},
    ],
}


class TaskDecomposer:
    """Decomposes complex tasks into executable sub-tasks.

    Uses templates for common patterns and generates dependency
    graphs for parallel execution.
    """

    def __init__(self) -> None:
        self._plans: dict[str, TaskPlan] = {}
        self._tasks: dict[str, SubTask] = {}
        self._plan_counter = 0
        self._task_counter = 0
        self._log = logger.bind(component="task_decomposer")

    def decompose(
        self,
        objective: str,
        template: str = "",
        target: str = "",
        token_budget: int = 50000,
    ) -> TaskPlan:
        """Decompose an objective into sub-tasks."""
        self._plan_counter += 1

        # Select template
        if not template:
            template = self._match_template(objective)

        template_data = DECOMPOSITION_TEMPLATES.get(
            template, DECOMPOSITION_TEMPLATES["full_assessment"]
        )

        # Create tasks from template
        tasks = []
        task_id_map: dict[str, str] = {}

        for t in template_data:
            self._task_counter += 1
            task_id = f"task-{self._task_counter}"
            task_id_map[t["name"]] = task_id

            task = SubTask(
                task_id=task_id,
                name=t["name"],
                description=f"{t['name']} for {objective}",
                priority=TaskPriority(t.get("priority", "medium")),
                tool=t.get("tool", ""),
                model=t.get("model", ""),
                strategy=t.get("strategy", ""),
                target=target,
                estimated_tokens=t.get("tokens", 1000),
                estimated_time_s=t.get("time", 60),
            )
            tasks.append(task)
            self._tasks[task_id] = task

        # Resolve dependencies
        for i, t in enumerate(template_data):
            task = tasks[i]
            for dep_name in t.get("deps", []):
                dep_id = task_id_map.get(dep_name, "")
                if dep_id:
                    task.depends_on.append(dep_id)

        # Topological sort for execution order
        execution_order = self._topological_sort(tasks)

        # Scale token estimates to budget
        total_est = sum(t.estimated_tokens for t in tasks)
        if total_est > token_budget:
            scale = token_budget / total_est
            for task in tasks:
                task.estimated_tokens = int(task.estimated_tokens * scale)

        plan = TaskPlan(
            plan_id=f"plan-{self._plan_counter}",
            objective=objective,
            tasks=tasks,
            execution_order=execution_order,
            total_estimated_tokens=sum(t.estimated_tokens for t in tasks),
            total_estimated_time_s=sum(t.estimated_time_s for t in tasks),
        )
        self._plans[plan.plan_id] = plan

        return plan

    def get_ready_tasks(self, plan_id: str) -> list[SubTask]:
        """Get tasks that are ready to execute (all deps complete)."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        ready = []
        for task in plan.tasks:
            if task.status != TaskStatus.PENDING:
                continue

            deps_met = all(
                self._tasks.get(dep, SubTask()).status == TaskStatus.COMPLETE
                for dep in task.depends_on
            )
            if deps_met:
                task.status = TaskStatus.READY
                ready.append(task)

        return ready

    def start_task(self, task_id: str) -> SubTask | None:
        """Mark a task as running."""
        task = self._tasks.get(task_id)
        if not task:
            return None
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()
        return task

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any] | None = None,
        tokens_used: int = 0,
    ) -> SubTask | None:
        """Mark a task as complete."""
        task = self._tasks.get(task_id)
        if not task:
            return None
        task.status = TaskStatus.COMPLETE
        task.completed_at = time.time()
        task.actual_time_s = task.completed_at - task.started_at
        task.actual_tokens = tokens_used
        task.result = result or {}
        return task

    def fail_task(
        self,
        task_id: str,
        error: str = "",
    ) -> SubTask | None:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if not task:
            return None
        task.status = TaskStatus.FAILED
        task.completed_at = time.time()
        task.result = {"error": error}
        return task

    @staticmethod
    def _topological_sort(tasks: list[SubTask]) -> list[list[str]]:
        """Sort tasks into batches respecting dependencies."""
        # Build dependency graph
        in_degree: dict[str, int] = {}
        dependents: dict[str, list[str]] = defaultdict(list)

        for task in tasks:
            in_degree[task.task_id] = len(task.depends_on)
            for dep in task.depends_on:
                dependents[dep].append(task.task_id)

        # BFS by layers (each layer = parallel batch)
        batches: list[list[str]] = []
        queue: deque[str] = deque(
            tid for tid, deg in in_degree.items() if deg == 0
        )

        while queue:
            batch = []
            next_queue: deque[str] = deque()

            while queue:
                tid = queue.popleft()
                batch.append(tid)

                for dep_tid in dependents.get(tid, []):
                    in_degree[dep_tid] -= 1
                    if in_degree[dep_tid] == 0:
                        next_queue.append(dep_tid)

            if batch:
                batches.append(batch)
            queue = next_queue

        return batches

    @staticmethod
    def _match_template(objective: str) -> str:
        """Match an objective to the best template."""
        obj_lower = objective.lower()

        if any(kw in obj_lower for kw in ("api", "graphql", "grpc", "rest")):
            return "api_assessment"
        if any(kw in obj_lower for kw in ("web", "webapp", "website", "http")):
            return "web_app_scan"
        if any(kw in obj_lower for kw in ("network", "subnet", "cidr", "ip range")):
            return "network_scan"

        return "full_assessment"

    def generate_decomposition_prompt(
        self,
        objective: str,
        context: str = "",
    ) -> str:
        """Generate a prompt for LLM-assisted task decomposition."""
        return (
            f"Decompose this security assessment objective into sub-tasks:\n"
            f"Objective: {objective}\n"
            f"{f'Context: {context}' if context else ''}\n\n"
            f"For each sub-task, specify:\n"
            f"1. Name (short identifier)\n"
            f"2. Tool to use (nmap, nuclei, sqlmap, etc.) or 'llm' for analysis\n"
            f"3. Dependencies (which tasks must complete first)\n"
            f"4. Priority (critical/high/medium/low)\n"
            f"5. Estimated time (seconds)\n\n"
            f"Consider: recon → scanning → analysis → exploitation → validation\n"
            f"Maximize parallelism where possible.\n"
        )

    def get_plan(self, plan_id: str) -> TaskPlan | None:
        return self._plans.get(plan_id)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for task in self._tasks.values():
            status_counts[task.status.value] += 1
        return {
            "plans": len(self._plans),
            "tasks": len(self._tasks),
            "by_status": dict(status_counts),
        }
