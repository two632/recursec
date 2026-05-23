"""Recursive task decomposer — breaks complex tasks into sub-tasks recursively.

Core to the recursive multi-agent architecture. Implements:
1. HTN-style hierarchical task decomposition
2. Depth-bounded recursive splitting
3. Sub-task dependency resolution
4. Parallel sub-task identification
5. Result aggregation from sub-tasks
6. Decomposition strategy selection
7. Base case detection (when to stop splitting)
8. Context inheritance for sub-tasks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"      # Single action, no decomposition
    SIMPLE = "simple"        # 2-3 steps
    MODERATE = "moderate"    # 4-8 steps, some parallelism
    COMPLEX = "complex"      # 9+ steps, deep decomposition
    RECURSIVE = "recursive"  # Needs recursive sub-agent spawning


class DecompStrategy(str, Enum):
    SEQUENTIAL = "sequential"     # One after another
    PARALLEL = "parallel"         # All at once
    MIXED = "mixed"               # Some parallel, some sequential
    DIVIDE_CONQUER = "divide_conquer"  # Split target space
    PIPELINE = "pipeline"         # Output of one feeds next
    ITERATIVE = "iterative"       # Repeat until convergence


class SubTaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    DELEGATED = "delegated"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    AGGREGATED = "aggregated"


@dataclass
class SubTask:
    """A sub-task produced by decomposition."""
    task_id: str = ""
    parent_id: str = ""
    title: str = ""
    description: str = ""
    task_type: str = ""          # recon, scan, analyze, exploit, validate
    target: str = ""
    assigned_role: str = ""
    assigned_model: str = ""
    tools: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    status: SubTaskStatus = SubTaskStatus.PENDING
    depth: int = 0
    estimated_tokens: int = 500
    result: dict[str, Any] = field(default_factory=dict)
    children: list[str] = field(default_factory=list)

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def is_ready(self) -> bool:
        return self.status == SubTaskStatus.READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id,
            "parent": self.parent_id[:15],
            "title": self.title[:30],
            "type": self.task_type[:10],
            "status": self.status.value,
            "depth": self.depth,
            "children": len(self.children),
            "deps": len(self.dependencies),
        }


@dataclass
class DecompositionResult:
    """Result of decomposing a task."""
    root_task_id: str = ""
    strategy: DecompStrategy = DecompStrategy.SEQUENTIAL
    sub_tasks: list[SubTask] = field(default_factory=list)
    max_depth: int = 0
    total_estimated_tokens: int = 0
    parallel_groups: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root_task_id[:15],
            "strategy": self.strategy.value,
            "tasks": len(self.sub_tasks),
            "max_depth": self.max_depth,
            "est_tokens": self.total_estimated_tokens,
            "parallel_groups": len(self.parallel_groups),
        }


# ── Decomposition Templates ──────────────────────────────────

DECOMP_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"title": "Scope validation", "type": "validate", "role": "coordinator",
         "tools": ["nmap"], "tokens": 300},
        {"title": "Subdomain enumeration", "type": "recon", "role": "recon",
         "tools": ["subfinder", "amass"], "tokens": 500, "parallel_group": 0},
        {"title": "Port scanning", "type": "recon", "role": "recon",
         "tools": ["nmap", "masscan"], "tokens": 500, "parallel_group": 0},
        {"title": "Technology fingerprinting", "type": "recon", "role": "recon",
         "tools": ["whatweb", "httpx"], "tokens": 300, "parallel_group": 0},
        {"title": "Vulnerability scanning", "type": "scan", "role": "scanner",
         "tools": ["nuclei", "nikto"], "tokens": 800, "deps": ["Port scanning"]},
        {"title": "Directory enumeration", "type": "scan", "role": "scanner",
         "tools": ["ffuf", "feroxbuster"], "tokens": 600, "parallel_group": 1},
        {"title": "Parameter discovery", "type": "scan", "role": "scanner",
         "tools": ["arjun"], "tokens": 400, "parallel_group": 1},
        {"title": "Analyze findings", "type": "analyze", "role": "analyzer",
         "model": "hermes-14b", "tokens": 3000,
         "deps": ["Vulnerability scanning", "Directory enumeration"]},
        {"title": "Deep code review", "type": "analyze", "role": "analyzer",
         "model": "qwen-coder-14b", "tokens": 5000},
        {"title": "Exploit verification", "type": "exploit", "role": "exploiter",
         "model": "whiterabbitneo-7b", "tokens": 4000, "deps": ["Analyze findings"]},
        {"title": "Cross-validate findings", "type": "validate", "role": "validator",
         "model": "deepseek-r1-7b", "tokens": 3000, "deps": ["Exploit verification"]},
        {"title": "Generate report", "type": "report", "role": "reporter",
         "model": "hermes-14b", "tokens": 2000, "deps": ["Cross-validate findings"]},
    ],
    "quick_scan": [
        {"title": "Port scan", "type": "recon", "role": "recon",
         "tools": ["nmap"], "tokens": 300},
        {"title": "Vuln scan", "type": "scan", "role": "scanner",
         "tools": ["nuclei"], "tokens": 500, "deps": ["Port scan"]},
        {"title": "Analyze", "type": "analyze", "role": "analyzer",
         "model": "hermes-14b", "tokens": 2000, "deps": ["Vuln scan"]},
        {"title": "Report", "type": "report", "role": "reporter",
         "model": "hermes-14b", "tokens": 1000, "deps": ["Analyze"]},
    ],
    "code_audit": [
        {"title": "Static analysis", "type": "scan", "role": "scanner",
         "tools": ["semgrep", "bandit"], "tokens": 500, "parallel_group": 0},
        {"title": "Dependency audit", "type": "scan", "role": "scanner",
         "tools": ["trivy", "grype"], "tokens": 300, "parallel_group": 0},
        {"title": "Manual code review", "type": "analyze", "role": "analyzer",
         "model": "qwen-coder-14b", "tokens": 6000,
         "deps": ["Static analysis"]},
        {"title": "Deep pattern analysis", "type": "analyze", "role": "analyzer",
         "model": "yi-9b-200k", "tokens": 8000,
         "deps": ["Static analysis"]},
        {"title": "Validate findings", "type": "validate", "role": "validator",
         "model": "deepseek-r1-7b", "tokens": 3000,
         "deps": ["Manual code review", "Deep pattern analysis"]},
        {"title": "Report", "type": "report", "role": "reporter",
         "model": "hermes-14b", "tokens": 1500, "deps": ["Validate findings"]},
    ],
    "recon_only": [
        {"title": "Subdomain enum", "type": "recon", "role": "recon",
         "tools": ["subfinder"], "tokens": 300, "parallel_group": 0},
        {"title": "Port scan", "type": "recon", "role": "recon",
         "tools": ["nmap"], "tokens": 400, "parallel_group": 0},
        {"title": "DNS enumeration", "type": "recon", "role": "recon",
         "tools": ["dnsx"], "tokens": 200, "parallel_group": 0},
        {"title": "Web probe", "type": "recon", "role": "recon",
         "tools": ["httpx"], "tokens": 200, "parallel_group": 0},
        {"title": "Tech fingerprint", "type": "recon", "role": "recon",
         "tools": ["whatweb"], "tokens": 200},
        {"title": "Compile recon report", "type": "analyze", "role": "analyzer",
         "model": "hermes-14b", "tokens": 2000,
         "deps": ["Subdomain enum", "Port scan", "DNS enumeration", "Web probe"]},
    ],
}


class RecursiveDecomposer:
    """Breaks complex tasks into sub-tasks recursively.

    Core of the recursive multi-agent architecture — determines
    what gets delegated, to whom, and in what order.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_sub_tasks: int = 50,
    ) -> None:
        self._tasks: dict[str, SubTask] = {}
        self._task_counter = 0
        self._max_depth = max_depth
        self._max_sub_tasks = max_sub_tasks
        self._log = logger.bind(component="recursive_decomposer")

    def decompose(
        self,
        goal: str,
        target: str = "",
        template: str = "",
        context: dict[str, Any] | None = None,
        depth: int = 0,
    ) -> DecompositionResult:
        """Decompose a task into sub-tasks."""
        # Create root task
        self._task_counter += 1
        root = SubTask(
            task_id=f"dt-{self._task_counter}",
            title=goal,
            target=target,
            context=context or {},
            depth=depth,
        )
        self._tasks[root.task_id] = root

        # Select template
        template_name = template or self._select_template(goal)
        template_data = DECOMP_TEMPLATES.get(template_name, DECOMP_TEMPLATES["quick_scan"])

        # Create sub-tasks from template
        sub_tasks = []
        task_id_map: dict[str, str] = {}
        parallel_groups: dict[int, list[str]] = defaultdict(list)

        for step in template_data:
            self._task_counter += 1
            task = SubTask(
                task_id=f"dt-{self._task_counter}",
                parent_id=root.task_id,
                title=step["title"],
                task_type=step.get("type", ""),
                target=target,
                assigned_role=step.get("role", ""),
                assigned_model=step.get("model", ""),
                tools=step.get("tools", []),
                depth=depth + 1,
                estimated_tokens=step.get("tokens", 500),
                context=context or {},
            )

            # Track for dependency resolution
            task_id_map[step["title"]] = task.task_id

            # Parallel group
            if "parallel_group" in step:
                parallel_groups[step["parallel_group"]].append(task.task_id)

            sub_tasks.append(task)
            self._tasks[task.task_id] = task
            root.children.append(task.task_id)

        # Resolve dependencies
        for step, task in zip(template_data, sub_tasks):
            for dep_title in step.get("deps", []):
                dep_id = task_id_map.get(dep_title)
                if dep_id:
                    task.dependencies.append(dep_id)

        # Mark ready tasks (no dependencies)
        for task in sub_tasks:
            if not task.dependencies:
                task.status = SubTaskStatus.READY

        # Determine strategy
        strategy = self._determine_strategy(sub_tasks, parallel_groups)

        total_tokens = sum(t.estimated_tokens for t in sub_tasks)

        return DecompositionResult(
            root_task_id=root.task_id,
            strategy=strategy,
            sub_tasks=sub_tasks,
            max_depth=depth + 1,
            total_estimated_tokens=total_tokens,
            parallel_groups=[list(g) for g in parallel_groups.values()],
        )

    def complete_sub_task(
        self,
        task_id: str,
        result: dict[str, Any],
        success: bool = True,
    ) -> list[SubTask]:
        """Mark a sub-task as complete and unblock dependents."""
        task = self._tasks.get(task_id)
        if not task:
            return []

        task.status = SubTaskStatus.COMPLETED if success else SubTaskStatus.FAILED
        task.result = result

        # Unblock dependent tasks
        newly_ready = []
        for other in self._tasks.values():
            if task_id in other.dependencies:
                other.dependencies.remove(task_id)
                if not other.dependencies and other.status == SubTaskStatus.PENDING:
                    other.status = SubTaskStatus.READY
                    newly_ready.append(other)

        return newly_ready

    def aggregate_results(self, root_task_id: str) -> dict[str, Any]:
        """Aggregate results from all sub-tasks of a root task."""
        root = self._tasks.get(root_task_id)
        if not root:
            return {}

        all_results: dict[str, Any] = {
            "root_task": root.title,
            "target": root.target,
            "sub_task_results": [],
            "total_sub_tasks": len(root.children),
            "completed": 0,
            "failed": 0,
        }

        for child_id in root.children:
            child = self._tasks.get(child_id)
            if child:
                all_results["sub_task_results"].append({
                    "title": child.title,
                    "status": child.status.value,
                    "result": child.result,
                })
                if child.status == SubTaskStatus.COMPLETED:
                    all_results["completed"] += 1
                elif child.status == SubTaskStatus.FAILED:
                    all_results["failed"] += 1

        return all_results

    @staticmethod
    def _select_template(goal: str) -> str:
        """Select a decomposition template based on the goal."""
        goal_lower = goal.lower()

        if any(kw in goal_lower for kw in ("code", "audit", "review", "source")):
            return "code_audit"

        if any(kw in goal_lower for kw in ("recon", "discover", "enumerate")):
            return "recon_only"

        if any(kw in goal_lower for kw in ("quick", "fast", "basic")):
            return "quick_scan"

        return "full_assessment"

    @staticmethod
    def _determine_strategy(
        sub_tasks: list[SubTask],
        parallel_groups: dict[int, list[str]],
    ) -> DecompStrategy:
        """Determine the decomposition strategy."""
        if parallel_groups:
            return DecompStrategy.MIXED

        has_deps = any(t.dependencies for t in sub_tasks)
        if has_deps:
            return DecompStrategy.PIPELINE

        return DecompStrategy.SEQUENTIAL

    def get_ready_tasks(self) -> list[SubTask]:
        return [t for t in self._tasks.values() if t.status == SubTaskStatus.READY]

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for task in self._tasks.values():
            status_counts[task.status.value] += 1
        return {
            "total_tasks": len(self._tasks),
            "statuses": dict(status_counts),
            "max_depth_seen": max((t.depth for t in self._tasks.values()), default=0),
        }
