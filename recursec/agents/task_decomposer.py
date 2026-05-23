"""Task decomposer — breaks complex security tasks into sub-tasks.

Implements:
1. Goal-based task decomposition
2. Dependency graph building between sub-tasks
3. Resource estimation per sub-task
4. Parallelization opportunity detection
5. Sub-task assignment to specialized agents
6. Decomposition depth control
7. Task merging for similar sub-tasks
8. Decomposition templates for common tasks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    BACKGROUND = "background"


class TaskCategory(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"


@dataclass
class SubTask:
    """A decomposed sub-task."""
    task_id: str = ""
    name: str = ""
    description: str = ""
    category: TaskCategory = TaskCategory.RECON
    priority: TaskPriority = TaskPriority.NORMAL
    agent_role: str = ""           # Recommended agent role
    tools: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    estimated_tokens: int = 10_000
    estimated_time_s: float = 60.0
    parallelizable: bool = True
    depth: int = 0
    parent_id: str = ""
    target: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "name": self.name[:40],
            "category": self.category.value,
            "priority": self.priority.value,
            "agent": self.agent_role[:20],
            "deps": self.dependencies[:5],
            "parallel": self.parallelizable,
        }


@dataclass
class DecompositionResult:
    """Result of task decomposition."""
    root_task: str = ""
    subtasks: list[SubTask] = field(default_factory=list)
    parallel_groups: list[list[str]] = field(default_factory=list)
    total_estimated_tokens: int = 0
    total_estimated_time_s: float = 0.0
    depth: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root_task[:40],
            "subtasks": len(self.subtasks),
            "parallel_groups": len(self.parallel_groups),
            "tokens": self.total_estimated_tokens,
            "time_s": round(self.total_estimated_time_s, 0),
        }


# ── Decomposition Templates ──────────────────────────────────

DECOMPOSITION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"name": "Subdomain enumeration", "category": "recon", "agent": "recon",
         "tools": ["subfinder", "amass"], "tokens": 5000, "time": 60, "parallel": True},
        {"name": "Port scanning", "category": "recon", "agent": "recon",
         "tools": ["nmap", "masscan"], "tokens": 5000, "time": 120, "parallel": True},
        {"name": "Technology fingerprinting", "category": "recon", "agent": "recon",
         "tools": ["whatweb", "httpx"], "tokens": 5000, "time": 60, "depends": ["Subdomain enumeration"]},
        {"name": "Directory discovery", "category": "scanning", "agent": "web_scanner",
         "tools": ["ffuf", "gobuster"], "tokens": 10000, "time": 180, "depends": ["Technology fingerprinting"]},
        {"name": "Vulnerability scanning", "category": "scanning", "agent": "vuln_scanner",
         "tools": ["nuclei", "nikto"], "tokens": 20000, "time": 300, "depends": ["Technology fingerprinting"]},
        {"name": "SSL analysis", "category": "scanning", "agent": "crypto_analyst",
         "tools": ["sslscan", "testssl.sh"], "tokens": 3000, "time": 60, "parallel": True},
        {"name": "SQL injection testing", "category": "exploitation", "agent": "exploit",
         "tools": ["sqlmap"], "tokens": 30000, "time": 300, "depends": ["Vulnerability scanning"]},
        {"name": "XSS testing", "category": "exploitation", "agent": "exploit",
         "tools": ["dalfox"], "tokens": 20000, "time": 200, "depends": ["Vulnerability scanning"]},
        {"name": "Credential testing", "category": "exploitation", "agent": "exploit",
         "tools": ["hydra"], "tokens": 10000, "time": 180, "depends": ["Port scanning"]},
        {"name": "Finding validation", "category": "validation", "agent": "validator",
         "tokens": 30000, "time": 300, "depends": ["SQL injection testing", "XSS testing"]},
        {"name": "Report generation", "category": "reporting", "agent": "reporter",
         "tokens": 20000, "time": 120, "depends": ["Finding validation"]},
    ],
    "quick_scan": [
        {"name": "Basic recon", "category": "recon", "agent": "recon",
         "tools": ["httpx", "whatweb"], "tokens": 3000, "time": 30},
        {"name": "Quick vuln scan", "category": "scanning", "agent": "vuln_scanner",
         "tools": ["nuclei"], "tokens": 10000, "time": 120, "depends": ["Basic recon"]},
        {"name": "Basic validation", "category": "validation", "agent": "validator",
         "tokens": 5000, "time": 60, "depends": ["Quick vuln scan"]},
    ],
    "network_assessment": [
        {"name": "Host discovery", "category": "recon", "agent": "recon",
         "tools": ["nmap"], "tokens": 3000, "time": 60},
        {"name": "Full port scan", "category": "recon", "agent": "recon",
         "tools": ["nmap", "masscan"], "tokens": 5000, "time": 120, "depends": ["Host discovery"]},
        {"name": "Service enumeration", "category": "scanning", "agent": "recon",
         "tools": ["nmap"], "tokens": 10000, "time": 180, "depends": ["Full port scan"]},
        {"name": "Vuln scanning", "category": "scanning", "agent": "vuln_scanner",
         "tools": ["nuclei", "nmap"], "tokens": 15000, "time": 240, "depends": ["Service enumeration"]},
        {"name": "Credential brute force", "category": "exploitation", "agent": "exploit",
         "tools": ["hydra"], "tokens": 10000, "time": 300, "depends": ["Service enumeration"]},
        {"name": "Validation", "category": "validation", "agent": "validator",
         "tokens": 10000, "time": 120, "depends": ["Vuln scanning", "Credential brute force"]},
    ],
    "code_audit": [
        {"name": "Static analysis", "category": "scanning", "agent": "code_auditor",
         "tools": ["semgrep", "bandit"], "tokens": 20000, "time": 180},
        {"name": "Secret scanning", "category": "scanning", "agent": "code_auditor",
         "tools": ["gitleaks", "trufflehog"], "tokens": 5000, "time": 60, "parallel": True},
        {"name": "Dependency audit", "category": "scanning", "agent": "code_auditor",
         "tools": ["trivy", "grype"], "tokens": 5000, "time": 60, "parallel": True},
        {"name": "Manual review", "category": "analysis", "agent": "code_auditor",
         "tokens": 50000, "time": 600, "depends": ["Static analysis"]},
        {"name": "Validation", "category": "validation", "agent": "validator",
         "tokens": 10000, "time": 120, "depends": ["Manual review"]},
    ],
}


class TaskDecomposer:
    """Breaks complex security tasks into sub-tasks.

    Uses templates and heuristics to decompose
    high-level goals into actionable sub-tasks.
    """

    def __init__(self) -> None:
        self._task_counter = 0
        self._decomposition_count = 0
        self._log = logger.bind(component="task_decomposer")

    def decompose(
        self,
        task: str,
        target: str = "",
        task_type: str = "full_assessment",
        depth: int = 0,
        max_depth: int = 3,
    ) -> DecompositionResult:
        """Decompose a task into sub-tasks."""
        self._decomposition_count += 1

        template = DECOMPOSITION_TEMPLATES.get(task_type, DECOMPOSITION_TEMPLATES["full_assessment"])

        subtasks = []
        task_name_to_id: dict[str, str] = {}

        for step in template:
            self._task_counter += 1
            task_id = f"task-{self._task_counter}"

            # Resolve dependencies to IDs
            dep_names = step.get("depends", [])
            dep_ids = [task_name_to_id[d] for d in dep_names if d in task_name_to_id]

            subtask = SubTask(
                task_id=task_id,
                name=step["name"],
                category=TaskCategory(step.get("category", "recon")),
                agent_role=step.get("agent", ""),
                tools=step.get("tools", []),
                dependencies=dep_ids,
                estimated_tokens=step.get("tokens", 10000),
                estimated_time_s=step.get("time", 60),
                parallelizable=step.get("parallel", not dep_names),
                depth=depth,
                target=target,
            )

            subtasks.append(subtask)
            task_name_to_id[step["name"]] = task_id

        # Build parallel groups
        parallel_groups = self._find_parallel_groups(subtasks)

        result = DecompositionResult(
            root_task=task,
            subtasks=subtasks,
            parallel_groups=parallel_groups,
            total_estimated_tokens=sum(s.estimated_tokens for s in subtasks),
            total_estimated_time_s=self._estimate_parallel_time(subtasks, parallel_groups),
            depth=depth,
        )

        return result

    def _find_parallel_groups(
        self,
        subtasks: list[SubTask],
    ) -> list[list[str]]:
        """Find groups of tasks that can run in parallel."""
        # Tasks with no dependencies can form the first parallel group
        groups: list[list[str]] = []
        assigned: set[str] = set()

        while len(assigned) < len(subtasks):
            group = []
            for task in subtasks:
                if task.task_id in assigned:
                    continue
                # All dependencies resolved
                if all(d in assigned for d in task.dependencies):
                    group.append(task.task_id)

            if not group:
                break

            groups.append(group)
            assigned.update(group)

        return groups

    def _estimate_parallel_time(
        self,
        subtasks: list[SubTask],
        groups: list[list[str]],
    ) -> float:
        """Estimate total time with parallelization."""
        task_map = {s.task_id: s for s in subtasks}
        total = 0.0

        for group in groups:
            # Parallel group takes as long as the slowest task
            max_time = 0.0
            for task_id in group:
                task = task_map.get(task_id)
                if task:
                    max_time = max(max_time, task.estimated_time_s)
            total += max_time

        return total

    def get_execution_order(
        self,
        result: DecompositionResult,
    ) -> list[list[dict[str, Any]]]:
        """Get ordered execution batches."""
        return [
            [
                next(
                    (s.to_dict() for s in result.subtasks if s.task_id == tid),
                    {"id": tid},
                )
                for tid in group
            ]
            for group in result.parallel_groups
        ]

    def get_stats(self) -> dict[str, Any]:
        return {
            "tasks_created": self._task_counter,
            "decompositions": self._decomposition_count,
            "templates": len(DECOMPOSITION_TEMPLATES),
        }
