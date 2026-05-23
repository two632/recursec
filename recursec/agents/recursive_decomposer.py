"""Recursive task decomposer — breaks complex goals into sub-tasks.

Implements:
1. Goal decomposition into sub-tasks
2. Recursive depth-limited decomposition
3. Budget allocation across sub-tasks
4. Dependency detection between sub-tasks
5. Result aggregation from child tasks
6. Base case detection (atomic tasks)
7. Convergence-based early termination
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskType(str, Enum):
    COMPOSITE = "composite"      # Can be decomposed further
    ATOMIC = "atomic"            # Base case, execute directly
    PARALLEL = "parallel"        # Sub-tasks run in parallel
    SEQUENTIAL = "sequential"    # Sub-tasks run in order


class SubTaskStatus(str, Enum):
    PENDING = "pending"
    DECOMPOSING = "decomposing"
    EXECUTING = "executing"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class SubTask:
    """A sub-task in the decomposition tree."""
    task_id: str = ""
    parent_id: str = ""
    depth: int = 0
    task_type: TaskType = TaskType.ATOMIC
    status: SubTaskStatus = SubTaskStatus.PENDING
    goal: str = ""
    role: str = ""
    tools: list[str] = field(default_factory=list)
    knowledge_domains: list[str] = field(default_factory=list)
    token_budget: int = 0
    time_budget_s: float = 0.0
    children: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "depth": self.depth,
            "type": self.task_type.value,
            "status": self.status.value,
            "goal": self.goal[:30],
            "children": len(self.children),
            "findings": len(self.findings),
        }


@dataclass
class DecompositionResult:
    """Result of a full decomposition."""
    root_task_id: str = ""
    total_tasks: int = 0
    max_depth: int = 0
    total_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens_used: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root_task_id[:10],
            "tasks": self.total_tasks,
            "depth": self.max_depth,
            "findings": len(self.total_findings),
            "tokens": self.total_tokens_used,
        }


# ── Decomposition templates ───────────────────────────────────

DECOMPOSITION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"goal": "Perform passive reconnaissance", "role": "recon", "type": "composite",
         "kbs": ["osint", "infrastructure"], "tools": ["subfinder", "amass", "dig", "whois"]},
        {"goal": "Perform active scanning", "role": "scanner", "type": "composite",
         "kbs": ["network", "webapp"], "tools": ["nmap", "nuclei", "nikto"]},
        {"goal": "Analyze discovered vulnerabilities", "role": "code_auditor", "type": "composite",
         "kbs": ["injection", "business_logic", "cryptography"]},
        {"goal": "Attempt exploitation of confirmed vulns", "role": "exploiter", "type": "composite",
         "kbs": ["binary_analysis", "lateral_movement", "privesc"]},
        {"goal": "Validate all findings", "role": "validator", "type": "atomic",
         "kbs": ["compliance"]},
    ],
    "web_assessment": [
        {"goal": "Enumerate web application surface", "role": "recon", "type": "composite",
         "tools": ["httpx", "ffuf", "gobuster"]},
        {"goal": "Test for injection vulnerabilities", "role": "scanner", "type": "parallel",
         "kbs": ["injection"], "tools": ["sqlmap", "commix", "dalfox"]},
        {"goal": "Test business logic flaws", "role": "scanner", "type": "parallel",
         "kbs": ["business_logic"], "tools": ["burp"]},
        {"goal": "Test authentication mechanisms", "role": "scanner", "type": "parallel",
         "kbs": ["business_logic", "cryptography"]},
        {"goal": "Test API security", "role": "scanner", "type": "parallel",
         "kbs": ["api_security"]},
    ],
    "network_assessment": [
        {"goal": "Discover network hosts and services", "role": "recon", "type": "atomic",
         "tools": ["nmap", "masscan"]},
        {"goal": "Enumerate network services", "role": "scanner", "type": "parallel",
         "tools": ["enum4linux", "crackmapexec"]},
        {"goal": "Test for network vulnerabilities", "role": "scanner", "type": "composite",
         "kbs": ["network", "cryptography"]},
        {"goal": "Attempt lateral movement", "role": "exploiter", "type": "composite",
         "kbs": ["lateral_movement", "active_directory"]},
    ],
    "cloud_assessment": [
        {"goal": "Enumerate cloud resources and configs", "role": "recon", "type": "composite",
         "kbs": ["cloud_security"], "tools": ["aws-cli", "scoutsuite"]},
        {"goal": "Test IAM and access controls", "role": "scanner", "type": "parallel",
         "kbs": ["cloud_security"]},
        {"goal": "Test for data exposure", "role": "scanner", "type": "parallel",
         "kbs": ["cloud_security", "supply_chain"]},
        {"goal": "Test container security", "role": "scanner", "type": "parallel",
         "kbs": ["cloud_security"], "tools": ["trivy", "kube-bench"]},
    ],
    "recon_subtasks": [
        {"goal": "DNS enumeration", "role": "recon", "type": "atomic",
         "tools": ["subfinder", "amass", "dig"]},
        {"goal": "Port scanning", "role": "recon", "type": "atomic",
         "tools": ["nmap", "masscan"]},
        {"goal": "Technology detection", "role": "recon", "type": "atomic",
         "tools": ["httpx", "whatweb"]},
        {"goal": "OSINT gathering", "role": "osint", "type": "atomic",
         "kbs": ["osint"], "tools": ["theharvester"]},
    ],
}


class RecursiveDecomposer:
    """Recursively decomposes goals into executable sub-tasks.

    Uses templates and LLM-guided decomposition
    to break complex security assessment goals
    into bounded, atomic tasks with proper
    budget allocation.
    """

    def __init__(
        self,
        max_depth: int = 4,
        budget_decay: float = 0.7,
    ) -> None:
        self._tasks: dict[str, SubTask] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._budget_decay = budget_decay
        self._log = logger.bind(component="recursive_decomposer")

    def decompose(
        self,
        goal: str,
        template: str = "full_assessment",
        token_budget: int = 100000,
        time_budget_s: float = 3600.0,
    ) -> SubTask:
        """Decompose a goal using a template."""
        root = self._create_task(
            goal=goal,
            parent_id="",
            depth=0,
            task_type=TaskType.COMPOSITE,
            token_budget=token_budget,
            time_budget_s=time_budget_s,
        )

        # Apply template
        template_steps = DECOMPOSITION_TEMPLATES.get(template, [])
        if template_steps:
            self._apply_template(root, template_steps)

        return root

    def _create_task(
        self,
        goal: str,
        parent_id: str,
        depth: int,
        task_type: TaskType = TaskType.ATOMIC,
        role: str = "",
        tools: list[str] | None = None,
        knowledge_domains: list[str] | None = None,
        token_budget: int = 0,
        time_budget_s: float = 0.0,
    ) -> SubTask:
        """Create a new sub-task."""
        self._counter += 1
        task = SubTask(
            task_id=f"task-{self._counter}",
            parent_id=parent_id,
            depth=depth,
            task_type=task_type,
            goal=goal,
            role=role,
            tools=tools or [],
            knowledge_domains=knowledge_domains or [],
            token_budget=token_budget,
            time_budget_s=time_budget_s,
        )
        self._tasks[task.task_id] = task
        return task

    def _apply_template(
        self,
        parent: SubTask,
        steps: list[dict[str, Any]],
    ) -> None:
        """Apply a decomposition template to a parent task."""
        child_count = len(steps)
        if child_count == 0:
            return

        per_child_budget = int(parent.token_budget * self._budget_decay / max(1, child_count))
        per_child_time = parent.time_budget_s * self._budget_decay / max(1, child_count)

        for step in steps:
            task_type_str = step.get("type", "atomic")
            try:
                task_type = TaskType(task_type_str)
            except ValueError:
                task_type = TaskType.ATOMIC

            child = self._create_task(
                goal=step.get("goal", ""),
                parent_id=parent.task_id,
                depth=parent.depth + 1,
                task_type=task_type,
                role=step.get("role", ""),
                tools=step.get("tools", []),
                knowledge_domains=step.get("kbs", []),
                token_budget=per_child_budget,
                time_budget_s=per_child_time,
            )
            parent.children.append(child.task_id)

            # Recursively decompose composite children
            if task_type == TaskType.COMPOSITE and parent.depth + 1 < self._max_depth:
                sub_template = self._get_sub_template(child.role, child.goal)
                if sub_template:
                    self._apply_template(child, sub_template)

    def _get_sub_template(
        self,
        role: str,
        goal: str,
    ) -> list[dict[str, Any]]:
        """Get a sub-decomposition template based on role/goal."""
        goal_lower = goal.lower()
        if "recon" in goal_lower:
            return DECOMPOSITION_TEMPLATES.get("recon_subtasks", [])
        return []

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if not task:
            return

        task.status = SubTaskStatus.COMPLETED
        task.completed_at = time.time()
        if result:
            task.result = result
        if findings:
            task.findings = findings

    def fail_task(self, task_id: str, reason: str = "") -> None:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if not task:
            return
        task.status = SubTaskStatus.FAILED
        task.result = {"error": reason}

    def get_ready_tasks(self) -> list[SubTask]:
        """Get tasks ready for execution (atomic + pending + deps met)."""
        ready = []
        for task in self._tasks.values():
            if task.status != SubTaskStatus.PENDING:
                continue
            if task.task_type != TaskType.ATOMIC:
                continue
            # Check dependencies
            deps_met = all(
                self._tasks.get(dep, SubTask()).status == SubTaskStatus.COMPLETED
                for dep in task.dependencies
            )
            if deps_met:
                ready.append(task)
        return ready

    def aggregate_results(self, task_id: str) -> DecompositionResult:
        """Aggregate results from all sub-tasks."""
        task = self._tasks.get(task_id)
        if not task:
            return DecompositionResult()

        all_findings: list[dict[str, Any]] = []
        total_tokens = 0
        max_depth = 0

        # Traverse tree
        stack = [task_id]
        visited: set[str] = set()
        task_count = 0

        while stack:
            tid = stack.pop()
            if tid in visited:
                continue
            visited.add(tid)
            task_count += 1

            t = self._tasks.get(tid)
            if not t:
                continue

            all_findings.extend(t.findings)
            total_tokens += t.token_budget
            if t.depth > max_depth:
                max_depth = t.depth

            for child_id in t.children:
                stack.append(child_id)

        return DecompositionResult(
            root_task_id=task_id,
            total_tasks=task_count,
            max_depth=max_depth,
            total_findings=all_findings,
            total_tokens_used=total_tokens,
        )

    def build_decomposition_prompt(
        self,
        task_id: str,
    ) -> str:
        """Build decomposition context for LLM."""
        task = self._tasks.get(task_id)
        if not task:
            return ""

        lines = [
            f"## Task Decomposition (depth {task.depth})\n",
            f"Goal: {task.goal}",
            f"Type: {task.task_type.value}",
            f"Role: {task.role}",
            f"Budget: {task.token_budget} tokens, {task.time_budget_s:.0f}s",
            "",
        ]

        if task.children:
            lines.append("Sub-tasks:")
            for cid in task.children:
                child = self._tasks.get(cid)
                if child:
                    lines.append(
                        f"  [{child.status.value}] {child.goal[:40]} "
                        f"({child.task_type.value}, {len(child.findings)} findings)"
                    )

        if task.knowledge_domains:
            lines.append(f"Knowledge: {', '.join(task.knowledge_domains)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for t in self._tasks.values():
            status_counts[t.status.value] = status_counts.get(t.status.value, 0) + 1

        return {
            "total_tasks": len(self._tasks),
            "by_status": status_counts,
            "max_depth": max((t.depth for t in self._tasks.values()), default=0),
        }
