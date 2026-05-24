"""Recursive task decomposer — bounded recursion.

Implements the core recursive multi-agent pattern:
1. Task → sub-task decomposition
2. Bounded recursion with depth limits
3. Token budget tracking per level
4. Result aggregation from children
5. Convergence detection
6. Decomposition prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskStatus(str, Enum):
    PENDING = "pending"
    DECOMPOSING = "decomposing"
    EXECUTING = "executing"
    WAITING = "waiting"        # Waiting for children
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DEPTH_LIMIT = "depth_limit"


class DecompositionStrategy(str, Enum):
    PARALLEL = "parallel"     # All sub-tasks run simultaneously
    SEQUENTIAL = "sequential" # Sub-tasks run in order
    PIPELINE = "pipeline"     # Output of one feeds into next
    COMPETITIVE = "competitive"  # Multiple agents, best wins
    HIERARCHICAL = "hierarchical"  # Manager → workers


@dataclass
class TaskNode:
    """A node in the recursive task tree."""
    task_id: str = ""
    parent_id: str = ""
    depth: int = 0
    description: str = ""
    role: str = ""
    model: str = ""
    status: TaskStatus = TaskStatus.PENDING
    strategy: DecompositionStrategy = DecompositionStrategy.SEQUENTIAL
    children: list[str] = field(default_factory=list)
    result: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    token_budget: int = 4096
    tokens_used: int = 0
    timeout_s: float = 300.0
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.TIMEOUT,
            TaskStatus.DEPTH_LIMIT,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "depth": self.depth,
            "status": self.status.value[:8],
            "children": len(self.children),
            "findings": len(self.findings),
        }


# Decomposition rules: task type → sub-tasks
DECOMPOSITION_RULES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"desc": "Passive reconnaissance", "role": "recon"},
        {"desc": "Active enumeration", "role": "scanner"},
        {"desc": "Vulnerability scanning", "role": "scanner"},
        {"desc": "Analysis and correlation", "role": "analyst"},
        {"desc": "Exploitation attempts", "role": "exploiter"},
        {"desc": "Validation of findings", "role": "validator"},
        {"desc": "Report generation", "role": "reporter"},
    ],
    "web_pentest": [
        {"desc": "Web technology fingerprinting", "role": "recon"},
        {"desc": "Directory and endpoint enumeration", "role": "web"},
        {"desc": "Automated vulnerability scanning", "role": "scanner"},
        {"desc": "Manual testing (auth, logic, injection)", "role": "web"},
        {"desc": "Exploit validation", "role": "validator"},
    ],
    "network_pentest": [
        {"desc": "Host discovery and port scanning", "role": "recon"},
        {"desc": "Service enumeration", "role": "network"},
        {"desc": "Vulnerability assessment", "role": "scanner"},
        {"desc": "Exploitation", "role": "exploiter"},
        {"desc": "Privilege escalation", "role": "exploiter"},
        {"desc": "Lateral movement", "role": "network"},
    ],
    "code_audit": [
        {"desc": "Static analysis with tools", "role": "code_auditor"},
        {"desc": "Dependency vulnerability check", "role": "scanner"},
        {"desc": "Manual code review (critical paths)", "role": "code_auditor"},
        {"desc": "Finding validation", "role": "validator"},
    ],
    "recon": [
        {"desc": "Subdomain enumeration", "role": "recon"},
        {"desc": "Port scanning", "role": "recon"},
        {"desc": "Technology detection", "role": "recon"},
        {"desc": "OSINT gathering", "role": "osint"},
    ],
    "exploit": [
        {"desc": "Vulnerability confirmation", "role": "validator"},
        {"desc": "Payload preparation", "role": "exploiter"},
        {"desc": "Exploitation attempt", "role": "exploiter"},
        {"desc": "Post-exploitation", "role": "exploiter"},
    ],
}

# Model selection for roles at different depths
DEPTH_MODEL_PREFERENCE: dict[int, dict[str, str]] = {
    0: {  # Root level — use best models
        "coordinator": "DeepSeek-R1",
        "planner": "Hermes-4-14B",
        "recon": "Mistral-7B",
        "scanner": "WhiteRabbitNeo-7B",
        "web": "WhiteRabbitNeo-7B",
        "analyst": "DeepSeek-R1",
        "exploiter": "WhiteRabbitNeo-7B",
        "validator": "Qwen2.5-Coder-14B",
        "code_auditor": "Qwen2.5-Coder-14B",
    },
    1: {  # Level 1 — use good models
        "recon": "Phi-3.5-mini",
        "scanner": "Dolphin-2.9",
        "web": "Dolphin-2.9",
        "analyst": "Hermes-4-14B",
        "exploiter": "Dolphin-2.9",
        "validator": "Qwen2.5-Coder-7B",
        "code_auditor": "CodeLlama-13B",
    },
    2: {  # Level 2 — use fast models
        "recon": "Phi-3.5-mini",
        "scanner": "Phi-3.5-mini",
        "web": "Qwen2.5-Coder-7B",
        "analyst": "Mistral-7B",
        "exploiter": "CodeLlama-7B",
        "validator": "Phi-3.5-mini",
        "code_auditor": "CodeLlama-7B",
    },
}


class RecursiveDecomposer:
    """Recursively decompose tasks with bounded depth.

    Core of the recursive multi-agent architecture:
    parent agents spawn children, children may
    spawn grandchildren, results flow back up.
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_children: int = 8,
        total_token_budget: int = 100000,
    ) -> None:
        self._tasks: dict[str, TaskNode] = {}
        self._task_counter = 0
        self._max_depth = max_depth
        self._max_children = max_children
        self._total_budget = total_token_budget
        self._total_tokens_used = 0
        self._log = logger.bind(component="decomposer")

    def create_root(
        self,
        description: str,
        task_type: str = "full_assessment",
        strategy: DecompositionStrategy = DecompositionStrategy.SEQUENTIAL,
    ) -> TaskNode:
        """Create the root task node."""
        self._task_counter += 1
        root = TaskNode(
            task_id=f"t-{self._task_counter}",
            depth=0,
            description=description,
            role="coordinator",
            model="DeepSeek-R1",
            status=TaskStatus.DECOMPOSING,
            strategy=strategy,
            token_budget=self._total_budget,
        )
        self._tasks[root.task_id] = root
        return root

    def decompose(
        self,
        parent_id: str,
        task_type: str = "",
    ) -> list[TaskNode]:
        """Decompose a task into sub-tasks."""
        parent = self._tasks.get(parent_id)
        if not parent:
            return []

        # Check depth limit
        if parent.depth >= self._max_depth:
            parent.status = TaskStatus.DEPTH_LIMIT
            return []

        # Get decomposition rules
        sub_tasks_data = DECOMPOSITION_RULES.get(task_type, [])
        if not sub_tasks_data:
            # If no rules, task is a leaf
            parent.status = TaskStatus.EXECUTING
            return []

        # Create child tasks
        children: list[TaskNode] = []
        child_budget = parent.token_budget // max(1, len(sub_tasks_data))
        depth_models = DEPTH_MODEL_PREFERENCE.get(
            parent.depth + 1,
            DEPTH_MODEL_PREFERENCE.get(2, {}),
        )

        for data in sub_tasks_data[:self._max_children]:
            self._task_counter += 1
            role = data.get("role", "scanner")
            child = TaskNode(
                task_id=f"t-{self._task_counter}",
                parent_id=parent_id,
                depth=parent.depth + 1,
                description=data.get("desc", ""),
                role=role,
                model=depth_models.get(role, "Mistral-7B"),
                token_budget=child_budget,
            )
            self._tasks[child.task_id] = child
            parent.children.append(child.task_id)
            children.append(child)

        parent.status = TaskStatus.WAITING
        return children

    def start_task(self, task_id: str) -> None:
        """Mark a task as started."""
        task = self._tasks.get(task_id)
        if task:
            task.status = TaskStatus.EXECUTING
            task.started_at = time.time()

    def complete_task(
        self,
        task_id: str,
        result: str = "",
        findings: list[dict[str, Any]] | None = None,
        tokens_used: int = 0,
    ) -> None:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if not task:
            return

        task.status = TaskStatus.COMPLETED
        task.result = result
        task.findings = findings or []
        task.tokens_used = tokens_used
        task.completed_at = time.time()
        self._total_tokens_used += tokens_used

        # Check if parent can aggregate
        if task.parent_id:
            self._check_parent_ready(task.parent_id)

    def fail_task(self, task_id: str, error: str = "") -> None:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if task:
            task.status = TaskStatus.FAILED
            task.error = error
            task.completed_at = time.time()

            if task.parent_id:
                self._check_parent_ready(task.parent_id)

    def _check_parent_ready(self, parent_id: str) -> None:
        """Check if parent's children are all done."""
        parent = self._tasks.get(parent_id)
        if not parent:
            return

        all_done = all(
            self._tasks.get(cid, TaskNode()).is_terminal
            for cid in parent.children
        )

        if all_done:
            parent.status = TaskStatus.AGGREGATING

    def aggregate(self, task_id: str) -> dict[str, Any]:
        """Aggregate results from children."""
        task = self._tasks.get(task_id)
        if not task:
            return {}

        all_findings: list[dict[str, Any]] = []
        all_results: list[str] = []
        total_tokens = 0
        child_count = 0
        success_count = 0

        for child_id in task.children:
            child = self._tasks.get(child_id)
            if not child:
                continue

            child_count += 1
            if child.status == TaskStatus.COMPLETED:
                success_count += 1
                all_findings.extend(child.findings)
                if child.result:
                    all_results.append(child.result)
            total_tokens += child.tokens_used

        task.findings = all_findings
        task.tokens_used = total_tokens
        task.result = "\n---\n".join(all_results)
        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()

        return {
            "findings": len(all_findings),
            "children": child_count,
            "succeeded": success_count,
            "tokens": total_tokens,
        }

    def get_ready_tasks(self) -> list[TaskNode]:
        """Get tasks ready for execution."""
        return [
            t for t in self._tasks.values()
            if t.status == TaskStatus.PENDING and t.is_leaf
        ]

    def get_aggregatable(self) -> list[TaskNode]:
        """Get tasks ready for aggregation."""
        return [
            t for t in self._tasks.values()
            if t.status == TaskStatus.AGGREGATING
        ]

    def get_tree_depth(self) -> int:
        """Get current max depth of the task tree."""
        if not self._tasks:
            return 0
        return max(t.depth for t in self._tasks.values())

    def is_converged(self) -> bool:
        """Check if all tasks are terminal."""
        return all(t.is_terminal for t in self._tasks.values())

    def build_decomposition_prompt(self) -> str:
        """Build decomposition state for LLM."""
        lines = ["## Task Tree\n"]

        total = len(self._tasks)
        completed = sum(
            1 for t in self._tasks.values()
            if t.status == TaskStatus.COMPLETED
        )
        pending = sum(
            1 for t in self._tasks.values()
            if t.status == TaskStatus.PENDING
        )
        executing = sum(
            1 for t in self._tasks.values()
            if t.status == TaskStatus.EXECUTING
        )

        lines.append(f"Tasks: {total} (done={completed}, pending={pending}, exec={executing})")
        lines.append(f"Depth: {self.get_tree_depth()}/{self._max_depth}")
        lines.append(f"Tokens: {self._total_tokens_used}/{self._total_budget}")
        lines.append(f"Converged: {self.is_converged()}")

        # Show top-level tasks
        roots = [t for t in self._tasks.values() if not t.parent_id]
        for root in roots[:1]:
            lines.append(f"\nRoot: {root.description[:25]}")
            for child_id in root.children[:5]:
                child = self._tasks.get(child_id)
                if child:
                    status_mark = {
                        TaskStatus.COMPLETED: "done",
                        TaskStatus.FAILED: "FAIL",
                        TaskStatus.EXECUTING: "...",
                        TaskStatus.PENDING: "wait",
                    }.get(child.status, child.status.value[:4])
                    lines.append(
                        f"  [{status_mark}] {child.description[:25]} "
                        f"({child.role[:6]})"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for t in self._tasks.values():
            status_counts[t.status.value] = (
                status_counts.get(t.status.value, 0) + 1
            )

        total_findings = sum(
            len(t.findings) for t in self._tasks.values()
        )

        return {
            "tasks": len(self._tasks),
            "depth": self.get_tree_depth(),
            "tokens_used": self._total_tokens_used,
            "findings": total_findings,
            "converged": self.is_converged(),
            "by_status": status_counts,
        }
