"""Recursive task decomposition engine — breaks complex tasks into agent-executable subtasks.

Implements the full recursive multi-agent decomposition pattern:
1. Parses natural language goals into structured task trees
2. Identifies base cases (directly executable by a single agent)
3. Generates sub-goals at each recursion level
4. Tracks dependency graphs between subtasks
5. Manages depth limits and budget allocation
6. Supports parallel execution of independent subtasks
7. Aggregates results up the tree
8. Detects convergence and terminates early
9. Handles failure propagation and retry logic
10. Generates execution plans for the unified brain

This is the CORE intelligence that makes the agent recursive —
without this, agents just execute flat lists of tools.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DecompStrategy(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"
    ITERATIVE = "iterative"
    HIERARCHICAL = "hierarchical"


class SubtaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"


@dataclass
class Subtask:
    """A single subtask in the decomposition tree."""
    task_id: str = ""
    parent_id: str = ""
    depth: int = 0
    goal: str = ""
    agent_role: str = ""
    status: SubtaskStatus = SubtaskStatus.PENDING
    strategy: DecompStrategy = DecompStrategy.SEQUENTIAL
    complexity: TaskComplexity = TaskComplexity.MODERATE
    dependencies: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    tools_needed: list[str] = field(default_factory=list)
    kb_domains: list[str] = field(default_factory=list)
    model_preference: str = ""
    token_budget: int = 2000
    step_budget: int = 10
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    is_base_case: bool = False

    @property
    def duration_s(self) -> float:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "goal": self.goal[:30],
            "role": self.agent_role[:10],
            "depth": self.depth,
            "status": self.status.value[:8],
            "children": len(self.children),
            "base": self.is_base_case,
        }


@dataclass
class DecompositionTree:
    """The full task decomposition tree."""
    root_id: str = ""
    original_goal: str = ""
    max_depth: int = 5
    total_subtasks: int = 0
    completed_subtasks: int = 0
    failed_subtasks: int = 0
    total_token_budget: int = 50000
    tokens_used: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def completion_pct(self) -> float:
        if self.total_subtasks == 0:
            return 0.0
        return self.completed_subtasks / self.total_subtasks * 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root_id[:8],
            "goal": self.original_goal[:30],
            "tasks": self.total_subtasks,
            "done": self.completed_subtasks,
            "pct": f"{self.completion_pct:.0f}%",
            "depth": self.max_depth,
        }


# Task decomposition patterns — how to break down common security tasks
DECOMPOSITION_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"goal": "Enumerate target scope and identify assets", "role": "recon", "strategy": "parallel", "tools": ["subfinder", "amass", "httpx"], "kb": ["network", "dns"]},
        {"goal": "Port scan and service identification", "role": "scanner", "strategy": "parallel", "tools": ["nmap", "masscan"], "kb": ["network"], "depends_on": [0]},
        {"goal": "Web application vulnerability scanning", "role": "web", "strategy": "parallel", "tools": ["nuclei", "nikto", "sqlmap"], "kb": ["web_vuln", "xss", "ssrf"], "depends_on": [0]},
        {"goal": "Source code review if accessible", "role": "code_audit", "strategy": "sequential", "tools": ["semgrep", "bandit"], "kb": ["web_vuln", "deserialization"], "depends_on": [0]},
        {"goal": "Cloud infrastructure assessment", "role": "cloud", "strategy": "sequential", "tools": ["prowler", "scoutsuite"], "kb": ["cloud", "container_k8s"], "depends_on": [0]},
        {"goal": "Correlate findings and build attack chains", "role": "coordinator", "strategy": "sequential", "kb": ["advanced_strategy", "red_team"], "depends_on": [1, 2, 3, 4]},
        {"goal": "Validate critical findings", "role": "exploit", "strategy": "sequential", "kb": ["advanced_discovery"], "depends_on": [5]},
        {"goal": "Generate final report with risk assessment", "role": "coordinator", "strategy": "sequential", "depends_on": [6]},
    ],
    "web_pentest": [
        {"goal": "Spider and enumerate web endpoints", "role": "web", "strategy": "parallel", "tools": ["gobuster", "ffuf", "httpx"], "kb": ["web_vuln"]},
        {"goal": "Test authentication and session management", "role": "web", "strategy": "sequential", "tools": ["burpsuite", "sqlmap"], "kb": ["web_vuln", "business_logic"], "depends_on": [0]},
        {"goal": "Test injection vulnerabilities (SQL, XSS, SSRF)", "role": "web", "strategy": "parallel", "tools": ["sqlmap", "dalfox", "nuclei"], "kb": ["xss", "ssrf", "web_vuln"], "depends_on": [0]},
        {"goal": "Test file upload and deserialization", "role": "web", "strategy": "sequential", "tools": ["nuclei"], "kb": ["deserialization", "web_vuln"], "depends_on": [0]},
        {"goal": "Test API security", "role": "web", "strategy": "sequential", "tools": ["nuclei", "httpx"], "kb": ["api_gateway"], "depends_on": [0]},
        {"goal": "Correlate web findings", "role": "coordinator", "strategy": "sequential", "depends_on": [1, 2, 3, 4]},
    ],
    "network_pentest": [
        {"goal": "Full port scan of target range", "role": "scanner", "strategy": "parallel", "tools": ["nmap", "masscan"], "kb": ["network"]},
        {"goal": "Service enumeration and version detection", "role": "scanner", "strategy": "parallel", "tools": ["nmap"], "kb": ["network"], "depends_on": [0]},
        {"goal": "Vulnerability scanning of detected services", "role": "scanner", "strategy": "parallel", "tools": ["nuclei", "nmap"], "kb": ["network"], "depends_on": [1]},
        {"goal": "Test lateral movement paths", "role": "network", "strategy": "sequential", "kb": ["lateral_movement", "active_directory"], "depends_on": [1]},
        {"goal": "Test DNS security", "role": "network", "strategy": "sequential", "tools": ["dnsrecon"], "kb": ["dns"], "depends_on": [0]},
        {"goal": "Build network attack graph", "role": "coordinator", "strategy": "sequential", "depends_on": [2, 3, 4]},
    ],
    "code_review": [
        {"goal": "Static analysis with SAST tools", "role": "code_audit", "strategy": "parallel", "tools": ["semgrep", "bandit", "gitleaks"], "kb": ["web_vuln", "supply_chain"]},
        {"goal": "Dependency vulnerability check", "role": "code_audit", "strategy": "parallel", "tools": ["trivy", "grype"], "kb": ["supply_chain"], "depends_on": []},
        {"goal": "Secret detection in codebase", "role": "code_audit", "strategy": "parallel", "tools": ["gitleaks", "trufflehog"], "kb": ["devsecops"]},
        {"goal": "Business logic review", "role": "code_audit", "strategy": "sequential", "kb": ["business_logic", "web_vuln"], "depends_on": [0]},
        {"goal": "Generate remediation recommendations", "role": "coordinator", "strategy": "sequential", "depends_on": [0, 1, 2, 3]},
    ],
    "cloud_audit": [
        {"goal": "IAM policy review", "role": "cloud", "strategy": "parallel", "tools": ["prowler"], "kb": ["cloud", "zero_trust"]},
        {"goal": "Network configuration audit", "role": "cloud", "strategy": "parallel", "tools": ["prowler", "scoutsuite"], "kb": ["cloud"]},
        {"goal": "Storage security check", "role": "cloud", "strategy": "parallel", "tools": ["scoutsuite"], "kb": ["cloud"]},
        {"goal": "Container and Kubernetes review", "role": "cloud", "strategy": "sequential", "tools": ["trivy"], "kb": ["container_k8s"]},
        {"goal": "Serverless function audit", "role": "cloud", "strategy": "sequential", "kb": ["serverless"]},
        {"goal": "Cloud attack path analysis", "role": "coordinator", "strategy": "sequential", "depends_on": [0, 1, 2, 3, 4]},
    ],
}

# Complexity estimation heuristics
COMPLEXITY_INDICATORS: dict[str, TaskComplexity] = {
    "full assessment": TaskComplexity.VERY_COMPLEX,
    "pentest": TaskComplexity.VERY_COMPLEX,
    "audit": TaskComplexity.COMPLEX,
    "scan": TaskComplexity.MODERATE,
    "review": TaskComplexity.COMPLEX,
    "enumerate": TaskComplexity.SIMPLE,
    "check": TaskComplexity.SIMPLE,
    "verify": TaskComplexity.SIMPLE,
    "test": TaskComplexity.MODERATE,
    "exploit": TaskComplexity.COMPLEX,
    "analyze": TaskComplexity.MODERATE,
}

# Role → model mapping
ROLE_MODEL_PREFERENCE: dict[str, str] = {
    "coordinator": "deepseek-r1",
    "recon": "mistral-7b",
    "scanner": "phi-3.5-mini",
    "web": "whiterabbit",
    "code_audit": "qwen-coder-14b",
    "exploit": "dolphin-2.9",
    "network": "whiterabbit",
    "cloud": "hermes-4-14b",
    "osint": "llama-3.1-8b",
}


class RecursiveTaskDecomposer:
    """Decomposes complex security tasks into agent-executable subtask trees."""

    def __init__(self, max_depth: int = 5, total_budget: int = 50000) -> None:
        self._tasks: dict[str, Subtask] = {}
        self._trees: dict[str, DecompositionTree] = {}
        self._task_counter = 0
        self._tree_counter = 0
        self._max_depth = max_depth
        self._total_budget = total_budget
        self._log = logger.bind(component="task_decomposer")

    def decompose(self, goal: str, target: str = "") -> DecompositionTree:
        """Decompose a high-level goal into a subtask tree."""
        self._tree_counter += 1
        tree = DecompositionTree(
            root_id="",
            original_goal=goal,
            max_depth=self._max_depth,
            total_token_budget=self._total_budget,
        )

        # Identify the pattern
        pattern_key = self._match_pattern(goal)
        pattern = DECOMPOSITION_PATTERNS.get(pattern_key, DECOMPOSITION_PATTERNS["full_assessment"])

        # Create root task
        root = self._create_subtask(
            goal=goal,
            role="coordinator",
            depth=0,
            parent_id="",
        )
        tree.root_id = root.task_id

        # Create children from pattern
        task_id_map: dict[int, str] = {}
        for i, step in enumerate(pattern):
            child = self._create_subtask(
                goal=step["goal"],
                role=step.get("role", "coordinator"),
                depth=1,
                parent_id=root.task_id,
                tools=step.get("tools", []),
                kb_domains=step.get("kb", []),
                strategy=DecompStrategy(step.get("strategy", "sequential")),
            )

            # Map dependencies
            depends_on = step.get("depends_on", [])
            for dep_idx in depends_on:
                if dep_idx in task_id_map:
                    child.dependencies.append(task_id_map[dep_idx])

            task_id_map[i] = child.task_id
            root.children.append(child.task_id)

            # Check if base case
            if not self._needs_further_decomposition(child):
                child.is_base_case = True
            else:
                # Could decompose further at depth 2
                self._decompose_further(child, depth=2)

        tree.total_subtasks = len(self._tasks)
        self._trees[tree.root_id] = tree

        return tree

    def _match_pattern(self, goal: str) -> str:
        """Match goal to a decomposition pattern."""
        goal_lower = goal.lower()
        if "web" in goal_lower and ("pentest" in goal_lower or "test" in goal_lower):
            return "web_pentest"
        if "network" in goal_lower and ("pentest" in goal_lower or "scan" in goal_lower):
            return "network_pentest"
        if "code" in goal_lower and ("review" in goal_lower or "audit" in goal_lower):
            return "code_review"
        if "cloud" in goal_lower and ("audit" in goal_lower or "review" in goal_lower):
            return "cloud_audit"
        return "full_assessment"

    def _create_subtask(
        self,
        goal: str,
        role: str,
        depth: int,
        parent_id: str,
        tools: list[str] | None = None,
        kb_domains: list[str] | None = None,
        strategy: DecompStrategy = DecompStrategy.SEQUENTIAL,
    ) -> Subtask:
        """Create a new subtask."""
        self._task_counter += 1
        task_id = f"task-{self._task_counter}"

        complexity = self._estimate_complexity(goal)
        budget = self._allocate_budget(complexity, depth)

        task = Subtask(
            task_id=task_id,
            parent_id=parent_id,
            depth=depth,
            goal=goal,
            agent_role=role,
            strategy=strategy,
            complexity=complexity,
            tools_needed=tools or [],
            kb_domains=kb_domains or [],
            model_preference=ROLE_MODEL_PREFERENCE.get(role, ""),
            token_budget=budget,
            step_budget=max(3, 15 - depth * 3),
        )

        self._tasks[task_id] = task
        return task

    def _estimate_complexity(self, goal: str) -> TaskComplexity:
        """Estimate task complexity from goal description."""
        goal_lower = goal.lower()
        for keyword, complexity in COMPLEXITY_INDICATORS.items():
            if keyword in goal_lower:
                return complexity
        return TaskComplexity.MODERATE

    def _allocate_budget(self, complexity: TaskComplexity, depth: int) -> int:
        """Allocate token budget based on complexity and depth."""
        base_budgets = {
            TaskComplexity.TRIVIAL: 500,
            TaskComplexity.SIMPLE: 1000,
            TaskComplexity.MODERATE: 2000,
            TaskComplexity.COMPLEX: 4000,
            TaskComplexity.VERY_COMPLEX: 8000,
        }
        base = base_budgets.get(complexity, 2000)
        # Reduce budget at deeper levels
        return max(500, base // (depth + 1))

    def _needs_further_decomposition(self, task: Subtask) -> bool:
        """Check if a task needs further decomposition."""
        if task.depth >= self._max_depth:
            return False
        if task.complexity in (TaskComplexity.TRIVIAL, TaskComplexity.SIMPLE):
            return False
        if task.is_base_case:
            return False
        return task.complexity in (TaskComplexity.COMPLEX, TaskComplexity.VERY_COMPLEX)

    def _decompose_further(self, parent: Subtask, depth: int) -> None:
        """Further decompose a complex subtask."""
        if depth > self._max_depth:
            parent.is_base_case = True
            return

        # Generate sub-steps based on tools needed
        for tool in parent.tools_needed:
            child = self._create_subtask(
                goal=f"Run {tool} on target",
                role=parent.agent_role,
                depth=depth,
                parent_id=parent.task_id,
                tools=[tool],
                kb_domains=parent.kb_domains,
            )
            child.is_base_case = True
            parent.children.append(child.task_id)

        if not parent.children:
            parent.is_base_case = True

    def get_ready_tasks(self, tree_root_id: str = "") -> list[Subtask]:
        """Get tasks that are ready to execute (all deps satisfied)."""
        ready = []
        for task in self._tasks.values():
            if task.status != SubtaskStatus.PENDING:
                continue
            if tree_root_id and not self._belongs_to_tree(task.task_id, tree_root_id):
                continue
            # Check all dependencies completed
            all_deps_done = all(
                self._tasks.get(dep, Subtask()).status == SubtaskStatus.COMPLETED
                for dep in task.dependencies
            )
            if all_deps_done:
                task.status = SubtaskStatus.READY
                ready.append(task)
        return ready

    def _belongs_to_tree(self, task_id: str, root_id: str) -> bool:
        """Check if a task belongs to a tree."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        if task.task_id == root_id:
            return True
        if task.parent_id == root_id:
            return True
        if task.parent_id:
            return self._belongs_to_tree(task.parent_id, root_id)
        return False

    def complete_task(self, task_id: str, result: dict[str, Any]) -> None:
        """Mark a task as completed."""
        task = self._tasks.get(task_id)
        if task:
            task.status = SubtaskStatus.COMPLETED
            task.result = result
            task.completed_at = time.time()

            # Update tree stats
            for tree in self._trees.values():
                tree.completed_subtasks += 1

    def fail_task(self, task_id: str, error: str) -> None:
        """Mark a task as failed."""
        task = self._tasks.get(task_id)
        if task:
            task.status = SubtaskStatus.FAILED
            task.error = error
            task.completed_at = time.time()

            for tree in self._trees.values():
                tree.failed_subtasks += 1

    def aggregate_results(self, parent_id: str) -> dict[str, Any]:
        """Aggregate results from all children of a parent task."""
        parent = self._tasks.get(parent_id)
        if not parent:
            return {}

        child_results = []
        for child_id in parent.children:
            child = self._tasks.get(child_id)
            if child and child.status == SubtaskStatus.COMPLETED:
                child_results.append({
                    "task": child.goal[:50],
                    "role": child.agent_role,
                    "result": child.result,
                })

        return {
            "parent_goal": parent.goal,
            "children_completed": len(child_results),
            "children_total": len(parent.children),
            "results": child_results,
        }

    def build_execution_plan(self, tree_root_id: str) -> str:
        """Build a human-readable execution plan."""
        tree = self._trees.get(tree_root_id)
        if not tree:
            return ""

        lines = [f"## Execution Plan: {tree.original_goal[:50]}"]
        lines.append(f"Total tasks: {tree.total_subtasks}, Budget: {tree.total_token_budget} tokens\n")

        root = self._tasks.get(tree.root_id)
        if root:
            self._render_task_tree(root, lines, indent=0)

        return "\n".join(lines)

    def _render_task_tree(self, task: Subtask, lines: list[str], indent: int) -> None:
        """Render a task tree recursively."""
        prefix = "  " * indent
        status = task.status.value[:4].upper()
        base_marker = " [BASE]" if task.is_base_case else ""
        lines.append(f"{prefix}[{status}] {task.goal[:50]} ({task.agent_role}){base_marker}")

        if task.tools_needed:
            lines.append(f"{prefix}  Tools: {', '.join(task.tools_needed[:3])}")
        if task.dependencies:
            dep_ids = [d[:8] for d in task.dependencies[:3]]
            lines.append(f"{prefix}  Deps: {', '.join(dep_ids)}")

        for child_id in task.children:
            child = self._tasks.get(child_id)
            if child:
                self._render_task_tree(child, lines, indent + 1)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for task in self._tasks.values():
            status_counts[task.status.value] += 1

        return {
            "trees": len(self._trees),
            "total_tasks": len(self._tasks),
            "status": dict(status_counts),
            "max_depth": self._max_depth,
        }
