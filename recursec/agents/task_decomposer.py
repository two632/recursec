"""Recursive task decomposition — breaks complex tasks into atomic operations.

Implements recursive decomposition with:
1. Top-down goal splitting (divide and conquer)
2. Dependency detection between subtasks
3. Atomic task identification (no further decomposition needed)
4. Depth-limited recursion with convergence
5. Task merging (combine related subtasks)
6. Dynamic re-decomposition when tasks fail
7. Cost estimation at each level
8. Parallel group identification

Decomposition strategies:
- Functional: Break by function (recon, scan, exploit)
- Component: Break by target component
- Technique: Break by attack technique
- Phase: Break by assessment phase
- Hybrid: Combine multiple strategies
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class DecompStrategy(str, Enum):
    FUNCTIONAL = "functional"
    COMPONENT = "component"
    TECHNIQUE = "technique"
    PHASE = "phase"
    HYBRID = "hybrid"


class TaskAtomicity(str, Enum):
    COMPOSITE = "composite"   # Can be decomposed further
    ATOMIC = "atomic"         # Cannot be decomposed further
    LEAF = "leaf"             # Chosen to not decompose (even though possible)


@dataclass
class DecomposedTask:
    """A task in the decomposition tree."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    depth: int = 0
    atomicity: TaskAtomicity = TaskAtomicity.COMPOSITE
    agent_role: str = ""
    tools: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    parallel_group: int = 0
    estimated_time_s: float = 60.0
    estimated_tokens: int = 5000
    priority: int = 5
    target: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"

    @property
    def is_atomic(self) -> bool:
        return self.atomicity in (TaskAtomicity.ATOMIC, TaskAtomicity.LEAF)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "name": self.name[:100],
            "depth": self.depth, "atomic": self.is_atomic,
            "agent": self.agent_role,
            "children": len(self.children),
            "deps": self.dependencies,
            "group": self.parallel_group,
            "status": self.status,
        }


@dataclass
class DecompositionTree:
    """The full decomposition tree."""
    root_id: str = ""
    tasks: dict[str, DecomposedTask] = field(default_factory=dict)
    max_depth: int = 0
    total_tasks: int = 0
    atomic_tasks: int = 0
    strategy: DecompStrategy = DecompStrategy.HYBRID

    def get_root(self) -> DecomposedTask | None:
        return self.tasks.get(self.root_id)

    def get_children(self, task_id: str) -> list[DecomposedTask]:
        task = self.tasks.get(task_id)
        if not task:
            return []
        return [self.tasks[cid] for cid in task.children if cid in self.tasks]

    def get_atomic_tasks(self) -> list[DecomposedTask]:
        return [t for t in self.tasks.values() if t.is_atomic]

    def get_ready_tasks(self) -> list[DecomposedTask]:
        """Get atomic tasks whose dependencies are all completed."""
        ready = []
        for task in self.get_atomic_tasks():
            if task.status != "pending":
                continue
            deps_met = all(
                self.tasks.get(dep, DecomposedTask()).status == "completed"
                for dep in task.dependencies
            )
            if deps_met:
                ready.append(task)
        return ready

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root_id,
            "total": self.total_tasks,
            "atomic": self.atomic_tasks,
            "max_depth": self.max_depth,
            "strategy": self.strategy.value,
        }


# ── Prompt Templates ────────────────────────────────────────

DECOMPOSE_PROMPT = """Break down this security task into subtasks.

Task: {task}
Target: {target}
Current depth: {depth}/{max_depth}
Strategy: {strategy}
Context: {context}

Rules:
- Each subtask should be more specific than the parent
- Mark tasks as "atomic" if they can be directly executed by a tool or agent
- Mark tasks as "composite" if they need further decomposition
- Identify dependencies between tasks
- Group independent tasks for parallel execution

Respond as JSON:
{{
  "subtasks": [
    {{
      "name": "task name",
      "description": "what to do",
      "atomicity": "atomic|composite",
      "agent_role": "recon|vuln_scan|exploit|code_audit|network|osint|web_scan|validator",
      "tools": ["tool names if atomic"],
      "dependencies": [0, 1],
      "parallel_group": 0,
      "estimated_time_s": 60,
      "priority": 1-10
    }}
  ]
}}"""


class TaskDecomposer:
    """Recursively decomposes complex tasks into atomic operations.

    Uses LLM reasoning to intelligently split tasks, identify
    dependencies, and organize for parallel execution.
    """

    def __init__(
        self,
        model_router: ModelRouter | None = None,
        max_depth: int = 4,
        max_children: int = 8,
    ) -> None:
        self._router = model_router
        self._max_depth = max_depth
        self._max_children = max_children
        self._trees: dict[str, DecompositionTree] = {}
        self._log = logger.bind(component="task_decomposer")

    async def decompose(
        self,
        task: str,
        target: str = "",
        strategy: DecompStrategy = DecompStrategy.HYBRID,
        context: dict[str, Any] | None = None,
    ) -> DecompositionTree:
        """Recursively decompose a task into a tree."""
        tree = DecompositionTree(strategy=strategy)

        # Create root task
        root = DecomposedTask(
            name=task,
            description=task,
            depth=0,
            atomicity=TaskAtomicity.COMPOSITE,
            target=target,
            context=context or {},
        )
        tree.root_id = root.task_id
        tree.tasks[root.task_id] = root

        # Recursively decompose
        await self._decompose_recursive(tree, root, target, strategy, context or {})

        # Calculate stats
        tree.total_tasks = len(tree.tasks)
        tree.atomic_tasks = len(tree.get_atomic_tasks())
        tree.max_depth = max((t.depth for t in tree.tasks.values()), default=0)

        # Assign parallel groups globally
        self._assign_parallel_groups(tree)

        self._trees[tree.root_id] = tree
        self._log.info(
            "decomposition_complete",
            total=tree.total_tasks,
            atomic=tree.atomic_tasks,
            depth=tree.max_depth,
        )

        return tree

    async def _decompose_recursive(
        self,
        tree: DecompositionTree,
        task: DecomposedTask,
        target: str,
        strategy: DecompStrategy,
        context: dict[str, Any],
    ) -> None:
        """Recursively decompose a composite task."""
        if task.depth >= self._max_depth:
            task.atomicity = TaskAtomicity.LEAF
            return

        if task.atomicity == TaskAtomicity.ATOMIC:
            return

        # Decompose using LLM or heuristics
        if self._router:
            subtasks_data = await self._llm_decompose(task, target, strategy, context)
        else:
            subtasks_data = self._heuristic_decompose(task, strategy)

        if not subtasks_data:
            task.atomicity = TaskAtomicity.LEAF
            return

        # Create child tasks
        child_ids: list[str] = []
        for sub_data in subtasks_data[:self._max_children]:
            try:
                atomicity = TaskAtomicity(sub_data.get("atomicity", "atomic"))
            except ValueError:
                atomicity = TaskAtomicity.ATOMIC

            child = DecomposedTask(
                name=sub_data.get("name", ""),
                description=sub_data.get("description", ""),
                parent_id=task.task_id,
                depth=task.depth + 1,
                atomicity=atomicity,
                agent_role=sub_data.get("agent_role", ""),
                tools=sub_data.get("tools", []),
                parallel_group=sub_data.get("parallel_group", 0),
                estimated_time_s=sub_data.get("estimated_time_s", 60),
                estimated_tokens=sub_data.get("estimated_tokens", 5000),
                priority=sub_data.get("priority", 5),
                target=target,
            )

            # Resolve dependencies (indices to task IDs)
            dep_indices = sub_data.get("dependencies", [])
            for idx in dep_indices:
                if isinstance(idx, int) and 0 <= idx < len(child_ids):
                    child.dependencies.append(child_ids[idx])

            tree.tasks[child.task_id] = child
            child_ids.append(child.task_id)

        task.children = child_ids

        # Recurse into composite children
        for child_id in child_ids:
            child = tree.tasks[child_id]
            if child.atomicity == TaskAtomicity.COMPOSITE:
                await self._decompose_recursive(tree, child, target, strategy, context)

    async def _llm_decompose(
        self,
        task: DecomposedTask,
        target: str,
        strategy: DecompStrategy,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Use LLM to decompose a task."""
        if not self._router:
            return []

        prompt = DECOMPOSE_PROMPT.format(
            task=task.name,
            target=target,
            depth=task.depth,
            max_depth=self._max_depth,
            strategy=strategy.value,
            context=json.dumps(context)[:500],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        return data.get("subtasks", [])

    def _heuristic_decompose(
        self,
        task: DecomposedTask,
        strategy: DecompStrategy,
    ) -> list[dict[str, Any]]:
        """Heuristic decomposition when no LLM is available."""
        task_lower = task.name.lower()

        # Phase-based decomposition
        if "assessment" in task_lower or "pentest" in task_lower:
            return [
                {"name": "Reconnaissance", "agent_role": "recon", "atomicity": "composite", "parallel_group": 0},
                {"name": "Enumeration", "agent_role": "recon", "atomicity": "composite",
                 "parallel_group": 0, "dependencies": [0]},
                {"name": "Vulnerability scanning", "agent_role": "vuln_scan", "atomicity": "composite",
                 "parallel_group": 1, "dependencies": [1]},
                {"name": "Exploitation", "agent_role": "exploit", "atomicity": "composite",
                 "dependencies": [2]},
                {"name": "Reporting", "agent_role": "validator", "atomicity": "atomic",
                 "dependencies": [3]},
            ]

        # Recon decomposition
        if "recon" in task_lower:
            return [
                {"name": "Subdomain enumeration", "agent_role": "recon", "atomicity": "atomic",
                 "tools": ["subfinder", "amass"], "parallel_group": 0},
                {"name": "Port scanning", "agent_role": "recon", "atomicity": "atomic",
                 "tools": ["nmap", "masscan"], "parallel_group": 0},
                {"name": "Technology fingerprinting", "agent_role": "recon", "atomicity": "atomic",
                 "tools": ["whatweb", "httpx"], "parallel_group": 0},
            ]

        # Default: make it atomic
        return [
            {"name": task.name, "agent_role": task.agent_role or "recon",
             "atomicity": "atomic", "tools": task.tools},
        ]

    def _assign_parallel_groups(self, tree: DecompositionTree) -> None:
        """Assign global parallel groups based on dependencies."""
        group_counter = 0
        tasks_by_depth: dict[int, list[DecomposedTask]] = defaultdict(list)

        for task in tree.tasks.values():
            if task.is_atomic:
                tasks_by_depth[task.depth].append(task)

        for depth in sorted(tasks_by_depth.keys()):
            tasks = tasks_by_depth[depth]
            # Group tasks with no dependencies on each other
            dep_groups: dict[str, list[DecomposedTask]] = defaultdict(list)
            for task in tasks:
                dep_key = "|".join(sorted(task.dependencies))
                dep_groups[dep_key].append(task)

            for group_tasks in dep_groups.values():
                for task in group_tasks:
                    task.parallel_group = group_counter
                group_counter += 1

    def redecompose_failed(
        self,
        tree: DecompositionTree,
        failed_task_id: str,
    ) -> list[DecomposedTask]:
        """Re-decompose a failed task with different strategy."""
        failed = tree.tasks.get(failed_task_id)
        if not failed:
            return []

        # Mark as composite for re-decomposition
        failed.atomicity = TaskAtomicity.COMPOSITE
        failed.status = "pending"
        failed.children = []

        # Create simpler atomic alternatives
        alternatives = [
            DecomposedTask(
                name=f"{failed.name} (retry with simpler approach)",
                description=f"Simplified retry of: {failed.description[:100]}",
                parent_id=failed.task_id,
                depth=failed.depth + 1,
                atomicity=TaskAtomicity.ATOMIC,
                agent_role=failed.agent_role,
                tools=failed.tools[:1],
                target=failed.target,
            ),
        ]

        for alt in alternatives:
            tree.tasks[alt.task_id] = alt
            failed.children.append(alt.task_id)

        return alternatives

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        total_trees = len(self._trees)
        total_tasks = sum(t.total_tasks for t in self._trees.values())
        return {
            "trees": total_trees,
            "total_tasks": total_tasks,
            "max_depth": self._max_depth,
        }
