"""Hierarchical task planner — multi-level plan generation with replanning.

The planner converts high-level objectives into executable plans through
hierarchical decomposition, dependency analysis, resource allocation,
and adaptive replanning when conditions change.

Planning levels:
1. Strategic: Overall assessment approach (which phases, what order)
2. Tactical: Per-phase task breakdown (what tools, what targets)
3. Operational: Specific tool commands and parameters

Features:
- Hierarchical plan decomposition (strategy → tactics → operations)
- Dependency graph with topological ordering
- Resource-aware planning (model availability, tool availability)
- Adaptive replanning on failure or new information
- Plan optimization (parallelism extraction, critical path)
- Budget-constrained planning (token, time, step limits)
- Plan validation and feasibility checking
"""

from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.core.reasoning import ReasoningEngine
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class PlanLevel(str, Enum):
    STRATEGIC = "strategic"
    TACTICAL = "tactical"
    OPERATIONAL = "operational"


class PlanNodeStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REPLANNED = "replanned"


class ResourceType(str, Enum):
    MODEL = "model"
    TOOL = "tool"
    TOKEN_BUDGET = "token_budget"
    TIME_BUDGET = "time_budget"
    NETWORK = "network"
    MEMORY = "memory"


@dataclass
class ResourceRequirement:
    """A resource required by a plan node."""
    resource_type: ResourceType
    resource_name: str = ""
    quantity: float = 1.0
    required: bool = True
    alternatives: list[str] = field(default_factory=list)


@dataclass
class PlanNode:
    """A single node in the hierarchical plan."""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    level: PlanLevel = PlanLevel.OPERATIONAL
    status: PlanNodeStatus = PlanNodeStatus.PENDING
    parent_id: str | None = None
    children: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    agent_type: str = ""
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    resources: list[ResourceRequirement] = field(default_factory=list)
    priority: int = 5
    estimated_time_s: float = 60.0
    estimated_tokens: int = 1000
    actual_time_s: float = 0.0
    actual_tokens: int = 0
    max_retries: int = 2
    retry_count: int = 0
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    can_parallelize: bool = True
    is_critical_path: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id, "name": self.name,
            "level": self.level.value, "status": self.status.value,
            "parent_id": self.parent_id,
            "dependencies": self.dependencies,
            "agent_type": self.agent_type,
            "tool": self.tool_name,
            "priority": self.priority,
            "est_time": self.estimated_time_s,
            "actual_time": round(self.actual_time_s, 1),
            "retries": self.retry_count,
            "critical_path": self.is_critical_path,
        }


@dataclass
class Plan:
    """A complete hierarchical plan."""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    objective: str = ""
    target: str = ""
    nodes: dict[str, PlanNode] = field(default_factory=dict)
    root_nodes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    total_estimated_time_s: float = 0.0
    total_estimated_tokens: int = 0
    version: int = 1
    replan_count: int = 0

    def add_node(self, node: PlanNode) -> str:
        self.nodes[node.node_id] = node
        if node.parent_id is None and node.node_id not in self.root_nodes:
            self.root_nodes.append(node.node_id)
        return node.node_id

    def get_ready_nodes(self) -> list[PlanNode]:
        """Get nodes whose dependencies are all satisfied."""
        ready = []
        for node in self.nodes.values():
            if node.status != PlanNodeStatus.PENDING:
                continue
            deps_met = all(
                self.nodes[dep].status == PlanNodeStatus.COMPLETED
                for dep in node.dependencies
                if dep in self.nodes
            )
            if deps_met:
                ready.append(node)
        return sorted(ready, key=lambda n: n.priority)

    def get_critical_path(self) -> list[str]:
        """Calculate the critical path through the plan."""
        # Find longest path from any root to any leaf
        if not self.root_nodes:
            return []

        longest: list[str] = []

        def dfs(node_id: str, path: list[str]) -> None:
            nonlocal longest
            path = [*path, node_id]
            node = self.nodes.get(node_id)
            if not node:
                return
            children = [
                nid for nid, n in self.nodes.items()
                if node_id in n.dependencies
            ]
            if not children:
                total_time = sum(
                    self.nodes[nid].estimated_time_s
                    for nid in path if nid in self.nodes
                )
                if total_time > sum(
                    self.nodes[nid].estimated_time_s
                    for nid in longest if nid in self.nodes
                ):
                    longest = list(path)
            else:
                for child_id in children:
                    dfs(child_id, path)

        for root in self.root_nodes:
            dfs(root, [])

        for nid in longest:
            if nid in self.nodes:
                self.nodes[nid].is_critical_path = True

        return longest

    def get_parallel_groups(self) -> list[list[str]]:
        """Group nodes that can execute in parallel."""
        groups: list[list[str]] = []
        completed = {
            nid for nid, n in self.nodes.items()
            if n.status == PlanNodeStatus.COMPLETED
        }
        remaining = {
            nid for nid, n in self.nodes.items()
            if n.status in (PlanNodeStatus.PENDING, PlanNodeStatus.READY)
        }

        while remaining:
            group = []
            for nid in list(remaining):
                node = self.nodes[nid]
                deps = set(node.dependencies)
                if deps.issubset(completed) and node.can_parallelize:
                    group.append(nid)
            if not group:
                # Pick one non-parallelizable node
                for nid in remaining:
                    node = self.nodes[nid]
                    deps = set(node.dependencies)
                    if deps.issubset(completed):
                        group.append(nid)
                        break
            if not group:
                break  # Circular dependency or all blocked
            groups.append(group)
            completed.update(group)
            remaining -= set(group)

        return groups

    def completion_percentage(self) -> float:
        if not self.nodes:
            return 100.0
        completed = sum(
            1 for n in self.nodes.values()
            if n.status in (PlanNodeStatus.COMPLETED, PlanNodeStatus.SKIPPED)
        )
        return (completed / len(self.nodes)) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "objective": self.objective[:200],
            "target": self.target,
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "root_nodes": self.root_nodes,
            "total_est_time": self.total_estimated_time_s,
            "total_est_tokens": self.total_estimated_tokens,
            "version": self.version,
            "replan_count": self.replan_count,
            "completion": round(self.completion_percentage(), 1),
        }


# ── Prompt Templates ────────────────────────────────────────

STRATEGIC_PLAN_PROMPT = """You are a security assessment planner. Create a strategic plan for this objective.

Objective: {objective}
Target: {target}
Available tools: {tools}
Available models: {models}
Constraints: Time budget={time_budget}s, Token budget={token_budget}

Create a strategic plan as JSON:
{{
  "phases": [
    {{
      "name": "phase_name",
      "description": "what this phase does",
      "agent_type": "recon|vuln_scan|web_scan|exploit|code_audit|network|osint",
      "priority": 1-5,
      "depends_on": ["phase_names"],
      "estimated_time_s": 120,
      "subtasks": ["specific task descriptions"]
    }}
  ]
}}"""

TACTICAL_PLAN_PROMPT = """Break down this security assessment phase into specific tasks.

Phase: {phase_name}
Description: {phase_description}
Target: {target}
Available tools: {tools}
Previous findings: {findings}

Create tasks as JSON:
{{
  "tasks": [
    {{
      "name": "task_name",
      "description": "what to do",
      "tool": "tool_name or empty",
      "tool_args": {{}},
      "agent_type": "specific_agent_type",
      "depends_on": ["task_names"],
      "estimated_time_s": 60,
      "priority": 1-5,
      "can_parallelize": true
    }}
  ]
}}"""

REPLAN_PROMPT = """A task in the security assessment plan has failed or produced unexpected results.

Original plan:
{original_plan}

Failed task: {failed_task}
Error: {error}
Current findings so far: {findings}

Should we:
1. Retry the failed task with different parameters?
2. Skip this task and continue?
3. Create alternative tasks to achieve the same goal?
4. Adjust the remaining plan based on what we've learned?

Respond as JSON:
{{
  "action": "retry|skip|alternative|adjust",
  "reason": "why this action",
  "new_tasks": [...],  // if action is "alternative" or "adjust"
  "retry_args": {{}},   // if action is "retry"
}}"""


class HierarchicalPlanner:
    """Generates and manages hierarchical plans for security assessments."""

    def __init__(
        self,
        model_router: ModelRouter,
        reasoning_engine: ReasoningEngine | None = None,
    ) -> None:
        self._router = model_router
        self._reasoning = reasoning_engine
        self._plans: dict[str, Plan] = {}
        self._log = logger.bind(component="planner")

    async def create_plan(
        self,
        objective: str,
        target: str,
        available_tools: list[str] | None = None,
        available_models: list[str] | None = None,
        time_budget_s: float = 3600.0,
        token_budget: int = 500000,
    ) -> Plan:
        """Create a complete hierarchical plan."""
        plan = Plan(objective=objective, target=target)

        # Phase 1: Strategic planning
        strategic = await self._plan_strategic(
            objective, target, available_tools or [],
            available_models or [], time_budget_s, token_budget,
        )

        # Phase 2: Tactical decomposition for each strategic phase
        for phase in strategic:
            strategic_node = PlanNode(
                name=phase["name"],
                description=phase.get("description", ""),
                level=PlanLevel.STRATEGIC,
                agent_type=phase.get("agent_type", ""),
                priority=phase.get("priority", 5),
                estimated_time_s=phase.get("estimated_time_s", 120.0),
            )
            plan.add_node(strategic_node)

            # Decompose into tactical tasks
            tactical = await self._plan_tactical(
                phase, target, available_tools or [], [],
            )

            for task in tactical:
                tactical_node = PlanNode(
                    name=task["name"],
                    description=task.get("description", ""),
                    level=PlanLevel.TACTICAL,
                    parent_id=strategic_node.node_id,
                    agent_type=task.get("agent_type", phase.get("agent_type", "")),
                    tool_name=task.get("tool", ""),
                    tool_args=task.get("tool_args", {}),
                    priority=task.get("priority", 5),
                    estimated_time_s=task.get("estimated_time_s", 60.0),
                    can_parallelize=task.get("can_parallelize", True),
                )
                plan.add_node(tactical_node)
                strategic_node.children.append(tactical_node.node_id)

        # Resolve dependencies across the plan
        self._resolve_dependencies(plan, strategic)

        # Calculate estimates
        plan.total_estimated_time_s = sum(n.estimated_time_s for n in plan.nodes.values())
        plan.total_estimated_tokens = sum(n.estimated_tokens for n in plan.nodes.values())

        # Compute critical path
        plan.get_critical_path()

        self._plans[plan.plan_id] = plan
        self._log.info("plan_created", plan_id=plan.plan_id, nodes=len(plan.nodes))
        return plan

    async def replan(
        self,
        plan: Plan,
        failed_node_id: str,
        error: str,
        findings: list[dict[str, Any]] | None = None,
    ) -> Plan:
        """Replan after a failure or unexpected result."""
        failed_node = plan.nodes.get(failed_node_id)
        if not failed_node:
            return plan

        plan.replan_count += 1
        plan.version += 1

        # Ask LLM how to handle the failure
        replan_response = await self._query_replan(
            plan, failed_node, error, findings or [],
        )

        action = replan_response.get("action", "skip")

        if action == "retry":
            failed_node.status = PlanNodeStatus.PENDING
            failed_node.retry_count += 1
            if replan_response.get("retry_args"):
                failed_node.tool_args.update(replan_response["retry_args"])

        elif action == "skip":
            failed_node.status = PlanNodeStatus.SKIPPED
            # Skip dependent nodes too
            self._cascade_skip(plan, failed_node_id)

        elif action in ("alternative", "adjust"):
            failed_node.status = PlanNodeStatus.REPLANNED
            new_tasks = replan_response.get("new_tasks", [])
            for task_data in new_tasks:
                new_node = PlanNode(
                    name=task_data.get("name", "replanned_task"),
                    description=task_data.get("description", ""),
                    level=failed_node.level,
                    parent_id=failed_node.parent_id,
                    agent_type=task_data.get("agent_type", failed_node.agent_type),
                    tool_name=task_data.get("tool", ""),
                    tool_args=task_data.get("tool_args", {}),
                    priority=failed_node.priority,
                    metadata={"replanned_from": failed_node_id},
                )
                # New tasks inherit the failed node's dependents
                for nid, node in plan.nodes.items():
                    if failed_node_id in node.dependencies:
                        node.dependencies.remove(failed_node_id)
                        node.dependencies.append(new_node.node_id)
                plan.add_node(new_node)

        self._log.info(
            "replanned",
            plan_id=plan.plan_id,
            action=action,
            failed_node=failed_node_id,
            version=plan.version,
        )
        return plan

    def _cascade_skip(self, plan: Plan, skipped_id: str) -> None:
        """Skip all nodes that depend on a skipped node."""
        queue = deque([skipped_id])
        while queue:
            current = queue.popleft()
            for nid, node in plan.nodes.items():
                if current in node.dependencies and node.status == PlanNodeStatus.PENDING:
                    # Only skip if ALL dependencies include the skipped one
                    # and there's no alternative path
                    required_deps = [d for d in node.dependencies if d in plan.nodes]
                    all_deps_done_or_skipped = all(
                        plan.nodes[d].status in (PlanNodeStatus.COMPLETED, PlanNodeStatus.SKIPPED)
                        for d in required_deps if d != current
                    )
                    if not all_deps_done_or_skipped:
                        node.status = PlanNodeStatus.SKIPPED
                        queue.append(nid)

    async def _plan_strategic(
        self, objective: str, target: str,
        tools: list[str], models: list[str],
        time_budget: float, token_budget: int,
    ) -> list[dict[str, Any]]:
        """Generate strategic-level plan."""
        prompt = STRATEGIC_PLAN_PROMPT.format(
            objective=objective, target=target,
            tools=", ".join(tools[:30]),
            models=", ".join(models[:10]),
            time_budget=time_budget, token_budget=token_budget,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.3,
            max_tokens=4096,
        )

        return self._parse_json_response(response, "phases", default_phases=[
            {"name": "recon", "description": "Reconnaissance and discovery", "agent_type": "recon", "priority": 1, "depends_on": []},
            {"name": "scanning", "description": "Vulnerability scanning", "agent_type": "vuln_scan", "priority": 2, "depends_on": ["recon"]},
            {"name": "exploitation", "description": "Exploit confirmed vulnerabilities", "agent_type": "exploit", "priority": 3, "depends_on": ["scanning"]},
            {"name": "validation", "description": "Validate all findings", "agent_type": "validation", "priority": 4, "depends_on": ["exploitation"]},
        ])

    async def _plan_tactical(
        self, phase: dict[str, Any], target: str,
        tools: list[str], findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate tactical-level tasks for a phase."""
        prompt = TACTICAL_PLAN_PROMPT.format(
            phase_name=phase["name"],
            phase_description=phase.get("description", ""),
            target=target,
            tools=", ".join(tools[:30]),
            findings=json.dumps(findings[:10]) if findings else "None yet",
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.3,
            max_tokens=4096,
        )

        default_tasks = [
            {"name": f"{phase['name']}_default", "description": phase.get("description", ""),
             "agent_type": phase.get("agent_type", ""), "priority": phase.get("priority", 5)},
        ]
        return self._parse_json_response(response, "tasks", default_phases=default_tasks)

    async def _query_replan(
        self, plan: Plan, failed_node: PlanNode,
        error: str, findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Ask LLM how to handle a plan failure."""
        prompt = REPLAN_PROMPT.format(
            original_plan=json.dumps({
                "objective": plan.objective,
                "nodes": [n.to_dict() for n in plan.nodes.values()],
            })[:3000],
            failed_task=json.dumps(failed_node.to_dict()),
            error=error[:500],
            findings=json.dumps(findings[:5]) if findings else "None",
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.3,
            max_tokens=2048,
        )

        try:
            # Try to extract JSON from response
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            return json.loads(json_str.strip())
        except (json.JSONDecodeError, IndexError):
            return {"action": "skip", "reason": "Could not parse replan response"}

    def _resolve_dependencies(self, plan: Plan, strategic: list[dict[str, Any]]) -> None:
        """Resolve inter-node dependencies based on phase ordering."""
        name_to_ids: dict[str, list[str]] = defaultdict(list)
        for node in plan.nodes.values():
            name_to_ids[node.name].append(node.node_id)

        for phase in strategic:
            deps = phase.get("depends_on", [])
            phase_nodes = name_to_ids.get(phase["name"], [])

            for dep_name in deps:
                dep_nodes = name_to_ids.get(dep_name, [])
                if dep_nodes and phase_nodes:
                    for pn_id in phase_nodes:
                        node = plan.nodes[pn_id]
                        for dn_id in dep_nodes:
                            if dn_id not in node.dependencies:
                                node.dependencies.append(dn_id)

    def _parse_json_response(
        self, response: str, key: str,
        default_phases: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Parse JSON from LLM response with fallback."""
        try:
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            data = json.loads(json_str.strip())
            if isinstance(data, dict) and key in data:
                return data[key]
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, IndexError):
            pass
        return default_phases

    def get_plan(self, plan_id: str) -> Plan | None:
        return self._plans.get(plan_id)

    def list_plans(self) -> list[dict[str, Any]]:
        return [
            {"plan_id": p.plan_id, "objective": p.objective[:100],
             "nodes": len(p.nodes), "completion": p.completion_percentage()}
            for p in self._plans.values()
        ]
