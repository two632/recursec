"""Recursive agent spawner — depth-bounded agent hierarchy.

Implements:
1. Recursive agent creation (parent → child → grandchild)
2. Depth limits (configurable max recursion depth)
3. Budget propagation (parent shares budget with children)
4. Result aggregation (children → parent)
5. Agent lineage tracking
6. Spawn strategy selection
7. Spawn context for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SpawnReason(str, Enum):
    DECOMPOSE = "decompose"            # Task needs sub-agents
    SPECIALIZE = "specialize"          # Need specialist agent
    PARALLEL = "parallel"              # Parallel exploration
    VALIDATE = "validate"              # Cross-validation
    EXPLORE = "explore"                # Explore alternative approach
    DEEPEN = "deepen"                  # Go deeper on finding


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    CODE_AUDIT = "code_audit"
    EXPLOIT = "exploit"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    PLANNER = "planner"


class SpawnStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SpawnedAgent:
    """A spawned child agent."""
    agent_id: str = ""
    parent_id: str = ""
    role: AgentRole = AgentRole.COORDINATOR
    depth: int = 0
    reason: SpawnReason = SpawnReason.DECOMPOSE
    status: SpawnStatus = SpawnStatus.PENDING
    task: str = ""
    model_id: str = ""
    token_budget: int = 0
    tokens_used: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    children: list[str] = field(default_factory=list)    # Child agent IDs
    result: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    created_at: float = field(default_factory=time.time)

    @property
    def runtime_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "parent": self.parent_id[:10] if self.parent_id else "root",
            "role": self.role.value[:8],
            "depth": self.depth,
            "status": self.status.value[:6],
            "findings": len(self.findings),
            "children": len(self.children),
        }


# ── Default spawn strategies per role ────────────────────────

SPAWN_STRATEGIES: dict[str, list[dict[str, Any]]] = {
    "full_assessment": [
        {"role": "recon", "reason": "decompose", "task": "Enumerate attack surface"},
        {"role": "vuln_scan", "reason": "decompose", "task": "Scan for vulnerabilities"},
        {"role": "web_audit", "reason": "specialize", "task": "Deep web application audit"},
        {"role": "code_audit", "reason": "specialize", "task": "Source code review"},
        {"role": "exploit", "reason": "decompose", "task": "Validate and exploit findings"},
        {"role": "reporter", "reason": "decompose", "task": "Generate assessment report"},
    ],
    "web_assessment": [
        {"role": "recon", "reason": "decompose", "task": "Web recon and crawling"},
        {"role": "web_audit", "reason": "specialize", "task": "OWASP testing"},
        {"role": "vuln_scan", "reason": "parallel", "task": "Automated scanning"},
        {"role": "validator", "reason": "validate", "task": "Validate findings"},
    ],
    "network_assessment": [
        {"role": "recon", "reason": "decompose", "task": "Network enumeration"},
        {"role": "vuln_scan", "reason": "decompose", "task": "Port and service scanning"},
        {"role": "exploit", "reason": "specialize", "task": "Exploit network services"},
    ],
    "validation": [
        {"role": "validator", "reason": "validate", "task": "Cross-validate finding"},
        {"role": "exploit", "reason": "deepen", "task": "Attempt exploitation"},
    ],
}

# Model assignments per role
ROLE_MODEL_PREFERENCE: dict[AgentRole, list[str]] = {
    AgentRole.COORDINATOR: ["Hermes-4-14B", "DeepSeek-R1"],
    AgentRole.RECON: ["Mistral-7B", "Llama-3.1-8B"],
    AgentRole.VULN_SCAN: ["WhiteRabbitNeo-7B", "Qwen2.5-Coder-7B"],
    AgentRole.WEB_AUDIT: ["WhiteRabbitNeo-7B", "Qwen2.5-Coder-14B"],
    AgentRole.CODE_AUDIT: ["Qwen2.5-Coder-14B", "CodeLlama-13B"],
    AgentRole.EXPLOIT: ["WhiteRabbitNeo-7B", "Dolphin-2.9"],
    AgentRole.VALIDATOR: ["DeepSeek-R1", "Hermes-4-14B"],
    AgentRole.REPORTER: ["Mistral-7B", "Llama-3.1-8B"],
    AgentRole.PLANNER: ["DeepSeek-R1", "Yi-9B-200K"],
}


class RecursiveSpawner:
    """Manages recursive agent spawning with depth limits.

    Parent agents spawn children, children spawn grandchildren,
    up to a configurable max depth. Budgets are propagated
    down and results aggregated up.
    """

    def __init__(
        self,
        max_depth: int = 4,
        max_children: int = 8,
        default_budget: int = 50000,
    ) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._max_depth = max_depth
        self._max_children = max_children
        self._default_budget = default_budget
        self._counter = 0
        self._log = logger.bind(component="recursive_spawner")

    def spawn(
        self,
        parent_id: str,
        role: AgentRole,
        task: str,
        reason: SpawnReason = SpawnReason.DECOMPOSE,
        model_id: str = "",
        token_budget: int = 0,
    ) -> SpawnedAgent | None:
        """Spawn a child agent."""
        parent = self._agents.get(parent_id)
        parent_depth = parent.depth if parent else -1

        # Check depth limit
        if parent_depth + 1 >= self._max_depth:
            self._log.warning(
                "max_depth_reached",
                parent=parent_id,
                depth=parent_depth + 1,
            )
            return None

        # Check children limit
        if parent and len(parent.children) >= self._max_children:
            self._log.warning(
                "max_children_reached",
                parent=parent_id,
                children=len(parent.children),
            )
            return None

        # Determine model
        if not model_id:
            prefs = ROLE_MODEL_PREFERENCE.get(role, [])
            model_id = prefs[0] if prefs else "Mistral-7B"

        # Determine budget
        if not token_budget:
            if parent:
                remaining = parent.token_budget - parent.tokens_used
                token_budget = remaining // (self._max_children - len(parent.children))
            else:
                token_budget = self._default_budget

        self._counter += 1
        agent = SpawnedAgent(
            agent_id=f"agent-{self._counter}",
            parent_id=parent_id,
            role=role,
            depth=parent_depth + 1,
            reason=reason,
            task=task,
            model_id=model_id,
            token_budget=token_budget,
        )

        self._agents[agent.agent_id] = agent
        if parent:
            parent.children.append(agent.agent_id)

        return agent

    def spawn_strategy(
        self,
        parent_id: str,
        strategy_name: str,
    ) -> list[SpawnedAgent]:
        """Spawn agents according to a named strategy."""
        strategy = SPAWN_STRATEGIES.get(strategy_name, [])
        spawned: list[SpawnedAgent] = []

        for spec in strategy:
            try:
                role = AgentRole(spec["role"])
                reason = SpawnReason(spec["reason"])
            except ValueError:
                continue

            agent = self.spawn(
                parent_id=parent_id,
                role=role,
                task=spec.get("task", ""),
                reason=reason,
            )
            if agent:
                spawned.append(agent)

        return spawned

    def start_agent(self, agent_id: str) -> bool:
        """Mark agent as running."""
        agent = self._agents.get(agent_id)
        if not agent or agent.status != SpawnStatus.PENDING:
            return False
        agent.status = SpawnStatus.RUNNING
        agent.started_at = time.time()
        return True

    def complete_agent(
        self,
        agent_id: str,
        findings: list[dict[str, Any]] | None = None,
        result: dict[str, Any] | None = None,
    ) -> bool:
        """Mark agent as completed with results."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.status = SpawnStatus.COMPLETED
        agent.completed_at = time.time()
        agent.findings = findings or []
        agent.result = result or {}
        return True

    def fail_agent(self, agent_id: str, reason: str = "") -> bool:
        """Mark agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.status = SpawnStatus.FAILED
        agent.completed_at = time.time()
        agent.result = {"error": reason}
        return True

    def aggregate_results(self, parent_id: str) -> dict[str, Any]:
        """Aggregate results from all children of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return {}

        all_findings: list[dict[str, Any]] = []
        child_results: list[dict[str, Any]] = []
        completed = 0
        failed = 0

        for child_id in parent.children:
            child = self._agents.get(child_id)
            if not child:
                continue
            if child.status == SpawnStatus.COMPLETED:
                completed += 1
                all_findings.extend(child.findings)
                child_results.append({
                    "agent": child.agent_id,
                    "role": child.role.value,
                    "findings": len(child.findings),
                    "runtime": child.runtime_s,
                })
            elif child.status == SpawnStatus.FAILED:
                failed += 1

        return {
            "children": len(parent.children),
            "completed": completed,
            "failed": failed,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "child_results": child_results,
        }

    def get_lineage(self, agent_id: str) -> list[str]:
        """Get full lineage (root → ... → agent)."""
        lineage: list[str] = []
        current = agent_id
        while current:
            lineage.insert(0, current)
            agent = self._agents.get(current)
            if not agent or not agent.parent_id:
                break
            current = agent.parent_id
        return lineage

    def build_spawn_prompt(self, agent_id: str = "") -> str:
        """Build spawner context for LLM."""
        lines = ["## Agent Hierarchy\n"]

        lines.append(
            f"Active agents: {len(self._agents)} | "
            f"Max depth: {self._max_depth} | "
            f"Max children: {self._max_children}"
        )

        # Status summary
        status_counts: dict[str, int] = {}
        for a in self._agents.values():
            status_counts[a.status.value] = status_counts.get(a.status.value, 0) + 1
        lines.append("Status: " + " ".join(f"{k}={v}" for k, v in status_counts.items()))

        # If specific agent, show its context
        if agent_id and agent_id in self._agents:
            agent = self._agents[agent_id]
            lineage = self.get_lineage(agent_id)
            lines.append(f"\nAgent: {agent_id[:10]} (depth={agent.depth})")
            lines.append(f"Role: {agent.role.value} | Model: {agent.model_id[:15]}")
            lines.append(f"Budget: {agent.tokens_used}/{agent.token_budget} tokens")
            lines.append(f"Lineage: {' → '.join(a[:8] for a in lineage)}")

            if agent.children:
                lines.append(f"Children ({len(agent.children)}):")
                for cid in agent.children[:5]:
                    child = self._agents.get(cid)
                    if child:
                        lines.append(
                            f"  {cid[:8]} [{child.role.value[:6]}] "
                            f"{child.status.value} ({len(child.findings)} findings)"
                        )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        role_counts: dict[str, int] = {}
        for a in self._agents.values():
            role_counts[a.role.value] = role_counts.get(a.role.value, 0) + 1

        max_depth = max((a.depth for a in self._agents.values()), default=0)

        return {
            "total_agents": len(self._agents),
            "max_depth_used": max_depth,
            "by_role": role_counts,
            "total_findings": sum(len(a.findings) for a in self._agents.values()),
        }
