"""Recursive agent spawner — bounded recursive agent hierarchy.

Implements the core recursive multi-agent pattern:
1. Parent agents decompose goals into sub-goals
2. Child agents are dynamically instantiated with specific roles
3. Budget decay (70% per level) prevents runaway recursion
4. Max depth limits (default 5 levels)
5. Agent pools for reuse of common agent types
6. Result aggregation from children to parent
7. Timeout enforcement per agent
8. State tracking across recursion levels
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    CODE_AUDITOR = "code_auditor"
    NETWORK_ANALYST = "network_analyst"
    OSINT = "osint"
    CLOUD_ANALYST = "cloud_analyst"
    SUPPLY_CHAIN = "supply_chain"
    REASONING = "reasoning"
    PLANNING = "planning"


class SpawnStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class AgentBudget:
    """Resource budget for an agent."""
    max_tokens: int = 50000
    max_time_s: float = 600.0
    max_tool_calls: int = 20
    max_llm_queries: int = 10
    max_child_agents: int = 5
    tokens_used: int = 0
    time_used_s: float = 0.0
    tool_calls_used: int = 0
    llm_queries_used: int = 0
    children_spawned: int = 0

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    @property
    def time_remaining_s(self) -> float:
        return max(0, self.max_time_s - self.time_used_s)

    @property
    def can_spawn_child(self) -> bool:
        return self.children_spawned < self.max_child_agents

    def decay(self, factor: float = 0.7) -> "AgentBudget":
        """Create a decayed budget for a child agent."""
        return AgentBudget(
            max_tokens=int(self.tokens_remaining * factor),
            max_time_s=self.time_remaining_s * factor,
            max_tool_calls=max(1, int(self.max_tool_calls * factor)),
            max_llm_queries=max(1, int(self.max_llm_queries * factor)),
            max_child_agents=max(0, self.max_child_agents - 1),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": f"{self.tokens_used}/{self.max_tokens}",
            "time": f"{self.time_used_s:.0f}/{self.max_time_s:.0f}s",
            "tools": f"{self.tool_calls_used}/{self.max_tool_calls}",
            "llm": f"{self.llm_queries_used}/{self.max_llm_queries}",
            "children": f"{self.children_spawned}/{self.max_child_agents}",
        }


@dataclass
class SpawnedAgent:
    """A spawned agent instance."""
    agent_id: str = ""
    role: AgentRole = AgentRole.COORDINATOR
    parent_id: str = ""
    depth: int = 0
    goal: str = ""
    context: str = ""
    tools: list[str] = field(default_factory=list)
    model: str = ""
    budget: AgentBudget = field(default_factory=AgentBudget)
    status: SpawnStatus = SpawnStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    children: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    system_prompt: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.created_at
        return time.time() - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.role.value,
            "depth": self.depth,
            "parent": self.parent_id[:10] if self.parent_id else "root",
            "status": self.status.value,
            "children": len(self.children),
            "budget": self.budget.to_dict(),
        }


# ── Role → Model + Tools Mapping ─────────────────────────────

ROLE_CONFIG: dict[str, dict[str, Any]] = {
    "coordinator": {
        "model": "hermes-14b",
        "tools": [],
        "system_prompt": (
            "You are the COORDINATOR agent. Your job is to:\n"
            "1. Decompose the security assessment goal into sub-tasks\n"
            "2. Assign each sub-task to the appropriate specialist agent\n"
            "3. Aggregate results from all child agents\n"
            "4. Make decisions about what to investigate further\n"
            "5. Produce the final assessment summary"
        ),
    },
    "recon": {
        "model": "mistral-7b",
        "tools": ["subfinder", "httpx", "dig", "whois"],
        "system_prompt": (
            "You are the RECON agent. Your job is to:\n"
            "1. Enumerate subdomains, IP addresses, and infrastructure\n"
            "2. Identify technologies, frameworks, and services\n"
            "3. Map the attack surface comprehensively\n"
            "4. Report all findings to your parent coordinator"
        ),
    },
    "scanner": {
        "model": "whiterabbitneo",
        "tools": ["nmap", "nuclei", "nikto", "testssl"],
        "system_prompt": (
            "You are the SCANNER agent. Your job is to:\n"
            "1. Run port scans and service detection\n"
            "2. Execute vulnerability scans with nuclei\n"
            "3. Check TLS configuration\n"
            "4. Identify known CVEs in detected services"
        ),
    },
    "analyzer": {
        "model": "qwen-coder-14b",
        "tools": ["semgrep", "bandit"],
        "system_prompt": (
            "You are the ANALYZER agent. Your job is to:\n"
            "1. Analyze code for security vulnerabilities\n"
            "2. Review configurations for misconfigurations\n"
            "3. Identify business logic flaws\n"
            "4. Assess the severity and exploitability of findings"
        ),
    },
    "exploiter": {
        "model": "whiterabbitneo",
        "tools": ["sqlmap", "gobuster", "ffuf", "hydra"],
        "system_prompt": (
            "You are the EXPLOITER agent. Your job is to:\n"
            "1. Validate vulnerabilities through safe exploitation\n"
            "2. Determine actual impact and exploitability\n"
            "3. Build exploitation chains from individual findings\n"
            "4. Document proof-of-concept for each confirmed vulnerability"
        ),
    },
    "validator": {
        "model": "deepseek-r1",
        "tools": [],
        "system_prompt": (
            "You are the VALIDATOR agent. Your job is to:\n"
            "1. Cross-check findings for false positives\n"
            "2. Verify evidence quality and completeness\n"
            "3. Assess confidence level for each finding\n"
            "4. Challenge assumptions and conclusions"
        ),
    },
    "code_auditor": {
        "model": "qwen-coder-14b",
        "tools": ["semgrep", "bandit"],
        "system_prompt": (
            "You are the CODE AUDITOR agent. Your job is to:\n"
            "1. Perform deep code review for security vulnerabilities\n"
            "2. Identify insecure patterns, injections, and logic flaws\n"
            "3. Review authentication and authorization code\n"
            "4. Check for hardcoded secrets and sensitive data exposure"
        ),
    },
    "reasoning": {
        "model": "deepseek-r1",
        "tools": [],
        "system_prompt": (
            "You are the REASONING agent. Your job is to:\n"
            "1. Perform deep analysis and chain-of-thought reasoning\n"
            "2. Identify non-obvious attack vectors\n"
            "3. Build attack chain hypotheses\n"
            "4. Evaluate trade-offs between different investigation paths"
        ),
    },
    "cloud_analyst": {
        "model": "hermes-14b",
        "tools": ["curl"],
        "system_prompt": (
            "You are the CLOUD ANALYST agent. Your job is to:\n"
            "1. Identify cloud infrastructure (AWS/Azure/GCP)\n"
            "2. Check for metadata service exposure\n"
            "3. Assess IAM configuration and privilege escalation paths\n"
            "4. Evaluate storage permissions and data exposure"
        ),
    },
}


class RecursiveSpawner:
    """Manages recursive agent hierarchy with bounded execution.

    Creates a tree of agents where each parent can spawn children,
    with budget decay (70% per level) and depth limits to prevent
    unbounded recursion.
    """

    def __init__(
        self,
        max_depth: int = 5,
        budget_decay: float = 0.7,
        default_budget: AgentBudget | None = None,
    ) -> None:
        self._max_depth = max_depth
        self._budget_decay = budget_decay
        self._default_budget = default_budget or AgentBudget()
        self._agents: dict[str, SpawnedAgent] = {}
        self._agent_counter = 0
        self._depth_stats: dict[int, int] = defaultdict(int)
        self._role_stats: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="recursive_spawner")

    def spawn(
        self,
        role: AgentRole,
        goal: str,
        parent_id: str = "",
        context: str = "",
        budget: AgentBudget | None = None,
        model_override: str = "",
        tools_override: list[str] | None = None,
    ) -> SpawnedAgent | None:
        """Spawn a new agent."""
        # Determine depth
        depth = 0
        if parent_id:
            parent = self._agents.get(parent_id)
            if not parent:
                return None
            depth = parent.depth + 1

            # Check depth limit
            if depth > self._max_depth:
                self._log.warning("max_depth_reached", depth=depth, role=role.value)
                return None

            # Check parent budget
            if not parent.budget.can_spawn_child:
                self._log.warning("parent_budget_exhausted", parent=parent_id)
                return None

            parent.budget.children_spawned += 1
            parent.children.append("")  # Will update with actual ID

        # Determine budget
        if budget is None:
            if parent_id and parent_id in self._agents:
                budget = self._agents[parent_id].budget.decay(self._budget_decay)
            else:
                budget = AgentBudget(
                    max_tokens=self._default_budget.max_tokens,
                    max_time_s=self._default_budget.max_time_s,
                    max_tool_calls=self._default_budget.max_tool_calls,
                    max_llm_queries=self._default_budget.max_llm_queries,
                    max_child_agents=self._default_budget.max_child_agents,
                )

        # Get role config
        role_cfg = ROLE_CONFIG.get(role.value, {})
        model = model_override or role_cfg.get("model", "mistral-7b")
        tools = tools_override if tools_override is not None else role_cfg.get("tools", [])
        system_prompt = role_cfg.get("system_prompt", "")

        self._agent_counter += 1
        agent_id = f"agent-{self._agent_counter}-{role.value}"

        agent = SpawnedAgent(
            agent_id=agent_id,
            role=role,
            parent_id=parent_id,
            depth=depth,
            goal=goal,
            context=context,
            tools=tools,
            model=model,
            budget=budget,
            status=SpawnStatus.RUNNING,
            system_prompt=system_prompt,
        )

        self._agents[agent_id] = agent

        # Update parent's children list
        if parent_id and parent_id in self._agents:
            parent_agent = self._agents[parent_id]
            if parent_agent.children and parent_agent.children[-1] == "":
                parent_agent.children[-1] = agent_id
            else:
                parent_agent.children.append(agent_id)

        self._depth_stats[depth] += 1
        self._role_stats[role.value] += 1

        return agent

    def complete_agent(
        self,
        agent_id: str,
        result: dict[str, Any] | None = None,
        success: bool = True,
    ) -> SpawnedAgent | None:
        """Mark an agent as complete."""
        agent = self._agents.get(agent_id)
        if not agent:
            return None

        agent.status = SpawnStatus.COMPLETE if success else SpawnStatus.FAILED
        agent.completed_at = time.time()
        agent.result = result or {}

        return agent

    def cancel_agent(self, agent_id: str) -> bool:
        """Cancel a running agent."""
        agent = self._agents.get(agent_id)
        if not agent or agent.status != SpawnStatus.RUNNING:
            return False

        agent.status = SpawnStatus.CANCELLED
        agent.completed_at = time.time()

        # Cancel all children
        for child_id in agent.children:
            self.cancel_agent(child_id)

        return True

    def get_children_results(self, agent_id: str) -> list[dict[str, Any]]:
        """Get results from all children of an agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return []

        results = []
        for child_id in agent.children:
            child = self._agents.get(child_id)
            if child and child.status == SpawnStatus.COMPLETE:
                results.append({
                    "agent_id": child.agent_id,
                    "role": child.role.value,
                    "result": child.result,
                    "duration_s": child.duration_s,
                })

        return results

    def get_tree(self, root_id: str = "") -> dict[str, Any]:
        """Get the agent tree structure."""
        if not root_id:
            # Find root (depth 0)
            roots = [a for a in self._agents.values() if a.depth == 0]
            if not roots:
                return {}
            root_id = roots[0].agent_id

        agent = self._agents.get(root_id)
        if not agent:
            return {}

        tree: dict[str, Any] = agent.to_dict()
        tree["children_details"] = []
        for child_id in agent.children:
            child_tree = self.get_tree(child_id)
            if child_tree:
                tree["children_details"].append(child_tree)

        return tree

    def get_running_agents(self) -> list[SpawnedAgent]:
        """Get all currently running agents."""
        return [
            a for a in self._agents.values()
            if a.status == SpawnStatus.RUNNING
        ]

    def check_timeouts(self) -> list[str]:
        """Check for timed-out agents."""
        timed_out = []
        for agent in self._agents.values():
            if agent.status != SpawnStatus.RUNNING:
                continue
            if agent.duration_s > agent.budget.max_time_s:
                agent.status = SpawnStatus.TIMEOUT
                agent.completed_at = time.time()
                timed_out.append(agent.agent_id)

        return timed_out

    def get_agent(self, agent_id: str) -> SpawnedAgent | None:
        return self._agents.get(agent_id)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for a in self._agents.values():
            status_counts[a.status.value] += 1

        return {
            "total_agents": len(self._agents),
            "by_status": dict(status_counts),
            "by_depth": dict(self._depth_stats),
            "by_role": dict(self._role_stats),
            "max_depth": self._max_depth,
            "budget_decay": self._budget_decay,
        }
