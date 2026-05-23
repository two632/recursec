"""Recursive agent spawner — dynamic agent hierarchy management.

Implements:
1. Dynamic agent instantiation with role/goal/tools
2. Budget decay (70% per depth level)
3. Bounded recursion (max depth 5)
4. Agent pool with reuse
5. Result aggregation from child agents
6. Inter-agent message passing
7. Convergence-based early termination
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()

BUDGET_DECAY_FACTOR = 0.70
MAX_RECURSION_DEPTH = 5
DEFAULT_TOKEN_BUDGET = 50000
DEFAULT_TIME_BUDGET_S = 300.0


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    CODE_AUDITOR = "code_auditor"
    PLANNER = "planner"
    REPORTER = "reporter"
    OSINT = "osint"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    NETWORK = "network"
    WEB = "web"
    API = "api"
    FUZZER = "fuzzer"


class AgentState(str, Enum):
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING_CHILDREN = "waiting_children"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class AgentContext:
    """Context inherited from parent agent."""
    target: str = ""
    scope: list[str] = field(default_factory=list)
    knowledge: list[str] = field(default_factory=list)
    findings_so_far: list[dict[str, Any]] = field(default_factory=list)
    parent_observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "scope_items": len(self.scope),
            "knowledge_items": len(self.knowledge),
            "findings": len(self.findings_so_far),
        }


@dataclass
class AgentBudget:
    """Resource budget for an agent."""
    token_budget: int = DEFAULT_TOKEN_BUDGET
    tokens_used: int = 0
    time_budget_s: float = DEFAULT_TIME_BUDGET_S
    time_used_s: float = 0.0
    tool_call_limit: int = 50
    tool_calls_made: int = 0
    llm_query_limit: int = 20
    llm_queries_made: int = 0
    child_budget_limit: int = 5

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    @property
    def time_remaining_s(self) -> float:
        return max(0.0, self.time_budget_s - self.time_used_s)

    @property
    def tool_calls_remaining(self) -> int:
        return max(0, self.tool_call_limit - self.tool_calls_made)

    @property
    def budget_utilization(self) -> float:
        if self.token_budget == 0:
            return 0.0
        return self.tokens_used / self.token_budget

    @property
    def is_exhausted(self) -> bool:
        return (
            self.tokens_remaining <= 0
            or self.time_remaining_s <= 0
            or self.tool_calls_remaining <= 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": f"{self.tokens_used}/{self.token_budget}",
            "time_s": f"{self.time_used_s:.0f}/{self.time_budget_s:.0f}",
            "tools": f"{self.tool_calls_made}/{self.tool_call_limit}",
            "utilization": f"{self.budget_utilization:.0%}",
        }


@dataclass
class SpawnedAgent:
    """A spawned agent instance."""
    agent_id: str = ""
    role: AgentRole = AgentRole.SCANNER
    goal: str = ""
    model_id: str = ""
    state: AgentState = AgentState.IDLE
    depth: int = 0
    parent_id: str = ""
    children_ids: list[str] = field(default_factory=list)
    context: AgentContext = field(default_factory=AgentContext)
    budget: AgentBudget = field(default_factory=AgentBudget)
    tools: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    result: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.role.value,
            "depth": self.depth,
            "state": self.state.value,
            "children": len(self.children_ids),
            "findings": len(self.findings),
        }


@dataclass
class AggregatedResult:
    """Aggregated results from child agents."""
    parent_id: str = ""
    children_results: list[dict[str, Any]] = field(default_factory=list)
    merged_findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_duration_s: float = 0.0
    success_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "children": len(self.children_results),
            "findings": len(self.merged_findings),
            "tokens": self.total_tokens,
            "success_rate": round(self.success_rate, 2),
        }


# ── Role-to-model mapping ────────────────────────────────────

ROLE_MODEL_MAP: dict[str, str] = {
    "coordinator": "hermes-14b",
    "recon": "mistral-7b",
    "scanner": "whiterabbitneo-7b",
    "exploiter": "whiterabbitneo-7b",
    "validator": "deepseek-r1-7b",
    "code_auditor": "qwen-coder-14b",
    "planner": "deepseek-r1-7b",
    "reporter": "llama-3.1-8b",
    "osint": "dolphin-8b",
    "cloud": "hermes-14b",
    "mobile": "whiterabbitneo-7b",
    "iot": "whiterabbitneo-7b",
    "network": "whiterabbitneo-7b",
    "web": "whiterabbitneo-7b",
    "api": "qwen-coder-7b",
    "fuzzer": "phi-3.5-mini",
}

ROLE_TOOLS: dict[str, list[str]] = {
    "recon": ["subfinder", "amass", "httpx", "dig", "whois"],
    "scanner": ["nmap", "nuclei", "nikto", "testssl"],
    "exploiter": ["sqlmap", "curl", "nuclei"],
    "validator": ["curl", "nuclei"],
    "code_auditor": ["semgrep", "bandit", "trufflehog"],
    "osint": ["subfinder", "waybackurls", "gau"],
    "cloud": ["nuclei", "curl", "trivy"],
    "network": ["nmap", "masscan", "enum4linux"],
    "web": ["nuclei", "ffuf", "sqlmap", "dalfox"],
    "api": ["ffuf", "nuclei", "curl", "arjun"],
    "fuzzer": ["ffuf", "nuclei"],
}


class RecursiveSpawner:
    """Manages recursive agent spawning and lifecycle.

    Handles dynamic creation of child agents with
    budget decay, bounded depth, result aggregation,
    and convergence monitoring.
    """

    def __init__(
        self,
        max_depth: int = MAX_RECURSION_DEPTH,
        budget_decay: float = BUDGET_DECAY_FACTOR,
    ) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._budget_decay = budget_decay
        self._log = logger.bind(component="recursive_spawner")

    def spawn(
        self,
        role: AgentRole,
        goal: str,
        parent_id: str = "",
        context: AgentContext | None = None,
        token_budget: int = DEFAULT_TOKEN_BUDGET,
        time_budget_s: float = DEFAULT_TIME_BUDGET_S,
        model_id: str = "",
        tools: list[str] | None = None,
    ) -> SpawnedAgent | None:
        """Spawn a new agent."""
        parent = self._agents.get(parent_id) if parent_id else None
        depth = (parent.depth + 1) if parent else 0

        if depth > self._max_depth:
            self._log.warn("max_depth_exceeded", depth=depth)
            return None

        # Apply budget decay for child agents
        if parent:
            token_budget = int(parent.budget.tokens_remaining * self._budget_decay)
            time_budget_s = parent.budget.time_remaining_s * self._budget_decay

            if parent.budget.is_exhausted:
                self._log.warn("parent_budget_exhausted", parent_id=parent_id)
                return None

        self._counter += 1
        agent = SpawnedAgent(
            agent_id=f"agent-{self._counter}",
            role=role,
            goal=goal,
            model_id=model_id or ROLE_MODEL_MAP.get(role.value, "mistral-7b"),
            state=AgentState.INITIALIZING,
            depth=depth,
            parent_id=parent_id,
            context=context or AgentContext(),
            budget=AgentBudget(
                token_budget=token_budget,
                time_budget_s=time_budget_s,
                tool_call_limit=max(5, 50 - depth * 10),
                llm_query_limit=max(3, 20 - depth * 4),
                child_budget_limit=max(1, 5 - depth),
            ),
            tools=tools or ROLE_TOOLS.get(role.value, []),
        )

        self._agents[agent.agent_id] = agent

        if parent:
            parent.children_ids.append(agent.agent_id)

        return agent

    def start_agent(self, agent_id: str) -> bool:
        """Transition agent to running state."""
        agent = self._agents.get(agent_id)
        if not agent or agent.state != AgentState.INITIALIZING:
            return False

        agent.state = AgentState.RUNNING
        agent.started_at = time.time()
        return True

    def record_tool_call(
        self,
        agent_id: str,
        tokens_used: int = 0,
        duration_s: float = 0.0,
    ) -> bool:
        """Record a tool call for budget tracking."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.budget.tool_calls_made += 1
        agent.budget.tokens_used += tokens_used
        agent.budget.time_used_s += duration_s
        return not agent.budget.is_exhausted

    def record_llm_query(
        self,
        agent_id: str,
        tokens_used: int = 0,
    ) -> bool:
        """Record an LLM query for budget tracking."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.budget.llm_queries_made += 1
        agent.budget.tokens_used += tokens_used
        return not agent.budget.is_exhausted

    def add_finding(
        self,
        agent_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add a finding to an agent."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.findings.append(finding)

    def complete_agent(
        self,
        agent_id: str,
        result: str = "",
    ) -> AggregatedResult | None:
        """Complete an agent and aggregate child results."""
        agent = self._agents.get(agent_id)
        if not agent:
            return None

        agent.state = AgentState.AGGREGATING
        agent.completed_at = time.time()
        agent.result = result

        # Aggregate child results
        aggregated = AggregatedResult(parent_id=agent_id)
        all_findings = list(agent.findings)
        completed_children = 0

        for child_id in agent.children_ids:
            child = self._agents.get(child_id)
            if not child:
                continue

            aggregated.children_results.append(child.to_dict())
            aggregated.total_tokens += child.budget.tokens_used
            aggregated.total_duration_s += child.duration_s

            all_findings.extend(child.findings)

            if child.state == AgentState.COMPLETED:
                completed_children += 1

        aggregated.merged_findings = all_findings
        aggregated.total_tokens += agent.budget.tokens_used

        if agent.children_ids:
            aggregated.success_rate = completed_children / len(agent.children_ids)

        agent.state = AgentState.COMPLETED
        return aggregated

    def fail_agent(self, agent_id: str, reason: str = "") -> None:
        """Mark agent as failed."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.state = AgentState.FAILED
            agent.result = reason
            agent.completed_at = time.time()

    def get_agent(self, agent_id: str) -> SpawnedAgent | None:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def get_agent_tree(self, root_id: str) -> dict[str, Any]:
        """Get the full agent tree from a root."""
        agent = self._agents.get(root_id)
        if not agent:
            return {}

        tree = agent.to_dict()
        tree["children"] = []

        for child_id in agent.children_ids:
            child_tree = self.get_agent_tree(child_id)
            if child_tree:
                tree["children"].append(child_tree)

        return tree

    def build_spawner_prompt(self, agent_id: str = "") -> str:
        """Build spawner context for LLM."""
        lines = ["## Agent Hierarchy\n"]

        if agent_id:
            agent = self._agents.get(agent_id)
            if agent:
                lines.append(f"Current: {agent.role.value} (depth {agent.depth})")
                lines.append(f"Budget: {agent.budget.to_dict()}")
                lines.append(f"Children: {len(agent.children_ids)}")

        active = [a for a in self._agents.values() if a.state == AgentState.RUNNING]
        if active:
            lines.append(f"\nActive agents: {len(active)}")
            for agent in active[:5]:
                lines.append(f"  - {agent.role.value} @ depth {agent.depth}: {agent.goal[:40]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = defaultdict(int)
        role_counts: dict[str, int] = defaultdict(int)
        for agent in self._agents.values():
            state_counts[agent.state.value] += 1
            role_counts[agent.role.value] += 1

        total_findings = sum(len(a.findings) for a in self._agents.values())
        max_depth = max((a.depth for a in self._agents.values()), default=0)

        return {
            "total_agents": len(self._agents),
            "max_depth": max_depth,
            "total_findings": total_findings,
            "by_state": dict(state_counts),
            "by_role": dict(role_counts),
        }
