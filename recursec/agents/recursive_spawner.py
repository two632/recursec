"""Recursive agent spawner — dynamic child agent management.

Implements:
1. Budget-decayed child spawning (70% budget per level)
2. Role-based agent assignment
3. Depth-limited recursion (max 5)
4. Result aggregation from children
5. Child lifecycle management
6. Inter-agent communication
7. Work stealing between idle agents
8. Agent pool management
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
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    CODE_REVIEWER = "code_reviewer"
    OSINT = "osint"
    FUZZER = "fuzzer"


class SpawnReason(str, Enum):
    TASK_DECOMPOSITION = "task_decomposition"
    PARALLEL_SCAN = "parallel_scan"
    VALIDATION = "validation"
    SPECIALIZED_ANALYSIS = "specialized_analysis"
    EXPLOITATION_ATTEMPT = "exploitation_attempt"
    DEPTH_EXPANSION = "depth_expansion"


class AgentState(str, Enum):
    INITIALIZING = "initializing"
    IDLE = "idle"
    WORKING = "working"
    WAITING = "waiting"
    COMPLETE = "complete"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class AgentBudget:
    """Resource budget for an agent."""
    max_tokens: int = 50000
    max_tool_calls: int = 50
    max_llm_calls: int = 20
    max_time_s: float = 600.0
    max_children: int = 5
    max_depth: int = 5
    used_tokens: int = 0
    used_tool_calls: int = 0
    used_llm_calls: int = 0
    started_at: float = field(default_factory=time.time)

    @property
    def token_remaining(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def time_remaining(self) -> float:
        elapsed = time.time() - self.started_at
        return max(0.0, self.max_time_s - elapsed)

    @property
    def budget_consumed(self) -> float:
        token_frac = self.used_tokens / max(1, self.max_tokens)
        tool_frac = self.used_tool_calls / max(1, self.max_tool_calls)
        llm_frac = self.used_llm_calls / max(1, self.max_llm_calls)
        return max(token_frac, tool_frac, llm_frac)

    def decay(self, factor: float = 0.7) -> "AgentBudget":
        """Create a decayed budget for child agent."""
        return AgentBudget(
            max_tokens=int(self.token_remaining * factor),
            max_tool_calls=int(max(1, self.max_tool_calls * factor)),
            max_llm_calls=int(max(1, self.max_llm_calls * factor)),
            max_time_s=self.time_remaining * factor,
            max_children=max(0, self.max_children - 1),
            max_depth=self.max_depth - 1,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": f"{self.used_tokens}/{self.max_tokens}",
            "tools": f"{self.used_tool_calls}/{self.max_tool_calls}",
            "llm": f"{self.used_llm_calls}/{self.max_llm_calls}",
            "time_remaining": round(self.time_remaining, 0),
            "consumed": round(self.budget_consumed, 2),
        }


@dataclass
class ChildAgent:
    """A spawned child agent."""
    agent_id: str = ""
    role: AgentRole = AgentRole.SCANNER
    state: AgentState = AgentState.INITIALIZING
    parent_id: str = ""
    depth: int = 0
    task: str = ""
    target: str = ""
    budget: AgentBudget = field(default_factory=AgentBudget)
    spawn_reason: SpawnReason = SpawnReason.TASK_DECOMPOSITION
    model: str = ""
    tools: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    children_ids: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        end = self.completed_at if self.completed_at > 0 else time.time()
        return end - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.role.value,
            "state": self.state.value,
            "depth": self.depth,
            "task": self.task[:25],
            "findings": len(self.findings),
            "children": len(self.children_ids),
            "budget": self.budget.to_dict(),
        }


# ── Role→Model+Tool assignments ─────────────────────────────

ROLE_CONFIGS: dict[str, dict[str, Any]] = {
    "coordinator": {
        "models": ["hermes-14b", "deepseek-r1-7b"],
        "tools": [],
        "system_prompt": "You are a security assessment coordinator. Decompose the assessment goal into subtasks and assign to specialized agents.",
    },
    "recon": {
        "models": ["mistral-7b", "llama-3.1-8b"],
        "tools": ["nmap", "subfinder", "amass", "httpx", "wafw00f", "dnsrecon", "theHarvester"],
        "system_prompt": "You are a reconnaissance specialist. Enumerate the target's attack surface: domains, subdomains, IPs, ports, services, technologies.",
    },
    "scanner": {
        "models": ["whiterabbitneo-7b", "qwen-coder-7b"],
        "tools": ["nuclei", "nikto", "sqlmap", "dalfox", "wpscan"],
        "system_prompt": "You are a vulnerability scanner. Run scanning tools against the target and identify potential vulnerabilities.",
    },
    "exploiter": {
        "models": ["whiterabbitneo-7b", "dolphin-8b"],
        "tools": ["sqlmap", "hydra", "metasploit", "searchsploit"],
        "system_prompt": "You are an exploitation specialist. Attempt to exploit confirmed vulnerabilities to demonstrate impact.",
    },
    "validator": {
        "models": ["qwen-coder-14b", "hermes-14b"],
        "tools": ["curl", "httpx", "nmap"],
        "system_prompt": "You are a finding validator. Verify each finding independently using different tools and methods. Eliminate false positives.",
    },
    "analyzer": {
        "models": ["deepseek-r1-7b", "qwen-coder-14b"],
        "tools": [],
        "system_prompt": "You are a vulnerability analyzer. Assess the severity, impact, and exploitability of each finding. Map to CWE/CVSS.",
    },
    "code_reviewer": {
        "models": ["qwen-coder-14b", "codellama-13b", "yi-9b-200k"],
        "tools": ["semgrep", "bandit", "trufflehog", "gitleaks"],
        "system_prompt": "You are a code security reviewer. Analyze source code for vulnerabilities, hardcoded secrets, and insecure patterns.",
    },
    "osint": {
        "models": ["llama-3.1-8b", "mistral-7b"],
        "tools": ["theHarvester", "subfinder", "dnsrecon"],
        "system_prompt": "You are an OSINT specialist. Gather intelligence from public sources about the target organization.",
    },
    "fuzzer": {
        "models": ["whiterabbitneo-7b", "phi-3.5-mini"],
        "tools": ["ffuf", "gobuster", "wfuzz"],
        "system_prompt": "You are a fuzzing specialist. Generate and test malformed inputs to discover hidden endpoints and input handling vulnerabilities.",
    },
    "reporter": {
        "models": ["hermes-14b", "llama-3.1-8b"],
        "tools": [],
        "system_prompt": "You are a report generator. Compile findings into a structured security assessment report.",
    },
}


class RecursiveSpawner:
    """Manages recursive agent spawning and lifecycle.

    Creates child agents with decayed budgets, tracks
    their execution, and aggregates results back to
    parent agents.
    """

    def __init__(
        self,
        max_depth: int = 5,
        budget_decay: float = 0.7,
        max_total_agents: int = 50,
    ) -> None:
        self._agents: dict[str, ChildAgent] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._budget_decay = budget_decay
        self._max_total_agents = max_total_agents
        self._log = logger.bind(component="recursive_spawner")

    def spawn(
        self,
        role: AgentRole,
        task: str,
        target: str = "",
        parent_id: str = "",
        parent_budget: AgentBudget | None = None,
        depth: int = 0,
        reason: SpawnReason = SpawnReason.TASK_DECOMPOSITION,
    ) -> ChildAgent | None:
        """Spawn a new child agent."""
        # Depth check
        if depth >= self._max_depth:
            self._log.warning("Max depth reached", depth=depth)
            return None

        # Total agent limit
        active = sum(1 for a in self._agents.values() if a.state in (AgentState.WORKING, AgentState.IDLE))
        if active >= self._max_total_agents:
            self._log.warning("Max total agents reached", active=active)
            return None

        # Calculate budget
        if parent_budget:
            budget = parent_budget.decay(self._budget_decay)
        else:
            budget = AgentBudget(max_depth=self._max_depth - depth)

        # Budget exhaustion check
        if budget.max_tokens < 100 or budget.max_time_s < 10:
            self._log.warning("Budget too small for child", tokens=budget.max_tokens)
            return None

        self._counter += 1
        role_config = ROLE_CONFIGS.get(role.value, {})

        agent = ChildAgent(
            agent_id=f"agent-{self._counter}-{role.value[:4]}",
            role=role,
            state=AgentState.IDLE,
            parent_id=parent_id,
            depth=depth,
            task=task,
            target=target,
            budget=budget,
            spawn_reason=reason,
            model=role_config.get("models", [""])[0] if role_config.get("models") else "",
            tools=role_config.get("tools", []),
        )

        self._agents[agent.agent_id] = agent

        # Register with parent
        if parent_id and parent_id in self._agents:
            self._agents[parent_id].children_ids.append(agent.agent_id)

        return agent

    def start_agent(self, agent_id: str) -> bool:
        """Start an agent's execution."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.state = AgentState.WORKING
        return True

    def complete_agent(
        self,
        agent_id: str,
        result: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
        success: bool = True,
    ) -> bool:
        """Complete an agent's execution."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.state = AgentState.COMPLETE if success else AgentState.FAILED
        agent.completed_at = time.time()
        agent.result = result or {}
        if findings:
            agent.findings.extend(findings)

        return True

    def aggregate_results(self, parent_id: str) -> dict[str, Any]:
        """Aggregate results from all children of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return {}

        all_findings: list[dict[str, Any]] = []
        child_results: list[dict[str, Any]] = []
        total_tokens = 0
        total_tools = 0

        for child_id in parent.children_ids:
            child = self._agents.get(child_id)
            if not child:
                continue

            all_findings.extend(child.findings)
            child_results.append({
                "agent": child.agent_id,
                "role": child.role.value,
                "state": child.state.value,
                "findings": len(child.findings),
                "duration_s": round(child.duration_s, 1),
            })
            total_tokens += child.budget.used_tokens
            total_tools += child.budget.used_tool_calls

        # Deduplicate findings by title
        seen_titles: set[str] = set()
        unique_findings = []
        for f in all_findings:
            title = f.get("title", "")
            if title not in seen_titles:
                seen_titles.add(title)
                unique_findings.append(f)

        return {
            "parent_id": parent_id,
            "children": len(parent.children_ids),
            "completed": sum(1 for cid in parent.children_ids
                           if self._agents.get(cid, ChildAgent()).state == AgentState.COMPLETE),
            "total_findings": len(unique_findings),
            "findings": unique_findings,
            "child_results": child_results,
            "total_tokens": total_tokens,
            "total_tool_calls": total_tools,
        }

    def get_idle_agents(self) -> list[ChildAgent]:
        """Get agents that are idle (for work stealing)."""
        return [a for a in self._agents.values() if a.state == AgentState.IDLE]

    def get_agent(self, agent_id: str) -> ChildAgent | None:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def get_children(self, parent_id: str) -> list[ChildAgent]:
        """Get all children of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return []
        return [self._agents[cid] for cid in parent.children_ids if cid in self._agents]

    def get_tree(self, root_id: str) -> dict[str, Any]:
        """Get the full agent tree from a root."""
        agent = self._agents.get(root_id)
        if not agent:
            return {}

        def build_tree(aid: str) -> dict[str, Any]:
            a = self._agents.get(aid)
            if not a:
                return {}
            children = []
            for cid in a.children_ids:
                children.append(build_tree(cid))
            return {
                "agent": a.to_dict(),
                "children": children,
            }

        return build_tree(root_id)

    def terminate_agent(self, agent_id: str) -> bool:
        """Terminate an agent and all its children."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        agent.state = AgentState.TERMINATED
        agent.completed_at = time.time()

        # Recursively terminate children
        for child_id in agent.children_ids:
            self.terminate_agent(child_id)

        return True

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = defaultdict(int)
        role_counts: dict[str, int] = defaultdict(int)
        total_findings = 0
        max_depth = 0

        for a in self._agents.values():
            state_counts[a.state.value] += 1
            role_counts[a.role.value] += 1
            total_findings += len(a.findings)
            max_depth = max(max_depth, a.depth)

        return {
            "total_agents": len(self._agents),
            "total_findings": total_findings,
            "max_depth": max_depth,
            "by_state": dict(state_counts),
            "by_role": dict(role_counts),
        }
