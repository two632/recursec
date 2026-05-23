"""Agent spawner — dynamic recursive agent instantiation.

Implements:
1. On-demand agent creation based on task requirements
2. Agent pool with reuse
3. Budget inheritance with decay
4. Depth-limited recursion
5. Agent lifecycle management
6. Role-specific agent templates
7. Agent genealogy tracking
"""

from __future__ import annotations

import time
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
    ANALYST = "analyst"
    REPORTER = "reporter"
    CODE_AUDITOR = "code_auditor"
    OSINT = "osint"
    FUZZER = "fuzzer"
    CLOUD = "cloud"
    WIRELESS = "wireless"
    FORENSICS = "forensics"
    SOCIAL_ENG = "social_eng"
    GENERAL = "general"


class AgentLifecycle(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class AgentSpec:
    """Specification for creating an agent."""
    role: AgentRole = AgentRole.GENERAL
    goal: str = ""
    model_preferences: list[str] = field(default_factory=list)
    tool_whitelist: list[str] = field(default_factory=list)
    token_budget: int = 100000
    time_budget_s: float = 3600.0
    tool_call_limit: int = 50
    max_child_depth: int = 3
    system_prompt_extra: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "goal": self.goal[:30],
            "token_budget": self.token_budget,
            "max_depth": self.max_child_depth,
        }


@dataclass
class AgentInstance:
    """A running agent instance."""
    agent_id: str = ""
    parent_id: str = ""
    spec: AgentSpec = field(default_factory=AgentSpec)
    lifecycle: AgentLifecycle = AgentLifecycle.CREATED
    depth: int = 0
    children: list[str] = field(default_factory=list)
    tokens_used: int = 0
    tool_calls: int = 0
    findings_count: int = 0
    result: str = ""
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "parent": self.parent_id[:10] if self.parent_id else "root",
            "role": self.spec.role.value,
            "lifecycle": self.lifecycle.value,
            "depth": self.depth,
            "children": len(self.children),
            "tokens": self.tokens_used,
            "findings": self.findings_count,
        }


# ── Role templates ───────────────────────────────────────────

ROLE_TEMPLATES: dict[str, dict[str, Any]] = {
    "recon": {
        "model_preferences": ["mistral-7b", "llama-3.1-8b"],
        "tool_whitelist": [
            "subfinder", "amass", "httpx", "dig", "whois",
            "nmap", "masscan", "shodan",
        ],
        "system_extra": (
            "You are a reconnaissance specialist. Enumerate subdomains, "
            "discover services, map the attack surface. Be thorough but quiet."
        ),
    },
    "scanner": {
        "model_preferences": ["whiterabbitneo-7b", "qwen-coder-7b"],
        "tool_whitelist": [
            "nuclei", "nikto", "wpscan", "testssl",
            "nmap", "ffuf", "gobuster",
        ],
        "system_extra": (
            "You are a vulnerability scanner. Run targeted scans based on "
            "discovered services. Prioritize high-severity checks."
        ),
    },
    "exploiter": {
        "model_preferences": ["whiterabbitneo-7b", "dolphin-8b"],
        "tool_whitelist": [
            "sqlmap", "hydra", "metasploit", "burp",
        ],
        "system_extra": (
            "You are an exploitation specialist. Validate and exploit "
            "confirmed vulnerabilities. Document proof-of-concept carefully."
        ),
    },
    "code_auditor": {
        "model_preferences": ["qwen-coder-14b", "codellama-13b"],
        "tool_whitelist": [
            "semgrep", "bandit", "trufflehog", "gitleaks",
        ],
        "system_extra": (
            "You are a code auditor. Analyze source code for security "
            "vulnerabilities, focusing on injection, auth, and crypto flaws."
        ),
    },
    "analyst": {
        "model_preferences": ["deepseek-r1-7b", "hermes-14b"],
        "tool_whitelist": [],
        "system_extra": (
            "You are a security analyst. Analyze findings, correlate "
            "results, build attack chains, and assess overall risk."
        ),
    },
    "validator": {
        "model_preferences": ["deepseek-r1-7b", "qwen-coder-14b"],
        "tool_whitelist": [],
        "system_extra": (
            "You are a validation specialist. Verify findings are real, "
            "eliminate false positives, and confirm exploitability."
        ),
    },
    "osint": {
        "model_preferences": ["llama-3.1-8b", "mistral-7b"],
        "tool_whitelist": [
            "theharvester", "sherlock", "recon-ng", "maltego",
        ],
        "system_extra": (
            "You are an OSINT specialist. Gather open-source intelligence "
            "about targets including people, infrastructure, and technology."
        ),
    },
    "cloud": {
        "model_preferences": ["qwen-coder-14b", "hermes-14b"],
        "tool_whitelist": [
            "pacu", "s3scanner", "trivy", "kube-hunter",
        ],
        "system_extra": (
            "You are a cloud security specialist. Assess cloud infrastructure "
            "for misconfigurations, IAM issues, and exposed resources."
        ),
    },
}

BUDGET_DECAY = 0.7  # Children get 70% of parent's remaining budget
MAX_GLOBAL_AGENTS = 100
MAX_DEPTH = 5


class AgentSpawner:
    """Spawns and manages agent instances.

    Creates agents on demand with role-specific
    configurations, tracks genealogy, and enforces
    depth/budget limits.
    """

    def __init__(self, max_depth: int = MAX_DEPTH) -> None:
        self._agents: dict[str, AgentInstance] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._log = logger.bind(component="agent_spawner")

    def spawn(
        self,
        role: AgentRole,
        goal: str,
        parent_id: str = "",
        token_budget: int = 0,
        time_budget_s: float = 0.0,
    ) -> AgentInstance | None:
        """Spawn a new agent."""
        # Check global limit
        active = [
            a for a in self._agents.values()
            if a.lifecycle in (AgentLifecycle.RUNNING, AgentLifecycle.WAITING)
        ]
        if len(active) >= MAX_GLOBAL_AGENTS:
            self._log.warning("max_agents_reached", active=len(active))
            return None

        # Check depth limit
        parent = self._agents.get(parent_id) if parent_id else None
        depth = (parent.depth + 1) if parent else 0

        if depth > self._max_depth:
            self._log.warning("max_depth_reached", depth=depth)
            return None

        # Apply budget decay from parent
        if parent and not token_budget:
            remaining = parent.spec.token_budget - parent.tokens_used
            token_budget = int(remaining * BUDGET_DECAY)
        if not token_budget:
            token_budget = 100000

        if parent and not time_budget_s:
            time_budget_s = parent.spec.time_budget_s * BUDGET_DECAY
        if not time_budget_s:
            time_budget_s = 3600.0

        # Build spec from role template
        template = ROLE_TEMPLATES.get(role.value, {})
        spec = AgentSpec(
            role=role,
            goal=goal,
            model_preferences=template.get("model_preferences", []),
            tool_whitelist=template.get("tool_whitelist", []),
            token_budget=token_budget,
            time_budget_s=time_budget_s,
            max_child_depth=self._max_depth - depth,
            system_prompt_extra=template.get("system_extra", ""),
        )

        # Create instance
        self._counter += 1
        agent = AgentInstance(
            agent_id=f"agent-{self._counter}",
            parent_id=parent_id,
            spec=spec,
            depth=depth,
        )

        self._agents[agent.agent_id] = agent

        # Register as child of parent
        if parent:
            parent.children.append(agent.agent_id)

        self._log.info(
            "agent_spawned",
            agent=agent.agent_id[:10],
            role=role.value,
            depth=depth,
            budget=token_budget,
        )

        return agent

    def start(self, agent_id: str) -> bool:
        """Mark agent as running."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.lifecycle = AgentLifecycle.RUNNING
        return True

    def complete(self, agent_id: str, result: str = "") -> bool:
        """Mark agent as completed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.lifecycle = AgentLifecycle.COMPLETED
        agent.result = result
        agent.completed_at = time.time()
        return True

    def fail(self, agent_id: str, error: str = "") -> bool:
        """Mark agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.lifecycle = AgentLifecycle.FAILED
        agent.result = error
        agent.completed_at = time.time()
        return True

    def terminate(self, agent_id: str) -> bool:
        """Terminate an agent and all its children."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        # Terminate children recursively
        for child_id in agent.children:
            self.terminate(child_id)

        agent.lifecycle = AgentLifecycle.TERMINATED
        agent.completed_at = time.time()
        return True

    def get_children(self, agent_id: str) -> list[AgentInstance]:
        """Get child agents."""
        agent = self._agents.get(agent_id)
        if not agent:
            return []
        return [
            self._agents[cid]
            for cid in agent.children
            if cid in self._agents
        ]

    def get_lineage(self, agent_id: str) -> list[str]:
        """Get full lineage from root to agent."""
        lineage: list[str] = [agent_id]
        current = self._agents.get(agent_id)
        while current and current.parent_id:
            lineage.insert(0, current.parent_id)
            current = self._agents.get(current.parent_id)
        return lineage

    def get_active_agents(self) -> list[AgentInstance]:
        """Get all active agents."""
        return [
            a for a in self._agents.values()
            if a.lifecycle in (AgentLifecycle.RUNNING, AgentLifecycle.WAITING)
        ]

    def build_hierarchy_prompt(self, agent_id: str = "") -> str:
        """Build agent hierarchy for LLM context."""
        lines = ["## Agent Hierarchy\n"]

        # Show roots
        roots = [
            a for a in self._agents.values()
            if not a.parent_id
        ]

        for root in roots:
            self._build_tree_lines(root, lines, indent=0)

        return "\n".join(lines)

    def _build_tree_lines(
        self,
        agent: AgentInstance,
        lines: list[str],
        indent: int,
    ) -> None:
        """Recursively build tree representation."""
        prefix = "  " * indent
        status_icon = {
            "running": "▶",
            "completed": "✓",
            "failed": "✗",
            "terminated": "■",
        }.get(agent.lifecycle.value, "○")

        lines.append(
            f"{prefix}{status_icon} {agent.spec.role.value} "
            f"({agent.agent_id[:8]}) "
            f"depth={agent.depth} findings={agent.findings_count}"
        )

        for child_id in agent.children:
            child = self._agents.get(child_id)
            if child:
                self._build_tree_lines(child, lines, indent + 1)

    def get_stats(self) -> dict[str, Any]:
        lifecycle_counts: dict[str, int] = {}
        role_counts: dict[str, int] = {}
        for a in self._agents.values():
            lifecycle_counts[a.lifecycle.value] = lifecycle_counts.get(a.lifecycle.value, 0) + 1
            role_counts[a.spec.role.value] = role_counts.get(a.spec.role.value, 0) + 1

        return {
            "total_agents": len(self._agents),
            "by_lifecycle": lifecycle_counts,
            "by_role": role_counts,
            "max_depth": max((a.depth for a in self._agents.values()), default=0),
            "total_tokens": sum(a.tokens_used for a in self._agents.values()),
        }
