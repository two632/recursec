"""Agent spawner — creates and manages child agents.

Implements:
1. Dynamic agent creation from templates
2. Role-based agent configuration
3. Budget inheritance with decay
4. Context propagation to children
5. Agent pool management
6. Agent lifecycle tracking
7. Result aggregation from children
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
    CODE_AUDITOR = "code_auditor"
    NETWORK_ANALYST = "network_analyst"
    WEB_TESTER = "web_tester"
    API_TESTER = "api_tester"
    OSINT = "osint"
    REPORTER = "reporter"
    PLANNER = "planner"


class AgentState(str, Enum):
    INITIALIZING = "initializing"
    IDLE = "idle"
    WORKING = "working"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class AgentSpec:
    """Specification for creating an agent."""
    role: AgentRole = AgentRole.COORDINATOR
    primary_model: str = ""
    secondary_models: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    knowledge_bases: list[str] = field(default_factory=list)
    system_prompt_additions: str = ""
    token_budget: int = 100_000
    time_budget_s: float = 600
    tool_call_limit: int = 50
    max_child_depth: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "model": self.primary_model[:15],
            "tools": len(self.tools),
            "token_budget": self.token_budget,
        }


@dataclass
class AgentInstance:
    """A spawned agent instance."""
    agent_id: str = ""
    spec: AgentSpec = field(default_factory=AgentSpec)
    state: AgentState = AgentState.INITIALIZING
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    depth: int = 0
    task: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    tokens_used: int = 0
    tool_calls: int = 0
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    result: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.spec.role.value,
            "state": self.state.value,
            "depth": self.depth,
            "children": len(self.children),
            "findings": len(self.findings),
            "tokens": self.tokens_used,
        }


# ── Role-based agent templates ───────────────────────────────

ROLE_TEMPLATES: dict[str, dict[str, Any]] = {
    "coordinator": {
        "model": "deepseek-r1-7b",
        "secondary": ["hermes-14b"],
        "tools": [],
        "kbs": ["advanced_strategy"],
        "prompt": "You are the assessment coordinator. Decompose the target into subtasks, assign to specialized agents, and aggregate findings.",
    },
    "recon": {
        "model": "mistral-7b",
        "secondary": ["phi-3.5-mini"],
        "tools": ["nmap", "masscan", "subfinder", "amass", "httpx", "whatweb", "dig", "whois", "dnsrecon"],
        "kbs": ["network_security"],
        "prompt": "You are a reconnaissance specialist. Enumerate all attack surfaces: subdomains, ports, services, technologies.",
    },
    "scanner": {
        "model": "whiterabbitneo-7b",
        "secondary": ["qwen-coder-14b"],
        "tools": ["nuclei", "nikto", "testssl", "wpscan"],
        "kbs": ["web_vuln", "api_security"],
        "prompt": "You are a vulnerability scanner. Run comprehensive scans and identify all potential vulnerabilities.",
    },
    "exploiter": {
        "model": "whiterabbitneo-7b",
        "secondary": ["dolphin-8b", "qwen-coder-14b"],
        "tools": ["sqlmap", "dalfox", "hydra", "searchsploit"],
        "kbs": ["web_vuln", "privesc", "advanced_strategy"],
        "prompt": "You are an exploitation specialist. Attempt to exploit confirmed vulnerabilities with minimal impact.",
    },
    "validator": {
        "model": "hermes-14b",
        "secondary": ["deepseek-r1-7b"],
        "tools": ["nuclei", "curl", "httpx"],
        "kbs": ["web_vuln"],
        "prompt": "You are a finding validator. Cross-verify all findings using different tools and methods. Eliminate false positives.",
    },
    "code_auditor": {
        "model": "qwen-coder-14b",
        "secondary": ["codellama-13b", "yi-9b-200k"],
        "tools": ["semgrep", "bandit", "trufflehog", "gitleaks", "trivy", "grype"],
        "kbs": ["code_vuln", "supply_chain", "secrets_detection"],
        "prompt": "You are a code auditor. Perform comprehensive static analysis, secret detection, and dependency auditing.",
    },
    "network_analyst": {
        "model": "llama-3.1-8b",
        "secondary": ["mistral-7b"],
        "tools": ["nmap", "enum4linux", "crackmapexec", "responder"],
        "kbs": ["network_security", "active_directory", "privesc"],
        "prompt": "You are a network security analyst. Analyze network services, identify misconfigurations, and test access controls.",
    },
    "web_tester": {
        "model": "whiterabbitneo-7b",
        "secondary": ["qwen-coder-7b"],
        "tools": ["ffuf", "gobuster", "sqlmap", "dalfox", "feroxbuster"],
        "kbs": ["web_vuln", "api_security"],
        "prompt": "You are a web application tester. Test all web endpoints for injection, authentication, and business logic vulnerabilities.",
    },
    "api_tester": {
        "model": "qwen-coder-14b",
        "secondary": ["whiterabbitneo-7b"],
        "tools": ["ffuf", "nuclei", "curl", "httpx"],
        "kbs": ["api_security", "web_vuln"],
        "prompt": "You are an API security tester. Test REST, GraphQL, gRPC, and WebSocket endpoints for authorization and injection issues.",
    },
    "planner": {
        "model": "deepseek-r1-7b",
        "secondary": ["hermes-14b"],
        "tools": [],
        "kbs": ["advanced_strategy", "compliance"],
        "prompt": "You are a strategic planner. Analyze the target, generate hypotheses, plan attack chains, and prioritize testing paths.",
    },
}


class AgentSpawner:
    """Spawns and manages child agents.

    Creates specialized agents with role-based
    configurations and budget inheritance.
    """

    def __init__(
        self,
        max_depth: int = 3,
        budget_decay: float = 0.70,
    ) -> None:
        self._agents: dict[str, AgentInstance] = {}
        self._counter = 0
        self._max_depth = max_depth
        self._budget_decay = budget_decay
        self._log = logger.bind(component="agent_spawner")

    def spawn(
        self,
        role: AgentRole,
        task: str,
        parent_id: str = "",
        token_budget: int = 0,
        time_budget_s: float = 0,
    ) -> AgentInstance | None:
        """Spawn a new agent."""
        parent = self._agents.get(parent_id) if parent_id else None
        depth = (parent.depth + 1) if parent else 0

        if depth > self._max_depth:
            self._log.warn("max_depth_reached", depth=depth)
            return None

        # Get role template
        template = ROLE_TEMPLATES.get(role.value, ROLE_TEMPLATES["coordinator"])

        # Calculate budget
        if token_budget == 0 and parent:
            token_budget = int(parent.spec.token_budget * self._budget_decay)
        elif token_budget == 0:
            token_budget = 100_000

        if time_budget_s == 0 and parent:
            time_budget_s = parent.spec.time_budget_s * self._budget_decay
        elif time_budget_s == 0:
            time_budget_s = 600

        self._counter += 1
        spec = AgentSpec(
            role=role,
            primary_model=template.get("model", "hermes-14b"),
            secondary_models=template.get("secondary", []),
            tools=template.get("tools", []),
            knowledge_bases=template.get("kbs", []),
            system_prompt_additions=template.get("prompt", ""),
            token_budget=token_budget,
            time_budget_s=time_budget_s,
        )

        agent = AgentInstance(
            agent_id=f"agent-{self._counter}",
            spec=spec,
            parent_id=parent_id,
            depth=depth,
            task=task,
        )

        self._agents[agent.agent_id] = agent

        if parent:
            parent.children.append(agent.agent_id)

        return agent

    def update_state(
        self,
        agent_id: str,
        state: AgentState,
        result: str = "",
        error: str = "",
    ) -> None:
        """Update an agent's state."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = state
        if result:
            agent.result = result
        if error:
            agent.error = error
        if state in (AgentState.COMPLETED, AgentState.FAILED, AgentState.TERMINATED):
            agent.completed_at = time.time()

    def add_finding(
        self,
        agent_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add a finding from an agent."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.findings.append(finding)

    def collect_findings(
        self,
        root_id: str,
    ) -> list[dict[str, Any]]:
        """Collect all findings from an agent and its children."""
        agent = self._agents.get(root_id)
        if not agent:
            return []

        findings = list(agent.findings)
        for child_id in agent.children:
            findings.extend(self.collect_findings(child_id))

        return findings

    def get_active_agents(self) -> list[AgentInstance]:
        """Get all active agents."""
        return [
            a for a in self._agents.values()
            if a.state in (AgentState.WORKING, AgentState.WAITING, AgentState.IDLE)
        ]

    def terminate_tree(self, root_id: str) -> int:
        """Terminate an agent and all its children."""
        agent = self._agents.get(root_id)
        if not agent:
            return 0

        count = 0
        for child_id in agent.children:
            count += self.terminate_tree(child_id)

        agent.state = AgentState.TERMINATED
        agent.completed_at = time.time()
        return count + 1

    def build_hierarchy_prompt(self) -> str:
        """Build a prompt describing the agent hierarchy."""
        roots = [a for a in self._agents.values() if not a.parent_id]
        if not roots:
            return ""

        lines = ["## Agent Hierarchy\n"]
        for root in roots:
            self._format_agent(root.agent_id, lines, 0)

        return "\n".join(lines)

    def _format_agent(
        self,
        agent_id: str,
        lines: list[str],
        indent: int,
    ) -> None:
        """Format an agent for display."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        prefix = "  " * indent
        lines.append(
            f"{prefix}[{agent.spec.role.value}] {agent.agent_id} "
            f"({agent.state.value}, {len(agent.findings)} findings)"
        )
        for child_id in agent.children:
            self._format_agent(child_id, lines, indent + 1)

    def get_stats(self) -> dict[str, Any]:
        state_counts: dict[str, int] = defaultdict(int)
        role_counts: dict[str, int] = defaultdict(int)
        depth_counts: dict[int, int] = defaultdict(int)

        for agent in self._agents.values():
            state_counts[agent.state.value] += 1
            role_counts[agent.spec.role.value] += 1
            depth_counts[agent.depth] += 1

        return {
            "total_agents": len(self._agents),
            "total_findings": sum(len(a.findings) for a in self._agents.values()),
            "by_state": dict(state_counts),
            "by_role": dict(role_counts),
            "by_depth": dict(depth_counts),
        }
