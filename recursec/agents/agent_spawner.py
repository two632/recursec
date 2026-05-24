"""Agent spawner — dynamic agent instantiation.

Creates agents on-the-fly with:
1. Specific roles and capabilities
2. Model assignment based on task
3. Inherited context from parent
4. Tool access control
5. Token budget allocation
6. Lifecycle management (pool, reuse, teardown)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentLifecycle(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    IDLE = "idle"
    PAUSED = "paused"
    SHUTTING_DOWN = "shutting_down"
    TERMINATED = "terminated"


class AgentPriority(str, Enum):
    CRITICAL = "critical"   # Must complete
    HIGH = "high"           # Important
    NORMAL = "normal"       # Standard
    LOW = "low"             # Best effort
    BACKGROUND = "background"  # When resources free


@dataclass
class SpawnedAgent:
    """A dynamically spawned agent."""
    agent_id: str = ""
    parent_id: str = ""
    role: str = ""
    model: str = ""
    lifecycle: AgentLifecycle = AgentLifecycle.CREATED
    priority: AgentPriority = AgentPriority.NORMAL
    task: str = ""
    system_prompt: str = ""
    tools_allowed: list[str] = field(default_factory=list)
    kb_domains: list[str] = field(default_factory=list)
    token_budget: int = 4096
    tokens_used: int = 0
    max_steps: int = 20
    steps_taken: int = 0
    context: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, str]] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def is_active(self) -> bool:
        return self.lifecycle in (
            AgentLifecycle.READY,
            AgentLifecycle.BUSY,
            AgentLifecycle.IDLE,
        )

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    @property
    def budget_remaining(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    @property
    def steps_remaining(self) -> int:
        return max(0, self.max_steps - self.steps_taken)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:8],
            "role": self.role[:8],
            "model": self.model[:12],
            "state": self.lifecycle.value[:8],
            "findings": len(self.findings),
            "budget": self.budget_remaining,
        }


# Role → default configuration
ROLE_DEFAULTS: dict[str, dict[str, Any]] = {
    "coordinator": {
        "model": "DeepSeek-R1",
        "tools": ["spawn_agent", "delegate", "aggregate"],
        "kb": ["planning", "strategy"],
        "budget": 8192,
        "max_steps": 30,
        "priority": "high",
        "prompt": (
            "You are the coordinator. Decompose tasks, "
            "spawn specialized agents, track progress, "
            "aggregate results. Think strategically."
        ),
    },
    "recon": {
        "model": "Mistral-7B",
        "tools": [
            "nmap", "masscan", "subfinder", "amass",
            "httpx", "whatweb", "shodan_cli",
        ],
        "kb": ["recon", "osint", "network_attack"],
        "budget": 4096,
        "max_steps": 25,
        "priority": "normal",
        "prompt": (
            "You are a reconnaissance specialist. Map the "
            "attack surface. Enumerate subdomains, ports, "
            "services, technologies. Be thorough."
        ),
    },
    "scanner": {
        "model": "WhiteRabbitNeo-7B",
        "tools": [
            "nuclei", "nikto", "nessus", "openvas",
            "wapiti", "arachni",
        ],
        "kb": ["web_vuln", "network_attack", "cloud_native"],
        "budget": 4096,
        "max_steps": 20,
        "priority": "normal",
        "prompt": (
            "You are a vulnerability scanner. Run automated "
            "scans, interpret results, identify true positives. "
            "Reduce false positives."
        ),
    },
    "web": {
        "model": "WhiteRabbitNeo-7B",
        "tools": [
            "sqlmap", "xsstrike", "ffuf", "burp",
            "commix", "dalfox",
        ],
        "kb": ["web_vuln", "xss", "ssrf", "sqli", "deserialization"],
        "budget": 4096,
        "max_steps": 25,
        "priority": "normal",
        "prompt": (
            "You are a web application security specialist. "
            "Test for OWASP Top 10, business logic flaws, "
            "authentication bypass, injection attacks."
        ),
    },
    "network": {
        "model": "Dolphin-2.9",
        "tools": [
            "nmap", "responder", "crackmapexec",
            "impacket", "bettercap", "wireshark_cli",
        ],
        "kb": ["network_attack", "active_directory", "privesc"],
        "budget": 4096,
        "max_steps": 20,
        "priority": "normal",
        "prompt": (
            "You are a network security specialist. "
            "Perform network-level attacks, sniffing, "
            "MitM, lateral movement."
        ),
    },
    "exploiter": {
        "model": "WhiteRabbitNeo-7B",
        "tools": [
            "metasploit", "bash", "python", "curl",
            "netcat",
        ],
        "kb": ["privesc", "binary_exploit", "web_vuln"],
        "budget": 6144,
        "max_steps": 20,
        "priority": "high",
        "prompt": (
            "You are an exploitation specialist. "
            "Validate vulnerabilities through exploitation. "
            "Escalate privileges. Document impact."
        ),
    },
    "code_auditor": {
        "model": "Qwen2.5-Coder-14B",
        "tools": [
            "semgrep", "bandit", "codeql", "gitleaks",
            "trufflehog",
        ],
        "kb": ["code_vuln", "deserialization", "crypto"],
        "budget": 8192,
        "max_steps": 20,
        "priority": "normal",
        "prompt": (
            "You are a code auditor. Review source code "
            "for vulnerabilities. Use static analysis and "
            "manual review. Focus on critical paths."
        ),
    },
    "analyst": {
        "model": "DeepSeek-R1",
        "tools": ["correlate", "chain", "score"],
        "kb": ["compliance", "incident_response"],
        "budget": 4096,
        "max_steps": 15,
        "priority": "normal",
        "prompt": (
            "You are a security analyst. Analyze findings, "
            "correlate vulnerabilities, identify attack chains, "
            "assess risk and impact."
        ),
    },
    "validator": {
        "model": "Qwen2.5-Coder-14B",
        "tools": ["bash", "curl", "python", "verify"],
        "kb": ["web_vuln", "network_attack"],
        "budget": 4096,
        "max_steps": 15,
        "priority": "high",
        "prompt": (
            "You are a validation specialist. Verify findings "
            "are real, not false positives. Re-test with "
            "different methods. Confirm exploitability."
        ),
    },
    "osint": {
        "model": "Llama-3.1-8B",
        "tools": [
            "theHarvester", "recon-ng", "sherlock",
            "spiderfoot",
        ],
        "kb": ["osint", "email_phishing", "recon"],
        "budget": 4096,
        "max_steps": 20,
        "priority": "low",
        "prompt": (
            "You are an OSINT specialist. Gather intelligence "
            "from public sources. Find emails, subdomains, "
            "employees, technologies, exposed data."
        ),
    },
    "cloud": {
        "model": "Hermes-4-14B",
        "tools": [
            "prowler", "scoutsuite", "pacu", "cloudfox",
            "steampipe",
        ],
        "kb": ["cloud_native", "devsecops", "identity_sso"],
        "budget": 4096,
        "max_steps": 20,
        "priority": "normal",
        "prompt": (
            "You are a cloud security specialist. Audit "
            "AWS/Azure/GCP configurations, IAM policies, "
            "storage permissions, network security."
        ),
    },
    "forensics": {
        "model": "Yi-9B-200K",
        "tools": [
            "volatility", "sleuthkit", "yara",
            "binwalk", "strings",
        ],
        "kb": ["incident_response", "forensics", "malware"],
        "budget": 8192,
        "max_steps": 20,
        "priority": "normal",
        "prompt": (
            "You are a digital forensics specialist. "
            "Analyze memory, disk, network captures. "
            "Find indicators of compromise. Use Yi-9B's "
            "200K context for large evidence files."
        ),
    },
    "reporter": {
        "model": "Mistral-7B",
        "tools": ["report_gen", "template"],
        "kb": ["compliance"],
        "budget": 4096,
        "max_steps": 10,
        "priority": "low",
        "prompt": (
            "You are the report generator. Compile findings "
            "into clear, actionable reports with severity "
            "ratings, remediation steps, and evidence."
        ),
    },
}

# Model → context window sizes
MODEL_CONTEXT_SIZES: dict[str, int] = {
    "WhiteRabbitNeo-7B": 8192,
    "Qwen2.5-Coder-14B": 32768,
    "Qwen2.5-Coder-7B": 32768,
    "DeepSeek-R1": 16384,
    "Yi-9B-200K": 200000,
    "Phi-3.5-mini": 4096,
    "Mistral-7B": 8192,
    "CodeLlama-13B": 16384,
    "CodeLlama-7B": 16384,
    "Hermes-4-14B": 16384,
    "Llama-3.1-8B": 8192,
    "Dolphin-2.9": 8192,
    "DeepSeek-Math-7B": 4096,
    "FunctionGemma-270m": 2048,
    "Llama-Guard-3": 4096,
}


class AgentSpawner:
    """Spawn agents dynamically with optimal config.

    Creates agents with the right model, tools,
    knowledge, and budget for any task.
    """

    def __init__(self, max_concurrent: int = 8) -> None:
        self._agents: dict[str, SpawnedAgent] = {}
        self._agent_counter = 0
        self._max_concurrent = max_concurrent
        self._pool: list[str] = []  # Reusable idle agents
        self._log = logger.bind(component="spawner")

    def spawn(
        self,
        role: str,
        task: str,
        parent_id: str = "",
        model_override: str = "",
        budget_override: int = 0,
        extra_tools: list[str] | None = None,
        extra_kb: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> SpawnedAgent:
        """Spawn a new agent."""
        defaults = ROLE_DEFAULTS.get(role, ROLE_DEFAULTS["scanner"])

        self._agent_counter += 1

        model = model_override or defaults.get("model", "Mistral-7B")
        tools = list(defaults.get("tools", []))
        if extra_tools:
            tools.extend(extra_tools)

        kb = list(defaults.get("kb", []))
        if extra_kb:
            kb.extend(extra_kb)

        budget = budget_override or defaults.get("budget", 4096)
        max_steps = defaults.get("max_steps", 20)

        agent = SpawnedAgent(
            agent_id=f"agent-{self._agent_counter}",
            parent_id=parent_id,
            role=role,
            model=model,
            lifecycle=AgentLifecycle.CREATED,
            priority=AgentPriority(defaults.get("priority", "normal")),
            task=task,
            system_prompt=defaults.get("prompt", ""),
            tools_allowed=tools,
            kb_domains=kb,
            token_budget=budget,
            max_steps=max_steps,
            context=context or {},
        )

        self._agents[agent.agent_id] = agent

        # If parent, track child
        if parent_id and parent_id in self._agents:
            self._agents[parent_id].children.append(agent.agent_id)

        return agent

    def reuse_or_spawn(
        self,
        role: str,
        task: str,
        parent_id: str = "",
    ) -> SpawnedAgent:
        """Try to reuse a pooled agent, else spawn new."""
        for agent_id in self._pool:
            agent = self._agents.get(agent_id)
            if agent and agent.role == role and agent.lifecycle == AgentLifecycle.IDLE:
                agent.task = task
                agent.parent_id = parent_id
                agent.lifecycle = AgentLifecycle.READY
                agent.findings = []
                agent.messages = []
                agent.steps_taken = 0
                self._pool.remove(agent_id)
                return agent

        return self.spawn(role, task, parent_id)

    def activate(self, agent_id: str) -> None:
        """Activate an agent for execution."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.lifecycle = AgentLifecycle.BUSY
            agent.started_at = time.time()

    def complete_agent(
        self,
        agent_id: str,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Mark agent as completed."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.lifecycle = AgentLifecycle.TERMINATED
            agent.completed_at = time.time()
            if findings:
                agent.findings.extend(findings)

    def pool_agent(self, agent_id: str) -> None:
        """Return agent to pool for reuse."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.lifecycle = AgentLifecycle.IDLE
            self._pool.append(agent_id)

    def get_active_agents(self) -> list[SpawnedAgent]:
        """Get all active agents."""
        return [
            a for a in self._agents.values()
            if a.is_active
        ]

    def get_children(self, parent_id: str) -> list[SpawnedAgent]:
        """Get all children of a parent agent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return []
        return [
            self._agents[cid]
            for cid in parent.children
            if cid in self._agents
        ]

    def can_spawn(self) -> bool:
        """Check if we can spawn more agents."""
        active = len(self.get_active_agents())
        return active < self._max_concurrent

    def build_spawner_prompt(self) -> str:
        """Build spawner state for LLM."""
        lines = ["## Agents\n"]
        active = self.get_active_agents()
        lines.append(f"Active: {len(active)}/{self._max_concurrent}")
        lines.append(f"Pool: {len(self._pool)}")
        lines.append(f"Total: {len(self._agents)}")

        for agent in active[:5]:
            lines.append(
                f"  [{agent.role[:6]}] {agent.model[:12]} "
                f"step={agent.steps_taken}/{agent.max_steps} "
                f"findings={len(agent.findings)}"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        role_counts: dict[str, int] = {}
        for a in self._agents.values():
            role_counts[a.role] = role_counts.get(a.role, 0) + 1

        total_findings = sum(
            len(a.findings) for a in self._agents.values()
        )

        return {
            "total_agents": len(self._agents),
            "active": len(self.get_active_agents()),
            "pooled": len(self._pool),
            "findings": total_findings,
            "by_role": role_counts,
        }
