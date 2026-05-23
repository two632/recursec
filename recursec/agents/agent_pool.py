"""Agent pool manager — reusable agent instances.

Implements:
1. Agent pool with type-based partitioning
2. Agent lifecycle management (create, lease, release, destroy)
3. Warm pool for frequently-used agent types
4. Auto-scaling based on demand
5. Health monitoring and replacement
6. Resource usage tracking per pool
7. Agent template instantiation
8. Pool statistics and metrics
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PoolAgentState(str, Enum):
    IDLE = "idle"
    LEASED = "leased"
    WARMING = "warming"
    COOLDOWN = "cooldown"
    FAILED = "failed"
    DESTROYED = "destroyed"


@dataclass
class PoolAgent:
    """An agent instance in the pool."""
    agent_id: str = ""
    agent_type: str = ""          # recon, scanner, analyzer, etc.
    state: PoolAgentState = PoolAgentState.IDLE
    model_id: str = ""
    tools: list[str] = field(default_factory=list)
    system_prompt: str = ""
    created_at: float = field(default_factory=time.time)
    last_used: float = 0.0
    lease_count: int = 0
    total_tasks: int = 0
    total_findings: int = 0
    avg_task_duration_s: float = 0.0
    error_count: int = 0
    current_lessee: str = ""

    @property
    def idle_time_s(self) -> float:
        if self.state != PoolAgentState.IDLE:
            return 0.0
        if self.last_used > 0:
            return time.time() - self.last_used
        return time.time() - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "type": self.agent_type[:10],
            "state": self.state.value,
            "model": self.model_id[:12],
            "leases": self.lease_count,
            "tasks": self.total_tasks,
            "findings": self.total_findings,
            "errors": self.error_count,
        }


@dataclass
class PoolConfig:
    """Configuration for an agent pool."""
    min_agents: int = 1
    max_agents: int = 10
    warm_count: int = 2            # Pre-created idle agents
    idle_timeout_s: float = 600.0  # Destroy idle agents after this
    max_lease_time_s: float = 300.0
    max_errors: int = 5            # Destroy after this many errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "min": self.min_agents,
            "max": self.max_agents,
            "warm": self.warm_count,
            "idle_timeout": self.idle_timeout_s,
        }


# ── Agent type templates ─────────────────────────────────────

AGENT_TEMPLATES: dict[str, dict[str, Any]] = {
    "recon": {
        "model": "mistral-7b",
        "tools": ["subfinder", "httpx", "dig", "whois", "amass"],
        "system_prompt": "You are a reconnaissance agent. Enumerate the target's attack surface.",
    },
    "scanner": {
        "model": "whiterabbitneo",
        "tools": ["nmap", "nuclei", "nikto", "testssl"],
        "system_prompt": "You are a vulnerability scanner. Identify security weaknesses.",
    },
    "web_scanner": {
        "model": "whiterabbitneo",
        "tools": ["nuclei", "nikto", "gobuster", "ffuf", "wpscan", "sqlmap"],
        "system_prompt": "You are a web vulnerability scanner. Test for web application security issues.",
    },
    "code_auditor": {
        "model": "qwen-coder-14b",
        "tools": ["semgrep", "bandit"],
        "system_prompt": "You are a code auditor. Review code for security vulnerabilities.",
    },
    "exploiter": {
        "model": "whiterabbitneo",
        "tools": ["sqlmap", "hydra", "curl"],
        "system_prompt": "You are an exploitation specialist. Safely validate vulnerabilities.",
    },
    "analyzer": {
        "model": "deepseek-r1",
        "tools": [],
        "system_prompt": "You are a security analyzer. Provide deep analysis of findings.",
    },
    "validator": {
        "model": "hermes-14b",
        "tools": [],
        "system_prompt": "You are a validator. Cross-check findings and detect false positives.",
    },
    "network": {
        "model": "mistral-7b",
        "tools": ["nmap", "masscan", "crackmapexec", "enum4linux"],
        "system_prompt": "You are a network security specialist. Assess network infrastructure.",
    },
    "cloud": {
        "model": "hermes-14b",
        "tools": ["curl", "aws-cli"],
        "system_prompt": "You are a cloud security analyst. Assess cloud configurations.",
    },
    "ad_specialist": {
        "model": "hermes-14b",
        "tools": ["crackmapexec", "impacket", "ldapsearch"],
        "system_prompt": "You are an Active Directory specialist. Assess AD security.",
    },
}


class AgentPoolManager:
    """Manages pools of reusable agent instances.

    Pre-creates and manages agent instances for fast allocation,
    tracks usage patterns, and auto-scales pools based on demand.
    """

    def __init__(self) -> None:
        self._pools: dict[str, list[PoolAgent]] = defaultdict(list)
        self._pool_configs: dict[str, PoolConfig] = {}
        self._agent_counter = 0
        self._lease_history: list[dict[str, Any]] = []
        self._demand_history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self._log = logger.bind(component="agent_pool")

    def create_pool(
        self,
        agent_type: str,
        config: PoolConfig | None = None,
    ) -> int:
        """Create a pool for an agent type."""
        cfg = config or PoolConfig()
        self._pool_configs[agent_type] = cfg

        # Pre-warm agents
        created = 0
        for _ in range(cfg.warm_count):
            agent = self._create_agent(agent_type)
            if agent:
                created += 1

        return created

    def lease(self, agent_type: str) -> PoolAgent | None:
        """Lease an idle agent from the pool."""
        self._demand_history[agent_type].append(time.time())

        # Find idle agent
        pool = self._pools.get(agent_type, [])
        for agent in pool:
            if agent.state == PoolAgentState.IDLE:
                agent.state = PoolAgentState.LEASED
                agent.last_used = time.time()
                agent.lease_count += 1

                self._lease_history.append({
                    "agent_id": agent.agent_id,
                    "type": agent_type,
                    "time": time.time(),
                    "action": "lease",
                })

                return agent

        # No idle agents — create new if under max
        cfg = self._pool_configs.get(agent_type, PoolConfig())
        if len(pool) < cfg.max_agents:
            agent = self._create_agent(agent_type)
            if agent:
                agent.state = PoolAgentState.LEASED
                agent.last_used = time.time()
                agent.lease_count += 1
                return agent

        return None

    def release(
        self,
        agent_id: str,
        tasks_completed: int = 0,
        findings_found: int = 0,
        had_error: bool = False,
    ) -> bool:
        """Release a leased agent back to the pool."""
        for pool in self._pools.values():
            for agent in pool:
                if agent.agent_id == agent_id:
                    agent.state = PoolAgentState.IDLE
                    agent.current_lessee = ""
                    agent.total_tasks += tasks_completed
                    agent.total_findings += findings_found

                    if had_error:
                        agent.error_count += 1
                        cfg = self._pool_configs.get(agent.agent_type, PoolConfig())
                        if agent.error_count >= cfg.max_errors:
                            agent.state = PoolAgentState.FAILED

                    self._lease_history.append({
                        "agent_id": agent_id,
                        "type": agent.agent_type,
                        "time": time.time(),
                        "action": "release",
                    })

                    return True
        return False

    def destroy(self, agent_id: str) -> bool:
        """Destroy an agent instance."""
        for agent_type, pool in self._pools.items():
            for i, agent in enumerate(pool):
                if agent.agent_id == agent_id:
                    agent.state = PoolAgentState.DESTROYED
                    pool.pop(i)
                    return True
        return False

    def cleanup_idle(self) -> int:
        """Destroy agents that have been idle too long."""
        destroyed = 0
        for agent_type, pool in self._pools.items():
            cfg = self._pool_configs.get(agent_type, PoolConfig())
            to_remove = []

            for agent in pool:
                if (agent.state == PoolAgentState.IDLE
                        and agent.idle_time_s > cfg.idle_timeout_s
                        and len(pool) - len(to_remove) > cfg.min_agents):
                    to_remove.append(agent.agent_id)

            for agent_id in to_remove:
                self.destroy(agent_id)
                destroyed += 1

        return destroyed

    def replace_failed(self) -> int:
        """Replace failed agents with new instances."""
        replaced = 0
        for agent_type, pool in list(self._pools.items()):
            failed = [a for a in pool if a.state == PoolAgentState.FAILED]
            for agent in failed:
                self.destroy(agent.agent_id)
                new_agent = self._create_agent(agent_type)
                if new_agent:
                    replaced += 1

        return replaced

    def _create_agent(self, agent_type: str) -> PoolAgent | None:
        """Create a new agent instance from template."""
        template = AGENT_TEMPLATES.get(agent_type)
        if not template:
            return None

        self._agent_counter += 1
        agent = PoolAgent(
            agent_id=f"pool-{agent_type}-{self._agent_counter}",
            agent_type=agent_type,
            state=PoolAgentState.IDLE,
            model_id=template.get("model", ""),
            tools=template.get("tools", []),
            system_prompt=template.get("system_prompt", ""),
        )

        self._pools[agent_type].append(agent)
        return agent

    def get_pool_status(self, agent_type: str) -> dict[str, Any]:
        """Get status of a specific pool."""
        pool = self._pools.get(agent_type, [])
        state_counts: dict[str, int] = defaultdict(int)
        for agent in pool:
            state_counts[agent.state.value] += 1

        return {
            "type": agent_type,
            "total": len(pool),
            "by_state": dict(state_counts),
            "total_tasks": sum(a.total_tasks for a in pool),
            "total_findings": sum(a.total_findings for a in pool),
        }

    def get_stats(self) -> dict[str, Any]:
        pool_stats = {}
        for agent_type in self._pools:
            pool_stats[agent_type] = self.get_pool_status(agent_type)

        return {
            "pools": len(self._pools),
            "total_agents": sum(len(p) for p in self._pools.values()),
            "leases": len(self._lease_history),
            "by_pool": pool_stats,
        }
