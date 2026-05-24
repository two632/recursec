"""Master orchestrator — ties all agent brain modules together.

Central integration point that wires:
1. State machine → controls assessment flow
2. Recursive planner → task decomposition
3. Prompt assembler → KB selection for LLM
4. Token budget → context window management
5. Chain-of-thought → structured reasoning
6. Model ensemble → multi-model coordination
7. Reward signals → learning feedback
8. Convergence → stopping criteria
9. Self-healing → error recovery
10. Collaboration → inter-agent sharing
11. Target profiler → target intelligence
12. Experience replay → learning from past
13. Delegation → child agent spawning
14. Tool effectiveness → tool selection
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OrchestratorMode(str, Enum):
    SINGLE_AGENT = "single_agent"
    MULTI_AGENT = "multi_agent"
    SWARM = "swarm"
    COMPETITIVE = "competitive"
    HIERARCHICAL = "hierarchical"


@dataclass
class AssessmentConfig:
    """Configuration for an assessment run."""
    target: str = ""
    scope: list[str] = field(default_factory=list)
    mode: OrchestratorMode = OrchestratorMode.MULTI_AGENT
    max_depth: int = 4
    max_agents: int = 10
    total_budget_tokens: int = 100000
    timeout_s: float = 3600.0
    auto_exploit: bool = False
    phases_enabled: list[str] = field(default_factory=lambda: [
        "recon", "enumeration", "scanning",
        "analysis", "exploitation", "validation",
        "reporting",
    ])

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "mode": self.mode.value[:10],
            "max_agents": self.max_agents,
            "phases": len(self.phases_enabled),
        }


@dataclass
class AgentInstance:
    """A running agent instance."""
    agent_id: str = ""
    role: str = ""
    model: str = ""
    parent_id: str = ""
    depth: int = 0
    task: str = ""
    status: str = "active"
    findings_count: int = 0
    started_at: float = field(default_factory=time.time)
    tokens_used: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "role": self.role[:10],
            "model": self.model[:12],
            "depth": self.depth,
            "status": self.status[:6],
        }


@dataclass
class AssessmentResult:
    """Result of an assessment run."""
    target: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    agents_spawned: int = 0
    total_tokens: int = 0
    duration_s: float = 0.0
    phases_completed: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "findings": len(self.findings),
            "risk": f"{self.risk_score:.1f}",
            "critical": self.critical_count,
            "high": self.high_count,
        }


# Role → preferred model mapping
ROLE_MODEL_MAP: dict[str, str] = {
    "security": "WhiteRabbitNeo",
    "code_audit": "Qwen2.5-Coder-14B",
    "reasoning": "DeepSeek-R1",
    "planning": "Hermes-4-14B",
    "fast_triage": "Phi-3.5-mini",
    "long_analysis": "Yi-9B-200K",
    "exploit_dev": "WhiteRabbitNeo",
    "general": "Mistral-7B",
    "uncensored": "Dolphin-2.9",
    "math_crypto": "DeepSeek-Math",
    "code": "CodeLlama-13B",
    "validation": "Qwen2.5-Coder-7B",
}

# Phase → agent roles needed
PHASE_ROLES: dict[str, list[str]] = {
    "recon": ["security", "general"],
    "enumeration": ["security", "fast_triage"],
    "scanning": ["security", "code_audit"],
    "analysis": ["reasoning", "security"],
    "exploitation": ["exploit_dev", "security"],
    "post_exploit": ["security", "uncensored"],
    "validation": ["validation", "reasoning"],
    "reporting": ["general", "planning"],
    "code_audit": ["code_audit", "code", "long_analysis"],
    "cloud_audit": ["security", "planning"],
    "container_audit": ["security", "code"],
}


class MasterOrchestrator:
    """Central orchestrator tying all brain modules together.

    Coordinates the full assessment lifecycle:
    - Spawns agents based on task complexity
    - Routes tasks to appropriate models
    - Manages state transitions
    - Tracks convergence and learning
    - Handles errors and recovery
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentInstance] = {}
        self._agent_counter = 0
        self._config: AssessmentConfig | None = None
        self._result: AssessmentResult | None = None
        self._started_at = 0.0
        self._log = logger.bind(component="orchestrator")

    def configure(self, config: AssessmentConfig) -> None:
        """Configure the orchestrator."""
        self._config = config
        self._result = AssessmentResult(target=config.target)

    def spawn_agent(
        self,
        role: str,
        task: str,
        parent_id: str = "",
        model: str = "",
        depth: int = 0,
    ) -> AgentInstance:
        """Spawn a new agent instance."""
        self._agent_counter += 1

        if not model:
            model = ROLE_MODEL_MAP.get(role, "Mistral-7B")

        agent = AgentInstance(
            agent_id=f"agent-{self._agent_counter}",
            role=role,
            model=model,
            parent_id=parent_id,
            depth=depth,
            task=task,
        )
        self._agents[agent.agent_id] = agent
        return agent

    def get_phase_agents(self, phase: str) -> list[str]:
        """Get agent roles needed for a phase."""
        return PHASE_ROLES.get(phase, ["general"])

    def retire_agent(
        self,
        agent_id: str,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Retire an agent after task completion."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.status = "retired"
        if findings:
            agent.findings_count = len(findings)
            if self._result:
                self._result.findings.extend(findings)

    def get_active_agents(self) -> list[AgentInstance]:
        """Get all active agents."""
        return [
            a for a in self._agents.values()
            if a.status == "active"
        ]

    def get_agent_tree(self) -> dict[str, list[str]]:
        """Get parent-child agent tree."""
        tree: dict[str, list[str]] = {}
        for agent in self._agents.values():
            parent = agent.parent_id or "root"
            if parent not in tree:
                tree[parent] = []
            tree[parent].append(agent.agent_id)
        return tree

    def should_spawn_child(
        self,
        parent_id: str,
        task_complexity: float,
    ) -> bool:
        """Decide if a child agent should be spawned."""
        if not self._config:
            return False

        parent = self._agents.get(parent_id)
        if not parent:
            return False

        # Depth limit
        if parent.depth >= self._config.max_depth:
            return False

        # Agent count limit
        active = len(self.get_active_agents())
        if active >= self._config.max_agents:
            return False

        # Complexity threshold
        return task_complexity > 0.6

    def select_model_for_task(
        self,
        task_type: str,
        context_length: int = 0,
    ) -> str:
        """Select the best model for a task."""
        # Long context → Yi-9B-200K
        if context_length > 8000:
            return "Yi-9B-200K"

        return ROLE_MODEL_MAP.get(task_type, "Mistral-7B")

    def record_finding(
        self,
        agent_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Record a finding from an agent."""
        if self._result:
            self._result.findings.append(finding)

            severity = finding.get("severity", "medium").lower()
            if severity == "critical":
                self._result.critical_count += 1
            elif severity == "high":
                self._result.high_count += 1
            elif severity == "medium":
                self._result.medium_count += 1
            elif severity == "low":
                self._result.low_count += 1

    def complete_phase(self, phase: str) -> None:
        """Mark a phase as completed."""
        if self._result and phase not in self._result.phases_completed:
            self._result.phases_completed.append(phase)

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score."""
        if not self._result:
            return 0.0

        score = (
            self._result.critical_count * 4.0 +
            self._result.high_count * 3.0 +
            self._result.medium_count * 2.0 +
            self._result.low_count * 1.0
        )
        return min(10.0, score)

    def build_orchestrator_prompt(self) -> str:
        """Build orchestrator context for LLM."""
        lines = ["## Orchestrator\n"]

        if self._config:
            lines.append(f"Target: {self._config.target[:20]}")
            lines.append(f"Mode: {self._config.mode.value}")

        active = self.get_active_agents()
        lines.append(f"Active agents: {len(active)}")
        lines.append(f"Total spawned: {len(self._agents)}")

        if self._result:
            lines.append(f"\nFindings: {len(self._result.findings)}")
            lines.append(
                f"  Critical: {self._result.critical_count}, "
                f"High: {self._result.high_count}, "
                f"Medium: {self._result.medium_count}"
            )
            lines.append(
                f"Phases done: {', '.join(self._result.phases_completed[:5])}"
            )

        # Agent tree summary
        if active:
            lines.append("\nActive:")
            for a in active[:5]:
                indent = "  " * a.depth
                lines.append(
                    f"{indent}{a.role[:10]} ({a.model[:10]}) "
                    f"→ {a.task[:20]}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        active = len(self.get_active_agents())
        return {
            "total_agents": len(self._agents),
            "active_agents": active,
            "findings": len(self._result.findings) if self._result else 0,
            "risk_score": self.calculate_risk_score(),
            "phases_completed": (
                self._result.phases_completed if self._result else []
            ),
        }
