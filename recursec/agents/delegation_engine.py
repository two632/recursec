"""Agent delegation engine — decides when/how to spawn child agents.

Implements:
1. Task complexity estimation
2. Delegation decision logic
3. Agent role selection
4. Resource allocation
5. Result aggregation strategy
6. Delegation prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DelegationStrategy(str, Enum):
    NONE = "none"               # Handle task directly
    SINGLE = "single"           # Delegate to one specialist
    PARALLEL = "parallel"       # Split across multiple agents
    SEQUENTIAL = "sequential"   # Chain of specialists
    HIERARCHICAL = "hierarchical"  # Tree of sub-delegates
    COMPETITIVE = "competitive"   # Multiple agents, best wins


class ComplexityLevel(str, Enum):
    TRIVIAL = "trivial"         # Direct LLM response
    SIMPLE = "simple"           # Single tool call
    MODERATE = "moderate"       # Multiple tools, single agent
    COMPLEX = "complex"         # Multiple agents needed
    VERY_COMPLEX = "very_complex"  # Deep hierarchical delegation


@dataclass
class DelegationDecision:
    """A delegation decision."""
    decision_id: str = ""
    task: str = ""
    complexity: ComplexityLevel = ComplexityLevel.MODERATE
    strategy: DelegationStrategy = DelegationStrategy.NONE
    agent_roles: list[str] = field(default_factory=list)
    model_preferences: list[str] = field(default_factory=list)
    estimated_steps: int = 1
    token_budget: int = 2048
    timeout_s: float = 300.0
    reasoning: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "complexity": self.complexity.value[:8],
            "strategy": self.strategy.value[:8],
            "agents": len(self.agent_roles),
            "budget": self.token_budget,
        }


# Task keywords → complexity signals
COMPLEXITY_SIGNALS: dict[str, int] = {
    "scan": 1,
    "check": 1,
    "enumerate": 2,
    "discover": 2,
    "analyze": 2,
    "exploit": 3,
    "privilege escalation": 3,
    "lateral movement": 3,
    "full assessment": 4,
    "pentest": 4,
    "red team": 5,
    "adversary emulation": 5,
    "zero-day": 5,
}

# Complexity → delegation strategy
COMPLEXITY_STRATEGY: dict[ComplexityLevel, DelegationStrategy] = {
    ComplexityLevel.TRIVIAL: DelegationStrategy.NONE,
    ComplexityLevel.SIMPLE: DelegationStrategy.NONE,
    ComplexityLevel.MODERATE: DelegationStrategy.SINGLE,
    ComplexityLevel.COMPLEX: DelegationStrategy.PARALLEL,
    ComplexityLevel.VERY_COMPLEX: DelegationStrategy.HIERARCHICAL,
}

# Task type → recommended agent roles
TASK_ROLES: dict[str, list[str]] = {
    "recon": ["recon", "osint"],
    "scan": ["scanner", "vuln_analyzer"],
    "web": ["web_auditor", "api_tester"],
    "exploit": ["exploit_dev", "validator"],
    "code": ["code_auditor", "static_analyzer"],
    "network": ["network_scanner", "protocol_analyzer"],
    "cloud": ["cloud_auditor", "config_checker"],
    "ad": ["ad_auditor", "privesc"],
    "container": ["container_auditor", "k8s_checker"],
    "wireless": ["wireless_scanner"],
    "social": ["social_eng", "osint"],
    "postexploit": ["postexploit", "data_collector", "persistence"],
}


class DelegationEngine:
    """Decides when and how to delegate tasks to child agents.

    Estimates complexity, selects strategy, assigns
    roles, and determines resource allocation.
    """

    def __init__(
        self,
        max_depth: int = 4,
        max_parallel: int = 5,
        default_timeout_s: float = 300.0,
        default_token_budget: int = 4096,
    ) -> None:
        self._max_depth = max_depth
        self._max_parallel = max_parallel
        self._default_timeout = default_timeout_s
        self._default_budget = default_token_budget
        self._decisions: list[DelegationDecision] = []
        self._decision_counter = 0
        self._log = logger.bind(component="delegation")

    def _estimate_complexity(self, task: str) -> ComplexityLevel:
        """Estimate task complexity from description."""
        lower = task.lower()
        max_signal = 0

        for keyword, signal in COMPLEXITY_SIGNALS.items():
            if keyword in lower:
                max_signal = max(max_signal, signal)

        # Word count as additional signal
        words = len(task.split())
        if words > 50:
            max_signal = max(max_signal, 3)
        elif words > 20:
            max_signal = max(max_signal, 2)

        if max_signal <= 1:
            return ComplexityLevel.TRIVIAL if max_signal == 0 else ComplexityLevel.SIMPLE
        if max_signal == 2:
            return ComplexityLevel.MODERATE
        if max_signal <= 4:
            return ComplexityLevel.COMPLEX
        return ComplexityLevel.VERY_COMPLEX

    def _select_roles(self, task: str) -> list[str]:
        """Select agent roles based on task."""
        lower = task.lower()
        roles: list[str] = []

        for task_type, type_roles in TASK_ROLES.items():
            if task_type in lower:
                for role in type_roles:
                    if role not in roles:
                        roles.append(role)

        # Default role if nothing matched
        if not roles:
            roles = ["general"]

        return roles[:self._max_parallel]

    def _select_models(self, roles: list[str]) -> list[str]:
        """Suggest models for agent roles."""
        role_model_map: dict[str, str] = {
            "recon": "Mistral-7B",
            "osint": "Yi-9B-200K",
            "scanner": "Phi-3.5-mini",
            "vuln_analyzer": "DeepSeek-R1",
            "web_auditor": "WhiteRabbitNeo",
            "api_tester": "Qwen2.5-Coder-7B",
            "exploit_dev": "WhiteRabbitNeo",
            "validator": "DeepSeek-R1",
            "code_auditor": "Qwen2.5-Coder-14B",
            "static_analyzer": "CodeLlama-13B",
            "network_scanner": "Phi-3.5-mini",
            "protocol_analyzer": "DeepSeek-R1",
            "cloud_auditor": "Hermes-4-14B",
            "config_checker": "Qwen2.5-Coder-7B",
            "ad_auditor": "WhiteRabbitNeo",
            "privesc": "Dolphin-2.9",
            "container_auditor": "Qwen2.5-Coder-7B",
            "k8s_checker": "Mistral-7B",
            "wireless_scanner": "Phi-3.5-mini",
            "social_eng": "Dolphin-2.9",
            "postexploit": "WhiteRabbitNeo",
            "data_collector": "Llama-3.1-8B",
            "persistence": "WhiteRabbitNeo",
            "general": "Hermes-4-14B",
        }

        models = []
        for role in roles:
            model = role_model_map.get(role, "Hermes-4-14B")
            models.append(model)

        return models

    def decide(
        self,
        task: str,
        current_depth: int = 0,
        available_budget: int = 0,
    ) -> DelegationDecision:
        """Make a delegation decision for a task."""
        self._decision_counter += 1

        complexity = self._estimate_complexity(task)

        # Reduce complexity at deeper levels
        if current_depth >= self._max_depth - 1:
            complexity = ComplexityLevel.SIMPLE

        strategy = COMPLEXITY_STRATEGY.get(complexity, DelegationStrategy.NONE)

        roles = self._select_roles(task) if strategy != DelegationStrategy.NONE else []
        models = self._select_models(roles) if roles else []

        # Resource allocation
        budget = available_budget or self._default_budget
        if strategy == DelegationStrategy.PARALLEL:
            per_agent = budget // max(1, len(roles))
        else:
            per_agent = budget

        # Estimate steps
        steps_map = {
            ComplexityLevel.TRIVIAL: 1,
            ComplexityLevel.SIMPLE: 3,
            ComplexityLevel.MODERATE: 8,
            ComplexityLevel.COMPLEX: 15,
            ComplexityLevel.VERY_COMPLEX: 30,
        }

        decision = DelegationDecision(
            decision_id=f"del-{self._decision_counter}",
            task=task,
            complexity=complexity,
            strategy=strategy,
            agent_roles=roles,
            model_preferences=models,
            estimated_steps=steps_map.get(complexity, 5),
            token_budget=per_agent,
            timeout_s=self._default_timeout,
            reasoning=f"Complexity={complexity.value}, depth={current_depth}/{self._max_depth}",
        )

        self._decisions.append(decision)
        return decision

    def build_delegation_prompt(self) -> str:
        """Build delegation context for LLM."""
        lines = ["## Delegation\n"]
        lines.append(f"Max depth: {self._max_depth}")
        lines.append(f"Max parallel: {self._max_parallel}")
        lines.append(f"Decisions made: {len(self._decisions)}")

        # Recent decisions
        recent = self._decisions[-3:]
        if recent:
            lines.append("\nRecent:")
            for d in recent:
                lines.append(
                    f"  [{d.complexity.value[:6]}] {d.strategy.value[:8]} "
                    f"→ {len(d.agent_roles)} agents"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        complexity_counts: dict[str, int] = {}
        strategy_counts: dict[str, int] = {}
        for d in self._decisions:
            complexity_counts[d.complexity.value] = complexity_counts.get(d.complexity.value, 0) + 1
            strategy_counts[d.strategy.value] = strategy_counts.get(d.strategy.value, 0) + 1

        return {
            "decisions": len(self._decisions),
            "by_complexity": complexity_counts,
            "by_strategy": strategy_counts,
        }
