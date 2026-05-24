"""Strategy optimizer — evolves strategies based on performance.

Implements:
1. Strategy performance tracking
2. A/B testing of different approaches
3. Multi-armed bandit selection (explore vs exploit)
4. Strategy mutation and crossover
5. Fitness scoring based on outcomes
6. Strategy recommendation engine
7. Optimizer prompt for LLM
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StrategyPhase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    VALIDATION = "validation"


@dataclass
class Strategy:
    """A specific strategy configuration."""
    strategy_id: str = ""
    name: str = ""
    phase: StrategyPhase = StrategyPhase.RECON
    parameters: dict[str, Any] = field(default_factory=dict)
    tool_sequence: list[str] = field(default_factory=list)
    knowledge_domains: list[str] = field(default_factory=list)
    trials: int = 0
    successes: int = 0
    total_findings: int = 0
    total_tokens: int = 0
    avg_duration_s: float = 0.0
    fitness: float = 0.5
    created_at: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        if self.trials == 0:
            return 0.0
        return self.successes / self.trials

    @property
    def ucb_score(self) -> float:
        """Upper Confidence Bound score for exploration."""
        if self.trials == 0:
            return float("inf")
        exploitation = self.success_rate
        exploration = math.sqrt(2 * math.log(max(1, self.trials + 1)) / self.trials)
        return exploitation + exploration

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.strategy_id[:10],
            "name": self.name[:20],
            "phase": self.phase.value[:6],
            "trials": self.trials,
            "success": f"{self.success_rate:.0%}",
            "fitness": round(self.fitness, 2),
        }


# ── Default strategies ───────────────────────────────────────

DEFAULT_STRATEGIES: list[dict[str, Any]] = [
    {
        "name": "Aggressive Recon",
        "phase": "recon",
        "params": {"depth": "deep", "breadth": "wide", "speed": "fast"},
        "tools": ["amass", "subfinder", "nmap", "masscan", "httpx"],
        "knowledge": ["network", "threat_intel"],
    },
    {
        "name": "Passive Recon",
        "phase": "recon",
        "params": {"depth": "shallow", "breadth": "wide", "speed": "slow"},
        "tools": ["subfinder", "theHarvester", "shodan", "crt.sh"],
        "knowledge": ["network", "threat_intel"],
    },
    {
        "name": "Targeted Recon",
        "phase": "recon",
        "params": {"depth": "deep", "breadth": "narrow", "speed": "slow"},
        "tools": ["amass", "dnsrecon", "whatweb"],
        "knowledge": ["network"],
    },
    {
        "name": "Broad Vulnerability Scan",
        "phase": "scanning",
        "params": {"templates": "all", "rate": "high", "severity": "all"},
        "tools": ["nuclei", "nikto", "wpscan"],
        "knowledge": ["web_security", "exploitation"],
    },
    {
        "name": "Targeted Vulnerability Scan",
        "phase": "scanning",
        "params": {"templates": "critical", "rate": "low", "severity": "high+"},
        "tools": ["nuclei", "sqlmap"],
        "knowledge": ["web_security", "exploitation"],
    },
    {
        "name": "Full Web Audit",
        "phase": "scanning",
        "params": {"methodology": "owasp", "coverage": "full"},
        "tools": ["burp", "zap", "ffuf", "sqlmap"],
        "knowledge": ["web_security", "api_security", "advanced_strategy"],
    },
    {
        "name": "Exploit Validation",
        "phase": "exploitation",
        "params": {"risk": "low", "approach": "verify_only"},
        "tools": ["sqlmap", "nuclei"],
        "knowledge": ["exploitation"],
    },
    {
        "name": "Full Exploitation",
        "phase": "exploitation",
        "params": {"risk": "medium", "approach": "exploit_and_pivot"},
        "tools": ["metasploit", "sqlmap", "hydra"],
        "knowledge": ["exploitation", "lateral_movement", "red_team"],
    },
    {
        "name": "Post-Exploit Enumeration",
        "phase": "post_exploit",
        "params": {"focus": "enumeration", "stealth": "medium"},
        "tools": ["linpeas", "winpeas", "bloodhound"],
        "knowledge": ["privilege_escalation", "active_directory"],
    },
]


class StrategyOptimizer:
    """Evolves assessment strategies based on performance.

    Tracks strategy outcomes, uses multi-armed bandit
    for selection, and mutates strategies to find
    optimal approaches.
    """

    def __init__(self) -> None:
        self._strategies: dict[str, Strategy] = {}
        self._counter = 0
        self._rng = random.Random(42)
        self._log = logger.bind(component="strategy_optimizer")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default strategies."""
        for spec in DEFAULT_STRATEGIES:
            self._counter += 1
            strategy = Strategy(
                strategy_id=f"strat-{self._counter}",
                name=spec["name"],
                phase=StrategyPhase(spec["phase"]),
                parameters=spec.get("params", {}),
                tool_sequence=spec.get("tools", []),
                knowledge_domains=spec.get("knowledge", []),
            )
            self._strategies[strategy.strategy_id] = strategy

    def select(
        self,
        phase: StrategyPhase,
        exploration_rate: float = 0.2,
    ) -> Strategy:
        """Select a strategy using epsilon-greedy + UCB."""
        candidates = [
            s for s in self._strategies.values()
            if s.phase == phase
        ]
        if not candidates:
            # Fallback: any strategy
            candidates = list(self._strategies.values())

        # Epsilon-greedy exploration
        if self._rng.random() < exploration_rate:
            return self._rng.choice(candidates)

        # UCB selection
        return max(candidates, key=lambda s: s.ucb_score)

    def record_outcome(
        self,
        strategy_id: str,
        success: bool,
        findings: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        """Record strategy outcome."""
        strategy = self._strategies.get(strategy_id)
        if not strategy:
            return

        strategy.trials += 1
        if success:
            strategy.successes += 1
        strategy.total_findings += findings
        strategy.total_tokens += tokens_used

        # Update running average duration
        if strategy.avg_duration_s == 0:
            strategy.avg_duration_s = duration_s
        else:
            strategy.avg_duration_s = (
                strategy.avg_duration_s * 0.8 + duration_s * 0.2
            )

        # Update fitness
        strategy.fitness = self._calculate_fitness(strategy)

    def _calculate_fitness(self, strategy: Strategy) -> float:
        """Calculate strategy fitness."""
        # Success rate component
        sr = strategy.success_rate * 0.4

        # Efficiency component
        if strategy.total_tokens > 0:
            eff = min(1.0, strategy.total_findings / strategy.total_tokens * 5000)
        else:
            eff = 0.0
        eff_component = eff * 0.3

        # Recency bonus (strategies tried recently score higher)
        trials_bonus = min(1.0, strategy.trials / 20) * 0.2

        # Finding rate
        if strategy.avg_duration_s > 0:
            rate = min(1.0, strategy.total_findings / strategy.avg_duration_s)
        else:
            rate = 0.0
        rate_component = rate * 0.1

        return sr + eff_component + trials_bonus + rate_component

    def mutate(self, strategy_id: str) -> Strategy | None:
        """Create a mutated variant of a strategy."""
        source = self._strategies.get(strategy_id)
        if not source:
            return None

        self._counter += 1
        mutated = Strategy(
            strategy_id=f"strat-{self._counter}",
            name=f"{source.name} (v{self._counter})",
            phase=source.phase,
            parameters=dict(source.parameters),
            tool_sequence=list(source.tool_sequence),
            knowledge_domains=list(source.knowledge_domains),
        )

        # Mutate parameters
        if mutated.parameters:
            key = self._rng.choice(list(mutated.parameters.keys()))
            if key == "depth":
                mutated.parameters[key] = self._rng.choice(["shallow", "medium", "deep"])
            elif key == "rate":
                mutated.parameters[key] = self._rng.choice(["low", "medium", "high"])
            elif key == "risk":
                mutated.parameters[key] = self._rng.choice(["low", "medium", "high"])

        self._strategies[mutated.strategy_id] = mutated
        return mutated

    def get_top_strategies(
        self,
        phase: StrategyPhase | None = None,
        limit: int = 5,
    ) -> list[Strategy]:
        """Get top-performing strategies."""
        candidates = list(self._strategies.values())
        if phase:
            candidates = [s for s in candidates if s.phase == phase]

        candidates.sort(key=lambda s: s.fitness, reverse=True)
        return candidates[:limit]

    def build_optimizer_prompt(
        self,
        phase: StrategyPhase | None = None,
    ) -> str:
        """Build optimizer context for LLM."""
        lines = ["## Strategy Optimizer\n"]

        lines.append(f"Total strategies: {len(self._strategies)}")

        top = self.get_top_strategies(phase=phase, limit=3)
        if top:
            lines.append(f"\nTop strategies{f' for {phase.value}' if phase else ''}:")
            for s in top:
                lines.append(
                    f"  {s.name[:20]} — "
                    f"fitness={s.fitness:.2f} "
                    f"success={s.success_rate:.0%} "
                    f"({s.trials} trials)"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = {}
        for s in self._strategies.values():
            p = s.phase.value
            phase_counts[p] = phase_counts.get(p, 0) + 1

        return {
            "total_strategies": len(self._strategies),
            "by_phase": phase_counts,
            "total_trials": sum(s.trials for s in self._strategies.values()),
            "avg_fitness": sum(s.fitness for s in self._strategies.values()) / max(1, len(self._strategies)),
        }
