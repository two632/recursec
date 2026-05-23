"""Strategy optimizer — optimizes agent strategies using reinforcement learning.

Implements:
1. Multi-armed bandit for strategy selection
2. Upper Confidence Bound (UCB1) exploration
3. Thompson sampling for uncertain strategies
4. Contextual bandits (strategy depends on target features)
5. Strategy performance tracking
6. Exploration vs exploitation balance
7. Strategy adaptation based on feedback
8. Strategy portfolio management
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Strategy:
    """A strategy option."""
    strategy_id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""             # recon, scanning, exploit, analysis
    applicable_to: list[str] = field(default_factory=list)  # target types
    # Performance stats
    total_uses: int = 0
    total_reward: float = 0.0
    successes: int = 0
    failures: int = 0
    avg_reward: float = 0.0
    # Thompson sampling parameters
    alpha: float = 1.0             # Beta distribution alpha (successes + 1)
    beta_param: float = 1.0        # Beta distribution beta (failures + 1)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successes / self.total_uses

    @property
    def ucb1_score(self) -> float:
        """Upper Confidence Bound score."""
        if self.total_uses == 0:
            return float("inf")
        exploitation = self.avg_reward
        exploration = math.sqrt(2.0 * math.log(max(1, self.total_uses * 10)) / self.total_uses)
        return exploitation + exploration

    def thompson_sample(self) -> float:
        """Sample from Beta distribution for Thompson sampling."""
        return random.betavariate(self.alpha, self.beta_param)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.strategy_id, "name": self.name[:40],
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
            "avg_reward": round(self.avg_reward, 2),
            "ucb1": round(self.ucb1_score, 2) if self.total_uses > 0 else "inf",
        }


@dataclass
class ContextFeatures:
    """Features of the current context for contextual bandits."""
    target_type: str = ""          # web, network, api, cloud
    has_waf: bool = False
    has_auth: bool = False
    tech_stack: list[str] = field(default_factory=list)
    open_ports: int = 0
    previous_findings: int = 0
    time_remaining_s: float = 3600.0
    budget_remaining: float = 1.0  # 0.0-1.0

    def to_feature_key(self) -> str:
        """Convert to a hashable feature key."""
        parts = [
            self.target_type,
            "waf" if self.has_waf else "no_waf",
            "auth" if self.has_auth else "no_auth",
            f"ports_{min(self.open_ports, 100)}",
        ]
        return ":".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.target_type,
            "waf": self.has_waf,
            "auth": self.has_auth,
            "ports": self.open_ports,
            "findings": self.previous_findings,
        }


# ── Default Strategies ────────────────────────────────────────

DEFAULT_STRATEGIES: list[dict[str, Any]] = [
    {
        "name": "Breadth-first recon",
        "desc": "Wide reconnaissance before deep analysis",
        "cat": "recon", "applicable": ["web", "network", "api"],
    },
    {
        "name": "Depth-first exploitation",
        "desc": "Deep dive into first promising finding",
        "cat": "exploit", "applicable": ["web", "api"],
    },
    {
        "name": "Parallel multi-tool scan",
        "desc": "Run multiple scanners simultaneously",
        "cat": "scanning", "applicable": ["web", "network"],
    },
    {
        "name": "Stealth progressive scan",
        "desc": "Slow, careful scanning to avoid detection",
        "cat": "scanning", "applicable": ["web", "network"],
    },
    {
        "name": "API fuzzing intensive",
        "desc": "Heavy fuzzing of API endpoints",
        "cat": "exploit", "applicable": ["api"],
    },
    {
        "name": "Credential-first approach",
        "desc": "Prioritize finding valid credentials",
        "cat": "exploit", "applicable": ["web", "network"],
    },
    {
        "name": "Configuration audit",
        "desc": "Focus on misconfigurations and defaults",
        "cat": "analysis", "applicable": ["web", "network", "cloud"],
    },
    {
        "name": "Supply chain analysis",
        "desc": "Analyze dependencies and third-party risks",
        "cat": "analysis", "applicable": ["web", "api"],
    },
    {
        "name": "Network lateral exploration",
        "desc": "Map network topology and lateral paths",
        "cat": "recon", "applicable": ["network"],
    },
    {
        "name": "Cloud resource enumeration",
        "desc": "Enumerate cloud services and misconfigs",
        "cat": "recon", "applicable": ["cloud"],
    },
]


class StrategyOptimizer:
    """Optimizes agent strategies using multi-armed bandit algorithms.

    Balances exploration (trying new strategies) with
    exploitation (using known-good strategies) based on
    accumulated performance data.
    """

    def __init__(
        self,
        exploration_rate: float = 0.1,
        method: str = "ucb1",       # ucb1, thompson, epsilon_greedy
    ) -> None:
        self._strategies: dict[str, Strategy] = {}
        self._method = method
        self._exploration_rate = exploration_rate
        self._strategy_counter = 0
        self._selection_count = 0
        # Contextual performance tracking
        self._context_rewards: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._context_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._log = logger.bind(component="strategy_optimizer")

        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default strategies."""
        for data in DEFAULT_STRATEGIES:
            self._strategy_counter += 1
            strategy = Strategy(
                strategy_id=f"strat-{self._strategy_counter}",
                name=data["name"],
                description=data.get("desc", ""),
                category=data.get("cat", ""),
                applicable_to=data.get("applicable", []),
            )
            self._strategies[strategy.strategy_id] = strategy

    def select(
        self,
        context: ContextFeatures | None = None,
        category: str = "",
    ) -> Strategy | None:
        """Select the best strategy."""
        self._selection_count += 1

        # Filter applicable strategies
        candidates = list(self._strategies.values())
        if context and context.target_type:
            candidates = [
                s for s in candidates
                if not s.applicable_to or context.target_type in s.applicable_to
            ]
        if category:
            candidates = [s for s in candidates if s.category == category]

        if not candidates:
            return None

        # Selection method
        if self._method == "ucb1":
            return self._ucb1_select(candidates)
        elif self._method == "thompson":
            return self._thompson_select(candidates)
        else:
            return self._epsilon_greedy_select(candidates)

    def _ucb1_select(self, candidates: list[Strategy]) -> Strategy:
        """Select using UCB1 algorithm."""
        return max(candidates, key=lambda s: s.ucb1_score)

    def _thompson_select(self, candidates: list[Strategy]) -> Strategy:
        """Select using Thompson sampling."""
        return max(candidates, key=lambda s: s.thompson_sample())

    def _epsilon_greedy_select(self, candidates: list[Strategy]) -> Strategy:
        """Select using epsilon-greedy."""
        if random.random() < self._exploration_rate:
            return random.choice(candidates)
        # Exploit: best known
        tried = [s for s in candidates if s.total_uses > 0]
        if not tried:
            return random.choice(candidates)
        return max(tried, key=lambda s: s.avg_reward)

    def record_reward(
        self,
        strategy_id: str,
        reward: float,
        success: bool = True,
        context: ContextFeatures | None = None,
    ) -> None:
        """Record the outcome of using a strategy."""
        strategy = self._strategies.get(strategy_id)
        if not strategy:
            return

        strategy.total_uses += 1
        strategy.total_reward += reward
        strategy.avg_reward = strategy.total_reward / strategy.total_uses

        if success:
            strategy.successes += 1
            strategy.alpha += 1.0
        else:
            strategy.failures += 1
            strategy.beta_param += 1.0

        # Contextual tracking
        if context:
            ctx_key = context.to_feature_key()
            self._context_rewards[ctx_key][strategy_id] += reward
            self._context_counts[ctx_key][strategy_id] += 1

    def get_recommendations(
        self,
        context: ContextFeatures | None = None,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Get top-k strategy recommendations."""
        candidates = list(self._strategies.values())
        if context and context.target_type:
            candidates = [
                s for s in candidates
                if not s.applicable_to or context.target_type in s.applicable_to
            ]

        # Score by UCB1
        scored = sorted(candidates, key=lambda s: s.ucb1_score, reverse=True)
        return [s.to_dict() for s in scored[:top_k]]

    def get_stats(self) -> dict[str, Any]:
        total_uses = sum(s.total_uses for s in self._strategies.values())
        return {
            "strategies": len(self._strategies),
            "selections": self._selection_count,
            "total_uses": total_uses,
            "method": self._method,
        }
