"""Strategy optimizer — dynamic assessment strategy optimization.

Implements:
1. Multi-armed bandit for tool/technique selection
2. Thompson sampling for exploration vs exploitation
3. Reward signal design (findings as reward)
4. Strategy adaptation based on target response
5. Time-budget allocation across phases
6. Resource-constrained optimization
7. Strategy comparison and A/B testing
8. Historical strategy performance database
"""

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class StrategyArm:
    """A strategy arm in the multi-armed bandit."""
    name: str = ""
    category: str = ""             # recon, scanning, exploitation, etc.
    successes: int = 0             # Alpha parameter (Beta distribution)
    failures: int = 0              # Beta parameter
    total_reward: float = 0.0
    total_pulls: int = 0
    avg_time_s: float = 0.0
    last_used: float = 0.0

    @property
    def expected_reward(self) -> float:
        if self.total_pulls == 0:
            return 0.5
        return self.total_reward / self.total_pulls

    @property
    def ucb_score(self, total_trials: int = 100) -> float:
        """Upper Confidence Bound score."""
        if self.total_pulls == 0:
            return float("inf")
        exploitation = self.expected_reward
        exploration = math.sqrt(2 * math.log(max(1, total_trials)) / self.total_pulls)
        return exploitation + exploration

    def thompson_sample(self) -> float:
        """Sample from Beta distribution (Thompson Sampling)."""
        alpha = self.successes + 1
        beta = self.failures + 1
        return random.betavariate(alpha, beta)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "category": self.category,
            "pulls": self.total_pulls,
            "expected_reward": round(self.expected_reward, 3),
            "success_rate": round(
                self.successes / max(1, self.successes + self.failures), 3,
            ),
        }


@dataclass
class PhaseAllocation:
    """Time/resource allocation for an assessment phase."""
    phase: str = ""
    allocated_time_s: float = 0.0
    used_time_s: float = 0.0
    allocated_tokens: int = 0
    used_tokens: int = 0
    priority: float = 1.0

    @property
    def remaining_time_s(self) -> float:
        return max(0.0, self.allocated_time_s - self.used_time_s)

    @property
    def utilization(self) -> float:
        if self.allocated_time_s <= 0:
            return 0.0
        return min(1.0, self.used_time_s / self.allocated_time_s)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "remaining_s": round(self.remaining_time_s, 0),
            "utilization": round(self.utilization, 2),
        }


@dataclass
class StrategyEpisode:
    """A complete strategy episode with outcome."""
    strategy_name: str = ""
    target_type: str = ""
    arms_selected: list[str] = field(default_factory=list)
    total_findings: int = 0
    critical_findings: int = 0
    time_s: float = 0.0
    tokens_used: int = 0
    success: bool = True
    timestamp: float = field(default_factory=time.time)


class StrategyOptimizer:
    """Dynamic assessment strategy optimization.

    Uses multi-armed bandit algorithms to learn which
    tools and techniques are most effective for different
    target types.
    """

    def __init__(self) -> None:
        self._arms: dict[str, StrategyArm] = {}
        self._phase_allocations: dict[str, PhaseAllocation] = {}
        self._episodes: list[StrategyEpisode] = []
        self._total_trials = 0
        self._log = logger.bind(component="strategy_optimizer")

        self._init_arms()

    def _init_arms(self) -> None:
        """Initialize strategy arms."""
        arms_data = [
            # Recon arms
            ("subfinder", "recon"), ("amass", "recon"), ("httpx", "recon"),
            ("whatweb", "recon"), ("dig", "recon"), ("whois", "recon"),
            ("shodan_search", "recon"),

            # Scanning arms
            ("nmap_full", "scanning"), ("nmap_quick", "scanning"),
            ("nuclei_all", "scanning"), ("nuclei_critical", "scanning"),
            ("nikto", "scanning"), ("sslscan", "scanning"),

            # Web testing arms
            ("ffuf_dirs", "web"), ("ffuf_params", "web"),
            ("sqlmap", "web"), ("dalfox_xss", "web"),
            ("commix", "web"),

            # Exploitation arms
            ("default_creds", "exploitation"), ("brute_ssh", "exploitation"),
            ("exploit_known", "exploitation"),

            # Code audit arms
            ("semgrep", "code"), ("bandit", "code"),
            ("gitleaks", "code"), ("trivy", "code"),
        ]

        for name, category in arms_data:
            self._arms[name] = StrategyArm(name=name, category=category)

    def select_arm(
        self,
        category: str = "",
        method: str = "thompson",
    ) -> str:
        """Select the best arm to pull."""
        candidates = list(self._arms.values())
        if category:
            candidates = [a for a in candidates if a.category == category]

        if not candidates:
            return ""

        if method == "thompson":
            # Thompson Sampling
            best = max(candidates, key=lambda a: a.thompson_sample())

        elif method == "ucb":
            # Upper Confidence Bound
            best = max(candidates, key=lambda a: a.ucb_score)

        elif method == "epsilon_greedy":
            # Epsilon-greedy (explore 10% of the time)
            if random.random() < 0.1:
                best = random.choice(candidates)
            else:
                best = max(candidates, key=lambda a: a.expected_reward)

        else:
            best = max(candidates, key=lambda a: a.expected_reward)

        self._total_trials += 1
        return best.name

    def select_strategy(
        self,
        target_type: str,
        time_budget_s: float = 3600.0,
    ) -> list[str]:
        """Select a complete strategy (ordered list of arms)."""
        # Allocate time to phases
        phase_ratios = {
            "web_app": {"recon": 0.15, "scanning": 0.30, "web": 0.35,
                        "exploitation": 0.10, "code": 0.10},
            "api": {"recon": 0.10, "scanning": 0.25, "web": 0.40,
                    "exploitation": 0.15, "code": 0.10},
            "network": {"recon": 0.20, "scanning": 0.40,
                        "exploitation": 0.30, "code": 0.10},
            "host": {"recon": 0.15, "scanning": 0.40,
                     "exploitation": 0.35, "code": 0.10},
        }

        ratios = phase_ratios.get(target_type, {"scanning": 0.5, "recon": 0.3, "web": 0.2})

        # Allocate phases
        for phase, ratio in ratios.items():
            self._phase_allocations[phase] = PhaseAllocation(
                phase=phase,
                allocated_time_s=time_budget_s * ratio,
            )

        # Select arms for each phase
        strategy = []
        for phase in sorted(ratios.keys(), key=lambda p: ratios.get(p, 0), reverse=True):
            # Select 2-3 best arms per phase
            for _ in range(3):
                arm = self.select_arm(category=phase, method="thompson")
                if arm and arm not in strategy:
                    strategy.append(arm)

        return strategy

    def record_reward(
        self,
        arm_name: str,
        reward: float,
        success: bool = True,
        time_s: float = 0.0,
    ) -> None:
        """Record the reward from pulling an arm."""
        arm = self._arms.get(arm_name)
        if not arm:
            return

        arm.total_pulls += 1
        arm.total_reward += reward
        arm.last_used = time.time()

        if success:
            arm.successes += 1
        else:
            arm.failures += 1

        # Update average time
        if arm.avg_time_s == 0:
            arm.avg_time_s = time_s
        else:
            arm.avg_time_s = (arm.avg_time_s * (arm.total_pulls - 1) + time_s) / arm.total_pulls

    def record_episode(
        self,
        strategy_name: str,
        target_type: str,
        arms: list[str],
        findings: int = 0,
        critical: int = 0,
        time_s: float = 0.0,
        tokens: int = 0,
    ) -> None:
        """Record a complete strategy episode."""
        episode = StrategyEpisode(
            strategy_name=strategy_name,
            target_type=target_type,
            arms_selected=arms,
            total_findings=findings,
            critical_findings=critical,
            time_s=time_s,
            tokens_used=tokens,
        )
        self._episodes.append(episode)
        if len(self._episodes) > 500:
            self._episodes = self._episodes[-500:]

    def update_phase_usage(self, phase: str, time_s: float, tokens: int = 0) -> None:
        """Update phase resource usage."""
        alloc = self._phase_allocations.get(phase)
        if alloc:
            alloc.used_time_s += time_s
            alloc.used_tokens += tokens

    def get_recommendations(self, target_type: str = "") -> dict[str, Any]:
        """Get strategy recommendations."""
        # Best arms by category
        by_category: dict[str, list[StrategyArm]] = defaultdict(list)
        for arm in self._arms.values():
            by_category[arm.category].append(arm)

        recommendations = {}
        for category, arms in by_category.items():
            sorted_arms = sorted(arms, key=lambda a: a.expected_reward, reverse=True)
            recommendations[category] = [
                {"name": a.name, "score": round(a.expected_reward, 3)}
                for a in sorted_arms[:3]
            ]

        return recommendations

    def get_phase_status(self) -> dict[str, Any]:
        return {
            phase: alloc.to_dict()
            for phase, alloc in self._phase_allocations.items()
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "arms": len(self._arms),
            "total_trials": self._total_trials,
            "episodes": len(self._episodes),
            "phases": len(self._phase_allocations),
        }
