"""Adaptive strategy selector — picks the best strategy for each situation.

Implements:
1. Multi-armed bandit for strategy selection (UCB1)
2. Context-aware strategy routing
3. Thompson sampling for exploration vs exploitation
4. Strategy performance tracking
5. Target-type-specific strategy preferences
6. Model selection per strategy
7. Dynamic strategy adjustment during assessment
8. Budget-aware strategy selection
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
    """A strategy in the multi-armed bandit."""
    arm_id: str = ""
    strategy_name: str = ""
    category: str = ""
    pulls: int = 0                 # Number of times selected
    total_reward: float = 0.0      # Cumulative reward
    successes: int = 0             # For Thompson sampling (beta distribution)
    failures: int = 0
    avg_tokens: float = 0.0
    avg_duration_s: float = 0.0
    applicable_targets: list[str] = field(default_factory=list)
    preferred_models: list[str] = field(default_factory=list)

    @property
    def mean_reward(self) -> float:
        if self.pulls == 0:
            return 0.0
        return self.total_reward / self.pulls

    @property
    def ucb1_score(self) -> float:
        """Upper Confidence Bound 1 score."""
        if self.pulls == 0:
            return float("inf")
        exploration = math.sqrt(2 * math.log(max(1, self._total_pulls)) / self.pulls)
        return self.mean_reward + exploration

    # Set externally by the selector
    _total_pulls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.arm_id,
            "strategy": self.strategy_name[:25],
            "pulls": self.pulls,
            "mean_reward": round(self.mean_reward, 3),
            "ucb1": round(self.ucb1_score, 3) if self.pulls > 0 else "inf",
        }


@dataclass
class SelectionContext:
    """Context for strategy selection."""
    target_type: str = ""
    phase: str = ""
    findings_so_far: int = 0
    tokens_remaining: int = 0
    time_remaining_s: float = 0.0
    failed_strategies: list[str] = field(default_factory=list)
    target_technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_type[:15],
            "phase": self.phase[:10],
            "findings": self.findings_so_far,
            "tokens_left": self.tokens_remaining,
            "failed": len(self.failed_strategies),
        }


@dataclass
class StrategyRecommendation:
    """A recommended strategy with rationale."""
    strategy_name: str = ""
    score: float = 0.0
    rationale: str = ""
    recommended_model: str = ""
    estimated_tokens: int = 0
    estimated_time_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name[:25],
            "score": round(self.score, 3),
            "model": self.recommended_model[:15],
            "est_tokens": self.estimated_tokens,
        }


# ── Default Strategy Arms ─────────────────────────────────────

DEFAULT_ARMS: list[dict[str, Any]] = [
    # Recon strategies
    {"name": "deep_infrastructure_fingerprint", "category": "recon",
     "targets": ["web_application", "api_service", "cloud_infrastructure"],
     "models": ["whiterabbitneo-7b", "mistral-7b"]},
    {"name": "hidden_attack_surface_discovery", "category": "recon",
     "targets": ["web_application", "api_service"],
     "models": ["whiterabbitneo-7b", "qwen2.5-coder-7b"]},
    {"name": "deep_technology_profiling", "category": "recon",
     "targets": ["web_application", "api_service", "e_commerce"],
     "models": ["qwen2.5-coder-14b", "mistral-7b"]},
    # Discovery strategies
    {"name": "emergent_complexity_analysis", "category": "discovery",
     "targets": ["microservice_architecture", "cloud_infrastructure"],
     "models": ["deepseek-r1-7b", "hermes-4-14b"]},
    {"name": "timing_race_condition_testing", "category": "discovery",
     "targets": ["web_application", "api_service", "e_commerce"],
     "models": ["whiterabbitneo-7b", "qwen2.5-coder-14b"]},
    {"name": "business_logic_analysis", "category": "discovery",
     "targets": ["web_application", "e_commerce", "saas_app"],
     "models": ["deepseek-r1-7b", "hermes-4-14b"]},
    {"name": "ai_llm_vuln_testing", "category": "discovery",
     "targets": ["ai_powered_application"],
     "models": ["whiterabbitneo-7b", "dolphin-2.9"]},
    {"name": "supply_chain_analysis", "category": "discovery",
     "targets": ["web_application", "api_service", "open_source"],
     "models": ["qwen2.5-coder-14b", "yi-9b-200k"]},
    {"name": "api_gateway_bypass_testing", "category": "discovery",
     "targets": ["api_service", "microservice_architecture"],
     "models": ["whiterabbitneo-7b", "mistral-7b"]},
    {"name": "cloud_misconfig_scanning", "category": "discovery",
     "targets": ["cloud_infrastructure", "aws", "gcp", "azure"],
     "models": ["whiterabbitneo-7b", "qwen2.5-coder-7b"]},
    {"name": "crypto_weakness_analysis", "category": "discovery",
     "targets": ["web_application", "api_service"],
     "models": ["deepseek-math-7b", "qwen2.5-coder-14b"]},
    {"name": "classic_vuln_scanning", "category": "discovery",
     "targets": ["web_application", "api_service", "e_commerce"],
     "models": ["whiterabbitneo-7b", "mistral-7b"]},
    # Exploitation strategies
    {"name": "attack_chain_construction", "category": "exploitation",
     "targets": ["web_application", "api_service", "cloud_infrastructure"],
     "models": ["whiterabbitneo-7b", "deepseek-r1-7b"]},
    {"name": "safe_exploitation_validation", "category": "exploitation",
     "targets": ["web_application", "api_service"],
     "models": ["whiterabbitneo-7b", "qwen2.5-coder-14b"]},
    # Post-exploit
    {"name": "lateral_movement_assessment", "category": "post_exploit",
     "targets": ["cloud_infrastructure", "network_infrastructure"],
     "models": ["whiterabbitneo-7b", "hermes-4-14b"]},
]


class AdaptiveStrategySelector:
    """Picks the best strategy using multi-armed bandit algorithms.

    Balances exploration (trying new strategies) with exploitation
    (using strategies known to work) using UCB1 and Thompson sampling.
    """

    def __init__(self, exploration_factor: float = 1.5) -> None:
        self._arms: dict[str, StrategyArm] = {}
        self._exploration_factor = exploration_factor
        self._arm_counter = 0
        self._selection_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="adaptive_strategy_selector")

        self._initialize_arms()

    def _initialize_arms(self) -> None:
        """Initialize default strategy arms."""
        for data in DEFAULT_ARMS:
            self._arm_counter += 1
            arm = StrategyArm(
                arm_id=f"arm-{self._arm_counter}",
                strategy_name=data["name"],
                category=data.get("category", ""),
                applicable_targets=data.get("targets", []),
                preferred_models=data.get("models", []),
                successes=1,    # Prior: assume 1 success (optimistic init)
                failures=1,     # Prior: assume 1 failure
            )
            self._arms[arm.arm_id] = arm

    def select_strategy(
        self,
        context: SelectionContext,
        method: str = "ucb1",
        top_k: int = 3,
    ) -> list[StrategyRecommendation]:
        """Select the best strategies for the current context."""
        # Filter applicable arms
        applicable = self._filter_applicable(context)

        if not applicable:
            return []

        # Set total pulls for UCB1 calculation
        total_pulls = sum(arm.pulls for arm in applicable)
        for arm in applicable:
            arm._total_pulls = max(1, total_pulls)

        # Score arms
        if method == "ucb1":
            scored = [(arm, arm.ucb1_score) for arm in applicable]
        elif method == "thompson":
            scored = [(arm, self._thompson_sample(arm)) for arm in applicable]
        else:
            scored = [(arm, arm.mean_reward) for arm in applicable]

        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)

        # Build recommendations
        recommendations = []
        for arm, score in scored[:top_k]:
            model = arm.preferred_models[0] if arm.preferred_models else "mistral-7b"

            recommendations.append(StrategyRecommendation(
                strategy_name=arm.strategy_name,
                score=score,
                rationale=self._explain_selection(arm, context),
                recommended_model=model,
                estimated_tokens=int(arm.avg_tokens) if arm.avg_tokens > 0 else 2000,
                estimated_time_s=arm.avg_duration_s if arm.avg_duration_s > 0 else 60.0,
            ))

        # Record selection
        if recommendations:
            self._selection_history.append({
                "time": time.time(),
                "context": context.to_dict(),
                "selected": recommendations[0].strategy_name,
                "score": recommendations[0].score,
            })

        return recommendations

    def update_reward(
        self,
        strategy_name: str,
        reward: float,
        success: bool = True,
        tokens_spent: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        """Update strategy arm after an attempt."""
        arm = self._find_arm(strategy_name)
        if not arm:
            return

        arm.pulls += 1
        arm.total_reward += reward

        if success:
            arm.successes += 1
        else:
            arm.failures += 1

        # Running average for tokens and duration
        if tokens_spent > 0:
            if arm.avg_tokens == 0:
                arm.avg_tokens = float(tokens_spent)
            else:
                arm.avg_tokens = 0.9 * arm.avg_tokens + 0.1 * tokens_spent

        if duration_s > 0:
            if arm.avg_duration_s == 0:
                arm.avg_duration_s = duration_s
            else:
                arm.avg_duration_s = 0.9 * arm.avg_duration_s + 0.1 * duration_s

    def _filter_applicable(self, context: SelectionContext) -> list[StrategyArm]:
        """Filter arms applicable to the current context."""
        applicable = []

        for arm in self._arms.values():
            # Filter by target type
            if context.target_type and arm.applicable_targets:
                if context.target_type not in arm.applicable_targets:
                    continue

            # Filter by phase
            if context.phase and arm.category != context.phase:
                continue

            # Skip recently failed strategies
            if arm.strategy_name in context.failed_strategies:
                continue

            # Budget check
            if context.tokens_remaining > 0:
                if arm.avg_tokens > 0 and arm.avg_tokens > context.tokens_remaining:
                    continue

            applicable.append(arm)

        return applicable

    @staticmethod
    def _thompson_sample(arm: StrategyArm) -> float:
        """Thompson sampling: sample from beta distribution."""
        return random.betavariate(
            max(1, arm.successes),
            max(1, arm.failures),
        )

    @staticmethod
    def _explain_selection(arm: StrategyArm, context: SelectionContext) -> str:
        """Explain why a strategy was selected."""
        parts = []

        if arm.pulls == 0:
            parts.append("unexplored strategy (exploration)")
        elif arm.mean_reward > 0.7:
            parts.append(f"high success rate ({arm.mean_reward:.0%})")
        elif arm.mean_reward > 0.4:
            parts.append(f"moderate success rate ({arm.mean_reward:.0%})")

        if context.target_type in arm.applicable_targets:
            parts.append(f"suited for {context.target_type}")

        return "; ".join(parts) if parts else "default selection"

    def _find_arm(self, strategy_name: str) -> StrategyArm | None:
        """Find an arm by strategy name."""
        for arm in self._arms.values():
            if arm.strategy_name == strategy_name:
                return arm
        return None

    def get_stats(self) -> dict[str, Any]:
        category_counts: dict[str, int] = defaultdict(int)
        for arm in self._arms.values():
            category_counts[arm.category] += 1
        return {
            "total_arms": len(self._arms),
            "total_selections": len(self._selection_history),
            "by_category": dict(category_counts),
            "top_strategies": [
                arm.to_dict()
                for arm in sorted(
                    self._arms.values(),
                    key=lambda a: a.mean_reward,
                    reverse=True,
                )[:5]
            ],
        }
