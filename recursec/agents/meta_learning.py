"""Meta-learning — learns how to learn new security tasks faster.

Implements:
1. Task similarity detection
2. Strategy transfer from similar past tasks
3. Few-shot learning from minimal examples
4. Learning curve prediction
5. Optimal strategy selection for new task types
6. Task embedding for similarity matching
7. Experience distillation into rules
8. Adaptive exploration-exploitation for new tasks
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TaskProfile:
    """Profile of a task type for meta-learning."""
    profile_id: str = ""
    task_type: str = ""
    features: dict[str, float] = field(default_factory=dict)
    best_strategy: str = ""
    best_model: str = ""
    best_tools: list[str] = field(default_factory=list)
    avg_tokens: int = 0
    avg_findings: float = 0.0
    success_rate: float = 0.0
    attempts: int = 0
    examples: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.profile_id,
            "type": self.task_type[:20],
            "strategy": self.best_strategy[:20],
            "model": self.best_model[:15],
            "success": round(self.success_rate, 2),
            "attempts": self.attempts,
        }


@dataclass
class StrategyRecord:
    """Record of a strategy's performance on a task."""
    strategy: str = ""
    model: str = ""
    tools: list[str] = field(default_factory=list)
    task_features: dict[str, float] = field(default_factory=dict)
    success: bool = False
    findings: int = 0
    tokens_used: int = 0
    quality: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy[:20],
            "model": self.model[:15],
            "success": self.success,
            "quality": round(self.quality, 2),
        }


@dataclass
class TransferRecommendation:
    """A recommendation for transferring learning from a similar task."""
    source_task: str = ""
    similarity: float = 0.0
    recommended_strategy: str = ""
    recommended_model: str = ""
    recommended_tools: list[str] = field(default_factory=list)
    expected_success_rate: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_task[:20],
            "similarity": round(self.similarity, 3),
            "strategy": self.recommended_strategy[:20],
            "expected_sr": round(self.expected_success_rate, 2),
            "confidence": round(self.confidence, 2),
        }


@dataclass
class DistilledRule:
    """A rule distilled from experience."""
    rule_id: str = ""
    condition: str = ""           # When this is true...
    action: str = ""              # Do this
    confidence: float = 0.5
    source_count: int = 0         # How many experiences support this
    exceptions: int = 0

    @property
    def reliability(self) -> float:
        total = self.source_count + self.exceptions
        if total == 0:
            return 0.0
        return self.source_count / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "if": self.condition[:30],
            "then": self.action[:30],
            "reliability": round(self.reliability, 2),
            "sources": self.source_count,
        }


# ── Feature Extractors ────────────────────────────────────────

TASK_FEATURE_KEYS: list[str] = [
    "has_web",           # Web application present
    "has_api",           # API endpoints present
    "has_ssh",           # SSH service
    "has_database",      # Database service
    "has_custom_app",    # Custom application
    "port_count",        # Number of open ports
    "endpoint_count",    # Number of endpoints
    "param_count",       # Number of parameters
    "tech_diversity",    # Number of different technologies
    "scope_size",        # Number of targets
    "is_internal",       # Internal vs external
    "has_waf",           # WAF detected
    "has_auth",          # Authentication required
]


class MetaLearning:
    """Learns how to learn new security tasks faster.

    Uses task similarity to transfer strategies from
    past experience, distills rules, and predicts
    optimal approaches for new tasks.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TaskProfile] = {}
        self._records: list[StrategyRecord] = []
        self._rules: dict[str, DistilledRule] = {}
        self._profile_counter = 0
        self._rule_counter = 0
        self._log = logger.bind(component="meta_learning")

    def register_task(
        self,
        task_type: str,
        features: dict[str, float] | None = None,
    ) -> TaskProfile:
        """Register a new task type."""
        existing = self._find_profile(task_type)
        if existing:
            return existing

        self._profile_counter += 1
        profile = TaskProfile(
            profile_id=f"tp-{self._profile_counter}",
            task_type=task_type,
            features=features or {},
        )
        self._profiles[task_type] = profile
        return profile

    def record_outcome(
        self,
        task_type: str,
        strategy: str,
        model: str = "",
        tools: list[str] | None = None,
        features: dict[str, float] | None = None,
        success: bool = False,
        findings: int = 0,
        tokens_used: int = 0,
        quality: float = 0.0,
    ) -> StrategyRecord:
        """Record the outcome of a strategy on a task."""
        record = StrategyRecord(
            strategy=strategy,
            model=model,
            tools=tools or [],
            task_features=features or {},
            success=success,
            findings=findings,
            tokens_used=tokens_used,
            quality=quality,
        )

        self._records.append(record)
        if len(self._records) > 1000:
            self._records = self._records[-1000:]

        # Update profile
        profile = self._profiles.get(task_type)
        if profile:
            profile.attempts += 1
            n = profile.attempts
            profile.success_rate = ((n - 1) * profile.success_rate + (1.0 if success else 0.0)) / n
            profile.avg_findings = ((n - 1) * profile.avg_findings + findings) / n
            profile.avg_tokens = int(((n - 1) * profile.avg_tokens + tokens_used) / n)

            if quality > 0.7 and success:
                profile.best_strategy = strategy
                profile.best_model = model
                profile.best_tools = tools or []

            # Keep examples for few-shot
            if len(profile.examples) < 10:
                profile.examples.append(record.to_dict())

        return record

    def recommend(
        self,
        task_features: dict[str, float],
    ) -> list[TransferRecommendation]:
        """Recommend strategies based on similar past tasks."""
        recommendations = []

        for profile in self._profiles.values():
            if profile.attempts < 2:
                continue

            similarity = self._compute_similarity(task_features, profile.features)
            if similarity < 0.3:
                continue

            # Confidence = similarity × sqrt(attempts)
            confidence = similarity * min(1.0, math.sqrt(profile.attempts) / 5.0)

            recommendations.append(TransferRecommendation(
                source_task=profile.task_type,
                similarity=similarity,
                recommended_strategy=profile.best_strategy,
                recommended_model=profile.best_model,
                recommended_tools=profile.best_tools,
                expected_success_rate=profile.success_rate,
                confidence=confidence,
            ))

        recommendations.sort(key=lambda r: r.confidence, reverse=True)
        return recommendations[:5]

    @staticmethod
    def _compute_similarity(
        features_a: dict[str, float],
        features_b: dict[str, float],
    ) -> float:
        """Compute cosine similarity between task feature vectors."""
        all_keys = set(features_a) | set(features_b)
        if not all_keys:
            return 0.0

        dot_product = 0.0
        norm_a = 0.0
        norm_b = 0.0

        for key in all_keys:
            va = features_a.get(key, 0.0)
            vb = features_b.get(key, 0.0)
            dot_product += va * vb
            norm_a += va * va
            norm_b += vb * vb

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (math.sqrt(norm_a) * math.sqrt(norm_b))

    def distill_rules(self) -> list[DistilledRule]:
        """Distill rules from accumulated experience."""
        new_rules = []

        # Group records by strategy
        strategy_outcomes: dict[str, list[StrategyRecord]] = defaultdict(list)
        for record in self._records:
            strategy_outcomes[record.strategy].append(record)

        for strategy, records in strategy_outcomes.items():
            if len(records) < 3:
                continue

            successes = [r for r in records if r.success]
            success_rate = len(successes) / len(records)

            if success_rate > 0.7:
                # Identify common features in successful cases
                common_features = self._find_common_features(successes)

                if common_features:
                    self._rule_counter += 1
                    condition_parts = []
                    for feat, val in common_features.items():
                        if val > 0.5:
                            condition_parts.append(f"{feat}=high")
                        elif val > 0:
                            condition_parts.append(f"{feat}=present")

                    rule = DistilledRule(
                        rule_id=f"rule-{self._rule_counter}",
                        condition=" AND ".join(condition_parts[:3]),
                        action=f"Use strategy '{strategy}'",
                        confidence=success_rate,
                        source_count=len(successes),
                        exceptions=len(records) - len(successes),
                    )
                    self._rules[rule.rule_id] = rule
                    new_rules.append(rule)

        return new_rules

    @staticmethod
    def _find_common_features(
        records: list[StrategyRecord],
    ) -> dict[str, float]:
        """Find features common to successful records."""
        if not records:
            return {}

        feature_sums: dict[str, float] = defaultdict(float)
        feature_counts: dict[str, int] = defaultdict(int)

        for record in records:
            for feat, val in record.task_features.items():
                feature_sums[feat] += val
                feature_counts[feat] += 1

        # Only keep features present in > 60% of records
        threshold = len(records) * 0.6
        common = {}
        for feat, count in feature_counts.items():
            if count >= threshold:
                common[feat] = feature_sums[feat] / count

        return common

    def get_exploration_rate(self, task_type: str) -> float:
        """Get exploration rate for a task type (higher = more exploration)."""
        profile = self._profiles.get(task_type)
        if not profile:
            return 0.9  # Unknown task → explore heavily

        # Decay exploration with attempts
        return max(0.1, 0.9 * math.exp(-profile.attempts / 10.0))

    def _find_profile(self, task_type: str) -> TaskProfile | None:
        return self._profiles.get(task_type)

    def get_stats(self) -> dict[str, Any]:
        return {
            "profiles": len(self._profiles),
            "records": len(self._records),
            "rules": len(self._rules),
        }
