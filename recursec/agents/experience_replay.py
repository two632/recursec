"""Experience replay — learning from past assessments.

Implements:
1. Experience storage (successful/failed actions)
2. Similarity-based experience retrieval
3. Strategy success rate tracking
4. Temporal decay for relevance
5. Experience compression
6. Pattern generalization from experiences
7. Context-aware experience suggestion
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExperienceOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    FALSE_POSITIVE = "false_positive"


class ExperienceCategory(str, Enum):
    TOOL_USE = "tool_use"
    STRATEGY = "strategy"
    FINDING = "finding"
    EXPLOITATION = "exploitation"
    REASONING = "reasoning"
    BYPASS = "bypass"


@dataclass
class Experience:
    """A recorded experience from past operations."""
    experience_id: str = ""
    category: ExperienceCategory = ExperienceCategory.TOOL_USE
    outcome: ExperienceOutcome = ExperienceOutcome.SUCCESS
    context_hash: str = ""       # Hash of context for similarity
    target_type: str = ""        # web, network, cloud, mobile, etc.
    service_type: str = ""       # apache, nginx, mysql, etc.
    action: str = ""             # What was done
    result_summary: str = ""     # What happened
    lesson: str = ""             # What was learned
    tool_used: str = ""
    tokens_spent: int = 0
    time_spent_s: float = 0.0
    created_at: float = field(default_factory=time.time)
    access_count: int = 0
    last_accessed: float = 0.0
    tags: list[str] = field(default_factory=list)

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    @property
    def relevance_score(self) -> float:
        base = {
            ExperienceOutcome.SUCCESS: 1.0,
            ExperienceOutcome.PARTIAL: 0.6,
            ExperienceOutcome.FAILURE: 0.3,
            ExperienceOutcome.FALSE_POSITIVE: 0.2,
        }.get(self.outcome, 0.5)
        # Temporal decay: half-life of 168 hours (1 week)
        decay = 0.5 ** (self.age_hours / 168)
        # Boost frequently accessed
        access_boost = min(0.2, self.access_count * 0.02)
        return base * decay + access_boost

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id[:10],
            "category": self.category.value,
            "outcome": self.outcome.value,
            "action": self.action[:30],
            "relevance": round(self.relevance_score, 2),
        }


@dataclass
class StrategyStats:
    """Statistics for a strategy's success rate."""
    strategy_name: str = ""
    total_uses: int = 0
    successes: int = 0
    partial_successes: int = 0
    failures: int = 0
    avg_tokens: float = 0.0
    avg_time_s: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return (self.successes + self.partial_successes * 0.5) / self.total_uses

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name[:20],
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
        }


@dataclass
class GeneralizedPattern:
    """A pattern generalized from multiple experiences."""
    pattern_id: str = ""
    description: str = ""
    conditions: list[str] = field(default_factory=list)
    recommended_action: str = ""
    success_rate: float = 0.0
    evidence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id[:10],
            "desc": self.description[:30],
            "success": round(self.success_rate, 2),
            "evidence": self.evidence_count,
        }


class ExperienceReplayBuffer:
    """Stores and retrieves experiences for learning.

    Records successful and failed actions,
    provides similarity-based retrieval, and
    generalizes patterns across experiences.
    """

    def __init__(self, max_experiences: int = 10000) -> None:
        self._experiences: dict[str, Experience] = {}
        self._strategies: dict[str, StrategyStats] = {}
        self._patterns: dict[str, GeneralizedPattern] = {}
        self._counter = 0
        self._max = max_experiences
        self._log = logger.bind(component="experience_replay")

    def record(
        self,
        category: ExperienceCategory,
        outcome: ExperienceOutcome,
        action: str,
        result_summary: str,
        target_type: str = "",
        service_type: str = "",
        tool_used: str = "",
        tokens_spent: int = 0,
        time_spent_s: float = 0.0,
        lesson: str = "",
        tags: list[str] | None = None,
    ) -> Experience:
        """Record a new experience."""
        self._counter += 1

        # Generate context hash for similarity matching
        context_str = f"{target_type}:{service_type}:{action}"
        context_hash = hashlib.sha256(context_str.encode()).hexdigest()[:16]

        exp = Experience(
            experience_id=f"exp-{self._counter}",
            category=category,
            outcome=outcome,
            context_hash=context_hash,
            target_type=target_type,
            service_type=service_type,
            action=action,
            result_summary=result_summary,
            lesson=lesson,
            tool_used=tool_used,
            tokens_spent=tokens_spent,
            time_spent_s=time_spent_s,
            tags=tags or [],
        )

        # Evict lowest relevance if at capacity
        if len(self._experiences) >= self._max:
            self._evict_lowest()

        self._experiences[exp.experience_id] = exp

        # Update strategy stats
        self._update_strategy_stats(action, outcome, tokens_spent, time_spent_s)

        return exp

    def retrieve_similar(
        self,
        target_type: str = "",
        service_type: str = "",
        action: str = "",
        category: ExperienceCategory | None = None,
        limit: int = 5,
    ) -> list[Experience]:
        """Retrieve similar experiences."""
        scored: list[tuple[float, Experience]] = []

        for exp in self._experiences.values():
            score = exp.relevance_score

            # Boost for matching context
            if target_type and exp.target_type == target_type:
                score *= 1.5
            if service_type and exp.service_type == service_type:
                score *= 1.5
            if category and exp.category == category:
                score *= 1.3

            # Simple keyword matching on action
            if action:
                action_words = set(action.lower().split())
                exp_words = set(exp.action.lower().split())
                overlap = len(action_words & exp_words)
                if overlap > 0:
                    score *= 1.0 + (overlap * 0.2)

            scored.append((score, exp))

        scored.sort(key=lambda x: x[0], reverse=True)

        results = [exp for _, exp in scored[:limit]]
        for exp in results:
            exp.access_count += 1
            exp.last_accessed = time.time()

        return results

    def get_strategy_stats(self, strategy_name: str = "") -> list[StrategyStats]:
        """Get strategy statistics."""
        if strategy_name:
            stats = self._strategies.get(strategy_name)
            return [stats] if stats else []
        return sorted(
            self._strategies.values(),
            key=lambda s: s.success_rate,
            reverse=True,
        )

    def generalize_patterns(self) -> list[GeneralizedPattern]:
        """Extract generalized patterns from experiences."""
        # Group by context hash
        groups: dict[str, list[Experience]] = {}
        for exp in self._experiences.values():
            groups.setdefault(exp.context_hash, []).append(exp)

        new_patterns: list[GeneralizedPattern] = []
        for context_hash, exps in groups.items():
            if len(exps) < 3:
                continue

            successes = [e for e in exps if e.outcome == ExperienceOutcome.SUCCESS]
            success_rate = len(successes) / len(exps)

            if successes:
                best = max(successes, key=lambda e: e.relevance_score)
                pattern = GeneralizedPattern(
                    pattern_id=f"gp-{context_hash[:8]}",
                    description=f"Pattern for {best.target_type}/{best.service_type}",
                    conditions=[
                        f"target_type={best.target_type}",
                        f"service_type={best.service_type}",
                    ],
                    recommended_action=best.action,
                    success_rate=success_rate,
                    evidence_count=len(exps),
                )
                self._patterns[pattern.pattern_id] = pattern
                new_patterns.append(pattern)

        return new_patterns

    def build_experience_prompt(
        self,
        target_type: str = "",
        service_type: str = "",
        max_experiences: int = 5,
    ) -> str:
        """Build experience context for LLM."""
        lines = ["## Past Experiences\n"]

        relevant = self.retrieve_similar(
            target_type=target_type,
            service_type=service_type,
            limit=max_experiences,
        )

        if not relevant:
            lines.append("No relevant past experiences.")
            return "\n".join(lines)

        for exp in relevant:
            outcome_icon = {
                "success": "+",
                "partial": "~",
                "failure": "-",
                "false_positive": "!",
            }.get(exp.outcome.value, "?")

            lines.append(
                f"  [{outcome_icon}] {exp.action[:50]}\n"
                f"      → {exp.result_summary[:50]}"
            )
            if exp.lesson:
                lines.append(f"      Lesson: {exp.lesson[:50]}")

        # Top strategies
        strategies = self.get_strategy_stats()
        if strategies:
            lines.append("\nStrategy success rates:")
            for s in strategies[:3]:
                lines.append(f"  {s.strategy_name}: {s.success_rate:.0%} ({s.total_uses} uses)")

        return "\n".join(lines)

    def _update_strategy_stats(
        self,
        action: str,
        outcome: ExperienceOutcome,
        tokens: int,
        time_s: float,
    ) -> None:
        """Update strategy statistics."""
        # Use first word of action as strategy name
        strategy_name = action.split()[0] if action else "unknown"

        stats = self._strategies.get(strategy_name)
        if not stats:
            stats = StrategyStats(strategy_name=strategy_name)
            self._strategies[strategy_name] = stats

        stats.total_uses += 1
        if outcome == ExperienceOutcome.SUCCESS:
            stats.successes += 1
        elif outcome == ExperienceOutcome.PARTIAL:
            stats.partial_successes += 1
        else:
            stats.failures += 1

        # Running average
        n = stats.total_uses
        stats.avg_tokens = ((n - 1) * stats.avg_tokens + tokens) / n
        stats.avg_time_s = ((n - 1) * stats.avg_time_s + time_s) / n

    def _evict_lowest(self) -> None:
        """Evict lowest-relevance experience."""
        if not self._experiences:
            return
        lowest = min(
            self._experiences.values(),
            key=lambda e: e.relevance_score,
        )
        del self._experiences[lowest.experience_id]

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for exp in self._experiences.values():
            outcome_counts[exp.outcome.value] = outcome_counts.get(exp.outcome.value, 0) + 1

        return {
            "total_experiences": len(self._experiences),
            "by_outcome": outcome_counts,
            "strategies": len(self._strategies),
            "patterns": len(self._patterns),
        }
