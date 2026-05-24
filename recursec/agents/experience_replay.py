"""Experience replay — stores and replays past reasoning chains.

Implements:
1. Successful reasoning chain storage
2. Similarity-based retrieval (find relevant past experience)
3. Chain quality scoring and ranking
4. Experience categorization by task type
5. Replay injection into prompts
6. Experience decay (older experiences fade)
7. Experience prompt for LLM
"""

from __future__ import annotations

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
    TIMEOUT = "timeout"


@dataclass
class ReasoningChain:
    """A stored reasoning chain from past assessment."""
    chain_id: str = ""
    task_type: str = ""
    target_type: str = ""
    description: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    outcome: ExperienceOutcome = ExperienceOutcome.SUCCESS
    findings_produced: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    quality_score: float = 0.5
    replay_count: int = 0
    created_at: float = field(default_factory=time.time)
    keywords: list[str] = field(default_factory=list)

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    @property
    def decayed_score(self) -> float:
        decay = 0.99 ** self.age_hours
        return self.quality_score * decay

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "task": self.task_type[:12],
            "outcome": self.outcome.value[:6],
            "steps": len(self.steps),
            "quality": round(self.quality_score, 2),
        }


class ExperienceReplay:
    """Stores and retrieves past successful reasoning chains.

    When the agent faces a similar task, relevant past
    experiences are injected into the prompt to guide
    the reasoning process.
    """

    def __init__(self, max_experiences: int = 200) -> None:
        self._experiences: dict[str, ReasoningChain] = {}
        self._max_experiences = max_experiences
        self._counter = 0
        self._log = logger.bind(component="experience_replay")

    def store(
        self,
        task_type: str,
        target_type: str,
        description: str,
        steps: list[dict[str, Any]],
        outcome: ExperienceOutcome = ExperienceOutcome.SUCCESS,
        findings_produced: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
        keywords: list[str] | None = None,
    ) -> ReasoningChain:
        """Store a reasoning chain from a completed task."""
        self._counter += 1

        # Calculate quality
        quality = self._calculate_quality(
            outcome, findings_produced, tokens_used, duration_s, len(steps),
        )

        chain = ReasoningChain(
            chain_id=f"exp-{self._counter}",
            task_type=task_type,
            target_type=target_type,
            description=description,
            steps=steps,
            outcome=outcome,
            findings_produced=findings_produced,
            tokens_used=tokens_used,
            duration_s=duration_s,
            quality_score=quality,
            keywords=keywords or [],
        )

        self._experiences[chain.chain_id] = chain

        # Evict low-quality old experiences
        while len(self._experiences) > self._max_experiences:
            self._evict_worst()

        return chain

    def _calculate_quality(
        self,
        outcome: ExperienceOutcome,
        findings: int,
        tokens: int,
        duration: float,
        steps: int,
    ) -> float:
        """Calculate quality score for an experience."""
        # Outcome score
        outcome_score = {
            ExperienceOutcome.SUCCESS: 1.0,
            ExperienceOutcome.PARTIAL: 0.6,
            ExperienceOutcome.FAILURE: 0.1,
            ExperienceOutcome.TIMEOUT: 0.3,
        }[outcome]

        # Efficiency (findings per token)
        efficiency = findings / max(1, tokens) * 10000
        efficiency_score = min(1.0, efficiency)

        # Conciseness (fewer steps for same outcome)
        conciseness = 1.0 / (1.0 + steps / 10.0)

        quality = outcome_score * 0.5 + efficiency_score * 0.3 + conciseness * 0.2
        return min(1.0, quality)

    def _evict_worst(self) -> None:
        """Evict the worst experience."""
        if not self._experiences:
            return
        worst_id = min(
            self._experiences,
            key=lambda k: self._experiences[k].decayed_score,
        )
        del self._experiences[worst_id]

    def retrieve(
        self,
        task_type: str = "",
        target_type: str = "",
        keywords: list[str] | None = None,
        max_results: int = 3,
        min_quality: float = 0.3,
    ) -> list[ReasoningChain]:
        """Retrieve relevant past experiences."""
        candidates: list[tuple[float, ReasoningChain]] = []

        for chain in self._experiences.values():
            if chain.decayed_score < min_quality:
                continue

            relevance = 0.0

            # Task type match
            if task_type and chain.task_type == task_type:
                relevance += 0.4

            # Target type match
            if target_type and chain.target_type == target_type:
                relevance += 0.3

            # Keyword overlap
            if keywords and chain.keywords:
                chain_kw_set = set(chain.keywords)
                query_kw_set = set(keywords)
                overlap = len(chain_kw_set & query_kw_set)
                if overlap > 0:
                    relevance += 0.3 * (overlap / len(query_kw_set))

            # Quality bonus
            relevance += chain.decayed_score * 0.2

            if relevance > 0:
                candidates.append((relevance, chain))

        # Sort by relevance descending
        candidates.sort(key=lambda x: x[0], reverse=True)

        results = [chain for _, chain in candidates[:max_results]]

        # Increment replay count
        for chain in results:
            chain.replay_count += 1

        return results

    def build_experience_prompt(
        self,
        task_type: str = "",
        target_type: str = "",
        keywords: list[str] | None = None,
    ) -> str:
        """Build experience replay prompt for LLM."""
        lines = ["## Past Experience\n"]

        relevant = self.retrieve(
            task_type=task_type,
            target_type=target_type,
            keywords=keywords,
            max_results=2,
        )

        if not relevant:
            lines.append("No relevant past experience found.")
            return "\n".join(lines)

        for chain in relevant:
            lines.append(
                f"### {chain.task_type} on {chain.target_type} "
                f"({chain.outcome.value}, quality={chain.quality_score:.0%})"
            )
            lines.append(f"What worked: {chain.description[:80]}")

            # Show steps summary
            if chain.steps:
                lines.append("Steps taken:")
                for step in chain.steps[:5]:
                    action = step.get("action", "unknown")
                    result = step.get("result", "")
                    lines.append(f"  - {action[:30]}: {result[:40]}")

            if chain.findings_produced:
                lines.append(f"Findings: {chain.findings_produced}")

            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        by_outcome: dict[str, int] = {}
        by_task: dict[str, int] = {}
        for chain in self._experiences.values():
            o = chain.outcome.value
            by_outcome[o] = by_outcome.get(o, 0) + 1
            t = chain.task_type
            by_task[t] = by_task.get(t, 0) + 1

        return {
            "total_experiences": len(self._experiences),
            "by_outcome": by_outcome,
            "by_task_type": by_task,
            "total_replays": sum(c.replay_count for c in self._experiences.values()),
        }
