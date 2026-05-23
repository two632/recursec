"""Episodic memory — records and retrieves assessment episodes.

Implements:
1. Episode recording (full assessment sequence)
2. Step-by-step action history
3. Episode search and retrieval
4. Pattern extraction from episodes
5. Success/failure classification
6. Temporal indexing
7. Episode summarization for context injection
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StepType(str, Enum):
    OBSERVE = "observe"
    REASON = "reason"
    DECIDE = "decide"
    EXECUTE = "execute"
    VALIDATE = "validate"
    REPORT = "report"


class EpisodeOutcome(str, Enum):
    SUCCESS = "success"          # Found real vulnerabilities
    PARTIAL = "partial"          # Found some findings
    FAILURE = "failure"          # No actionable findings
    ABORTED = "aborted"          # Budget/time exhausted
    ERROR = "error"              # System error


@dataclass
class EpisodeStep:
    """A single step in an episode."""
    step_number: int = 0
    step_type: StepType = StepType.EXECUTE
    action: str = ""
    tool: str = ""
    model: str = ""
    input_summary: str = ""
    output_summary: str = ""
    findings_count: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    success: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "type": self.step_type.value,
            "action": self.action[:20],
            "findings": self.findings_count,
            "success": self.success,
        }


@dataclass
class Episode:
    """A complete assessment episode."""
    episode_id: str = ""
    target: str = ""
    target_type: str = ""
    steps: list[EpisodeStep] = field(default_factory=list)
    outcome: EpisodeOutcome = EpisodeOutcome.PARTIAL
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    strategies_used: list[str] = field(default_factory=list)
    total_tokens: int = 0
    total_duration_s: float = 0.0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    tags: list[str] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id[:10],
            "target": self.target[:20],
            "outcome": self.outcome.value,
            "steps": len(self.steps),
            "findings": self.total_findings,
            "tokens": self.total_tokens,
        }


class EpisodicMemory:
    """Records and retrieves assessment episodes.

    Stores complete assessment episodes with
    step-by-step history for pattern extraction
    and learning.
    """

    def __init__(self, max_episodes: int = 1000) -> None:
        self._episodes: dict[str, Episode] = {}
        self._counter = 0
        self._max_episodes = max_episodes
        self._log = logger.bind(component="episodic_memory")

    def start_episode(
        self,
        target: str,
        target_type: str = "",
        tags: list[str] | None = None,
    ) -> Episode:
        """Start recording a new episode."""
        self._counter += 1
        episode = Episode(
            episode_id=f"ep-{self._counter}",
            target=target,
            target_type=target_type,
            tags=tags or [],
        )
        self._episodes[episode.episode_id] = episode

        # Trim old episodes
        if len(self._episodes) > self._max_episodes:
            oldest = sorted(
                self._episodes.values(),
                key=lambda e: e.started_at,
            )
            for old in oldest[:len(self._episodes) - self._max_episodes]:
                del self._episodes[old.episode_id]

        return episode

    def add_step(
        self,
        episode_id: str,
        step_type: StepType,
        action: str,
        tool: str = "",
        model: str = "",
        input_summary: str = "",
        output_summary: str = "",
        findings_count: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
        success: bool = True,
    ) -> EpisodeStep | None:
        """Add a step to an episode."""
        episode = self._episodes.get(episode_id)
        if not episode:
            return None

        step = EpisodeStep(
            step_number=len(episode.steps) + 1,
            step_type=step_type,
            action=action,
            tool=tool,
            model=model,
            input_summary=input_summary,
            output_summary=output_summary,
            findings_count=findings_count,
            tokens_used=tokens_used,
            duration_s=duration_s,
            success=success,
        )
        episode.steps.append(step)

        # Update episode stats
        episode.total_tokens += tokens_used
        episode.total_findings += findings_count

        if tool and tool not in episode.tools_used:
            episode.tools_used.append(tool)
        if model and model not in episode.models_used:
            episode.models_used.append(model)

        return step

    def complete_episode(
        self,
        episode_id: str,
        outcome: EpisodeOutcome = EpisodeOutcome.PARTIAL,
        lessons: list[str] | None = None,
    ) -> Episode | None:
        """Complete an episode."""
        episode = self._episodes.get(episode_id)
        if not episode:
            return None

        episode.outcome = outcome
        episode.completed_at = time.time()
        episode.total_duration_s = episode.completed_at - episode.started_at
        episode.lessons = lessons or []

        return episode

    def search_episodes(
        self,
        target_type: str = "",
        outcome: EpisodeOutcome | None = None,
        min_findings: int = 0,
        tags: list[str] | None = None,
        limit: int = 10,
    ) -> list[Episode]:
        """Search episodes by criteria."""
        matches = []
        for episode in self._episodes.values():
            if target_type and episode.target_type != target_type:
                continue
            if outcome and episode.outcome != outcome:
                continue
            if episode.total_findings < min_findings:
                continue
            if tags:
                if not any(t in episode.tags for t in tags):
                    continue
            matches.append(episode)

        matches.sort(key=lambda e: e.total_findings, reverse=True)
        return matches[:limit]

    def get_successful_patterns(
        self,
        target_type: str = "",
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Extract successful patterns from episodes."""
        successful = self.search_episodes(
            target_type=target_type,
            outcome=EpisodeOutcome.SUCCESS,
            limit=20,
        )

        tool_freq: dict[str, int] = defaultdict(int)
        strategy_freq: dict[str, int] = defaultdict(int)

        for episode in successful:
            for tool in episode.tools_used:
                tool_freq[tool] += 1
            for strat in episode.strategies_used:
                strategy_freq[strat] += 1

        patterns: list[dict[str, Any]] = []

        top_tools = sorted(tool_freq.items(), key=lambda x: x[1], reverse=True)[:limit]
        for tool, count in top_tools:
            patterns.append({
                "type": "tool",
                "name": tool,
                "frequency": count,
            })

        top_strats = sorted(strategy_freq.items(), key=lambda x: x[1], reverse=True)[:limit]
        for strat, count in top_strats:
            patterns.append({
                "type": "strategy",
                "name": strat,
                "frequency": count,
            })

        return patterns

    def build_episodic_prompt(
        self,
        target_type: str = "",
        max_episodes: int = 3,
    ) -> str:
        """Build prompt from past episodes."""
        lines = ["## Past Assessment Episodes\n"]

        recent = self.search_episodes(
            target_type=target_type,
            min_findings=1,
            limit=max_episodes,
        )

        if not recent:
            lines.append("No relevant past episodes.")
            return "\n".join(lines)

        for episode in recent:
            lines.append(
                f"### {episode.target} ({episode.outcome.value}): "
                f"{episode.total_findings} findings"
            )
            lines.append(f"  Tools: {', '.join(episode.tools_used[:5])}")
            if episode.lessons:
                lines.append(f"  Lessons: {'; '.join(episode.lessons[:3])}")

        patterns = self.get_successful_patterns(target_type=target_type)
        if patterns:
            lines.append("\n### Successful Patterns")
            for pattern in patterns[:5]:
                lines.append(f"  - {pattern['type']}: {pattern['name']} ({pattern['frequency']}x)")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = defaultdict(int)
        for ep in self._episodes.values():
            outcome_counts[ep.outcome.value] += 1

        return {
            "total_episodes": len(self._episodes),
            "total_findings": sum(ep.total_findings for ep in self._episodes.values()),
            "total_tokens": sum(ep.total_tokens for ep in self._episodes.values()),
            "by_outcome": dict(outcome_counts),
        }
