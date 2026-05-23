"""Experience replay — episodic memory for agent learning.

Implements:
1. Episode recording (full assessment sequences)
2. Experience retrieval by similarity
3. Success pattern extraction
4. Failure pattern analysis
5. Strategy replay for similar targets
6. Compressed episode storage
7. Priority-based experience sampling
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EpisodeOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


class StepType(str, Enum):
    OBSERVATION = "observation"
    DECISION = "decision"
    TOOL_USE = "tool_use"
    LLM_QUERY = "llm_query"
    FINDING = "finding"
    ERROR = "error"
    PIVOT = "pivot"


@dataclass
class EpisodeStep:
    """A single step in an episode."""
    step_num: int = 0
    step_type: StepType = StepType.OBSERVATION
    action: str = ""
    tool: str = ""
    model: str = ""
    input_summary: str = ""
    output_summary: str = ""
    tokens_used: int = 0
    duration_s: float = 0.0
    success: bool = True
    finding_severity: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_num,
            "type": self.step_type.value,
            "action": self.action[:25],
            "tool": self.tool[:10],
            "tokens": self.tokens_used,
            "ok": self.success,
        }


@dataclass
class Episode:
    """A complete assessment episode."""
    episode_id: str = ""
    target_type: str = ""        # web, network, api, code, cloud
    target_tech: list[str] = field(default_factory=list)   # nginx, django, mysql
    strategy: str = ""
    steps: list[EpisodeStep] = field(default_factory=list)
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    total_tokens: int = 0
    total_tools: int = 0
    outcome: EpisodeOutcome = EpisodeOutcome.SUCCESS
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    priority: float = 0.5       # For prioritized replay

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    @property
    def efficiency(self) -> float:
        """Findings per 1000 tokens."""
        return self.findings_count * 1000 / max(1, self.total_tokens)

    @property
    def success_rate(self) -> float:
        """Rate of successful steps."""
        if not self.steps:
            return 0.0
        return sum(1 for s in self.steps if s.success) / len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id[:10],
            "target_type": self.target_type[:8],
            "strategy": self.strategy[:15],
            "steps": len(self.steps),
            "findings": self.findings_count,
            "outcome": self.outcome.value,
            "efficiency": round(self.efficiency, 2),
        }


@dataclass
class StrategyPattern:
    """An extracted strategy pattern from episodes."""
    pattern_id: str = ""
    target_type: str = ""
    target_tech: list[str] = field(default_factory=list)
    tool_sequence: list[str] = field(default_factory=list)
    model_preferences: list[str] = field(default_factory=list)
    avg_findings: float = 0.0
    avg_efficiency: float = 0.0
    episode_count: int = 0
    success_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id[:10],
            "target": self.target_type[:8],
            "tools": self.tool_sequence[:5],
            "avg_findings": round(self.avg_findings, 1),
            "episodes": self.episode_count,
        }


class ExperienceReplayBuffer:
    """Episodic memory for agent learning.

    Records complete assessment episodes and extracts
    patterns for improving future assessments.
    """

    def __init__(
        self,
        max_episodes: int = 1000,
        data_dir: str = "",
    ) -> None:
        self._episodes: list[Episode] = []
        self._max_episodes = max_episodes
        self._counter = 0
        self._data_dir = data_dir or os.path.expanduser("~/.recursec/episodes")
        self._log = logger.bind(component="experience_replay")

    def start_episode(
        self,
        target_type: str,
        target_tech: list[str] | None = None,
        strategy: str = "",
    ) -> Episode:
        """Start recording a new episode."""
        self._counter += 1
        episode = Episode(
            episode_id=f"ep-{self._counter}",
            target_type=target_type,
            target_tech=target_tech or [],
            strategy=strategy,
        )
        self._episodes.append(episode)

        # Evict oldest if over limit
        if len(self._episodes) > self._max_episodes:
            # Keep high-priority episodes
            self._episodes.sort(key=lambda e: e.priority, reverse=True)
            self._episodes = self._episodes[:self._max_episodes]

        return episode

    def record_step(
        self,
        episode_id: str,
        step_type: StepType,
        action: str,
        tool: str = "",
        model: str = "",
        input_summary: str = "",
        output_summary: str = "",
        tokens_used: int = 0,
        duration_s: float = 0.0,
        success: bool = True,
        finding_severity: str = "",
    ) -> EpisodeStep | None:
        """Record a step in an episode."""
        episode = self._find_episode(episode_id)
        if not episode:
            return None

        step = EpisodeStep(
            step_num=len(episode.steps) + 1,
            step_type=step_type,
            action=action,
            tool=tool,
            model=model,
            input_summary=input_summary,
            output_summary=output_summary,
            tokens_used=tokens_used,
            duration_s=duration_s,
            success=success,
            finding_severity=finding_severity,
        )
        episode.steps.append(step)

        # Update episode totals
        episode.total_tokens += tokens_used
        if tool:
            episode.total_tools += 1
        if finding_severity:
            episode.findings_count += 1
            if finding_severity == "critical":
                episode.critical_count += 1
            elif finding_severity == "high":
                episode.high_count += 1

        return step

    def complete_episode(
        self,
        episode_id: str,
        outcome: EpisodeOutcome = EpisodeOutcome.SUCCESS,
    ) -> Episode | None:
        """Complete an episode."""
        episode = self._find_episode(episode_id)
        if not episode:
            return None

        episode.completed_at = time.time()
        episode.outcome = outcome

        # Calculate priority for replay
        episode.priority = self._calculate_priority(episode)

        return episode

    def _calculate_priority(self, episode: Episode) -> float:
        """Calculate replay priority for an episode.

        Higher priority for:
        - More findings (especially critical/high)
        - Better efficiency
        - Successful outcomes
        - Recent episodes
        """
        finding_score = (
            episode.critical_count * 4
            + episode.high_count * 2
            + episode.findings_count
        ) / 10.0

        efficiency_score = min(1.0, episode.efficiency / 5.0)

        outcome_scores = {
            EpisodeOutcome.SUCCESS: 1.0,
            EpisodeOutcome.PARTIAL: 0.6,
            EpisodeOutcome.FAILURE: 0.3,
            EpisodeOutcome.TIMEOUT: 0.2,
            EpisodeOutcome.ERROR: 0.1,
        }
        outcome_score = outcome_scores.get(episode.outcome, 0.3)

        # Recency bias
        age_hours = (time.time() - episode.started_at) / 3600
        recency_score = 1.0 / (1.0 + age_hours / 24)

        return min(1.0, (
            finding_score * 0.4
            + efficiency_score * 0.2
            + outcome_score * 0.2
            + recency_score * 0.2
        ))

    def get_similar_episodes(
        self,
        target_type: str,
        target_tech: list[str] | None = None,
        limit: int = 5,
    ) -> list[Episode]:
        """Get episodes similar to a given target."""
        scored: list[tuple[float, Episode]] = []

        for episode in self._episodes:
            if not episode.completed_at:
                continue

            score = 0.0

            # Target type match
            if episode.target_type == target_type:
                score += 1.0

            # Tech stack overlap
            if target_tech:
                overlap = len(set(episode.target_tech) & set(target_tech))
                if overlap > 0:
                    score += overlap / max(len(target_tech), 1)

            # Outcome bonus
            if episode.outcome == EpisodeOutcome.SUCCESS:
                score += 0.5
            elif episode.outcome == EpisodeOutcome.PARTIAL:
                score += 0.2

            scored.append((score, episode))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [ep for _, ep in scored[:limit]]

    def extract_strategy_patterns(self) -> list[StrategyPattern]:
        """Extract successful strategy patterns from episodes."""
        # Group by target type + strategy
        groups: dict[str, list[Episode]] = defaultdict(list)
        for episode in self._episodes:
            if episode.outcome in (EpisodeOutcome.SUCCESS, EpisodeOutcome.PARTIAL):
                key = f"{episode.target_type}:{episode.strategy}"
                groups[key].append(episode)

        patterns = []
        for key, episodes in groups.items():
            if len(episodes) < 2:
                continue

            # Extract common tool sequences
            tool_counts: dict[str, int] = defaultdict(int)
            model_counts: dict[str, int] = defaultdict(int)
            tech_counts: dict[str, int] = defaultdict(int)

            for ep in episodes:
                for step in ep.steps:
                    if step.tool:
                        tool_counts[step.tool] += 1
                    if step.model:
                        model_counts[step.model] += 1
                for tech in ep.target_tech:
                    tech_counts[tech] += 1

            top_tools = sorted(tool_counts, key=tool_counts.get, reverse=True)[:5]
            top_models = sorted(model_counts, key=model_counts.get, reverse=True)[:3]
            top_tech = sorted(tech_counts, key=tech_counts.get, reverse=True)[:5]

            target_type, strategy = key.split(":", 1)

            self._counter += 1
            pattern = StrategyPattern(
                pattern_id=f"pat-{self._counter}",
                target_type=target_type,
                target_tech=top_tech,
                tool_sequence=top_tools,
                model_preferences=top_models,
                avg_findings=sum(ep.findings_count for ep in episodes) / len(episodes),
                avg_efficiency=sum(ep.efficiency for ep in episodes) / len(episodes),
                episode_count=len(episodes),
                success_rate=sum(1 for ep in episodes if ep.outcome == EpisodeOutcome.SUCCESS) / len(episodes),
            )
            patterns.append(pattern)

        return patterns

    def build_replay_prompt(
        self,
        target_type: str,
        target_tech: list[str] | None = None,
        max_episodes: int = 3,
    ) -> str:
        """Build a prompt from past experiences."""
        similar = self.get_similar_episodes(target_type, target_tech, limit=max_episodes)
        if not similar:
            return ""

        lines = ["## Past Experience\n"]
        for ep in similar:
            lines.append(f"### Episode: {ep.target_type} ({ep.strategy})")
            lines.append(f"Outcome: {ep.outcome.value}, Findings: {ep.findings_count}")
            lines.append(f"Tech: {', '.join(ep.target_tech[:3])}")

            # Show key steps
            finding_steps = [s for s in ep.steps if s.finding_severity]
            tool_steps = [s for s in ep.steps if s.step_type == StepType.TOOL_USE]

            if tool_steps:
                lines.append("Tools used: " + ", ".join(
                    s.tool for s in tool_steps[:5] if s.tool
                ))
            if finding_steps:
                lines.append("Findings from: " + ", ".join(
                    f"{s.tool}({s.finding_severity})" for s in finding_steps[:5]
                ))
            lines.append("")

        return "\n".join(lines)

    def save(self) -> bool:
        """Save episodes to disk."""
        try:
            os.makedirs(self._data_dir, exist_ok=True)
            path = os.path.join(self._data_dir, "episodes.jsonl")
            with open(path, "w") as f:
                for ep in self._episodes:
                    f.write(json.dumps(ep.to_dict()) + "\n")
            return True
        except OSError:
            return False

    def _find_episode(self, episode_id: str) -> Episode | None:
        """Find an episode by ID."""
        for ep in self._episodes:
            if ep.episode_id == episode_id:
                return ep
        return None

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        outcome_counts: dict[str, int] = defaultdict(int)
        for ep in self._episodes:
            type_counts[ep.target_type] += 1
            outcome_counts[ep.outcome.value] += 1

        return {
            "episodes": len(self._episodes),
            "total_findings": sum(ep.findings_count for ep in self._episodes),
            "total_tokens": sum(ep.total_tokens for ep in self._episodes),
            "by_type": dict(type_counts),
            "by_outcome": dict(outcome_counts),
        }
