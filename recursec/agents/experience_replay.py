"""Experience replay buffer — stores and replays past strategies.

Implements:
1. Experience storage (state-action-reward tuples)
2. Prioritized replay (higher reward = more likely)
3. Episode tracking (full assessment sequences)
4. Strategy extraction from successful runs
5. Similarity-based experience retrieval
6. Replay prompt for LLM
"""

from __future__ import annotations

import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Experience:
    """A single state-action-reward experience."""
    experience_id: str = ""
    episode_id: str = ""
    step: int = 0
    state: dict[str, Any] = field(default_factory=dict)
    action: str = ""
    action_params: dict[str, Any] = field(default_factory=dict)
    reward: float = 0.0
    next_state: dict[str, Any] = field(default_factory=dict)
    target_type: str = ""
    tool_used: str = ""
    model_used: str = ""
    finding_severity: str = ""
    timestamp: float = field(default_factory=time.time)
    priority: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action[:15],
            "reward": f"{self.reward:.2f}",
            "tool": self.tool_used[:10],
            "sev": self.finding_severity[:4] or "none",
        }


@dataclass
class Episode:
    """A complete assessment episode."""
    episode_id: str = ""
    target: str = ""
    target_type: str = ""
    experiences: list[str] = field(default_factory=list)  # experience_ids
    total_reward: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    duration_s: float = 0.0
    strategy_summary: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:15],
            "reward": f"{self.total_reward:.1f}",
            "findings": self.findings_count,
            "critical": self.critical_count,
        }


class ExperienceReplayBuffer:
    """Prioritized experience replay for agent learning.

    Stores past assessment experiences, enables
    replay of successful strategies, and provides
    similarity-based retrieval for new targets.
    """

    def __init__(
        self,
        max_experiences: int = 5000,
        max_episodes: int = 100,
        priority_alpha: float = 0.6,
    ) -> None:
        self._experiences: dict[str, Experience] = {}
        self._episodes: dict[str, Episode] = {}
        self._buffer: deque[str] = deque(maxlen=max_experiences)
        self._exp_counter = 0
        self._episode_counter = 0
        self._priority_alpha = priority_alpha
        self._rng = random.Random(42)
        self._log = logger.bind(component="replay")

    def start_episode(
        self,
        target: str = "",
        target_type: str = "",
    ) -> Episode:
        """Start a new assessment episode."""
        self._episode_counter += 1
        episode = Episode(
            episode_id=f"ep-{self._episode_counter}",
            target=target,
            target_type=target_type,
        )
        self._episodes[episode.episode_id] = episode
        return episode

    def end_episode(self, episode_id: str) -> Episode | None:
        """End an episode and calculate totals."""
        episode = self._episodes.get(episode_id)
        if not episode:
            return None

        episode.completed_at = time.time()
        episode.duration_s = episode.completed_at - episode.started_at

        # Calculate totals
        total_reward = 0.0
        findings = 0
        critical = 0

        for exp_id in episode.experiences:
            exp = self._experiences.get(exp_id)
            if exp:
                total_reward += exp.reward
                if exp.finding_severity:
                    findings += 1
                    if exp.finding_severity == "critical":
                        critical += 1

        episode.total_reward = total_reward
        episode.findings_count = findings
        episode.critical_count = critical

        return episode

    def store(
        self,
        episode_id: str,
        state: dict[str, Any],
        action: str,
        reward: float,
        next_state: dict[str, Any] | None = None,
        action_params: dict[str, Any] | None = None,
        target_type: str = "",
        tool_used: str = "",
        model_used: str = "",
        finding_severity: str = "",
    ) -> Experience:
        """Store an experience."""
        self._exp_counter += 1

        # Priority based on reward (higher reward = higher priority)
        priority = max(0.1, abs(reward) + 0.1) ** self._priority_alpha

        exp = Experience(
            experience_id=f"exp-{self._exp_counter}",
            episode_id=episode_id,
            step=self._exp_counter,
            state=state,
            action=action,
            action_params=action_params or {},
            reward=reward,
            next_state=next_state or {},
            target_type=target_type,
            tool_used=tool_used,
            model_used=model_used,
            finding_severity=finding_severity,
            priority=priority,
        )

        self._experiences[exp.experience_id] = exp
        self._buffer.append(exp.experience_id)

        # Add to episode
        episode = self._episodes.get(episode_id)
        if episode:
            episode.experiences.append(exp.experience_id)

        return exp

    def sample(self, n: int = 10) -> list[Experience]:
        """Sample experiences with priority weighting."""
        if not self._buffer:
            return []

        n = min(n, len(self._buffer))

        # Priority-weighted sampling
        exp_ids = list(self._buffer)
        priorities = []
        for eid in exp_ids:
            exp = self._experiences.get(eid)
            priorities.append(exp.priority if exp else 1.0)

        total = sum(priorities)
        if total == 0:
            return []

        probs = [p / total for p in priorities]

        # Weighted sample without replacement
        indices = []
        remaining_probs = list(probs)
        remaining_indices = list(range(len(exp_ids)))

        for _ in range(n):
            if not remaining_indices:
                break
            total_p = sum(remaining_probs)
            if total_p <= 0:
                break

            r = self._rng.random() * total_p
            cumulative = 0.0
            chosen = 0
            for i, p in enumerate(remaining_probs):
                cumulative += p
                if cumulative >= r:
                    chosen = i
                    break

            indices.append(remaining_indices[chosen])
            remaining_probs.pop(chosen)
            remaining_indices.pop(chosen)

        return [
            self._experiences[exp_ids[i]]
            for i in indices
            if exp_ids[i] in self._experiences
        ]

    def retrieve_similar(
        self,
        target_type: str = "",
        action: str = "",
        max_results: int = 5,
    ) -> list[Experience]:
        """Retrieve experiences similar to current situation."""
        matches = []

        for exp in self._experiences.values():
            score = 0.0
            if target_type and exp.target_type == target_type:
                score += 0.5
            if action and exp.action == action:
                score += 0.3
            if exp.reward > 0:
                score += min(0.2, exp.reward / 10)

            if score > 0:
                matches.append((exp, score))

        matches.sort(key=lambda x: x[1], reverse=True)
        return [m[0] for m in matches[:max_results]]

    def get_best_episodes(self, n: int = 5) -> list[Episode]:
        """Get episodes with highest total reward."""
        episodes = sorted(
            self._episodes.values(),
            key=lambda e: e.total_reward,
            reverse=True,
        )
        return episodes[:n]

    def get_tool_effectiveness(self) -> dict[str, dict[str, float]]:
        """Analyze tool effectiveness from experiences."""
        tool_stats: dict[str, dict[str, float]] = {}

        for exp in self._experiences.values():
            if not exp.tool_used:
                continue

            tool = exp.tool_used
            if tool not in tool_stats:
                tool_stats[tool] = {
                    "uses": 0,
                    "total_reward": 0.0,
                    "findings": 0,
                    "avg_reward": 0.0,
                }

            tool_stats[tool]["uses"] += 1
            tool_stats[tool]["total_reward"] += exp.reward
            if exp.finding_severity:
                tool_stats[tool]["findings"] += 1

        # Calculate averages
        for stats in tool_stats.values():
            if stats["uses"] > 0:
                stats["avg_reward"] = stats["total_reward"] / stats["uses"]

        return tool_stats

    def build_replay_prompt(
        self,
        target_type: str = "",
        max_experiences: int = 5,
    ) -> str:
        """Build replay context for LLM."""
        lines = ["## Experience Replay\n"]
        lines.append(f"Episodes: {len(self._episodes)}")
        lines.append(f"Experiences: {len(self._experiences)}")

        # Best episodes
        best = self.get_best_episodes(3)
        if best:
            lines.append("\nBest episodes:")
            for ep in best:
                lines.append(
                    f"  {ep.target[:15]}: reward={ep.total_reward:.1f}, "
                    f"findings={ep.findings_count}"
                )

        # Similar experiences
        if target_type:
            similar = self.retrieve_similar(target_type=target_type, max_results=max_experiences)
            if similar:
                lines.append(f"\nSimilar to '{target_type}':")
                for exp in similar:
                    lines.append(
                        f"  {exp.action[:15]} → reward={exp.reward:.1f} "
                        f"(tool={exp.tool_used[:8]})"
                    )

        # Tool effectiveness
        tools = self.get_tool_effectiveness()
        if tools:
            top_tools = sorted(
                tools.items(),
                key=lambda x: x[1]["avg_reward"],
                reverse=True,
            )[:5]
            lines.append("\nTop tools:")
            for tool, stats in top_tools:
                lines.append(
                    f"  {tool[:12]}: avg={stats['avg_reward']:.1f}, "
                    f"findings={stats['findings']:.0f}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "episodes": len(self._episodes),
            "experiences": len(self._experiences),
            "buffer_size": len(self._buffer),
            "tool_effectiveness": {
                t: s["avg_reward"]
                for t, s in self.get_tool_effectiveness().items()
            },
        }
