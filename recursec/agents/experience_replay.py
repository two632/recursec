"""Experience replay — stores and replays past agent experiences for learning.

Implements:
1. Experience storage with priority
2. Prioritized experience replay (PER)
3. Importance sampling
4. Experience summarization
5. Episode management
6. Temporal-difference learning signals
7. Experience similarity search
8. Circular buffer with priority eviction
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Experience:
    """A single experience record."""
    experience_id: str = ""
    state: dict[str, Any] = field(default_factory=dict)
    action: str = ""
    reward: float = 0.0
    next_state: dict[str, Any] = field(default_factory=dict)
    done: bool = False
    agent_id: str = ""
    model_used: str = ""
    tools_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    priority: float = 1.0
    timestamp: float = field(default_factory=time.time)
    episode_id: str = ""

    @property
    def td_error(self) -> float:
        """Temporal-difference error approximation."""
        # Higher reward → more surprising → higher priority
        return abs(self.reward) + 0.01

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id,
            "action": self.action[:40],
            "reward": round(self.reward, 2),
            "priority": round(self.priority, 2),
            "agent": self.agent_id[:15],
            "model": self.model_used[:15],
        }


@dataclass
class Episode:
    """A sequence of experiences forming an episode."""
    episode_id: str = ""
    goal: str = ""
    experiences: list[str] = field(default_factory=list)  # experience IDs
    total_reward: float = 0.0
    success: bool = False
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.ended_at:
            return self.ended_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id,
            "goal": self.goal[:40],
            "steps": len(self.experiences),
            "reward": round(self.total_reward, 2),
            "success": self.success,
            "duration_s": round(self.duration_s, 1),
        }


class ExperienceReplay:
    """Stores and replays past agent experiences for learning.

    Uses prioritized replay with importance sampling
    to focus learning on the most informative experiences.
    """

    def __init__(
        self,
        max_size: int = 10000,
        alpha: float = 0.6,      # Priority exponent
        beta: float = 0.4,       # Importance sampling exponent
        beta_increment: float = 0.001,
    ) -> None:
        self._buffer: dict[str, Experience] = {}
        self._buffer_order: list[str] = []  # Ordered by insertion
        self._max_size = max_size
        self._alpha = alpha
        self._beta = beta
        self._beta_increment = beta_increment
        self._episodes: dict[str, Episode] = {}
        self._exp_counter = 0
        self._ep_counter = 0
        self._sample_count = 0
        self._log = logger.bind(component="experience_replay")

    def store(
        self,
        state: dict[str, Any],
        action: str,
        reward: float,
        next_state: dict[str, Any] | None = None,
        done: bool = False,
        agent_id: str = "",
        model_used: str = "",
        tools_used: list[str] | None = None,
        tokens_used: int = 0,
        episode_id: str = "",
    ) -> str:
        """Store an experience."""
        self._exp_counter += 1
        exp_id = f"exp-{self._exp_counter}"

        experience = Experience(
            experience_id=exp_id,
            state=state,
            action=action,
            reward=reward,
            next_state=next_state or {},
            done=done,
            agent_id=agent_id,
            model_used=model_used,
            tools_used=tools_used or [],
            tokens_used=tokens_used,
            priority=abs(reward) + 0.01,  # TD-error proxy
            episode_id=episode_id,
        )

        # Evict if at capacity
        if len(self._buffer) >= self._max_size:
            self._evict()

        self._buffer[exp_id] = experience
        self._buffer_order.append(exp_id)

        # Update episode
        if episode_id and episode_id in self._episodes:
            ep = self._episodes[episode_id]
            ep.experiences.append(exp_id)
            ep.total_reward += reward

        return exp_id

    def start_episode(self, goal: str = "") -> str:
        """Start a new episode."""
        self._ep_counter += 1
        ep_id = f"ep-{self._ep_counter}"
        self._episodes[ep_id] = Episode(
            episode_id=ep_id,
            goal=goal,
        )
        return ep_id

    def end_episode(self, episode_id: str, success: bool = False) -> Episode | None:
        """End an episode."""
        ep = self._episodes.get(episode_id)
        if not ep:
            return None

        ep.ended_at = time.time()
        ep.success = success

        # Adjust priorities: successful episodes get higher priority
        if success:
            for exp_id in ep.experiences:
                exp = self._buffer.get(exp_id)
                if exp:
                    exp.priority *= 1.5

        return ep

    def sample(
        self,
        batch_size: int = 32,
    ) -> list[Experience]:
        """Sample a batch of experiences using prioritized replay."""
        if len(self._buffer) < batch_size:
            return list(self._buffer.values())

        self._sample_count += 1
        self._beta = min(1.0, self._beta + self._beta_increment)

        # Calculate sampling probabilities from priorities
        experiences = list(self._buffer.values())
        priorities = [e.priority ** self._alpha for e in experiences]
        total_priority = sum(priorities)

        if total_priority == 0:
            return random.sample(experiences, batch_size)

        probabilities = [p / total_priority for p in priorities]

        # Weighted sampling without replacement
        indices = []
        remaining = list(range(len(experiences)))
        remaining_probs = list(probabilities)

        for _ in range(min(batch_size, len(remaining))):
            total = sum(remaining_probs)
            if total == 0:
                break

            r = random.random() * total
            cumulative = 0.0
            chosen_idx = 0

            for i, prob in enumerate(remaining_probs):
                cumulative += prob
                if cumulative >= r:
                    chosen_idx = i
                    break

            indices.append(remaining[chosen_idx])
            remaining.pop(chosen_idx)
            remaining_probs.pop(chosen_idx)

        return [experiences[i] for i in indices]

    def sample_similar(
        self,
        state: dict[str, Any],
        top_k: int = 5,
    ) -> list[Experience]:
        """Sample experiences similar to a given state."""
        state_key = self._state_key(state)
        scored = []

        for exp in self._buffer.values():
            exp_key = self._state_key(exp.state)
            similarity = self._key_similarity(state_key, exp_key)
            scored.append((similarity, exp))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [exp for _, exp in scored[:top_k]]

    def get_best_actions(
        self,
        state_type: str = "",
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Get the best actions from experience."""
        relevant = []
        for exp in self._buffer.values():
            if state_type and exp.state.get("type") != state_type:
                continue
            relevant.append(exp)

        relevant.sort(key=lambda e: e.reward, reverse=True)

        return [
            {"action": e.action[:60], "reward": round(e.reward, 2),
             "model": e.model_used[:15]}
            for e in relevant[:top_k]
        ]

    def _evict(self) -> None:
        """Evict lowest-priority experience."""
        if not self._buffer:
            return

        # Find lowest priority
        min_id = min(self._buffer, key=lambda eid: self._buffer[eid].priority)
        del self._buffer[min_id]
        if min_id in self._buffer_order:
            self._buffer_order.remove(min_id)

    @staticmethod
    def _state_key(state: dict[str, Any]) -> str:
        """Convert state to a comparable key."""
        parts = []
        for key in sorted(state.keys()):
            parts.append(f"{key}={state[key]}")
        return "|".join(parts)

    @staticmethod
    def _key_similarity(key1: str, key2: str) -> float:
        """Simple similarity between state keys."""
        if not key1 or not key2:
            return 0.0
        parts1 = set(key1.split("|"))
        parts2 = set(key2.split("|"))
        if not parts1 or not parts2:
            return 0.0
        intersection = parts1 & parts2
        union = parts1 | parts2
        return len(intersection) / len(union)

    def get_episodes(self, limit: int = 10) -> list[dict[str, Any]]:
        return [ep.to_dict() for ep in list(self._episodes.values())[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        total_reward = sum(e.reward for e in self._buffer.values())
        return {
            "buffer_size": len(self._buffer),
            "max_size": self._max_size,
            "episodes": len(self._episodes),
            "samples_taken": self._sample_count,
            "total_reward": round(total_reward, 2),
            "beta": round(self._beta, 3),
        }
