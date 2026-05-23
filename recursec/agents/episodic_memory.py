"""Episodic memory — stores and retrieves complete episodes of agent experience.

Unlike experience replay (individual transitions), episodic memory
stores rich, contextualized episodes with narrative structure. Implements:
1. Episode recording with temporal ordering
2. Episode indexing and retrieval
3. Similarity-based episode search
4. Episode summarization
5. Cue-based memory recall
6. Memory consolidation (short-term → long-term)
7. Forgetting curves (less-accessed memories fade)
8. Cross-episode pattern detection
"""

from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MemoryEvent:
    """A single event within an episode."""
    event_id: str = ""
    event_type: str = ""          # action, observation, decision, finding, error
    content: str = ""
    agent_id: str = ""
    tool: str = ""
    model: str = ""
    importance: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "type": self.event_type[:15],
            "content": self.content[:60],
            "importance": round(self.importance, 2),
        }


@dataclass
class Episode:
    """A complete episode of agent experience."""
    episode_id: str = ""
    title: str = ""
    target: str = ""
    goal: str = ""
    events: list[MemoryEvent] = field(default_factory=list)
    outcome: str = ""              # success, failure, partial
    key_findings: list[str] = field(default_factory=list)
    lessons_learned: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    total_tokens: int = 0
    created_at: float = field(default_factory=time.time)
    access_count: int = 0
    last_accessed: float = 0.0
    importance: float = 0.5
    consolidated: bool = False

    @property
    def duration_s(self) -> float:
        if not self.events:
            return 0.0
        return self.events[-1].timestamp - self.events[0].timestamp

    @property
    def memory_strength(self) -> float:
        """How strong this memory is (decays with time, boosted by access)."""
        if self.last_accessed == 0:
            age = time.time() - self.created_at
        else:
            age = time.time() - self.last_accessed

        # Ebbinghaus forgetting curve
        base_strength = self.importance * (1 + math.log1p(self.access_count))
        decay = math.exp(-age / (86400.0 * 7))  # ~1 week half-life
        return base_strength * decay

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id,
            "title": self.title[:40],
            "target": self.target[:20],
            "outcome": self.outcome,
            "events": len(self.events),
            "findings": len(self.key_findings),
            "strength": round(self.memory_strength, 3),
            "accesses": self.access_count,
        }


@dataclass
class MemoryQuery:
    """A query to search episodic memory."""
    target: str = ""
    goal: str = ""
    tags: list[str] = field(default_factory=list)
    outcome_filter: str = ""
    min_importance: float = 0.0
    limit: int = 10


class EpisodicMemory:
    """Stores and retrieves complete episodes of agent experience.

    Rich episodic memory with temporal ordering, forgetting
    curves, consolidation, and pattern detection.
    """

    def __init__(
        self,
        data_dir: str = "data/episodic_memory",
        max_episodes: int = 500,
        max_short_term: int = 50,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._long_term: dict[str, Episode] = {}
        self._short_term: list[Episode] = []
        self._active_episode: Episode | None = None
        self._episode_counter = 0
        self._event_counter = 0
        self._max_episodes = max_episodes
        self._max_short_term = max_short_term
        self._log = logger.bind(component="episodic_memory")

    def start_episode(
        self,
        title: str,
        target: str = "",
        goal: str = "",
        tags: list[str] | None = None,
    ) -> Episode:
        """Start recording a new episode."""
        # Close any active episode
        if self._active_episode:
            self.end_episode()

        self._episode_counter += 1
        episode = Episode(
            episode_id=f"ep-{self._episode_counter}",
            title=title,
            target=target,
            goal=goal,
            tags=tags or [],
        )

        self._active_episode = episode
        return episode

    def record_event(
        self,
        event_type: str,
        content: str,
        agent_id: str = "",
        tool: str = "",
        model: str = "",
        importance: float = 0.5,
    ) -> MemoryEvent | None:
        """Record an event in the current episode."""
        if not self._active_episode:
            return None

        self._event_counter += 1
        event = MemoryEvent(
            event_id=f"ev-{self._event_counter}",
            event_type=event_type,
            content=content,
            agent_id=agent_id,
            tool=tool,
            model=model,
            importance=importance,
        )

        self._active_episode.events.append(event)
        return event

    def end_episode(
        self,
        outcome: str = "unknown",
        key_findings: list[str] | None = None,
        lessons_learned: list[str] | None = None,
    ) -> Episode | None:
        """End the current episode and store it."""
        if not self._active_episode:
            return None

        episode = self._active_episode
        episode.outcome = outcome
        episode.key_findings = key_findings or []
        episode.lessons_learned = lessons_learned or []

        # Calculate importance
        episode.importance = self._calculate_importance(episode)

        # Store in short-term memory
        self._short_term.append(episode)
        if len(self._short_term) > self._max_short_term:
            self._consolidate()

        # Persist
        self._save_episode(episode)

        self._active_episode = None
        return episode

    def recall(self, query: MemoryQuery) -> list[Episode]:
        """Recall episodes matching a query."""
        results = []

        all_episodes = list(self._long_term.values()) + self._short_term

        for episode in all_episodes:
            score = self._match_score(episode, query)
            if score > 0:
                results.append((score, episode))

        # Sort by relevance
        results.sort(key=lambda x: x[0], reverse=True)

        recalled = []
        for _, episode in results[:query.limit]:
            episode.access_count += 1
            episode.last_accessed = time.time()
            recalled.append(episode)

        return recalled

    def recall_by_cue(self, cue: str) -> list[Episode]:
        """Recall episodes triggered by a cue (keyword/phrase)."""
        cue_lower = cue.lower()
        results = []

        all_episodes = list(self._long_term.values()) + self._short_term

        for episode in all_episodes:
            relevance = 0.0

            # Check title
            if cue_lower in episode.title.lower():
                relevance += 0.5

            # Check target
            if cue_lower in episode.target.lower():
                relevance += 0.3

            # Check events
            for event in episode.events:
                if cue_lower in event.content.lower():
                    relevance += 0.1

            # Check tags
            if cue_lower in [t.lower() for t in episode.tags]:
                relevance += 0.4

            if relevance > 0:
                results.append((relevance * episode.memory_strength, episode))

        results.sort(key=lambda x: x[0], reverse=True)
        return [ep for _, ep in results[:10]]

    def find_patterns(self) -> list[dict[str, Any]]:
        """Detect patterns across episodes."""
        patterns = []

        all_episodes = list(self._long_term.values()) + self._short_term

        # Pattern: Common tools in successful episodes
        successful_tools: dict[str, int] = defaultdict(int)
        failed_tools: dict[str, int] = defaultdict(int)

        for episode in all_episodes:
            tool_set = {e.tool for e in episode.events if e.tool}
            for tool in tool_set:
                if episode.outcome == "success":
                    successful_tools[tool] += 1
                elif episode.outcome == "failure":
                    failed_tools[tool] += 1

        # Tools that correlate with success
        for tool, success_count in successful_tools.items():
            fail_count = failed_tools.get(tool, 0)
            if success_count > fail_count * 2 and success_count >= 3:
                patterns.append({
                    "type": "tool_success_correlation",
                    "tool": tool,
                    "success_count": success_count,
                    "fail_count": fail_count,
                })

        # Pattern: Target type → outcome correlation
        target_outcomes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for episode in all_episodes:
            target_type = episode.target.split(":")[:1]
            target_key = target_type[0] if target_type else "unknown"
            target_outcomes[target_key][episode.outcome] += 1

        for target_type, outcomes in target_outcomes.items():
            if outcomes.get("success", 0) > 5:
                patterns.append({
                    "type": "target_success_pattern",
                    "target_type": target_type,
                    "outcomes": dict(outcomes),
                })

        return patterns

    def _consolidate(self) -> None:
        """Consolidate short-term memories into long-term storage."""
        for episode in self._short_term:
            if episode.memory_strength > 0.1:
                self._long_term[episode.episode_id] = episode
                episode.consolidated = True

        self._short_term = []

        # Evict weakest from long-term if over limit
        if len(self._long_term) > self._max_episodes:
            sorted_eps = sorted(
                self._long_term.values(),
                key=lambda e: e.memory_strength,
            )
            for ep in sorted_eps[:len(self._long_term) - self._max_episodes]:
                del self._long_term[ep.episode_id]

    def _match_score(self, episode: Episode, query: MemoryQuery) -> float:
        """Score how well an episode matches a query."""
        score = 0.0

        if query.target and query.target.lower() in episode.target.lower():
            score += 0.3

        if query.goal and query.goal.lower() in episode.goal.lower():
            score += 0.3

        if query.tags:
            matching_tags = set(query.tags) & set(episode.tags)
            score += 0.2 * (len(matching_tags) / len(query.tags))

        if query.outcome_filter and episode.outcome == query.outcome_filter:
            score += 0.2

        if episode.importance < query.min_importance:
            return 0.0

        return score * episode.memory_strength

    @staticmethod
    def _calculate_importance(episode: Episode) -> float:
        """Calculate episode importance."""
        importance = 0.5

        # Findings boost importance
        importance += min(0.3, len(episode.key_findings) * 0.1)

        # Success is more important to remember
        if episode.outcome == "success":
            importance += 0.1

        # Long episodes (more detail) are more important
        if len(episode.events) > 10:
            importance += 0.1

        return min(1.0, importance)

    def _save_episode(self, episode: Episode) -> None:
        """Save episode to disk."""
        path = self._data_dir / f"{episode.episode_id}.json"
        try:
            data = episode.to_dict()
            data["events"] = [e.to_dict() for e in episode.events]
            path.write_text(json.dumps(data, indent=2, default=str))
        except OSError:
            pass

    def get_stats(self) -> dict[str, Any]:
        return {
            "short_term": len(self._short_term),
            "long_term": len(self._long_term),
            "total_episodes": self._episode_counter,
            "total_events": self._event_counter,
            "active": self._active_episode is not None,
        }
