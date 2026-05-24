"""Episodic memory — sequence-based event memory.

Implements:
1. Event sequence recording
2. Episode boundaries and segmentation
3. Temporal pattern detection
4. Episode retrieval by similarity
5. Narrative generation from episodes
6. Episode prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    TOOL_RUN = "tool_run"           # Tool executed
    FINDING = "finding"             # Finding discovered
    DECISION = "decision"           # Agent made decision
    ERROR = "error"                 # Error occurred
    PHASE_CHANGE = "phase_change"   # Phase transition
    AGENT_SPAWN = "agent_spawn"     # Child agent spawned
    MODEL_CALL = "model_call"       # LLM invocation
    STRATEGY_CHANGE = "strategy"    # Strategy changed


class EpisodeOutcome(str, Enum):
    SUCCESS = "success"             # Episode succeeded
    PARTIAL = "partial"             # Partial success
    FAILURE = "failure"             # Episode failed
    ABANDONED = "abandoned"         # Episode abandoned


@dataclass
class Event:
    """A single event in an episode."""
    event_id: str = ""
    event_type: EventType = EventType.TOOL_RUN
    action: str = ""
    result: str = ""
    success: bool = True
    tool: str = ""
    model: str = ""
    target: str = ""
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.event_type.value[:8],
            "action": self.action[:20],
            "ok": self.success,
        }


@dataclass
class Episode:
    """A complete episode (a logical unit of work)."""
    episode_id: str = ""
    title: str = ""
    events: list[Event] = field(default_factory=list)
    outcome: EpisodeOutcome = EpisodeOutcome.PARTIAL
    findings_count: int = 0
    target: str = ""
    phase: str = ""
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    tags: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        if self.ended_at:
            return self.ended_at - self.started_at
        return time.time() - self.started_at

    @property
    def success_rate(self) -> float:
        if not self.events:
            return 0.0
        successes = sum(1 for e in self.events if e.success)
        return successes / len(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title[:20],
            "events": len(self.events),
            "outcome": self.outcome.value[:8],
            "findings": self.findings_count,
        }


class EpisodicMemory:
    """Sequence-based memory of assessment events.

    Records events in episodes, detects
    patterns, and enables narrative retrieval.
    """

    def __init__(self, max_episodes: int = 50) -> None:
        self._episodes: dict[str, Episode] = {}
        self._current: Episode | None = None
        self._episode_counter = 0
        self._event_counter = 0
        self._max_episodes = max_episodes
        self._log = logger.bind(component="episodic")

    def start_episode(
        self,
        title: str,
        target: str = "",
        phase: str = "",
        tags: list[str] | None = None,
    ) -> Episode:
        """Start a new episode."""
        # End current episode if open
        if self._current:
            self.end_episode()

        self._episode_counter += 1
        episode = Episode(
            episode_id=f"ep-{self._episode_counter}",
            title=title,
            target=target,
            phase=phase,
            tags=tags or [],
        )
        self._episodes[episode.episode_id] = episode
        self._current = episode

        # Evict old episodes
        if len(self._episodes) > self._max_episodes:
            oldest = min(
                self._episodes,
                key=lambda k: self._episodes[k].started_at,
            )
            del self._episodes[oldest]

        return episode

    def record_event(
        self,
        event_type: EventType,
        action: str,
        result: str = "",
        success: bool = True,
        tool: str = "",
        model: str = "",
        duration_s: float = 0.0,
    ) -> Event:
        """Record an event in the current episode."""
        self._event_counter += 1

        event = Event(
            event_id=f"ev-{self._event_counter}",
            event_type=event_type,
            action=action,
            result=result,
            success=success,
            tool=tool,
            model=model,
            target=self._current.target if self._current else "",
            duration_s=duration_s,
        )

        if self._current:
            self._current.events.append(event)
            if event_type == EventType.FINDING:
                self._current.findings_count += 1

        return event

    def end_episode(
        self,
        outcome: EpisodeOutcome | None = None,
    ) -> Episode | None:
        """End the current episode."""
        if not self._current:
            return None

        if outcome:
            self._current.outcome = outcome
        else:
            # Auto-determine outcome
            rate = self._current.success_rate
            if rate >= 0.8:
                self._current.outcome = EpisodeOutcome.SUCCESS
            elif rate >= 0.4:
                self._current.outcome = EpisodeOutcome.PARTIAL
            else:
                self._current.outcome = EpisodeOutcome.FAILURE

        self._current.ended_at = time.time()
        episode = self._current
        self._current = None
        return episode

    def get_similar_episodes(
        self,
        target: str = "",
        phase: str = "",
        tags: list[str] | None = None,
        limit: int = 3,
    ) -> list[Episode]:
        """Find similar past episodes."""
        scored: list[tuple[Episode, float]] = []

        for episode in self._episodes.values():
            score = 0.0

            if target and episode.target == target:
                score += 3.0
            if phase and episode.phase == phase:
                score += 2.0
            if tags:
                overlap = set(tags) & set(episode.tags)
                score += len(overlap)

            if score > 0:
                scored.append((episode, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [ep for ep, _ in scored[:limit]]

    def get_patterns(self) -> list[dict[str, Any]]:
        """Detect patterns across episodes."""
        patterns: list[dict[str, Any]] = []

        # Tool success rates
        tool_stats: dict[str, dict[str, int]] = {}
        for episode in self._episodes.values():
            for event in episode.events:
                if event.tool:
                    if event.tool not in tool_stats:
                        tool_stats[event.tool] = {"success": 0, "total": 0}
                    tool_stats[event.tool]["total"] += 1
                    if event.success:
                        tool_stats[event.tool]["success"] += 1

        for tool, stats in tool_stats.items():
            if stats["total"] >= 3:
                rate = stats["success"] / stats["total"]
                patterns.append({
                    "type": "tool_reliability",
                    "tool": tool,
                    "rate": f"{rate:.0%}",
                    "total": stats["total"],
                })

        # Common failure sequences
        fail_sequences: dict[str, int] = {}
        for episode in self._episodes.values():
            for i, event in enumerate(episode.events):
                if not event.success and i > 0:
                    prev = episode.events[i - 1]
                    seq = f"{prev.action[:10]}→{event.action[:10]}"
                    fail_sequences[seq] = fail_sequences.get(seq, 0) + 1

        for seq, count in fail_sequences.items():
            if count >= 2:
                patterns.append({
                    "type": "fail_sequence",
                    "sequence": seq,
                    "count": count,
                })

        return patterns

    def build_narrative(self, episode_id: str) -> str:
        """Build a narrative from an episode."""
        episode = self._episodes.get(episode_id)
        if not episode:
            return ""

        lines = [f"Episode: {episode.title}"]
        lines.append(f"Outcome: {episode.outcome.value}")
        lines.append(f"Duration: {episode.duration_s:.0f}s")

        for event in episode.events[:10]:
            status = "ok" if event.success else "FAIL"
            lines.append(
                f"  [{status}] {event.action[:25]}"
                + (f" ({event.tool})" if event.tool else "")
            )

        return "\n".join(lines)

    def build_episodic_prompt(self, max_episodes: int = 3) -> str:
        """Build episodic memory context for LLM."""
        lines = ["## Episodes\n"]
        lines.append(f"Total: {len(self._episodes)}")

        if self._current:
            lines.append(
                f"Current: {self._current.title[:20]} "
                f"({len(self._current.events)} events)"
            )

        # Recent episodes
        recent = sorted(
            self._episodes.values(),
            key=lambda e: e.started_at,
            reverse=True,
        )[:max_episodes]

        for ep in recent:
            lines.append(
                f"\n[{ep.outcome.value[:6]}] {ep.title[:20]} "
                f"({ep.findings_count} findings)"
            )

        # Patterns
        patterns = self.get_patterns()
        if patterns:
            lines.append("\nPatterns:")
            for p in patterns[:3]:
                if p["type"] == "tool_reliability":
                    lines.append(
                        f"  {p['tool'][:10]}: {p['rate']} reliable"
                    )
                elif p["type"] == "fail_sequence":
                    lines.append(
                        f"  {p['sequence']}: fails {p['count']}x"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for ep in self._episodes.values():
            outcome_counts[ep.outcome.value] = (
                outcome_counts.get(ep.outcome.value, 0) + 1
            )

        return {
            "episodes": len(self._episodes),
            "total_events": sum(
                len(ep.events) for ep in self._episodes.values()
            ),
            "by_outcome": outcome_counts,
        }
