"""Episodic memory — records and retrieves past assessment episodes.

Models episodic memory from cognitive science:
- Episodes are complete sequences of events (assessments, investigations)
- Temporal ordering preserved
- Context-dependent retrieval (similar situations trigger recall)
- Consolidation: important episodes strengthened, trivial ones forgotten
- Integration: patterns across episodes extracted

Uses:
- "Last time we scanned a WordPress site, we found..."
- "This network topology is similar to assessment X..."
- "Technique Y was effective against target type Z..."
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Event:
    """A single event within an episode."""
    event_id: str = ""
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""  # action, observation, finding, decision, reflection
    actor: str = ""       # Agent that performed this event
    content: str = ""
    result: str = ""
    success: bool = True
    importance: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id, "type": self.event_type,
            "actor": self.actor, "content": self.content[:200],
            "result": self.result[:200], "success": self.success,
            "importance": round(self.importance, 2),
            "timestamp": self.timestamp,
        }


@dataclass
class Episode:
    """A complete episode (assessment sequence)."""
    episode_id: str = ""
    title: str = ""
    target: str = ""
    target_type: str = ""  # web, network, code, cloud, etc.
    objective: str = ""
    events: list[Event] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    outcome: str = ""   # success, partial, failed
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    duration_s: float = 0.0
    technologies: list[str] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    lessons_learned: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    strength: float = 1.0  # Memory strength (consolidation)

    def __post_init__(self) -> None:
        if not self.episode_id:
            self.episode_id = hashlib.md5(
                f"{self.target}:{self.started_at}".encode()
            ).hexdigest()[:10]

    def add_event(self, event: Event) -> None:
        self.events.append(event)

    def complete(self, outcome: str = "", lessons: list[str] | None = None) -> None:
        """Mark episode as complete."""
        self.ended_at = time.time()
        self.duration_s = self.ended_at - self.started_at
        self.outcome = outcome
        if lessons:
            self.lessons_learned.extend(lessons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id, "title": self.title,
            "target": self.target, "target_type": self.target_type,
            "outcome": self.outcome,
            "events_count": len(self.events),
            "findings_count": len(self.findings),
            "duration_s": round(self.duration_s, 1),
            "technologies": self.technologies,
            "tools_used": self.tools_used[:10],
            "lessons": self.lessons_learned[:5],
            "strength": round(self.strength, 2),
        }

    def to_summary(self) -> str:
        """Brief text summary for retrieval context."""
        lines = [
            f"Episode: {self.title}",
            f"Target: {self.target} ({self.target_type})",
            f"Outcome: {self.outcome}",
            f"Technologies: {', '.join(self.technologies[:5])}",
            f"Findings: {len(self.findings)} total",
        ]
        if self.lessons_learned:
            lines.append(f"Lessons: {'; '.join(self.lessons_learned[:3])}")
        return "\n".join(lines)


class EpisodicMemory:
    """Stores and retrieves past assessment episodes.

    Enables agents to learn from past experiences and apply
    lessons to new situations.
    """

    def __init__(self, storage_dir: str = "data/episodes") -> None:
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._episodes: dict[str, Episode] = {}
        self._current_episode: Episode | None = None
        self._index: dict[str, list[str]] = defaultdict(list)  # tag → episode_ids
        self._log = logger.bind(component="episodic_memory")

        # Load persisted episodes
        self._load_all()

    def start_episode(
        self,
        target: str,
        target_type: str = "",
        objective: str = "",
        title: str = "",
    ) -> Episode:
        """Start recording a new episode."""
        episode = Episode(
            title=title or f"Assessment of {target}",
            target=target,
            target_type=target_type,
            objective=objective,
        )
        self._episodes[episode.episode_id] = episode
        self._current_episode = episode
        self._log.info("episode_started", episode=episode.episode_id, target=target)
        return episode

    def record_event(
        self,
        event_type: str,
        content: str,
        actor: str = "",
        result: str = "",
        success: bool = True,
        importance: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> Event | None:
        """Record an event in the current episode."""
        if not self._current_episode:
            return None

        event = Event(
            event_id=f"e{len(self._current_episode.events)}",
            event_type=event_type,
            actor=actor,
            content=content,
            result=result,
            success=success,
            importance=importance,
            metadata=metadata or {},
        )
        self._current_episode.add_event(event)
        return event

    def end_episode(
        self,
        outcome: str = "completed",
        findings: list[dict[str, Any]] | None = None,
        technologies: list[str] | None = None,
        techniques: list[str] | None = None,
        tools: list[str] | None = None,
        lessons: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Episode | None:
        """End the current episode and persist it."""
        if not self._current_episode:
            return None

        ep = self._current_episode
        ep.complete(outcome=outcome, lessons=lessons)
        if findings:
            ep.findings = findings
        if technologies:
            ep.technologies = technologies
        if techniques:
            ep.techniques_used = techniques
        if tools:
            ep.tools_used = tools
        if tags:
            ep.tags = tags

        # Index by tags
        for tag in ep.tags:
            self._index[tag].append(ep.episode_id)
        self._index[ep.target_type].append(ep.episode_id)

        # Persist
        self._save_episode(ep)
        self._current_episode = None

        self._log.info(
            "episode_ended", episode=ep.episode_id,
            events=len(ep.events), findings=len(ep.findings),
        )
        return ep

    def recall_by_target_type(self, target_type: str, limit: int = 5) -> list[Episode]:
        """Recall episodes involving similar target types."""
        ids = self._index.get(target_type, [])
        episodes = [
            self._episodes[eid] for eid in ids
            if eid in self._episodes
        ]
        episodes.sort(key=lambda e: -e.strength)
        return episodes[:limit]

    def recall_by_technology(self, technology: str, limit: int = 5) -> list[Episode]:
        """Recall episodes involving a specific technology."""
        results = []
        tech_lower = technology.lower()
        for ep in self._episodes.values():
            if any(tech_lower in t.lower() for t in ep.technologies):
                results.append(ep)
        results.sort(key=lambda e: -e.strength)
        return results[:limit]

    def recall_by_tag(self, tag: str, limit: int = 5) -> list[Episode]:
        """Recall episodes with a specific tag."""
        ids = self._index.get(tag, [])
        episodes = [
            self._episodes[eid] for eid in ids
            if eid in self._episodes
        ]
        return episodes[:limit]

    def recall_similar(self, target: str, target_type: str = "", limit: int = 5) -> list[Episode]:
        """Recall episodes similar to the given target context."""
        scored: list[tuple[Episode, float]] = []
        target_lower = target.lower()

        for ep in self._episodes.values():
            score = 0.0
            # Match target type
            if target_type and ep.target_type == target_type:
                score += 2.0
            # Match target name overlap
            if any(word in ep.target.lower() for word in target_lower.split()):
                score += 1.0
            # Recency bonus
            age_days = (time.time() - ep.started_at) / 86400
            score += max(0, 1.0 - age_days / 30)
            # Strength
            score *= ep.strength

            if score > 0:
                scored.append((ep, score))

        scored.sort(key=lambda x: -x[1])
        return [ep for ep, _ in scored[:limit]]

    def get_lessons_for_context(
        self,
        target_type: str = "",
        technologies: list[str] | None = None,
    ) -> list[str]:
        """Get accumulated lessons relevant to a context."""
        all_lessons = []
        episodes = self.recall_by_target_type(target_type, limit=10)

        if technologies:
            for tech in technologies:
                episodes.extend(self.recall_by_technology(tech, limit=5))

        seen = set()
        for ep in episodes:
            for lesson in ep.lessons_learned:
                if lesson not in seen:
                    all_lessons.append(lesson)
                    seen.add(lesson)

        return all_lessons

    def consolidate(self) -> None:
        """Consolidation pass: strengthen important episodes, weaken trivial ones.

        Modeled on memory consolidation in sleep.
        """
        for ep in self._episodes.values():
            # Strengthen episodes with many findings
            if len(ep.findings) > 5:
                ep.strength = min(2.0, ep.strength * 1.1)
            # Strengthen episodes with lessons
            if ep.lessons_learned:
                ep.strength = min(2.0, ep.strength * 1.05)
            # Weaken old episodes with no findings
            if len(ep.findings) == 0:
                ep.strength *= 0.9
            # Age-based decay
            age_days = (time.time() - ep.started_at) / 86400
            if age_days > 30:
                ep.strength *= 0.95

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        by_outcome: dict[str, int] = defaultdict(int)
        for ep in self._episodes.values():
            by_type[ep.target_type] += 1
            by_outcome[ep.outcome] += 1
        return {
            "total_episodes": len(self._episodes),
            "by_target_type": dict(by_type),
            "by_outcome": dict(by_outcome),
            "total_events": sum(len(ep.events) for ep in self._episodes.values()),
            "total_findings": sum(len(ep.findings) for ep in self._episodes.values()),
        }

    # ── Persistence ──────────────────────────────────────

    def _save_episode(self, episode: Episode) -> None:
        try:
            path = self._storage_dir / f"{episode.episode_id}.json"
            data = {
                "episode_id": episode.episode_id,
                "title": episode.title,
                "target": episode.target,
                "target_type": episode.target_type,
                "objective": episode.objective,
                "outcome": episode.outcome,
                "started_at": episode.started_at,
                "ended_at": episode.ended_at,
                "duration_s": episode.duration_s,
                "technologies": episode.technologies,
                "techniques_used": episode.techniques_used,
                "tools_used": episode.tools_used,
                "lessons_learned": episode.lessons_learned,
                "tags": episode.tags,
                "strength": episode.strength,
                "events": [e.to_dict() for e in episode.events],
                "findings": episode.findings,
            }
            path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            self._log.warning("episode_save_failed", error=str(e))

    def _load_all(self) -> None:
        """Load all persisted episodes."""
        for path in self._storage_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                episode = Episode(
                    episode_id=data["episode_id"],
                    title=data.get("title", ""),
                    target=data.get("target", ""),
                    target_type=data.get("target_type", ""),
                    objective=data.get("objective", ""),
                    outcome=data.get("outcome", ""),
                    started_at=data.get("started_at", 0),
                    ended_at=data.get("ended_at", 0),
                    duration_s=data.get("duration_s", 0),
                    technologies=data.get("technologies", []),
                    techniques_used=data.get("techniques_used", []),
                    tools_used=data.get("tools_used", []),
                    lessons_learned=data.get("lessons_learned", []),
                    tags=data.get("tags", []),
                    strength=data.get("strength", 1.0),
                    findings=data.get("findings", []),
                )

                for event_data in data.get("events", []):
                    event = Event(
                        event_id=event_data.get("id", ""),
                        event_type=event_data.get("type", ""),
                        actor=event_data.get("actor", ""),
                        content=event_data.get("content", ""),
                        result=event_data.get("result", ""),
                        success=event_data.get("success", True),
                        importance=event_data.get("importance", 0.5),
                        timestamp=event_data.get("timestamp", 0),
                    )
                    episode.events.append(event)

                self._episodes[episode.episode_id] = episode
                for tag in episode.tags:
                    self._index[tag].append(episode.episode_id)
                self._index[episode.target_type].append(episode.episode_id)

            except (json.JSONDecodeError, OSError, KeyError) as e:
                self._log.warning("episode_load_failed", path=str(path), error=str(e))
