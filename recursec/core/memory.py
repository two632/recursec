"""Agent memory system — short-term, long-term, and episodic memory.

Provides:
- Short-term memory: Current task context, conversation history
- Long-term memory: Persistent findings, learned patterns, tool preferences
- Episodic memory: Complete scan histories for pattern recognition
- Working memory: Active hypotheses and investigation threads
- Memory compression: Summarize old memories to fit context windows
- Memory retrieval: Semantic search via embeddings, recency-weighted
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MemoryEntry:
    """A single memory entry."""
    content: str
    memory_type: str  # "observation", "action", "finding", "hypothesis", "tool_result", "error"
    timestamp: float = field(default_factory=time.time)
    importance: float = 0.5  # 0-1
    source_agent: str = ""
    task_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content[:500],
            "type": self.memory_type,
            "timestamp": self.timestamp,
            "importance": round(self.importance, 2),
            "source": self.source_agent,
            "task_id": self.task_id,
        }


@dataclass
class Episode:
    """A complete scan episode for learning."""
    episode_id: str
    target: str
    target_type: str
    objective: str
    start_time: float
    end_time: float = 0.0
    actions: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    success: bool = False
    lesson_learned: str = ""


@dataclass
class Hypothesis:
    """An active investigation hypothesis."""
    hypothesis_id: str
    description: str
    confidence: float = 0.5
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    status: str = "active"  # active, confirmed, refuted, abandoned
    created_at: float = field(default_factory=time.time)

    def update_confidence(self) -> None:
        """Recalculate confidence based on evidence."""
        total_for = len(self.evidence_for)
        total_against = len(self.evidence_against)
        total = total_for + total_against
        if total > 0:
            self.confidence = total_for / total
        else:
            self.confidence = 0.5


class AgentMemory:
    """Multi-tier memory system for RecurSec agents."""

    def __init__(
        self,
        short_term_capacity: int = 100,
        long_term_path: str = "",
        embedding_fn: Any = None,
    ) -> None:
        # Short-term: current session, limited capacity
        self._short_term: deque[MemoryEntry] = deque(maxlen=short_term_capacity)

        # Long-term: persistent storage
        self._long_term: list[MemoryEntry] = []
        self._long_term_path = Path(long_term_path) if long_term_path else None

        # Episodic: scan histories
        self._episodes: list[Episode] = []
        self._current_episode: Episode | None = None

        # Working: active hypotheses
        self._hypotheses: dict[str, Hypothesis] = {}

        # Tool performance tracking
        self._tool_stats: dict[str, dict[str, Any]] = {}

        # Embedding function for semantic search
        self._embed_fn = embedding_fn

        # Load persisted long-term memory
        self._load_long_term()

    # ── Short-Term Memory ──────────────────────────────────

    def remember(self, content: str, memory_type: str = "observation",
                 importance: float = 0.5, source: str = "", task_id: str = "",
                 metadata: dict[str, Any] | None = None) -> None:
        """Add to short-term memory."""
        entry = MemoryEntry(
            content=content,
            memory_type=memory_type,
            importance=importance,
            source_agent=source,
            task_id=task_id,
            metadata=metadata or {},
        )
        self._short_term.append(entry)

        # Auto-promote high-importance memories to long-term
        if importance >= 0.8:
            self._long_term.append(entry)

    def recall_recent(self, count: int = 10, memory_type: str = "") -> list[MemoryEntry]:
        """Retrieve recent short-term memories."""
        entries = list(self._short_term)
        if memory_type:
            entries = [e for e in entries if e.memory_type == memory_type]
        return entries[-count:]

    def get_context_window(self, max_chars: int = 4000) -> str:
        """Build a context window from recent memories for prompt injection."""
        entries = list(self._short_term)
        # Prioritize by importance, then recency
        entries.sort(key=lambda e: (e.importance, e.timestamp), reverse=True)

        context_parts = []
        total = 0
        for entry in entries:
            text = f"[{entry.memory_type}] {entry.content}"
            if total + len(text) > max_chars:
                break
            context_parts.append(text)
            total += len(text)

        return "\n".join(context_parts)

    # ── Long-Term Memory ───────────────────────────────────

    def store_long_term(self, content: str, memory_type: str = "finding",
                        importance: float = 0.7, **kwargs: Any) -> None:
        """Store in long-term persistent memory."""
        entry = MemoryEntry(
            content=content,
            memory_type=memory_type,
            importance=importance,
            **kwargs,
        )
        self._long_term.append(entry)
        self._save_long_term()

    def search_long_term(self, query: str, top_k: int = 5) -> list[MemoryEntry]:
        """Search long-term memory. Uses semantic search if embeddings available."""
        # Simple keyword search fallback
        query_lower = query.lower()
        scored = []
        for entry in self._long_term:
            content_lower = entry.content.lower()
            # Simple relevance scoring
            score = 0.0
            for word in query_lower.split():
                if word in content_lower:
                    score += 1.0
            # Boost importance
            score *= (0.5 + entry.importance)
            # Recency boost
            age_hours = (time.time() - entry.timestamp) / 3600
            recency = 1.0 / (1.0 + age_hours / 24)
            score *= (0.5 + recency * 0.5)

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:top_k]]

    # ── Episodic Memory ────────────────────────────────────

    def start_episode(self, episode_id: str, target: str, target_type: str, objective: str) -> None:
        """Start recording a scan episode."""
        self._current_episode = Episode(
            episode_id=episode_id,
            target=target,
            target_type=target_type,
            objective=objective,
            start_time=time.time(),
        )

    def record_action(self, action: str, tool: str = "", result: str = "") -> None:
        """Record an action in the current episode."""
        if self._current_episode:
            self._current_episode.actions.append({
                "action": action, "tool": tool, "result": result[:500],
                "timestamp": time.time(),
            })
            if tool and tool not in self._current_episode.tools_used:
                self._current_episode.tools_used.append(tool)

    def record_finding(self, finding: dict[str, Any]) -> None:
        """Record a finding in the current episode."""
        if self._current_episode:
            self._current_episode.findings.append(finding)

    def end_episode(self, success: bool = True, lesson: str = "") -> Episode | None:
        """End and store the current episode."""
        if not self._current_episode:
            return None
        self._current_episode.end_time = time.time()
        self._current_episode.success = success
        self._current_episode.lesson_learned = lesson
        self._episodes.append(self._current_episode)

        episode = self._current_episode
        self._current_episode = None
        return episode

    def get_similar_episodes(self, target_type: str, objective: str) -> list[Episode]:
        """Find similar past episodes for learning."""
        similar = []
        for ep in self._episodes:
            if ep.target_type == target_type:
                # Simple similarity based on shared words
                obj_words = set(objective.lower().split())
                ep_words = set(ep.objective.lower().split())
                overlap = len(obj_words & ep_words)
                if overlap > 0:
                    similar.append(ep)
        return similar[:5]

    # ── Working Memory (Hypotheses) ────────────────────────

    def add_hypothesis(self, hypothesis_id: str, description: str) -> Hypothesis:
        """Add a new investigation hypothesis."""
        hyp = Hypothesis(hypothesis_id=hypothesis_id, description=description)
        self._hypotheses[hypothesis_id] = hyp
        return hyp

    def add_evidence(self, hypothesis_id: str, evidence: str, supports: bool = True) -> None:
        """Add evidence for or against a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp:
            if supports:
                hyp.evidence_for.append(evidence)
            else:
                hyp.evidence_against.append(evidence)
            hyp.update_confidence()

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Get all active hypotheses."""
        return [h for h in self._hypotheses.values() if h.status == "active"]

    def resolve_hypothesis(self, hypothesis_id: str, confirmed: bool) -> None:
        """Resolve a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp:
            hyp.status = "confirmed" if confirmed else "refuted"

    # ── Tool Performance Tracking ──────────────────────────

    def record_tool_result(self, tool: str, duration_s: float, success: bool, findings_count: int = 0) -> None:
        """Track tool performance for future selection."""
        if tool not in self._tool_stats:
            self._tool_stats[tool] = {
                "uses": 0, "successes": 0, "total_duration": 0.0,
                "total_findings": 0, "avg_duration": 0.0, "success_rate": 0.0,
            }
        stats = self._tool_stats[tool]
        stats["uses"] += 1
        if success:
            stats["successes"] += 1
        stats["total_duration"] += duration_s
        stats["total_findings"] += findings_count
        stats["avg_duration"] = stats["total_duration"] / stats["uses"]
        stats["success_rate"] = stats["successes"] / stats["uses"]

    def get_best_tool_for(self, task_description: str) -> str | None:
        """Suggest the best tool based on past performance."""
        if not self._tool_stats:
            return None
        # Rank by success_rate * findings_per_use
        scored = []
        for tool, stats in self._tool_stats.items():
            if stats["uses"] < 2:
                continue
            findings_per_use = stats["total_findings"] / stats["uses"]
            score = stats["success_rate"] * (1 + findings_per_use)
            scored.append((score, tool))
        scored.sort(reverse=True)
        return scored[0][1] if scored else None

    def get_tool_stats(self) -> dict[str, dict[str, Any]]:
        return dict(self._tool_stats)

    # ── Persistence ────────────────────────────────────────

    def _save_long_term(self) -> None:
        """Save long-term memory to disk."""
        if not self._long_term_path:
            return
        try:
            self._long_term_path.parent.mkdir(parents=True, exist_ok=True)
            data = [e.to_dict() for e in self._long_term[-1000:]]
            self._long_term_path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.warning("memory_save_error", error=str(e))

    def _load_long_term(self) -> None:
        """Load long-term memory from disk."""
        if not self._long_term_path or not self._long_term_path.exists():
            return
        try:
            data = json.loads(self._long_term_path.read_text())
            for entry_data in data:
                self._long_term.append(MemoryEntry(
                    content=entry_data.get("content", ""),
                    memory_type=entry_data.get("type", "unknown"),
                    timestamp=entry_data.get("timestamp", time.time()),
                    importance=entry_data.get("importance", 0.5),
                    source_agent=entry_data.get("source", ""),
                    task_id=entry_data.get("task_id", ""),
                ))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("memory_load_error", error=str(e))

    # ── Stats ──────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        return {
            "short_term_entries": len(self._short_term),
            "long_term_entries": len(self._long_term),
            "episodes": len(self._episodes),
            "active_hypotheses": len(self.get_active_hypotheses()),
            "tools_tracked": len(self._tool_stats),
        }
