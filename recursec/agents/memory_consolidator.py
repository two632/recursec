"""Memory consolidator — episodic to semantic memory.

Implements:
1. Episodic memory storage (recent events)
2. Semantic memory extraction (patterns/facts)
3. Importance scoring for retention
4. Memory decay and pruning
5. Working memory management
6. Memory prompt for LLM
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    EPISODIC = "episodic"      # Specific events
    SEMANTIC = "semantic"      # General knowledge
    WORKING = "working"        # Current context


class MemoryTag(str, Enum):
    FINDING = "finding"
    TOOL_RESULT = "tool_result"
    DECISION = "decision"
    ERROR = "error"
    INSIGHT = "insight"
    STRATEGY = "strategy"


@dataclass
class EpisodicMemory:
    """A specific event memory."""
    memory_id: str = ""
    content: str = ""
    tag: MemoryTag = MemoryTag.TOOL_RESULT
    source: str = ""
    importance: float = 0.5
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    @property
    def retention_score(self) -> float:
        """Score for deciding whether to keep."""
        recency = 1.0 / (1.0 + self.age_hours)
        frequency = min(1.0, self.access_count * 0.2)
        return (self.importance * 0.5 + recency * 0.3 + frequency * 0.2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id[:10],
            "tag": self.tag.value[:6],
            "importance": f"{self.importance:.1f}",
            "retention": f"{self.retention_score:.2f}",
        }


@dataclass
class SemanticMemory:
    """A general knowledge/pattern memory."""
    memory_id: str = ""
    fact: str = ""
    category: str = ""
    confidence: float = 0.7
    supporting_episodes: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id[:10],
            "fact": self.fact[:25],
            "conf": f"{self.confidence:.0%}",
            "episodes": self.supporting_episodes,
        }


@dataclass
class WorkingMemoryItem:
    """An item in working memory (active context)."""
    item_id: str = ""
    content: str = ""
    relevance: float = 1.0
    added_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content[:20],
            "relevance": f"{self.relevance:.1f}",
        }


class MemoryConsolidator:
    """Manages multi-tier memory system.

    Episodic: recent events (large capacity, decays)
    Semantic: extracted patterns (small, persistent)
    Working: current context (very small, active)
    """

    def __init__(
        self,
        max_episodic: int = 500,
        max_semantic: int = 200,
        max_working: int = 10,
    ) -> None:
        self._episodic: deque[EpisodicMemory] = deque(maxlen=max_episodic)
        self._semantic: list[SemanticMemory] = []
        self._working: list[WorkingMemoryItem] = []
        self._max_semantic = max_semantic
        self._max_working = max_working
        self._ep_counter = 0
        self._sem_counter = 0
        self._wm_counter = 0
        self._consolidation_count = 0
        self._log = logger.bind(component="memory")

    def store_episodic(
        self,
        content: str,
        tag: MemoryTag = MemoryTag.TOOL_RESULT,
        source: str = "",
        importance: float = 0.5,
    ) -> EpisodicMemory:
        """Store a new episodic memory."""
        self._ep_counter += 1

        mem = EpisodicMemory(
            memory_id=f"ep-{self._ep_counter}",
            content=content,
            tag=tag,
            source=source,
            importance=importance,
        )
        self._episodic.append(mem)
        return mem

    def store_semantic(
        self,
        fact: str,
        category: str = "",
        confidence: float = 0.7,
    ) -> SemanticMemory:
        """Store a semantic memory (extracted fact/pattern)."""
        self._sem_counter += 1

        mem = SemanticMemory(
            memory_id=f"sem-{self._sem_counter}",
            fact=fact,
            category=category,
            confidence=confidence,
        )
        self._semantic.append(mem)

        # Prune if over capacity
        if len(self._semantic) > self._max_semantic:
            self._semantic.sort(key=lambda m: m.confidence)
            self._semantic.pop(0)

        return mem

    def set_working(self, content: str, relevance: float = 1.0) -> WorkingMemoryItem:
        """Add to working memory."""
        self._wm_counter += 1

        item = WorkingMemoryItem(
            item_id=f"wm-{self._wm_counter}",
            content=content,
            relevance=relevance,
        )
        self._working.append(item)

        # Evict lowest relevance if over capacity
        if len(self._working) > self._max_working:
            self._working.sort(key=lambda w: w.relevance)
            self._working.pop(0)

        return item

    def clear_working(self) -> None:
        """Clear working memory for new context."""
        self._working.clear()

    def recall_episodic(
        self,
        tag: MemoryTag | None = None,
        source: str = "",
        min_importance: float = 0.0,
        limit: int = 10,
    ) -> list[EpisodicMemory]:
        """Recall episodic memories matching criteria."""
        results: list[EpisodicMemory] = []

        for mem in reversed(self._episodic):
            if tag and mem.tag != tag:
                continue
            if source and mem.source != source:
                continue
            if mem.importance < min_importance:
                continue

            mem.access_count += 1
            mem.last_accessed = time.time()
            results.append(mem)

            if len(results) >= limit:
                break

        return results

    def recall_semantic(
        self,
        category: str = "",
        min_confidence: float = 0.5,
        limit: int = 10,
    ) -> list[SemanticMemory]:
        """Recall semantic memories."""
        results = []
        for mem in self._semantic:
            if category and mem.category != category:
                continue
            if mem.confidence < min_confidence:
                continue
            results.append(mem)

        # Sort by confidence
        results.sort(key=lambda m: m.confidence, reverse=True)
        return results[:limit]

    def consolidate(self) -> int:
        """Consolidate episodic memories into semantic.

        Extracts patterns from episodic memories and
        creates/updates semantic memories.
        Returns number of new semantic memories created.
        """
        self._consolidation_count += 1
        new_count = 0

        # Find high-importance episodic memories
        important = [m for m in self._episodic if m.importance > 0.7]

        # Group by tag
        by_tag: dict[str, list[EpisodicMemory]] = {}
        for mem in important:
            by_tag.setdefault(mem.tag.value, []).append(mem)

        # Create semantic memories from clusters
        for tag, memories in by_tag.items():
            if len(memories) >= 2:
                # Extract common pattern
                combined = f"Pattern from {len(memories)} {tag} events"
                self.store_semantic(
                    fact=combined,
                    category=tag,
                    confidence=min(0.9, 0.5 + len(memories) * 0.1),
                )
                new_count += 1

        # Prune old low-importance episodic memories
        self._prune_episodic()

        return new_count

    def _prune_episodic(self) -> int:
        """Remove low-retention episodic memories."""
        if len(self._episodic) < 100:
            return 0

        threshold = 0.2
        to_remove = [
            m for m in self._episodic
            if m.retention_score < threshold
        ]

        for mem in to_remove:
            self._episodic.remove(mem)

        return len(to_remove)

    def build_memory_prompt(self) -> str:
        """Build memory context for LLM."""
        lines = ["## Memory\n"]

        # Working memory (highest priority)
        if self._working:
            lines.append(f"Working ({len(self._working)}):")
            for item in self._working:
                lines.append(f"  • {item.content[:50]}")

        # Recent episodic
        recent = list(self._episodic)[-5:]
        if recent:
            lines.append(f"\nRecent ({len(self._episodic)} total):")
            for mem in recent:
                lines.append(
                    f"  [{mem.tag.value[:6]}] {mem.content[:40]} "
                    f"imp={mem.importance:.1f}"
                )

        # Key semantic
        key_facts = self.recall_semantic(min_confidence=0.7, limit=5)
        if key_facts:
            lines.append(f"\nKnowledge ({len(self._semantic)} total):")
            for mem in key_facts:
                lines.append(f"  [{mem.confidence:.0%}] {mem.fact[:40]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "episodic": len(self._episodic),
            "semantic": len(self._semantic),
            "working": len(self._working),
            "consolidations": self._consolidation_count,
        }
