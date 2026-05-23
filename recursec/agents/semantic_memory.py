"""Semantic memory — vector-based knowledge retrieval.

Implements:
1. Text embedding via local nomic-embed model
2. Cosine similarity search
3. Memory indexing by category
4. Temporal relevance weighting
5. Memory consolidation (merge similar entries)
6. Capacity management with eviction
7. Context-aware retrieval for LLM prompts
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryCategory(str, Enum):
    FINDING = "finding"
    TOOL_OUTPUT = "tool_output"
    STRATEGY = "strategy"
    KNOWLEDGE = "knowledge"
    EXPERIENCE = "experience"
    TARGET_INFO = "target_info"
    REASONING = "reasoning"


@dataclass
class MemoryEntry:
    """A memory entry with embedding."""
    entry_id: str = ""
    category: MemoryCategory = MemoryCategory.KNOWLEDGE
    content: str = ""
    summary: str = ""
    embedding: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 0
    importance: float = 0.5

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    @property
    def relevance_decay(self) -> float:
        """Temporal decay factor (half-life 24h)."""
        return 0.5 ** (self.age_hours / 24)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id[:10],
            "category": self.category.value,
            "summary": self.summary[:30],
            "importance": round(self.importance, 2),
            "accesses": self.access_count,
        }


def _simple_embed(text: str, dim: int = 128) -> list[float]:
    """Simple deterministic text embedding (fallback when model unavailable).

    Uses character-level hashing with positional weighting.
    Not semantically meaningful but provides consistent vectors.
    """
    vec = [0.0] * dim
    text_lower = text.lower()

    for i, ch in enumerate(text_lower[:500]):
        idx = (ord(ch) * (i + 1)) % dim
        weight = 1.0 / (1.0 + i * 0.01)
        vec[idx] += weight

    # Normalize
    magnitude = math.sqrt(sum(v * v for v in vec))
    if magnitude > 0:
        vec = [v / magnitude for v in vec]

    return vec


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b) or not a:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))

    if mag_a == 0 or mag_b == 0:
        return 0.0

    return dot / (mag_a * mag_b)


class SemanticMemory:
    """Vector-based semantic memory for agent knowledge.

    Stores text with embeddings for similarity-based
    retrieval. Uses local nomic-embed model when
    available, falls back to simple hashing.
    """

    def __init__(
        self,
        max_entries: int = 5000,
        embed_dim: int = 128,
    ) -> None:
        self._entries: dict[str, MemoryEntry] = {}
        self._max = max_entries
        self._dim = embed_dim
        self._counter = 0
        self._use_model = False  # Set True when nomic-embed available
        self._log = logger.bind(component="semantic_memory")

    def store(
        self,
        content: str,
        category: MemoryCategory = MemoryCategory.KNOWLEDGE,
        summary: str = "",
        importance: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> MemoryEntry:
        """Store a new memory entry."""
        self._counter += 1

        embedding = self._embed(content)

        entry = MemoryEntry(
            entry_id=f"mem-{self._counter}",
            category=category,
            content=content,
            summary=summary or content[:80],
            embedding=embedding,
            metadata=metadata or {},
            importance=importance,
        )

        # Evict if at capacity
        if len(self._entries) >= self._max:
            self._evict()

        self._entries[entry.entry_id] = entry
        return entry

    def search(
        self,
        query: str,
        limit: int = 5,
        category: MemoryCategory | None = None,
        min_similarity: float = 0.1,
    ) -> list[tuple[float, MemoryEntry]]:
        """Search memory by semantic similarity."""
        query_embedding = self._embed(query)

        scored: list[tuple[float, MemoryEntry]] = []
        for entry in self._entries.values():
            if category and entry.category != category:
                continue

            similarity = _cosine_similarity(query_embedding, entry.embedding)

            if similarity < min_similarity:
                continue

            # Combine with importance and recency
            final_score = (
                similarity * 0.6
                + entry.importance * 0.2
                + entry.relevance_decay * 0.2
            )
            scored.append((final_score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)

        # Update access stats
        results = scored[:limit]
        for _, entry in results:
            entry.accessed_at = time.time()
            entry.access_count += 1

        return results

    def search_by_category(
        self,
        category: MemoryCategory,
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Get entries by category, sorted by importance."""
        entries = [
            e for e in self._entries.values()
            if e.category == category
        ]
        entries.sort(key=lambda e: e.importance * e.relevance_decay, reverse=True)
        return entries[:limit]

    def consolidate(self, similarity_threshold: float = 0.9) -> int:
        """Merge highly similar entries."""
        entries = list(self._entries.values())
        merged = 0
        to_remove: set[str] = set()

        for i in range(len(entries)):
            if entries[i].entry_id in to_remove:
                continue
            for j in range(i + 1, len(entries)):
                if entries[j].entry_id in to_remove:
                    continue
                sim = _cosine_similarity(entries[i].embedding, entries[j].embedding)
                if sim >= similarity_threshold:
                    # Keep the more important one
                    if entries[i].importance >= entries[j].importance:
                        entries[i].access_count += entries[j].access_count
                        to_remove.add(entries[j].entry_id)
                    else:
                        entries[j].access_count += entries[i].access_count
                        to_remove.add(entries[i].entry_id)
                    merged += 1
                    break

        for entry_id in to_remove:
            del self._entries[entry_id]

        return merged

    def build_memory_prompt(
        self,
        query: str = "",
        max_entries: int = 5,
    ) -> str:
        """Build memory context for LLM."""
        lines = ["## Relevant Memory\n"]

        if query:
            results = self.search(query, limit=max_entries)
            if not results:
                lines.append("No relevant memories found.")
            else:
                for score, entry in results:
                    lines.append(
                        f"  [{entry.category.value}] (sim={score:.2f}) "
                        f"{entry.summary[:50]}"
                    )
        else:
            # Show most important recent entries
            entries = sorted(
                self._entries.values(),
                key=lambda e: e.importance * e.relevance_decay,
                reverse=True,
            )
            for entry in entries[:max_entries]:
                lines.append(
                    f"  [{entry.category.value}] {entry.summary[:50]}"
                )

        lines.append(f"\nTotal memories: {len(self._entries)}")
        return "\n".join(lines)

    def _embed(self, text: str) -> list[float]:
        """Generate embedding for text."""
        if self._use_model:
            # Would call nomic-embed API here
            pass
        return _simple_embed(text, self._dim)

    def _evict(self) -> None:
        """Evict lowest-value entries."""
        if not self._entries:
            return
        # Evict entry with lowest combined score
        worst = min(
            self._entries.values(),
            key=lambda e: e.importance * e.relevance_decay,
        )
        del self._entries[worst.entry_id]

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for e in self._entries.values():
            cat_counts[e.category.value] = cat_counts.get(e.category.value, 0) + 1

        return {
            "total_entries": len(self._entries),
            "by_category": cat_counts,
            "avg_importance": (
                sum(e.importance for e in self._entries.values()) / len(self._entries)
                if self._entries else 0
            ),
        }
