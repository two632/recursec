"""Semantic memory — vector-based knowledge retrieval.

Implements:
1. Text embedding via Nomic-Embed model
2. Cosine similarity search
3. Memory storage with metadata
4. Category-based retrieval
5. Temporal decay for relevance
6. Memory consolidation
7. Cross-assessment knowledge transfer
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    FINDING = "finding"
    TECHNIQUE = "technique"
    TOOL_RESULT = "tool_result"
    STRATEGY = "strategy"
    OBSERVATION = "observation"
    LESSON = "lesson"
    PATTERN = "pattern"


@dataclass
class MemoryEntry:
    """A memory entry with embedding."""
    memory_id: str = ""
    memory_type: MemoryType = MemoryType.OBSERVATION
    content: str = ""
    embedding: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    assessment_id: str = ""
    importance: float = 0.5
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id[:10],
            "type": self.memory_type.value,
            "content": self.content[:30],
            "importance": round(self.importance, 2),
            "accesses": self.access_count,
        }


@dataclass
class SearchResult:
    """A search result with similarity score."""
    memory: MemoryEntry = field(default_factory=MemoryEntry)
    similarity: float = 0.0
    relevance_score: float = 0.0  # Combined similarity + recency + importance

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory.memory_id[:10],
            "similarity": round(self.similarity, 3),
            "relevance": round(self.relevance_score, 3),
            "content": self.memory.content[:30],
        }


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b) or not a:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


def _simple_embed(text: str, dim: int = 128) -> list[float]:
    """Simple embedding for when Nomic model is unavailable.

    Uses character-level hashing to create a fixed-size
    embedding. NOT production quality — use Nomic-Embed
    via the LLM client for real embeddings.
    """
    embedding = [0.0] * dim
    text_lower = text.lower()

    for i, char in enumerate(text_lower):
        idx = hash(f"{char}_{i}") % dim
        embedding[idx] += 1.0

    # Normalize
    norm = math.sqrt(sum(x * x for x in embedding))
    if norm > 0:
        embedding = [x / norm for x in embedding]

    return embedding


class SemanticMemory:
    """Vector-based semantic memory system.

    Stores memories with embeddings for
    similarity-based retrieval. Uses Nomic-Embed
    for production embeddings, fallback to simple
    hashing for offline use.
    """

    def __init__(
        self,
        embed_dim: int = 128,
        max_memories: int = 10000,
        decay_rate: float = 0.001,
    ) -> None:
        self._memories: dict[str, MemoryEntry] = {}
        self._counter = 0
        self._embed_dim = embed_dim
        self._max_memories = max_memories
        self._decay_rate = decay_rate
        self._log = logger.bind(component="semantic_memory")

    def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.OBSERVATION,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        assessment_id: str = "",
        importance: float = 0.5,
        embedding: list[float] | None = None,
    ) -> MemoryEntry:
        """Store a new memory."""
        self._counter += 1
        entry = MemoryEntry(
            memory_id=f"mem-{self._counter}",
            memory_type=memory_type,
            content=content,
            embedding=embedding or _simple_embed(content, self._embed_dim),
            metadata=metadata or {},
            tags=tags or [],
            assessment_id=assessment_id,
            importance=importance,
        )
        self._memories[entry.memory_id] = entry

        # Evict least important if at capacity
        if len(self._memories) > self._max_memories:
            self._evict_least_important()

        return entry

    def search(
        self,
        query: str,
        top_k: int = 5,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        min_similarity: float = 0.1,
        query_embedding: list[float] | None = None,
    ) -> list[SearchResult]:
        """Search memories by semantic similarity."""
        q_embed = query_embedding or _simple_embed(query, self._embed_dim)
        results: list[SearchResult] = []
        now = time.time()

        for entry in self._memories.values():
            # Filter by type
            if memory_type and entry.memory_type != memory_type:
                continue

            # Filter by tags
            if tags and not any(t in entry.tags for t in tags):
                continue

            # Compute similarity
            similarity = _cosine_similarity(q_embed, entry.embedding)
            if similarity < min_similarity:
                continue

            # Compute relevance (similarity + recency + importance)
            age_hours = (now - entry.created_at) / 3600
            recency_factor = math.exp(-self._decay_rate * age_hours)

            relevance = (
                similarity * 0.5
                + recency_factor * 0.2
                + entry.importance * 0.3
            )

            results.append(SearchResult(
                memory=entry,
                similarity=similarity,
                relevance_score=relevance,
            ))

        # Sort by relevance
        results.sort(key=lambda r: r.relevance_score, reverse=True)
        results = results[:top_k]

        # Update access counts
        for result in results:
            result.memory.access_count += 1
            result.memory.last_accessed = now

        return results

    def get_by_type(
        self,
        memory_type: MemoryType,
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Get memories by type."""
        entries = [
            e for e in self._memories.values()
            if e.memory_type == memory_type
        ]
        entries.sort(key=lambda e: e.importance, reverse=True)
        return entries[:limit]

    def get_by_assessment(
        self,
        assessment_id: str,
    ) -> list[MemoryEntry]:
        """Get all memories for an assessment."""
        return [
            e for e in self._memories.values()
            if e.assessment_id == assessment_id
        ]

    def consolidate(
        self,
        min_accesses: int = 3,
    ) -> int:
        """Consolidate memories — boost frequently accessed, prune stale."""
        boosted = 0
        for entry in self._memories.values():
            if entry.access_count >= min_accesses:
                entry.importance = min(1.0, entry.importance + 0.1)
                boosted += 1
        return boosted

    def _evict_least_important(self) -> None:
        """Evict least important memory."""
        if not self._memories:
            return

        least = min(
            self._memories.values(),
            key=lambda e: e.importance * (e.access_count + 1),
        )
        del self._memories[least.memory_id]

    def build_memory_prompt(
        self,
        query: str,
        top_k: int = 3,
    ) -> str:
        """Build memory context for LLM."""
        results = self.search(query, top_k=top_k)
        if not results:
            return ""

        lines = ["## Relevant Memories\n"]
        for result in results:
            lines.append(
                f"- [{result.memory.memory_type.value}] "
                f"(relevance: {result.relevance_score:.2f}): "
                f"{result.memory.content[:100]}"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for entry in self._memories.values():
            type_counts[entry.memory_type.value] = type_counts.get(
                entry.memory_type.value, 0,
            ) + 1

        return {
            "total_memories": len(self._memories),
            "by_type": type_counts,
            "avg_importance": round(
                sum(e.importance for e in self._memories.values()) /
                max(1, len(self._memories)), 2,
            ),
        }
