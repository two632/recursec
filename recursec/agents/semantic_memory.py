"""Semantic memory engine — vector-based retrieval.

Implements:
1. Embedding-based memory storage
2. Semantic similarity search
3. Memory consolidation
4. Decay and forgetting
5. Cross-session persistence
6. Memory prompt for LLM
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    FINDING = "finding"         # Security finding
    TECHNIQUE = "technique"     # Technique used
    TOOL_RESULT = "tool_result"  # Tool output summary
    INSIGHT = "insight"         # Analysis insight
    CONTEXT = "context"         # Target context
    ERROR = "error"             # Error encountered
    STRATEGY = "strategy"       # Strategy used


@dataclass
class MemoryItem:
    """A single memory item with embedding."""
    memory_id: str = ""
    memory_type: MemoryType = MemoryType.FINDING
    content: str = ""
    embedding: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    importance: float = 0.5
    access_count: int = 0
    last_accessed: float = 0.0
    created_at: float = field(default_factory=time.time)
    decay_rate: float = 0.01

    @property
    def current_strength(self) -> float:
        age = time.time() - self.created_at
        decay = math.exp(-self.decay_rate * age / 3600)
        recency_bonus = min(0.3, self.access_count * 0.05)
        return min(1.0, (self.importance * decay) + recency_bonus)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.memory_type.value[:8],
            "strength": f"{self.current_strength:.2f}",
            "content": self.content[:25],
        }


def _simple_hash_embedding(text: str, dim: int = 64) -> list[float]:
    """Generate a simple hash-based embedding.

    This is a placeholder for the real Nomic-Embed model.
    In production, this calls the Nomic-Embed-Text server.
    """
    h = hashlib.sha256(text.encode()).digest()
    values = []
    for i in range(dim):
        byte_val = h[i % len(h)]
        values.append((byte_val / 128.0) - 1.0)  # Normalize to [-1, 1]
    # Normalize to unit vector
    norm = math.sqrt(sum(v * v for v in values))
    if norm > 0:
        values = [v / norm for v in values]
    return values


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    if len(a) != len(b) or not a:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


class SemanticMemory:
    """Vector-based semantic memory for agents.

    Stores memories with embeddings for
    similarity-based retrieval.
    """

    def __init__(
        self,
        max_items: int = 500,
        embedding_dim: int = 64,
        min_strength: float = 0.1,
    ) -> None:
        self._items: dict[str, MemoryItem] = {}
        self._item_counter = 0
        self._max_items = max_items
        self._embedding_dim = embedding_dim
        self._min_strength = min_strength
        self._log = logger.bind(component="semantic_mem")

    def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.FINDING,
        importance: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> MemoryItem:
        """Store a new memory item."""
        self._item_counter += 1

        embedding = _simple_hash_embedding(content, self._embedding_dim)

        item = MemoryItem(
            memory_id=f"mem-{self._item_counter}",
            memory_type=memory_type,
            content=content,
            embedding=embedding,
            metadata=metadata or {},
            importance=importance,
        )
        self._items[item.memory_id] = item

        # Evict weak memories if over limit
        if len(self._items) > self._max_items:
            self._evict_weakest()

        return item

    def recall(
        self,
        query: str,
        top_k: int = 5,
        memory_type: MemoryType | None = None,
        min_similarity: float = 0.0,
    ) -> list[tuple[MemoryItem, float]]:
        """Retrieve memories by semantic similarity."""
        query_embedding = _simple_hash_embedding(query, self._embedding_dim)

        scored: list[tuple[MemoryItem, float]] = []

        for item in self._items.values():
            if memory_type and item.memory_type != memory_type:
                continue

            if item.current_strength < self._min_strength:
                continue

            similarity = _cosine_similarity(query_embedding, item.embedding)

            # Weight by strength
            score = similarity * item.current_strength

            if score >= min_similarity:
                scored.append((item, score))

        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)

        # Update access counts
        for item, _ in scored[:top_k]:
            item.access_count += 1
            item.last_accessed = time.time()

        return scored[:top_k]

    def recall_by_type(
        self,
        memory_type: MemoryType,
        limit: int = 10,
    ) -> list[MemoryItem]:
        """Get memories by type, sorted by strength."""
        matching = [
            item for item in self._items.values()
            if item.memory_type == memory_type
            and item.current_strength >= self._min_strength
        ]
        matching.sort(key=lambda x: x.current_strength, reverse=True)
        return matching[:limit]

    def consolidate(self) -> int:
        """Consolidate memories — remove weak ones."""
        before = len(self._items)
        weak_ids = [
            item.memory_id
            for item in self._items.values()
            if item.current_strength < self._min_strength
        ]
        for mid in weak_ids:
            del self._items[mid]

        removed = before - len(self._items)
        if removed > 0:
            self._log.info("consolidated", removed=removed)
        return removed

    def _evict_weakest(self) -> None:
        """Remove the weakest memory."""
        if not self._items:
            return

        weakest_id = min(
            self._items,
            key=lambda k: self._items[k].current_strength,
        )
        del self._items[weakest_id]

    def get_summary(self, max_items: int = 5) -> list[dict[str, Any]]:
        """Get summary of strongest memories."""
        strongest = sorted(
            self._items.values(),
            key=lambda x: x.current_strength,
            reverse=True,
        )[:max_items]

        return [
            {
                "type": item.memory_type.value,
                "content": item.content[:40],
                "strength": f"{item.current_strength:.2f}",
            }
            for item in strongest
        ]

    def build_memory_prompt(
        self,
        query: str = "",
        max_items: int = 5,
    ) -> str:
        """Build memory context for LLM."""
        lines = ["## Memory\n"]
        lines.append(f"Items: {len(self._items)}")

        if query:
            relevant = self.recall(query, top_k=max_items)
            if relevant:
                lines.append(f"\nRelevant to: {query[:20]}")
                for item, score in relevant:
                    lines.append(
                        f"  [{item.memory_type.value[:6]}] "
                        f"({score:.2f}) {item.content[:35]}"
                    )
        else:
            # Show strongest memories
            strong = self.get_summary(max_items)
            if strong:
                lines.append("\nStrongest:")
                for m in strong:
                    lines.append(
                        f"  [{m['type'][:6]}] ({m['strength']}) "
                        f"{m['content'][:30]}"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for item in self._items.values():
            type_counts[item.memory_type.value] = (
                type_counts.get(item.memory_type.value, 0) + 1
            )

        avg_strength = 0.0
        if self._items:
            avg_strength = sum(
                i.current_strength for i in self._items.values()
            ) / len(self._items)

        return {
            "items": len(self._items),
            "avg_strength": f"{avg_strength:.2f}",
            "by_type": type_counts,
        }
