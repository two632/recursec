"""Contextual memory — manages agent working memory and context windows.

Implements:
1. Working memory (current task context)
2. Short-term memory (recent interactions)
3. Long-term memory (persistent knowledge)
4. Memory consolidation (short-term → long-term)
5. Context window management (fit within model limits)
6. Priority-based context selection
7. Memory decay (older memories fade)
8. Associative recall (retrieve related memories)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MemoryEntry:
    """A single memory entry."""
    memory_id: str = ""
    content: str = ""
    memory_type: str = "short"      # working, short, long
    importance: float = 0.5         # 0.0-1.0
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)
    source: str = ""                # Agent/tool that created this
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    @property
    def recency_score(self) -> float:
        """Score based on how recently accessed (exponential decay)."""
        age = time.time() - self.last_accessed
        half_life = 300.0  # 5 minutes
        return math.exp(-0.693 * age / half_life)

    @property
    def relevance_score(self) -> float:
        """Combined score for memory prioritization."""
        return (
            self.importance * 0.4 +
            self.recency_score * 0.3 +
            min(1.0, self.access_count / 10) * 0.2 +
            0.1  # Base score
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id, "type": self.memory_type,
            "importance": round(self.importance, 2),
            "relevance": round(self.relevance_score, 2),
            "tags": self.tags[:3],
            "content_len": len(self.content),
        }


@dataclass
class ContextWindow:
    """A context window for model input."""
    max_tokens: int = 4096
    entries: list[MemoryEntry] = field(default_factory=list)
    total_chars: int = 0

    @property
    def estimated_tokens(self) -> int:
        return self.total_chars // 4

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.estimated_tokens)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_tokens": self.max_tokens,
            "used_tokens": self.estimated_tokens,
            "entries": len(self.entries),
        }


class ContextualMemory:
    """Manages agent working memory and context windows.

    Implements hierarchical memory with automatic
    consolidation, decay, and priority-based selection.
    """

    def __init__(self) -> None:
        self._working: dict[str, MemoryEntry] = {}       # Current task
        self._short_term: dict[str, MemoryEntry] = {}     # Recent
        self._long_term: dict[str, MemoryEntry] = {}      # Persistent
        self._memory_counter = 0
        self._consolidation_threshold = 100               # Consolidate when short-term exceeds this
        self._max_short_term = 200
        self._max_long_term = 1000
        self._log = logger.bind(component="contextual_memory")

    def store(
        self,
        content: str,
        memory_type: str = "short",
        importance: float = 0.5,
        tags: list[str] | None = None,
        source: str = "",
    ) -> str:
        """Store a memory entry."""
        self._memory_counter += 1
        mid = f"mem-{self._memory_counter}"

        entry = MemoryEntry(
            memory_id=mid,
            content=content[:5000],
            memory_type=memory_type,
            importance=importance,
            tags=tags or [],
            source=source,
        )

        if memory_type == "working":
            self._working[mid] = entry
        elif memory_type == "long":
            self._long_term[mid] = entry
            self._enforce_limit(self._long_term, self._max_long_term)
        else:
            self._short_term[mid] = entry
            self._enforce_limit(self._short_term, self._max_short_term)

            if len(self._short_term) >= self._consolidation_threshold:
                self._consolidate()

        return mid

    def recall(
        self,
        query: str = "",
        memory_type: str = "",
        tags: list[str] | None = None,
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Recall memories matching criteria."""
        candidates: list[MemoryEntry] = []

        stores = []
        if memory_type in ("working", ""):
            stores.append(self._working)
        if memory_type in ("short", ""):
            stores.append(self._short_term)
        if memory_type in ("long", ""):
            stores.append(self._long_term)

        for store in stores:
            for entry in store.values():
                # Tag filter
                if tags:
                    if not set(tags) & set(entry.tags):
                        continue

                # Query filter (keyword match)
                if query:
                    query_lower = query.lower()
                    if query_lower not in entry.content.lower():
                        # Check tags
                        if not any(query_lower in t.lower() for t in entry.tags):
                            continue

                candidates.append(entry)

        # Sort by relevance
        candidates.sort(key=lambda e: e.relevance_score, reverse=True)

        # Update access counts
        for entry in candidates[:limit]:
            entry.access_count += 1
            entry.last_accessed = time.time()

        return candidates[:limit]

    def build_context(
        self,
        query: str = "",
        max_tokens: int = 4096,
        include_working: bool = True,
        include_short: bool = True,
        include_long: bool = True,
    ) -> ContextWindow:
        """Build a context window from memory."""
        window = ContextWindow(max_tokens=max_tokens)

        # Priority: working > short-term > long-term
        all_entries: list[MemoryEntry] = []

        if include_working:
            all_entries.extend(self._working.values())
        if include_short:
            all_entries.extend(self._short_term.values())
        if include_long:
            all_entries.extend(self._long_term.values())

        # Filter by query relevance if query provided
        if query:
            scored = []
            query_lower = query.lower()
            for entry in all_entries:
                # Base relevance score
                score = entry.relevance_score

                # Query match boost
                if query_lower in entry.content.lower():
                    score += 0.3

                scored.append((score, entry))

            scored.sort(key=lambda x: x[0], reverse=True)
            all_entries = [e for _, e in scored]
        else:
            all_entries.sort(key=lambda e: e.relevance_score, reverse=True)

        # Fill context window
        for entry in all_entries:
            entry_tokens = len(entry.content) // 4
            if window.total_chars // 4 + entry_tokens > max_tokens:
                # Try to fit truncated version
                remaining = (max_tokens - window.total_chars // 4) * 4
                if remaining > 100:
                    truncated = MemoryEntry(
                        memory_id=entry.memory_id,
                        content=entry.content[:remaining],
                        memory_type=entry.memory_type,
                        importance=entry.importance,
                        tags=entry.tags,
                    )
                    window.entries.append(truncated)
                    window.total_chars += remaining
                break

            window.entries.append(entry)
            window.total_chars += len(entry.content)

        return window

    def clear_working(self) -> None:
        """Clear working memory."""
        self._working.clear()

    def _consolidate(self) -> None:
        """Consolidate short-term memory into long-term."""
        # Move high-importance, frequently accessed entries to long-term
        to_consolidate = []
        for mid, entry in self._short_term.items():
            if entry.importance >= 0.7 or entry.access_count >= 3:
                to_consolidate.append(mid)

        for mid in to_consolidate:
            entry = self._short_term.pop(mid)
            entry.memory_type = "long"
            self._long_term[mid] = entry

        self._enforce_limit(self._long_term, self._max_long_term)

    def _enforce_limit(
        self,
        store: dict[str, MemoryEntry],
        max_size: int,
    ) -> None:
        """Remove lowest-relevance entries to enforce size limit."""
        if len(store) <= max_size:
            return

        sorted_entries = sorted(
            store.items(),
            key=lambda x: x[1].relevance_score,
        )

        remove_count = len(store) - max_size
        for mid, _ in sorted_entries[:remove_count]:
            del store[mid]

    def decay(self) -> None:
        """Apply time-based decay to memories."""
        for store in [self._short_term, self._long_term]:
            to_remove = []
            for mid, entry in store.items():
                # Remove entries with very low relevance
                if entry.relevance_score < 0.05:
                    to_remove.append(mid)
            for mid in to_remove:
                del store[mid]

    def get_stats(self) -> dict[str, Any]:
        return {
            "working": len(self._working),
            "short_term": len(self._short_term),
            "long_term": len(self._long_term),
            "total": len(self._working) + len(self._short_term) + len(self._long_term),
        }
