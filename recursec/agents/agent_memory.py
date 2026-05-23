"""Agent memory manager — episodic, semantic, and working memory.

Implements:
1. Working memory (current task context, limited capacity)
2. Episodic memory (past experiences, indexed by similarity)
3. Semantic memory (facts, relationships, knowledge)
4. Memory consolidation (working → episodic → semantic)
5. Retrieval with relevance scoring
6. Memory decay and forgetting
7. Memory prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    WORKING = "working"        # Current task context
    EPISODIC = "episodic"      # Past experiences
    SEMANTIC = "semantic"      # Facts and knowledge


class MemoryImportance(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class MemoryItem:
    """A single memory item."""
    memory_id: str = ""
    memory_type: MemoryType = MemoryType.WORKING
    importance: MemoryImportance = MemoryImportance.MEDIUM
    content: str = ""
    context: str = ""          # What was happening when this was stored
    tags: list[str] = field(default_factory=list)
    source: str = ""           # Agent/tool that created this
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    decay_rate: float = 0.01   # How fast this memory fades

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    @property
    def relevance_score(self) -> float:
        """Calculate relevance based on importance, recency, access."""
        imp_scores = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
        base = imp_scores.get(self.importance.value, 0.4)

        # Recency boost (decays over hours)
        hours = self.age_s / 3600
        recency = max(0.0, 1.0 - (hours * self.decay_rate))

        # Access frequency boost
        access_boost = min(0.3, self.access_count * 0.05)

        return min(1.0, base * recency + access_boost)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id[:10],
            "type": self.memory_type.value[:4],
            "importance": self.importance.value[:4],
            "content": self.content[:25],
            "relevance": round(self.relevance_score, 2),
            "accesses": self.access_count,
        }


class AgentMemory:
    """Multi-tier memory system for agents.

    Manages working memory (limited, current task),
    episodic memory (past experiences), and semantic
    memory (facts/knowledge). Supports consolidation,
    retrieval, and decay.
    """

    def __init__(
        self,
        working_capacity: int = 10,
        episodic_capacity: int = 500,
        semantic_capacity: int = 200,
    ) -> None:
        self._working: dict[str, MemoryItem] = {}
        self._episodic: dict[str, MemoryItem] = {}
        self._semantic: dict[str, MemoryItem] = {}
        self._working_cap = working_capacity
        self._episodic_cap = episodic_capacity
        self._semantic_cap = semantic_capacity
        self._counter = 0
        self._log = logger.bind(component="agent_memory")

    def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.WORKING,
        importance: MemoryImportance = MemoryImportance.MEDIUM,
        context: str = "",
        tags: list[str] | None = None,
        source: str = "",
    ) -> MemoryItem:
        """Store a memory item."""
        self._counter += 1
        item = MemoryItem(
            memory_id=f"mem-{self._counter}",
            memory_type=memory_type,
            importance=importance,
            content=content,
            context=context,
            tags=tags or [],
            source=source,
        )

        store = self._get_store(memory_type)
        cap = self._get_capacity(memory_type)

        # Evict lowest relevance if over capacity
        while len(store) >= cap:
            lowest = min(store.values(), key=lambda m: m.relevance_score)
            del store[lowest.memory_id]

        store[item.memory_id] = item
        return item

    def recall(
        self,
        query_tags: list[str] | None = None,
        memory_type: MemoryType | None = None,
        max_items: int = 5,
        min_relevance: float = 0.0,
    ) -> list[MemoryItem]:
        """Recall memories matching criteria."""
        candidates: list[MemoryItem] = []

        stores = (
            [self._get_store(memory_type)]
            if memory_type
            else [self._working, self._episodic, self._semantic]
        )

        for store in stores:
            for item in store.values():
                if item.relevance_score < min_relevance:
                    continue
                if query_tags:
                    tag_overlap = len(set(query_tags) & set(item.tags))
                    if tag_overlap == 0:
                        continue
                candidates.append(item)

        # Sort by relevance
        candidates.sort(key=lambda m: m.relevance_score, reverse=True)

        # Update access counts
        results = candidates[:max_items]
        for item in results:
            item.access_count += 1
            item.last_accessed = time.time()

        return results

    def consolidate(self) -> int:
        """Consolidate working memory → episodic memory.

        Returns number of items consolidated.
        """
        consolidated = 0
        to_remove: list[str] = []

        for mid, item in self._working.items():
            # Only consolidate if item has been accessed and is important
            if item.access_count >= 2 or item.importance.value in ("critical", "high"):
                # Move to episodic
                new_item = MemoryItem(
                    memory_id=item.memory_id,
                    memory_type=MemoryType.EPISODIC,
                    importance=item.importance,
                    content=item.content,
                    context=item.context,
                    tags=item.tags,
                    source=item.source,
                    access_count=item.access_count,
                    created_at=item.created_at,
                )

                while len(self._episodic) >= self._episodic_cap:
                    lowest = min(self._episodic.values(), key=lambda m: m.relevance_score)
                    del self._episodic[lowest.memory_id]

                self._episodic[new_item.memory_id] = new_item
                to_remove.append(mid)
                consolidated += 1

        for mid in to_remove:
            del self._working[mid]

        return consolidated

    def generalize(self) -> int:
        """Generalize episodic → semantic memory.

        Extracts common patterns from episodic memories
        and stores as semantic facts.
        Returns number of facts created.
        """
        # Group episodic memories by tags
        tag_groups: dict[str, list[MemoryItem]] = {}
        for item in self._episodic.values():
            for tag in item.tags:
                tag_groups.setdefault(tag, []).append(item)

        facts_created = 0
        for tag, items in tag_groups.items():
            if len(items) < 3:  # Need multiple experiences to generalize
                continue

            # Create semantic summary
            summary = f"Pattern ({tag}): observed {len(items)} times"
            self.store(
                content=summary,
                memory_type=MemoryType.SEMANTIC,
                importance=MemoryImportance.HIGH,
                tags=[tag, "generalized"],
                source="consolidation",
            )
            facts_created += 1

        return facts_created

    def clear_working(self) -> None:
        """Clear working memory."""
        self._working.clear()

    def build_memory_prompt(
        self,
        task_tags: list[str] | None = None,
        max_items: int = 8,
    ) -> str:
        """Build memory context for LLM."""
        lines = ["## Agent Memory\n"]

        lines.append(
            f"Working: {len(self._working)}/{self._working_cap} | "
            f"Episodic: {len(self._episodic)}/{self._episodic_cap} | "
            f"Semantic: {len(self._semantic)}/{self._semantic_cap}"
        )

        # Working memory (always include)
        if self._working:
            lines.append("\nWorking memory:")
            for item in sorted(
                self._working.values(),
                key=lambda m: m.relevance_score,
                reverse=True,
            )[:max_items]:
                lines.append(f"  [{item.importance.value[0].upper()}] {item.content[:35]}")

        # Relevant episodic memories
        if task_tags:
            relevant = self.recall(
                query_tags=task_tags,
                memory_type=MemoryType.EPISODIC,
                max_items=3,
            )
            if relevant:
                lines.append("\nRelevant past experiences:")
                for item in relevant:
                    lines.append(f"  {item.content[:35]} (rel={item.relevance_score:.0%})")

        # Semantic facts
        if self._semantic:
            lines.append(f"\nKnown facts: {len(self._semantic)}")
            for item in list(self._semantic.values())[:3]:
                lines.append(f"  {item.content[:35]}")

        return "\n".join(lines)

    def _get_store(self, memory_type: MemoryType) -> dict[str, MemoryItem]:
        """Get the store for a memory type."""
        if memory_type == MemoryType.WORKING:
            return self._working
        elif memory_type == MemoryType.EPISODIC:
            return self._episodic
        else:
            return self._semantic

    def _get_capacity(self, memory_type: MemoryType) -> int:
        """Get the capacity for a memory type."""
        if memory_type == MemoryType.WORKING:
            return self._working_cap
        elif memory_type == MemoryType.EPISODIC:
            return self._episodic_cap
        else:
            return self._semantic_cap

    def get_stats(self) -> dict[str, Any]:
        return {
            "working": len(self._working),
            "episodic": len(self._episodic),
            "semantic": len(self._semantic),
            "total": len(self._working) + len(self._episodic) + len(self._semantic),
        }
