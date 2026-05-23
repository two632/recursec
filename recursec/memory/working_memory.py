"""Working memory — active, attention-based memory for agent reasoning.

Models the concept of working memory from cognitive science:
- Limited capacity (configurable)
- Attention-based prioritization
- Automatic decay of irrelevant items
- Promotion of important items to long-term memory
- Integration with reasoning context

Working memory holds:
- Current goals and subgoals
- Recent observations and findings
- Active hypotheses
- Tool results being analyzed
- Intermediate reasoning results
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryItemType(str, Enum):
    GOAL = "goal"
    OBSERVATION = "observation"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    TOOL_RESULT = "tool_result"
    REASONING = "reasoning"
    CONTEXT = "context"
    PLAN = "plan"
    DECISION = "decision"


class AttentionLevel(str, Enum):
    FOCAL = "focal"          # Currently being processed
    ACTIVE = "active"        # Readily available
    PERIPHERAL = "peripheral"  # Available but not attended
    DECAYING = "decaying"    # About to be evicted


@dataclass
class WorkingMemoryItem:
    """A single item in working memory."""
    item_id: str = ""
    item_type: MemoryItemType = MemoryItemType.OBSERVATION
    content: str = ""
    importance: float = 0.5  # 0.0-1.0
    relevance: float = 0.5   # To current task
    attention: AttentionLevel = AttentionLevel.ACTIVE
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    linked_items: list[str] = field(default_factory=list)  # Related item_ids

    @property
    def priority_score(self) -> float:
        """Combined priority: importance * relevance * recency."""
        age_s = time.time() - self.last_accessed
        recency = 1.0 / (1.0 + age_s / 60.0)  # Decay over minutes
        return self.importance * self.relevance * recency * (1.0 + 0.1 * min(self.access_count, 10))

    def access(self) -> None:
        """Mark as accessed (updates recency)."""
        self.last_accessed = time.time()
        self.access_count += 1
        if self.attention == AttentionLevel.DECAYING:
            self.attention = AttentionLevel.PERIPHERAL
        elif self.attention == AttentionLevel.PERIPHERAL:
            self.attention = AttentionLevel.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id, "type": self.item_type.value,
            "content": self.content[:200], "importance": round(self.importance, 2),
            "relevance": round(self.relevance, 2),
            "attention": self.attention.value,
            "priority": round(self.priority_score, 3),
            "age_s": round(time.time() - self.created_at, 1),
        }


class WorkingMemory:
    """Attention-based working memory for agent reasoning.

    Maintains a limited-capacity buffer of currently relevant
    information, with automatic decay and promotion.
    """

    def __init__(
        self,
        capacity: int = 50,
        decay_interval_s: float = 60.0,
        min_importance_to_keep: float = 0.2,
    ) -> None:
        self._items: dict[str, WorkingMemoryItem] = {}
        self._capacity = capacity
        self._decay_interval = decay_interval_s
        self._min_importance = min_importance_to_keep
        self._evicted_items: list[WorkingMemoryItem] = []  # For promotion to LTM
        self._last_decay = time.time()
        self._log = logger.bind(component="working_memory")

    def add(
        self,
        item_id: str,
        content: str,
        item_type: MemoryItemType = MemoryItemType.OBSERVATION,
        importance: float = 0.5,
        relevance: float = 0.5,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> WorkingMemoryItem:
        """Add an item to working memory."""
        # Run decay if needed
        if time.time() - self._last_decay > self._decay_interval:
            self._decay()

        # Evict if at capacity
        if len(self._items) >= self._capacity and item_id not in self._items:
            self._evict_lowest()

        item = WorkingMemoryItem(
            item_id=item_id,
            item_type=item_type,
            content=content,
            importance=importance,
            relevance=relevance,
            tags=tags or [],
            metadata=metadata or {},
        )
        self._items[item_id] = item
        return item

    def get(self, item_id: str) -> WorkingMemoryItem | None:
        """Get an item, updating its access time."""
        item = self._items.get(item_id)
        if item:
            item.access()
        return item

    def search(
        self,
        query: str = "",
        item_type: MemoryItemType | None = None,
        tags: list[str] | None = None,
        min_importance: float = 0.0,
        limit: int = 10,
    ) -> list[WorkingMemoryItem]:
        """Search working memory."""
        results = []
        query_lower = query.lower()

        for item in self._items.values():
            if item_type and item.item_type != item_type:
                continue
            if tags and not any(t in item.tags for t in tags):
                continue
            if item.importance < min_importance:
                continue
            if query_lower and query_lower not in item.content.lower():
                continue
            results.append(item)

        results.sort(key=lambda i: -i.priority_score)
        return results[:limit]

    def get_focal_items(self) -> list[WorkingMemoryItem]:
        """Get items currently being actively processed."""
        return [
            i for i in self._items.values()
            if i.attention == AttentionLevel.FOCAL
        ]

    def focus_on(self, item_id: str) -> None:
        """Set focal attention on an item."""
        # Defocus all current focal items
        for item in self._items.values():
            if item.attention == AttentionLevel.FOCAL:
                item.attention = AttentionLevel.ACTIVE

        item = self._items.get(item_id)
        if item:
            item.attention = AttentionLevel.FOCAL
            item.access()

    def update_relevance(self, item_id: str, relevance: float) -> None:
        """Update relevance score (e.g., when task changes)."""
        item = self._items.get(item_id)
        if item:
            item.relevance = relevance

    def link_items(self, item_id_a: str, item_id_b: str) -> None:
        """Link two related items."""
        item_a = self._items.get(item_id_a)
        item_b = self._items.get(item_id_b)
        if item_a and item_b:
            if item_id_b not in item_a.linked_items:
                item_a.linked_items.append(item_id_b)
            if item_id_a not in item_b.linked_items:
                item_b.linked_items.append(item_id_a)

    def get_context_string(self, max_items: int = 20, max_chars: int = 4000) -> str:
        """Get working memory as a context string for LLM prompts."""
        items = sorted(self._items.values(), key=lambda i: -i.priority_score)[:max_items]
        lines = ["Current working memory:"]
        total_chars = 0
        for item in items:
            line = f"[{item.item_type.value}] {item.content[:200]}"
            if total_chars + len(line) > max_chars:
                break
            lines.append(line)
            total_chars += len(line)
        return "\n".join(lines)

    def get_evicted_items(self) -> list[WorkingMemoryItem]:
        """Get items that were evicted (for promotion to long-term memory)."""
        evicted = list(self._evicted_items)
        self._evicted_items.clear()
        return evicted

    def _decay(self) -> None:
        """Decay attention levels and evict stale items."""
        now = time.time()
        to_evict = []

        for item_id, item in self._items.items():
            age_s = now - item.last_accessed
            if age_s > self._decay_interval * 3:
                if item.attention == AttentionLevel.ACTIVE:
                    item.attention = AttentionLevel.PERIPHERAL
                elif item.attention == AttentionLevel.PERIPHERAL:
                    item.attention = AttentionLevel.DECAYING
                elif item.attention == AttentionLevel.DECAYING:
                    if item.importance < self._min_importance:
                        to_evict.append(item_id)

        for item_id in to_evict:
            self._evict(item_id)

        self._last_decay = now

    def _evict_lowest(self) -> None:
        """Evict the lowest priority item."""
        if not self._items:
            return
        lowest = min(self._items.values(), key=lambda i: i.priority_score)
        self._evict(lowest.item_id)

    def _evict(self, item_id: str) -> None:
        """Evict a specific item."""
        item = self._items.pop(item_id, None)
        if item:
            self._evicted_items.append(item)

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        by_attention: dict[str, int] = defaultdict(int)
        for item in self._items.values():
            by_type[item.item_type.value] += 1
            by_attention[item.attention.value] += 1
        return {
            "total_items": len(self._items),
            "capacity": self._capacity,
            "utilization": round(len(self._items) / self._capacity * 100, 1),
            "by_type": dict(by_type),
            "by_attention": dict(by_attention),
            "evicted_pending": len(self._evicted_items),
        }
