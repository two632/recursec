"""Attention mechanism — dynamic focus allocation across findings, targets, and tasks.

Implements:
1. Importance-weighted attention scoring
2. Attention decay over time
3. Surprise-based attention boost
4. Multi-head attention (security, novelty, urgency)
5. Attention budget management
6. Focus switching with context cost
7. Attention history for learning
8. Salience map generation
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AttentionHead(str, Enum):
    SECURITY = "security"       # How critical is the finding?
    NOVELTY = "novelty"         # How new/unexpected is this?
    URGENCY = "urgency"         # How time-sensitive?
    CONFIDENCE = "confidence"   # How confident are we?
    IMPACT = "impact"           # What's the potential impact?


@dataclass
class AttentionItem:
    """An item competing for attention."""
    item_id: str = ""
    item_type: str = ""          # finding, target, task, anomaly
    description: str = ""
    base_importance: float = 0.5
    # Multi-head scores
    security_score: float = 0.5
    novelty_score: float = 0.5
    urgency_score: float = 0.5
    confidence_score: float = 0.5
    impact_score: float = 0.5
    # Dynamics
    created_at: float = field(default_factory=time.time)
    last_attended_at: float = 0.0
    attention_count: int = 0
    total_time_spent_s: float = 0.0

    @property
    def attention_score(self) -> float:
        """Compute overall attention score from all heads."""
        weights = {
            AttentionHead.SECURITY: 0.30,
            AttentionHead.NOVELTY: 0.15,
            AttentionHead.URGENCY: 0.20,
            AttentionHead.CONFIDENCE: 0.15,
            AttentionHead.IMPACT: 0.20,
        }

        raw = (
            self.security_score * weights[AttentionHead.SECURITY] +
            self.novelty_score * weights[AttentionHead.NOVELTY] +
            self.urgency_score * weights[AttentionHead.URGENCY] +
            self.confidence_score * weights[AttentionHead.CONFIDENCE] +
            self.impact_score * weights[AttentionHead.IMPACT]
        )

        # Decay: items lose attention over time
        age = time.time() - self.created_at
        decay = math.exp(-age / 3600.0)  # Half-life ~1 hour

        # Novelty boost: items not recently attended get a boost
        if self.last_attended_at > 0:
            since_attended = time.time() - self.last_attended_at
            novelty_boost = min(0.3, since_attended / 600.0)
        else:
            novelty_boost = 0.3  # Never attended

        return raw * decay + novelty_boost

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "type": self.item_type,
            "desc": self.description[:40],
            "attention": round(self.attention_score, 3),
            "security": round(self.security_score, 2),
            "novelty": round(self.novelty_score, 2),
            "urgency": round(self.urgency_score, 2),
            "attended": self.attention_count,
        }


@dataclass
class FocusSwitch:
    """Record of a focus switch."""
    from_item: str = ""
    to_item: str = ""
    reason: str = ""
    cost: float = 0.0            # Context switching cost
    timestamp: float = field(default_factory=time.time)


class AttentionMechanism:
    """Dynamic focus allocation across findings, targets, and tasks.

    Uses multi-head attention with decay and surprise
    to decide what the agent should focus on next.
    """

    def __init__(
        self,
        max_items: int = 200,
        switch_cost: float = 0.1,
    ) -> None:
        self._items: dict[str, AttentionItem] = {}
        self._current_focus: str = ""
        self._switches: list[FocusSwitch] = []
        self._item_counter = 0
        self._max_items = max_items
        self._switch_cost = switch_cost
        self._log = logger.bind(component="attention")

    def add_item(
        self,
        item_type: str,
        description: str,
        security: float = 0.5,
        novelty: float = 0.5,
        urgency: float = 0.5,
        confidence: float = 0.5,
        impact: float = 0.5,
    ) -> str:
        """Add an item to the attention pool."""
        self._item_counter += 1
        item_id = f"attn-{self._item_counter}"

        item = AttentionItem(
            item_id=item_id,
            item_type=item_type,
            description=description,
            security_score=security,
            novelty_score=novelty,
            urgency_score=urgency,
            confidence_score=confidence,
            impact_score=impact,
        )

        # Evict lowest if at capacity
        if len(self._items) >= self._max_items:
            self._evict_lowest()

        self._items[item_id] = item
        return item_id

    def get_focus(self) -> AttentionItem | None:
        """Get the item that should receive focus."""
        if not self._items:
            return None

        scored = sorted(
            self._items.values(),
            key=lambda i: i.attention_score,
            reverse=True,
        )

        best = scored[0]

        # Record focus switch if changing
        if self._current_focus and self._current_focus != best.item_id:
            self._switches.append(FocusSwitch(
                from_item=self._current_focus,
                to_item=best.item_id,
                reason="higher_attention_score",
                cost=self._switch_cost,
            ))
            if len(self._switches) > 200:
                self._switches = self._switches[-200:]

        # Update tracking
        best.last_attended_at = time.time()
        best.attention_count += 1
        self._current_focus = best.item_id

        return best

    def get_top_k(self, k: int = 5) -> list[dict[str, Any]]:
        """Get top-k items by attention score."""
        scored = sorted(
            self._items.values(),
            key=lambda i: i.attention_score,
            reverse=True,
        )
        return [item.to_dict() for item in scored[:k]]

    def update_scores(
        self,
        item_id: str,
        security: float | None = None,
        novelty: float | None = None,
        urgency: float | None = None,
        confidence: float | None = None,
        impact: float | None = None,
    ) -> None:
        """Update attention scores for an item."""
        item = self._items.get(item_id)
        if not item:
            return

        if security is not None:
            item.security_score = security
        if novelty is not None:
            item.novelty_score = novelty
        if urgency is not None:
            item.urgency_score = urgency
        if confidence is not None:
            item.confidence_score = confidence
        if impact is not None:
            item.impact_score = impact

    def surprise_boost(self, item_id: str, magnitude: float = 0.3) -> None:
        """Boost attention on a surprising item."""
        item = self._items.get(item_id)
        if item:
            item.novelty_score = min(1.0, item.novelty_score + magnitude)
            item.urgency_score = min(1.0, item.urgency_score + magnitude * 0.5)

    def record_time_spent(self, item_id: str, seconds: float) -> None:
        """Record time spent on an item."""
        item = self._items.get(item_id)
        if item:
            item.total_time_spent_s += seconds

    def get_salience_map(self) -> dict[str, list[dict[str, Any]]]:
        """Generate a salience map grouped by item type."""
        groups: dict[str, list[AttentionItem]] = defaultdict(list)
        for item in self._items.values():
            groups[item.item_type].append(item)

        result = {}
        for item_type, items in groups.items():
            sorted_items = sorted(items, key=lambda i: i.attention_score, reverse=True)
            result[item_type] = [i.to_dict() for i in sorted_items[:10]]

        return result

    def _evict_lowest(self) -> None:
        """Evict the lowest-attention item."""
        if not self._items:
            return
        lowest = min(self._items.values(), key=lambda i: i.attention_score)
        del self._items[lowest.item_id]

    def get_stats(self) -> dict[str, Any]:
        return {
            "items": len(self._items),
            "current_focus": self._current_focus[:15] if self._current_focus else "",
            "switches": len(self._switches),
            "avg_score": round(
                sum(i.attention_score for i in self._items.values()) / max(1, len(self._items)), 3
            ),
        }
