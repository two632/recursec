"""Context window manager — manages limited context across agent turns.

Implements:
1. Context budget allocation by priority
2. Message summarization for older context
3. Important information pinning
4. Context compression strategies
5. Sliding window with importance weighting
6. Context retrieval from memory
7. Dynamic context sizing per model
8. Multi-turn conversation tracking
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextPriority(str, Enum):
    CRITICAL = "critical"     # Always include (system prompt, target)
    HIGH = "high"             # Important (recent findings, decisions)
    MEDIUM = "medium"         # Useful (tool outputs, analysis)
    LOW = "low"               # Background (old results)
    EPHEMERAL = "ephemeral"   # Can be dropped first


@dataclass
class ContextItem:
    """An item in the context window."""
    item_id: str = ""
    content: str = ""
    priority: ContextPriority = ContextPriority.MEDIUM
    estimated_tokens: int = 0
    pinned: bool = False
    source: str = ""              # Where this came from
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "priority": self.priority.value,
            "tokens": self.estimated_tokens,
            "pinned": self.pinned,
            "source": self.source[:15],
        }


@dataclass
class ContextWindow:
    """A managed context window for a model."""
    window_id: str = ""
    model_id: str = ""
    max_tokens: int = 4096
    reserved_tokens: int = 500     # Reserved for response
    items: list[ContextItem] = field(default_factory=list)

    @property
    def used_tokens(self) -> int:
        return sum(item.estimated_tokens for item in self.items)

    @property
    def available_tokens(self) -> int:
        return max(0, self.max_tokens - self.reserved_tokens - self.used_tokens)

    @property
    def utilization(self) -> float:
        usable = self.max_tokens - self.reserved_tokens
        if usable <= 0:
            return 1.0
        return self.used_tokens / usable

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.window_id,
            "model": self.model_id[:15],
            "max": self.max_tokens,
            "used": self.used_tokens,
            "available": self.available_tokens,
            "items": len(self.items),
            "util": round(self.utilization, 2),
        }


@dataclass
class ConversationTurn:
    """A turn in the conversation."""
    role: str = ""        # system, user, assistant
    content: str = ""
    tokens: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "tokens": self.tokens,
        }


# ── Token Estimation ──────────────────────────────────────────

CHARS_PER_TOKEN = 4  # Rough estimate

# ── Priority Weights ──────────────────────────────────────────

PRIORITY_RETENTION: dict[ContextPriority, float] = {
    ContextPriority.CRITICAL: 1.0,     # Always keep
    ContextPriority.HIGH: 0.9,
    ContextPriority.MEDIUM: 0.6,
    ContextPriority.LOW: 0.3,
    ContextPriority.EPHEMERAL: 0.1,
}


class ContextWindowManager:
    """Manages limited context across agent turns.

    Ensures the most important information fits within
    model context limits through prioritization and compression.
    """

    def __init__(self) -> None:
        self._windows: dict[str, ContextWindow] = {}
        self._conversations: dict[str, list[ConversationTurn]] = defaultdict(list)
        self._item_counter = 0
        self._window_counter = 0
        self._log = logger.bind(component="context_window")

    def create_window(
        self,
        model_id: str,
        max_tokens: int = 4096,
        reserved_tokens: int = 500,
    ) -> ContextWindow:
        """Create a new context window."""
        self._window_counter += 1
        window = ContextWindow(
            window_id=f"cw-{self._window_counter}",
            model_id=model_id,
            max_tokens=max_tokens,
            reserved_tokens=reserved_tokens,
        )
        self._windows[window.window_id] = window
        return window

    def add_item(
        self,
        window_id: str,
        content: str,
        priority: ContextPriority = ContextPriority.MEDIUM,
        source: str = "",
        pinned: bool = False,
    ) -> ContextItem | None:
        """Add an item to a context window."""
        window = self._windows.get(window_id)
        if not window:
            return None

        self._item_counter += 1
        estimated_tokens = len(content) // CHARS_PER_TOKEN + 1

        item = ContextItem(
            item_id=f"ci-{self._item_counter}",
            content=content,
            priority=priority,
            estimated_tokens=estimated_tokens,
            pinned=pinned,
            source=source,
        )

        # Check if it fits
        if estimated_tokens > window.available_tokens:
            # Try to make room
            freed = self._evict(window, estimated_tokens - window.available_tokens)
            if freed < estimated_tokens - window.available_tokens:
                # Truncate content
                available_chars = window.available_tokens * CHARS_PER_TOKEN
                item.content = content[:available_chars]
                item.estimated_tokens = window.available_tokens

        window.items.append(item)
        return item

    def _evict(self, window: ContextWindow, tokens_needed: int) -> int:
        """Evict low-priority items to make room."""
        freed = 0

        # Sort by eviction priority (ephemeral first, then low, etc.)
        candidates = [
            item for item in window.items
            if not item.pinned
        ]
        candidates.sort(key=lambda x: (
            PRIORITY_RETENTION.get(x.priority, 0.5),
            x.accessed_at,
        ))

        to_remove = []
        for item in candidates:
            if freed >= tokens_needed:
                break
            to_remove.append(item.item_id)
            freed += item.estimated_tokens

        window.items = [
            item for item in window.items
            if item.item_id not in set(to_remove)
        ]

        return freed

    def pin_item(self, window_id: str, item_id: str) -> None:
        """Pin an item (prevent eviction)."""
        window = self._windows.get(window_id)
        if not window:
            return
        for item in window.items:
            if item.item_id == item_id:
                item.pinned = True
                break

    def add_turn(
        self,
        conversation_id: str,
        role: str,
        content: str,
    ) -> ConversationTurn:
        """Add a conversation turn."""
        tokens = len(content) // CHARS_PER_TOKEN + 1
        turn = ConversationTurn(
            role=role,
            content=content,
            tokens=tokens,
        )
        self._conversations[conversation_id].append(turn)

        # Keep last 50 turns
        if len(self._conversations[conversation_id]) > 50:
            self._conversations[conversation_id] = \
                self._conversations[conversation_id][-50:]

        return turn

    def build_messages(
        self,
        window_id: str,
        conversation_id: str = "",
        max_turns: int = 10,
    ) -> list[dict[str, str]]:
        """Build messages for LLM from context window and conversation."""
        window = self._windows.get(window_id)
        if not window:
            return []

        messages = []

        # System message from critical items
        system_parts = []
        for item in window.items:
            if item.priority == ContextPriority.CRITICAL:
                system_parts.append(item.content)

        if system_parts:
            messages.append({
                "role": "system",
                "content": "\n\n".join(system_parts),
            })

        # Context from high/medium items
        context_parts = []
        for item in window.items:
            if item.priority in (ContextPriority.HIGH, ContextPriority.MEDIUM):
                context_parts.append(f"[{item.source}] {item.content}")

        if context_parts:
            messages.append({
                "role": "user",
                "content": "Context:\n" + "\n\n".join(context_parts),
            })

        # Conversation turns
        turns = self._conversations.get(conversation_id, [])
        for turn in turns[-max_turns:]:
            messages.append({
                "role": turn.role,
                "content": turn.content,
            })

        return messages

    def summarize_old_items(
        self,
        window_id: str,
        keep_recent: int = 5,
    ) -> str:
        """Summarize old context items into a condensed form."""
        window = self._windows.get(window_id)
        if not window:
            return ""

        old_items = [
            item for item in window.items[:-keep_recent]
            if not item.pinned and item.priority != ContextPriority.CRITICAL
        ]

        if not old_items:
            return ""

        # Create brief summary
        summary_parts = []
        for item in old_items:
            brief = item.content[:100].replace("\n", " ")
            summary_parts.append(f"- [{item.source}] {brief}")

        summary = "Previous context summary:\n" + "\n".join(summary_parts)

        # Replace old items with summary
        old_ids = {item.item_id for item in old_items}
        window.items = [
            item for item in window.items
            if item.item_id not in old_ids
        ]

        # Add summary as a single item
        self.add_item(window_id, summary, ContextPriority.LOW, source="summary")

        return summary

    def get_stats(self) -> dict[str, Any]:
        return {
            "windows": len(self._windows),
            "conversations": len(self._conversations),
            "total_items": sum(len(w.items) for w in self._windows.values()),
        }
