"""Context window manager — multi-model context optimization.

Implements:
1. Context size tracking per model
2. Priority-based context packing
3. Sliding window for long conversations
4. Context compression/summarization triggers
5. Multi-model context adaptation
6. Token counting estimation
7. Context overflow prevention
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextPriority(str, Enum):
    CRITICAL = "critical"     # System prompt, current task
    HIGH = "high"             # Recent findings, active hypotheses
    MEDIUM = "medium"         # Past tool outputs, knowledge base
    LOW = "low"               # History, old findings
    EPHEMERAL = "ephemeral"   # Single-use context


class ContextItemType(str, Enum):
    SYSTEM_PROMPT = "system_prompt"
    TASK_CONTEXT = "task_context"
    TOOL_OUTPUT = "tool_output"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    KNOWLEDGE = "knowledge"
    EXPERIENCE = "experience"
    REASONING = "reasoning"
    CONVERSATION = "conversation"


@dataclass
class ContextItem:
    """An item in the context window."""
    item_id: str = ""
    item_type: ContextItemType = ContextItemType.CONVERSATION
    priority: ContextPriority = ContextPriority.MEDIUM
    content: str = ""
    token_estimate: int = 0
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 0
    compressible: bool = True

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    @property
    def priority_score(self) -> float:
        base = {
            ContextPriority.CRITICAL: 1.0,
            ContextPriority.HIGH: 0.75,
            ContextPriority.MEDIUM: 0.5,
            ContextPriority.LOW: 0.25,
            ContextPriority.EPHEMERAL: 0.1,
        }.get(self.priority, 0.5)
        # Recency boost
        recency = 1.0 / (1.0 + self.age_s / 3600)
        return base * 0.7 + recency * 0.3

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id[:10],
            "type": self.item_type.value,
            "priority": self.priority.value,
            "tokens": self.token_estimate,
        }


# ── Model context sizes ─────────────────────────────────────

MODEL_CONTEXT_SIZES: dict[str, int] = {
    "whiterabbitneo-7b": 8192,
    "qwen-coder-14b": 32768,
    "qwen-coder-7b": 32768,
    "deepseek-r1-7b": 32768,
    "deepseek-math-7b": 8192,
    "hermes-14b": 8192,
    "llama-3.1-8b": 131072,
    "dolphin-8b": 8192,
    "mistral-7b": 32768,
    "codellama-13b": 16384,
    "codellama-7b": 16384,
    "yi-9b-200k": 200000,
    "phi-3.5-mini": 128000,
    "nomic-embed": 8192,
    "llama-guard": 8192,
    "functiongemma": 8192,
}

DEFAULT_CONTEXT_SIZE = 8192
CONTEXT_RESERVE = 0.15  # Reserve 15% for response


def estimate_tokens(text: str) -> int:
    """Estimate token count from text."""
    return max(1, len(text) // 4)


class ContextWindowManager:
    """Manages context windows for multiple models.

    Packs context items by priority to fit
    within model-specific context windows,
    handles overflow, and triggers compression.
    """

    def __init__(self) -> None:
        self._items: dict[str, ContextItem] = {}
        self._counter = 0
        self._log = logger.bind(component="context_window")

    def add(
        self,
        content: str,
        item_type: ContextItemType = ContextItemType.CONVERSATION,
        priority: ContextPriority = ContextPriority.MEDIUM,
        compressible: bool = True,
    ) -> ContextItem:
        """Add an item to the context pool."""
        self._counter += 1
        item = ContextItem(
            item_id=f"ctx-{self._counter}",
            item_type=item_type,
            priority=priority,
            content=content,
            token_estimate=estimate_tokens(content),
            compressible=compressible,
        )
        self._items[item.item_id] = item
        return item

    def pack(
        self,
        model_id: str,
        max_tokens: int = 0,
        required_types: list[ContextItemType] | None = None,
    ) -> list[ContextItem]:
        """Pack context items to fit the model's window."""
        if not max_tokens:
            max_tokens = MODEL_CONTEXT_SIZES.get(model_id, DEFAULT_CONTEXT_SIZE)

        # Reserve space for response
        available = int(max_tokens * (1 - CONTEXT_RESERVE))

        # Sort by priority score
        sorted_items = sorted(
            self._items.values(),
            key=lambda i: i.priority_score,
            reverse=True,
        )

        packed: list[ContextItem] = []
        used_tokens = 0

        # First pass: required types
        if required_types:
            for item in sorted_items:
                if item.item_type in required_types:
                    if used_tokens + item.token_estimate <= available:
                        packed.append(item)
                        used_tokens += item.token_estimate
                        item.accessed_at = time.time()
                        item.access_count += 1

        # Second pass: everything else by priority
        packed_ids = {i.item_id for i in packed}
        for item in sorted_items:
            if item.item_id in packed_ids:
                continue
            if used_tokens + item.token_estimate <= available:
                packed.append(item)
                used_tokens += item.token_estimate
                item.accessed_at = time.time()
                item.access_count += 1
            elif item.compressible and item.token_estimate > 100:
                # Try to fit a compressed version
                compressed_est = item.token_estimate // 3
                if used_tokens + compressed_est <= available:
                    compressed = ContextItem(
                        item_id=item.item_id + "-c",
                        item_type=item.item_type,
                        priority=item.priority,
                        content=item.content[:compressed_est * 4],
                        token_estimate=compressed_est,
                        compressible=False,
                    )
                    packed.append(compressed)
                    used_tokens += compressed_est

        return packed

    def build_context_string(
        self,
        model_id: str,
        max_tokens: int = 0,
    ) -> str:
        """Build a single context string for a model."""
        packed = self.pack(model_id, max_tokens)

        parts: list[str] = []
        for item in packed:
            parts.append(item.content)

        return "\n\n".join(parts)

    def get_utilization(self, model_id: str) -> dict[str, Any]:
        """Get context utilization stats for a model."""
        max_tokens = MODEL_CONTEXT_SIZES.get(model_id, DEFAULT_CONTEXT_SIZE)
        total_tokens = sum(i.token_estimate for i in self._items.values())
        packed = self.pack(model_id)
        packed_tokens = sum(i.token_estimate for i in packed)

        return {
            "model": model_id[:15],
            "context_size": max_tokens,
            "total_items": len(self._items),
            "total_tokens": total_tokens,
            "packed_items": len(packed),
            "packed_tokens": packed_tokens,
            "utilization": round(packed_tokens / max_tokens, 2) if max_tokens else 0,
            "overflow": total_tokens > max_tokens,
        }

    def should_compress(self, model_id: str) -> bool:
        """Check if context needs compression."""
        max_tokens = MODEL_CONTEXT_SIZES.get(model_id, DEFAULT_CONTEXT_SIZE)
        total = sum(i.token_estimate for i in self._items.values())
        return total > max_tokens * 0.8

    def evict_low_priority(self, keep_count: int = 20) -> int:
        """Evict lowest-priority items."""
        if len(self._items) <= keep_count:
            return 0

        sorted_items = sorted(
            self._items.values(),
            key=lambda i: i.priority_score,
        )
        to_remove = len(self._items) - keep_count
        removed = 0

        for item in sorted_items[:to_remove]:
            if item.priority != ContextPriority.CRITICAL:
                del self._items[item.item_id]
                removed += 1

        return removed

    def build_context_prompt(self, model_id: str) -> str:
        """Build context management info for LLM."""
        util = self.get_utilization(model_id)
        lines = [
            f"## Context Window: {model_id[:15]}",
            f"Size: {util['context_size']} tokens",
            f"Used: {util['packed_tokens']} ({util['utilization']:.0%})",
        ]
        if util.get("overflow"):
            lines.append("WARNING: Context overflow — some items excluded")
        if self.should_compress(model_id):
            lines.append("Note: Context compression recommended")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        priority_counts: dict[str, int] = {}
        for item in self._items.values():
            type_counts[item.item_type.value] = type_counts.get(item.item_type.value, 0) + 1
            priority_counts[item.priority.value] = priority_counts.get(item.priority.value, 0) + 1

        return {
            "total_items": len(self._items),
            "total_tokens": sum(i.token_estimate for i in self._items.values()),
            "by_type": type_counts,
            "by_priority": priority_counts,
        }
