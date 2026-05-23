"""Context window manager — optimizes what goes into each LLM context.

Implements:
1. Context budget allocation per model (respects max tokens)
2. Priority-based content inclusion
3. Content summarization for overflow
4. Sliding window for conversation history
5. Relevance scoring for context items
6. Structured context assembly (system + knowledge + history + task)
7. Token estimation without external dependencies
8. Context compression strategies
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContentPriority(str, Enum):
    CRITICAL = "critical"    # Always include (system prompt, current task)
    HIGH = "high"            # Include if space (recent findings, tool outputs)
    MEDIUM = "medium"        # Include if room (strategy knowledge, history)
    LOW = "low"              # Include only with large context (old history)
    BACKGROUND = "background"  # Only for long-context models (200K+)


class ContentType(str, Enum):
    SYSTEM_PROMPT = "system_prompt"
    STRATEGY_KNOWLEDGE = "strategy_knowledge"
    TARGET_PROFILE = "target_profile"
    TOOL_OUTPUT = "tool_output"
    FINDING = "finding"
    CONVERSATION = "conversation"
    REASONING_CHAIN = "reasoning_chain"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    TASK_DESCRIPTION = "task_description"
    EXAMPLE = "example"


@dataclass
class ContextItem:
    """A piece of content that can be included in context."""
    item_id: str = ""
    content: str = ""
    content_type: ContentType = ContentType.CONVERSATION
    priority: ContentPriority = ContentPriority.MEDIUM
    estimated_tokens: int = 0
    relevance_score: float = 0.5
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "type": self.content_type.value,
            "priority": self.priority.value,
            "tokens": self.estimated_tokens,
            "relevance": round(self.relevance_score, 2),
        }


@dataclass
class ContextWindow:
    """An assembled context window for a model."""
    window_id: str = ""
    model: str = ""
    max_tokens: int = 4096
    items: list[ContextItem] = field(default_factory=list)
    total_tokens: int = 0
    utilization: float = 0.0
    items_dropped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.window_id,
            "model": self.model[:20],
            "max": self.max_tokens,
            "used": self.total_tokens,
            "util": round(self.utilization, 2),
            "items": len(self.items),
            "dropped": self.items_dropped,
        }


@dataclass
class ContextBudget:
    """Budget allocation for different content types."""
    system_prompt_pct: float = 0.15      # 15% for system prompt
    strategy_knowledge_pct: float = 0.15  # 15% for strategy knowledge
    target_profile_pct: float = 0.10     # 10% for target info
    tool_output_pct: float = 0.25        # 25% for tool outputs
    findings_pct: float = 0.10           # 10% for findings
    conversation_pct: float = 0.15       # 15% for conversation history
    reasoning_pct: float = 0.10          # 10% for reasoning chains

    def get_allocation(
        self,
        content_type: ContentType,
        max_tokens: int,
    ) -> int:
        """Get token allocation for a content type."""
        pct_map = {
            ContentType.SYSTEM_PROMPT: self.system_prompt_pct,
            ContentType.STRATEGY_KNOWLEDGE: self.strategy_knowledge_pct,
            ContentType.TARGET_PROFILE: self.target_profile_pct,
            ContentType.TOOL_OUTPUT: self.tool_output_pct,
            ContentType.FINDING: self.findings_pct,
            ContentType.CONVERSATION: self.conversation_pct,
            ContentType.REASONING_CHAIN: self.reasoning_pct,
        }
        pct = pct_map.get(content_type, 0.05)
        return int(max_tokens * pct)


# ── Model Context Sizes ──────────────────────────────────────

MODEL_CONTEXT_SIZES: dict[str, int] = {
    "whiterabbitneo-7b": 8192,
    "qwen2.5-coder-14b": 32768,
    "qwen2.5-coder-7b": 32768,
    "deepseek-r1-7b": 32768,
    "deepseek-math-7b": 4096,
    "hermes-4-14b": 32768,
    "llama-3.1-8b": 131072,
    "dolphin-2.9": 8192,
    "mistral-7b": 32768,
    "codellama-13b": 16384,
    "codellama-7b": 16384,
    "yi-9b-200k": 200000,
    "phi-3.5-mini": 131072,
    "nomic-embed": 8192,
    "llama-guard-3": 8192,
    "functiongemma-270m": 8192,
}


def estimate_tokens(text: str) -> int:
    """Estimate token count (approx 4 chars per token for English)."""
    return max(1, len(text) // 4)


class ContextWindowManager:
    """Manages context windows for multiple models.

    Optimizes what content goes into each LLM's context window,
    respecting token limits and prioritizing the most relevant
    information for the current task.
    """

    def __init__(self) -> None:
        self._items: dict[str, ContextItem] = {}
        self._item_counter = 0
        self._window_counter = 0
        self._budget = ContextBudget()
        self._log = logger.bind(component="context_window_manager")

    def add_item(
        self,
        content: str,
        content_type: ContentType,
        priority: ContentPriority = ContentPriority.MEDIUM,
        relevance_score: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> ContextItem:
        """Add content to the context pool."""
        self._item_counter += 1
        item = ContextItem(
            item_id=f"ctx-{self._item_counter}",
            content=content,
            content_type=content_type,
            priority=priority,
            estimated_tokens=estimate_tokens(content),
            relevance_score=relevance_score,
            metadata=metadata or {},
        )
        self._items[item.item_id] = item
        return item

    def build_window(
        self,
        model: str,
        task_content: str = "",
        max_tokens: int | None = None,
        response_reserve: int = 1024,
    ) -> ContextWindow:
        """Build a context window for a specific model."""
        self._window_counter += 1

        # Determine max context size
        if max_tokens is None:
            max_tokens = MODEL_CONTEXT_SIZES.get(model, 4096)

        available = max_tokens - response_reserve

        window = ContextWindow(
            window_id=f"win-{self._window_counter}",
            model=model,
            max_tokens=max_tokens,
        )

        # Sort items by priority, then relevance
        priority_order = {
            ContentPriority.CRITICAL: 0,
            ContentPriority.HIGH: 1,
            ContentPriority.MEDIUM: 2,
            ContentPriority.LOW: 3,
            ContentPriority.BACKGROUND: 4,
        }

        sorted_items = sorted(
            self._items.values(),
            key=lambda x: (
                priority_order.get(x.priority, 5),
                -x.relevance_score,
            ),
        )

        # Add task content first if provided
        if task_content:
            task_tokens = estimate_tokens(task_content)
            if task_tokens <= available:
                task_item = ContextItem(
                    item_id="task",
                    content=task_content,
                    content_type=ContentType.TASK_DESCRIPTION,
                    priority=ContentPriority.CRITICAL,
                    estimated_tokens=task_tokens,
                    relevance_score=1.0,
                )
                window.items.append(task_item)
                available -= task_tokens

        # Budget-aware inclusion
        type_tokens_used: dict[ContentType, int] = defaultdict(int)

        for item in sorted_items:
            if available <= 0:
                window.items_dropped += 1
                continue

            # Check type budget
            type_budget = self._budget.get_allocation(
                item.content_type, max_tokens
            )
            type_used = type_tokens_used[item.content_type]
            type_remaining = type_budget - type_used

            if item.estimated_tokens > type_remaining and item.priority != ContentPriority.CRITICAL:
                # Try truncating
                if type_remaining > 100:
                    truncated = self._truncate_content(
                        item, type_remaining
                    )
                    if truncated:
                        window.items.append(truncated)
                        available -= truncated.estimated_tokens
                        type_tokens_used[item.content_type] += truncated.estimated_tokens
                        continue
                window.items_dropped += 1
                continue

            if item.estimated_tokens > available:
                # Try truncating to fit
                truncated = self._truncate_content(item, available)
                if truncated:
                    window.items.append(truncated)
                    available -= truncated.estimated_tokens
                    type_tokens_used[item.content_type] += truncated.estimated_tokens
                else:
                    window.items_dropped += 1
                continue

            window.items.append(item)
            available -= item.estimated_tokens
            type_tokens_used[item.content_type] += item.estimated_tokens

        # Calculate stats
        window.total_tokens = sum(i.estimated_tokens for i in window.items)
        window.utilization = window.total_tokens / max(1, max_tokens)

        return window

    def assemble_prompt(self, window: ContextWindow) -> str:
        """Assemble the final prompt from a context window."""
        sections: dict[str, list[str]] = defaultdict(list)

        for item in window.items:
            sections[item.content_type.value].append(item.content)

        parts = []

        # System prompt first
        if "system_prompt" in sections:
            parts.append("\n".join(sections["system_prompt"]))

        # Strategy knowledge
        if "strategy_knowledge" in sections:
            parts.append(
                "## Strategy Knowledge\n" +
                "\n".join(sections["strategy_knowledge"])
            )

        # Target profile
        if "target_profile" in sections:
            parts.append(
                "## Target Information\n" +
                "\n".join(sections["target_profile"])
            )

        # Tool outputs
        if "tool_output" in sections:
            parts.append(
                "## Tool Outputs\n" +
                "\n".join(sections["tool_output"])
            )

        # Findings
        if "finding" in sections:
            parts.append(
                "## Findings So Far\n" +
                "\n".join(sections["finding"])
            )

        # Conversation history
        if "conversation" in sections:
            parts.append(
                "## Conversation\n" +
                "\n".join(sections["conversation"])
            )

        # Reasoning
        if "reasoning_chain" in sections:
            parts.append(
                "## Reasoning\n" +
                "\n".join(sections["reasoning_chain"])
            )

        # Task
        if "task_description" in sections:
            parts.append(
                "## Current Task\n" +
                "\n".join(sections["task_description"])
            )

        return "\n\n".join(parts)

    @staticmethod
    def _truncate_content(
        item: ContextItem,
        max_tokens: int,
    ) -> ContextItem | None:
        """Truncate content to fit within token budget."""
        if max_tokens < 50:
            return None

        max_chars = max_tokens * 4
        truncated_text = item.content[:max_chars]

        if len(truncated_text) < len(item.content):
            truncated_text += "\n... [truncated]"

        return ContextItem(
            item_id=item.item_id + "-trunc",
            content=truncated_text,
            content_type=item.content_type,
            priority=item.priority,
            estimated_tokens=estimate_tokens(truncated_text),
            relevance_score=item.relevance_score * 0.9,
            metadata=item.metadata,
        )

    def clear_items(self, content_type: ContentType | None = None) -> int:
        """Clear items from the pool."""
        if content_type is None:
            count = len(self._items)
            self._items.clear()
            return count

        to_remove = [
            k for k, v in self._items.items()
            if v.content_type == content_type
        ]
        for k in to_remove:
            del self._items[k]
        return len(to_remove)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        type_tokens: dict[str, int] = defaultdict(int)
        for item in self._items.values():
            type_counts[item.content_type.value] += 1
            type_tokens[item.content_type.value] += item.estimated_tokens
        return {
            "items": len(self._items),
            "total_tokens": sum(i.estimated_tokens for i in self._items.values()),
            "by_type_count": dict(type_counts),
            "by_type_tokens": dict(type_tokens),
        }
