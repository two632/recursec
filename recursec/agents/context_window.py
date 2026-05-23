"""Context window manager — manages LLM context token budgets.

Handles:
1. Token counting and estimation
2. Context priority ranking
3. Sliding window management
4. Context compression and summarization
5. Multi-source context assembly
6. Token budget allocation per source
7. Important information preservation
8. Context diff for incremental updates
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextSource(str, Enum):
    SYSTEM_PROMPT = "system_prompt"
    TASK = "task"
    FINDINGS = "findings"
    TOOL_OUTPUT = "tool_output"
    CONVERSATION = "conversation"
    KNOWLEDGE = "knowledge"
    PARENT_CONTEXT = "parent_context"
    SIBLING_FINDINGS = "sibling_findings"


class ContentPriority(str, Enum):
    CRITICAL = "critical"     # Must include
    HIGH = "high"             # Include if space
    MEDIUM = "medium"         # Include if comfortable
    LOW = "low"               # Include only if excess space


@dataclass
class ContextBlock:
    """A block of context to include in the LLM prompt."""
    block_id: str = ""
    source: ContextSource = ContextSource.TASK
    priority: ContentPriority = ContentPriority.MEDIUM
    content: str = ""
    token_estimate: int = 0
    max_tokens: int = 0        # 0 = no limit
    created_at: float = field(default_factory=time.time)
    is_compressed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.block_id,
            "source": self.source.value,
            "priority": self.priority.value,
            "tokens": self.token_estimate,
            "compressed": self.is_compressed,
        }


@dataclass
class ContextWindow:
    """An assembled context window for an LLM call."""
    blocks: list[ContextBlock] = field(default_factory=list)
    total_tokens: int = 0
    max_tokens: int = 4096
    messages: list[dict[str, str]] = field(default_factory=list)
    overflow_blocks: list[ContextBlock] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocks": len(self.blocks),
            "tokens_used": self.total_tokens,
            "max_tokens": self.max_tokens,
            "messages": len(self.messages),
            "overflow": len(self.overflow_blocks),
        }


# ── Token Estimation ─────────────────────────────────────────

PRIORITY_ORDER = {
    ContentPriority.CRITICAL: 0,
    ContentPriority.HIGH: 1,
    ContentPriority.MEDIUM: 2,
    ContentPriority.LOW: 3,
}


def estimate_tokens(text: str) -> int:
    """Estimate token count from text (rough 4 chars per token)."""
    return max(1, len(text) // 4)


class ContextWindowManager:
    """Manages LLM context windows and token budgets.

    Assembles context from multiple sources, respects token
    budgets, and prioritizes information.
    """

    def __init__(
        self,
        default_max_tokens: int = 4096,
        reserve_for_output: int = 1024,
    ) -> None:
        self._default_max = default_max_tokens
        self._output_reserve = reserve_for_output
        self._block_counter = 0
        self._blocks: dict[str, ContextBlock] = {}
        self._source_budgets: dict[str, int] = {}
        self._log = logger.bind(component="context_window")

    def set_source_budget(self, source: ContextSource, max_tokens: int) -> None:
        """Set a token budget for a context source."""
        self._source_budgets[source.value] = max_tokens

    def add_block(
        self,
        content: str,
        source: ContextSource,
        priority: ContentPriority = ContentPriority.MEDIUM,
        max_tokens: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Add a context block."""
        self._block_counter += 1
        block_id = f"ctx-{self._block_counter}"

        tokens = estimate_tokens(content)

        # Apply source budget
        source_budget = self._source_budgets.get(source.value, 0)
        if source_budget and max_tokens == 0:
            max_tokens = source_budget

        # Truncate if over budget
        if max_tokens and tokens > max_tokens:
            chars_limit = max_tokens * 4
            content = content[:chars_limit] + "\n... (truncated)"
            tokens = max_tokens

        block = ContextBlock(
            block_id=block_id,
            source=source,
            priority=priority,
            content=content,
            token_estimate=tokens,
            max_tokens=max_tokens,
            metadata=metadata or {},
        )

        self._blocks[block_id] = block
        return block_id

    def remove_block(self, block_id: str) -> bool:
        return self._blocks.pop(block_id, None) is not None

    def build_window(
        self,
        max_tokens: int = 0,
        sources: list[ContextSource] | None = None,
    ) -> ContextWindow:
        """Build a context window from available blocks."""
        budget = (max_tokens or self._default_max) - self._output_reserve

        # Filter by requested sources
        blocks = list(self._blocks.values())
        if sources:
            source_values = {s.value for s in sources}
            blocks = [b for b in blocks if b.source.value in source_values]

        # Sort by priority (critical first)
        blocks.sort(key=lambda b: PRIORITY_ORDER.get(b.priority, 2))

        window = ContextWindow(max_tokens=budget)
        used = 0

        for block in blocks:
            if used + block.token_estimate <= budget:
                window.blocks.append(block)
                used += block.token_estimate
            else:
                # Try to fit a compressed version
                remaining = budget - used
                if remaining > 100 and block.priority in (ContentPriority.CRITICAL, ContentPriority.HIGH):
                    compressed = self._compress_block(block, remaining)
                    window.blocks.append(compressed)
                    used += compressed.token_estimate
                else:
                    window.overflow_blocks.append(block)

        window.total_tokens = used

        # Build messages
        window.messages = self._blocks_to_messages(window.blocks)

        return window

    def build_messages(
        self,
        system_prompt: str,
        task: str,
        context_blocks: list[str] | None = None,
        max_tokens: int = 0,
    ) -> list[dict[str, str]]:
        """Build LLM messages with context."""
        budget = (max_tokens or self._default_max) - self._output_reserve
        messages: list[dict[str, str]] = []

        # System message
        sys_tokens = estimate_tokens(system_prompt)
        messages.append({"role": "system", "content": system_prompt})
        used = sys_tokens

        # Add context blocks
        context_content = []
        if context_blocks:
            for block_id in context_blocks:
                block = self._blocks.get(block_id)
                if block and used + block.token_estimate <= budget:
                    context_content.append(block.content)
                    used += block.token_estimate

        # User message with task and context
        user_parts = []
        if context_content:
            user_parts.append("Context:\n" + "\n---\n".join(context_content))
        user_parts.append(f"Task: {task}")

        user_msg = "\n\n".join(user_parts)
        user_tokens = estimate_tokens(user_msg)

        if used + user_tokens > budget:
            char_limit = (budget - used) * 4
            user_msg = user_msg[:char_limit]

        messages.append({"role": "user", "content": user_msg})

        return messages

    def _compress_block(self, block: ContextBlock, target_tokens: int) -> ContextBlock:
        """Compress a block to fit in target tokens."""
        char_limit = target_tokens * 4
        compressed_content = block.content[:char_limit]
        if len(block.content) > char_limit:
            compressed_content += "\n... (compressed)"

        return ContextBlock(
            block_id=block.block_id + "-compressed",
            source=block.source,
            priority=block.priority,
            content=compressed_content,
            token_estimate=target_tokens,
            is_compressed=True,
            metadata=block.metadata,
        )

    def _blocks_to_messages(
        self,
        blocks: list[ContextBlock],
    ) -> list[dict[str, str]]:
        """Convert context blocks to LLM messages."""
        messages = []

        # Group by source
        system_blocks = [b for b in blocks if b.source == ContextSource.SYSTEM_PROMPT]
        task_blocks = [b for b in blocks if b.source == ContextSource.TASK]
        other_blocks = [
            b for b in blocks
            if b.source not in (ContextSource.SYSTEM_PROMPT, ContextSource.TASK)
        ]

        # System message
        if system_blocks:
            content = "\n\n".join(b.content for b in system_blocks)
            messages.append({"role": "system", "content": content})

        # Context + task as user message
        parts = []
        if other_blocks:
            parts.append("Context:")
            for block in other_blocks:
                parts.append(f"[{block.source.value}] {block.content}")
        if task_blocks:
            parts.append("Task:")
            for block in task_blocks:
                parts.append(block.content)

        if parts:
            messages.append({"role": "user", "content": "\n\n".join(parts)})

        return messages

    def get_stats(self) -> dict[str, Any]:
        total_tokens = sum(b.token_estimate for b in self._blocks.values())
        by_source: dict[str, int] = {}
        for b in self._blocks.values():
            by_source.setdefault(b.source.value, 0)
            by_source[b.source.value] += b.token_estimate
        return {
            "blocks": len(self._blocks),
            "total_tokens": total_tokens,
            "by_source": by_source,
        }
