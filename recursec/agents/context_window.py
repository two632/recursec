"""Context window manager — manages LLM context efficiently.

Implements:
1. Context window size tracking per model
2. Sliding window for conversation history
3. Priority-based context packing
4. Automatic summarization triggers
5. Context compression strategies
6. Multi-model context adaptation
7. Token counting estimation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextSection(str, Enum):
    SYSTEM = "system"              # System prompt (always included)
    ROLE = "role"                  # Agent role definition
    KNOWLEDGE = "knowledge"        # Injected KB patterns
    FINDINGS = "findings"          # Current findings context
    TOOL_OUTPUT = "tool_output"    # Recent tool outputs
    CONVERSATION = "conversation"  # Conversation history
    TASK = "task"                  # Current task description
    MEMORY = "memory"              # Relevant memories
    HYPOTHESIS = "hypothesis"      # Active hypotheses
    BUDGET = "budget"              # Resource budget info


class CompressionStrategy(str, Enum):
    TRUNCATE = "truncate"         # Cut from end
    SUMMARIZE = "summarize"       # Summarize via LLM
    DROP_LOW_PRIORITY = "drop_low_priority"
    SLIDING_WINDOW = "sliding_window"


@dataclass
class ContextBlock:
    """A block of content in the context window."""
    section: ContextSection = ContextSection.SYSTEM
    content: str = ""
    priority: int = 5             # 1=highest, 10=lowest
    token_estimate: int = 0
    required: bool = False        # If True, never dropped
    timestamp: float = field(default_factory=time.time)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value,
            "priority": self.priority,
            "tokens": self.token_estimate,
            "required": self.required,
            "source": self.source[:15],
        }


# ── Model context limits ─────────────────────────────────────

MODEL_CONTEXT_LIMITS: dict[str, int] = {
    "whiterabbitneo-7b": 8192,
    "qwen-coder-14b": 32768,
    "qwen-coder-7b": 32768,
    "deepseek-r1-7b": 32768,
    "deepseek-math-7b": 4096,
    "hermes-14b": 32768,
    "llama-3.1-8b": 131072,
    "dolphin-8b": 8192,
    "mistral-7b": 32768,
    "codellama-13b": 16384,
    "codellama-7b": 16384,
    "yi-9b-200k": 200000,
    "phi-3.5-mini": 128000,
    "nomic-embed": 8192,
    "llama-guard-3": 8192,
    "functiongemma": 8192,
}

# ── Section priority defaults ────────────────────────────────

SECTION_PRIORITIES: dict[str, int] = {
    "system": 1,
    "role": 2,
    "task": 3,
    "knowledge": 4,
    "findings": 5,
    "hypothesis": 5,
    "tool_output": 6,
    "memory": 7,
    "conversation": 8,
    "budget": 9,
}

# ── Section required flags ───────────────────────────────────

SECTION_REQUIRED: dict[str, bool] = {
    "system": True,
    "role": True,
    "task": True,
    "knowledge": False,
    "findings": False,
    "hypothesis": False,
    "tool_output": False,
    "memory": False,
    "conversation": False,
    "budget": False,
}


def _estimate_tokens(text: str) -> int:
    """Estimate token count from text (rough: ~4 chars/token for English)."""
    return max(1, len(text) // 4)


class ContextWindow:
    """Manages LLM context window for an agent.

    Packs context blocks into the available
    window size, prioritizing important content
    and compressing/dropping low-priority blocks.
    """

    def __init__(
        self,
        model_id: str = "",
        max_tokens: int = 0,
        output_reserve: int = 2048,
    ) -> None:
        self._model_id = model_id
        self._max_tokens = max_tokens or MODEL_CONTEXT_LIMITS.get(model_id, 8192)
        self._output_reserve = output_reserve
        self._blocks: list[ContextBlock] = []
        self._log = logger.bind(component="context_window", model=model_id[:12])

    @property
    def available_tokens(self) -> int:
        return self._max_tokens - self._output_reserve

    @property
    def used_tokens(self) -> int:
        return sum(b.token_estimate for b in self._blocks)

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.available_tokens - self.used_tokens)

    def add_block(
        self,
        section: ContextSection,
        content: str,
        priority: int | None = None,
        required: bool | None = None,
        source: str = "",
    ) -> ContextBlock:
        """Add a content block to the context."""
        prio = priority if priority is not None else SECTION_PRIORITIES.get(section.value, 5)
        req = required if required is not None else SECTION_REQUIRED.get(section.value, False)

        block = ContextBlock(
            section=section,
            content=content,
            priority=prio,
            token_estimate=_estimate_tokens(content),
            required=req,
            source=source,
        )
        self._blocks.append(block)
        return block

    def compile(self) -> str:
        """Compile all blocks into final context string."""
        # Sort by priority
        sorted_blocks = sorted(self._blocks, key=lambda b: b.priority)

        # Pack into available space
        packed: list[ContextBlock] = []
        total_tokens = 0

        # First pass: add all required blocks
        for block in sorted_blocks:
            if block.required:
                packed.append(block)
                total_tokens += block.token_estimate

        # Second pass: add optional blocks by priority
        for block in sorted_blocks:
            if block.required:
                continue
            if total_tokens + block.token_estimate <= self.available_tokens:
                packed.append(block)
                total_tokens += block.token_estimate
            else:
                # Try to fit truncated version
                remaining = self.available_tokens - total_tokens
                if remaining > 100:
                    truncated = block.content[:remaining * 4]
                    block.content = truncated
                    block.token_estimate = _estimate_tokens(truncated)
                    packed.append(block)
                    total_tokens += block.token_estimate
                    break

        # Sort packed blocks by section order for readability
        section_order = [s.value for s in ContextSection]
        packed.sort(key=lambda b: section_order.index(b.section.value))

        # Assemble
        parts: list[str] = []
        for block in packed:
            if block.content.strip():
                parts.append(block.content)

        return "\n\n".join(parts)

    def adapt_for_model(self, model_id: str) -> None:
        """Adapt context for a different model's limits."""
        self._model_id = model_id
        self._max_tokens = MODEL_CONTEXT_LIMITS.get(model_id, 8192)

    def clear(self) -> None:
        """Clear all blocks."""
        self._blocks.clear()

    def get_stats(self) -> dict[str, Any]:
        section_tokens: dict[str, int] = {}
        for block in self._blocks:
            section_tokens[block.section.value] = (
                section_tokens.get(block.section.value, 0) + block.token_estimate
            )

        return {
            "model": self._model_id[:12],
            "max_tokens": self._max_tokens,
            "used_tokens": self.used_tokens,
            "remaining_tokens": self.remaining_tokens,
            "blocks": len(self._blocks),
            "by_section": section_tokens,
        }
