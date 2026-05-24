"""Context window manager — intelligent context allocation.

Implements:
1. Token budget tracking per model
2. Context compression strategies
3. Sliding window with importance weighting
4. Section-based allocation (system/task/memory/tools)
5. Context overflow handling
6. Context prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextSection(str, Enum):
    SYSTEM = "system"           # Role and instructions
    TASK = "task"               # Current task description
    KNOWLEDGE = "knowledge"     # KB patterns
    MEMORY = "memory"           # Past events/facts
    FINDINGS = "findings"       # Current findings
    TOOLS = "tools"             # Available tools
    CONVERSATION = "conversation"  # Chat history
    REASONING = "reasoning"     # Chain of thought


# Default allocation percentages (of total context)
DEFAULT_ALLOCATIONS: dict[ContextSection, float] = {
    ContextSection.SYSTEM: 0.10,
    ContextSection.TASK: 0.10,
    ContextSection.KNOWLEDGE: 0.20,
    ContextSection.MEMORY: 0.10,
    ContextSection.FINDINGS: 0.15,
    ContextSection.TOOLS: 0.10,
    ContextSection.CONVERSATION: 0.15,
    ContextSection.REASONING: 0.10,
}


class CompressionStrategy(str, Enum):
    TRUNCATE = "truncate"       # Cut from end
    SUMMARIZE = "summarize"     # Summarize content
    SAMPLE = "sample"           # Keep important samples
    SLIDING = "sliding"         # Keep recent + important


@dataclass
class ContextBlock:
    """A block of context content."""
    block_id: str = ""
    section: ContextSection = ContextSection.SYSTEM
    content: str = ""
    token_count: int = 0
    importance: float = 0.5
    timestamp: float = field(default_factory=time.time)
    compressed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value[:6],
            "tokens": self.token_count,
            "importance": f"{self.importance:.1f}",
        }


@dataclass
class ContextBudget:
    """Token budget for a context window."""
    total_tokens: int = 4096
    used_tokens: int = 0
    section_usage: dict[str, int] = field(default_factory=dict)
    section_limits: dict[str, int] = field(default_factory=dict)

    @property
    def remaining(self) -> int:
        return max(0, self.total_tokens - self.used_tokens)

    @property
    def utilization(self) -> float:
        if self.total_tokens == 0:
            return 0.0
        return self.used_tokens / self.total_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total_tokens,
            "used": self.used_tokens,
            "remaining": self.remaining,
            "util": f"{self.utilization:.0%}",
        }


class ContextWindowManager:
    """Manages LLM context window allocation.

    Tracks token budgets per section, handles
    overflow with compression strategies, and
    ensures critical context always fits.
    """

    def __init__(
        self,
        model_context_size: int = 4096,
        allocations: dict[ContextSection, float] | None = None,
    ) -> None:
        self._context_size = model_context_size
        self._allocations = allocations or DEFAULT_ALLOCATIONS
        self._blocks: list[ContextBlock] = []
        self._block_counter = 0
        self._budget = ContextBudget(total_tokens=model_context_size)
        self._compression_count = 0
        self._log = logger.bind(component="context_mgr")

        # Calculate section limits
        for section, pct in self._allocations.items():
            self._budget.section_limits[section.value] = int(model_context_size * pct)

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return max(1, len(text) // 4)

    def add_block(
        self,
        section: ContextSection,
        content: str,
        importance: float = 0.5,
    ) -> ContextBlock | None:
        """Add a context block."""
        tokens = self.estimate_tokens(content)

        # Check section limit
        section_key = section.value
        current_usage = self._budget.section_usage.get(section_key, 0)
        section_limit = self._budget.section_limits.get(section_key, self._context_size)

        if current_usage + tokens > section_limit:
            # Try compression
            compressed = self._compress_section(section, tokens)
            if not compressed:
                # Truncate to fit
                available = section_limit - current_usage
                if available <= 0:
                    return None
                ratio = available / tokens
                content = content[:int(len(content) * ratio)]
                tokens = available

        self._block_counter += 1
        block = ContextBlock(
            block_id=f"ctx-{self._block_counter}",
            section=section,
            content=content,
            token_count=tokens,
            importance=importance,
        )

        self._blocks.append(block)
        self._budget.used_tokens += tokens
        self._budget.section_usage[section_key] = (
            self._budget.section_usage.get(section_key, 0) + tokens
        )

        return block

    def _compress_section(self, section: ContextSection, needed: int) -> bool:
        """Compress a section to free space."""
        section_blocks = [
            b for b in self._blocks
            if b.section == section and not b.compressed
        ]

        if not section_blocks:
            return False

        # Sort by importance (lowest first) then age (oldest first)
        section_blocks.sort(key=lambda b: (b.importance, -b.timestamp))

        freed = 0
        for block in section_blocks:
            if freed >= needed:
                break

            # Compress: keep first 25% of content
            original_tokens = block.token_count
            compressed_content = block.content[:len(block.content) // 4]
            new_tokens = self.estimate_tokens(compressed_content)

            freed_tokens = original_tokens - new_tokens
            block.content = compressed_content
            block.token_count = new_tokens
            block.compressed = True

            freed += freed_tokens
            self._budget.used_tokens -= freed_tokens
            section_key = section.value
            self._budget.section_usage[section_key] = max(
                0, self._budget.section_usage.get(section_key, 0) - freed_tokens
            )

        self._compression_count += 1
        return freed >= needed

    def clear_section(self, section: ContextSection) -> int:
        """Clear all blocks in a section."""
        to_remove = [b for b in self._blocks if b.section == section]
        freed = 0
        for block in to_remove:
            freed += block.token_count
            self._blocks.remove(block)

        self._budget.used_tokens -= freed
        self._budget.section_usage[section.value] = 0
        return freed

    def get_section_content(self, section: ContextSection) -> str:
        """Get all content for a section."""
        blocks = [b for b in self._blocks if b.section == section]
        blocks.sort(key=lambda b: b.importance, reverse=True)
        return "\n".join(b.content for b in blocks)

    def assemble_context(self) -> str:
        """Assemble full context from all sections."""
        sections_order = [
            ContextSection.SYSTEM,
            ContextSection.TASK,
            ContextSection.KNOWLEDGE,
            ContextSection.MEMORY,
            ContextSection.FINDINGS,
            ContextSection.TOOLS,
            ContextSection.CONVERSATION,
            ContextSection.REASONING,
        ]

        parts = []
        for section in sections_order:
            content = self.get_section_content(section)
            if content:
                parts.append(content)

        return "\n\n".join(parts)

    def resize(self, new_context_size: int) -> None:
        """Resize context window (for different models)."""
        self._context_size = new_context_size
        self._budget.total_tokens = new_context_size

        for section, pct in self._allocations.items():
            self._budget.section_limits[section.value] = int(new_context_size * pct)

    def build_context_prompt(self) -> str:
        """Build context management info for LLM."""
        lines = ["## Context Window\n"]
        lines.append(f"Size: {self._context_size} tokens")
        lines.append(f"Used: {self._budget.used_tokens} ({self._budget.utilization:.0%})")
        lines.append(f"Remaining: {self._budget.remaining}")

        lines.append("\nSections:")
        for section in ContextSection:
            used = self._budget.section_usage.get(section.value, 0)
            limit = self._budget.section_limits.get(section.value, 0)
            pct = used / limit * 100 if limit > 0 else 0
            lines.append(f"  {section.value[:8]}: {used}/{limit} ({pct:.0f}%)")

        if self._compression_count > 0:
            lines.append(f"\nCompressions: {self._compression_count}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "context_size": self._context_size,
            "used": self._budget.used_tokens,
            "utilization": f"{self._budget.utilization:.0%}",
            "blocks": len(self._blocks),
            "compressions": self._compression_count,
        }
