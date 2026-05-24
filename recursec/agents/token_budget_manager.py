"""Token budget manager — allocates context window.

Manages token allocation across prompt sections:
1. Section-based budgets with priorities
2. Dynamic reallocation based on need
3. Overflow handling (truncation, summarization)
4. Token counting (estimation and exact)
5. Budget tracking and analytics
6. Budget prompt for LLM
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BudgetSection(str, Enum):
    SYSTEM = "system"              # System prompt
    KNOWLEDGE = "knowledge"        # KB patterns
    MEMORY = "memory"              # Episodic/semantic memory
    FINDINGS = "findings"          # Current findings
    TASK = "task"                  # Task description
    TOOLS = "tools"               # Tool descriptions
    CONVERSATION = "conversation"  # Recent conversation
    REASONING = "reasoning"        # Chain-of-thought
    RESERVED = "reserved"          # Output generation


class OverflowStrategy(str, Enum):
    TRUNCATE_END = "truncate_end"     # Cut from the end
    TRUNCATE_START = "truncate_start"  # Cut from the start
    SUMMARIZE = "summarize"           # Request summarization
    PRIORITY_DROP = "priority_drop"   # Drop lowest priority items
    COMPRESS = "compress"             # Remove whitespace/formatting


@dataclass
class SectionBudget:
    """Budget allocation for a prompt section."""
    section: BudgetSection = BudgetSection.SYSTEM
    max_tokens: int = 512
    min_tokens: int = 64
    priority: int = 5
    overflow: OverflowStrategy = OverflowStrategy.TRUNCATE_END
    current_tokens: int = 0
    content: str = ""

    @property
    def utilization(self) -> float:
        if self.max_tokens == 0:
            return 0.0
        return self.current_tokens / self.max_tokens

    @property
    def remaining(self) -> int:
        return max(0, self.max_tokens - self.current_tokens)

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value[:10],
            "used": self.current_tokens,
            "max": self.max_tokens,
            "util": f"{self.utilization:.0%}",
        }


# Default budget allocations (percentages of total context)
DEFAULT_ALLOCATIONS: dict[BudgetSection, dict[str, Any]] = {
    BudgetSection.SYSTEM: {"pct": 0.08, "priority": 10, "overflow": OverflowStrategy.TRUNCATE_END},
    BudgetSection.KNOWLEDGE: {"pct": 0.25, "priority": 7, "overflow": OverflowStrategy.PRIORITY_DROP},
    BudgetSection.MEMORY: {"pct": 0.12, "priority": 5, "overflow": OverflowStrategy.TRUNCATE_START},
    BudgetSection.FINDINGS: {"pct": 0.12, "priority": 8, "overflow": OverflowStrategy.PRIORITY_DROP},
    BudgetSection.TASK: {"pct": 0.10, "priority": 9, "overflow": OverflowStrategy.TRUNCATE_END},
    BudgetSection.TOOLS: {"pct": 0.08, "priority": 6, "overflow": OverflowStrategy.PRIORITY_DROP},
    BudgetSection.CONVERSATION: {"pct": 0.10, "priority": 4, "overflow": OverflowStrategy.TRUNCATE_START},
    BudgetSection.REASONING: {"pct": 0.05, "priority": 3, "overflow": OverflowStrategy.SUMMARIZE},
    BudgetSection.RESERVED: {"pct": 0.10, "priority": 10, "overflow": OverflowStrategy.TRUNCATE_END},
}


class TokenBudgetManager:
    """Manages token budget allocation across prompt sections.

    Allocates, tracks, and rebalances token
    budgets to maximize context utilization.
    """

    def __init__(
        self,
        total_context: int = 4096,
        chars_per_token: float = 4.0,
    ) -> None:
        self._total_context = total_context
        self._chars_per_token = chars_per_token
        self._budgets: dict[BudgetSection, SectionBudget] = {}
        self._allocation_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="token_budget")
        self._init_budgets()

    def _init_budgets(self) -> None:
        """Initialize budgets from defaults."""
        for section, config in DEFAULT_ALLOCATIONS.items():
            max_tokens = int(self._total_context * config["pct"])
            self._budgets[section] = SectionBudget(
                section=section,
                max_tokens=max_tokens,
                min_tokens=max(32, max_tokens // 8),
                priority=config["priority"],
                overflow=config["overflow"],
            )

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count from text."""
        return max(1, int(len(text) / self._chars_per_token))

    def set_total_context(self, total: int) -> None:
        """Update total context window and reallocate."""
        self._total_context = total
        for section, config in DEFAULT_ALLOCATIONS.items():
            budget = self._budgets.get(section)
            if budget:
                budget.max_tokens = int(total * config["pct"])
                budget.min_tokens = max(32, budget.max_tokens // 8)

    def allocate(
        self,
        section: BudgetSection,
        content: str,
    ) -> str:
        """Allocate content to a section, handling overflow."""
        budget = self._budgets.get(section)
        if not budget:
            return content

        tokens = self.estimate_tokens(content)

        if tokens <= budget.max_tokens:
            budget.current_tokens = tokens
            budget.content = content
            return content

        # Handle overflow
        result = self._handle_overflow(budget, content, tokens)
        budget.current_tokens = self.estimate_tokens(result)
        budget.content = result

        return result

    def _handle_overflow(
        self,
        budget: SectionBudget,
        content: str,
        tokens: int,
    ) -> str:
        """Handle content overflow for a section."""
        max_chars = int(budget.max_tokens * self._chars_per_token)

        if budget.overflow == OverflowStrategy.TRUNCATE_END:
            return content[:max_chars]

        if budget.overflow == OverflowStrategy.TRUNCATE_START:
            return content[-max_chars:]

        if budget.overflow == OverflowStrategy.COMPRESS:
            # Remove extra whitespace
            lines = content.split("\n")
            compressed = "\n".join(line.strip() for line in lines if line.strip())
            if len(compressed) <= max_chars:
                return compressed
            return compressed[:max_chars]

        if budget.overflow == OverflowStrategy.PRIORITY_DROP:
            # Drop sections (delimited by headers)
            sections = content.split("\n### ")
            if len(sections) <= 1:
                return content[:max_chars]

            # Keep header sections until budget filled
            result_parts = [sections[0]]
            current = len(sections[0])
            for s in sections[1:]:
                section_text = "\n### " + s
                if current + len(section_text) <= max_chars:
                    result_parts.append(section_text)
                    current += len(section_text)
            return "".join(result_parts)

        # Default: truncate end
        return content[:max_chars]

    def reallocate_unused(self) -> None:
        """Redistribute unused budget to needy sections."""
        # Find sections with unused budget
        surplus = 0
        deficit_sections: list[BudgetSection] = []

        for section, budget in self._budgets.items():
            if budget.current_tokens < budget.max_tokens * 0.5:
                freed = budget.max_tokens - max(budget.current_tokens, budget.min_tokens)
                surplus += freed
            elif budget.current_tokens >= budget.max_tokens * 0.9:
                deficit_sections.append(section)

        if surplus > 0 and deficit_sections:
            per_section = surplus // len(deficit_sections)
            for section in deficit_sections:
                self._budgets[section].max_tokens += per_section

    def get_budget(self, section: BudgetSection) -> SectionBudget:
        """Get budget for a section."""
        return self._budgets.get(section, SectionBudget())

    def get_total_used(self) -> int:
        """Get total tokens used across all sections."""
        return sum(b.current_tokens for b in self._budgets.values())

    def get_total_remaining(self) -> int:
        """Get total remaining capacity."""
        return max(0, self._total_context - self.get_total_used())

    def build_budget_prompt(self) -> str:
        """Build budget context for LLM."""
        lines = ["## Token Budget\n"]
        total_used = self.get_total_used()
        lines.append(f"Context: {self._total_context} tokens")
        lines.append(f"Used: {total_used} ({total_used / self._total_context:.0%})")
        lines.append(f"Remaining: {self.get_total_remaining()}")

        lines.append("\nSections:")
        for section, budget in sorted(
            self._budgets.items(),
            key=lambda x: x[1].priority,
            reverse=True,
        ):
            if budget.current_tokens > 0:
                lines.append(
                    f"  {section.value[:12]}: "
                    f"{budget.current_tokens}/{budget.max_tokens} "
                    f"({budget.utilization:.0%})"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_context": self._total_context,
            "total_used": self.get_total_used(),
            "utilization": f"{self.get_total_used() / self._total_context:.0%}",
            "sections": {
                s.value: b.to_dict()
                for s, b in self._budgets.items()
            },
        }
