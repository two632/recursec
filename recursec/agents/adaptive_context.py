"""Adaptive context window — dynamic LLM context.

Implements:
1. Dynamic context section sizing
2. Phase-aware context assembly
3. Relevance scoring for content
4. Sliding window management
5. Priority insertion/eviction
6. Context window prompt
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextSection(str, Enum):
    SYSTEM = "system"               # System prompt
    TARGET = "target"               # Target info
    KNOWLEDGE = "knowledge"         # KB patterns
    MEMORY = "memory"               # Past findings
    CONVERSATION = "conversation"   # Recent turns
    FINDINGS = "findings"           # Current findings
    TOOLS = "tools"                 # Available tools
    REASONING = "reasoning"         # CoT state
    TASK = "task"                   # Current task


class PhaseProfile(str, Enum):
    RECON = "recon"                 # Heavy on target, light on findings
    SCANNING = "scanning"           # Heavy on knowledge, moderate tools
    ANALYSIS = "analysis"           # Heavy on findings, memory
    EXPLOITATION = "exploitation"   # Heavy on knowledge, findings
    VALIDATION = "validation"       # Heavy on findings, reasoning
    REPORTING = "reporting"         # Heavy on findings, light knowledge


# Phase → section weight profiles (multipliers)
PHASE_WEIGHTS: dict[PhaseProfile, dict[ContextSection, float]] = {
    PhaseProfile.RECON: {
        ContextSection.SYSTEM: 1.0,
        ContextSection.TARGET: 2.0,
        ContextSection.KNOWLEDGE: 1.5,
        ContextSection.MEMORY: 0.5,
        ContextSection.CONVERSATION: 0.8,
        ContextSection.FINDINGS: 0.3,
        ContextSection.TOOLS: 1.5,
        ContextSection.REASONING: 0.5,
        ContextSection.TASK: 1.2,
    },
    PhaseProfile.SCANNING: {
        ContextSection.SYSTEM: 1.0,
        ContextSection.TARGET: 1.0,
        ContextSection.KNOWLEDGE: 2.0,
        ContextSection.MEMORY: 1.0,
        ContextSection.CONVERSATION: 0.5,
        ContextSection.FINDINGS: 1.0,
        ContextSection.TOOLS: 1.5,
        ContextSection.REASONING: 0.5,
        ContextSection.TASK: 1.0,
    },
    PhaseProfile.ANALYSIS: {
        ContextSection.SYSTEM: 1.0,
        ContextSection.TARGET: 0.8,
        ContextSection.KNOWLEDGE: 1.5,
        ContextSection.MEMORY: 1.5,
        ContextSection.CONVERSATION: 0.5,
        ContextSection.FINDINGS: 2.0,
        ContextSection.TOOLS: 0.5,
        ContextSection.REASONING: 1.5,
        ContextSection.TASK: 0.8,
    },
    PhaseProfile.EXPLOITATION: {
        ContextSection.SYSTEM: 1.0,
        ContextSection.TARGET: 1.0,
        ContextSection.KNOWLEDGE: 2.0,
        ContextSection.MEMORY: 1.0,
        ContextSection.CONVERSATION: 0.3,
        ContextSection.FINDINGS: 1.5,
        ContextSection.TOOLS: 1.5,
        ContextSection.REASONING: 1.0,
        ContextSection.TASK: 1.0,
    },
    PhaseProfile.VALIDATION: {
        ContextSection.SYSTEM: 1.0,
        ContextSection.TARGET: 0.5,
        ContextSection.KNOWLEDGE: 1.0,
        ContextSection.MEMORY: 0.5,
        ContextSection.CONVERSATION: 0.3,
        ContextSection.FINDINGS: 2.5,
        ContextSection.TOOLS: 0.5,
        ContextSection.REASONING: 2.0,
        ContextSection.TASK: 0.8,
    },
    PhaseProfile.REPORTING: {
        ContextSection.SYSTEM: 0.5,
        ContextSection.TARGET: 1.0,
        ContextSection.KNOWLEDGE: 0.3,
        ContextSection.MEMORY: 0.5,
        ContextSection.CONVERSATION: 0.3,
        ContextSection.FINDINGS: 3.0,
        ContextSection.TOOLS: 0.2,
        ContextSection.REASONING: 0.5,
        ContextSection.TASK: 1.0,
    },
}


@dataclass
class ContextBlock:
    """A block of content for the context window."""
    section: ContextSection = ContextSection.SYSTEM
    content: str = ""
    token_count: int = 0
    relevance: float = 1.0
    priority: int = 5
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value[:8],
            "tokens": self.token_count,
            "rel": f"{self.relevance:.2f}",
        }


@dataclass
class ContextWindowState:
    """Current state of the context window."""
    total_tokens: int = 0
    max_tokens: int = 4096
    sections: dict[str, int] = field(default_factory=dict)
    utilization: float = 0.0
    phase: PhaseProfile = PhaseProfile.RECON

    def to_dict(self) -> dict[str, Any]:
        return {
            "used": self.total_tokens,
            "max": self.max_tokens,
            "util": f"{self.utilization:.0%}",
            "phase": self.phase.value[:8],
        }


class AdaptiveContextWindow:
    """Dynamically manage LLM context window.

    Adjusts section sizes based on phase,
    relevance, and available tokens.
    """

    def __init__(
        self,
        max_tokens: int = 4096,
        reserve_output: int = 512,
    ) -> None:
        self._blocks: dict[ContextSection, list[ContextBlock]] = {
            s: [] for s in ContextSection
        }
        self._max_tokens = max_tokens
        self._reserve = reserve_output
        self._phase = PhaseProfile.RECON
        self._log = logger.bind(component="ctx_window")

    @property
    def available_tokens(self) -> int:
        used = sum(
            sum(b.token_count for b in blocks)
            for blocks in self._blocks.values()
        )
        return max(0, self._max_tokens - self._reserve - used)

    def set_phase(self, phase: PhaseProfile) -> None:
        """Update the current phase."""
        self._phase = phase

    def set_max_tokens(self, max_tokens: int) -> None:
        """Update max token budget."""
        self._max_tokens = max_tokens

    def add_content(
        self,
        section: ContextSection,
        content: str,
        relevance: float = 1.0,
        priority: int = 5,
    ) -> bool:
        """Add content to a section."""
        token_count = max(1, len(content) // 4)

        block = ContextBlock(
            section=section,
            content=content,
            token_count=token_count,
            relevance=relevance,
            priority=priority,
        )

        self._blocks[section].append(block)

        # Evict if over budget
        while self.available_tokens < 0:
            if not self._evict_lowest():
                break

        return True

    def replace_content(
        self,
        section: ContextSection,
        content: str,
        relevance: float = 1.0,
    ) -> None:
        """Replace all content in a section."""
        self._blocks[section] = []
        self.add_content(section, content, relevance)

    def _evict_lowest(self) -> bool:
        """Evict the lowest-value content block."""
        weights = PHASE_WEIGHTS.get(self._phase, {})

        lowest_score = float('inf')
        lowest_section: ContextSection | None = None
        lowest_idx = -1

        for section, blocks in self._blocks.items():
            if not blocks:
                continue

            phase_weight = weights.get(section, 1.0)

            for i, block in enumerate(blocks):
                score = block.relevance * block.priority * phase_weight
                if score < lowest_score:
                    lowest_score = score
                    lowest_section = section
                    lowest_idx = i

        if lowest_section is not None and lowest_idx >= 0:
            self._blocks[lowest_section].pop(lowest_idx)
            return True

        return False

    def assemble(self) -> str:
        """Assemble the full context window."""
        weights = PHASE_WEIGHTS.get(self._phase, {})

        # Sort sections by phase weight
        ordered_sections = sorted(
            ContextSection,
            key=lambda s: weights.get(s, 1.0),
            reverse=True,
        )

        parts: list[str] = []
        for section in ordered_sections:
            blocks = self._blocks.get(section, [])
            if not blocks:
                continue

            # Sort blocks by relevance × priority
            sorted_blocks = sorted(
                blocks,
                key=lambda b: b.relevance * b.priority,
                reverse=True,
            )

            for block in sorted_blocks:
                parts.append(block.content)

        return "\n\n".join(parts)

    def get_section_tokens(self) -> dict[str, int]:
        """Get token count per section."""
        return {
            section.value: sum(b.token_count for b in blocks)
            for section, blocks in self._blocks.items()
            if blocks
        }

    def get_state(self) -> ContextWindowState:
        """Get current window state."""
        section_tokens = self.get_section_tokens()
        total = sum(section_tokens.values())

        return ContextWindowState(
            total_tokens=total,
            max_tokens=self._max_tokens,
            sections=section_tokens,
            utilization=total / max(1, self._max_tokens),
            phase=self._phase,
        )

    def build_context_prompt(self) -> str:
        """Build context window state for LLM."""
        state = self.get_state()
        lines = ["## Context Window\n"]
        lines.append(f"Phase: {state.phase.value}")
        lines.append(
            f"Tokens: {state.total_tokens}/{state.max_tokens} "
            f"({state.utilization:.0%})"
        )

        if state.sections:
            lines.append("\nSections:")
            for section, tokens in sorted(
                state.sections.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                lines.append(f"  {section[:10]}: {tokens}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        state = self.get_state()
        return {
            "total_tokens": state.total_tokens,
            "max_tokens": state.max_tokens,
            "utilization": f"{state.utilization:.0%}",
            "phase": state.phase.value,
            "sections": state.sections,
        }
