"""Context window manager — intelligent context management for LLMs.

Implements:
1. Context window tracking per model
2. Priority-based section allocation
3. Sliding window for conversation history
4. Context compression (summarization)
5. Dynamic context selection
6. Section overflow handling
7. Multi-model context adaptation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SectionPriority(str, Enum):
    CRITICAL = "critical"      # Always included (system prompt, task)
    HIGH = "high"             # Included unless space is tight
    MEDIUM = "medium"         # Included if space available
    LOW = "low"              # Only if plenty of space
    OPTIONAL = "optional"    # First to be cut


@dataclass
class ContextSection:
    """A section of context to include in the prompt."""
    section_id: str = ""
    name: str = ""
    content: str = ""
    priority: SectionPriority = SectionPriority.MEDIUM
    token_count: int = 0
    max_tokens: int = 0       # 0 = no limit
    compressible: bool = True
    compressed_content: str = ""

    @property
    def effective_content(self) -> str:
        """Return compressed content if available, else original."""
        return self.compressed_content or self.content

    @property
    def effective_tokens(self) -> int:
        """Token count of effective content."""
        content = self.effective_content
        return len(content) // 4

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.section_id[:10],
            "name": self.name[:15],
            "priority": self.priority.value,
            "tokens": self.effective_tokens,
        }


@dataclass
class ModelContextSpec:
    """Context window specification for a model."""
    model_id: str = ""
    context_size: int = 8192
    reserved_output: int = 2048
    reserved_system: int = 1024

    @property
    def available_tokens(self) -> int:
        return self.context_size - self.reserved_output - self.reserved_system

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "context": self.context_size,
            "available": self.available_tokens,
        }


# ── Model context sizes ──────────────────────────────────────

MODEL_CONTEXTS: dict[str, int] = {
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
    "nomic-embed": 2048,
    "llama-guard-3": 8192,
    "functiongemma-270m": 2048,
}


@dataclass
class ConversationTurn:
    """A single conversation turn."""
    role: str = "user"        # user, assistant, system
    content: str = ""
    token_count: int = 0
    timestamp: float = field(default_factory=time.time)
    important: bool = False   # Mark important turns to keep

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "tokens": self.token_count,
            "important": self.important,
        }


class ContextWindowManager:
    """Manages context window allocation for LLM interactions.

    Intelligently allocates the limited context
    window across system prompt, task, knowledge,
    findings, history, and other sections.
    """

    def __init__(self, default_context_size: int = 8192) -> None:
        self._sections: dict[str, ContextSection] = {}
        self._history: list[ConversationTurn] = []
        self._default_context = default_context_size
        self._model_specs: dict[str, ModelContextSpec] = {}
        self._counter = 0
        self._log = logger.bind(component="context_window")

        # Initialize model specs
        for model_id, ctx_size in MODEL_CONTEXTS.items():
            self._model_specs[model_id] = ModelContextSpec(
                model_id=model_id,
                context_size=ctx_size,
            )

    def add_section(
        self,
        name: str,
        content: str,
        priority: SectionPriority = SectionPriority.MEDIUM,
        max_tokens: int = 0,
        compressible: bool = True,
    ) -> ContextSection:
        """Add or update a context section."""
        self._counter += 1
        section = ContextSection(
            section_id=f"ctx-{self._counter}",
            name=name,
            content=content,
            priority=priority,
            token_count=len(content) // 4,
            max_tokens=max_tokens,
            compressible=compressible,
        )
        self._sections[name] = section
        return section

    def add_history_turn(
        self,
        role: str,
        content: str,
        important: bool = False,
    ) -> None:
        """Add a conversation turn."""
        turn = ConversationTurn(
            role=role,
            content=content,
            token_count=len(content) // 4,
            important=important,
        )
        self._history.append(turn)

    def assemble(
        self,
        model_id: str = "",
        include_history: bool = True,
        max_history_turns: int = 20,
    ) -> tuple[list[ContextSection], int]:
        """Assemble context sections that fit in the model's window."""
        spec = self._model_specs.get(model_id)
        available = spec.available_tokens if spec else self._default_context

        # Sort sections by priority
        priority_order = {
            SectionPriority.CRITICAL: 0,
            SectionPriority.HIGH: 1,
            SectionPriority.MEDIUM: 2,
            SectionPriority.LOW: 3,
            SectionPriority.OPTIONAL: 4,
        }

        sorted_sections = sorted(
            self._sections.values(),
            key=lambda s: priority_order.get(s.priority, 5),
        )

        included: list[ContextSection] = []
        tokens_used = 0

        for section in sorted_sections:
            section_tokens = section.effective_tokens

            # Apply max_tokens limit
            if section.max_tokens > 0:
                section_tokens = min(section_tokens, section.max_tokens)

            if tokens_used + section_tokens <= available:
                included.append(section)
                tokens_used += section_tokens
            elif section.priority == SectionPriority.CRITICAL:
                # Critical sections always included
                included.append(section)
                tokens_used += section_tokens
            elif section.compressible and section.compressed_content:
                # Try compressed version
                compressed_tokens = len(section.compressed_content) // 4
                if tokens_used + compressed_tokens <= available:
                    included.append(section)
                    tokens_used += compressed_tokens

        # Add history if space allows
        if include_history:
            history_budget = available - tokens_used
            history_tokens = 0
            # Include recent turns, always include important ones
            recent = self._history[-max_history_turns:]
            for turn in reversed(recent):
                if history_tokens + turn.token_count > history_budget:
                    if not turn.important:
                        continue
                history_tokens += turn.token_count

        return included, tokens_used

    def get_model_context(self, model_id: str) -> int:
        """Get available context size for a model."""
        spec = self._model_specs.get(model_id)
        return spec.available_tokens if spec else self._default_context

    def compress_section(self, name: str, compressed: str) -> bool:
        """Set compressed version of a section."""
        section = self._sections.get(name)
        if not section:
            return False
        section.compressed_content = compressed
        return True

    def trim_history(self, keep_last: int = 10) -> int:
        """Trim conversation history, keeping important turns."""
        if len(self._history) <= keep_last:
            return 0

        important = [t for t in self._history[:-keep_last] if t.important]
        recent = self._history[-keep_last:]
        removed = len(self._history) - len(important) - len(recent)
        self._history = important + recent
        return removed

    def build_context_prompt(self, model_id: str = "") -> str:
        """Build context status for LLM."""
        lines = ["## Context Status\n"]

        ctx = self.get_model_context(model_id) if model_id else self._default_context
        total_section_tokens = sum(s.effective_tokens for s in self._sections.values())
        history_tokens = sum(t.token_count for t in self._history)

        lines.append(f"Available: {ctx} tokens")
        lines.append(f"Sections: {total_section_tokens} tokens ({len(self._sections)} sections)")
        lines.append(f"History: {history_tokens} tokens ({len(self._history)} turns)")
        lines.append(f"Utilization: {(total_section_tokens + history_tokens) / ctx:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "sections": len(self._sections),
            "history_turns": len(self._history),
            "total_section_tokens": sum(s.effective_tokens for s in self._sections.values()),
            "models_configured": len(self._model_specs),
        }
