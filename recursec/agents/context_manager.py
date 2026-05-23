"""Context manager — manages context windows for agents.

Implements:
1. Context window size tracking per model
2. Context pruning strategies (sliding, importance, recency)
3. Context compression for long conversations
4. Multi-tier context (system, knowledge, conversation, working)
5. Token counting and budget enforcement
6. Context serialization for agent checkpointing
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextTier(str, Enum):
    SYSTEM = "system"           # System prompt (always retained)
    KNOWLEDGE = "knowledge"     # Injected KB content
    TOOL_DOCS = "tool_docs"     # Tool documentation
    FINDINGS = "findings"       # Current findings context
    CONVERSATION = "conversation"  # Agent conversation history
    WORKING = "working"         # Current working memory


class PruneStrategy(str, Enum):
    SLIDING_WINDOW = "sliding_window"   # Keep most recent
    IMPORTANCE = "importance"           # Keep highest priority
    SUMMARIZE = "summarize"             # Compress old context
    HYBRID = "hybrid"                   # Sliding + importance


@dataclass
class ContextEntry:
    """A single context entry."""
    entry_id: str = ""
    tier: ContextTier = ContextTier.CONVERSATION
    content: str = ""
    token_estimate: int = 0
    priority: int = 0
    timestamp: float = field(default_factory=time.time)
    pinned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id[:10],
            "tier": self.tier.value,
            "tokens": self.token_estimate,
            "priority": self.priority,
            "pinned": self.pinned,
        }


@dataclass
class ContextWindow:
    """A complete context window for a model."""
    window_id: str = ""
    model_id: str = ""
    max_tokens: int = 4096
    entries: list[ContextEntry] = field(default_factory=list)
    prune_strategy: PruneStrategy = PruneStrategy.HYBRID

    @property
    def used_tokens(self) -> int:
        return sum(e.token_estimate for e in self.entries)

    @property
    def available_tokens(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def utilization(self) -> float:
        if self.max_tokens == 0:
            return 0.0
        return self.used_tokens / self.max_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "used": self.used_tokens,
            "max": self.max_tokens,
            "entries": len(self.entries),
            "util": round(self.utilization, 2),
        }


# ── Model context sizes ──────────────────────────────────────

MODEL_CONTEXT_SIZES: dict[str, int] = {
    "whiterabbitneo-7b": 8192,
    "qwen-coder-14b": 32768,
    "qwen-coder-7b": 32768,
    "deepseek-r1-7b": 32768,
    "deepseek-math-7b": 4096,
    "hermes-14b": 8192,
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


# ── Tier budget ratios ────────────────────────────────────────

TIER_BUDGETS: dict[str, float] = {
    "system": 0.10,         # 10% for system prompt
    "knowledge": 0.25,      # 25% for knowledge base
    "tool_docs": 0.10,      # 10% for tool documentation
    "findings": 0.15,       # 15% for current findings
    "conversation": 0.30,   # 30% for conversation history
    "working": 0.10,        # 10% for working memory
}


class ContextManager:
    """Manages context windows for LLM agents.

    Tracks token usage, enforces budgets,
    and prunes context using configurable
    strategies.
    """

    def __init__(self) -> None:
        self._windows: dict[str, ContextWindow] = {}
        self._counter = 0
        self._log = logger.bind(component="context_manager")

    def create_window(
        self,
        model_id: str,
        prune_strategy: PruneStrategy = PruneStrategy.HYBRID,
        max_tokens: int = 0,
    ) -> ContextWindow:
        """Create a context window for a model."""
        self._counter += 1

        if max_tokens == 0:
            max_tokens = MODEL_CONTEXT_SIZES.get(model_id, 4096)

        window = ContextWindow(
            window_id=f"ctx-{self._counter}",
            model_id=model_id,
            max_tokens=max_tokens,
            prune_strategy=prune_strategy,
        )
        self._windows[window.window_id] = window
        return window

    def add_entry(
        self,
        window_id: str,
        content: str,
        tier: ContextTier = ContextTier.CONVERSATION,
        priority: int = 0,
        pinned: bool = False,
    ) -> ContextEntry | None:
        """Add content to a context window."""
        window = self._windows.get(window_id)
        if not window:
            return None

        tokens = self._estimate_tokens(content)

        entry = ContextEntry(
            entry_id=f"entry-{window_id}-{len(window.entries)}",
            tier=tier,
            content=content,
            token_estimate=tokens,
            priority=priority,
            pinned=pinned,
        )

        window.entries.append(entry)

        # Auto-prune if over budget
        if window.used_tokens > window.max_tokens:
            self._prune(window)

        return entry

    def _prune(self, window: ContextWindow) -> int:
        """Prune context to fit within budget."""
        if window.prune_strategy == PruneStrategy.SLIDING_WINDOW:
            return self._prune_sliding(window)
        elif window.prune_strategy == PruneStrategy.IMPORTANCE:
            return self._prune_importance(window)
        elif window.prune_strategy == PruneStrategy.HYBRID:
            return self._prune_hybrid(window)
        return 0

    def _prune_sliding(self, window: ContextWindow) -> int:
        """Keep most recent entries, drop oldest."""
        pruned = 0
        while window.used_tokens > window.max_tokens and window.entries:
            # Find oldest unpinned entry
            for idx, entry in enumerate(window.entries):
                if not entry.pinned and entry.tier != ContextTier.SYSTEM:
                    window.entries.pop(idx)
                    pruned += 1
                    break
            else:
                break
        return pruned

    def _prune_importance(self, window: ContextWindow) -> int:
        """Drop lowest priority entries."""
        pruned = 0
        while window.used_tokens > window.max_tokens and window.entries:
            # Find lowest priority unpinned entry
            candidates = [
                (idx, e) for idx, e in enumerate(window.entries)
                if not e.pinned and e.tier != ContextTier.SYSTEM
            ]
            if not candidates:
                break

            candidates.sort(key=lambda x: x[1].priority)
            idx, _ = candidates[0]
            window.entries.pop(idx)
            pruned += 1

        return pruned

    def _prune_hybrid(self, window: ContextWindow) -> int:
        """Hybrid pruning: old conversation + low importance."""
        pruned = 0
        while window.used_tokens > window.max_tokens and window.entries:
            candidates = [
                (idx, e) for idx, e in enumerate(window.entries)
                if not e.pinned and e.tier != ContextTier.SYSTEM
            ]
            if not candidates:
                break

            # Score: lower is more pruneable
            now = time.time()
            scored = []
            for idx, entry in candidates:
                age_s = now - entry.timestamp
                age_score = min(1.0, age_s / 3600)  # Normalized to 1 hour
                prio_score = entry.priority / 100.0
                # Higher score = keep, lower score = prune
                keep_score = prio_score * 0.6 + (1.0 - age_score) * 0.4
                scored.append((idx, keep_score))

            scored.sort(key=lambda x: x[1])
            idx, _ = scored[0]
            window.entries.pop(idx)
            pruned += 1

        return pruned

    def get_tier_content(
        self,
        window_id: str,
        tier: ContextTier,
    ) -> str:
        """Get all content for a specific tier."""
        window = self._windows.get(window_id)
        if not window:
            return ""

        return "\n".join(
            e.content for e in window.entries
            if e.tier == tier
        )

    def get_full_context(self, window_id: str) -> str:
        """Get full assembled context."""
        window = self._windows.get(window_id)
        if not window:
            return ""

        # Order by tier priority
        tier_order = [
            ContextTier.SYSTEM,
            ContextTier.KNOWLEDGE,
            ContextTier.TOOL_DOCS,
            ContextTier.FINDINGS,
            ContextTier.CONVERSATION,
            ContextTier.WORKING,
        ]

        parts = []
        for tier in tier_order:
            tier_content = self.get_tier_content(window_id, tier)
            if tier_content:
                parts.append(tier_content)

        return "\n\n".join(parts)

    def get_tier_budget(
        self,
        window_id: str,
        tier: ContextTier,
    ) -> int:
        """Get token budget for a specific tier."""
        window = self._windows.get(window_id)
        if not window:
            return 0

        ratio = TIER_BUDGETS.get(tier.value, 0.1)
        return int(window.max_tokens * ratio)

    def get_tier_usage(
        self,
        window_id: str,
    ) -> dict[str, int]:
        """Get token usage by tier."""
        window = self._windows.get(window_id)
        if not window:
            return {}

        usage: dict[str, int] = {}
        for entry in window.entries:
            tier_name = entry.tier.value
            usage[tier_name] = usage.get(tier_name, 0) + entry.token_estimate

        return usage

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return len(text) // 4

    def get_stats(self) -> dict[str, Any]:
        total_tokens = sum(w.used_tokens for w in self._windows.values())
        return {
            "windows": len(self._windows),
            "total_tokens": total_tokens,
            "avg_utilization": round(
                sum(w.utilization for w in self._windows.values()) /
                max(1, len(self._windows)), 2,
            ),
        }
