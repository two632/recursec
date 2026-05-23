"""Context manager — manages LLM context windows across agent hierarchy.

Implements:
1. Context window allocation per agent
2. Context compression when approaching limits
3. Priority-based content selection
4. Hierarchical context inheritance (parent → child)
5. Context summarization for long conversations
6. Token counting and budget tracking
7. Sliding window with importance scoring
8. Context snapshot and restore
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContentPriority(str, Enum):
    CRITICAL = "critical"       # System prompt, current task — never evict
    HIGH = "high"               # Recent tool outputs, findings
    MEDIUM = "medium"           # Earlier observations, context
    LOW = "low"                 # Background info, history
    EPHEMERAL = "ephemeral"     # Can be dropped anytime


@dataclass
class ContextEntry:
    """A single entry in the context window."""
    entry_id: str = ""
    content: str = ""
    role: str = "system"          # system, user, assistant, tool
    priority: ContentPriority = ContentPriority.MEDIUM
    token_count: int = 0
    source: str = ""              # Which agent/tool produced this
    timestamp: float = field(default_factory=time.time)
    access_count: int = 0
    is_summary: bool = False      # Was this summarized from longer content?

    @property
    def importance_score(self) -> float:
        """Dynamic importance based on priority, recency, and access."""
        priority_weights = {
            ContentPriority.CRITICAL: 10.0,
            ContentPriority.HIGH: 5.0,
            ContentPriority.MEDIUM: 2.0,
            ContentPriority.LOW: 1.0,
            ContentPriority.EPHEMERAL: 0.5,
        }
        base = priority_weights.get(self.priority, 1.0)

        # Recency boost (decays over 10 minutes)
        age = time.time() - self.timestamp
        recency = max(0.1, 1.0 - age / 600.0)

        # Access boost
        access_boost = min(2.0, 1.0 + self.access_count * 0.1)

        return base * recency * access_boost

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id,
            "role": self.role,
            "priority": self.priority.value,
            "tokens": self.token_count,
            "importance": round(self.importance_score, 2),
            "source": self.source[:20],
        }


@dataclass
class ContextWindow:
    """A managed context window."""
    window_id: str = ""
    agent_id: str = ""
    max_tokens: int = 4096
    entries: list[ContextEntry] = field(default_factory=list)
    total_tokens: int = 0
    eviction_count: int = 0
    compression_count: int = 0

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.total_tokens)

    @property
    def utilization(self) -> float:
        if self.max_tokens == 0:
            return 0.0
        return self.total_tokens / self.max_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.window_id,
            "agent": self.agent_id[:20],
            "tokens": self.total_tokens,
            "max": self.max_tokens,
            "entries": len(self.entries),
            "util_pct": round(self.utilization * 100, 1),
        }


class ContextManager:
    """Manages LLM context windows across the agent hierarchy.

    Handles token budgeting, priority-based eviction,
    compression, and hierarchical context inheritance.
    """

    def __init__(self, default_max_tokens: int = 4096) -> None:
        self._windows: dict[str, ContextWindow] = {}
        self._window_counter = 0
        self._entry_counter = 0
        self._default_max = default_max_tokens
        self._log = logger.bind(component="context_manager")

    def create_window(
        self,
        agent_id: str,
        max_tokens: int = 0,
    ) -> ContextWindow:
        """Create a context window for an agent."""
        self._window_counter += 1
        window = ContextWindow(
            window_id=f"ctx-{self._window_counter}",
            agent_id=agent_id,
            max_tokens=max_tokens or self._default_max,
        )
        self._windows[window.window_id] = window
        return window

    def add(
        self,
        window_id: str,
        content: str,
        role: str = "system",
        priority: ContentPriority = ContentPriority.MEDIUM,
        source: str = "",
    ) -> ContextEntry | None:
        """Add content to a context window."""
        window = self._windows.get(window_id)
        if not window:
            return None

        token_count = self._estimate_tokens(content)

        # Check if we need to make room
        while window.total_tokens + token_count > window.max_tokens:
            if not self._evict_lowest(window):
                break

        # Still too big? Truncate
        if window.total_tokens + token_count > window.max_tokens:
            available = window.remaining_tokens
            if available < 50:
                return None
            content = content[:available * 4]  # ~4 chars per token
            token_count = self._estimate_tokens(content)

        self._entry_counter += 1
        entry = ContextEntry(
            entry_id=f"ce-{self._entry_counter}",
            content=content,
            role=role,
            priority=priority,
            token_count=token_count,
            source=source,
        )

        window.entries.append(entry)
        window.total_tokens += token_count

        return entry

    def get_context(
        self,
        window_id: str,
        max_tokens: int = 0,
    ) -> list[dict[str, str]]:
        """Get the context as a list of messages."""
        window = self._windows.get(window_id)
        if not window:
            return []

        entries = window.entries
        if max_tokens > 0:
            # Take highest-importance entries that fit
            sorted_entries = sorted(entries, key=lambda e: e.importance_score, reverse=True)
            selected = []
            used = 0
            for entry in sorted_entries:
                if used + entry.token_count <= max_tokens:
                    selected.append(entry)
                    used += entry.token_count
                    entry.access_count += 1

            # Re-sort by timestamp for correct ordering
            selected.sort(key=lambda e: e.timestamp)
            entries = selected

        return [{"role": e.role, "content": e.content} for e in entries]

    def compress(self, window_id: str) -> int:
        """Compress the context by summarizing old entries."""
        window = self._windows.get(window_id)
        if not window:
            return 0

        # Find low-priority entries that can be compressed
        compressible = [
            e for e in window.entries
            if e.priority in (ContentPriority.LOW, ContentPriority.EPHEMERAL)
            and not e.is_summary and e.token_count > 50
        ]

        tokens_saved = 0
        for entry in compressible:
            # Simple compression: truncate to ~25% of original
            original_tokens = entry.token_count
            compressed_len = len(entry.content) // 4
            entry.content = entry.content[:compressed_len] + "..."
            entry.token_count = self._estimate_tokens(entry.content)
            entry.is_summary = True

            saved = original_tokens - entry.token_count
            tokens_saved += saved
            window.total_tokens -= saved

        window.compression_count += 1
        return tokens_saved

    def inherit(
        self,
        parent_window_id: str,
        child_window_id: str,
        max_inherit_tokens: int = 1024,
    ) -> int:
        """Inherit context from parent to child window."""
        parent = self._windows.get(parent_window_id)
        child = self._windows.get(child_window_id)
        if not parent or not child:
            return 0

        # Get highest-priority entries from parent
        sorted_entries = sorted(
            parent.entries,
            key=lambda e: e.importance_score,
            reverse=True,
        )

        inherited = 0
        for entry in sorted_entries:
            if inherited + entry.token_count > max_inherit_tokens:
                continue

            self.add(
                child_window_id,
                content=entry.content,
                role=entry.role,
                priority=entry.priority,
                source=f"inherited:{entry.source}",
            )
            inherited += entry.token_count

        return inherited

    def _evict_lowest(self, window: ContextWindow) -> bool:
        """Evict the lowest-importance entry."""
        if not window.entries:
            return False

        # Never evict CRITICAL entries
        evictable = [
            (i, e) for i, e in enumerate(window.entries)
            if e.priority != ContentPriority.CRITICAL
        ]

        if not evictable:
            return False

        # Find lowest importance
        min_idx, min_entry = min(evictable, key=lambda x: x[1].importance_score)
        window.entries.pop(min_idx)
        window.total_tokens -= min_entry.token_count
        window.eviction_count += 1
        return True

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return max(1, len(text) // 4)

    def snapshot(self, window_id: str) -> dict[str, Any]:
        """Snapshot a context window for later restore."""
        window = self._windows.get(window_id)
        if not window:
            return {}

        return {
            "window_id": window.window_id,
            "agent_id": window.agent_id,
            "max_tokens": window.max_tokens,
            "entries": [
                {
                    "content": e.content,
                    "role": e.role,
                    "priority": e.priority.value,
                    "source": e.source,
                    "tokens": e.token_count,
                }
                for e in window.entries
            ],
        }

    def restore(self, snapshot: dict[str, Any]) -> str:
        """Restore a context window from a snapshot."""
        window = self.create_window(
            agent_id=snapshot.get("agent_id", ""),
            max_tokens=snapshot.get("max_tokens", self._default_max),
        )

        for entry_data in snapshot.get("entries", []):
            self.add(
                window.window_id,
                content=entry_data.get("content", ""),
                role=entry_data.get("role", "system"),
                priority=ContentPriority(entry_data.get("priority", "medium")),
                source=entry_data.get("source", "restored"),
            )

        return window.window_id

    def get_stats(self) -> dict[str, Any]:
        total_tokens = sum(w.total_tokens for w in self._windows.values())
        total_evictions = sum(w.eviction_count for w in self._windows.values())
        return {
            "windows": len(self._windows),
            "total_tokens": total_tokens,
            "total_entries": self._entry_counter,
            "total_evictions": total_evictions,
        }
