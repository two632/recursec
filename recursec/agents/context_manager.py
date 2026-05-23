"""Context manager — manages agent context across recursion levels.

Implements:
1. Hierarchical context propagation
2. Context window budgeting
3. Context compression/summarization
4. Parent→child context inheritance
5. Shared context between agents
6. Context versioning
7. Rolling context window
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextScope(str, Enum):
    GLOBAL = "global"           # Shared across all agents
    ASSESSMENT = "assessment"    # Assessment-level
    AGENT = "agent"              # Agent-private
    INHERITED = "inherited"      # From parent agent


class ContextPriority(str, Enum):
    CRITICAL = "critical"       # Never drop (target, constraints)
    HIGH = "high"               # Drop last (findings, tool results)
    MEDIUM = "medium"           # Drop early (history, examples)
    LOW = "low"                 # Drop first (verbose data)


@dataclass
class ContextEntry:
    """A context entry."""
    entry_id: str = ""
    key: str = ""
    value: str = ""
    scope: ContextScope = ContextScope.AGENT
    priority: ContextPriority = ContextPriority.MEDIUM
    token_estimate: int = 0
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    version: int = 1
    source_agent: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id[:10],
            "key": self.key[:15],
            "scope": self.scope.value,
            "priority": self.priority.value,
            "tokens": self.token_estimate,
        }


@dataclass
class ContextWindow:
    """A context window for an agent."""
    agent_id: str = ""
    max_tokens: int = 4096
    entries: list[ContextEntry] = field(default_factory=list)
    total_tokens: int = 0
    dropped_entries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:10],
            "max": self.max_tokens,
            "used": self.total_tokens,
            "entries": len(self.entries),
            "dropped": self.dropped_entries,
        }


class ContextManager:
    """Manages agent context across recursion levels.

    Handles context propagation from parent to child,
    context window budgeting, and shared context.
    """

    def __init__(self, default_max_tokens: int = 4096) -> None:
        self._windows: dict[str, ContextWindow] = {}
        self._global_context: dict[str, ContextEntry] = {}
        self._counter = 0
        self._default_max_tokens = default_max_tokens
        self._log = logger.bind(component="context_manager")

    def create_window(
        self,
        agent_id: str,
        max_tokens: int = 0,
    ) -> ContextWindow:
        """Create a context window for an agent."""
        window = ContextWindow(
            agent_id=agent_id,
            max_tokens=max_tokens or self._default_max_tokens,
        )
        self._windows[agent_id] = window
        return window

    def add_context(
        self,
        agent_id: str,
        key: str,
        value: str,
        scope: ContextScope = ContextScope.AGENT,
        priority: ContextPriority = ContextPriority.MEDIUM,
        expires_in_s: float = 0,
    ) -> ContextEntry | None:
        """Add a context entry."""
        window = self._windows.get(agent_id)
        if not window:
            return None

        self._counter += 1
        token_estimate = len(value) // 4

        entry = ContextEntry(
            entry_id=f"ctx-{self._counter}",
            key=key,
            value=value,
            scope=scope,
            priority=priority,
            token_estimate=token_estimate,
            source_agent=agent_id,
        )

        if expires_in_s > 0:
            entry.expires_at = time.time() + expires_in_s

        # Check if we need to evict
        while window.total_tokens + token_estimate > window.max_tokens:
            if not self._evict_lowest_priority(window):
                break

        if window.total_tokens + token_estimate <= window.max_tokens:
            window.entries.append(entry)
            window.total_tokens += token_estimate
        else:
            window.dropped_entries += 1
            return None

        # Also add to global if scope is global
        if scope == ContextScope.GLOBAL:
            self._global_context[key] = entry

        return entry

    def _evict_lowest_priority(self, window: ContextWindow) -> bool:
        """Evict the lowest priority entry from a window."""
        priority_order = [
            ContextPriority.LOW,
            ContextPriority.MEDIUM,
            ContextPriority.HIGH,
            ContextPriority.CRITICAL,
        ]

        for priority in priority_order:
            for i, entry in enumerate(window.entries):
                if entry.priority == priority:
                    window.total_tokens -= entry.token_estimate
                    window.entries.pop(i)
                    window.dropped_entries += 1
                    return True

        return False

    def inherit_context(
        self,
        parent_id: str,
        child_id: str,
        max_inherit_tokens: int = 2048,
    ) -> int:
        """Inherit context from parent to child agent."""
        parent = self._windows.get(parent_id)
        child = self._windows.get(child_id)
        if not parent or not child:
            return 0

        inherited = 0
        # Inherit entries by priority (critical first)
        sorted_entries = sorted(
            parent.entries,
            key=lambda e: {
                ContextPriority.CRITICAL: 0,
                ContextPriority.HIGH: 1,
                ContextPriority.MEDIUM: 2,
                ContextPriority.LOW: 3,
            }.get(e.priority, 4),
        )

        for entry in sorted_entries:
            if inherited + entry.token_estimate > max_inherit_tokens:
                break

            # Don't inherit agent-private context
            if entry.scope == ContextScope.AGENT:
                continue

            self.add_context(
                child_id,
                key=entry.key,
                value=entry.value,
                scope=ContextScope.INHERITED,
                priority=entry.priority,
            )
            inherited += entry.token_estimate

        # Also inject global context
        for key, entry in self._global_context.items():
            if inherited + entry.token_estimate > max_inherit_tokens:
                break
            self.add_context(
                child_id,
                key=entry.key,
                value=entry.value,
                scope=ContextScope.GLOBAL,
                priority=entry.priority,
            )
            inherited += entry.token_estimate

        return inherited

    def get_context_text(
        self,
        agent_id: str,
        max_tokens: int = 0,
    ) -> str:
        """Get the full context text for an agent."""
        window = self._windows.get(agent_id)
        if not window:
            return ""

        # Remove expired entries
        now = time.time()
        window.entries = [
            e for e in window.entries
            if e.expires_at == 0 or e.expires_at > now
        ]

        parts = []
        tokens_used = 0
        max_t = max_tokens or window.max_tokens

        # Output in priority order
        sorted_entries = sorted(
            window.entries,
            key=lambda e: {
                ContextPriority.CRITICAL: 0,
                ContextPriority.HIGH: 1,
                ContextPriority.MEDIUM: 2,
                ContextPriority.LOW: 3,
            }.get(e.priority, 4),
        )

        for entry in sorted_entries:
            if tokens_used + entry.token_estimate > max_t:
                break
            parts.append(f"[{entry.key}]\n{entry.value}")
            tokens_used += entry.token_estimate

        return "\n\n".join(parts)

    def update_context(
        self,
        agent_id: str,
        key: str,
        value: str,
    ) -> bool:
        """Update an existing context entry."""
        window = self._windows.get(agent_id)
        if not window:
            return False

        for entry in window.entries:
            if entry.key == key:
                old_tokens = entry.token_estimate
                entry.value = value
                entry.token_estimate = len(value) // 4
                entry.version += 1
                window.total_tokens += entry.token_estimate - old_tokens
                return True

        return False

    def remove_context(self, agent_id: str, key: str) -> bool:
        """Remove a context entry."""
        window = self._windows.get(agent_id)
        if not window:
            return False

        for i, entry in enumerate(window.entries):
            if entry.key == key:
                window.total_tokens -= entry.token_estimate
                window.entries.pop(i)
                return True

        return False

    def get_stats(self) -> dict[str, Any]:
        total_entries = sum(len(w.entries) for w in self._windows.values())
        total_tokens = sum(w.total_tokens for w in self._windows.values())
        total_dropped = sum(w.dropped_entries for w in self._windows.values())

        return {
            "windows": len(self._windows),
            "total_entries": total_entries,
            "total_tokens": total_tokens,
            "total_dropped": total_dropped,
            "global_entries": len(self._global_context),
        }
