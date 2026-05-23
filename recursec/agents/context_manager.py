"""Context manager — manages context propagation across recursion levels.

Handles:
- Context inheritance (parent → child agents)
- Context windowing (fitting relevant context into LLM context windows)
- Context prioritization (most relevant information first)
- Context compression (summarizing long contexts)
- Context isolation (preventing context leakage between tasks)
- Shared context (findings, knowledge) vs private context (tool outputs)
- Context versioning and diff tracking
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


@dataclass
class ContextEntry:
    """A single entry in the agent's context."""
    key: str
    content: str
    source: str = ""  # agent_id that produced this
    entry_type: str = "general"  # general, finding, tool_output, plan, summary
    priority: float = 0.5  # 0.0 = low, 1.0 = high
    token_estimate: int = 0
    timestamp: float = field(default_factory=time.time)
    depth: int = 0  # Recursion depth at which this was created
    is_shared: bool = True  # Can be inherited by child agents
    is_compressed: bool = False
    version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.token_estimate:
            self.token_estimate = len(self.content) // 4  # Rough estimate

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "content": self.content[:200],
            "source": self.source, "type": self.entry_type,
            "priority": self.priority, "tokens": self.token_estimate,
            "depth": self.depth, "shared": self.is_shared,
        }


@dataclass
class ContextWindow:
    """A windowed view of context that fits within a token budget."""
    entries: list[ContextEntry] = field(default_factory=list)
    total_tokens: int = 0
    max_tokens: int = 4096
    truncated_count: int = 0

    def to_text(self) -> str:
        """Convert to text for LLM consumption."""
        parts = []
        for entry in self.entries:
            if entry.entry_type == "finding":
                parts.append(f"[FINDING] {entry.content}")
            elif entry.entry_type == "tool_output":
                parts.append(f"[TOOL:{entry.source}] {entry.content}")
            elif entry.entry_type == "plan":
                parts.append(f"[PLAN] {entry.content}")
            elif entry.entry_type == "summary":
                parts.append(f"[SUMMARY] {entry.content}")
            else:
                parts.append(entry.content)
        return "\n\n".join(parts)

    def to_messages(self) -> list[dict[str, str]]:
        """Convert to chat message format."""
        messages = []
        for entry in self.entries:
            role = "system" if entry.entry_type in ("plan", "summary") else "user"
            messages.append({"role": role, "content": entry.content})
        return messages


class ContextManager:
    """Manages context for agents across recursion levels.

    The context manager is responsible for:
    1. Storing and organizing context entries
    2. Building context windows that fit within token budgets
    3. Propagating relevant context to child agents
    4. Compressing context when it exceeds limits
    5. Tracking context changes between iterations
    """

    PRIORITY_BOOST = {
        "finding": 0.3,       # Findings get priority boost
        "plan": 0.2,          # Plans are important
        "summary": 0.15,      # Summaries are useful
        "tool_output": 0.0,   # Tool outputs are baseline
        "general": -0.1,      # General context is lower priority
    }

    def __init__(
        self,
        agent_id: str,
        max_context_tokens: int = 8192,
        model_router: ModelRouter | None = None,
    ) -> None:
        self.agent_id = agent_id
        self._max_tokens = max_context_tokens
        self._router = model_router
        self._entries: dict[str, ContextEntry] = {}
        self._shared_entries: dict[str, ContextEntry] = {}  # Inherited from parent
        self._compressed_summaries: list[str] = []
        self._total_tokens = 0
        self._log = logger.bind(agent=agent_id, component="context_mgr")

    def add(
        self,
        key: str,
        content: str,
        entry_type: str = "general",
        priority: float = 0.5,
        source: str = "",
        depth: int = 0,
        is_shared: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a context entry."""
        entry = ContextEntry(
            key=key, content=content,
            source=source or self.agent_id,
            entry_type=entry_type,
            priority=priority + self.PRIORITY_BOOST.get(entry_type, 0),
            depth=depth, is_shared=is_shared,
            metadata=metadata or {},
        )

        # Update or add
        old = self._entries.get(key)
        if old:
            self._total_tokens -= old.token_estimate
            entry.version = old.version + 1

        self._entries[key] = entry
        self._total_tokens += entry.token_estimate

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a finding to context."""
        key = f"finding_{finding.get('id', hashlib.md5(json.dumps(finding, sort_keys=True).encode()).hexdigest()[:8])}"
        severity = finding.get("severity", "info")
        priority_map = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}
        self.add(
            key=key,
            content=json.dumps(finding),
            entry_type="finding",
            priority=priority_map.get(severity, 0.5),
        )

    def add_tool_output(self, tool_name: str, output: str, is_shared: bool = False) -> None:
        """Add tool output to context."""
        key = f"tool_{tool_name}_{int(time.time())}"
        self.add(
            key=key,
            content=output[:2000],
            entry_type="tool_output",
            source=tool_name,
            priority=0.4,
            is_shared=is_shared,
        )

    def add_plan(self, plan_text: str) -> None:
        """Add the current plan to context."""
        self.add(
            key="current_plan",
            content=plan_text,
            entry_type="plan",
            priority=0.8,
        )

    def remove(self, key: str) -> None:
        """Remove a context entry."""
        entry = self._entries.pop(key, None)
        if entry:
            self._total_tokens -= entry.token_estimate

    def get_window(
        self,
        max_tokens: int | None = None,
        entry_types: list[str] | None = None,
        min_priority: float = 0.0,
        include_shared: bool = True,
    ) -> ContextWindow:
        """Build a context window that fits within the token budget.

        Entries are selected by priority, with higher-priority entries
        included first until the token budget is exhausted.
        """
        budget = max_tokens or self._max_tokens
        window = ContextWindow(max_tokens=budget)

        # Collect all candidate entries
        candidates: list[ContextEntry] = []
        for entry in self._entries.values():
            if entry_types and entry.entry_type not in entry_types:
                continue
            if entry.priority < min_priority:
                continue
            candidates.append(entry)

        if include_shared:
            for entry in self._shared_entries.values():
                if entry_types and entry.entry_type not in entry_types:
                    continue
                candidates.append(entry)

        # Sort by priority (highest first), then by recency
        candidates.sort(key=lambda e: (-e.priority, -e.timestamp))

        # Fill window
        for entry in candidates:
            if window.total_tokens + entry.token_estimate <= budget:
                window.entries.append(entry)
                window.total_tokens += entry.token_estimate
            else:
                window.truncated_count += 1

        return window

    def get_for_child(self, child_depth: int) -> dict[str, ContextEntry]:
        """Get context entries to propagate to a child agent."""
        child_context: dict[str, ContextEntry] = {}

        for key, entry in self._entries.items():
            if not entry.is_shared:
                continue
            # Reduce priority for older entries at deeper levels
            adjusted_priority = entry.priority * (0.9 ** (child_depth - entry.depth))
            child_entry = ContextEntry(
                key=key, content=entry.content,
                source=entry.source, entry_type=entry.entry_type,
                priority=adjusted_priority, depth=entry.depth,
                is_shared=True, metadata=entry.metadata,
            )
            child_context[key] = child_entry

        return child_context

    def inherit_from_parent(self, parent_context: dict[str, ContextEntry]) -> None:
        """Inherit context from a parent agent."""
        self._shared_entries.update(parent_context)

    async def compress(self) -> None:
        """Compress context by summarizing long entries."""
        if not self._router or self._total_tokens <= self._max_tokens:
            return

        # Find entries that can be compressed
        compressible = sorted(
            [e for e in self._entries.values() if not e.is_compressed and e.token_estimate > 500],
            key=lambda e: e.priority,
        )

        for entry in compressible:
            if self._total_tokens <= self._max_tokens * 0.8:
                break

            try:
                summary = await self._summarize(entry.content)
                old_tokens = entry.token_estimate
                entry.content = summary
                entry.token_estimate = len(summary) // 4
                entry.is_compressed = True
                entry.version += 1
                self._total_tokens -= (old_tokens - entry.token_estimate)
                self._compressed_summaries.append(f"Compressed {entry.key}: saved {old_tokens - entry.token_estimate} tokens")
            except Exception as e:
                self._log.warning("compression_error", key=entry.key, error=str(e))

    async def _summarize(self, text: str) -> str:
        """Summarize text using LLM."""
        if not self._router:
            # Fallback: simple truncation
            return text[:500] + "..." if len(text) > 500 else text

        prompt = f"Summarize this security assessment data concisely, preserving all critical findings and technical details:\n\n{text[:4000]}"
        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="general",
            temperature=0.1,
            max_tokens=512,
        )
        return response

    def get_stats(self) -> dict[str, Any]:
        """Get context statistics."""
        by_type: dict[str, int] = defaultdict(int)
        for entry in self._entries.values():
            by_type[entry.entry_type] += 1
        return {
            "total_entries": len(self._entries),
            "shared_entries": len(self._shared_entries),
            "total_tokens": self._total_tokens,
            "max_tokens": self._max_tokens,
            "utilization": round(self._total_tokens / self._max_tokens * 100, 1) if self._max_tokens else 0,
            "by_type": dict(by_type),
            "compressions": len(self._compressed_summaries),
        }

    def clear(self) -> None:
        """Clear all context."""
        self._entries.clear()
        self._total_tokens = 0


class ContextPool:
    """Shared context pool across multiple agents.

    Allows agents to share findings, knowledge, and discoveries
    without direct message passing. Implements a publish-subscribe
    model where agents can subscribe to specific context types.
    """

    def __init__(self) -> None:
        self._pool: dict[str, ContextEntry] = {}
        self._subscribers: dict[str, set[str]] = defaultdict(set)  # entry_type → agent_ids
        self._notify_callbacks: dict[str, list[Any]] = defaultdict(list)

    def publish(self, entry: ContextEntry) -> None:
        """Publish a context entry to the pool."""
        self._pool[entry.key] = entry

        # Notify subscribers
        for agent_id in self._subscribers.get(entry.entry_type, set()):
            for callback in self._notify_callbacks.get(agent_id, []):
                try:
                    callback(entry)
                except Exception:
                    pass

    def subscribe(self, agent_id: str, entry_type: str) -> None:
        """Subscribe to context entries of a specific type."""
        self._subscribers[entry_type].add(agent_id)

    def get_entries(
        self,
        entry_type: str = "",
        min_priority: float = 0.0,
        limit: int = 50,
    ) -> list[ContextEntry]:
        """Get entries from the pool."""
        entries = list(self._pool.values())
        if entry_type:
            entries = [e for e in entries if e.entry_type == entry_type]
        entries = [e for e in entries if e.priority >= min_priority]
        entries.sort(key=lambda e: (-e.priority, -e.timestamp))
        return entries[:limit]

    def get_findings(self) -> list[ContextEntry]:
        """Get all findings from the pool."""
        return self.get_entries(entry_type="finding")

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        for entry in self._pool.values():
            by_type[entry.entry_type] += 1
        return {
            "total_entries": len(self._pool),
            "by_type": dict(by_type),
            "subscribers": {t: len(s) for t, s in self._subscribers.items()},
        }
