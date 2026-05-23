"""Context memory manager — multi-tier memory system.

Implements:
1. Working memory (current task context)
2. Episodic memory (past interactions/findings)
3. Semantic memory (learned concepts)
4. Procedural memory (learned tool usage patterns)
5. Memory consolidation (working → long-term)
6. Memory retrieval with relevance scoring
7. Memory compression for token efficiency
8. Cross-session memory persistence
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    WORKING = "working"       # Current task context, volatile
    EPISODIC = "episodic"     # Past events and interactions
    SEMANTIC = "semantic"     # Learned facts and concepts
    PROCEDURAL = "procedural"  # Learned procedures and patterns


class MemoryPriority(str, Enum):
    CRITICAL = "critical"     # Always keep (e.g., confirmed vulns)
    HIGH = "high"             # Keep unless under pressure
    NORMAL = "normal"         # Standard retention
    LOW = "low"               # First to evict


@dataclass
class MemoryEntry:
    """A single memory entry."""
    memory_id: str = ""
    memory_type: MemoryType = MemoryType.WORKING
    priority: MemoryPriority = MemoryPriority.NORMAL
    content: str = ""
    summary: str = ""         # Compressed version
    tags: list[str] = field(default_factory=list)
    source: str = ""          # What created this memory
    relevance: float = 1.0    # Current relevance score
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = 0.0
    expires_at: float = 0.0   # 0 = never expires
    token_estimate: int = 0

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id[:10],
            "type": self.memory_type.value,
            "priority": self.priority.value,
            "content_len": len(self.content),
            "tags": self.tags[:3],
            "relevance": round(self.relevance, 2),
            "accesses": self.access_count,
            "tokens": self.token_estimate,
        }


@dataclass
class WorkingMemory:
    """Current task context — volatile, limited capacity."""
    target: str = ""
    goal: str = ""
    current_phase: str = ""
    recent_findings: list[dict[str, Any]] = field(default_factory=list)
    recent_tool_outputs: list[dict[str, Any]] = field(default_factory=list)
    active_hypotheses: list[str] = field(default_factory=list)
    current_strategy: str = ""
    conversation: list[dict[str, str]] = field(default_factory=list)
    token_usage: int = 0
    max_tokens: int = 4096

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.recent_findings.append(finding)
        # Keep bounded
        if len(self.recent_findings) > 20:
            self.recent_findings = self.recent_findings[-20:]

    def add_tool_output(self, output: dict[str, Any]) -> None:
        self.recent_tool_outputs.append(output)
        if len(self.recent_tool_outputs) > 10:
            self.recent_tool_outputs = self.recent_tool_outputs[-10:]

    def add_message(self, role: str, content: str) -> None:
        self.conversation.append({"role": role, "content": content})
        if len(self.conversation) > 50:
            self.conversation = self.conversation[-50:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "phase": self.current_phase[:10],
            "findings": len(self.recent_findings),
            "tool_outputs": len(self.recent_tool_outputs),
            "hypotheses": len(self.active_hypotheses),
            "conversation": len(self.conversation),
            "tokens": self.token_usage,
        }


class ContextMemoryManager:
    """Multi-tier memory system for the agent.

    Manages working memory (volatile, current task),
    episodic memory (past events), semantic memory
    (learned knowledge), and procedural memory
    (learned patterns).
    """

    def __init__(
        self,
        max_working_tokens: int = 4096,
        max_episodic: int = 1000,
        max_semantic: int = 500,
        max_procedural: int = 200,
    ) -> None:
        self._working = WorkingMemory(max_tokens=max_working_tokens)
        self._entries: dict[str, MemoryEntry] = {}
        self._counter = 0
        self._limits = {
            MemoryType.EPISODIC: max_episodic,
            MemoryType.SEMANTIC: max_semantic,
            MemoryType.PROCEDURAL: max_procedural,
        }
        self._log = logger.bind(component="context_memory")

    @property
    def working(self) -> WorkingMemory:
        return self._working

    def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.EPISODIC,
        priority: MemoryPriority = MemoryPriority.NORMAL,
        tags: list[str] | None = None,
        source: str = "",
        summary: str = "",
        ttl_s: float = 0.0,
    ) -> MemoryEntry:
        """Store a new memory."""
        self._counter += 1

        content_hash = hashlib.md5(content[:200].encode()).hexdigest()[:8]
        entry = MemoryEntry(
            memory_id=f"mem-{self._counter}-{content_hash}",
            memory_type=memory_type,
            priority=priority,
            content=content,
            summary=summary or content[:100],
            tags=tags or [],
            source=source,
            relevance=1.0,
            token_estimate=len(content) // 4,
            expires_at=time.time() + ttl_s if ttl_s > 0 else 0.0,
        )

        self._entries[entry.memory_id] = entry

        # Enforce limits
        self._enforce_limits(memory_type)

        return entry

    def retrieve(
        self,
        query: str = "",
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        top_k: int = 10,
    ) -> list[MemoryEntry]:
        """Retrieve relevant memories."""
        candidates = []

        for entry in self._entries.values():
            if entry.is_expired:
                continue
            if memory_type and entry.memory_type != memory_type:
                continue
            if tags:
                if not any(t in entry.tags for t in tags):
                    continue

            # Simple relevance scoring
            score = entry.relevance
            if query:
                # Term overlap scoring
                query_terms = set(query.lower().split())
                content_terms = set(entry.content.lower().split()[:50])
                overlap = len(query_terms & content_terms)
                score *= (1 + overlap * 0.1)

            # Recency boost
            age_hours = entry.age_s / 3600
            recency_boost = 1.0 / (1 + age_hours * 0.1)
            score *= recency_boost

            # Priority boost
            priority_multiplier = {
                MemoryPriority.CRITICAL: 2.0,
                MemoryPriority.HIGH: 1.5,
                MemoryPriority.NORMAL: 1.0,
                MemoryPriority.LOW: 0.5,
            }
            score *= priority_multiplier.get(entry.priority, 1.0)

            candidates.append((score, entry))

        candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        for _, entry in candidates[:top_k]:
            entry.access_count += 1
            entry.last_accessed = time.time()
            results.append(entry)

        return results

    def consolidate(self) -> int:
        """Consolidate working memory into episodic/semantic.

        Moves important working memory items into long-term
        storage and compresses them.
        """
        consolidated = 0

        # Store significant findings
        for finding in self._working.recent_findings:
            severity = finding.get("severity", "info")
            if severity in ("critical", "high"):
                self.store(
                    content=str(finding),
                    memory_type=MemoryType.EPISODIC,
                    priority=MemoryPriority.HIGH,
                    tags=["finding", severity],
                    source="consolidation",
                )
                consolidated += 1

        return consolidated

    def compress(self, memory_id: str) -> bool:
        """Compress a memory entry (replace content with summary)."""
        entry = self._entries.get(memory_id)
        if not entry:
            return False

        if entry.summary and len(entry.summary) < len(entry.content):
            entry.content = entry.summary
            entry.token_estimate = len(entry.content) // 4
            return True

        return False

    def forget(self, memory_id: str) -> bool:
        """Explicitly forget a memory."""
        return self._entries.pop(memory_id, None) is not None

    def cleanup_expired(self) -> int:
        """Remove expired memories."""
        expired = [
            mid for mid, entry in self._entries.items()
            if entry.is_expired
        ]
        for mid in expired:
            del self._entries[mid]
        return len(expired)

    def _enforce_limits(self, memory_type: MemoryType) -> None:
        """Evict lowest-priority memories when over limit."""
        limit = self._limits.get(memory_type, 1000)
        entries_of_type = [
            (mid, entry) for mid, entry in self._entries.items()
            if entry.memory_type == memory_type
        ]

        if len(entries_of_type) <= limit:
            return

        # Sort by eviction priority (low priority, low relevance, old)
        entries_of_type.sort(key=lambda x: (
            {"critical": 3, "high": 2, "normal": 1, "low": 0}[x[1].priority.value],
            x[1].relevance,
            -x[1].age_s,
        ))

        # Evict from the bottom
        to_evict = len(entries_of_type) - limit
        for mid, _ in entries_of_type[:to_evict]:
            del self._entries[mid]

    def build_context_string(
        self,
        query: str = "",
        max_tokens: int = 2000,
        include_working: bool = True,
    ) -> str:
        """Build a context string for LLM consumption."""
        parts = []
        token_budget = max_tokens

        if include_working:
            wm = self._working
            if wm.target:
                parts.append(f"Target: {wm.target}")
            if wm.goal:
                parts.append(f"Goal: {wm.goal}")
            if wm.current_phase:
                parts.append(f"Phase: {wm.current_phase}")
            if wm.current_strategy:
                parts.append(f"Strategy: {wm.current_strategy}")

            # Recent findings summary
            if wm.recent_findings:
                findings_text = "\n".join(
                    f"- [{f.get('severity', 'info')}] {f.get('title', 'unknown')}"
                    for f in wm.recent_findings[-5:]
                )
                parts.append(f"Recent findings:\n{findings_text}")

            working_text = "\n".join(parts)
            working_tokens = len(working_text) // 4
            token_budget -= working_tokens

        # Retrieve relevant long-term memories
        memories = self.retrieve(query=query, top_k=10)
        memory_parts = []
        for mem in memories:
            text = mem.summary or mem.content[:200]
            tokens = len(text) // 4
            if tokens > token_budget:
                break
            memory_parts.append(f"[{mem.memory_type.value}] {text}")
            token_budget -= tokens

        if memory_parts:
            parts.append("Relevant memories:\n" + "\n".join(memory_parts))

        return "\n\n".join(parts)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        priority_counts: dict[str, int] = defaultdict(int)
        total_tokens = 0

        for entry in self._entries.values():
            type_counts[entry.memory_type.value] += 1
            priority_counts[entry.priority.value] += 1
            total_tokens += entry.token_estimate

        return {
            "total_memories": len(self._entries),
            "total_tokens": total_tokens,
            "working_memory": self._working.to_dict(),
            "by_type": dict(type_counts),
            "by_priority": dict(priority_counts),
        }
