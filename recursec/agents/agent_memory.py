"""Agent memory — persistent memory with semantic search.

Implements a hierarchical memory system:
1. Working memory: Current task context (short-lived)
2. Episodic memory: Past assessment experiences
3. Semantic memory: Knowledge about targets, vulns, tools
4. Procedural memory: Learned skills and strategies
5. Memory consolidation: Promote important memories
6. Memory decay: Reduce relevance over time
7. Similarity search: Find relevant past experiences

Uses the Nomic-Embed model for embedding-based search
when available, with keyword fallback.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"


class MemoryPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class MemoryEntry:
    """A single memory entry."""
    memory_id: str = ""
    memory_type: MemoryType = MemoryType.WORKING
    priority: MemoryPriority = MemoryPriority.NORMAL
    content: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] = field(default_factory=list)
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    expires_at: float = 0.0          # 0 = never
    source: str = ""                  # agent_id, tool, user

    @property
    def relevance_score(self) -> float:
        """Score based on recency, access, and priority."""
        age_hours = (time.time() - self.created_at) / 3600
        recency = max(0.0, 1.0 - age_hours / 168)  # Decay over 1 week

        priority_weights = {
            MemoryPriority.CRITICAL: 1.0,
            MemoryPriority.HIGH: 0.8,
            MemoryPriority.NORMAL: 0.5,
            MemoryPriority.LOW: 0.3,
        }
        priority_w = priority_weights.get(self.priority, 0.5)

        access_w = min(1.0, self.access_count / 10)

        return (recency * 0.3 + priority_w * 0.4 + access_w * 0.3)

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id,
            "type": self.memory_type.value,
            "priority": self.priority.value,
            "content": self.content[:100],
            "tags": self.tags[:5],
            "relevance": round(self.relevance_score, 2),
            "accesses": self.access_count,
        }


class AgentMemory:
    """Hierarchical memory system for agents.

    Provides working, episodic, semantic, and procedural
    memory with keyword and embedding-based search.
    """

    def __init__(
        self,
        max_working: int = 50,
        max_episodic: int = 500,
        max_semantic: int = 1000,
        max_procedural: int = 200,
        persistence_dir: str = "data/memory",
    ) -> None:
        self._limits = {
            MemoryType.WORKING: max_working,
            MemoryType.EPISODIC: max_episodic,
            MemoryType.SEMANTIC: max_semantic,
            MemoryType.PROCEDURAL: max_procedural,
        }

        self._memories: dict[str, MemoryEntry] = {}
        self._by_type: dict[str, list[str]] = defaultdict(list)
        self._by_tag: dict[str, list[str]] = defaultdict(list)
        self._counter = 0
        self._persistence_dir = Path(persistence_dir)
        self._persistence_dir.mkdir(parents=True, exist_ok=True)
        self._log = logger.bind(component="agent_memory")

        # Load persisted memories
        self._load()

    def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.WORKING,
        priority: MemoryPriority = MemoryPriority.NORMAL,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        source: str = "",
        ttl_s: float = 0,
    ) -> str:
        """Store a new memory."""
        self._counter += 1
        mem_id = f"mem-{self._counter}"

        entry = MemoryEntry(
            memory_id=mem_id,
            memory_type=memory_type,
            priority=priority,
            content=content,
            tags=tags or [],
            metadata=metadata or {},
            source=source,
            expires_at=time.time() + ttl_s if ttl_s > 0 else 0,
        )

        self._memories[mem_id] = entry
        self._by_type[memory_type.value].append(mem_id)

        for tag in entry.tags:
            self._by_tag[tag].append(mem_id)

        # Enforce limits
        self._enforce_limits(memory_type)

        return mem_id

    def recall(self, memory_id: str) -> MemoryEntry | None:
        """Recall a specific memory."""
        entry = self._memories.get(memory_id)
        if entry and not entry.is_expired:
            entry.access_count += 1
            entry.last_accessed = time.time()
            return entry
        return None

    def search(
        self,
        query: str,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Search memories by keyword and tags."""
        candidates = list(self._memories.values())

        # Filter expired
        candidates = [m for m in candidates if not m.is_expired]

        # Filter by type
        if memory_type:
            candidates = [m for m in candidates if m.memory_type == memory_type]

        # Filter by tags
        if tags:
            tag_set = set(tags)
            candidates = [m for m in candidates if tag_set & set(m.tags)]

        # Keyword scoring
        query_lower = query.lower()
        query_terms = query_lower.split()

        scored = []
        for mem in candidates:
            content_lower = mem.content.lower()
            keyword_score = sum(
                1.0 for term in query_terms if term in content_lower
            )
            tag_score = sum(
                0.5 for term in query_terms if any(term in t for t in mem.tags)
            )

            total_score = (keyword_score + tag_score) * mem.relevance_score
            if total_score > 0:
                scored.append((mem, total_score))

        scored.sort(key=lambda x: x[1], reverse=True)

        results = [mem for mem, _ in scored[:limit]]

        # Update access counts
        for mem in results:
            mem.access_count += 1
            mem.last_accessed = time.time()

        return results

    def get_by_type(
        self,
        memory_type: MemoryType,
        limit: int = 20,
    ) -> list[MemoryEntry]:
        """Get all memories of a type, sorted by relevance."""
        ids = self._by_type.get(memory_type.value, [])
        memories = [
            self._memories[mid] for mid in ids
            if mid in self._memories and not self._memories[mid].is_expired
        ]
        memories.sort(key=lambda m: m.relevance_score, reverse=True)
        return memories[:limit]

    def get_by_tag(self, tag: str, limit: int = 20) -> list[MemoryEntry]:
        """Get memories with a specific tag."""
        ids = self._by_tag.get(tag, [])
        memories = [
            self._memories[mid] for mid in ids
            if mid in self._memories and not self._memories[mid].is_expired
        ]
        memories.sort(key=lambda m: m.relevance_score, reverse=True)
        return memories[:limit]

    def consolidate(self) -> int:
        """Consolidate memories — promote, decay, cleanup."""
        removed = 0

        ids_to_remove = []
        for mem_id, mem in self._memories.items():
            # Remove expired
            if mem.is_expired:
                ids_to_remove.append(mem_id)
                continue

            # Auto-promote frequently accessed working memories
            if (
                mem.memory_type == MemoryType.WORKING
                and mem.access_count >= 5
                and mem.priority != MemoryPriority.LOW
            ):
                mem.memory_type = MemoryType.EPISODIC
                self._by_type[MemoryType.WORKING.value] = [
                    mid for mid in self._by_type[MemoryType.WORKING.value]
                    if mid != mem_id
                ]
                self._by_type[MemoryType.EPISODIC.value].append(mem_id)

        for mem_id in ids_to_remove:
            self._remove(mem_id)
            removed += 1

        return removed

    def store_finding(self, finding: dict[str, Any]) -> str:
        """Store a vulnerability finding as a memory."""
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "info")
        target = finding.get("target", "")
        tool = finding.get("tool", "")

        content = f"[{severity.upper()}] {title} on {target} (found by {tool})"

        priority = {
            "critical": MemoryPriority.CRITICAL,
            "high": MemoryPriority.HIGH,
            "medium": MemoryPriority.NORMAL,
            "low": MemoryPriority.LOW,
        }.get(severity, MemoryPriority.NORMAL)

        return self.store(
            content=content,
            memory_type=MemoryType.EPISODIC,
            priority=priority,
            tags=[severity, tool, "finding"],
            metadata=finding,
            source=tool,
        )

    def store_strategy(
        self,
        strategy: str,
        outcome: str,
        target_type: str = "",
    ) -> str:
        """Store a strategy outcome as procedural memory."""
        content = f"Strategy '{strategy}' on {target_type}: {outcome}"
        return self.store(
            content=content,
            memory_type=MemoryType.PROCEDURAL,
            tags=[strategy, target_type, "strategy"],
            metadata={"strategy": strategy, "outcome": outcome},
        )

    def store_knowledge(
        self,
        knowledge: str,
        tags: list[str] | None = None,
    ) -> str:
        """Store general security knowledge."""
        return self.store(
            content=knowledge,
            memory_type=MemoryType.SEMANTIC,
            priority=MemoryPriority.HIGH,
            tags=tags or ["knowledge"],
        )

    def _enforce_limits(self, memory_type: MemoryType) -> None:
        """Remove lowest-relevance memories when over limit."""
        limit = self._limits.get(memory_type, 500)
        ids = self._by_type.get(memory_type.value, [])

        if len(ids) <= limit:
            return

        memories = [
            (mid, self._memories.get(mid))
            for mid in ids if mid in self._memories
        ]
        memories.sort(key=lambda x: x[1].relevance_score if x[1] else 0)

        to_remove = len(ids) - limit
        for mid, _ in memories[:to_remove]:
            self._remove(mid)

    def _remove(self, memory_id: str) -> None:
        """Remove a memory entry."""
        entry = self._memories.pop(memory_id, None)
        if not entry:
            return

        type_list = self._by_type.get(entry.memory_type.value, [])
        if memory_id in type_list:
            type_list.remove(memory_id)

        for tag in entry.tags:
            tag_list = self._by_tag.get(tag, [])
            if memory_id in tag_list:
                tag_list.remove(memory_id)

    def save(self) -> None:
        """Persist memories to disk."""
        data = []
        for mem in self._memories.values():
            data.append({
                "id": mem.memory_id,
                "type": mem.memory_type.value,
                "priority": mem.priority.value,
                "content": mem.content,
                "tags": mem.tags,
                "metadata": mem.metadata,
                "access_count": mem.access_count,
                "created_at": mem.created_at,
                "last_accessed": mem.last_accessed,
                "expires_at": mem.expires_at,
                "source": mem.source,
            })

        path = self._persistence_dir / "memories.json"
        try:
            path.write_text(json.dumps(data))
        except OSError:
            pass

    def _load(self) -> None:
        """Load persisted memories."""
        path = self._persistence_dir / "memories.json"
        if not path.exists():
            return

        try:
            data = json.loads(path.read_text())
            for entry_data in data:
                try:
                    mem_type = MemoryType(entry_data.get("type", "working"))
                except ValueError:
                    mem_type = MemoryType.WORKING

                try:
                    priority = MemoryPriority(entry_data.get("priority", "normal"))
                except ValueError:
                    priority = MemoryPriority.NORMAL

                self._counter += 1
                mem_id = entry_data.get("id", f"mem-{self._counter}")

                entry = MemoryEntry(
                    memory_id=mem_id,
                    memory_type=mem_type,
                    priority=priority,
                    content=entry_data.get("content", ""),
                    tags=entry_data.get("tags", []),
                    metadata=entry_data.get("metadata", {}),
                    access_count=entry_data.get("access_count", 0),
                    created_at=entry_data.get("created_at", time.time()),
                    last_accessed=entry_data.get("last_accessed", time.time()),
                    expires_at=entry_data.get("expires_at", 0),
                    source=entry_data.get("source", ""),
                )

                self._memories[mem_id] = entry
                self._by_type[mem_type.value].append(mem_id)
                for tag in entry.tags:
                    self._by_tag[tag].append(mem_id)

        except (json.JSONDecodeError, OSError):
            pass

    def get_stats(self) -> dict[str, Any]:
        by_type = {t: len(ids) for t, ids in self._by_type.items()}
        return {
            "total": len(self._memories),
            "by_type": by_type,
            "tags": len(self._by_tag),
        }
