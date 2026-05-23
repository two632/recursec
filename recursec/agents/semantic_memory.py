"""Semantic memory — long-term knowledge store.

Implements:
1. Fact storage with semantic tagging
2. Pattern consolidation from episodes
3. Cross-assessment knowledge transfer
4. Decay-based relevance scoring
5. Memory retrieval by similarity
6. Knowledge graph triplets
7. Procedural knowledge (how-to) storage
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    FACT = "fact"                     # Declarative knowledge
    PATTERN = "pattern"               # Recurring patterns
    PROCEDURE = "procedure"           # How-to knowledge
    ASSOCIATION = "association"        # Related concepts
    HEURISTIC = "heuristic"          # Rules of thumb


class MemorySource(str, Enum):
    OBSERVATION = "observation"       # From tool output
    REASONING = "reasoning"           # From LLM reasoning
    CONSOLIDATION = "consolidation"   # From episode consolidation
    INJECTION = "injection"           # From knowledge base
    USER = "user"                     # From user input


@dataclass
class MemoryEntry:
    """A semantic memory entry."""
    entry_id: str = ""
    content: str = ""
    memory_type: MemoryType = MemoryType.FACT
    source: MemorySource = MemorySource.OBSERVATION
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.5
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    related_entries: list[str] = field(default_factory=list)

    @property
    def relevance_score(self) -> float:
        """Decay-based relevance score."""
        age_hours = (time.time() - self.last_accessed) / 3600
        recency = math.exp(-0.01 * age_hours)
        frequency = min(1.0, self.access_count / 10)
        return self.confidence * 0.4 + recency * 0.3 + frequency * 0.3

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id[:10],
            "type": self.memory_type.value,
            "content": self.content[:30],
            "confidence": round(self.confidence, 2),
            "relevance": round(self.relevance_score, 2),
        }


@dataclass
class KnowledgeTriple:
    """A subject-predicate-object triple."""
    triple_id: str = ""
    subject: str = ""
    predicate: str = ""
    obj: str = ""
    confidence: float = 0.5
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.triple_id[:10],
            "s": self.subject[:15],
            "p": self.predicate[:15],
            "o": self.obj[:15],
        }


class SemanticMemory:
    """Long-term semantic memory store.

    Stores declarative facts, patterns, and procedures
    that persist across assessments.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: dict[str, MemoryEntry] = {}
        self._triples: dict[str, KnowledgeTriple] = {}
        self._tag_index: dict[str, list[str]] = defaultdict(list)
        self._counter = 0
        self._max_entries = max_entries
        self._log = logger.bind(component="semantic_memory")

    def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.FACT,
        source: MemorySource = MemorySource.OBSERVATION,
        tags: list[str] | None = None,
        confidence: float = 0.5,
    ) -> MemoryEntry:
        """Store a memory entry."""
        self._counter += 1
        entry = MemoryEntry(
            entry_id=f"mem-{self._counter}",
            content=content,
            memory_type=memory_type,
            source=source,
            tags=tags or [],
            confidence=confidence,
        )

        self._entries[entry.entry_id] = entry

        for tag in entry.tags:
            self._tag_index[tag].append(entry.entry_id)

        # Evict if over capacity
        if len(self._entries) > self._max_entries:
            self._evict_least_relevant()

        return entry

    def store_triple(
        self,
        subject: str,
        predicate: str,
        obj: str,
        confidence: float = 0.5,
        source: str = "",
    ) -> KnowledgeTriple:
        """Store a knowledge triple."""
        self._counter += 1
        triple = KnowledgeTriple(
            triple_id=f"triple-{self._counter}",
            subject=subject,
            predicate=predicate,
            obj=obj,
            confidence=confidence,
            source=source,
        )
        self._triples[triple.triple_id] = triple
        return triple

    def recall_by_tags(
        self,
        tags: list[str],
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Recall memories matching tags."""
        matching_ids: set[str] = set()
        for tag in tags:
            matching_ids.update(self._tag_index.get(tag, []))

        entries = [
            self._entries[mid] for mid in matching_ids
            if mid in self._entries
        ]

        # Sort by relevance and update access
        entries.sort(key=lambda e: e.relevance_score, reverse=True)
        for entry in entries[:limit]:
            entry.access_count += 1
            entry.last_accessed = time.time()

        return entries[:limit]

    def recall_by_type(
        self,
        memory_type: MemoryType,
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Recall memories by type."""
        entries = [
            e for e in self._entries.values()
            if e.memory_type == memory_type
        ]
        entries.sort(key=lambda e: e.relevance_score, reverse=True)

        for entry in entries[:limit]:
            entry.access_count += 1
            entry.last_accessed = time.time()

        return entries[:limit]

    def recall_similar(
        self,
        query: str,
        limit: int = 10,
    ) -> list[MemoryEntry]:
        """Recall memories similar to a query string."""
        query_words = set(query.lower().split())
        scored: list[tuple[float, MemoryEntry]] = []

        for entry in self._entries.values():
            entry_words = set(entry.content.lower().split())
            entry_words.update(t.lower() for t in entry.tags)

            overlap = len(query_words & entry_words)
            if overlap > 0:
                sim = overlap / max(len(query_words), len(entry_words))
                combined = sim * 0.6 + entry.relevance_score * 0.4
                scored.append((combined, entry))

        scored.sort(key=lambda x: x[0], reverse=True)

        result = []
        for _score, entry in scored[:limit]:
            entry.access_count += 1
            entry.last_accessed = time.time()
            result.append(entry)

        return result

    def query_triples(
        self,
        subject: str = "",
        predicate: str = "",
        obj: str = "",
    ) -> list[KnowledgeTriple]:
        """Query knowledge triples."""
        results = []
        for triple in self._triples.values():
            if subject and triple.subject.lower() != subject.lower():
                continue
            if predicate and triple.predicate.lower() != predicate.lower():
                continue
            if obj and triple.obj.lower() != obj.lower():
                continue
            results.append(triple)
        return results

    def consolidate_from_episode(
        self,
        findings: list[dict[str, Any]],
        strategies: list[str],
        target: str,
    ) -> list[MemoryEntry]:
        """Consolidate episode results into semantic memory."""
        new_entries = []

        # Store findings as facts
        for finding in findings:
            entry = self.store(
                content=f"Found {finding.get('title', '')} on {target}",
                memory_type=MemoryType.FACT,
                source=MemorySource.CONSOLIDATION,
                tags=[
                    target,
                    finding.get("severity", "medium"),
                    finding.get("tool", ""),
                ],
                confidence=finding.get("confidence", 0.5),
            )
            new_entries.append(entry)

        # Store effective strategies as procedures
        for strategy in strategies:
            entry = self.store(
                content=f"Strategy '{strategy}' effective against {target}",
                memory_type=MemoryType.PROCEDURE,
                source=MemorySource.CONSOLIDATION,
                tags=[target, "strategy", strategy],
                confidence=0.7,
            )
            new_entries.append(entry)

        return new_entries

    def _evict_least_relevant(self) -> None:
        """Evict the least relevant entry."""
        if not self._entries:
            return

        least = min(self._entries.values(), key=lambda e: e.relevance_score)
        del self._entries[least.entry_id]

    def build_memory_prompt(
        self,
        tags: list[str] | None = None,
        limit: int = 5,
    ) -> str:
        """Build a prompt from relevant memories."""
        if tags:
            entries = self.recall_by_tags(tags, limit)
        else:
            entries = sorted(
                self._entries.values(),
                key=lambda e: e.relevance_score,
                reverse=True,
            )[:limit]

        if not entries:
            return ""

        lines = ["## Relevant Knowledge\n"]
        for entry in entries:
            lines.append(f"- [{entry.memory_type.value}] {entry.content}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        source_counts: dict[str, int] = defaultdict(int)

        for entry in self._entries.values():
            type_counts[entry.memory_type.value] += 1
            source_counts[entry.source.value] += 1

        return {
            "entries": len(self._entries),
            "triples": len(self._triples),
            "tags": len(self._tag_index),
            "by_type": dict(type_counts),
            "by_source": dict(source_counts),
        }
