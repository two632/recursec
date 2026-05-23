"""Semantic memory — long-term knowledge storage with vector-based retrieval.

Implements a comprehensive semantic memory system:
1. Store facts, observations, and learnings with embeddings
2. Retrieve by semantic similarity (RAG pattern)
3. Organize by topics and domains
4. Track provenance (where knowledge came from)
5. Decay old irrelevant knowledge
6. Cross-reference between memory items
7. Generate context summaries for LLM prompts

Memory types:
- Factual: Things that are true about targets
- Procedural: How to do things (skills, techniques)
- Strategic: What works in what situations
- Relational: How things connect to each other
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

from recursec.memory.embeddings import EmbeddingClient

logger = structlog.get_logger()


class MemoryType(str, Enum):
    FACTUAL = "factual"         # Facts about targets
    PROCEDURAL = "procedural"   # How to do things
    STRATEGIC = "strategic"     # What works when
    RELATIONAL = "relational"   # How things connect
    OBSERVATION = "observation"  # Raw observations
    LESSON = "lesson"           # Learned lessons


class MemoryDomain(str, Enum):
    SECURITY = "security"
    NETWORK = "network"
    WEB = "web"
    CODE = "code"
    INFRASTRUCTURE = "infrastructure"
    CLOUD = "cloud"
    CREDENTIALS = "credentials"
    GENERAL = "general"


@dataclass
class MemoryItem:
    """A single item in semantic memory."""
    item_id: str = ""
    content: str = ""
    memory_type: MemoryType = MemoryType.FACTUAL
    domain: MemoryDomain = MemoryDomain.GENERAL
    embedding: list[float] = field(default_factory=list)
    importance: float = 0.5
    confidence: float = 0.5
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    source: str = ""            # Where this came from
    source_agent: str = ""      # Which agent stored this
    tags: list[str] = field(default_factory=list)
    related_items: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.item_id:
            self.item_id = hashlib.md5(
                f"{self.content[:100]}:{self.created_at}".encode()
            ).hexdigest()[:12]

    @property
    def strength(self) -> float:
        """Memory strength — decays over time, strengthened by access."""
        age_days = (time.time() - self.created_at) / 86400
        recency_days = (time.time() - self.last_accessed) / 86400
        base = self.importance * self.confidence
        access_bonus = min(1.0, self.access_count * 0.1)
        age_decay = 1.0 / (1.0 + age_days / 30)
        recency_decay = 1.0 / (1.0 + recency_days / 7)
        return base * (1.0 + access_bonus) * age_decay * recency_decay

    def access(self) -> None:
        self.last_accessed = time.time()
        self.access_count += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "content": self.content[:200],
            "type": self.memory_type.value,
            "domain": self.domain.value,
            "importance": round(self.importance, 2),
            "confidence": round(self.confidence, 2),
            "strength": round(self.strength, 3),
            "source": self.source[:50],
            "tags": self.tags[:5],
            "access_count": self.access_count,
        }


@dataclass
class RetrievalResult:
    """Result of a memory retrieval."""
    items: list[MemoryItem] = field(default_factory=list)
    scores: list[float] = field(default_factory=list)
    query: str = ""
    retrieval_time_ms: float = 0.0

    def to_context_string(self, max_items: int = 10, max_chars: int = 3000) -> str:
        """Convert to a context string for LLM prompts."""
        lines = []
        total_chars = 0
        for item, score in zip(self.items[:max_items], self.scores[:max_items]):
            line = f"[{item.memory_type.value}|{item.domain.value}|{score:.2f}] {item.content[:200]}"
            if total_chars + len(line) > max_chars:
                break
            lines.append(line)
            total_chars += len(line)
        return "\n".join(lines)


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = sum(a * a for a in vec_a) ** 0.5
    mag_b = sum(b * b for b in vec_b) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


class SemanticMemory:
    """Long-term semantic memory with vector-based retrieval.

    Stores knowledge as embedded vectors for semantic similarity
    search. Supports multiple memory types, domains, and
    provenance tracking.
    """

    def __init__(
        self,
        embedding_client: EmbeddingClient,
        storage_dir: str = "data/semantic_memory",
        max_items: int = 50000,
    ) -> None:
        self._embedder = embedding_client
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._max_items = max_items

        self._items: dict[str, MemoryItem] = {}
        self._by_type: dict[str, list[str]] = defaultdict(list)
        self._by_domain: dict[str, list[str]] = defaultdict(list)
        self._by_tag: dict[str, list[str]] = defaultdict(list)

        self._log = logger.bind(component="semantic_memory")
        self._load()

    async def store(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.FACTUAL,
        domain: MemoryDomain = MemoryDomain.GENERAL,
        importance: float = 0.5,
        confidence: float = 0.5,
        source: str = "",
        source_agent: str = "",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a new memory item with embedding."""
        # Check for near-duplicates
        existing = await self._find_near_duplicate(content)
        if existing:
            existing.access()
            existing.confidence = max(existing.confidence, confidence)
            return existing.item_id

        # Get embedding
        embedding = await self._embedder.embed_one(content)

        item = MemoryItem(
            content=content,
            memory_type=memory_type,
            domain=domain,
            embedding=embedding,
            importance=importance,
            confidence=confidence,
            source=source,
            source_agent=source_agent,
            tags=tags or [],
            metadata=metadata or {},
        )

        # Evict if at capacity
        if len(self._items) >= self._max_items:
            self._evict_weakest()

        self._items[item.item_id] = item
        self._by_type[memory_type.value].append(item.item_id)
        self._by_domain[domain.value].append(item.item_id)
        for tag in item.tags:
            self._by_tag[tag].append(item.item_id)

        return item.item_id

    async def retrieve(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.3,
        memory_type: MemoryType | None = None,
        domain: MemoryDomain | None = None,
        tags: list[str] | None = None,
    ) -> RetrievalResult:
        """Retrieve memories by semantic similarity."""
        start = time.time()
        query_embedding = await self._embedder.embed_one(query)

        if not query_embedding:
            return RetrievalResult(query=query)

        # Filter candidates
        candidates = self._get_candidates(memory_type, domain, tags)

        # Score by similarity
        scored: list[tuple[MemoryItem, float]] = []
        for item in candidates:
            if not item.embedding:
                continue
            sim = _cosine_similarity(query_embedding, item.embedding)
            # Boost by strength
            adjusted = sim * (0.7 + 0.3 * item.strength)
            if adjusted >= min_score:
                scored.append((item, adjusted))

        # Sort by score
        scored.sort(key=lambda x: -x[1])
        top = scored[:top_k]

        # Mark as accessed
        for item, _ in top:
            item.access()

        result = RetrievalResult(
            items=[item for item, _ in top],
            scores=[score for _, score in top],
            query=query,
            retrieval_time_ms=(time.time() - start) * 1000,
        )

        return result

    async def store_finding(self, finding: dict[str, Any]) -> str:
        """Store a security finding as memory."""
        content = (
            f"Finding: {finding.get('title', '')}\n"
            f"Severity: {finding.get('severity', '')}\n"
            f"Component: {finding.get('component', '')}\n"
            f"Description: {finding.get('description', '')[:300]}\n"
            f"Evidence: {finding.get('evidence', '')[:200]}"
        )
        return await self.store(
            content=content,
            memory_type=MemoryType.FACTUAL,
            domain=MemoryDomain.SECURITY,
            importance=self._severity_to_importance(finding.get("severity", "medium")),
            confidence=finding.get("confidence", 0.5),
            source=finding.get("source", ""),
            tags=["finding", finding.get("category", "")],
        )

    async def store_tool_result(
        self,
        tool_name: str,
        command: str,
        output: str,
        target: str = "",
    ) -> str:
        """Store a tool execution result."""
        content = f"Tool: {tool_name}\nTarget: {target}\nCommand: {command}\nOutput: {output[:500]}"
        return await self.store(
            content=content,
            memory_type=MemoryType.OBSERVATION,
            domain=MemoryDomain.GENERAL,
            importance=0.4,
            source=tool_name,
            tags=["tool_result", tool_name],
        )

    async def store_lesson(self, lesson: str, context: str = "") -> str:
        """Store a learned lesson."""
        content = f"Lesson: {lesson}"
        if context:
            content += f"\nContext: {context}"
        return await self.store(
            content=content,
            memory_type=MemoryType.LESSON,
            importance=0.7,
            tags=["lesson"],
        )

    async def store_technique(self, technique: str, effectiveness: float = 0.5) -> str:
        """Store a technique/procedure."""
        return await self.store(
            content=technique,
            memory_type=MemoryType.PROCEDURAL,
            domain=MemoryDomain.SECURITY,
            importance=effectiveness,
            tags=["technique"],
        )

    def get_item(self, item_id: str) -> MemoryItem | None:
        return self._items.get(item_id)

    def link_items(self, item_a_id: str, item_b_id: str) -> None:
        """Create a bidirectional link between memory items."""
        item_a = self._items.get(item_a_id)
        item_b = self._items.get(item_b_id)
        if item_a and item_b:
            if item_b_id not in item_a.related_items:
                item_a.related_items.append(item_b_id)
            if item_a_id not in item_b.related_items:
                item_b.related_items.append(item_a_id)

    def get_related(self, item_id: str, depth: int = 1) -> list[MemoryItem]:
        """Get related items up to a given depth."""
        visited: set[str] = set()
        current_ids = {item_id}
        results = []

        for _ in range(depth):
            next_ids: set[str] = set()
            for mid in current_ids:
                if mid in visited:
                    continue
                visited.add(mid)
                item = self._items.get(mid)
                if item:
                    results.append(item)
                    next_ids.update(item.related_items)
            current_ids = next_ids - visited

        return results

    def consolidate(self) -> int:
        """Consolidate memory: remove weak items, strengthen important ones."""
        removed = 0
        for item_id in list(self._items.keys()):
            item = self._items[item_id]
            if item.strength < 0.05 and item.access_count == 0:
                del self._items[item_id]
                removed += 1
        return removed

    # ── Persistence ──────────────────────────────────────

    def save(self) -> None:
        """Persist memory to disk."""
        try:
            data = {
                "items": {
                    item_id: {
                        "content": item.content,
                        "type": item.memory_type.value,
                        "domain": item.domain.value,
                        "importance": item.importance,
                        "confidence": item.confidence,
                        "created_at": item.created_at,
                        "last_accessed": item.last_accessed,
                        "access_count": item.access_count,
                        "source": item.source,
                        "source_agent": item.source_agent,
                        "tags": item.tags,
                        "related": item.related_items,
                        "embedding": item.embedding[:10],  # Save truncated
                    }
                    for item_id, item in list(self._items.items())[:5000]
                },
            }
            path = self._storage_dir / "semantic_memory.json"
            path.write_text(json.dumps(data))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def _load(self) -> None:
        """Load persisted memory."""
        path = self._storage_dir / "semantic_memory.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for item_id, item_data in data.get("items", {}).items():
                try:
                    mt = MemoryType(item_data.get("type", "factual"))
                except ValueError:
                    mt = MemoryType.FACTUAL
                try:
                    md = MemoryDomain(item_data.get("domain", "general"))
                except ValueError:
                    md = MemoryDomain.GENERAL

                item = MemoryItem(
                    item_id=item_id,
                    content=item_data.get("content", ""),
                    memory_type=mt,
                    domain=md,
                    importance=item_data.get("importance", 0.5),
                    confidence=item_data.get("confidence", 0.5),
                    created_at=item_data.get("created_at", 0),
                    last_accessed=item_data.get("last_accessed", 0),
                    access_count=item_data.get("access_count", 0),
                    source=item_data.get("source", ""),
                    source_agent=item_data.get("source_agent", ""),
                    tags=item_data.get("tags", []),
                    related_items=item_data.get("related", []),
                )
                self._items[item_id] = item
                self._by_type[mt.value].append(item_id)
                self._by_domain[md.value].append(item_id)
        except (json.JSONDecodeError, OSError) as e:
            self._log.warning("load_failed", error=str(e))

    # ── Internal ─────────────────────────────────────────

    def _get_candidates(
        self,
        memory_type: MemoryType | None,
        domain: MemoryDomain | None,
        tags: list[str] | None,
    ) -> list[MemoryItem]:
        """Get candidate items for retrieval, filtered by type/domain/tags."""
        if memory_type:
            ids = set(self._by_type.get(memory_type.value, []))
        elif domain:
            ids = set(self._by_domain.get(domain.value, []))
        elif tags:
            ids = set()
            for tag in tags:
                ids.update(self._by_tag.get(tag, []))
        else:
            ids = set(self._items.keys())

        return [self._items[mid] for mid in ids if mid in self._items]

    async def _find_near_duplicate(self, content: str, threshold: float = 0.95) -> MemoryItem | None:
        """Find a near-duplicate of the given content."""
        embedding = await self._embedder.embed_one(content)
        if not embedding:
            return None

        for item in self._items.values():
            if item.embedding:
                sim = _cosine_similarity(embedding, item.embedding)
                if sim >= threshold:
                    return item
        return None

    def _evict_weakest(self) -> None:
        """Evict the weakest memory item."""
        if not self._items:
            return
        weakest = min(self._items.values(), key=lambda i: i.strength)
        del self._items[weakest.item_id]

    def _severity_to_importance(self, severity: str) -> float:
        return {
            "critical": 0.95, "high": 0.8,
            "medium": 0.5, "low": 0.3, "info": 0.1,
        }.get(severity.lower(), 0.5)

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        by_domain: dict[str, int] = defaultdict(int)
        for item in self._items.values():
            by_type[item.memory_type.value] += 1
            by_domain[item.domain.value] += 1
        return {
            "total_items": len(self._items),
            "by_type": dict(by_type),
            "by_domain": dict(by_domain),
            "max_items": self._max_items,
        }
