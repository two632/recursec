"""Semantic deduplicator — uses embedding similarity for finding dedup.

Implements:
1. Semantic similarity using Nomic-Embed embeddings
2. Configurable similarity threshold
3. Cluster-based grouping of similar findings
4. Cross-assessment deduplication
5. Near-duplicate detection (different wording, same vuln)
6. Embedding cache management
7. Hierarchical clustering for finding organization
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class EmbeddedItem:
    """An item with its embedding vector."""
    item_id: str = ""
    text: str = ""
    embedding: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "text": self.text[:40],
            "dim": len(self.embedding),
        }


@dataclass
class SimilarityResult:
    """Result of a similarity comparison."""
    item_a: str = ""
    item_b: str = ""
    score: float = 0.0
    is_duplicate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "a": self.item_a[:10],
            "b": self.item_b[:10],
            "score": round(self.score, 3),
            "dup": self.is_duplicate,
        }


@dataclass
class FindingCluster:
    """A cluster of semantically similar findings."""
    cluster_id: str = ""
    representative: str = ""       # ID of the most representative item
    members: list[str] = field(default_factory=list)
    avg_similarity: float = 0.0
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cluster_id,
            "representative": self.representative[:10],
            "members": len(self.members),
            "avg_sim": round(self.avg_similarity, 3),
        }


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    if len(a) != len(b) or not a:
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


def euclidean_distance(a: list[float], b: list[float]) -> float:
    """Calculate euclidean distance between two vectors."""
    if len(a) != len(b) or not a:
        return float("inf")

    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


class SemanticDeduplicator:
    """Deduplicates findings using semantic similarity.

    Uses embedding vectors (from Nomic-Embed or similar) to
    detect semantically similar findings even when they have
    different wording.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        embedding_dim: int = 768,
    ) -> None:
        self._threshold = similarity_threshold
        self._dim = embedding_dim
        self._items: dict[str, EmbeddedItem] = {}
        self._clusters: dict[str, FindingCluster] = {}
        self._cluster_counter = 0
        self._similarity_cache: dict[tuple[str, str], float] = {}
        self._log = logger.bind(component="semantic_dedup")

    def add_item(
        self,
        item_id: str,
        text: str,
        embedding: list[float],
        metadata: dict[str, Any] | None = None,
    ) -> list[SimilarityResult]:
        """Add an item and check for duplicates."""
        item = EmbeddedItem(
            item_id=item_id,
            text=text,
            embedding=embedding,
            metadata=metadata or {},
        )
        self._items[item_id] = item

        # Check against existing items
        duplicates = []
        for other_id, other in self._items.items():
            if other_id == item_id:
                continue

            score = self._compute_similarity(item_id, other_id)
            is_dup = score >= self._threshold

            if is_dup:
                duplicates.append(SimilarityResult(
                    item_a=item_id,
                    item_b=other_id,
                    score=score,
                    is_duplicate=True,
                ))

        return duplicates

    def find_similar(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        min_score: float = 0.5,
    ) -> list[tuple[str, float]]:
        """Find items most similar to a query embedding."""
        scores: list[tuple[str, float]] = []

        for item_id, item in self._items.items():
            score = cosine_similarity(query_embedding, item.embedding)
            if score >= min_score:
                scores.append((item_id, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def cluster_items(
        self,
        min_cluster_similarity: float = 0.7,
    ) -> list[FindingCluster]:
        """Cluster items by semantic similarity using agglomerative approach."""
        # Build distance matrix
        items = list(self._items.keys())
        n = len(items)

        if n < 2:
            return []

        # Single-linkage agglomerative clustering
        assignments: dict[str, int] = {item: i for i, item in enumerate(items)}
        clusters_members: dict[int, list[str]] = {i: [item] for i, item in enumerate(items)}
        # Compute all pairwise similarities
        pairs: list[tuple[float, str, str]] = []
        for i in range(n):
            for j in range(i + 1, n):
                sim = self._compute_similarity(items[i], items[j])
                pairs.append((sim, items[i], items[j]))

        # Sort by similarity (highest first)
        pairs.sort(reverse=True)

        for sim, a, b in pairs:
            if sim < min_cluster_similarity:
                break

            cluster_a = assignments[a]
            cluster_b = assignments[b]

            if cluster_a == cluster_b:
                continue

            # Merge clusters
            members_b = clusters_members[cluster_b]
            clusters_members[cluster_a].extend(members_b)
            for member in members_b:
                assignments[member] = cluster_a
            del clusters_members[cluster_b]

        # Build result
        result = []
        for cluster_id_num, members in clusters_members.items():
            if len(members) < 2:
                continue

            self._cluster_counter += 1

            # Representative = member with highest avg similarity to others
            best_rep = members[0]
            best_avg = 0.0
            for m in members:
                avg = 0.0
                count = 0
                for o in members:
                    if o != m:
                        avg += self._compute_similarity(m, o)
                        count += 1
                if count > 0:
                    avg /= count
                if avg > best_avg:
                    best_avg = avg
                    best_rep = m

            cluster = FindingCluster(
                cluster_id=f"cluster-{self._cluster_counter}",
                representative=best_rep,
                members=members,
                avg_similarity=best_avg,
            )
            result.append(cluster)
            self._clusters[cluster.cluster_id] = cluster

        return result

    def _compute_similarity(self, id_a: str, id_b: str) -> float:
        """Compute similarity between two items (with caching)."""
        cache_key = (min(id_a, id_b), max(id_a, id_b))
        if cache_key in self._similarity_cache:
            return self._similarity_cache[cache_key]

        item_a = self._items.get(id_a)
        item_b = self._items.get(id_b)
        if not item_a or not item_b:
            return 0.0

        score = cosine_similarity(item_a.embedding, item_b.embedding)
        self._similarity_cache[cache_key] = score
        return score

    def get_item(self, item_id: str) -> EmbeddedItem | None:
        return self._items.get(item_id)

    def get_stats(self) -> dict[str, Any]:
        return {
            "items": len(self._items),
            "clusters": len(self._clusters),
            "cache_size": len(self._similarity_cache),
            "threshold": self._threshold,
            "dim": self._dim,
        }
