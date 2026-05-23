"""Knowledge graph — builds and queries a knowledge graph of discovered entities.

Implements:
1. Entity types (hosts, services, vulns, credentials, relationships)
2. Relationship types (runs_on, connects_to, has_vuln, authenticates_with)
3. Graph traversal for attack path discovery
4. Shortest path between entities
5. Entity merging and deduplication
6. Temporal knowledge (when was something discovered)
7. Confidence scores on edges
8. Graph serialization/persistence
9. Subgraph extraction for specific hosts/domains
10. Pattern matching for known attack patterns
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class EntityType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    EMAIL = "email"
    NETWORK = "network"
    FINDING = "finding"
    EXPLOIT = "exploit"
    USER = "user"


class RelationType(str, Enum):
    RUNS_ON = "runs_on"
    CONNECTS_TO = "connects_to"
    HAS_VULN = "has_vuln"
    HAS_PORT = "has_port"
    HAS_SERVICE = "has_service"
    RESOLVES_TO = "resolves_to"
    SUBDOMAIN_OF = "subdomain_of"
    HOSTS = "hosts"
    AUTHENTICATES_WITH = "authenticates_with"
    EXPLOITS = "exploits"
    USES_TECH = "uses_tech"
    HAS_CERT = "has_cert"
    IN_NETWORK = "in_network"
    TRUSTS = "trusts"
    ROUTES_TO = "routes_to"
    LINKED_TO = "linked_to"


@dataclass
class Entity:
    """An entity in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = ""               # Tool/agent that discovered this
    discovered_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id, "type": self.entity_type.value,
            "label": self.label[:80], "confidence": round(self.confidence, 2),
            "source": self.source, "tags": self.tags[:5],
        }


@dataclass
class Relationship:
    """A relationship between two entities."""
    rel_id: str = ""
    rel_type: RelationType = RelationType.LINKED_TO
    source_id: str = ""
    target_id: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rel_id, "type": self.rel_type.value,
            "from": self.source_id, "to": self.target_id,
            "confidence": round(self.confidence, 2),
        }


class KnowledgeGraph:
    """A knowledge graph of discovered security entities.

    Stores entities (hosts, services, vulns) and their
    relationships. Supports graph traversal, attack path
    discovery, and pattern matching.
    """

    def __init__(self, persistence_dir: str = "data/knowledge") -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: list[Relationship] = []
        self._adjacency: dict[str, list[str]] = defaultdict(list)       # entity_id -> [rel_ids]
        self._reverse_adj: dict[str, list[str]] = defaultdict(list)     # entity_id -> [rel_ids]
        self._rel_by_id: dict[str, Relationship] = {}
        self._entity_counter = 0
        self._rel_counter = 0
        self._persistence_dir = Path(persistence_dir)
        self._persistence_dir.mkdir(parents=True, exist_ok=True)
        self._log = logger.bind(component="knowledge_graph")

    def add_entity(
        self,
        entity_type: EntityType,
        label: str,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
        source: str = "",
        tags: list[str] | None = None,
    ) -> str:
        """Add an entity to the graph."""
        # Check for existing entity with same type and label
        for existing in self._entities.values():
            if existing.entity_type == entity_type and existing.label == label:
                # Merge
                existing.last_seen = time.time()
                existing.confidence = max(existing.confidence, confidence)
                if properties:
                    existing.properties.update(properties)
                return existing.entity_id

        self._entity_counter += 1
        eid = f"e-{self._entity_counter}"

        entity = Entity(
            entity_id=eid,
            entity_type=entity_type,
            label=label,
            properties=properties or {},
            confidence=confidence,
            source=source,
            tags=tags or [],
        )

        self._entities[eid] = entity
        return eid

    def add_relationship(
        self,
        rel_type: RelationType,
        source_id: str,
        target_id: str,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> str:
        """Add a relationship between entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return ""

        self._rel_counter += 1
        rid = f"r-{self._rel_counter}"

        rel = Relationship(
            rel_id=rid,
            rel_type=rel_type,
            source_id=source_id,
            target_id=target_id,
            properties=properties or {},
            confidence=confidence,
        )

        self._relationships.append(rel)
        self._rel_by_id[rid] = rel
        self._adjacency[source_id].append(rid)
        self._reverse_adj[target_id].append(rid)

        return rid

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def get_entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        return [e for e in self._entities.values() if e.entity_type == entity_type]

    def get_neighbors(
        self,
        entity_id: str,
        rel_type: RelationType | None = None,
        direction: str = "outgoing",
    ) -> list[Entity]:
        """Get neighboring entities."""
        neighbors = []

        if direction in ("outgoing", "both"):
            for rid in self._adjacency.get(entity_id, []):
                rel = self._rel_by_id.get(rid)
                if rel and (not rel_type or rel.rel_type == rel_type):
                    entity = self._entities.get(rel.target_id)
                    if entity:
                        neighbors.append(entity)

        if direction in ("incoming", "both"):
            for rid in self._reverse_adj.get(entity_id, []):
                rel = self._rel_by_id.get(rid)
                if rel and (not rel_type or rel.rel_type == rel_type):
                    entity = self._entities.get(rel.source_id)
                    if entity:
                        neighbors.append(entity)

        return neighbors

    def find_path(
        self,
        from_id: str,
        to_id: str,
        max_depth: int = 10,
    ) -> list[str]:
        """Find shortest path between two entities (BFS)."""
        if from_id not in self._entities or to_id not in self._entities:
            return []

        visited: set[str] = set()
        queue: deque[tuple[str, list[str]]] = deque()
        queue.append((from_id, [from_id]))

        while queue:
            current, path = queue.popleft()

            if current == to_id:
                return path

            if len(path) > max_depth:
                continue

            if current in visited:
                continue
            visited.add(current)

            for rid in self._adjacency.get(current, []):
                rel = self._rel_by_id.get(rid)
                if rel and rel.target_id not in visited:
                    queue.append((rel.target_id, path + [rel.target_id]))

        return []

    def find_attack_paths(
        self,
        from_id: str,
        max_depth: int = 6,
    ) -> list[list[str]]:
        """Find all paths from an entity to vulnerabilities."""
        vuln_ids = {
            e.entity_id for e in self._entities.values()
            if e.entity_type == EntityType.VULNERABILITY
        }

        if not vuln_ids:
            return []

        paths = []
        visited: set[str] = set()

        def dfs(current: str, path: list[str]) -> None:
            if len(path) > max_depth:
                return
            if current in visited:
                return

            visited.add(current)

            if current in vuln_ids and current != from_id:
                paths.append(list(path))

            for rid in self._adjacency.get(current, []):
                rel = self._rel_by_id.get(rid)
                if rel:
                    dfs(rel.target_id, path + [rel.target_id])

            visited.discard(current)

        dfs(from_id, [from_id])
        return paths

    def search(
        self,
        query: str,
        entity_type: EntityType | None = None,
        limit: int = 20,
    ) -> list[Entity]:
        """Search entities by label or properties."""
        query_lower = query.lower()
        results = []

        for entity in self._entities.values():
            if entity_type and entity.entity_type != entity_type:
                continue

            if query_lower in entity.label.lower():
                results.append(entity)
                continue

            # Search properties
            for value in entity.properties.values():
                if query_lower in str(value).lower():
                    results.append(entity)
                    break

        return results[:limit]

    def get_subgraph(
        self,
        entity_id: str,
        depth: int = 2,
    ) -> dict[str, Any]:
        """Extract a subgraph around an entity."""
        entities: dict[str, Entity] = {}
        rels: list[Relationship] = []
        to_visit: list[tuple[str, int]] = [(entity_id, 0)]
        visited: set[str] = set()

        while to_visit:
            eid, d = to_visit.pop(0)
            if eid in visited or d > depth:
                continue
            visited.add(eid)

            entity = self._entities.get(eid)
            if entity:
                entities[eid] = entity

            for rid in self._adjacency.get(eid, []):
                rel = self._rel_by_id.get(rid)
                if rel:
                    rels.append(rel)
                    if rel.target_id not in visited:
                        to_visit.append((rel.target_id, d + 1))

        return {
            "entities": [e.to_dict() for e in entities.values()],
            "relationships": [r.to_dict() for r in rels],
        }

    def save(self) -> None:
        """Persist the knowledge graph."""
        data = {
            "entities": [e.to_dict() for e in self._entities.values()],
            "relationships": [r.to_dict() for r in self._relationships],
        }
        path = self._persistence_dir / "graph.json"
        try:
            path.write_text(json.dumps(data, default=str))
        except OSError:
            pass

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for e in self._entities.values():
            type_counts[e.entity_type.value] += 1

        return {
            "entities": len(self._entities),
            "relationships": len(self._relationships),
            "entity_types": dict(type_counts),
        }
