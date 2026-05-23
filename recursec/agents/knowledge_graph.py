"""Knowledge graph — rich interconnected knowledge representation.

Implements:
1. Entity-relationship graph storage
2. Multi-hop query traversal
3. Knowledge inference (derive new facts)
4. Graph-based similarity
5. Knowledge merging from multiple sources
6. Temporal knowledge (facts with time bounds)
7. Knowledge provenance tracking
8. Graph statistics and analysis
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EntityType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    TECHNOLOGY = "technology"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    FINDING = "finding"
    TOOL = "tool"
    AGENT = "agent"
    ATTACK_VECTOR = "attack_vector"


class RelType(str, Enum):
    RUNS = "runs"                  # host RUNS service
    HAS = "has"                    # host HAS vulnerability
    USES = "uses"                  # service USES technology
    FOUND_BY = "found_by"         # vulnerability FOUND_BY tool
    EXPLOITS = "exploits"          # attack_vector EXPLOITS vulnerability
    CONNECTS_TO = "connects_to"    # host CONNECTS_TO host
    DEPENDS_ON = "depends_on"      # service DEPENDS_ON service
    CONTAINS = "contains"          # endpoint CONTAINS parameter
    AUTHENTICATES = "authenticates"  # credential AUTHENTICATES service
    DISCOVERED = "discovered"      # agent DISCOVERED finding


@dataclass
class Entity:
    """An entity in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source: str = ""
    created_at: float = field(default_factory=time.time)
    valid_until: float = 0.0       # 0 = no expiry

    @property
    def is_valid(self) -> bool:
        if self.valid_until == 0:
            return True
        return time.time() < self.valid_until

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id,
            "type": self.entity_type.value,
            "name": self.name[:25],
            "confidence": round(self.confidence, 2),
            "props": len(self.properties),
            "valid": self.is_valid,
        }


@dataclass
class Relationship:
    """A relationship between entities."""
    rel_id: str = ""
    source_id: str = ""
    target_id: str = ""
    rel_type: RelType = RelType.HAS
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rel_id,
            "from": self.source_id[:15],
            "to": self.target_id[:15],
            "type": self.rel_type.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class QueryResult:
    """Result of a graph query."""
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    paths: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": len(self.entities),
            "relationships": len(self.relationships),
            "paths": len(self.paths),
        }


class KnowledgeGraph:
    """Rich interconnected knowledge representation.

    Stores entities and their relationships as a graph,
    supporting multi-hop queries and inference.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: list[Relationship] = []
        self._adjacency: dict[str, list[str]] = defaultdict(list)
        self._reverse_adj: dict[str, list[str]] = defaultdict(list)
        self._type_index: dict[EntityType, list[str]] = defaultdict(list)
        self._name_index: dict[str, str] = {}
        self._entity_counter = 0
        self._rel_counter = 0
        self._log = logger.bind(component="knowledge_graph")

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: dict[str, Any] | None = None,
        confidence: float = 0.5,
        source: str = "",
        valid_until: float = 0.0,
    ) -> Entity:
        """Add an entity to the graph."""
        # Check if entity already exists by name
        existing_id = self._name_index.get(name.lower())
        if existing_id and existing_id in self._entities:
            existing = self._entities[existing_id]
            if properties:
                existing.properties.update(properties)
            existing.confidence = max(existing.confidence, confidence)
            return existing

        self._entity_counter += 1
        entity = Entity(
            entity_id=f"kg-{self._entity_counter}",
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            confidence=confidence,
            source=source,
            valid_until=valid_until,
        )

        self._entities[entity.entity_id] = entity
        self._type_index[entity_type].append(entity.entity_id)
        self._name_index[name.lower()] = entity.entity_id
        return entity

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: RelType,
        properties: dict[str, Any] | None = None,
        confidence: float = 0.5,
        source: str = "",
    ) -> Relationship:
        """Add a relationship between entities."""
        self._rel_counter += 1
        rel = Relationship(
            rel_id=f"kr-{self._rel_counter}",
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            properties=properties or {},
            confidence=confidence,
            source=source,
        )

        self._relationships.append(rel)
        self._adjacency[source_id].append(rel.rel_id)
        self._reverse_adj[target_id].append(rel.rel_id)
        return rel

    def get_entity(self, name: str) -> Entity | None:
        """Get entity by name."""
        eid = self._name_index.get(name.lower())
        if eid:
            return self._entities.get(eid)
        return None

    def get_by_type(self, entity_type: EntityType) -> list[Entity]:
        """Get all entities of a type."""
        return [
            self._entities[eid]
            for eid in self._type_index.get(entity_type, [])
            if eid in self._entities
        ]

    def get_neighbors(
        self,
        entity_id: str,
        rel_type: RelType | None = None,
        direction: str = "outgoing",
    ) -> list[tuple[Relationship, Entity]]:
        """Get neighboring entities."""
        results = []

        if direction in ("outgoing", "both"):
            for rel_id in self._adjacency.get(entity_id, []):
                rel = self._find_rel(rel_id)
                if rel and (not rel_type or rel.rel_type == rel_type):
                    target = self._entities.get(rel.target_id)
                    if target:
                        results.append((rel, target))

        if direction in ("incoming", "both"):
            for rel_id in self._reverse_adj.get(entity_id, []):
                rel = self._find_rel(rel_id)
                if rel and (not rel_type or rel.rel_type == rel_type):
                    source_ent = self._entities.get(rel.source_id)
                    if source_ent:
                        results.append((rel, source_ent))

        return results

    def query_path(
        self,
        start_name: str,
        end_name: str,
        max_hops: int = 5,
    ) -> list[list[str]]:
        """Find paths between two entities."""
        start = self.get_entity(start_name)
        end = self.get_entity(end_name)
        if not start or not end:
            return []

        paths = []
        visited: set[str] = set()
        queue: deque[list[str]] = deque([[start.entity_id]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == end.entity_id:
                paths.append(path)
                continue

            if len(path) >= max_hops + 1:
                continue

            if current in visited:
                continue
            visited.add(current)

            for rel_id in self._adjacency.get(current, []):
                rel = self._find_rel(rel_id)
                if rel and rel.target_id not in visited:
                    queue.append(path + [rel.target_id])

        return paths

    def infer(self) -> list[Relationship]:
        """Infer new relationships from existing knowledge."""
        new_rels = []

        # If A RUNS service and service HAS vuln, then A HAS vuln
        for entity in self._entities.values():
            if entity.entity_type == EntityType.HOST:
                # Get services
                services = self.get_neighbors(entity.entity_id, RelType.RUNS)
                for _, service in services:
                    # Get vulnerabilities of service
                    vulns = self.get_neighbors(service.entity_id, RelType.HAS)
                    for _, vuln in vulns:
                        # Check if host-vuln relationship already exists
                        existing = any(
                            r.source_id == entity.entity_id and
                            r.target_id == vuln.entity_id and
                            r.rel_type == RelType.HAS
                            for r in self._relationships
                        )
                        if not existing:
                            rel = self.add_relationship(
                                entity.entity_id, vuln.entity_id,
                                RelType.HAS,
                                confidence=0.7,
                                source="inferred",
                            )
                            new_rels.append(rel)

        return new_rels

    def merge(self, other_entities: list[dict[str, Any]]) -> int:
        """Merge knowledge from another source."""
        merged = 0
        for data in other_entities:
            name = data.get("name", "")
            if not name:
                continue

            entity_type = EntityType(data.get("type", "host"))
            self.add_entity(
                entity_type=entity_type,
                name=name,
                properties=data.get("properties", {}),
                confidence=data.get("confidence", 0.5),
                source=data.get("source", "merge"),
            )
            merged += 1

        return merged

    def _find_rel(self, rel_id: str) -> Relationship | None:
        for rel in self._relationships:
            if rel.rel_id == rel_id:
                return rel
        return None

    def get_stats(self) -> dict[str, Any]:
        type_counts = {
            t.value: len(ids) for t, ids in self._type_index.items()
        }
        rel_type_counts: dict[str, int] = defaultdict(int)
        for rel in self._relationships:
            rel_type_counts[rel.rel_type.value] += 1

        return {
            "entities": len(self._entities),
            "relationships": len(self._relationships),
            "entity_types": type_counts,
            "rel_types": dict(rel_type_counts),
        }
