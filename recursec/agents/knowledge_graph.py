"""Knowledge graph — relationship-based knowledge store.

Implements:
1. Entity-relationship graph for security knowledge
2. Triple store (subject, predicate, object)
3. Graph traversal for attack path discovery
4. Entity resolution and linking
5. Subgraph extraction for agent context
6. Property graph with typed edges
7. Query interface for pattern matching
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EntityType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    USER = "user"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    FINDING = "finding"
    NETWORK = "network"


class RelationType(str, Enum):
    HAS_PORT = "has_port"
    RUNS_SERVICE = "runs_service"
    HAS_VULNERABILITY = "has_vulnerability"
    BELONGS_TO = "belongs_to"
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    USES_TECHNOLOGY = "uses_technology"
    AUTHENTICATES_WITH = "authenticates_with"
    CONNECTED_TO = "connected_to"
    SUBDOMAIN_OF = "subdomain_of"
    EXPLOITABLE_VIA = "exploitable_via"
    LEADS_TO = "leads_to"
    SAME_AS = "same_as"


@dataclass
class Entity:
    """A node in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id[:15],
            "type": self.entity_type.value,
            "name": self.name[:20],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Relation:
    """An edge in the knowledge graph."""
    relation_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relation_type: RelationType = RelationType.CONNECTED_TO
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source_tool: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.relation_id[:15],
            "type": self.relation_type.value,
            "from": self.source_id[:10],
            "to": self.target_id[:10],
        }


@dataclass
class GraphPath:
    """A path through the knowledge graph."""
    entities: list[Entity] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    total_confidence: float = 1.0

    @property
    def length(self) -> int:
        return len(self.relations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "length": self.length,
            "entities": [e.name for e in self.entities],
            "confidence": round(self.total_confidence, 2),
        }


class KnowledgeGraph:
    """Graph-based knowledge store for security assessments.

    Stores entities (hosts, services, vulns) and
    their relationships. Supports graph traversal
    for attack path discovery and context extraction.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relations: list[Relation] = []
        self._adjacency: dict[str, list[str]] = defaultdict(list)  # entity_id → [relation indices]
        self._counter = 0
        self._rel_counter = 0
        self._log = logger.bind(component="knowledge_graph")

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
        source: str = "",
    ) -> Entity:
        """Add an entity to the graph."""
        # Check for existing entity with same type+name
        for existing in self._entities.values():
            if existing.entity_type == entity_type and existing.name == name:
                # Update properties
                if properties:
                    existing.properties.update(properties)
                existing.confidence = max(existing.confidence, confidence)
                return existing

        self._counter += 1
        entity = Entity(
            entity_id=f"e-{self._counter}",
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            confidence=confidence,
            source=source,
        )
        self._entities[entity.entity_id] = entity
        return entity

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
        source_tool: str = "",
    ) -> Relation | None:
        """Add a relation between entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return None

        self._rel_counter += 1
        relation = Relation(
            relation_id=f"r-{self._rel_counter}",
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties or {},
            confidence=confidence,
            source_tool=source_tool,
        )
        rel_idx = str(len(self._relations))
        self._relations.append(relation)
        self._adjacency[source_id].append(rel_idx)
        self._adjacency[target_id].append(rel_idx)
        return relation

    def get_entity(self, entity_id: str) -> Entity | None:
        """Get entity by ID."""
        return self._entities.get(entity_id)

    def get_entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        """Get all entities of a type."""
        return [
            e for e in self._entities.values()
            if e.entity_type == entity_type
        ]

    def get_neighbors(
        self,
        entity_id: str,
        relation_type: RelationType | None = None,
    ) -> list[tuple[Relation, Entity]]:
        """Get neighboring entities."""
        neighbors = []
        for rel_idx in self._adjacency.get(entity_id, []):
            rel = self._relations[int(rel_idx)]
            if relation_type and rel.relation_type != relation_type:
                continue

            if rel.source_id == entity_id:
                target = self._entities.get(rel.target_id)
            else:
                target = self._entities.get(rel.source_id)

            if target:
                neighbors.append((rel, target))

        return neighbors

    def find_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
    ) -> list[GraphPath]:
        """Find all paths between two entities."""
        paths: list[GraphPath] = []
        self._dfs_paths(start_id, end_id, set(), [], [], max_depth, paths)
        return paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        visited: set[str],
        current_entities: list[Entity],
        current_relations: list[Relation],
        max_depth: int,
        results: list[GraphPath],
    ) -> None:
        """Depth-first search for paths."""
        if len(current_relations) > max_depth:
            return

        entity = self._entities.get(current)
        if not entity:
            return

        visited.add(current)
        current_entities.append(entity)

        if current == target:
            confidence = 1.0
            for rel in current_relations:
                confidence *= rel.confidence

            results.append(GraphPath(
                entities=list(current_entities),
                relations=list(current_relations),
                total_confidence=confidence,
            ))
        else:
            for rel_idx in self._adjacency.get(current, []):
                rel = self._relations[int(rel_idx)]
                next_id = rel.target_id if rel.source_id == current else rel.source_id

                if next_id not in visited:
                    current_relations.append(rel)
                    self._dfs_paths(
                        next_id, target, visited,
                        current_entities, current_relations,
                        max_depth, results,
                    )
                    current_relations.pop()

        current_entities.pop()
        visited.discard(current)

    def get_attack_surface(self) -> dict[str, Any]:
        """Get attack surface summary from the graph."""
        hosts = self.get_entities_by_type(EntityType.HOST)
        services = self.get_entities_by_type(EntityType.SERVICE)
        vulns = self.get_entities_by_type(EntityType.VULNERABILITY)
        domains = self.get_entities_by_type(EntityType.DOMAIN)

        return {
            "hosts": len(hosts),
            "services": len(services),
            "vulnerabilities": len(vulns),
            "domains": len(domains),
            "total_entities": len(self._entities),
            "total_relations": len(self._relations),
        }

    def build_graph_prompt(
        self,
        entity_id: str = "",
        max_depth: int = 2,
    ) -> str:
        """Build a prompt from graph context."""
        lines = ["## Knowledge Graph Context\n"]

        surface = self.get_attack_surface()
        lines.append(f"Attack Surface: {surface['hosts']} hosts, "
                      f"{surface['services']} services, "
                      f"{surface['vulnerabilities']} vulns")

        if entity_id:
            entity = self._entities.get(entity_id)
            if entity:
                lines.append(f"\nFocus: {entity.name} ({entity.entity_type.value})")
                neighbors = self.get_neighbors(entity_id)
                for rel, neighbor in neighbors[:10]:
                    lines.append(
                        f"  → {rel.relation_type.value} → "
                        f"{neighbor.name} ({neighbor.entity_type.value})"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for entity in self._entities.values():
            type_counts[entity.entity_type.value] += 1

        return {
            "entities": len(self._entities),
            "relations": len(self._relations),
            "by_type": dict(type_counts),
        }
