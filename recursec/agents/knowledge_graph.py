"""Knowledge graph — builds and queries a graph of security knowledge.

Implements:
1. Entity-relationship graph for targets, findings, tools, techniques
2. Graph traversal for attack path discovery
3. Entity linking (connect related findings)
4. Temporal knowledge (when things were discovered)
5. Relationship inference (if A→B and B→C then A→C)
6. Graph-based reasoning prompts
7. Subgraph extraction for context building
8. Knowledge persistence and incremental updates
"""

from __future__ import annotations

import json
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
    PORT = "port"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    CREDENTIAL = "credential"
    USER = "user"
    ENDPOINT = "endpoint"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"
    NETWORK = "network"
    ATTACK_TECHNIQUE = "attack_technique"


class RelationType(str, Enum):
    HAS_PORT = "has_port"
    RUNS_SERVICE = "runs_service"
    USES_TECHNOLOGY = "uses_technology"
    HAS_VULNERABILITY = "has_vulnerability"
    EXPOSES_ENDPOINT = "exposes_endpoint"
    RESOLVES_TO = "resolves_to"
    TRUSTS = "trusts"
    AUTHENTICATES_VIA = "authenticates_via"
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    EXPLOITED_BY = "exploited_by"
    MITIGATED_BY = "mitigated_by"
    OWNED_BY = "owned_by"
    SUBDOMAIN_OF = "subdomain_of"
    HOSTS = "hosts"
    ACCESS_LEADS_TO = "access_leads_to"
    SAME_AS = "same_as"


@dataclass
class Entity:
    """A node in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    discovered_by: str = ""       # Tool or agent that found it
    confidence: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id,
            "type": self.entity_type.value,
            "name": self.name[:25],
            "props": len(self.properties),
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Relationship:
    """An edge in the knowledge graph."""
    relation_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relation_type: RelationType = RelationType.CONNECTS_TO
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.relation_id,
            "type": self.relation_type.value,
            "source": self.source_id[:10],
            "target": self.target_id[:10],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class GraphQuery:
    """A query against the knowledge graph."""
    start_entity: str = ""
    relation_types: list[RelationType] = field(default_factory=list)
    target_type: EntityType | None = None
    max_depth: int = 3
    min_confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start_entity[:10],
            "relations": [r.value for r in self.relation_types[:3]],
            "depth": self.max_depth,
        }


@dataclass
class GraphPath:
    """A path through the knowledge graph."""
    entities: list[str] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)
    total_confidence: float = 1.0
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "length": self.length,
            "confidence": round(self.total_confidence, 3),
            "entities": self.entities[:5],
        }


class KnowledgeGraph:
    """Graph-based security knowledge management.

    Stores entities (hosts, services, vulns) and relationships
    between them. Supports graph traversal for attack path
    discovery and context building for LLM prompts.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, Relationship] = {}
        self._adjacency: dict[str, list[str]] = defaultdict(list)  # entity -> [relation_ids]
        self._entity_counter = 0
        self._relation_counter = 0
        self._log = logger.bind(component="knowledge_graph")

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: dict[str, Any] | None = None,
        discovered_by: str = "",
        confidence: float = 0.8,
    ) -> Entity:
        """Add an entity to the graph."""
        # Check for existing entity with same type and name
        for existing in self._entities.values():
            if existing.entity_type == entity_type and existing.name == name:
                # Update properties
                if properties:
                    existing.properties.update(properties)
                existing.confidence = max(existing.confidence, confidence)
                return existing

        self._entity_counter += 1
        entity = Entity(
            entity_id=f"e-{self._entity_counter}",
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            discovered_by=discovered_by,
            confidence=confidence,
        )
        self._entities[entity.entity_id] = entity
        return entity

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        properties: dict[str, Any] | None = None,
        confidence: float = 0.8,
    ) -> Relationship | None:
        """Add a relationship between entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return None

        # Check for duplicate
        for rel in self._relationships.values():
            if (rel.source_id == source_id and
                    rel.target_id == target_id and
                    rel.relation_type == relation_type):
                if properties:
                    rel.properties.update(properties)
                rel.confidence = max(rel.confidence, confidence)
                return rel

        self._relation_counter += 1
        rel = Relationship(
            relation_id=f"r-{self._relation_counter}",
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties or {},
            confidence=confidence,
        )
        self._relationships[rel.relation_id] = rel
        self._adjacency[source_id].append(rel.relation_id)
        self._adjacency[target_id].append(rel.relation_id)
        return rel

    def query(self, graph_query: GraphQuery) -> list[GraphPath]:
        """Query the graph for paths matching criteria."""
        start = graph_query.start_entity

        if start not in self._entities:
            return []

        paths: list[GraphPath] = []
        visited: set[str] = set()
        queue: deque[tuple[list[str], list[str], float]] = deque()

        queue.append(([start], [], 1.0))

        while queue:
            current_entities, current_rels, current_conf = queue.popleft()
            current_entity = current_entities[-1]

            if len(current_entities) > graph_query.max_depth + 1:
                continue

            if len(current_entities) > 1:
                entity = self._entities.get(current_entity)
                if entity:
                    if (not graph_query.target_type or
                            entity.entity_type == graph_query.target_type):
                        if current_conf >= graph_query.min_confidence:
                            paths.append(GraphPath(
                                entities=list(current_entities),
                                relationships=list(current_rels),
                                total_confidence=current_conf,
                                length=len(current_entities) - 1,
                            ))

            # Explore neighbors
            visit_key = (current_entity, len(current_entities))
            if visit_key in visited:
                continue
            visited.add(visit_key)

            for rel_id in self._adjacency.get(current_entity, []):
                rel = self._relationships.get(rel_id)
                if not rel:
                    continue

                # Filter by relation type if specified
                if graph_query.relation_types:
                    if rel.relation_type not in graph_query.relation_types:
                        continue

                # Determine neighbor
                if rel.source_id == current_entity:
                    neighbor = rel.target_id
                elif rel.target_id == current_entity:
                    neighbor = rel.source_id
                else:
                    continue

                if neighbor in current_entities:
                    continue  # Avoid cycles

                new_conf = current_conf * rel.confidence
                if new_conf < graph_query.min_confidence:
                    continue

                queue.append((
                    current_entities + [neighbor],
                    current_rels + [rel_id],
                    new_conf,
                ))

        paths.sort(key=lambda p: p.total_confidence, reverse=True)
        return paths

    def find_attack_paths(
        self,
        from_entity: str,
        to_entity: str,
        max_depth: int = 5,
    ) -> list[GraphPath]:
        """Find attack paths between two entities."""
        if from_entity not in self._entities or to_entity not in self._entities:
            return []

        paths: list[GraphPath] = []
        stack: list[tuple[list[str], list[str], float]] = [
            ([from_entity], [], 1.0)
        ]

        while stack:
            current_path, current_rels, conf = stack.pop()
            current = current_path[-1]

            if current == to_entity and len(current_path) > 1:
                paths.append(GraphPath(
                    entities=list(current_path),
                    relationships=list(current_rels),
                    total_confidence=conf,
                    length=len(current_path) - 1,
                ))
                continue

            if len(current_path) > max_depth:
                continue

            for rel_id in self._adjacency.get(current, []):
                rel = self._relationships.get(rel_id)
                if not rel:
                    continue

                if rel.source_id == current:
                    neighbor = rel.target_id
                else:
                    continue  # Only follow forward edges for attack paths

                if neighbor in current_path:
                    continue

                stack.append((
                    current_path + [neighbor],
                    current_rels + [rel_id],
                    conf * rel.confidence,
                ))

        paths.sort(key=lambda p: p.total_confidence, reverse=True)
        return paths

    def get_neighbors(
        self,
        entity_id: str,
        relation_types: list[RelationType] | None = None,
    ) -> list[tuple[Entity, Relationship]]:
        """Get neighboring entities."""
        neighbors = []

        for rel_id in self._adjacency.get(entity_id, []):
            rel = self._relationships.get(rel_id)
            if not rel:
                continue

            if relation_types and rel.relation_type not in relation_types:
                continue

            if rel.source_id == entity_id:
                neighbor = self._entities.get(rel.target_id)
            else:
                neighbor = self._entities.get(rel.source_id)

            if neighbor:
                neighbors.append((neighbor, rel))

        return neighbors

    def extract_subgraph(
        self,
        center_entity: str,
        depth: int = 2,
    ) -> dict[str, Any]:
        """Extract a subgraph around an entity for context building."""
        if center_entity not in self._entities:
            return {}

        visited_entities: set[str] = set()
        visited_rels: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(center_entity, 0)])

        while queue:
            entity_id, current_depth = queue.popleft()
            if entity_id in visited_entities:
                continue
            visited_entities.add(entity_id)

            if current_depth >= depth:
                continue

            for rel_id in self._adjacency.get(entity_id, []):
                visited_rels.add(rel_id)
                rel = self._relationships.get(rel_id)
                if not rel:
                    continue

                neighbor = (
                    rel.target_id if rel.source_id == entity_id
                    else rel.source_id
                )
                if neighbor not in visited_entities:
                    queue.append((neighbor, current_depth + 1))

        entities = [
            self._entities[eid].to_dict()
            for eid in visited_entities
            if eid in self._entities
        ]
        relationships = [
            self._relationships[rid].to_dict()
            for rid in visited_rels
            if rid in self._relationships
        ]

        return {
            "center": center_entity,
            "entities": entities,
            "relationships": relationships,
        }

    def build_context_prompt(
        self,
        entity_id: str,
        depth: int = 2,
    ) -> str:
        """Build a context prompt from the knowledge graph for LLM reasoning."""
        subgraph = self.extract_subgraph(entity_id, depth)
        if not subgraph:
            return ""

        center = self._entities.get(entity_id)
        if not center:
            return ""

        lines = [f"Knowledge about {center.entity_type.value}: {center.name}\n"]

        # Group entities by type
        entities_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in subgraph["entities"]:
            entities_by_type[e["type"]].append(e)

        for etype, entities in entities_by_type.items():
            lines.append(f"\n{etype.upper()}:")
            for e in entities:
                lines.append(f"  - {e['name']}")

        lines.append(f"\nRelationships: {len(subgraph['relationships'])}")
        for r in subgraph["relationships"][:10]:
            lines.append(
                f"  {r['source']}... --[{r['type']}]--> {r['target']}..."
            )

        return "\n".join(lines)

    def to_json(self) -> str:
        """Serialize the graph to JSON."""
        data = {
            "entities": [e.to_dict() for e in self._entities.values()],
            "relationships": [r.to_dict() for r in self._relationships.values()],
        }
        return json.dumps(data, indent=2)

    def get_entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        return [
            e for e in self._entities.values()
            if e.entity_type == entity_type
        ]

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for e in self._entities.values():
            type_counts[e.entity_type.value] += 1
        rel_counts: dict[str, int] = defaultdict(int)
        for r in self._relationships.values():
            rel_counts[r.relation_type.value] += 1
        return {
            "entities": len(self._entities),
            "relationships": len(self._relationships),
            "entity_types": dict(type_counts),
            "relation_types": dict(rel_counts),
        }
