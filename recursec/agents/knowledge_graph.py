"""Knowledge graph engine — entity-relationship graph for security findings.

Implements:
1. Entity creation (hosts, services, vulns, credentials, etc.)
2. Relationship tracking between entities
3. Graph traversal for attack path discovery
4. Entity enrichment from multiple sources
5. Temporal graph evolution
6. Subgraph extraction for context injection
7. Graph query for LLM prompt building
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
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
    USER = "user"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    FINDING = "finding"
    NETWORK = "network"
    APPLICATION = "application"


class RelationType(str, Enum):
    RUNS_ON = "runs_on"             # service → host
    EXPOSES = "exposes"             # host → port
    RESOLVES_TO = "resolves_to"     # domain → host
    SUBDOMAIN_OF = "subdomain_of"   # subdomain → domain
    HAS_VULN = "has_vuln"          # service → vulnerability
    AUTHENTICATES = "authenticates"  # credential → service
    BELONGS_TO = "belongs_to"       # user → host
    USES_TECH = "uses_tech"         # service → technology
    LINKS_TO = "links_to"          # url → url
    DEPENDS_ON = "depends_on"       # service → service
    CONTAINS = "contains"           # network → host
    EXPLOITS = "exploits"           # finding → vulnerability
    SERVES = "serves"               # host → url
    CHAIN = "chain"                 # finding → finding (attack chain)


@dataclass
class Entity:
    """A node in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    source: str = ""              # Tool or agent that created this
    confidence: float = 1.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id[:12],
            "type": self.entity_type.value,
            "name": self.name[:20],
            "props": len(self.properties),
            "conf": round(self.confidence, 2),
        }


@dataclass
class Relationship:
    """An edge in the knowledge graph."""
    rel_id: str = ""
    rel_type: RelationType = RelationType.RUNS_ON
    source_id: str = ""
    target_id: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rel_id[:10],
            "type": self.rel_type.value,
            "src": self.source_id[:10],
            "tgt": self.target_id[:10],
        }


class KnowledgeGraph:
    """Entity-relationship graph for security findings.

    Tracks hosts, services, vulnerabilities, credentials,
    and their relationships. Supports attack path discovery
    and context injection into LLM prompts.
    """

    def __init__(self, max_entities: int = 10000) -> None:
        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, Relationship] = {}
        self._adjacency: dict[str, list[str]] = {}      # entity_id → [rel_ids]
        self._reverse_adj: dict[str, list[str]] = {}     # entity_id → [rel_ids targeting this]
        self._name_index: dict[str, str] = {}            # name → entity_id
        self._max_entities = max_entities
        self._counter = 0
        self._log = logger.bind(component="knowledge_graph")

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: dict[str, Any] | None = None,
        source: str = "",
        confidence: float = 1.0,
        tags: list[str] | None = None,
    ) -> Entity:
        """Add or update an entity."""
        # Check if entity already exists
        existing_id = self._name_index.get(f"{entity_type.value}:{name.lower()}")
        if existing_id and existing_id in self._entities:
            existing = self._entities[existing_id]
            existing.last_seen = time.time()
            if properties:
                existing.properties.update(properties)
            existing.confidence = max(existing.confidence, confidence)
            return existing

        self._counter += 1
        entity = Entity(
            entity_id=f"ent-{self._counter}",
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            source=source,
            confidence=confidence,
            tags=tags or [],
        )

        self._entities[entity.entity_id] = entity
        self._name_index[f"{entity_type.value}:{name.lower()}"] = entity.entity_id
        self._adjacency[entity.entity_id] = []
        self._reverse_adj[entity.entity_id] = []

        # Evict old entities if over limit
        while len(self._entities) > self._max_entities:
            oldest = min(
                self._entities.values(),
                key=lambda e: e.last_seen,
            )
            self.remove_entity(oldest.entity_id)

        return entity

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: RelationType,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> Relationship | None:
        """Add a relationship between entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return None

        self._counter += 1
        rel = Relationship(
            rel_id=f"rel-{self._counter}",
            rel_type=rel_type,
            source_id=source_id,
            target_id=target_id,
            properties=properties or {},
            confidence=confidence,
        )

        self._relationships[rel.rel_id] = rel
        self._adjacency.setdefault(source_id, []).append(rel.rel_id)
        self._reverse_adj.setdefault(target_id, []).append(rel.rel_id)

        return rel

    def remove_entity(self, entity_id: str) -> bool:
        """Remove an entity and its relationships."""
        if entity_id not in self._entities:
            return False

        # Remove relationships
        rel_ids = list(self._adjacency.get(entity_id, []))
        rel_ids += list(self._reverse_adj.get(entity_id, []))
        for rid in set(rel_ids):
            self._relationships.pop(rid, None)

        entity = self._entities.pop(entity_id)
        self._name_index.pop(f"{entity.entity_type.value}:{entity.name.lower()}", None)
        self._adjacency.pop(entity_id, None)
        self._reverse_adj.pop(entity_id, None)
        return True

    def get_neighbors(
        self,
        entity_id: str,
        rel_type: RelationType | None = None,
    ) -> list[Entity]:
        """Get neighboring entities."""
        neighbors: list[Entity] = []
        for rel_id in self._adjacency.get(entity_id, []):
            rel = self._relationships.get(rel_id)
            if not rel:
                continue
            if rel_type and rel.rel_type != rel_type:
                continue
            target = self._entities.get(rel.target_id)
            if target:
                neighbors.append(target)
        return neighbors

    def find_path(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
    ) -> list[str] | None:
        """Find shortest path between entities (BFS)."""
        if start_id not in self._entities or end_id not in self._entities:
            return None

        visited: set[str] = set()
        queue: list[tuple[str, list[str]]] = [(start_id, [start_id])]

        while queue:
            current, path = queue.pop(0)
            if current == end_id:
                return path
            if len(path) > max_depth:
                continue
            if current in visited:
                continue
            visited.add(current)

            for rel_id in self._adjacency.get(current, []):
                rel = self._relationships.get(rel_id)
                if rel and rel.target_id not in visited:
                    queue.append((rel.target_id, path + [rel.target_id]))

        return None

    def get_attack_paths(
        self,
        target_entity_id: str,
        max_depth: int = 4,
    ) -> list[list[str]]:
        """Find all paths leading to a target (reverse BFS)."""
        paths: list[list[str]] = []

        def dfs(entity_id: str, current_path: list[str], depth: int) -> None:
            if depth > max_depth:
                return
            for rel_id in self._reverse_adj.get(entity_id, []):
                rel = self._relationships.get(rel_id)
                if not rel or rel.source_id in current_path:
                    continue
                new_path = [rel.source_id] + current_path
                paths.append(new_path)
                dfs(rel.source_id, new_path, depth + 1)

        dfs(target_entity_id, [target_entity_id], 0)
        return paths

    def get_by_type(self, entity_type: EntityType) -> list[Entity]:
        """Get all entities of a type."""
        return [e for e in self._entities.values() if e.entity_type == entity_type]

    def build_graph_prompt(
        self,
        focus_entity: str = "",
        max_entities: int = 15,
        max_rels: int = 20,
    ) -> str:
        """Build knowledge graph context for LLM."""
        lines = ["## Knowledge Graph\n"]

        # Summary
        type_counts: dict[str, int] = {}
        for e in self._entities.values():
            type_counts[e.entity_type.value] = type_counts.get(e.entity_type.value, 0) + 1

        lines.append(
            f"Entities: {len(self._entities)} | "
            f"Relationships: {len(self._relationships)}"
        )
        lines.append("Types: " + " ".join(f"{k}={v}" for k, v in type_counts.items()))

        if focus_entity and focus_entity in self._entities:
            entity = self._entities[focus_entity]
            lines.append(f"\nFocus: {entity.name} ({entity.entity_type.value})")

            neighbors = self.get_neighbors(focus_entity)
            if neighbors:
                lines.append(f"Connected to {len(neighbors)} entities:")
                for n in neighbors[:max_entities]:
                    lines.append(f"  → {n.name[:20]} ({n.entity_type.value})")
        else:
            # Show high-value entities
            vulns = self.get_by_type(EntityType.VULNERABILITY)
            if vulns:
                lines.append(f"\nVulnerabilities ({len(vulns)}):")
                for v in vulns[:5]:
                    lines.append(f"  {v.name[:30]}")

            hosts = self.get_by_type(EntityType.HOST)
            if hosts:
                lines.append(f"\nHosts ({len(hosts)}):")
                for h in hosts[:5]:
                    lines.append(f"  {h.name[:30]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for e in self._entities.values():
            type_counts[e.entity_type.value] = type_counts.get(e.entity_type.value, 0) + 1

        rel_counts: dict[str, int] = {}
        for r in self._relationships.values():
            rel_counts[r.rel_type.value] = rel_counts.get(r.rel_type.value, 0) + 1

        return {
            "entities": len(self._entities),
            "relationships": len(self._relationships),
            "by_type": type_counts,
            "by_rel_type": rel_counts,
        }
