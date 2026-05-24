"""Knowledge graph reasoner — connects findings via graph relationships.

Implements:
1. Entity-relationship graph for security findings
2. Relationship inference (attack paths, correlation)
3. Graph traversal for attack chain discovery
4. Pattern matching across findings
5. Graph-based risk scoring
6. Knowledge graph prompt for LLM
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
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    USER = "user"
    NETWORK = "network"
    APPLICATION = "application"
    DOMAIN = "domain"
    FINDING = "finding"
    TOOL = "tool"


class RelationType(str, Enum):
    RUNS_ON = "runs_on"             # Service → Host
    EXPLOITS = "exploits"           # Vuln → Service
    AUTHENTICATES = "authenticates"  # Credential → Service
    CONNECTS_TO = "connects_to"     # Host → Host
    BELONGS_TO = "belongs_to"       # Host → Network
    DISCOVERED_BY = "discovered_by"  # Finding → Tool
    LEADS_TO = "leads_to"           # Finding → Finding (attack chain)
    ASSOCIATED_WITH = "associated_with"  # General association
    PART_OF = "part_of"             # Subdomain → Domain
    ACCESSES = "accesses"           # User → Application


@dataclass
class GraphEntity:
    """An entity in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id[:10],
            "type": self.entity_type.value[:6],
            "name": self.name[:20],
            "risk": f"{self.risk_score:.1f}",
        }


@dataclass
class GraphRelation:
    """A relationship in the knowledge graph."""
    relation_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relation_type: RelationType = RelationType.ASSOCIATED_WITH
    confidence: float = 0.5
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.source_id[:10],
            "rel": self.relation_type.value[:8],
            "tgt": self.target_id[:10],
            "conf": f"{self.confidence:.2f}",
        }


class KnowledgeGraphReasoner:
    """Graph-based reasoning over security findings.

    Connects entities via relationships, discovers
    attack paths, correlates findings, and provides
    graph-based risk assessment.
    """

    def __init__(self) -> None:
        self._entities: dict[str, GraphEntity] = {}
        self._relations: list[GraphRelation] = []
        self._adjacency: dict[str, list[str]] = {}  # entity_id → [relation indices]
        self._entity_counter = 0
        self._relation_counter = 0
        self._log = logger.bind(component="kg_reasoner")

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: dict[str, Any] | None = None,
        risk_score: float = 0.0,
    ) -> GraphEntity:
        """Add an entity to the graph."""
        self._entity_counter += 1
        entity = GraphEntity(
            entity_id=f"ent-{self._entity_counter}",
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            risk_score=risk_score,
        )
        self._entities[entity.entity_id] = entity
        self._adjacency.setdefault(entity.entity_id, [])
        return entity

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        confidence: float = 0.5,
        properties: dict[str, Any] | None = None,
    ) -> GraphRelation | None:
        """Add a relationship between entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return None

        self._relation_counter += 1
        relation = GraphRelation(
            relation_id=f"rel-{self._relation_counter}",
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            confidence=confidence,
            properties=properties or {},
        )
        self._relations.append(relation)

        rel_idx = str(len(self._relations) - 1)
        self._adjacency.setdefault(source_id, []).append(rel_idx)
        self._adjacency.setdefault(target_id, []).append(rel_idx)

        return relation

    def find_attack_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 6,
    ) -> list[list[str]]:
        """Find all attack paths between two entities."""
        paths: list[list[str]] = []
        self._dfs_paths(start_id, end_id, [start_id], set(), paths, max_depth)
        return paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: list[str],
        visited: set[str],
        paths: list[list[str]],
        max_depth: int,
    ) -> None:
        """DFS for path finding."""
        if len(path) > max_depth:
            return

        if current == target:
            paths.append(list(path))
            return

        visited.add(current)

        for rel_idx in self._adjacency.get(current, []):
            idx = int(rel_idx)
            if idx >= len(self._relations):
                continue
            rel = self._relations[idx]

            # Follow outgoing relations
            next_id = ""
            if rel.source_id == current:
                next_id = rel.target_id
            elif rel.target_id == current:
                next_id = rel.source_id

            if next_id and next_id not in visited:
                path.append(next_id)
                self._dfs_paths(next_id, target, path, visited, paths, max_depth)
                path.pop()

        visited.discard(current)

    def get_neighbors(
        self,
        entity_id: str,
        relation_type: RelationType | None = None,
    ) -> list[GraphEntity]:
        """Get neighboring entities."""
        neighbors = []

        for rel_idx in self._adjacency.get(entity_id, []):
            idx = int(rel_idx)
            if idx >= len(self._relations):
                continue
            rel = self._relations[idx]

            if relation_type and rel.relation_type != relation_type:
                continue

            neighbor_id = ""
            if rel.source_id == entity_id:
                neighbor_id = rel.target_id
            elif rel.target_id == entity_id:
                neighbor_id = rel.source_id

            if neighbor_id and neighbor_id in self._entities:
                neighbors.append(self._entities[neighbor_id])

        return neighbors

    def calculate_risk_propagation(self) -> dict[str, float]:
        """Propagate risk scores through the graph."""
        risk_scores: dict[str, float] = {}
        for eid, entity in self._entities.items():
            risk_scores[eid] = entity.risk_score

        # Propagate risk through relationships (3 iterations)
        for _ in range(3):
            new_scores = dict(risk_scores)
            for rel in self._relations:
                source_risk = risk_scores.get(rel.source_id, 0)
                target_risk = risk_scores.get(rel.target_id, 0)

                # Risk flows through LEADS_TO and EXPLOITS
                if rel.relation_type in (RelationType.LEADS_TO, RelationType.EXPLOITS):
                    propagated = source_risk * rel.confidence * 0.5
                    new_scores[rel.target_id] = max(
                        new_scores.get(rel.target_id, 0),
                        target_risk + propagated,
                    )

            risk_scores = new_scores

        return risk_scores

    def find_by_type(self, entity_type: EntityType) -> list[GraphEntity]:
        """Find all entities of a given type."""
        return [e for e in self._entities.values() if e.entity_type == entity_type]

    def get_entity_context(self, entity_id: str) -> dict[str, Any]:
        """Get full context for an entity."""
        entity = self._entities.get(entity_id)
        if not entity:
            return {}

        neighbors = self.get_neighbors(entity_id)
        relations = [
            r for r in self._relations
            if r.source_id == entity_id or r.target_id == entity_id
        ]

        return {
            "entity": entity.to_dict(),
            "neighbors": [n.to_dict() for n in neighbors],
            "relations": [r.to_dict() for r in relations],
        }

    def build_graph_prompt(self, focus_entity_id: str = "") -> str:
        """Build knowledge graph context for LLM."""
        lines = ["## Knowledge Graph\n"]
        lines.append(f"Entities: {len(self._entities)}")
        lines.append(f"Relations: {len(self._relations)}")

        # Type distribution
        type_counts: dict[str, int] = {}
        for e in self._entities.values():
            t = e.entity_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        lines.append("\nEntity types:")
        for etype, count in type_counts.items():
            lines.append(f"  {etype}: {count}")

        # High-risk entities
        risk_scores = self.calculate_risk_propagation()
        sorted_risks = sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)

        if sorted_risks:
            lines.append("\nHighest risk:")
            for eid, score in sorted_risks[:5]:
                entity = self._entities.get(eid)
                if entity and score > 0:
                    lines.append(f"  {entity.name[:20]}: {score:.1f}")

        # Focus entity context
        if focus_entity_id and focus_entity_id in self._entities:
            ctx = self.get_entity_context(focus_entity_id)
            lines.append(f"\nFocus: {ctx['entity']['name']}")
            lines.append(f"Neighbors: {len(ctx['neighbors'])}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for e in self._entities.values():
            t = e.entity_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        rel_counts: dict[str, int] = {}
        for r in self._relations:
            t = r.relation_type.value
            rel_counts[t] = rel_counts.get(t, 0) + 1

        return {
            "entities": len(self._entities),
            "relations": len(self._relations),
            "entity_types": type_counts,
            "relation_types": rel_counts,
        }
