"""Knowledge graph — structured relationships between security concepts.

Builds and maintains a graph of:
1. Vulnerabilities and their relationships
2. Techniques (MITRE ATT&CK mapping)
3. Tools and their capabilities
4. Targets and their components
5. Findings and evidence chains
6. Remediation actions

Supports:
- Entity creation and linking
- Relationship traversal
- Pattern matching
- Subgraph extraction
- Graph-based reasoning
- Persistence (JSON)
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


class EntityType(str, Enum):
    VULNERABILITY = "vulnerability"
    TECHNIQUE = "technique"
    TOOL = "tool"
    TARGET = "target"
    HOST = "host"
    SERVICE = "service"
    FINDING = "finding"
    EVIDENCE = "evidence"
    REMEDIATION = "remediation"
    CVE = "cve"
    CWE = "cwe"
    PORT = "port"
    CREDENTIAL = "credential"
    TECHNOLOGY = "technology"
    ATTACKER = "attacker"
    ASSET = "asset"


class RelationType(str, Enum):
    EXPLOITS = "exploits"           # Technique → Vulnerability
    USES_TOOL = "uses_tool"         # Technique → Tool
    AFFECTS = "affects"             # Vulnerability → Target
    RUNS_ON = "runs_on"            # Service → Host
    HAS_PORT = "has_port"          # Host → Port
    DISCOVERED_BY = "discovered_by"  # Finding → Tool
    EVIDENCE_FOR = "evidence_for"    # Evidence → Finding
    REMEDIATES = "remediates"       # Remediation → Vulnerability
    RELATED_TO = "related_to"       # Generic relationship
    DEPENDS_ON = "depends_on"       # Dependency
    LEADS_TO = "leads_to"          # Chaining relationship
    MITIGATED_BY = "mitigated_by"   # Vulnerability → Control
    IDENTIFIED_AS = "identified_as"  # Finding → CVE
    CLASSIFIED_AS = "classified_as"  # Finding → CWE
    AUTHENTICATES = "authenticates"  # Credential → Service
    USES_TECH = "uses_tech"        # Target → Technology


@dataclass
class Entity:
    """An entity in the knowledge graph."""
    entity_id: str = ""
    entity_type: EntityType = EntityType.FINDING
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id,
            "type": self.entity_type.value,
            "name": self.name[:100],
            "properties": {k: str(v)[:50] for k, v in list(self.properties.items())[:5]},
        }


@dataclass
class Relationship:
    """A relationship between two entities."""
    rel_id: str = ""
    source: str = ""        # Entity ID
    target: str = ""        # Entity ID
    rel_type: RelationType = RelationType.RELATED_TO
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rel_id,
            "from": self.source,
            "to": self.target,
            "type": self.rel_type.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class GraphQuery:
    """A query against the knowledge graph."""
    entity_type: EntityType | None = None
    rel_type: RelationType | None = None
    name_contains: str = ""
    property_filters: dict[str, Any] = field(default_factory=dict)
    max_depth: int = 1
    limit: int = 50


class KnowledgeGraph:
    """Knowledge graph for structured security relationships.

    Stores entities (vulns, techniques, tools, targets) and
    relationships between them for graph-based reasoning.
    """

    def __init__(self, storage_path: str = "data/knowledge_graph.json") -> None:
        self._storage_path = Path(storage_path)
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)

        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, Relationship] = {}
        self._adjacency: dict[str, list[str]] = defaultdict(list)    # entity_id → [rel_ids]
        self._reverse_adj: dict[str, list[str]] = defaultdict(list)  # entity_id → [incoming rel_ids]
        self._type_index: dict[str, set[str]] = defaultdict(set)     # type → {entity_ids}

        self._entity_counter = 0
        self._rel_counter = 0
        self._log = logger.bind(component="knowledge_graph")

        self._load()

    # ── Entity Operations ────────────────────────────────

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: dict[str, Any] | None = None,
        entity_id: str = "",
    ) -> str:
        """Add an entity to the graph."""
        if not entity_id:
            self._entity_counter += 1
            entity_id = f"{entity_type.value}-{self._entity_counter}"

        # Check for duplicates
        for existing in self._entities.values():
            if existing.name == name and existing.entity_type == entity_type:
                existing.properties.update(properties or {})
                existing.updated_at = time.time()
                return existing.entity_id

        entity = Entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            properties=properties or {},
        )

        self._entities[entity_id] = entity
        self._type_index[entity_type.value].add(entity_id)

        return entity_id

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def find_entities(
        self,
        entity_type: EntityType | None = None,
        name_contains: str = "",
        **properties: Any,
    ) -> list[Entity]:
        """Find entities matching criteria."""
        results = list(self._entities.values())

        if entity_type:
            type_ids = self._type_index.get(entity_type.value, set())
            results = [e for e in results if e.entity_id in type_ids]

        if name_contains:
            lower = name_contains.lower()
            results = [e for e in results if lower in e.name.lower()]

        for key, value in properties.items():
            results = [e for e in results if e.properties.get(key) == value]

        return results

    def update_entity(
        self,
        entity_id: str,
        properties: dict[str, Any],
    ) -> bool:
        """Update entity properties."""
        entity = self._entities.get(entity_id)
        if not entity:
            return False
        entity.properties.update(properties)
        entity.updated_at = time.time()
        return True

    def remove_entity(self, entity_id: str) -> bool:
        """Remove an entity and its relationships."""
        if entity_id not in self._entities:
            return False

        # Remove relationships
        rel_ids = list(self._adjacency.get(entity_id, []))
        rel_ids.extend(self._reverse_adj.get(entity_id, []))
        for rel_id in set(rel_ids):
            self.remove_relationship(rel_id)

        entity = self._entities.pop(entity_id)
        self._type_index[entity.entity_type.value].discard(entity_id)

        return True

    # ── Relationship Operations ──────────────────────────

    def add_relationship(
        self,
        source: str,
        target: str,
        rel_type: RelationType,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> str:
        """Add a relationship between entities."""
        if source not in self._entities or target not in self._entities:
            return ""

        # Check for duplicate
        for rel in self._relationships.values():
            if rel.source == source and rel.target == target and rel.rel_type == rel_type:
                rel.properties.update(properties or {})
                rel.confidence = max(rel.confidence, confidence)
                return rel.rel_id

        self._rel_counter += 1
        rel_id = f"rel-{self._rel_counter}"

        rel = Relationship(
            rel_id=rel_id,
            source=source,
            target=target,
            rel_type=rel_type,
            properties=properties or {},
            confidence=confidence,
        )

        self._relationships[rel_id] = rel
        self._adjacency[source].append(rel_id)
        self._reverse_adj[target].append(rel_id)

        return rel_id

    def get_relationships(
        self,
        entity_id: str,
        direction: str = "outgoing",  # outgoing, incoming, both
        rel_type: RelationType | None = None,
    ) -> list[Relationship]:
        """Get relationships for an entity."""
        rel_ids: set[str] = set()

        if direction in ("outgoing", "both"):
            rel_ids.update(self._adjacency.get(entity_id, []))
        if direction in ("incoming", "both"):
            rel_ids.update(self._reverse_adj.get(entity_id, []))

        rels = [self._relationships[rid] for rid in rel_ids if rid in self._relationships]

        if rel_type:
            rels = [r for r in rels if r.rel_type == rel_type]

        return rels

    def remove_relationship(self, rel_id: str) -> bool:
        rel = self._relationships.pop(rel_id, None)
        if not rel:
            return False
        if rel_id in self._adjacency.get(rel.source, []):
            self._adjacency[rel.source].remove(rel_id)
        if rel_id in self._reverse_adj.get(rel.target, []):
            self._reverse_adj[rel.target].remove(rel_id)
        return True

    # ── Graph Traversal ──────────────────────────────────

    def traverse(
        self,
        start: str,
        max_depth: int = 3,
        rel_types: list[RelationType] | None = None,
    ) -> dict[str, Any]:
        """Traverse the graph from a starting entity."""
        visited: set[str] = set()
        result: dict[str, Any] = {"nodes": [], "edges": []}

        queue: list[tuple[str, int]] = [(start, 0)]

        while queue:
            entity_id, depth = queue.pop(0)
            if entity_id in visited or depth > max_depth:
                continue

            visited.add(entity_id)
            entity = self._entities.get(entity_id)
            if entity:
                result["nodes"].append(entity.to_dict())

            for rel_id in self._adjacency.get(entity_id, []):
                rel = self._relationships.get(rel_id)
                if not rel:
                    continue
                if rel_types and rel.rel_type not in rel_types:
                    continue
                result["edges"].append(rel.to_dict())
                if rel.target not in visited:
                    queue.append((rel.target, depth + 1))

        return result

    def find_paths(
        self,
        start: str,
        end: str,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Find all paths between two entities."""
        paths: list[list[str]] = []
        stack: list[tuple[str, list[str], set[str]]] = [(start, [start], {start})]

        while stack and len(paths) < 10:
            current, path, visited = stack.pop()

            if current == end and len(path) > 1:
                paths.append(path)
                continue

            if len(path) > max_depth:
                continue

            for rel_id in self._adjacency.get(current, []):
                rel = self._relationships.get(rel_id)
                if rel and rel.target not in visited:
                    stack.append((
                        rel.target,
                        path + [rel.target],
                        visited | {rel.target},
                    ))

        return paths

    def get_neighbors(
        self,
        entity_id: str,
        direction: str = "both",
    ) -> list[Entity]:
        """Get neighboring entities."""
        neighbor_ids: set[str] = set()

        if direction in ("outgoing", "both"):
            for rel_id in self._adjacency.get(entity_id, []):
                rel = self._relationships.get(rel_id)
                if rel:
                    neighbor_ids.add(rel.target)

        if direction in ("incoming", "both"):
            for rel_id in self._reverse_adj.get(entity_id, []):
                rel = self._relationships.get(rel_id)
                if rel:
                    neighbor_ids.add(rel.source)

        return [self._entities[nid] for nid in neighbor_ids if nid in self._entities]

    # ── Convenience Methods ──────────────────────────────

    def add_finding(
        self,
        title: str,
        severity: str = "medium",
        target: str = "",
        tool: str = "",
        cve: str = "",
        **extra: Any,
    ) -> str:
        """Add a finding with relationships."""
        finding_id = self.add_entity(
            EntityType.FINDING, title,
            {"severity": severity, **extra},
        )

        if target:
            target_id = self.add_entity(EntityType.TARGET, target)
            self.add_relationship(finding_id, target_id, RelationType.AFFECTS)

        if tool:
            tool_id = self.add_entity(EntityType.TOOL, tool)
            self.add_relationship(finding_id, tool_id, RelationType.DISCOVERED_BY)

        if cve:
            cve_id = self.add_entity(EntityType.CVE, cve)
            self.add_relationship(finding_id, cve_id, RelationType.IDENTIFIED_AS)

        return finding_id

    def add_technique(
        self,
        name: str,
        mitre_id: str = "",
        tools: list[str] | None = None,
        vulnerabilities: list[str] | None = None,
    ) -> str:
        """Add a MITRE ATT&CK technique with relationships."""
        tech_id = self.add_entity(
            EntityType.TECHNIQUE, name,
            {"mitre_id": mitre_id} if mitre_id else {},
        )

        for tool_name in (tools or []):
            tool_id = self.add_entity(EntityType.TOOL, tool_name)
            self.add_relationship(tech_id, tool_id, RelationType.USES_TOOL)

        for vuln_name in (vulnerabilities or []):
            vuln_id = self.add_entity(EntityType.VULNERABILITY, vuln_name)
            self.add_relationship(tech_id, vuln_id, RelationType.EXPLOITS)

        return tech_id

    # ── Persistence ──────────────────────────────────────

    def save(self) -> None:
        """Persist graph to disk."""
        try:
            data = {
                "entities": {
                    eid: {
                        "id": e.entity_id,
                        "type": e.entity_type.value,
                        "name": e.name,
                        "properties": e.properties,
                    }
                    for eid, e in self._entities.items()
                },
                "relationships": {
                    rid: {
                        "id": r.rel_id,
                        "source": r.source,
                        "target": r.target,
                        "type": r.rel_type.value,
                        "properties": r.properties,
                        "confidence": r.confidence,
                    }
                    for rid, r in self._relationships.items()
                },
                "counters": {
                    "entity": self._entity_counter,
                    "rel": self._rel_counter,
                },
            }
            self._storage_path.write_text(json.dumps(data))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def _load(self) -> None:
        """Load graph from disk."""
        if not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text())

            for eid, e_data in data.get("entities", {}).items():
                try:
                    etype = EntityType(e_data["type"])
                except ValueError:
                    etype = EntityType.FINDING
                entity = Entity(
                    entity_id=eid,
                    entity_type=etype,
                    name=e_data.get("name", ""),
                    properties=e_data.get("properties", {}),
                )
                self._entities[eid] = entity
                self._type_index[etype.value].add(eid)

            for rid, r_data in data.get("relationships", {}).items():
                try:
                    rtype = RelationType(r_data["type"])
                except ValueError:
                    rtype = RelationType.RELATED_TO
                rel = Relationship(
                    rel_id=rid,
                    source=r_data["source"],
                    target=r_data["target"],
                    rel_type=rtype,
                    properties=r_data.get("properties", {}),
                    confidence=r_data.get("confidence", 1.0),
                )
                self._relationships[rid] = rel
                self._adjacency[rel.source].append(rid)
                self._reverse_adj[rel.target].append(rid)

            counters = data.get("counters", {})
            self._entity_counter = counters.get("entity", 0)
            self._rel_counter = counters.get("rel", 0)

        except (json.JSONDecodeError, OSError):
            pass

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {
            t: len(ids) for t, ids in self._type_index.items()
        }
        by_rel: dict[str, int] = defaultdict(int)
        for r in self._relationships.values():
            by_rel[r.rel_type.value] += 1
        return {
            "entities": len(self._entities),
            "relationships": len(self._relationships),
            "entity_types": dict(by_type),
            "relationship_types": dict(by_rel),
        }
