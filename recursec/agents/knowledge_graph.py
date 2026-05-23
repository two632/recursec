"""Knowledge graph — entity relationships for attack chains.

Implements:
1. Entity nodes (hosts, services, vulns, credentials)
2. Typed relationship edges
3. Subgraph extraction
4. Path finding between entities
5. Attack surface visualization
6. Impact propagation analysis
7. Graph-based context for LLM
"""

from __future__ import annotations

import time
from collections import deque
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
    URL = "url"
    CERTIFICATE = "certificate"
    SOFTWARE = "software"
    FINDING = "finding"
    NETWORK = "network"


class RelationType(str, Enum):
    HOSTS = "hosts"             # network → host
    RUNS = "runs"               # host → service
    LISTENS_ON = "listens_on"   # service → port
    HAS_VULN = "has_vuln"       # service → vulnerability
    AUTHENTICATES = "authenticates"  # credential → service
    RESOLVES_TO = "resolves_to"     # domain → host
    SERVES = "serves"               # host → url
    USES = "uses"                   # service → software
    ISSUED_TO = "issued_to"         # certificate → domain
    EXPLOITS = "exploits"           # finding → vulnerability
    LEADS_TO = "leads_to"           # vulnerability → vulnerability
    OWNS = "owns"                   # user → credential
    MEMBER_OF = "member_of"         # user → group


@dataclass
class GraphNode:
    """An entity in the knowledge graph."""
    node_id: str = ""
    entity_type: EntityType = EntityType.HOST
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:12],
            "type": self.entity_type.value,
            "label": self.label[:25],
        }


@dataclass
class GraphEdge:
    """A relationship in the knowledge graph."""
    edge_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relation: RelationType = RelationType.HOSTS
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.source_id[:12],
            "rel": self.relation.value,
            "tgt": self.target_id[:12],
            "conf": round(self.confidence, 2),
        }


class KnowledgeGraph:
    """Manages an entity knowledge graph for assessments.

    Stores discovered entities and their relationships,
    supports path finding for attack chain analysis,
    and provides graph context for LLM reasoning.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._adjacency: dict[str, list[str]] = {}   # node_id → [edge_ids]
        self._node_counter = 0
        self._edge_counter = 0
        self._log = logger.bind(component="knowledge_graph")

    def add_node(
        self,
        entity_type: EntityType,
        label: str,
        properties: dict[str, Any] | None = None,
    ) -> GraphNode:
        """Add an entity node."""
        # Check for duplicate
        for node in self._nodes.values():
            if node.entity_type == entity_type and node.label == label:
                if properties:
                    node.properties.update(properties)
                return node

        self._node_counter += 1
        node = GraphNode(
            node_id=f"n-{self._node_counter}",
            entity_type=entity_type,
            label=label,
            properties=properties or {},
        )
        self._nodes[node.node_id] = node
        self._adjacency[node.node_id] = []
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: RelationType,
        confidence: float = 1.0,
        properties: dict[str, Any] | None = None,
    ) -> GraphEdge | None:
        """Add a relationship edge."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        # Check for duplicate
        for eid in self._adjacency.get(source_id, []):
            edge = self._edges.get(eid)
            if edge and edge.target_id == target_id and edge.relation == relation:
                return edge

        self._edge_counter += 1
        edge = GraphEdge(
            edge_id=f"e-{self._edge_counter}",
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            confidence=confidence,
            properties=properties or {},
        )
        self._edges[edge.edge_id] = edge
        self._adjacency.setdefault(source_id, []).append(edge.edge_id)

        return edge

    def get_neighbors(
        self,
        node_id: str,
        relation: RelationType | None = None,
    ) -> list[tuple[GraphEdge, GraphNode]]:
        """Get neighboring nodes."""
        results: list[tuple[GraphEdge, GraphNode]] = []
        for eid in self._adjacency.get(node_id, []):
            edge = self._edges.get(eid)
            if not edge:
                continue
            if relation and edge.relation != relation:
                continue
            target = self._nodes.get(edge.target_id)
            if target:
                results.append((edge, target))
        return results

    def find_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Find all paths between two nodes (BFS)."""
        if start_id not in self._nodes or end_id not in self._nodes:
            return []

        queue: deque[list[str]] = deque([[start_id]])
        paths: list[list[str]] = []

        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue

            current = path[-1]
            if current == end_id and len(path) > 1:
                paths.append(path)
                continue

            for eid in self._adjacency.get(current, []):
                edge = self._edges.get(eid)
                if edge and edge.target_id not in path:
                    queue.append(path + [edge.target_id])

        return paths

    def get_attack_surface(self) -> dict[str, Any]:
        """Summarize the attack surface from the graph."""
        hosts = [n for n in self._nodes.values() if n.entity_type == EntityType.HOST]
        services = [n for n in self._nodes.values() if n.entity_type == EntityType.SERVICE]
        vulns = [n for n in self._nodes.values() if n.entity_type == EntityType.VULNERABILITY]
        creds = [n for n in self._nodes.values() if n.entity_type == EntityType.CREDENTIAL]

        return {
            "hosts": len(hosts),
            "services": len(services),
            "vulnerabilities": len(vulns),
            "credentials": len(creds),
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
        }

    def get_subgraph(
        self,
        center_id: str,
        depth: int = 2,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Extract a subgraph around a node."""
        visited: set[str] = set()
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        queue: deque[tuple[str, int]] = deque([(center_id, 0)])

        while queue:
            nid, d = queue.popleft()
            if nid in visited or d > depth:
                continue
            visited.add(nid)

            node = self._nodes.get(nid)
            if node:
                nodes.append(node)

            for eid in self._adjacency.get(nid, []):
                edge = self._edges.get(eid)
                if edge:
                    edges.append(edge)
                    if edge.target_id not in visited:
                        queue.append((edge.target_id, d + 1))

        return nodes, edges

    def build_graph_prompt(
        self,
        focus_id: str = "",
        max_nodes: int = 20,
    ) -> str:
        """Build knowledge graph context for LLM."""
        lines = ["## Knowledge Graph\n"]

        surface = self.get_attack_surface()
        lines.append(
            f"Attack surface: {surface['hosts']} hosts, "
            f"{surface['services']} services, "
            f"{surface['vulnerabilities']} vulns"
        )

        if focus_id:
            nodes, edges = self.get_subgraph(focus_id, depth=2)
            lines.append(f"\nSubgraph around {focus_id[:12]}:")
            for edge in edges[:max_nodes]:
                src = self._nodes.get(edge.source_id)
                tgt = self._nodes.get(edge.target_id)
                if src and tgt:
                    lines.append(
                        f"  {src.label[:15]} --[{edge.relation.value}]--> {tgt.label[:15]}"
                    )
        else:
            # Show high-value nodes
            vulns = [n for n in self._nodes.values() if n.entity_type == EntityType.VULNERABILITY]
            if vulns:
                lines.append(f"\nVulnerabilities ({len(vulns)}):")
                for v in vulns[:5]:
                    lines.append(f"  - {v.label[:40]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for n in self._nodes.values():
            type_counts[n.entity_type.value] = type_counts.get(n.entity_type.value, 0) + 1

        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_type": type_counts,
        }
