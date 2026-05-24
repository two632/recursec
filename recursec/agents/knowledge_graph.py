"""Knowledge graph — entity-relationship intelligence.

Builds and queries a graph of security entities:
1. Nodes: hosts, services, vulns, findings, credentials
2. Edges: relationships (runs_on, exploits, authenticates)
3. Path finding: attack paths through the graph
4. Centrality: identify high-value targets
5. Pattern matching: find known attack patterns
6. LLM prompt generation from graph context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class NodeType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    CREDENTIAL = "credential"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    TECHNOLOGY = "technology"
    USER = "user"
    CERTIFICATE = "certificate"
    NETWORK = "network"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    DATABASE = "database"
    API_ENDPOINT = "api_endpoint"


class EdgeType(str, Enum):
    RUNS_ON = "runs_on"
    LISTENS_ON = "listens_on"
    EXPLOITS = "exploits"
    AUTHENTICATES = "authenticates"
    CONNECTS_TO = "connects_to"
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    USES_TECH = "uses_tech"
    HAS_VULN = "has_vuln"
    PART_OF = "part_of"
    TRUSTS = "trusts"
    ACCESSES = "accesses"
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    LEADS_TO = "leads_to"


@dataclass
class GraphNode:
    """A node in the knowledge graph."""
    node_id: str = ""
    node_type: NodeType = NodeType.HOST
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    severity: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:12],
            "type": self.node_type.value[:8],
            "label": self.label[:20],
        }


@dataclass
class GraphEdge:
    """An edge in the knowledge graph."""
    edge_id: str = ""
    edge_type: EdgeType = EdgeType.CONNECTS_TO
    source_id: str = ""
    target_id: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.edge_type.value[:10],
            "src": self.source_id[:8],
            "tgt": self.target_id[:8],
            "w": f"{self.weight:.1f}",
        }


@dataclass
class AttackPath:
    """An attack path through the graph."""
    path_id: str = ""
    nodes: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    total_weight: float = 0.0
    severity: str = "medium"
    description: str = ""

    @property
    def length(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path_id[:8],
            "length": self.length,
            "weight": f"{self.total_weight:.1f}",
            "severity": self.severity[:6],
        }


# Severity weights for path scoring
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
}

# Node type → typical properties
NODE_SCHEMAS: dict[NodeType, list[str]] = {
    NodeType.HOST: ["ip", "hostname", "os", "os_version"],
    NodeType.SERVICE: ["name", "version", "banner", "state"],
    NodeType.PORT: ["number", "protocol", "state"],
    NodeType.VULNERABILITY: [
        "cve", "cvss", "severity", "description", "exploitable",
    ],
    NodeType.CREDENTIAL: [
        "username", "credential_type", "service", "source",
    ],
    NodeType.DOMAIN: ["registrar", "creation_date", "nameservers"],
    NodeType.SUBDOMAIN: ["parent_domain", "cname", "ip"],
    NodeType.URL: ["path", "method", "status_code", "content_type"],
    NodeType.TECHNOLOGY: ["name", "version", "category"],
    NodeType.CLOUD_RESOURCE: [
        "provider", "resource_type", "region", "arn",
    ],
    NodeType.API_ENDPOINT: ["method", "path", "auth_required"],
}


class KnowledgeGraph:
    """Security knowledge graph.

    Maintains a graph of discovered entities
    and their relationships, enabling attack
    path analysis and context injection.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._adjacency: dict[str, list[str]] = {}  # node_id → edge_ids
        self._node_counter = 0
        self._edge_counter = 0
        self._paths: list[AttackPath] = []
        self._log = logger.bind(component="kg")

    def add_node(
        self,
        node_type: NodeType,
        label: str,
        properties: dict[str, Any] | None = None,
        severity: str = "",
        confidence: float = 1.0,
    ) -> GraphNode:
        """Add a node to the graph."""
        # Check for duplicate
        for existing in self._nodes.values():
            if existing.label == label and existing.node_type == node_type:
                # Update properties
                if properties:
                    existing.properties.update(properties)
                return existing

        self._node_counter += 1
        node = GraphNode(
            node_id=f"n-{self._node_counter}",
            node_type=node_type,
            label=label,
            properties=properties or {},
            severity=severity,
            confidence=confidence,
        )
        self._nodes[node.node_id] = node
        self._adjacency[node.node_id] = []
        return node

    def add_edge(
        self,
        edge_type: EdgeType,
        source_id: str,
        target_id: str,
        properties: dict[str, Any] | None = None,
        weight: float = 1.0,
    ) -> GraphEdge | None:
        """Add an edge to the graph."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        # Check for duplicate
        for existing in self._edges.values():
            if (
                existing.source_id == source_id
                and existing.target_id == target_id
                and existing.edge_type == edge_type
            ):
                return existing

        self._edge_counter += 1
        edge = GraphEdge(
            edge_id=f"e-{self._edge_counter}",
            edge_type=edge_type,
            source_id=source_id,
            target_id=target_id,
            properties=properties or {},
            weight=weight,
        )
        self._edges[edge.edge_id] = edge
        self._adjacency[source_id].append(edge.edge_id)
        return edge

    def get_neighbors(
        self,
        node_id: str,
        edge_type: EdgeType | None = None,
    ) -> list[GraphNode]:
        """Get neighboring nodes."""
        neighbors: list[GraphNode] = []
        for edge_id in self._adjacency.get(node_id, []):
            edge = self._edges.get(edge_id)
            if not edge:
                continue
            if edge_type and edge.edge_type != edge_type:
                continue
            target = self._nodes.get(edge.target_id)
            if target:
                neighbors.append(target)
        return neighbors

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Get all nodes of a specific type."""
        return [
            n for n in self._nodes.values()
            if n.node_type == node_type
        ]

    def get_vulnerabilities(self) -> list[GraphNode]:
        """Get all vulnerability nodes."""
        return self.get_nodes_by_type(NodeType.VULNERABILITY)

    def get_high_severity_nodes(self) -> list[GraphNode]:
        """Get nodes with high/critical severity."""
        return [
            n for n in self._nodes.values()
            if n.severity in ("critical", "high")
        ]

    def find_attack_paths(
        self,
        start_id: str,
        target_id: str,
        max_depth: int = 5,
    ) -> list[AttackPath]:
        """Find attack paths between two nodes using BFS."""
        if start_id not in self._nodes or target_id not in self._nodes:
            return []

        paths: list[AttackPath] = []
        queue: list[tuple[list[str], list[str], float]] = [
            ([start_id], [], 0.0),
        ]
        visited_paths: set[str] = set()

        while queue and len(paths) < 10:
            current_nodes, current_edges, current_weight = queue.pop(0)
            current_id = current_nodes[-1]

            if len(current_nodes) > max_depth:
                continue

            if current_id == target_id and len(current_nodes) > 1:
                path_key = "→".join(current_nodes)
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    path = AttackPath(
                        path_id=f"path-{len(paths) + 1}",
                        nodes=list(current_nodes),
                        edges=list(current_edges),
                        total_weight=current_weight,
                    )
                    paths.append(path)
                continue

            for edge_id in self._adjacency.get(current_id, []):
                edge = self._edges.get(edge_id)
                if not edge:
                    continue
                next_id = edge.target_id
                if next_id not in current_nodes:
                    queue.append((
                        current_nodes + [next_id],
                        current_edges + [edge_id],
                        current_weight + edge.weight,
                    ))

        return sorted(paths, key=lambda p: p.total_weight)

    def compute_centrality(self) -> dict[str, float]:
        """Compute degree centrality for each node."""
        centrality: dict[str, float] = {}
        total_nodes = max(1, len(self._nodes) - 1)

        for node_id in self._nodes:
            outgoing = len(self._adjacency.get(node_id, []))
            incoming = sum(
                1 for e in self._edges.values()
                if e.target_id == node_id
            )
            centrality[node_id] = (outgoing + incoming) / total_nodes

        return centrality

    def get_high_value_targets(self, top_n: int = 5) -> list[GraphNode]:
        """Get the highest-centrality nodes."""
        centrality = self.compute_centrality()
        sorted_ids = sorted(
            centrality, key=centrality.get, reverse=True,  # type: ignore[arg-type]
        )
        return [
            self._nodes[nid]
            for nid in sorted_ids[:top_n]
            if nid in self._nodes
        ]

    def build_graph_prompt(
        self,
        focus_node_id: str = "",
        max_nodes: int = 20,
    ) -> str:
        """Build graph context for LLM prompt."""
        lines = ["## Knowledge Graph\n"]
        lines.append(f"Nodes: {len(self._nodes)}")
        lines.append(f"Edges: {len(self._edges)}")

        # Type distribution
        type_counts: dict[str, int] = {}
        for n in self._nodes.values():
            type_counts[n.node_type.value] = (
                type_counts.get(n.node_type.value, 0) + 1
            )
        for ntype, count in sorted(
            type_counts.items(), key=lambda x: x[1], reverse=True,
        )[:5]:
            lines.append(f"  {ntype}: {count}")

        # High-severity nodes
        high_sev = self.get_high_severity_nodes()
        if high_sev:
            lines.append(f"\nHigh severity: {len(high_sev)}")
            for node in high_sev[:3]:
                lines.append(f"  [{node.severity[:4]}] {node.label[:25]}")

        # Focus node context
        if focus_node_id and focus_node_id in self._nodes:
            node = self._nodes[focus_node_id]
            neighbors = self.get_neighbors(focus_node_id)
            lines.append(f"\nFocus: {node.label}")
            lines.append(f"  Type: {node.node_type.value}")
            lines.append(f"  Neighbors: {len(neighbors)}")
            for nb in neighbors[:3]:
                lines.append(f"    → {nb.label[:20]} ({nb.node_type.value})")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for n in self._nodes.values():
            type_counts[n.node_type.value] = (
                type_counts.get(n.node_type.value, 0) + 1
            )

        edge_counts: dict[str, int] = {}
        for e in self._edges.values():
            edge_counts[e.edge_type.value] = (
                edge_counts.get(e.edge_type.value, 0) + 1
            )

        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "paths": len(self._paths),
            "by_node_type": type_counts,
            "by_edge_type": edge_counts,
        }
