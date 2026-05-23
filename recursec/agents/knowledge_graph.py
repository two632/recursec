"""Knowledge graph — stores and queries relationships between security entities.

Implements:
1. Entity node management (targets, vulns, services, etc.)
2. Relationship edge management
3. Graph traversal queries
4. Path finding between entities
5. Subgraph extraction
6. Pattern matching in graph
7. Graph persistence (JSON)
8. Entity scoring based on relationships
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class GraphNode:
    """A node in the knowledge graph."""
    node_id: str = ""
    node_type: str = ""          # target, service, vuln, finding, tool, domain, ip, cve, cwe
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id, "type": self.node_type,
            "label": self.label[:40],
            "props": len(self.properties),
        }


@dataclass
class GraphEdge:
    """An edge (relationship) in the knowledge graph."""
    edge_id: str = ""
    source: str = ""
    target: str = ""
    relation: str = ""           # has_port, runs_service, has_vuln, found_by, resolves_to, etc.
    weight: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id, "source": self.source[:20],
            "target": self.target[:20], "relation": self.relation,
            "weight": round(self.weight, 2),
        }


class KnowledgeGraph:
    """Stores and queries relationships between security entities.

    Provides graph-based knowledge management with
    traversal, path finding, and pattern matching.
    """

    def __init__(self, data_dir: str = "data/knowledge") -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        # Adjacency lists
        self._outgoing: dict[str, list[str]] = defaultdict(list)   # node_id -> [edge_ids]
        self._incoming: dict[str, list[str]] = defaultdict(list)   # node_id -> [edge_ids]
        self._node_counter = 0
        self._edge_counter = 0
        self._log = logger.bind(component="knowledge_graph")

    def add_node(
        self,
        node_type: str,
        label: str,
        properties: dict[str, Any] | None = None,
        node_id: str = "",
    ) -> str:
        """Add a node to the graph."""
        if not node_id:
            self._node_counter += 1
            node_id = f"n-{self._node_counter}"

        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
        )
        self._nodes[node_id] = node
        return node_id

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        weight: float = 1.0,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Add an edge between two nodes."""
        if source not in self._nodes or target not in self._nodes:
            return ""

        self._edge_counter += 1
        edge_id = f"e-{self._edge_counter}"

        edge = GraphEdge(
            edge_id=edge_id,
            source=source,
            target=target,
            relation=relation,
            weight=weight,
            properties=properties or {},
        )
        self._edges[edge_id] = edge
        self._outgoing[source].append(edge_id)
        self._incoming[target].append(edge_id)
        return edge_id

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "out",
        relation: str = "",
    ) -> list[GraphNode]:
        """Get neighboring nodes."""
        neighbors = []

        if direction in ("out", "both"):
            for edge_id in self._outgoing.get(node_id, []):
                edge = self._edges.get(edge_id)
                if edge and (not relation or edge.relation == relation):
                    node = self._nodes.get(edge.target)
                    if node:
                        neighbors.append(node)

        if direction in ("in", "both"):
            for edge_id in self._incoming.get(node_id, []):
                edge = self._edges.get(edge_id)
                if edge and (not relation or edge.relation == relation):
                    node = self._nodes.get(edge.source)
                    if node:
                        neighbors.append(node)

        return neighbors

    def find_path(
        self,
        start: str,
        end: str,
        max_depth: int = 10,
    ) -> list[str]:
        """Find shortest path between two nodes (BFS)."""
        if start not in self._nodes or end not in self._nodes:
            return []

        visited: set[str] = {start}
        queue: deque[tuple[str, list[str]]] = deque([(start, [start])])

        while queue:
            current, path = queue.popleft()

            if current == end:
                return path

            if len(path) >= max_depth:
                continue

            for edge_id in self._outgoing.get(current, []):
                edge = self._edges.get(edge_id)
                if edge and edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))

        return []

    def find_nodes_by_type(
        self,
        node_type: str,
        limit: int = 50,
    ) -> list[GraphNode]:
        """Find all nodes of a given type."""
        results = []
        for node in self._nodes.values():
            if node.node_type == node_type:
                results.append(node)
                if len(results) >= limit:
                    break
        return results

    def find_patterns(
        self,
        pattern: list[tuple[str, str, str]],
    ) -> list[list[str]]:
        """Find subgraphs matching a pattern.

        Pattern is a list of (source_type, relation, target_type) triples.
        """
        if not pattern:
            return []

        # Start with first pattern element
        first_type, first_rel, _ = pattern[0]
        candidates = self.find_nodes_by_type(first_type)
        results = []

        for start_node in candidates:
            path = self._match_pattern_from(start_node.node_id, pattern, 0)
            if path:
                results.append(path)

        return results

    def _match_pattern_from(
        self,
        node_id: str,
        pattern: list[tuple[str, str, str]],
        pattern_idx: int,
    ) -> list[str]:
        """Recursively match a pattern from a starting node."""
        if pattern_idx >= len(pattern):
            return [node_id]

        _, relation, target_type = pattern[pattern_idx]

        neighbors = self.get_neighbors(node_id, direction="out", relation=relation)

        for neighbor in neighbors:
            if neighbor.node_type == target_type:
                rest = self._match_pattern_from(
                    neighbor.node_id, pattern, pattern_idx + 1,
                )
                if rest:
                    return [node_id] + rest

        return []

    def score_node(self, node_id: str) -> float:
        """Score a node based on its connections."""
        node = self._nodes.get(node_id)
        if not node:
            return 0.0

        score = 0.0

        # Degree centrality
        out_degree = len(self._outgoing.get(node_id, []))
        in_degree = len(self._incoming.get(node_id, []))
        score += (out_degree + in_degree) * 0.1

        # Weighted connections
        for edge_id in self._outgoing.get(node_id, []) + self._incoming.get(node_id, []):
            edge = self._edges.get(edge_id)
            if edge:
                score += edge.weight * 0.2

        return min(10.0, score)

    def subgraph(
        self,
        center: str,
        depth: int = 2,
    ) -> dict[str, Any]:
        """Extract a subgraph around a center node."""
        nodes: set[str] = set()
        edges_found: list[str] = []

        queue: deque[tuple[str, int]] = deque([(center, 0)])
        visited: set[str] = {center}

        while queue:
            current, current_depth = queue.popleft()
            nodes.add(current)

            if current_depth >= depth:
                continue

            for edge_id in self._outgoing.get(current, []):
                edge = self._edges.get(edge_id)
                if edge:
                    edges_found.append(edge_id)
                    if edge.target not in visited:
                        visited.add(edge.target)
                        queue.append((edge.target, current_depth + 1))

        return {
            "center": center,
            "nodes": [self._nodes[n].to_dict() for n in nodes if n in self._nodes],
            "edges": [self._edges[e].to_dict() for e in edges_found if e in self._edges],
        }

    def save(self) -> str:
        """Save graph to disk."""
        path = self._data_dir / "graph.json"
        data = {
            "nodes": {nid: {"type": n.node_type, "label": n.label, "props": n.properties}
                      for nid, n in self._nodes.items()},
            "edges": {eid: {"source": e.source, "target": e.target,
                           "relation": e.relation, "weight": e.weight}
                      for eid, e in self._edges.items()},
        }
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    def load(self) -> bool:
        """Load graph from disk."""
        path = self._data_dir / "graph.json"
        if not path.exists():
            return False

        try:
            data = json.loads(path.read_text())
            for nid, ndata in data.get("nodes", {}).items():
                self.add_node(
                    node_type=ndata["type"],
                    label=ndata["label"],
                    properties=ndata.get("props", {}),
                    node_id=nid,
                )
            for eid_key, edata in data.get("edges", {}).items():
                self.add_edge(
                    source=edata["source"],
                    target=edata["target"],
                    relation=edata["relation"],
                    weight=edata.get("weight", 1.0),
                )
            return True
        except (json.JSONDecodeError, OSError, KeyError):
            return False

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type] += 1

        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "node_types": dict(type_counts),
        }
