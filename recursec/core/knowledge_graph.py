"""Knowledge graph — models relationships between discovered entities.

This builds a graph of the target's attack surface: hosts, services, endpoints,
users, credentials, vulnerabilities, and their relationships. Enables agents
to reason about lateral movement paths, attack chains, and interdependencies.

Node types: Host, Service, Port, Endpoint, User, Credential, Vulnerability,
            Domain, Subdomain, Certificate, Technology, Database, Container,
            NetworkRange, ASN, Organization

Edge types: RUNS_ON, EXPOSES, HAS_VULN, AUTHENTICATES_TO, CONNECTS_TO,
            DELEGATES_TO, BELONGS_TO, RESOLVED_FROM, CHAINS_TO, DEPENDS_ON
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    ENDPOINT = "endpoint"
    USER = "user"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    DATABASE = "database"
    CONTAINER = "container"
    NETWORK_RANGE = "network_range"
    ASN = "asn"
    ORGANIZATION = "organization"
    FILE = "file"
    SECRET = "secret"
    API_KEY = "api_key"
    EMAIL = "email"
    PHONE = "phone"


class EdgeType(str, Enum):
    RUNS_ON = "runs_on"
    EXPOSES = "exposes"
    HAS_VULN = "has_vuln"
    AUTHENTICATES_TO = "authenticates_to"
    CONNECTS_TO = "connects_to"
    DELEGATES_TO = "delegates_to"
    BELONGS_TO = "belongs_to"
    RESOLVED_FROM = "resolved_from"
    CHAINS_TO = "chains_to"
    DEPENDS_ON = "depends_on"
    CONTAINS = "contains"
    PART_OF = "part_of"
    USES = "uses"
    VULNERABLE_TO = "vulnerable_to"
    ACCESS_TO = "access_to"
    DISCOVERED_BY = "discovered_by"
    SAME_AS = "same_as"
    PROXIES_TO = "proxies_to"
    ENCRYPTS_WITH = "encrypts_with"
    STORED_IN = "stored_in"


@dataclass
class GraphNode:
    """A node in the knowledge graph."""
    id: str
    node_type: NodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    confidence: float = 1.0
    discovered_at: float = field(default_factory=time.time)
    discovered_by: str = ""  # agent/tool that discovered this
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "tags": self.tags,
            "confidence": self.confidence,
            "discovered_by": self.discovered_by,
        }

    def matches_filter(self, filters: dict[str, Any]) -> bool:
        for key, value in filters.items():
            if key == "type" and self.node_type.value != value:
                return False
            if key == "tag" and value not in self.tags:
                return False
            if key in self.properties and self.properties[key] != value:
                return False
        return True


@dataclass
class GraphEdge:
    """An edge in the knowledge graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    confidence: float = 1.0
    discovered_at: float = field(default_factory=time.time)
    discovered_by: str = ""
    bidirectional: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "weight": self.weight,
            "confidence": self.confidence,
            "properties": self.properties,
        }


class KnowledgeGraph:
    """In-memory knowledge graph with query capabilities.

    Supports:
    - Node/edge CRUD
    - Graph traversal (BFS, DFS)
    - Path finding (shortest path, all paths)
    - Subgraph extraction
    - Pattern matching
    - Attack path computation
    - Export to various formats
    """

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[tuple[str, GraphEdge]]] = defaultdict(list)
        self._reverse_adjacency: dict[str, list[tuple[str, GraphEdge]]] = defaultdict(list)
        self._type_index: dict[NodeType, set[str]] = defaultdict(set)
        self._label_index: dict[str, set[str]] = defaultdict(set)

    # ── Node Operations ────────────────────────────────────

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        properties: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        confidence: float = 1.0,
        discovered_by: str = "",
    ) -> GraphNode:
        """Add or update a node."""
        if node_id in self._nodes:
            existing = self._nodes[node_id]
            if properties:
                existing.properties.update(properties)
            if tags:
                existing.tags = list(set(existing.tags + tags))
            existing.last_seen = time.time()
            existing.confidence = max(existing.confidence, confidence)
            return existing

        node = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
            tags=tags or [],
            confidence=confidence,
            discovered_by=discovered_by,
        )
        self._nodes[node_id] = node
        self._type_index[node_type].add(node_id)
        self._label_index[label.lower()].add(node_id)
        return node

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def remove_node(self, node_id: str) -> bool:
        node = self._nodes.pop(node_id, None)
        if not node:
            return False
        self._type_index[node.node_type].discard(node_id)
        self._label_index[node.label.lower()].discard(node_id)
        # Remove edges
        self._edges = [e for e in self._edges if e.source_id != node_id and e.target_id != node_id]
        self._adjacency.pop(node_id, None)
        self._reverse_adjacency.pop(node_id, None)
        for adj_list in self._adjacency.values():
            adj_list[:] = [(nid, e) for nid, e in adj_list if nid != node_id]
        for adj_list in self._reverse_adjacency.values():
            adj_list[:] = [(nid, e) for nid, e in adj_list if nid != node_id]
        return True

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        ids = self._type_index.get(node_type, set())
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def search_nodes(self, query: str, node_type: NodeType | None = None) -> list[GraphNode]:
        """Full-text search across node labels and properties."""
        query_lower = query.lower()
        results = []
        candidates = self._nodes.values()
        if node_type:
            candidate_ids = self._type_index.get(node_type, set())
            candidates = [self._nodes[nid] for nid in candidate_ids if nid in self._nodes]

        for node in candidates:
            score = 0.0
            if query_lower in node.label.lower():
                score += 1.0
            if query_lower in node.id.lower():
                score += 0.8
            for v in node.properties.values():
                if query_lower in str(v).lower():
                    score += 0.5
                    break
            for tag in node.tags:
                if query_lower in tag.lower():
                    score += 0.3
            if score > 0:
                results.append((score, node))

        results.sort(key=lambda x: x[0], reverse=True)
        return [node for _, node in results]

    # ── Edge Operations ────────────────────────────────────

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        properties: dict[str, Any] | None = None,
        weight: float = 1.0,
        confidence: float = 1.0,
        discovered_by: str = "",
        bidirectional: bool = False,
    ) -> GraphEdge | None:
        """Add an edge between two nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        # Check for duplicate
        for _, existing_edge in self._adjacency[source_id]:
            if _ == target_id and existing_edge.edge_type == edge_type:
                existing_edge.weight = max(existing_edge.weight, weight)
                existing_edge.confidence = max(existing_edge.confidence, confidence)
                if properties:
                    existing_edge.properties.update(properties)
                return existing_edge

        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties or {},
            weight=weight,
            confidence=confidence,
            discovered_by=discovered_by,
            bidirectional=bidirectional,
        )
        self._edges.append(edge)
        self._adjacency[source_id].append((target_id, edge))
        self._reverse_adjacency[target_id].append((source_id, edge))

        if bidirectional:
            reverse_edge = GraphEdge(
                source_id=target_id,
                target_id=source_id,
                edge_type=edge_type,
                properties=properties or {},
                weight=weight,
                confidence=confidence,
                discovered_by=discovered_by,
                bidirectional=True,
            )
            self._edges.append(reverse_edge)
            self._adjacency[target_id].append((source_id, reverse_edge))
            self._reverse_adjacency[source_id].append((target_id, reverse_edge))

        return edge

    def get_edges(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        edge_type: EdgeType | None = None,
    ) -> list[GraphEdge]:
        """Get edges matching criteria."""
        results = self._edges
        if source_id:
            results = [e for e in results if e.source_id == source_id]
        if target_id:
            results = [e for e in results if e.target_id == target_id]
        if edge_type:
            results = [e for e in results if e.edge_type == edge_type]
        return results

    def get_neighbors(
        self,
        node_id: str,
        edge_type: EdgeType | None = None,
        direction: str = "outgoing",
    ) -> list[tuple[GraphNode, GraphEdge]]:
        """Get neighboring nodes."""
        if direction in ("outgoing", "both"):
            adj = self._adjacency.get(node_id, [])
        else:
            adj = []

        if direction in ("incoming", "both"):
            adj = list(adj) + self._reverse_adjacency.get(node_id, [])

        results = []
        seen = set()
        for nid, edge in adj:
            if nid in seen:
                continue
            if edge_type and edge.edge_type != edge_type:
                continue
            node = self._nodes.get(nid)
            if node:
                results.append((node, edge))
                seen.add(nid)

        return results

    # ── Traversal ──────────────────────────────────────────

    def bfs(
        self,
        start_id: str,
        max_depth: int = 10,
        edge_filter: EdgeType | None = None,
        node_filter: NodeType | None = None,
    ) -> list[tuple[GraphNode, int]]:
        """Breadth-first search from a starting node."""
        if start_id not in self._nodes:
            return []

        visited: set[str] = {start_id}
        queue: list[tuple[str, int]] = [(start_id, 0)]
        results: list[tuple[GraphNode, int]] = [(self._nodes[start_id], 0)]

        while queue:
            current_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            for nid, edge in self._adjacency.get(current_id, []):
                if nid in visited:
                    continue
                if edge_filter and edge.edge_type != edge_filter:
                    continue
                node = self._nodes.get(nid)
                if not node:
                    continue
                if node_filter and node.node_type != node_filter:
                    continue

                visited.add(nid)
                queue.append((nid, depth + 1))
                results.append((node, depth + 1))

        return results

    def dfs(
        self,
        start_id: str,
        max_depth: int = 10,
        edge_filter: EdgeType | None = None,
    ) -> list[tuple[GraphNode, int]]:
        """Depth-first search from a starting node."""
        if start_id not in self._nodes:
            return []

        visited: set[str] = set()
        results: list[tuple[GraphNode, int]] = []

        def _dfs_inner(nid: str, depth: int) -> None:
            if nid in visited or depth > max_depth:
                return
            visited.add(nid)
            node = self._nodes.get(nid)
            if node:
                results.append((node, depth))
            for neighbor_id, edge in self._adjacency.get(nid, []):
                if edge_filter and edge.edge_type != edge_filter:
                    continue
                _dfs_inner(neighbor_id, depth + 1)

        _dfs_inner(start_id, 0)
        return results

    # ── Path Finding ───────────────────────────────────────

    def shortest_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 20,
    ) -> list[tuple[GraphNode, GraphEdge | None]] | None:
        """Find shortest path between two nodes using BFS."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None
        if source_id == target_id:
            return [(self._nodes[source_id], None)]

        visited: set[str] = {source_id}
        # Queue of (current_id, path)
        queue: list[tuple[str, list[tuple[str, GraphEdge | None]]]] = [
            (source_id, [(source_id, None)])
        ]

        while queue:
            current_id, path = queue.pop(0)
            if len(path) > max_depth:
                continue

            for nid, edge in self._adjacency.get(current_id, []):
                if nid in visited:
                    continue
                new_path = path + [(nid, edge)]
                if nid == target_id:
                    return [
                        (self._nodes[pid], e) for pid, e in new_path
                        if pid in self._nodes
                    ]
                visited.add(nid)
                queue.append((nid, new_path))

        return None

    def all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
        max_paths: int = 100,
    ) -> list[list[tuple[GraphNode, GraphEdge | None]]]:
        """Find all paths between two nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []

        paths: list[list[tuple[str, GraphEdge | None]]] = []

        def _find_paths(current: str, target: str, visited: set[str], path: list[tuple[str, GraphEdge | None]]) -> None:
            if len(paths) >= max_paths:
                return
            if len(path) > max_depth:
                return
            if current == target:
                paths.append(list(path))
                return

            for nid, edge in self._adjacency.get(current, []):
                if nid not in visited:
                    visited.add(nid)
                    path.append((nid, edge))
                    _find_paths(nid, target, visited, path)
                    path.pop()
                    visited.discard(nid)

        _find_paths(source_id, target_id, {source_id}, [(source_id, None)])

        return [
            [(self._nodes[nid], e) for nid, e in path if nid in self._nodes]
            for path in paths
        ]

    # ── Attack Path Analysis ───────────────────────────────

    def find_attack_paths(
        self,
        entry_point_id: str | None = None,
        target_type: NodeType = NodeType.CREDENTIAL,
        max_depth: int = 10,
    ) -> list[dict[str, Any]]:
        """Find attack paths from entry points to high-value targets."""
        # If no entry point, use all external-facing services
        entry_points = []
        if entry_point_id:
            entry_points = [entry_point_id]
        else:
            # Find external-facing services (those with vulnerabilities)
            for node in self.get_nodes_by_type(NodeType.SERVICE):
                if "external" in node.tags or node.properties.get("external"):
                    entry_points.append(node.id)
            if not entry_points:
                # Use hosts
                for node in self.get_nodes_by_type(NodeType.HOST):
                    entry_points.append(node.id)

        # Find high-value targets
        targets = set()
        for target_t in [target_type, NodeType.SECRET, NodeType.API_KEY, NodeType.DATABASE]:
            for node in self.get_nodes_by_type(target_t):
                targets.add(node.id)

        # Find paths from each entry to each target
        attack_paths = []
        for entry in entry_points[:10]:
            for target in targets:
                paths = self.all_paths(entry, target, max_depth=max_depth, max_paths=5)
                for path in paths:
                    vulns_in_path = [
                        n for n, _ in path
                        if n.node_type == NodeType.VULNERABILITY
                    ]
                    if vulns_in_path:
                        attack_paths.append({
                            "entry": entry,
                            "target": target,
                            "path": [n.label for n, _ in path],
                            "path_length": len(path),
                            "vulnerabilities": [v.label for v in vulns_in_path],
                            "risk_score": self._compute_path_risk(path),
                        })

        attack_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        return attack_paths

    def _compute_path_risk(
        self, path: list[tuple[GraphNode, GraphEdge | None]]
    ) -> float:
        """Compute risk score for an attack path."""
        score = 0.0
        vuln_count = 0
        for node, edge in path:
            if node.node_type == NodeType.VULNERABILITY:
                severity = node.properties.get("severity", "low")
                severity_scores = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
                score += severity_scores.get(severity, 1.0)
                vuln_count += 1
            if edge:
                score += edge.weight * edge.confidence

        # Shorter paths are more likely to succeed
        length_factor = 1.0 / max(len(path), 1)
        return score * length_factor * max(vuln_count, 1)

    def find_lateral_movement_paths(self, compromised_host_id: str) -> list[dict[str, Any]]:
        """Find paths for lateral movement from a compromised host."""
        paths = []
        # Find all reachable hosts via CONNECTS_TO edges
        reachable = self.bfs(
            compromised_host_id,
            max_depth=5,
            edge_filter=EdgeType.CONNECTS_TO,
            node_filter=NodeType.HOST,
        )

        for node, depth in reachable:
            if node.id == compromised_host_id:
                continue
            # Check for vulnerabilities on this host
            vulns = self.get_neighbors(node.id, edge_type=EdgeType.HAS_VULN)
            # Check for shared credentials
            creds = self.get_neighbors(node.id, edge_type=EdgeType.AUTHENTICATES_TO, direction="incoming")

            paths.append({
                "target_host": node.label,
                "hops": depth,
                "vulnerabilities": [v.label for v, _ in vulns],
                "credential_access": len(creds) > 0,
                "risk": "high" if vulns else "medium" if creds else "low",
            })

        paths.sort(key=lambda p: {"high": 3, "medium": 2, "low": 1}[p["risk"]], reverse=True)
        return paths

    # ── Subgraph Extraction ────────────────────────────────

    def extract_subgraph(
        self,
        center_id: str,
        radius: int = 3,
    ) -> dict[str, Any]:
        """Extract a subgraph centered on a node."""
        nodes_in_radius = self.bfs(center_id, max_depth=radius)
        node_ids = {n.id for n, _ in nodes_in_radius}

        sub_nodes = [n.to_dict() for n, _ in nodes_in_radius]
        sub_edges = [
            e.to_dict() for e in self._edges
            if e.source_id in node_ids and e.target_id in node_ids
        ]

        return {
            "center": center_id,
            "radius": radius,
            "nodes": sub_nodes,
            "edges": sub_edges,
        }

    # ── Ingestion from Scanner Results ─────────────────────

    def ingest_port_scan(self, host_ip: str, scan_result: dict[str, Any], discovered_by: str = "port_scanner") -> None:
        """Ingest results from a port scan."""
        host = self.add_node(
            f"host:{host_ip}", NodeType.HOST, host_ip,
            properties={"ip": host_ip, "os": scan_result.get("os_guess", "")},
            discovered_by=discovered_by,
        )

        for port_info in scan_result.get("open_ports", []):
            port_num = port_info.get("port", 0)
            service = port_info.get("service", "unknown")
            version = port_info.get("version", "")

            port_id = f"port:{host_ip}:{port_num}"
            self.add_node(
                port_id, NodeType.PORT, f"{host_ip}:{port_num}",
                properties={"port": port_num, "protocol": port_info.get("protocol", "tcp")},
                discovered_by=discovered_by,
            )
            self.add_edge(host.id, port_id, EdgeType.EXPOSES, discovered_by=discovered_by)

            svc_id = f"svc:{host_ip}:{port_num}:{service}"
            self.add_node(
                svc_id, NodeType.SERVICE, f"{service} on {host_ip}:{port_num}",
                properties={"service": service, "version": version, "port": port_num},
                tags=["external"] if port_num in (80, 443, 8080, 8443) else [],
                discovered_by=discovered_by,
            )
            self.add_edge(port_id, svc_id, EdgeType.RUNS_ON, discovered_by=discovered_by)

    def ingest_vulnerability(self, vuln: dict[str, Any], discovered_by: str = "vuln_scanner") -> None:
        """Ingest a vulnerability finding."""
        vuln_id = f"vuln:{vuln.get('id', vuln.get('title', 'unknown')[:20])}"
        component = vuln.get("affected_component", "")

        self.add_node(
            vuln_id, NodeType.VULNERABILITY, vuln.get("title", "Unknown"),
            properties={
                "severity": vuln.get("severity", "info"),
                "cvss": vuln.get("cvss_score", 0),
                "cve": vuln.get("cve_id", ""),
                "cwe": vuln.get("cwe_id", ""),
                "description": vuln.get("description", "")[:500],
                "confidence": vuln.get("confidence", 0),
            },
            tags=[vuln.get("severity", "info")],
            discovered_by=discovered_by,
        )

        if component:
            # Try to find the node this vuln belongs to
            matching_nodes = self.search_nodes(component)
            for node in matching_nodes[:1]:
                self.add_edge(node.id, vuln_id, EdgeType.HAS_VULN, discovered_by=discovered_by)

    def ingest_subdomain(self, parent_domain: str, subdomain: str, discovered_by: str = "osint") -> None:
        """Ingest a discovered subdomain."""
        domain_id = f"domain:{parent_domain}"
        sub_id = f"subdomain:{subdomain}"

        self.add_node(domain_id, NodeType.DOMAIN, parent_domain, discovered_by=discovered_by)
        self.add_node(sub_id, NodeType.SUBDOMAIN, subdomain, discovered_by=discovered_by)
        self.add_edge(sub_id, domain_id, EdgeType.BELONGS_TO, discovered_by=discovered_by)

    def ingest_credential(
        self, username: str, password: str, target: str, discovered_by: str = ""
    ) -> None:
        """Ingest a discovered credential."""
        cred_id = f"cred:{username}@{target}"
        self.add_node(
            cred_id, NodeType.CREDENTIAL, f"{username}@{target}",
            properties={"username": username, "password_hash": "***", "target": target},
            discovered_by=discovered_by,
        )

        # Link to target
        target_nodes = self.search_nodes(target)
        for tn in target_nodes[:1]:
            self.add_edge(cred_id, tn.id, EdgeType.AUTHENTICATES_TO, discovered_by=discovered_by)

    # ── Statistics and Export ───────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        type_counts = {}
        for nt, ids in self._type_index.items():
            type_counts[nt.value] = len(ids)

        edge_type_counts: dict[str, int] = {}
        for e in self._edges:
            edge_type_counts[e.edge_type.value] = edge_type_counts.get(e.edge_type.value, 0) + 1

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_types": type_counts,
            "edge_types": edge_type_counts,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "stats": self.get_stats(),
        }

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)
