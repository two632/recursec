"""Attack graph engine — models relationships between vulnerabilities.

Builds a directed graph where:
- Nodes represent states (initial access, compromise levels, targets)
- Edges represent vulnerabilities/techniques that enable transitions
- Paths through the graph represent attack chains

Capabilities:
1. Build graph from discovered findings
2. Find all paths from entry to objective
3. Score paths by difficulty, impact, and stealth
4. Identify critical nodes (high betweenness centrality)
5. Suggest next actions to maximize graph coverage
6. Simulate attack scenarios
7. Generate attack narratives
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class NodeType(str, Enum):
    ENTRY_POINT = "entry_point"
    VULNERABILITY = "vulnerability"
    COMPROMISE = "compromise"
    LATERAL_MOVE = "lateral_move"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    OBJECTIVE = "objective"
    SERVICE = "service"
    HOST = "host"


class EdgeType(str, Enum):
    EXPLOIT = "exploit"
    CREDENTIAL = "credential"
    MISCONFIGURATION = "misconfiguration"
    SOCIAL_ENGINEERING = "social_engineering"
    NETWORK = "network"
    PHYSICAL = "physical"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class AttackNode:
    """A node in the attack graph."""
    node_id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.VULNERABILITY
    description: str = ""
    host: str = ""
    port: int = 0
    service: str = ""
    confidence: float = 0.5
    impact: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id, "name": self.name[:100],
            "type": self.node_type.value,
            "host": self.host, "port": self.port,
            "confidence": round(self.confidence, 2),
            "impact": round(self.impact, 2),
        }


@dataclass
class AttackEdge:
    """An edge (transition) in the attack graph."""
    edge_id: str = ""
    source: str = ""    # Source node ID
    target: str = ""    # Target node ID
    edge_type: EdgeType = EdgeType.EXPLOIT
    technique: str = ""
    difficulty: float = 0.5     # 0=easy, 1=hard
    stealth: float = 0.5       # 0=noisy, 1=stealthy
    reliability: float = 0.5   # 0=unreliable, 1=reliable
    prerequisites: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    @property
    def weight(self) -> float:
        """Edge weight — lower is better for pathfinding."""
        return self.difficulty * (1 - self.reliability) * (1 - self.stealth)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "from": self.source, "to": self.target,
            "type": self.edge_type.value,
            "technique": self.technique[:100],
            "difficulty": round(self.difficulty, 2),
            "stealth": round(self.stealth, 2),
            "reliability": round(self.reliability, 2),
            "tools": self.tools[:3],
        }


@dataclass
class AttackPath:
    """A complete attack path through the graph."""
    path_id: str = ""
    nodes: list[str] = field(default_factory=list)    # Node IDs
    edges: list[str] = field(default_factory=list)    # Edge IDs
    total_difficulty: float = 0.0
    total_impact: float = 0.0
    overall_stealth: float = 0.0
    success_probability: float = 0.0
    narrative: str = ""

    @property
    def score(self) -> float:
        """Combined score — high impact, low difficulty, high stealth."""
        if not self.total_difficulty:
            return 0.0
        return (self.total_impact * self.success_probability * self.overall_stealth) / self.total_difficulty

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path_id,
            "length": len(self.nodes),
            "difficulty": round(self.total_difficulty, 2),
            "impact": round(self.total_impact, 2),
            "stealth": round(self.overall_stealth, 2),
            "probability": round(self.success_probability, 2),
            "score": round(self.score, 3),
            "nodes": self.nodes[:10],
        }


NARRATIVE_PROMPT = """Generate a concise attack narrative for this attack path.

Path steps:
{steps}

Create a clear, professional narrative describing:
1. How an attacker would execute this path
2. What each step achieves
3. What the final impact would be
4. How difficult this would be in practice

Respond as a single paragraph, 3-5 sentences. No JSON needed."""


class AttackGraph:
    """Models relationships between vulnerabilities as a directed graph.

    Enables attack path analysis, critical node identification,
    and attack scenario simulation.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._nodes: dict[str, AttackNode] = {}
        self._edges: dict[str, AttackEdge] = {}
        self._adjacency: dict[str, list[str]] = defaultdict(list)  # node_id → [edge_ids]
        self._reverse_adj: dict[str, list[str]] = defaultdict(list)  # node_id → [incoming edge_ids]
        self._paths: list[AttackPath] = []
        self._edge_counter = 0
        self._path_counter = 0
        self._log = logger.bind(component="attack_graph")

    def add_node(self, node: AttackNode) -> str:
        """Add a node to the graph."""
        self._nodes[node.node_id] = node
        return node.node_id

    def add_edge(self, edge: AttackEdge) -> str:
        """Add an edge (attack transition) to the graph."""
        if not edge.edge_id:
            self._edge_counter += 1
            edge.edge_id = f"edge-{self._edge_counter}"

        if edge.source not in self._nodes or edge.target not in self._nodes:
            self._log.warning("edge_invalid_nodes", source=edge.source, target=edge.target)
            return ""

        self._edges[edge.edge_id] = edge
        self._adjacency[edge.source].append(edge.edge_id)
        self._reverse_adj[edge.target].append(edge.edge_id)

        return edge.edge_id

    def add_finding_as_edge(
        self,
        finding: dict[str, Any],
        source_node_id: str,
        target_node_id: str,
    ) -> str:
        """Convert a finding into an attack graph edge."""
        severity = finding.get("severity", "medium").lower()
        difficulty_map = {
            "critical": 0.1, "high": 0.3,
            "medium": 0.5, "low": 0.7, "info": 0.9,
        }

        edge = AttackEdge(
            source=source_node_id,
            target=target_node_id,
            technique=finding.get("title", ""),
            difficulty=difficulty_map.get(severity, 0.5),
            reliability=finding.get("confidence", 0.5),
            tools=finding.get("tools", []),
        )

        return self.add_edge(edge)

    # ── Path Finding ─────────────────────────────────────

    def find_all_paths(
        self,
        start: str,
        end: str,
        max_depth: int = 10,
        max_paths: int = 20,
    ) -> list[AttackPath]:
        """Find all paths from start to end using DFS."""
        if start not in self._nodes or end not in self._nodes:
            return []

        paths: list[AttackPath] = []
        stack: list[tuple[str, list[str], list[str], set[str]]] = [
            (start, [start], [], {start}),
        ]

        while stack and len(paths) < max_paths:
            current, path_nodes, path_edges, visited = stack.pop()

            if current == end and len(path_nodes) > 1:
                self._path_counter += 1
                attack_path = self._build_path(
                    f"path-{self._path_counter}",
                    path_nodes, path_edges,
                )
                paths.append(attack_path)
                continue

            if len(path_nodes) >= max_depth:
                continue

            for edge_id in self._adjacency.get(current, []):
                edge = self._edges.get(edge_id)
                if not edge:
                    continue
                next_node = edge.target
                if next_node not in visited:
                    new_visited = visited | {next_node}
                    stack.append((
                        next_node,
                        path_nodes + [next_node],
                        path_edges + [edge_id],
                        new_visited,
                    ))

        # Sort by score
        paths.sort(key=lambda p: -p.score)
        self._paths.extend(paths)
        return paths

    def find_shortest_path(self, start: str, end: str) -> AttackPath | None:
        """Find shortest (easiest) path using BFS."""
        if start not in self._nodes or end not in self._nodes:
            return None

        queue: deque[tuple[str, list[str], list[str]]] = deque([(start, [start], [])])
        visited: set[str] = {start}

        while queue:
            current, path_nodes, path_edges = queue.popleft()

            if current == end and len(path_nodes) > 1:
                self._path_counter += 1
                return self._build_path(
                    f"path-{self._path_counter}",
                    path_nodes, path_edges,
                )

            for edge_id in self._adjacency.get(current, []):
                edge = self._edges.get(edge_id)
                if not edge:
                    continue
                next_node = edge.target
                if next_node not in visited:
                    visited.add(next_node)
                    queue.append((
                        next_node,
                        path_nodes + [next_node],
                        path_edges + [edge_id],
                    ))

        return None

    # ── Analysis ─────────────────────────────────────────

    def get_critical_nodes(self, top_k: int = 10) -> list[dict[str, Any]]:
        """Find nodes with highest betweenness centrality."""
        centrality: dict[str, float] = defaultdict(float)

        nodes = list(self._nodes.keys())
        for source in nodes:
            for target in nodes:
                if source == target:
                    continue
                path = self.find_shortest_path(source, target)
                if path and len(path.nodes) > 2:
                    for node_id in path.nodes[1:-1]:
                        centrality[node_id] += 1.0

        # Normalize
        total = sum(centrality.values()) or 1.0
        normalized = {nid: c / total for nid, c in centrality.items()}

        # Sort and return top-k
        sorted_nodes = sorted(normalized.items(), key=lambda x: -x[1])[:top_k]
        return [
            {
                "node": self._nodes[nid].to_dict(),
                "centrality": round(score, 4),
            }
            for nid, score in sorted_nodes if nid in self._nodes
        ]

    def get_entry_points(self) -> list[AttackNode]:
        """Get nodes with no incoming edges (potential entry points)."""
        has_incoming = set()
        for edge in self._edges.values():
            has_incoming.add(edge.target)
        return [
            node for node_id, node in self._nodes.items()
            if node_id not in has_incoming
        ]

    def get_objectives(self) -> list[AttackNode]:
        """Get objective nodes (explicit or leaf nodes with high impact)."""
        objectives = [
            n for n in self._nodes.values()
            if n.node_type == NodeType.OBJECTIVE
        ]
        if not objectives:
            # Fall back to leaf nodes with high impact
            has_outgoing = set()
            for edge in self._edges.values():
                has_outgoing.add(edge.source)
            objectives = [
                n for nid, n in self._nodes.items()
                if nid not in has_outgoing and n.impact > 0.5
            ]
        return objectives

    def suggest_next_actions(self, current_position: str) -> list[dict[str, Any]]:
        """Suggest next actions from current position."""
        suggestions = []
        for edge_id in self._adjacency.get(current_position, []):
            edge = self._edges.get(edge_id)
            if not edge:
                continue
            target_node = self._nodes.get(edge.target)
            if not target_node:
                continue
            suggestions.append({
                "action": edge.technique,
                "target": target_node.name,
                "difficulty": edge.difficulty,
                "impact": target_node.impact,
                "tools": edge.tools,
                "score": (target_node.impact * (1 - edge.difficulty)),
            })
        suggestions.sort(key=lambda s: -s["score"])
        return suggestions

    # ── Narrative Generation ─────────────────────────────

    async def generate_narrative(self, path: AttackPath) -> str:
        """Generate a natural language narrative for an attack path."""
        steps_text = ""
        for i, (node_id, edge_id) in enumerate(
            zip(path.nodes[:-1], path.edges)
        ):
            node = self._nodes.get(node_id)
            edge = self._edges.get(edge_id)
            next_node = self._nodes.get(path.nodes[i + 1]) if i + 1 < len(path.nodes) else None
            if node and edge and next_node:
                steps_text += (
                    f"{i+1}. From '{node.name}' ({node.node_type.value}): "
                    f"Use {edge.technique} (difficulty: {edge.difficulty:.1f}) "
                    f"to reach '{next_node.name}' ({next_node.node_type.value})\n"
                )

        if not self._router:
            path.narrative = steps_text
            return steps_text

        prompt = NARRATIVE_PROMPT.format(steps=steps_text)
        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=256,
        )

        path.narrative = response.strip()
        return path.narrative

    # ── Utilities ────────────────────────────────────────

    def _build_path(
        self,
        path_id: str,
        node_ids: list[str],
        edge_ids: list[str],
    ) -> AttackPath:
        """Build an AttackPath from node/edge lists."""
        total_difficulty = 0.0
        total_impact = 0.0
        reliability_product = 1.0
        stealth_sum = 0.0

        for edge_id in edge_ids:
            edge = self._edges.get(edge_id)
            if edge:
                total_difficulty += edge.difficulty
                reliability_product *= edge.reliability
                stealth_sum += edge.stealth

        for node_id in node_ids:
            node = self._nodes.get(node_id)
            if node:
                total_impact = max(total_impact, node.impact)

        num_edges = max(1, len(edge_ids))

        return AttackPath(
            path_id=path_id,
            nodes=node_ids,
            edges=edge_ids,
            total_difficulty=total_difficulty,
            total_impact=total_impact,
            overall_stealth=stealth_sum / num_edges,
            success_probability=reliability_product,
        )

    def get_graph_data(self) -> dict[str, Any]:
        """Get full graph data for visualization."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "paths": [p.to_dict() for p in self._paths],
        }

    def get_stats(self) -> dict[str, Any]:
        node_types: dict[str, int] = defaultdict(int)
        for n in self._nodes.values():
            node_types[n.node_type.value] += 1
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "paths_found": len(self._paths),
            "node_types": dict(node_types),
            "entry_points": len(self.get_entry_points()),
            "objectives": len(self.get_objectives()),
        }
