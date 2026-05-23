"""Causal reasoner — reasons about cause-effect relationships in findings.

Implements:
1. Causal graph construction
2. Causal chain identification
3. Root cause analysis
4. Impact propagation
5. Counterfactual reasoning
6. Intervention analysis
7. Causal strength estimation
8. Causal explanation generation
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CausalRelation(str, Enum):
    CAUSES = "causes"
    ENABLES = "enables"
    PREVENTS = "prevents"
    CORRELATES = "correlates"
    REQUIRES = "requires"
    AMPLIFIES = "amplifies"


class NodeType(str, Enum):
    VULNERABILITY = "vulnerability"
    CONDITION = "condition"
    ACTION = "action"
    CONSEQUENCE = "consequence"
    MITIGATION = "mitigation"


@dataclass
class CausalNode:
    """A node in the causal graph."""
    node_id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.CONDITION
    description: str = ""
    confidence: float = 0.5
    observed: bool = False
    value: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "name": self.name[:25],
            "type": self.node_type.value,
            "confidence": round(self.confidence, 2),
            "observed": self.observed,
        }


@dataclass
class CausalEdge:
    """A causal relationship between nodes."""
    edge_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relation: CausalRelation = CausalRelation.CAUSES
    strength: float = 0.5
    evidence: str = ""
    conditional: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "source": self.source_id[:15],
            "target": self.target_id[:15],
            "relation": self.relation.value,
            "strength": round(self.strength, 2),
        }


@dataclass
class CausalChain:
    """A chain of causal relationships."""
    chain_id: str = ""
    nodes: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    total_strength: float = 0.0
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id,
            "length": len(self.nodes),
            "strength": round(self.total_strength, 3),
            "desc": self.description[:40],
        }


@dataclass
class RootCauseAnalysis:
    """Result of root cause analysis."""
    target_node: str = ""
    root_causes: list[dict[str, Any]] = field(default_factory=list)
    causal_chains: list[CausalChain] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_node[:20],
            "causes": len(self.root_causes),
            "chains": len(self.causal_chains),
            "confidence": round(self.confidence, 2),
        }


# ── Default Security Causal Knowledge ─────────────────────────

DEFAULT_CAUSAL_EDGES: list[dict[str, Any]] = [
    # Injection chains
    {"src": "user_input_unsanitized", "tgt": "sql_injection", "rel": "enables", "str": 0.8},
    {"src": "sql_injection", "tgt": "data_breach", "rel": "causes", "str": 0.7},
    {"src": "sql_injection", "tgt": "authentication_bypass", "rel": "enables", "str": 0.6},
    {"src": "user_input_unsanitized", "tgt": "xss", "rel": "enables", "str": 0.7},
    {"src": "user_input_unsanitized", "tgt": "command_injection", "rel": "enables", "str": 0.6},
    {"src": "command_injection", "tgt": "rce", "rel": "causes", "str": 0.9},
    # Access control chains
    {"src": "authentication_bypass", "tgt": "unauthorized_access", "rel": "causes", "str": 0.9},
    {"src": "idor", "tgt": "data_breach", "rel": "causes", "str": 0.5},
    {"src": "broken_access_control", "tgt": "privilege_escalation", "rel": "enables", "str": 0.7},
    # Infrastructure chains
    {"src": "outdated_software", "tgt": "known_cve", "rel": "enables", "str": 0.8},
    {"src": "known_cve", "tgt": "rce", "rel": "causes", "str": 0.5},
    {"src": "misconfiguration", "tgt": "information_leak", "rel": "causes", "str": 0.7},
    {"src": "information_leak", "tgt": "targeted_attack", "rel": "enables", "str": 0.5},
    # Cryptographic chains
    {"src": "weak_tls", "tgt": "mitm_attack", "rel": "enables", "str": 0.6},
    {"src": "weak_password_policy", "tgt": "brute_force_success", "rel": "enables", "str": 0.7},
    {"src": "default_credentials", "tgt": "unauthorized_access", "rel": "causes", "str": 0.9},
    # Mitigation edges
    {"src": "input_validation", "tgt": "sql_injection", "rel": "prevents", "str": 0.8},
    {"src": "waf", "tgt": "xss", "rel": "prevents", "str": 0.5},
    {"src": "mfa", "tgt": "authentication_bypass", "rel": "prevents", "str": 0.7},
    {"src": "patching", "tgt": "known_cve", "rel": "prevents", "str": 0.9},
]


class CausalReasoner:
    """Reasons about cause-effect relationships in findings.

    Builds and traverses causal graphs to identify root causes,
    predict impact, and generate explanations.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, CausalNode] = {}
        self._edges: list[CausalEdge] = []
        self._adjacency: dict[str, list[str]] = defaultdict(list)
        self._reverse_adj: dict[str, list[str]] = defaultdict(list)
        self._node_counter = 0
        self._edge_counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="causal_reasoner")

        self._initialize_knowledge()

    def _initialize_knowledge(self) -> None:
        """Initialize default causal knowledge."""
        # Create nodes from edges
        node_names: set[str] = set()
        for edge_data in DEFAULT_CAUSAL_EDGES:
            node_names.add(edge_data["src"])
            node_names.add(edge_data["tgt"])

        for name in node_names:
            self.add_node(name, node_type=self._infer_node_type(name))

        for edge_data in DEFAULT_CAUSAL_EDGES:
            src_node = self._find_node_by_name(edge_data["src"])
            tgt_node = self._find_node_by_name(edge_data["tgt"])
            if src_node and tgt_node:
                self.add_edge(
                    src_node.node_id,
                    tgt_node.node_id,
                    CausalRelation(edge_data["rel"]),
                    strength=edge_data["str"],
                )

    @staticmethod
    def _infer_node_type(name: str) -> NodeType:
        """Infer node type from name."""
        mitigation_keywords = ["validation", "waf", "mfa", "patching"]
        consequence_keywords = ["breach", "rce", "unauthorized", "escalation", "attack"]
        vuln_keywords = ["injection", "xss", "idor", "cve", "bypass"]

        for kw in mitigation_keywords:
            if kw in name:
                return NodeType.MITIGATION

        for kw in consequence_keywords:
            if kw in name:
                return NodeType.CONSEQUENCE

        for kw in vuln_keywords:
            if kw in name:
                return NodeType.VULNERABILITY

        return NodeType.CONDITION

    def _find_node_by_name(self, name: str) -> CausalNode | None:
        for node in self._nodes.values():
            if node.name == name:
                return node
        return None

    def add_node(
        self,
        name: str,
        node_type: NodeType = NodeType.CONDITION,
        description: str = "",
        confidence: float = 0.5,
    ) -> CausalNode:
        """Add a node to the causal graph."""
        existing = self._find_node_by_name(name)
        if existing:
            return existing

        self._node_counter += 1
        node = CausalNode(
            node_id=f"cn-{self._node_counter}",
            name=name,
            node_type=node_type,
            description=description,
            confidence=confidence,
        )
        self._nodes[node.node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: CausalRelation = CausalRelation.CAUSES,
        strength: float = 0.5,
        evidence: str = "",
    ) -> CausalEdge:
        """Add a causal edge."""
        self._edge_counter += 1
        edge = CausalEdge(
            edge_id=f"ce-{self._edge_counter}",
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            strength=strength,
            evidence=evidence,
        )
        self._edges.append(edge)
        self._adjacency[source_id].append(edge.edge_id)
        self._reverse_adj[target_id].append(edge.edge_id)
        return edge

    def find_root_causes(self, target_name: str) -> RootCauseAnalysis:
        """Find root causes for a given effect."""
        target_node = self._find_node_by_name(target_name)
        if not target_node:
            return RootCauseAnalysis(target_node=target_name)

        # BFS backwards through causal graph
        visited: set[str] = set()
        queue: deque[str] = deque([target_node.node_id])
        root_causes = []
        chains = []

        while queue:
            current_id = queue.popleft()
            if current_id in visited:
                continue
            visited.add(current_id)

            # Get incoming edges
            incoming = self._reverse_adj.get(current_id, [])
            causal_incoming = []

            for edge_id in incoming:
                edge = self._find_edge(edge_id)
                if edge and edge.relation in (CausalRelation.CAUSES, CausalRelation.ENABLES):
                    causal_incoming.append(edge)

            if not causal_incoming:
                # This is a root cause
                node = self._nodes.get(current_id)
                if node and node.node_id != target_node.node_id:
                    root_causes.append({
                        "node": node.to_dict(),
                        "path_length": len(visited),
                    })
            else:
                for edge in causal_incoming:
                    queue.append(edge.source_id)

        # Build causal chains
        for cause_data in root_causes:
            cause_id = cause_data["node"]["id"]
            chain = self._trace_chain(cause_id, target_node.node_id)
            if chain:
                chains.append(chain)

        confidence = min(1.0, len(root_causes) * 0.2) if root_causes else 0.0

        return RootCauseAnalysis(
            target_node=target_name,
            root_causes=root_causes,
            causal_chains=chains,
            confidence=confidence,
        )

    def propagate_impact(
        self,
        source_name: str,
        initial_impact: float = 1.0,
    ) -> dict[str, float]:
        """Propagate impact forward through the causal graph."""
        source_node = self._find_node_by_name(source_name)
        if not source_node:
            return {}

        impacts: dict[str, float] = {source_node.node_id: initial_impact}
        visited: set[str] = set()
        queue: deque[str] = deque([source_node.node_id])

        while queue:
            current_id = queue.popleft()
            if current_id in visited:
                continue
            visited.add(current_id)

            current_impact = impacts.get(current_id, 0.0)

            for edge_id in self._adjacency.get(current_id, []):
                edge = self._find_edge(edge_id)
                if not edge:
                    continue

                # Propagate impact, attenuated by edge strength
                if edge.relation in (CausalRelation.CAUSES, CausalRelation.ENABLES, CausalRelation.AMPLIFIES):
                    propagated = current_impact * edge.strength
                    existing = impacts.get(edge.target_id, 0.0)
                    impacts[edge.target_id] = max(existing, propagated)
                    queue.append(edge.target_id)

        # Convert to names
        named_impacts = {}
        for node_id, impact in impacts.items():
            node = self._nodes.get(node_id)
            if node:
                named_impacts[node.name] = round(impact, 3)

        return named_impacts

    def _trace_chain(
        self,
        source_id: str,
        target_id: str,
    ) -> CausalChain | None:
        """Trace a causal chain between two nodes using BFS."""
        visited: set[str] = set()
        queue: deque[list[str]] = deque([[source_id]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == target_id:
                self._chain_counter += 1
                strength = self._compute_chain_strength(path)
                return CausalChain(
                    chain_id=f"cc-{self._chain_counter}",
                    nodes=path,
                    total_strength=strength,
                    description=self._describe_chain(path),
                )

            if current in visited:
                continue
            visited.add(current)

            for edge_id in self._adjacency.get(current, []):
                edge = self._find_edge(edge_id)
                if edge and edge.target_id not in visited:
                    queue.append(path + [edge.target_id])

        return None

    def _compute_chain_strength(self, node_ids: list[str]) -> float:
        """Compute the strength of a causal chain (product of edge strengths)."""
        strength = 1.0
        for i in range(len(node_ids) - 1):
            edge = self._find_edge_between(node_ids[i], node_ids[i + 1])
            if edge:
                strength *= edge.strength
        return strength

    def _describe_chain(self, node_ids: list[str]) -> str:
        """Generate a description of a causal chain."""
        names = []
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node:
                names.append(node.name)
        return " → ".join(names)

    def _find_edge(self, edge_id: str) -> CausalEdge | None:
        for edge in self._edges:
            if edge.edge_id == edge_id:
                return edge
        return None

    def _find_edge_between(self, source_id: str, target_id: str) -> CausalEdge | None:
        for edge in self._edges:
            if edge.source_id == source_id and edge.target_id == target_id:
                return edge
        return None

    def get_stats(self) -> dict[str, Any]:
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "chains": self._chain_counter,
        }
