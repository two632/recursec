"""Attack tree builder — models exploitation paths.

Implements:
1. Attack tree construction from findings
2. Path scoring (probability × impact)
3. Prerequisite chain analysis
4. Optimal attack path selection
5. Kill chain mapping
6. Attack surface visualization data
7. Risk-based prioritization
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class NodeType(str, Enum):
    ROOT = "root"
    AND = "and"                 # All children required
    OR = "or"                   # Any child sufficient
    LEAF = "leaf"               # Concrete action
    PREREQUISITE = "prerequisite"


class AttackPhase(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackNode:
    """A node in the attack tree."""
    node_id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.LEAF
    phase: AttackPhase = AttackPhase.INITIAL_ACCESS
    description: str = ""
    probability: float = 0.5    # 0-1 likelihood of success
    impact: float = 0.5         # 0-1 impact if successful
    cost: float = 0.5           # 0-1 effort required
    tool: str = ""
    finding_id: str = ""
    children: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        """Risk = probability × impact."""
        return self.probability * self.impact

    @property
    def efficiency(self) -> float:
        """Efficiency = risk_score / cost."""
        return self.risk_score / max(0.01, self.cost)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:10],
            "name": self.name[:25],
            "type": self.node_type.value,
            "phase": self.phase.value[:15],
            "risk": round(self.risk_score, 2),
            "children": len(self.children),
        }


@dataclass
class AttackPath:
    """A complete attack path through the tree."""
    path_id: str = ""
    nodes: list[str] = field(default_factory=list)
    phases: list[str] = field(default_factory=list)
    total_probability: float = 0.0
    total_impact: float = 0.0
    total_cost: float = 0.0
    tools: list[str] = field(default_factory=list)

    @property
    def path_risk(self) -> float:
        return self.total_probability * self.total_impact

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path_id[:10],
            "steps": len(self.nodes),
            "risk": round(self.path_risk, 2),
            "cost": round(self.total_cost, 2),
            "phases": self.phases[:5],
        }


class AttackTreeBuilder:
    """Builds and analyzes attack trees from findings.

    Models exploitation paths as trees where:
    - AND nodes require all children to succeed
    - OR nodes require any child to succeed
    - LEAF nodes are concrete attack steps
    """

    def __init__(self) -> None:
        self._nodes: dict[str, AttackNode] = {}
        self._root_id: str = ""
        self._counter = 0
        self._log = logger.bind(component="attack_tree")

    def create_root(self, target: str) -> AttackNode:
        """Create the root node for an attack tree."""
        self._counter += 1
        root = AttackNode(
            node_id=f"node-{self._counter}",
            name=f"Compromise: {target}",
            node_type=NodeType.ROOT,
            phase=AttackPhase.IMPACT,
            probability=0.0,
            impact=1.0,
        )
        self._nodes[root.node_id] = root
        self._root_id = root.node_id
        return root

    def add_node(
        self,
        parent_id: str,
        name: str,
        node_type: NodeType = NodeType.LEAF,
        phase: AttackPhase = AttackPhase.INITIAL_ACCESS,
        probability: float = 0.5,
        impact: float = 0.5,
        cost: float = 0.5,
        tool: str = "",
        finding_id: str = "",
        prerequisites: list[str] | None = None,
    ) -> AttackNode | None:
        """Add a node to the attack tree."""
        parent = self._nodes.get(parent_id)
        if not parent:
            return None

        self._counter += 1
        node = AttackNode(
            node_id=f"node-{self._counter}",
            name=name,
            node_type=node_type,
            phase=phase,
            probability=probability,
            impact=impact,
            cost=cost,
            tool=tool,
            finding_id=finding_id,
            prerequisites=prerequisites or [],
        )
        self._nodes[node.node_id] = node
        parent.children.append(node.node_id)

        # Recalculate parent probability
        self._update_probabilities(parent_id)

        return node

    def add_finding_as_node(
        self,
        parent_id: str,
        finding: dict[str, Any],
    ) -> AttackNode | None:
        """Convert a finding into an attack tree node."""
        severity_prob = {
            "critical": 0.8, "high": 0.6, "medium": 0.4, "low": 0.2,
        }
        severity_impact = {
            "critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.1,
        }

        sev = finding.get("severity", "medium")
        phase = self._guess_phase(finding)

        return self.add_node(
            parent_id=parent_id,
            name=finding.get("title", "Unknown"),
            node_type=NodeType.LEAF,
            phase=phase,
            probability=severity_prob.get(sev, 0.3),
            impact=severity_impact.get(sev, 0.3),
            cost=0.3,
            tool=finding.get("tool", ""),
            finding_id=finding.get("id", ""),
        )

    def _guess_phase(self, finding: dict[str, Any]) -> AttackPhase:
        """Guess the attack phase from a finding."""
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        text = f"{title} {desc}"

        phase_keywords = {
            AttackPhase.INITIAL_ACCESS: ["login", "auth", "bypass", "injection", "rce", "sqli"],
            AttackPhase.EXECUTION: ["command", "exec", "shell", "code execution"],
            AttackPhase.PERSISTENCE: ["backdoor", "cron", "webshell", "ssh key"],
            AttackPhase.PRIVILEGE_ESCALATION: ["privesc", "privilege", "suid", "sudo", "root"],
            AttackPhase.CREDENTIAL_ACCESS: ["password", "credential", "hash", "token", "secret"],
            AttackPhase.DISCOVERY: ["enumerate", "scan", "fingerprint", "recon"],
            AttackPhase.LATERAL_MOVEMENT: ["pivot", "lateral", "smb", "wmi", "rdp"],
            AttackPhase.EXFILTRATION: ["exfil", "data leak", "download", "extract"],
        }

        for phase, keywords in phase_keywords.items():
            if any(kw in text for kw in keywords):
                return phase

        return AttackPhase.INITIAL_ACCESS

    def _update_probabilities(self, node_id: str) -> None:
        """Recursively update node probabilities."""
        node = self._nodes.get(node_id)
        if not node or not node.children:
            return

        child_probs = []
        for child_id in node.children:
            child = self._nodes.get(child_id)
            if child:
                child_probs.append(child.probability)

        if not child_probs:
            return

        if node.node_type in (NodeType.AND, NodeType.ROOT):
            # AND: multiply probabilities
            prob = 1.0
            for p in child_probs:
                prob *= p
            node.probability = prob
        elif node.node_type == NodeType.OR:
            # OR: 1 - product of (1-p)
            prob = 1.0
            for p in child_probs:
                prob *= (1.0 - p)
            node.probability = 1.0 - prob

    def find_paths(
        self,
        max_paths: int = 10,
    ) -> list[AttackPath]:
        """Find all attack paths from leaves to root."""
        if not self._root_id:
            return []

        paths: list[AttackPath] = []
        self._dfs_paths(self._root_id, [], paths, max_paths)

        # Sort by risk score
        paths.sort(key=lambda p: p.path_risk, reverse=True)
        return paths[:max_paths]

    def _dfs_paths(
        self,
        node_id: str,
        current_path: list[str],
        paths: list[AttackPath],
        max_paths: int,
    ) -> None:
        """DFS to find attack paths."""
        if len(paths) >= max_paths:
            return

        node = self._nodes.get(node_id)
        if not node:
            return

        current_path = [*current_path, node_id]

        if not node.children:
            # Leaf node — complete path
            self._counter += 1
            path = AttackPath(
                path_id=f"path-{self._counter}",
                nodes=list(reversed(current_path)),
            )

            # Calculate path metrics
            prob = 1.0
            max_impact = 0.0
            total_cost = 0.0
            for nid in current_path:
                n = self._nodes.get(nid)
                if n:
                    prob *= max(0.01, n.probability)
                    max_impact = max(max_impact, n.impact)
                    total_cost += n.cost
                    path.phases.append(n.phase.value)
                    if n.tool:
                        path.tools.append(n.tool)

            path.total_probability = prob
            path.total_impact = max_impact
            path.total_cost = total_cost

            paths.append(path)
            return

        for child_id in node.children:
            self._dfs_paths(child_id, current_path, paths, max_paths)

    def get_optimal_path(self) -> AttackPath | None:
        """Get the highest risk path."""
        paths = self.find_paths(max_paths=1)
        return paths[0] if paths else None

    def get_high_risk_nodes(
        self,
        min_risk: float = 0.5,
    ) -> list[AttackNode]:
        """Get nodes above a risk threshold."""
        return sorted(
            [n for n in self._nodes.values() if n.risk_score >= min_risk],
            key=lambda n: n.risk_score,
            reverse=True,
        )

    def build_tree_prompt(self) -> str:
        """Build a prompt describing the attack tree."""
        if not self._root_id:
            return ""

        lines = ["## Attack Tree\n"]
        self._format_node(self._root_id, lines, indent=0)
        return "\n".join(lines)

    def _format_node(
        self,
        node_id: str,
        lines: list[str],
        indent: int,
    ) -> None:
        """Recursively format nodes for display."""
        node = self._nodes.get(node_id)
        if not node:
            return

        prefix = "  " * indent
        risk = f"[risk={node.risk_score:.2f}]"
        lines.append(f"{prefix}{node.node_type.value}: {node.name} {risk}")

        for child_id in node.children:
            self._format_node(child_id, lines, indent + 1)

    def get_stats(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = defaultdict(int)
        type_counts: dict[str, int] = defaultdict(int)

        for node in self._nodes.values():
            phase_counts[node.phase.value] += 1
            type_counts[node.node_type.value] += 1

        paths = self.find_paths(max_paths=5)
        avg_risk = sum(p.path_risk for p in paths) / max(1, len(paths))

        return {
            "nodes": len(self._nodes),
            "paths": len(paths),
            "avg_path_risk": round(avg_risk, 2),
            "by_phase": dict(phase_counts),
            "by_type": dict(type_counts),
        }
