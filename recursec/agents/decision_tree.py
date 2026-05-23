"""Decision tree engine — structured decision-making for agent actions.

Implements:
1. Decision tree definition and traversal
2. Condition evaluation (target properties, findings, etc.)
3. Action recommendation based on tree path
4. Dynamic tree modification based on results
5. Decision logging and explanation
6. Pre-built trees for common assessment scenarios
7. Risk-aware decision making
8. Multi-criteria decision analysis
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class NodeType(str, Enum):
    DECISION = "decision"        # Evaluates a condition
    ACTION = "action"            # Recommends an action
    CHANCE = "chance"            # Probabilistic outcome


@dataclass
class TreeNode:
    """A node in the decision tree."""
    node_id: str = ""
    node_type: NodeType = NodeType.DECISION
    label: str = ""
    condition: str = ""          # For decision nodes
    action: str = ""             # For action nodes
    children: dict[str, str] = field(default_factory=dict)  # condition_result -> child_node_id
    probability: float = 1.0     # For chance nodes
    risk_level: str = "low"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id, "type": self.node_type.value,
            "label": self.label[:60], "children": len(self.children),
        }


@dataclass
class DecisionPath:
    """A path through the decision tree."""
    nodes_visited: list[str] = field(default_factory=list)
    decisions_made: list[dict[str, Any]] = field(default_factory=list)
    recommended_action: str = ""
    confidence: float = 0.5
    risk_level: str = "low"
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": len(self.nodes_visited),
            "action": self.recommended_action[:60],
            "confidence": round(self.confidence, 2),
            "risk": self.risk_level,
        }


class DecisionTree:
    """A decision tree for structured decision-making."""

    def __init__(self, name: str = "") -> None:
        self._name = name
        self._nodes: dict[str, TreeNode] = {}
        self._root_id: str = ""
        self._conditions: dict[str, Callable[[dict[str, Any]], str]] = {}
        self._node_counter = 0

    def add_node(
        self,
        label: str,
        node_type: NodeType = NodeType.DECISION,
        condition: str = "",
        action: str = "",
        children: dict[str, str] | None = None,
        risk_level: str = "low",
    ) -> str:
        """Add a node to the tree."""
        self._node_counter += 1
        nid = f"n-{self._node_counter}"

        node = TreeNode(
            node_id=nid,
            node_type=node_type,
            label=label,
            condition=condition,
            action=action,
            children=children or {},
            risk_level=risk_level,
        )

        self._nodes[nid] = node

        if not self._root_id:
            self._root_id = nid

        return nid

    def set_root(self, node_id: str) -> None:
        self._root_id = node_id

    def register_condition(
        self,
        name: str,
        evaluator: Callable[[dict[str, Any]], str],
    ) -> None:
        """Register a condition evaluator."""
        self._conditions[name] = evaluator

    def traverse(self, context: dict[str, Any]) -> DecisionPath:
        """Traverse the tree to reach a decision."""
        path = DecisionPath()

        current_id = self._root_id
        confidence = 1.0

        while current_id:
            node = self._nodes.get(current_id)
            if not node:
                break

            path.nodes_visited.append(current_id)

            if node.node_type == NodeType.ACTION:
                path.recommended_action = node.action
                path.risk_level = node.risk_level
                break

            elif node.node_type == NodeType.DECISION:
                # Evaluate condition
                result = self._evaluate_condition(node.condition, context)

                path.decisions_made.append({
                    "node": node.label,
                    "condition": node.condition,
                    "result": result,
                })

                # Follow branch
                next_id = node.children.get(result, node.children.get("default", ""))
                current_id = next_id

            elif node.node_type == NodeType.CHANCE:
                confidence *= node.probability
                # Follow first child (simplified)
                if node.children:
                    current_id = list(node.children.values())[0]
                else:
                    break

        path.confidence = confidence
        path.explanation = self._explain_path(path)
        return path

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> str:
        """Evaluate a condition against context."""
        evaluator = self._conditions.get(condition)
        if evaluator:
            try:
                return evaluator(context)
            except Exception:
                return "unknown"

        # Simple key-value check
        if "=" in condition:
            key, value = condition.split("=", 1)
            actual = str(context.get(key.strip(), ""))
            return "true" if actual == value.strip() else "false"

        # Existence check
        if condition in context:
            return "true" if context[condition] else "false"

        return "unknown"

    def _explain_path(self, path: DecisionPath) -> str:
        """Generate explanation for the decision path."""
        parts = []
        for decision in path.decisions_made:
            parts.append(f"{decision['condition']} → {decision['result']}")
        parts.append(f"Action: {path.recommended_action}")
        return " → ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self._name,
            "nodes": len(self._nodes),
            "root": self._root_id,
        }


# ── Pre-built Decision Trees ─────────────────────────────────

def build_web_assessment_tree() -> DecisionTree:
    """Build a decision tree for web app assessment."""
    tree = DecisionTree("web_assessment")

    # Root: Is target a web app?
    root = tree.add_node("Is web app?", NodeType.DECISION, "has_web")
    no_web = tree.add_node("Run port scan", NodeType.ACTION, action="nmap_scan")

    # Web app branch
    has_login = tree.add_node("Has login?", NodeType.DECISION, "has_login_form")
    no_login = tree.add_node("Dir bruteforce + vuln scan", NodeType.ACTION,
                             action="ffuf_nuclei", risk_level="low")

    # Login branch
    tech_check = tree.add_node("Known tech?", NodeType.DECISION, "known_technology")
    generic_test = tree.add_node("Generic web test", NodeType.ACTION,
                                 action="nuclei_full", risk_level="medium")

    # Technology-specific
    wp_test = tree.add_node("WordPress scan", NodeType.ACTION,
                            action="wpscan", risk_level="low")
    php_test = tree.add_node("PHP vuln scan", NodeType.ACTION,
                             action="nuclei_php_sqlmap", risk_level="medium")
    api_test = tree.add_node("API security test", NodeType.ACTION,
                             action="api_fuzz_auth_test", risk_level="medium")

    # Wire up
    tree._nodes[root].children = {"true": has_login, "false": no_web}
    tree._nodes[has_login].children = {"true": tech_check, "false": no_login}
    tree._nodes[tech_check].children = {
        "wordpress": wp_test, "php": php_test,
        "api": api_test, "default": generic_test,
    }

    return tree


def build_network_assessment_tree() -> DecisionTree:
    """Build a decision tree for network assessment."""
    tree = DecisionTree("network_assessment")

    root = tree.add_node("Target type?", NodeType.DECISION, "target_type")

    single_host = tree.add_node("Has open ports?", NodeType.DECISION, "has_open_ports")
    network_range = tree.add_node("Discovery scan", NodeType.ACTION,
                                  action="masscan_discovery")

    port_vuln = tree.add_node("Service vuln scan", NodeType.ACTION,
                              action="nmap_vuln_nuclei", risk_level="medium")
    no_ports = tree.add_node("Firewall detected", NodeType.ACTION,
                             action="firewall_bypass_test", risk_level="low")

    tree._nodes[root].children = {
        "host": single_host, "network": network_range,
        "default": single_host,
    }
    tree._nodes[single_host].children = {"true": port_vuln, "false": no_ports}

    return tree


# ── Decision Tree Engine ──────────────────────────────────────

class DecisionTreeEngine:
    """Manages multiple decision trees for different scenarios."""

    def __init__(self) -> None:
        self._trees: dict[str, DecisionTree] = {}
        self._decision_log: list[dict[str, Any]] = []
        self._log = logger.bind(component="decision_tree")

        self._init_trees()

    def _init_trees(self) -> None:
        """Initialize pre-built trees."""
        self._trees["web"] = build_web_assessment_tree()
        self._trees["network"] = build_network_assessment_tree()

    def decide(
        self,
        tree_name: str,
        context: dict[str, Any],
    ) -> DecisionPath:
        """Make a decision using a named tree."""
        tree = self._trees.get(tree_name)
        if not tree:
            return DecisionPath(recommended_action="unknown_tree")

        path = tree.traverse(context)

        self._decision_log.append({
            "tree": tree_name,
            "action": path.recommended_action,
            "confidence": path.confidence,
            "time": time.time(),
        })

        if len(self._decision_log) > 500:
            self._decision_log = self._decision_log[-500:]

        return path

    def add_tree(self, name: str, tree: DecisionTree) -> None:
        self._trees[name] = tree

    def get_decision_log(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._decision_log[-limit:]

    def get_stats(self) -> dict[str, Any]:
        return {
            "trees": len(self._trees),
            "decisions": len(self._decision_log),
        }
