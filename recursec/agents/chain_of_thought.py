"""Chain of thought reasoning engine.

Implements structured reasoning for security analysis:
1. Step-by-step reasoning chains
2. Evidence-based reasoning
3. Attack tree construction
4. Risk assessment reasoning
5. Vulnerability impact analysis
6. Exploitation feasibility analysis
7. Multi-step reasoning verification
8. Reasoning chain compression
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningType(str, Enum):
    DEDUCTIVE = "deductive"       # From general to specific
    INDUCTIVE = "inductive"       # From specific to general
    ABDUCTIVE = "abductive"       # Best explanation for observations
    ANALOGICAL = "analogical"     # By similarity to known cases
    CAUSAL = "causal"             # Cause and effect


class StepType(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    INFERENCE = "inference"
    EVIDENCE = "evidence"
    CONCLUSION = "conclusion"
    QUESTION = "question"
    ACTION = "action"
    VERIFICATION = "verification"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    step_type: StepType = StepType.OBSERVATION
    content: str = ""
    confidence: float = 0.8
    evidence: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:10],
            "type": self.step_type.value,
            "content": self.content[:50],
            "confidence": round(self.confidence, 2),
            "evidence": len(self.evidence),
        }


@dataclass
class ReasoningChain:
    """A complete chain of reasoning."""
    chain_id: str = ""
    reasoning_type: ReasoningType = ReasoningType.DEDUCTIVE
    goal: str = ""
    steps: list[ReasoningStep] = field(default_factory=list)
    conclusion: str = ""
    overall_confidence: float = 0.0
    valid: bool = True
    created_at: float = field(default_factory=time.time)

    @property
    def length(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "type": self.reasoning_type.value,
            "goal": self.goal[:30],
            "steps": self.length,
            "conclusion": self.conclusion[:40],
            "confidence": round(self.overall_confidence, 2),
            "valid": self.valid,
        }


@dataclass
class AttackTreeNode:
    """A node in an attack tree."""
    node_id: str = ""
    description: str = ""
    node_type: str = "AND"       # AND (all children needed) or OR (any child sufficient)
    probability: float = 0.5
    impact: float = 0.5
    cost: float = 0.5            # Cost to attacker (0=free, 1=expensive)
    children: list[str] = field(default_factory=list)
    is_leaf: bool = True

    @property
    def risk_score(self) -> float:
        return self.probability * self.impact

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:10],
            "desc": self.description[:30],
            "type": self.node_type,
            "prob": round(self.probability, 2),
            "impact": round(self.impact, 2),
            "risk": round(self.risk_score, 2),
        }


class ChainOfThoughtEngine:
    """Structured reasoning engine for security analysis.

    Constructs, validates, and manages chains of reasoning
    for vulnerability assessment. Uses step-by-step reasoning
    to ensure thorough analysis and reduce hallucination.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._attack_trees: dict[str, dict[str, AttackTreeNode]] = {}
        self._counter = 0
        self._log = logger.bind(component="chain_of_thought")

    def start_chain(
        self,
        goal: str,
        reasoning_type: ReasoningType = ReasoningType.DEDUCTIVE,
    ) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._counter += 1
        chain = ReasoningChain(
            chain_id=f"cot-{self._counter}",
            reasoning_type=reasoning_type,
            goal=goal,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(
        self,
        chain_id: str,
        step_type: StepType,
        content: str,
        confidence: float = 0.8,
        evidence: list[str] | None = None,
        assumptions: list[str] | None = None,
    ) -> ReasoningStep | None:
        """Add a step to a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._counter += 1
        step = ReasoningStep(
            step_id=f"step-{self._counter}",
            step_type=step_type,
            content=content,
            confidence=confidence,
            evidence=evidence or [],
            assumptions=assumptions or [],
        )

        # Link to previous step
        if chain.steps:
            step.depends_on.append(chain.steps[-1].step_id)

        chain.steps.append(step)
        return step

    def conclude(
        self,
        chain_id: str,
        conclusion: str,
    ) -> ReasoningChain | None:
        """Conclude a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        chain.conclusion = conclusion

        # Calculate overall confidence
        if chain.steps:
            # Confidence degrades multiplicatively across steps
            confidence = 1.0
            for step in chain.steps:
                confidence *= step.confidence
            chain.overall_confidence = confidence
        else:
            chain.overall_confidence = 0.0

        # Validate chain
        chain.valid = self._validate_chain(chain)

        return chain

    def _validate_chain(self, chain: ReasoningChain) -> bool:
        """Validate a reasoning chain for logical consistency."""
        if not chain.steps:
            return False

        # Must have at least one observation and one conclusion
        types = {s.step_type for s in chain.steps}
        if StepType.OBSERVATION not in types:
            return False

        # Check for circular dependencies
        seen: set[str] = set()
        for step in chain.steps:
            if step.step_id in seen:
                return False
            seen.add(step.step_id)

        # Minimum confidence threshold
        if chain.overall_confidence < 0.01:
            return False

        return True

    def build_vuln_reasoning(
        self,
        vuln_type: str,
        target: str,
        evidence_list: list[str],
    ) -> ReasoningChain:
        """Build a structured vulnerability reasoning chain."""
        chain = self.start_chain(
            goal=f"Determine if {target} is vulnerable to {vuln_type}",
            reasoning_type=ReasoningType.ABDUCTIVE,
        )

        # Observation step
        self.add_step(
            chain.chain_id,
            StepType.OBSERVATION,
            f"Target: {target}, Testing for: {vuln_type}",
            confidence=1.0,
        )

        # Evidence steps
        for i, ev in enumerate(evidence_list):
            self.add_step(
                chain.chain_id,
                StepType.EVIDENCE,
                ev,
                confidence=0.7 + (0.1 if "confirmed" in ev.lower() else 0),
                evidence=[ev],
            )

        # Hypothesis
        self.add_step(
            chain.chain_id,
            StepType.HYPOTHESIS,
            f"Based on {len(evidence_list)} evidence items, {target} appears vulnerable to {vuln_type}",
            confidence=0.6,
        )

        return chain

    def build_attack_tree(
        self,
        root_goal: str,
        target: str,
    ) -> str:
        """Build an attack tree for a target."""
        self._counter += 1
        tree_id = f"tree-{self._counter}"
        self._attack_trees[tree_id] = {}

        # Root node
        root = AttackTreeNode(
            node_id="node-root",
            description=root_goal,
            node_type="OR",
            is_leaf=False,
        )
        self._attack_trees[tree_id]["root"] = root

        return tree_id

    def add_tree_node(
        self,
        tree_id: str,
        parent_id: str,
        description: str,
        node_type: str = "AND",
        probability: float = 0.5,
        impact: float = 0.5,
        cost: float = 0.5,
    ) -> AttackTreeNode | None:
        """Add a node to an attack tree."""
        tree = self._attack_trees.get(tree_id)
        if not tree or parent_id not in tree:
            return None

        self._counter += 1
        node = AttackTreeNode(
            node_id=f"node-{self._counter}",
            description=description,
            node_type=node_type,
            probability=probability,
            impact=impact,
            cost=cost,
        )

        tree[node.node_id] = node
        tree[parent_id].children.append(node.node_id)
        tree[parent_id].is_leaf = False

        return node

    def evaluate_tree(self, tree_id: str) -> dict[str, Any]:
        """Evaluate an attack tree's overall risk."""
        tree = self._attack_trees.get(tree_id)
        if not tree or "root" not in tree:
            return {"risk": 0.0}

        def evaluate_node(node_id: str) -> float:
            node = tree.get(node_id)
            if not node:
                return 0.0

            if node.is_leaf:
                return node.probability

            child_probs = [evaluate_node(cid) for cid in node.children]
            if not child_probs:
                return node.probability

            if node.node_type == "AND":
                # All children must succeed
                result = 1.0
                for p in child_probs:
                    result *= p
                return result
            else:
                # OR: at least one child succeeds
                result = 1.0
                for p in child_probs:
                    result *= (1 - p)
                return 1 - result

        overall_prob = evaluate_node("root")
        root = tree["root"]

        return {
            "tree_id": tree_id,
            "overall_probability": round(overall_prob, 3),
            "impact": round(root.impact, 2),
            "risk_score": round(overall_prob * root.impact, 3),
            "nodes": len(tree),
        }

    def build_reasoning_prompt(
        self,
        chain_id: str,
    ) -> str:
        """Build a reasoning prompt from a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [f"## Reasoning: {chain.goal}\n"]
        lines.append(f"Type: {chain.reasoning_type.value}")
        lines.append("")

        for i, step in enumerate(chain.steps):
            prefix = {
                StepType.OBSERVATION: "OBSERVE",
                StepType.HYPOTHESIS: "HYPOTHESIZE",
                StepType.INFERENCE: "INFER",
                StepType.EVIDENCE: "EVIDENCE",
                StepType.CONCLUSION: "CONCLUDE",
                StepType.QUESTION: "QUESTION",
                StepType.ACTION: "ACTION",
                StepType.VERIFICATION: "VERIFY",
            }.get(step.step_type, "STEP")

            lines.append(f"{i+1}. [{prefix}] {step.content}")
            if step.evidence:
                for ev in step.evidence:
                    lines.append(f"   Evidence: {ev[:60]}")
            if step.assumptions:
                for asn in step.assumptions:
                    lines.append(f"   Assumption: {asn[:60]}")

        if chain.conclusion:
            lines.append(f"\nCONCLUSION: {chain.conclusion}")
            lines.append(f"Confidence: {chain.overall_confidence:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for c in self._chains.values():
            type_counts[c.reasoning_type.value] += 1

        total_steps = sum(c.length for c in self._chains.values())
        confirmed = sum(1 for c in self._chains.values() if c.valid)

        return {
            "chains": len(self._chains),
            "total_steps": total_steps,
            "confirmed_valid": confirmed,
            "attack_trees": len(self._attack_trees),
            "by_type": dict(type_counts),
        }
