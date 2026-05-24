"""Agent reasoning chain engine — structured multi-step reasoning.

Implements multiple reasoning paradigms:
1. Chain-of-Thought (CoT) — linear step-by-step reasoning
2. Tree-of-Thought (ToT) — branching exploration with evaluation
3. ReAct — Reason + Act interleaving
4. Self-Consistency — multiple chains, majority vote
5. Reflexion — self-critique and improvement
6. Hypothesis Testing — generate hypotheses, test, refine
7. Adversarial Reasoning — red team vs blue team thought
8. Analogical Reasoning — map to known patterns
9. Abductive Reasoning — best explanation from evidence
10. Bayesian Reasoning — update beliefs with evidence

This is the core thinking engine that produces high-quality
security analysis by chaining multiple reasoning steps.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningMode(str, Enum):
    CHAIN_OF_THOUGHT = "chain_of_thought"
    TREE_OF_THOUGHT = "tree_of_thought"
    REACT = "react"
    SELF_CONSISTENCY = "self_consistency"
    REFLEXION = "reflexion"
    HYPOTHESIS_TEST = "hypothesis_test"
    ADVERSARIAL = "adversarial"
    ANALOGICAL = "analogical"
    ABDUCTIVE = "abductive"
    BAYESIAN = "bayesian"


class StepStatus(str, Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: int = 0
    thought: str = ""
    action: str = ""
    observation: str = ""
    confidence: float = 0.5
    status: StepStatus = StepStatus.PENDING
    tool_used: str = ""
    model_used: str = ""
    tokens_used: int = 0
    duration_ms: float = 0.0
    alternatives_considered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_id,
            "thought": self.thought[:30],
            "action": self.action[:20],
            "conf": f"{self.confidence:.0%}",
            "status": self.status.value[:8],
        }


@dataclass
class ReasoningChain:
    """A complete reasoning chain."""
    chain_id: str = ""
    mode: ReasoningMode = ReasoningMode.CHAIN_OF_THOUGHT
    goal: str = ""
    steps: list[ReasoningStep] = field(default_factory=list)
    conclusion: str = ""
    overall_confidence: float = 0.0
    total_tokens: int = 0
    total_duration_ms: float = 0.0
    created_at: float = field(default_factory=time.time)

    @property
    def length(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:8],
            "mode": self.mode.value[:12],
            "steps": self.length,
            "conf": f"{self.overall_confidence:.0%}",
            "conclusion": self.conclusion[:30],
        }


@dataclass
class Hypothesis:
    """A hypothesis for testing."""
    hypothesis_id: str = ""
    statement: str = ""
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    prior_probability: float = 0.5
    posterior_probability: float = 0.5
    status: str = "untested"
    tests_run: int = 0

    def update_probability(self, evidence_supports: bool, strength: float = 0.2) -> None:
        if evidence_supports:
            self.posterior_probability = min(0.99, self.posterior_probability + strength * (1 - self.posterior_probability))
        else:
            self.posterior_probability = max(0.01, self.posterior_probability - strength * self.posterior_probability)
        self.tests_run += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "stmt": self.statement[:30],
            "prob": f"{self.posterior_probability:.0%}",
            "tests": self.tests_run,
            "status": self.status[:8],
        }


@dataclass
class BeliefState:
    """Bayesian belief tracking."""
    beliefs: dict[str, float] = field(default_factory=dict)
    evidence_log: list[tuple[str, bool, float]] = field(default_factory=list)

    def update(self, belief_key: str, evidence_supports: bool, strength: float = 0.15) -> None:
        current = self.beliefs.get(belief_key, 0.5)
        if evidence_supports:
            new = min(0.99, current + strength * (1 - current))
        else:
            new = max(0.01, current - strength * current)
        self.beliefs[belief_key] = new
        self.evidence_log.append((belief_key, evidence_supports, strength))

    def get_top_beliefs(self, n: int = 5) -> list[tuple[str, float]]:
        sorted_beliefs = sorted(self.beliefs.items(), key=lambda x: x[1], reverse=True)
        return sorted_beliefs[:n]


@dataclass
class ThoughtNode:
    """A node in a Tree-of-Thought."""
    node_id: int = 0
    thought: str = ""
    score: float = 0.0
    children: list[int] = field(default_factory=list)
    parent_id: int = -1
    depth: int = 0
    is_leaf: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "thought": self.thought[:25],
            "score": f"{self.score:.2f}",
            "children": len(self.children),
            "depth": self.depth,
        }


# Reasoning prompts by mode
REASONING_PROMPTS: dict[ReasoningMode, str] = {
    ReasoningMode.CHAIN_OF_THOUGHT: (
        "Think through this step by step:\n"
        "Step 1: What is the goal?\n"
        "Step 2: What information do I have?\n"
        "Step 3: What is the most likely approach?\n"
        "Step 4: What tools should I use?\n"
        "Step 5: What could go wrong?\n"
        "Step 6: What is my conclusion?"
    ),
    ReasoningMode.REACT: (
        "Use the ReAct pattern:\n"
        "Thought: [What am I trying to do?]\n"
        "Action: [What tool/command to run]\n"
        "Observation: [What did I see?]\n"
        "Thought: [What does this mean?]\n"
        "... repeat until conclusion"
    ),
    ReasoningMode.HYPOTHESIS_TEST: (
        "Form and test hypotheses:\n"
        "1. Based on evidence, what hypotheses can I form?\n"
        "2. For each hypothesis, what test would confirm/deny it?\n"
        "3. Run the tests\n"
        "4. Update belief probabilities\n"
        "5. What is the strongest hypothesis?"
    ),
    ReasoningMode.ADVERSARIAL: (
        "Think as both attacker and defender:\n"
        "ATTACKER: What are the possible attack vectors?\n"
        "DEFENDER: How can each be detected/prevented?\n"
        "ATTACKER: How can I bypass the defenses?\n"
        "DEFENDER: What additional mitigations exist?\n"
        "CONCLUSION: What is the real risk?"
    ),
    ReasoningMode.ABDUCTIVE: (
        "Find the best explanation:\n"
        "1. What observations/evidence do I have?\n"
        "2. What are possible explanations?\n"
        "3. Which explanation best fits ALL the evidence?\n"
        "4. Are there any counter-examples?\n"
        "5. Rank explanations by plausibility"
    ),
}

# Task type → recommended reasoning mode
TASK_REASONING_MAP: dict[str, ReasoningMode] = {
    "vulnerability_analysis": ReasoningMode.HYPOTHESIS_TEST,
    "code_review": ReasoningMode.CHAIN_OF_THOUGHT,
    "exploit_planning": ReasoningMode.ADVERSARIAL,
    "triage": ReasoningMode.ABDUCTIVE,
    "recon_analysis": ReasoningMode.CHAIN_OF_THOUGHT,
    "finding_validation": ReasoningMode.HYPOTHESIS_TEST,
    "attack_planning": ReasoningMode.TREE_OF_THOUGHT,
    "risk_assessment": ReasoningMode.BAYESIAN,
    "incident_response": ReasoningMode.REACT,
    "defense_strategy": ReasoningMode.ADVERSARIAL,
}


class ReasoningChainEngine:
    """Manages and executes reasoning chains."""

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._hypotheses: dict[str, Hypothesis] = {}
        self._beliefs = BeliefState()
        self._thought_tree: dict[int, ThoughtNode] = {}
        self._chain_counter = 0
        self._hypothesis_counter = 0
        self._node_counter = 0
        self._log = logger.bind(component="reasoning_chain")

    def select_mode(self, task_type: str) -> ReasoningMode:
        """Select best reasoning mode for a task type."""
        return TASK_REASONING_MAP.get(task_type, ReasoningMode.CHAIN_OF_THOUGHT)

    def create_chain(self, goal: str, mode: ReasoningMode | None = None) -> ReasoningChain:
        """Create a new reasoning chain."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"chain-{self._chain_counter}",
            mode=mode or ReasoningMode.CHAIN_OF_THOUGHT,
            goal=goal,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(self, chain_id: str, thought: str, action: str = "", observation: str = "", confidence: float = 0.5) -> ReasoningStep:
        """Add a step to a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ReasoningStep()

        step = ReasoningStep(
            step_id=len(chain.steps),
            thought=thought,
            action=action,
            observation=observation,
            confidence=confidence,
            status=StepStatus.COMPLETED,
        )
        chain.steps.append(step)

        # Update chain confidence
        if chain.steps:
            chain.overall_confidence = sum(s.confidence for s in chain.steps) / len(chain.steps)

        return step

    def conclude_chain(self, chain_id: str, conclusion: str) -> ReasoningChain:
        """Conclude a reasoning chain."""
        chain = self._chains.get(chain_id)
        if chain:
            chain.conclusion = conclusion
        return chain or ReasoningChain()

    def create_hypothesis(self, statement: str, prior: float = 0.5) -> Hypothesis:
        """Create a new hypothesis for testing."""
        self._hypothesis_counter += 1
        hyp = Hypothesis(
            hypothesis_id=f"hyp-{self._hypothesis_counter}",
            statement=statement,
            prior_probability=prior,
            posterior_probability=prior,
        )
        self._hypotheses[hyp.hypothesis_id] = hyp
        return hyp

    def test_hypothesis(self, hypothesis_id: str, evidence: str, supports: bool, strength: float = 0.2) -> Hypothesis:
        """Update a hypothesis with new evidence."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return Hypothesis()
        if supports:
            hyp.evidence_for.append(evidence)
        else:
            hyp.evidence_against.append(evidence)
        hyp.update_probability(supports, strength)
        return hyp

    def create_thought_tree(self, root_thought: str) -> ThoughtNode:
        """Create a Tree-of-Thought root node."""
        self._node_counter += 1
        node = ThoughtNode(
            node_id=self._node_counter,
            thought=root_thought,
            depth=0,
        )
        self._thought_tree[node.node_id] = node
        return node

    def expand_thought(self, parent_id: int, thoughts: list[str]) -> list[ThoughtNode]:
        """Expand a thought node with children."""
        parent = self._thought_tree.get(parent_id)
        if not parent:
            return []

        children = []
        for thought in thoughts:
            self._node_counter += 1
            child = ThoughtNode(
                node_id=self._node_counter,
                thought=thought,
                parent_id=parent_id,
                depth=parent.depth + 1,
            )
            self._thought_tree[child.node_id] = child
            parent.children.append(child.node_id)
            children.append(child)

        return children

    def score_thought(self, node_id: int, score: float) -> None:
        """Score a thought node."""
        node = self._thought_tree.get(node_id)
        if node:
            node.score = score

    def get_best_path(self, root_id: int) -> list[ThoughtNode]:
        """Get the highest-scoring path in the thought tree."""
        root = self._thought_tree.get(root_id)
        if not root:
            return []

        path = [root]
        current = root
        while current.children:
            best_child = None
            best_score = -1.0
            for child_id in current.children:
                child = self._thought_tree.get(child_id)
                if child and child.score > best_score:
                    best_score = child.score
                    best_child = child
            if best_child:
                path.append(best_child)
                current = best_child
            else:
                break

        return path

    def self_consistency_vote(self, chains: list[str]) -> str:
        """Vote across multiple chains for self-consistency."""
        conclusions: dict[str, int] = defaultdict(int)
        for chain_id in chains:
            chain = self._chains.get(chain_id)
            if chain and chain.conclusion:
                conclusions[chain.conclusion] += 1
        if not conclusions:
            return ""
        return max(conclusions, key=conclusions.get)

    def build_reasoning_prompt(self, goal: str, mode: ReasoningMode, context: str = "") -> str:
        """Build a reasoning prompt for the LLM."""
        lines = ["## Reasoning Task"]
        lines.append(f"Mode: {mode.value}")
        lines.append(f"Goal: {goal}")

        scaffold = REASONING_PROMPTS.get(mode, "")
        if scaffold:
            lines.append(f"\n{scaffold}")

        if context:
            lines.append(f"\n## Context:\n{context}")

        # Add relevant hypotheses
        active_hyps = [h for h in self._hypotheses.values() if h.status != "rejected"]
        if active_hyps:
            lines.append("\n## Active Hypotheses:")
            for hyp in sorted(active_hyps, key=lambda h: h.posterior_probability, reverse=True)[:3]:
                lines.append(f"  - [{hyp.posterior_probability:.0%}] {hyp.statement[:50]}")

        # Add top beliefs
        top_beliefs = self._beliefs.get_top_beliefs(3)
        if top_beliefs:
            lines.append("\n## Current Beliefs:")
            for belief, prob in top_beliefs:
                lines.append(f"  - [{prob:.0%}] {belief[:40]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "chains": len(self._chains),
            "hypotheses": len(self._hypotheses),
            "beliefs": len(self._beliefs.beliefs),
            "tree_nodes": len(self._thought_tree),
        }
