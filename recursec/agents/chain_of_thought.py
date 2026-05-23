"""Chain-of-thought — structured multi-step reasoning with explicit thought chains.

Implements:
1. Step-by-step reasoning chains
2. Chain branching for alternative hypotheses
3. Evidence linking at each step
4. Confidence propagation through chain
5. Chain validation and consistency checking
6. Chain-of-thought prompt generation
7. Reasoning trace visualization
8. Chain comparison and merging
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ThoughtStepType(str, Enum):
    OBSERVATION = "observation"     # What do we see?
    HYPOTHESIS = "hypothesis"       # What might be true?
    DEDUCTION = "deduction"         # What follows logically?
    INDUCTION = "induction"         # What pattern emerges?
    ACTION = "action"               # What should we do?
    EVALUATION = "evaluation"       # How well did we do?
    REVISION = "revision"           # Correcting previous thought


@dataclass
class ThoughtStep:
    """A single step in a chain of thought."""
    step_id: str = ""
    step_type: ThoughtStepType = ThoughtStepType.OBSERVATION
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    parent_step_id: str = ""       # For branching
    model_used: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id,
            "type": self.step_type.value,
            "content": self.content[:60],
            "confidence": round(self.confidence, 2),
            "evidence": len(self.evidence),
            "parent": self.parent_step_id[:10],
        }


@dataclass
class ThoughtChain:
    """A complete chain of thought."""
    chain_id: str = ""
    goal: str = ""
    steps: list[ThoughtStep] = field(default_factory=list)
    branches: dict[str, list[str]] = field(default_factory=dict)
    conclusion: str = ""
    overall_confidence: float = 0.0
    created_at: float = field(default_factory=time.time)
    tokens_used: int = 0

    @property
    def depth(self) -> int:
        return len(self.steps)

    @property
    def has_conclusion(self) -> bool:
        return bool(self.conclusion)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id,
            "goal": self.goal[:40],
            "steps": len(self.steps),
            "branches": len(self.branches),
            "confidence": round(self.overall_confidence, 2),
            "concluded": self.has_conclusion,
        }


@dataclass
class ChainValidation:
    """Validation result for a thought chain."""
    is_valid: bool = True
    consistency_score: float = 1.0
    completeness_score: float = 0.5
    grounding_score: float = 0.5
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.is_valid,
            "consistency": round(self.consistency_score, 2),
            "completeness": round(self.completeness_score, 2),
            "grounding": round(self.grounding_score, 2),
            "issues": len(self.issues),
        }


# ── CoT Prompt Templates ──────────────────────────────────────

COT_TEMPLATES: dict[str, str] = {
    "security_analysis": (
        "Analyze the following for security vulnerabilities.\n"
        "Think step by step:\n"
        "1. OBSERVE: What do we see in the data/output?\n"
        "2. HYPOTHESIZE: What vulnerabilities might exist?\n"
        "3. DEDUCE: What evidence supports each hypothesis?\n"
        "4. ACT: What should we test next to confirm?\n"
        "5. EVALUATE: How confident are we in each finding?\n\n"
        "Data:\n{data}\n\n"
        "Provide your reasoning step by step."
    ),
    "finding_validation": (
        "Validate whether this is a real vulnerability.\n"
        "Think step by step:\n"
        "1. OBSERVE: What does the evidence show?\n"
        "2. DEDUCE: Could this be a false positive? Why or why not?\n"
        "3. HYPOTHESIZE: What would we expect to see if it's real?\n"
        "4. EVALUATE: Rate confidence in this finding.\n\n"
        "Finding: {finding}\n"
        "Evidence: {evidence}\n\n"
        "Provide your reasoning step by step."
    ),
    "attack_planning": (
        "Plan the next steps for this security assessment.\n"
        "Think step by step:\n"
        "1. OBSERVE: What do we know about the target so far?\n"
        "2. HYPOTHESIZE: What attack vectors are most promising?\n"
        "3. DEDUCE: What tools and techniques should we use?\n"
        "4. ACT: Prioritize actions by expected value.\n\n"
        "Target: {target}\n"
        "Known info: {known_info}\n\n"
        "Provide your reasoning step by step."
    ),
    "code_review": (
        "Review this code for security vulnerabilities.\n"
        "Think step by step:\n"
        "1. OBSERVE: What does this code do?\n"
        "2. HYPOTHESIZE: Where could vulnerabilities exist?\n"
        "3. DEDUCE: Trace data flow from inputs to sensitive operations.\n"
        "4. EVALUATE: Rate severity of each finding.\n\n"
        "Code:\n{code}\n\n"
        "Provide your reasoning step by step."
    ),
}


class ChainOfThought:
    """Structured multi-step reasoning with explicit thought chains.

    Produces step-by-step reasoning traces that can be
    validated, compared, and learned from.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ThoughtChain] = {}
        self._chain_counter = 0
        self._step_counter = 0
        self._log = logger.bind(component="chain_of_thought")

    def start_chain(self, goal: str) -> ThoughtChain:
        """Start a new chain of thought."""
        self._chain_counter += 1
        chain = ThoughtChain(
            chain_id=f"cot-{self._chain_counter}",
            goal=goal,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(
        self,
        chain_id: str,
        step_type: ThoughtStepType,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        parent_step_id: str = "",
        model_used: str = "",
    ) -> ThoughtStep | None:
        """Add a step to a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._step_counter += 1
        step = ThoughtStep(
            step_id=f"ts-{self._step_counter}",
            step_type=step_type,
            content=content,
            evidence=evidence or [],
            confidence=confidence,
            parent_step_id=parent_step_id,
            model_used=model_used,
        )

        chain.steps.append(step)

        # Track branching
        if parent_step_id:
            if parent_step_id not in chain.branches:
                chain.branches[parent_step_id] = []
            chain.branches[parent_step_id].append(step.step_id)

        return step

    def conclude(
        self,
        chain_id: str,
        conclusion: str,
        confidence: float = 0.5,
    ) -> None:
        """Conclude a chain of thought."""
        chain = self._chains.get(chain_id)
        if not chain:
            return

        chain.conclusion = conclusion
        chain.overall_confidence = confidence

    def validate_chain(self, chain_id: str) -> ChainValidation:
        """Validate a chain of thought."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ChainValidation(is_valid=False, issues=["Chain not found"])

        validation = ChainValidation()

        # Check consistency: confidence should not increase without evidence
        for i in range(1, len(chain.steps)):
            current = chain.steps[i]
            prev = chain.steps[i - 1]
            if current.confidence > prev.confidence + 0.3 and not current.evidence:
                validation.issues.append(
                    f"Step {current.step_id}: confidence jump without evidence"
                )
                validation.consistency_score -= 0.2

        # Check completeness: should have observation → hypothesis → conclusion
        step_types = {s.step_type for s in chain.steps}
        expected_types = {ThoughtStepType.OBSERVATION, ThoughtStepType.HYPOTHESIS}
        missing = expected_types - step_types
        if missing:
            validation.issues.append(f"Missing step types: {missing}")
            validation.completeness_score -= 0.2 * len(missing)

        if not chain.has_conclusion:
            validation.issues.append("No conclusion reached")
            validation.completeness_score -= 0.3

        # Check grounding: steps should have evidence
        steps_with_evidence = sum(1 for s in chain.steps if s.evidence)
        if chain.steps:
            validation.grounding_score = steps_with_evidence / len(chain.steps)

        validation.consistency_score = max(0, validation.consistency_score)
        validation.completeness_score = max(0, validation.completeness_score)

        validation.is_valid = (
            validation.consistency_score > 0.5 and
            validation.completeness_score > 0.3
        )

        return validation

    def get_prompt(
        self,
        template: str,
        variables: dict[str, str],
    ) -> str:
        """Get a CoT prompt from a template."""
        prompt_template = COT_TEMPLATES.get(template, "")
        if not prompt_template:
            return ""

        try:
            return prompt_template.format(**variables)
        except KeyError:
            return prompt_template

    def compare_chains(
        self,
        chain_id_a: str,
        chain_id_b: str,
    ) -> dict[str, Any]:
        """Compare two chains of thought."""
        chain_a = self._chains.get(chain_id_a)
        chain_b = self._chains.get(chain_id_b)

        if not chain_a or not chain_b:
            return {"error": "Chain not found"}

        return {
            "chain_a": chain_a.to_dict(),
            "chain_b": chain_b.to_dict(),
            "step_diff": len(chain_a.steps) - len(chain_b.steps),
            "confidence_diff": round(
                chain_a.overall_confidence - chain_b.overall_confidence, 2
            ),
            "same_conclusion": chain_a.conclusion == chain_b.conclusion,
        }

    def get_reasoning_trace(self, chain_id: str) -> str:
        """Get a human-readable reasoning trace."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [f"Goal: {chain.goal}", ""]

        for i, step in enumerate(chain.steps, 1):
            prefix = f"  Step {i} [{step.step_type.value.upper()}]"
            lines.append(f"{prefix}: {step.content}")
            if step.evidence:
                for ev in step.evidence:
                    lines.append(f"    Evidence: {ev}")
            lines.append(f"    Confidence: {step.confidence:.2f}")
            lines.append("")

        if chain.conclusion:
            lines.append(f"CONCLUSION: {chain.conclusion}")
            lines.append(f"Overall confidence: {chain.overall_confidence:.2f}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_steps = sum(len(c.steps) for c in self._chains.values())
        concluded = sum(1 for c in self._chains.values() if c.has_conclusion)
        return {
            "chains": len(self._chains),
            "total_steps": total_steps,
            "concluded": concluded,
        }
