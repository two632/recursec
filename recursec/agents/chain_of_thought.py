"""Chain-of-thought engine — structured reasoning chains.

Implements:
1. Chain-of-thought reasoning
2. Tree-of-thought branching
3. Reasoning step tracking
4. Confidence propagation
5. Reasoning chain visualization
6. Self-critique and reflection
7. Multi-step planning chains
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
    CHAIN_OF_THOUGHT = "cot"         # Linear reasoning
    TREE_OF_THOUGHT = "tot"          # Branching reasoning
    SELF_CRITIQUE = "self_critique"  # Self-evaluation
    REFLECTION = "reflection"        # Post-action reflection
    DECOMPOSITION = "decomposition"  # Task breakdown
    SYNTHESIS = "synthesis"          # Result combination


class StepStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    PRUNED = "pruned"


@dataclass
class ReasoningStep:
    """A single reasoning step."""
    step_id: str = ""
    content: str = ""
    step_type: ReasoningType = ReasoningType.CHAIN_OF_THOUGHT
    status: StepStatus = StepStatus.PENDING
    confidence: float = 0.5
    parent_step: str = ""
    children: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    model_used: str = ""
    tokens_used: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:10],
            "content": self.content[:30],
            "type": self.step_type.value,
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReasoningChain:
    """A complete reasoning chain."""
    chain_id: str = ""
    reasoning_type: ReasoningType = ReasoningType.CHAIN_OF_THOUGHT
    question: str = ""
    steps: list[str] = field(default_factory=list)
    conclusion: str = ""
    overall_confidence: float = 0.0
    total_tokens: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "type": self.reasoning_type.value,
            "steps": len(self.steps),
            "confidence": round(self.overall_confidence, 2),
        }


# ── CoT prompt templates ─────────────────────────────────────

COT_TEMPLATES: dict[str, str] = {
    "vulnerability_analysis": (
        "Let's analyze this potential vulnerability step by step:\n"
        "Step 1: Identify the vulnerability type and CWE\n"
        "Step 2: Assess the attack surface and prerequisites\n"
        "Step 3: Determine exploitability (CVSS metrics)\n"
        "Step 4: Evaluate potential impact (CIA triad)\n"
        "Step 5: Consider existing mitigations\n"
        "Step 6: Determine real-world risk rating\n"
        "Step 7: Recommend verification approach\n"
    ),
    "exploitation_planning": (
        "Let's plan the exploitation approach step by step:\n"
        "Step 1: Confirm vulnerability is exploitable\n"
        "Step 2: Identify required tools and payloads\n"
        "Step 3: Plan attack chain (prerequisite → exploit → post-exploit)\n"
        "Step 4: Assess detection risk\n"
        "Step 5: Prepare rollback/cleanup plan\n"
        "Step 6: Estimate success probability\n"
    ),
    "finding_verification": (
        "Let's verify this finding step by step:\n"
        "Step 1: Review the raw evidence\n"
        "Step 2: Check for false positive indicators\n"
        "Step 3: Cross-reference with other tools/findings\n"
        "Step 4: Attempt manual reproduction\n"
        "Step 5: Determine confidence level\n"
    ),
    "attack_surface_analysis": (
        "Let's analyze the attack surface step by step:\n"
        "Step 1: Map all exposed services and ports\n"
        "Step 2: Identify technologies and versions\n"
        "Step 3: Enumerate entry points (forms, APIs, parameters)\n"
        "Step 4: Assess authentication mechanisms\n"
        "Step 5: Identify trust boundaries\n"
        "Step 6: Rate each surface by risk\n"
    ),
    "task_decomposition": (
        "Let's decompose this task into subtasks:\n"
        "Step 1: Define the overall objective\n"
        "Step 2: Identify required inputs and prerequisites\n"
        "Step 3: Break into independent subtasks\n"
        "Step 4: Identify dependencies between subtasks\n"
        "Step 5: Prioritize subtasks by value and effort\n"
        "Step 6: Assign tools and models to each subtask\n"
    ),
}


class ChainOfThoughtEngine:
    """Structured reasoning chain engine.

    Builds chain-of-thought and tree-of-thought
    reasoning chains for security analysis.
    """

    def __init__(self) -> None:
        self._steps: dict[str, ReasoningStep] = {}
        self._chains: dict[str, ReasoningChain] = {}
        self._counter = 0
        self._log = logger.bind(component="chain_of_thought")

    def start_chain(
        self,
        question: str,
        reasoning_type: ReasoningType = ReasoningType.CHAIN_OF_THOUGHT,
    ) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._counter += 1
        chain = ReasoningChain(
            chain_id=f"chain-{self._counter}",
            reasoning_type=reasoning_type,
            question=question,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(
        self,
        chain_id: str,
        content: str,
        confidence: float = 0.5,
        evidence: list[str] | None = None,
        model_used: str = "",
        tokens_used: int = 0,
        parent_step: str = "",
    ) -> ReasoningStep | None:
        """Add a reasoning step to a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._counter += 1
        step = ReasoningStep(
            step_id=f"step-{self._counter}",
            content=content,
            step_type=chain.reasoning_type,
            status=StepStatus.COMPLETED,
            confidence=confidence,
            parent_step=parent_step,
            evidence=evidence or [],
            model_used=model_used,
            tokens_used=tokens_used,
        )

        self._steps[step.step_id] = step
        chain.steps.append(step.step_id)
        chain.total_tokens += tokens_used

        # Update parent's children
        if parent_step and parent_step in self._steps:
            self._steps[parent_step].children.append(step.step_id)

        # Update overall confidence
        self._update_chain_confidence(chain)

        return step

    def conclude_chain(
        self,
        chain_id: str,
        conclusion: str,
    ) -> ReasoningChain | None:
        """Conclude a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        chain.conclusion = conclusion
        return chain

    def _update_chain_confidence(self, chain: ReasoningChain) -> None:
        """Update chain's overall confidence from steps."""
        if not chain.steps:
            return

        step_confidences = []
        for step_id in chain.steps:
            step = self._steps.get(step_id)
            if step and step.status == StepStatus.COMPLETED:
                step_confidences.append(step.confidence)

        if step_confidences:
            # Chain confidence = product of step confidences
            if chain.reasoning_type == ReasoningType.CHAIN_OF_THOUGHT:
                conf = 1.0
                for c in step_confidences:
                    conf *= c
                chain.overall_confidence = conf
            else:
                # Tree: max of branch confidences
                chain.overall_confidence = max(step_confidences)

    def build_cot_prompt(
        self,
        template_name: str,
        context: str = "",
    ) -> str:
        """Build a chain-of-thought prompt from a template."""
        template = COT_TEMPLATES.get(template_name, "")
        if not template:
            return ""

        parts = []
        if context:
            parts.append(f"Context:\n{context}\n")
        parts.append(template)
        parts.append("Think through each step carefully before proceeding to the next.")

        return "\n".join(parts)

    def build_self_critique_prompt(
        self,
        chain_id: str,
    ) -> str:
        """Build a self-critique prompt for a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [
            "Review the following reasoning chain and critique it:\n",
            f"Question: {chain.question}\n",
        ]

        for i, step_id in enumerate(chain.steps):
            step = self._steps.get(step_id)
            if step:
                lines.append(f"Step {i + 1} (confidence={step.confidence:.2f}): {step.content}")

        if chain.conclusion:
            lines.append(f"\nConclusion: {chain.conclusion}")

        lines.append(
            "\nCritique:\n"
            "1. Are there any logical errors in the reasoning?\n"
            "2. Are there any missing steps or overlooked factors?\n"
            "3. Is the confidence level appropriate for each step?\n"
            "4. Could the conclusion be wrong? What alternative conclusions are possible?\n"
            "5. What additional evidence would strengthen or weaken this analysis?"
        )

        return "\n".join(lines)

    def prune_low_confidence(
        self,
        chain_id: str,
        threshold: float = 0.3,
    ) -> int:
        """Prune low-confidence branches in tree-of-thought."""
        chain = self._chains.get(chain_id)
        if not chain:
            return 0

        pruned = 0
        for step_id in chain.steps:
            step = self._steps.get(step_id)
            if step and step.confidence < threshold:
                step.status = StepStatus.PRUNED
                pruned += 1

        return pruned

    def get_chain_text(self, chain_id: str) -> str:
        """Get the full text of a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [f"## Reasoning: {chain.question}\n"]
        for i, step_id in enumerate(chain.steps):
            step = self._steps.get(step_id)
            if step and step.status != StepStatus.PRUNED:
                lines.append(f"Step {i + 1}: {step.content}")

        if chain.conclusion:
            lines.append(f"\nConclusion: {chain.conclusion}")
            lines.append(f"Confidence: {chain.overall_confidence:.2f}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for chain in self._chains.values():
            type_counts[chain.reasoning_type.value] += 1

        return {
            "chains": len(self._chains),
            "steps": len(self._steps),
            "total_tokens": sum(c.total_tokens for c in self._chains.values()),
            "avg_confidence": round(
                sum(c.overall_confidence for c in self._chains.values()) /
                max(1, len(self._chains)), 2,
            ),
            "by_type": dict(type_counts),
        }
