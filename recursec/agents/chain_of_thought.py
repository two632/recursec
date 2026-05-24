"""Chain-of-thought engine — structured reasoning.

Implements:
1. Thought chains with evidence linking
2. Reasoning step tracking
3. Hypothesis formation and testing
4. Logical inference chains
5. Reasoning quality assessment
6. CoT prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ThoughtType(str, Enum):
    OBSERVATION = "observation"       # Raw observation
    HYPOTHESIS = "hypothesis"         # Proposed explanation
    INFERENCE = "inference"           # Logical deduction
    EVIDENCE = "evidence"             # Supporting evidence
    CONTRADICTION = "contradiction"   # Contradicting evidence
    CONCLUSION = "conclusion"         # Final conclusion
    QUESTION = "question"             # Open question
    ACTION = "action"                 # Recommended action


class ReasoningQuality(str, Enum):
    STRONG = "strong"         # Multiple evidence, consistent
    MODERATE = "moderate"     # Some evidence, plausible
    WEAK = "weak"             # Limited evidence
    SPECULATIVE = "speculative"  # No direct evidence


@dataclass
class Thought:
    """A single thought in the reasoning chain."""
    thought_id: str = ""
    thought_type: ThoughtType = ThoughtType.OBSERVATION
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    parent_id: str = ""  # Previous thought in chain
    references: list[str] = field(default_factory=list)  # Related thoughts
    source: str = ""  # What produced this thought
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.thought_type.value[:8],
            "content": self.content[:30],
            "conf": f"{self.confidence:.2f}",
            "evidence": len(self.evidence),
        }


@dataclass
class ReasoningChain:
    """A complete chain of reasoning."""
    chain_id: str = ""
    topic: str = ""
    thoughts: list[str] = field(default_factory=list)  # thought_ids
    quality: ReasoningQuality = ReasoningQuality.SPECULATIVE
    conclusion: str = ""
    confidence: float = 0.0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic[:20],
            "steps": len(self.thoughts),
            "quality": self.quality.value[:8],
            "conf": f"{self.confidence:.2f}",
        }


class ChainOfThoughtEngine:
    """Structured chain-of-thought reasoning.

    Builds and evaluates reasoning chains,
    tracks evidence, and assesses quality.
    """

    def __init__(self, max_chain_length: int = 20) -> None:
        self._thoughts: dict[str, Thought] = {}
        self._chains: dict[str, ReasoningChain] = {}
        self._thought_counter = 0
        self._chain_counter = 0
        self._max_chain = max_chain_length
        self._log = logger.bind(component="cot")

    def start_chain(self, topic: str) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"chain-{self._chain_counter}",
            topic=topic,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_thought(
        self,
        chain_id: str,
        thought_type: ThoughtType,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        source: str = "",
    ) -> Thought:
        """Add a thought to a chain."""
        self._thought_counter += 1

        chain = self._chains.get(chain_id)
        parent_id = ""
        if chain and chain.thoughts:
            parent_id = chain.thoughts[-1]

        thought = Thought(
            thought_id=f"t-{self._thought_counter}",
            thought_type=thought_type,
            content=content,
            evidence=evidence or [],
            confidence=confidence,
            parent_id=parent_id,
            source=source,
        )
        self._thoughts[thought.thought_id] = thought

        if chain:
            chain.thoughts.append(thought.thought_id)
            self._update_chain_quality(chain_id)

        return thought

    def observe(
        self,
        chain_id: str,
        observation: str,
        source: str = "",
    ) -> Thought:
        """Add an observation."""
        return self.add_thought(
            chain_id, ThoughtType.OBSERVATION,
            observation, confidence=0.8, source=source,
        )

    def hypothesize(
        self,
        chain_id: str,
        hypothesis: str,
        supporting_evidence: list[str] | None = None,
    ) -> Thought:
        """Add a hypothesis."""
        return self.add_thought(
            chain_id, ThoughtType.HYPOTHESIS,
            hypothesis, evidence=supporting_evidence, confidence=0.4,
        )

    def infer(
        self,
        chain_id: str,
        inference: str,
        based_on: list[str] | None = None,
        confidence: float = 0.6,
    ) -> Thought:
        """Add an inference."""
        return self.add_thought(
            chain_id, ThoughtType.INFERENCE,
            inference, evidence=based_on, confidence=confidence,
        )

    def add_evidence(
        self,
        chain_id: str,
        evidence_text: str,
        supports_thought_id: str = "",
        confidence: float = 0.7,
    ) -> Thought:
        """Add supporting evidence."""
        thought = self.add_thought(
            chain_id, ThoughtType.EVIDENCE,
            evidence_text, confidence=confidence,
        )

        # Link to supported thought
        if supports_thought_id and supports_thought_id in self._thoughts:
            self._thoughts[supports_thought_id].references.append(
                thought.thought_id
            )
            # Boost supported thought's confidence
            supported = self._thoughts[supports_thought_id]
            supported.confidence = min(
                0.95, supported.confidence + 0.1
            )

        return thought

    def contradict(
        self,
        chain_id: str,
        contradiction: str,
        contradicts_thought_id: str = "",
    ) -> Thought:
        """Add contradicting evidence."""
        thought = self.add_thought(
            chain_id, ThoughtType.CONTRADICTION,
            contradiction, confidence=0.7,
        )

        # Reduce confidence of contradicted thought
        if contradicts_thought_id and contradicts_thought_id in self._thoughts:
            contradicted = self._thoughts[contradicts_thought_id]
            contradicted.confidence = max(
                0.05, contradicted.confidence - 0.2
            )

        return thought

    def conclude(
        self,
        chain_id: str,
        conclusion: str,
        confidence: float = 0.0,
    ) -> Thought:
        """Add a conclusion to the chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return Thought()

        # Auto-calculate confidence from chain
        if confidence == 0.0:
            confidence = self._calculate_chain_confidence(chain_id)

        thought = self.add_thought(
            chain_id, ThoughtType.CONCLUSION,
            conclusion, confidence=confidence,
        )

        chain.conclusion = conclusion
        chain.confidence = confidence
        chain.completed_at = time.time()

        return thought

    def _calculate_chain_confidence(self, chain_id: str) -> float:
        """Calculate overall chain confidence."""
        chain = self._chains.get(chain_id)
        if not chain or not chain.thoughts:
            return 0.0

        thoughts = [
            self._thoughts[tid]
            for tid in chain.thoughts
            if tid in self._thoughts
        ]

        if not thoughts:
            return 0.0

        # Weight by type
        type_weights = {
            ThoughtType.EVIDENCE: 1.5,
            ThoughtType.OBSERVATION: 1.2,
            ThoughtType.INFERENCE: 1.0,
            ThoughtType.HYPOTHESIS: 0.8,
            ThoughtType.CONTRADICTION: -0.5,
            ThoughtType.QUESTION: 0.0,
            ThoughtType.ACTION: 0.5,
            ThoughtType.CONCLUSION: 0.0,  # Don't count itself
        }

        total_weight = 0.0
        weighted_conf = 0.0

        for t in thoughts:
            w = type_weights.get(t.thought_type, 1.0)
            if w > 0:
                weighted_conf += t.confidence * w
                total_weight += w
            elif w < 0:
                weighted_conf += w  # Penalty

        if total_weight == 0:
            return 0.0

        return max(0.0, min(1.0, weighted_conf / total_weight))

    def _update_chain_quality(self, chain_id: str) -> None:
        """Update chain quality assessment."""
        chain = self._chains.get(chain_id)
        if not chain:
            return

        thoughts = [
            self._thoughts[tid]
            for tid in chain.thoughts
            if tid in self._thoughts
        ]

        evidence_count = sum(
            1 for t in thoughts
            if t.thought_type == ThoughtType.EVIDENCE
        )
        contradiction_count = sum(
            1 for t in thoughts
            if t.thought_type == ThoughtType.CONTRADICTION
        )
        has_hypothesis = any(
            t.thought_type == ThoughtType.HYPOTHESIS
            for t in thoughts
        )

        if evidence_count >= 3 and contradiction_count == 0:
            chain.quality = ReasoningQuality.STRONG
        elif evidence_count >= 1 and has_hypothesis:
            chain.quality = ReasoningQuality.MODERATE
        elif evidence_count >= 1 or has_hypothesis:
            chain.quality = ReasoningQuality.WEAK
        else:
            chain.quality = ReasoningQuality.SPECULATIVE

    def build_cot_prompt(self, chain_id: str = "") -> str:
        """Build chain-of-thought context for LLM."""
        if chain_id and chain_id in self._chains:
            return self._build_chain_detail(chain_id)

        lines = ["## Reasoning\n"]
        lines.append(f"Chains: {len(self._chains)}")
        lines.append(f"Thoughts: {len(self._thoughts)}")

        # Recent chains
        recent = sorted(
            self._chains.values(),
            key=lambda c: c.started_at,
            reverse=True,
        )[:3]

        for chain in recent:
            lines.append(
                f"\n[{chain.quality.value[:5]}] {chain.topic[:25]}"
            )
            if chain.conclusion:
                lines.append(f"  → {chain.conclusion[:40]}")

        return "\n".join(lines)

    def _build_chain_detail(self, chain_id: str) -> str:
        """Build detailed view of a single chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [f"## Reasoning: {chain.topic}\n"]
        lines.append(f"Quality: {chain.quality.value}")
        lines.append(f"Steps: {len(chain.thoughts)}")

        for tid in chain.thoughts:
            t = self._thoughts.get(tid)
            if not t:
                continue
            prefix = {
                ThoughtType.OBSERVATION: "OBS",
                ThoughtType.HYPOTHESIS: "HYP",
                ThoughtType.INFERENCE: "INF",
                ThoughtType.EVIDENCE: "EVD",
                ThoughtType.CONTRADICTION: "CON",
                ThoughtType.CONCLUSION: "===",
                ThoughtType.QUESTION: "???",
                ThoughtType.ACTION: "ACT",
            }.get(t.thought_type, "???")

            lines.append(
                f"  [{prefix}] ({t.confidence:.2f}) {t.content[:40]}"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        quality_counts: dict[str, int] = {}
        for c in self._chains.values():
            quality_counts[c.quality.value] = quality_counts.get(c.quality.value, 0) + 1

        return {
            "chains": len(self._chains),
            "thoughts": len(self._thoughts),
            "by_quality": quality_counts,
        }
