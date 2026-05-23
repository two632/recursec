"""Reasoning chain — structured chain-of-thought for security analysis.

Implements multi-step reasoning with:
1. Evidence collection and weighting
2. Hypothesis formation
3. Deductive and inductive reasoning steps
4. Confidence propagation through chains
5. Contradiction detection
6. Reasoning with uncertainty
7. Multi-chain aggregation
8. Reasoning explanation generation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ReasoningType(str, Enum):
    DEDUCTIVE = "deductive"     # General rule → specific conclusion
    INDUCTIVE = "inductive"     # Specific observations → general rule
    ABDUCTIVE = "abductive"     # Observation → best explanation
    ANALOGICAL = "analogical"   # Similar cases → inference
    CAUSAL = "causal"           # Cause → effect reasoning


class EvidenceStrength(str, Enum):
    STRONG = "strong"           # Direct, verified evidence
    MODERATE = "moderate"       # Indirect but reliable
    WEAK = "weak"               # Circumstantial or unverified
    CONTRADICTORY = "contradictory"


@dataclass
class Evidence:
    """A piece of evidence for reasoning."""
    evidence_id: str = ""
    description: str = ""
    source: str = ""            # Tool output, observation, prior finding
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    confidence: float = 0.5
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def weight(self) -> float:
        strength_weights = {
            EvidenceStrength.STRONG: 1.0,
            EvidenceStrength.MODERATE: 0.6,
            EvidenceStrength.WEAK: 0.3,
            EvidenceStrength.CONTRADICTORY: -0.5,
        }
        return strength_weights.get(self.strength, 0.5) * self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "description": self.description[:100],
            "source": self.source,
            "strength": self.strength.value,
            "confidence": round(self.confidence, 2),
            "weight": round(self.weight, 2),
        }


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    step_number: int = 0
    reasoning_type: ReasoningType = ReasoningType.DEDUCTIVE
    premise: str = ""
    inference: str = ""
    conclusion: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    contradictions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "type": self.reasoning_type.value,
            "premise": self.premise[:100],
            "conclusion": self.conclusion[:100],
            "confidence": round(self.confidence, 2),
            "contradictions": len(self.contradictions),
        }


@dataclass
class ReasoningChain:
    """A complete chain of reasoning."""
    chain_id: str = ""
    question: str = ""
    steps: list[ReasoningStep] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    final_conclusion: str = ""
    overall_confidence: float = 0.0
    has_contradictions: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id,
            "question": self.question[:100],
            "steps": len(self.steps),
            "evidence": len(self.evidence),
            "conclusion": self.final_conclusion[:100],
            "confidence": round(self.overall_confidence, 2),
            "contradictions": self.has_contradictions,
        }


REASONING_PROMPT = """You are a security analyst performing structured reasoning.

Question: {question}

Evidence:
{evidence_text}

Perform step-by-step reasoning to answer the question.
For each step, identify:
1. The type of reasoning (deductive, inductive, abductive, analogical, causal)
2. The premise (what we know)
3. The inference (how we derive new knowledge)
4. The conclusion (what we can conclude)
5. Any contradictions or uncertainties

Respond as JSON:
{{
  "steps": [
    {{
      "type": "deductive|inductive|abductive|analogical|causal",
      "premise": "what we know",
      "inference": "reasoning process",
      "conclusion": "what we conclude",
      "confidence": 0.X,
      "contradictions": ["any contradictions"]
    }}
  ],
  "final_conclusion": "overall conclusion",
  "overall_confidence": 0.X
}}"""


class ReasoningEngine:
    """Structured chain-of-thought reasoning for security analysis.

    Builds evidence-based reasoning chains with confidence
    propagation, contradiction detection, and multi-chain
    aggregation.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._chains: dict[str, ReasoningChain] = {}
        self._evidence_store: dict[str, Evidence] = {}
        self._chain_counter = 0
        self._evidence_counter = 0
        self._step_counter = 0
        self._log = logger.bind(component="reasoning_chain")

    def add_evidence(
        self,
        description: str,
        source: str,
        strength: EvidenceStrength = EvidenceStrength.MODERATE,
        confidence: float = 0.5,
        data: dict[str, Any] | None = None,
    ) -> str:
        """Add evidence to the store."""
        self._evidence_counter += 1
        ev_id = f"ev-{self._evidence_counter}"

        evidence = Evidence(
            evidence_id=ev_id,
            description=description,
            source=source,
            strength=strength,
            confidence=confidence,
            data=data or {},
        )

        self._evidence_store[ev_id] = evidence
        return ev_id

    async def reason(
        self,
        question: str,
        evidence_ids: list[str] | None = None,
    ) -> ReasoningChain:
        """Build a reasoning chain for a question."""
        self._chain_counter += 1
        chain_id = f"chain-{self._chain_counter}"

        chain = ReasoningChain(
            chain_id=chain_id,
            question=question,
        )

        # Gather evidence
        if evidence_ids:
            chain.evidence = [
                self._evidence_store[eid] for eid in evidence_ids
                if eid in self._evidence_store
            ]
        else:
            chain.evidence = list(self._evidence_store.values())[-10:]

        # LLM reasoning
        if self._router:
            steps, conclusion, confidence = await self._llm_reason(question, chain.evidence)
            chain.steps = steps
            chain.final_conclusion = conclusion
            chain.overall_confidence = confidence
        else:
            chain = self._heuristic_reason(chain)

        # Check for contradictions
        chain.has_contradictions = any(
            step.contradictions for step in chain.steps
        )

        # Adjust confidence for contradictions
        if chain.has_contradictions:
            chain.overall_confidence *= 0.7

        self._chains[chain_id] = chain
        return chain

    async def reason_about_finding(
        self,
        finding: dict[str, Any],
    ) -> ReasoningChain:
        """Reason about whether a finding is valid."""
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "unknown")
        evidence_text = finding.get("evidence", "")
        tool = finding.get("tool", "")

        question = (
            f"Is this {severity} vulnerability finding valid? "
            f"'{title}' found by {tool}. Evidence: {evidence_text[:200]}"
        )

        ev_id = self.add_evidence(
            description=f"Finding: {title}",
            source=tool,
            strength=EvidenceStrength.MODERATE,
            confidence=0.6,
            data=finding,
        )

        return await self.reason(question, evidence_ids=[ev_id])

    async def multi_chain_aggregate(
        self,
        question: str,
        num_chains: int = 3,
        evidence_ids: list[str] | None = None,
    ) -> ReasoningChain:
        """Run multiple reasoning chains and aggregate."""
        chains = []
        for _ in range(num_chains):
            chain = await self.reason(question, evidence_ids)
            chains.append(chain)

        # Aggregate: take majority conclusion with averaged confidence
        if not chains:
            return ReasoningChain(question=question)

        best = max(chains, key=lambda c: c.overall_confidence)

        # Average confidence across chains
        avg_confidence = sum(c.overall_confidence for c in chains) / len(chains)

        result = ReasoningChain(
            chain_id=best.chain_id + "-agg",
            question=question,
            steps=best.steps,
            evidence=best.evidence,
            final_conclusion=best.final_conclusion,
            overall_confidence=avg_confidence,
            has_contradictions=any(c.has_contradictions for c in chains),
        )

        return result

    async def _llm_reason(
        self,
        question: str,
        evidence: list[Evidence],
    ) -> tuple[list[ReasoningStep], str, float]:
        """Use LLM for reasoning."""
        if not self._router:
            return [], "", 0.0

        evidence_text = "\n".join(
            f"  [{e.strength.value}] {e.description} (source: {e.source}, confidence: {e.confidence:.2f})"
            for e in evidence
        ) or "  No evidence available."

        prompt = REASONING_PROMPT.format(
            question=question[:300],
            evidence_text=evidence_text[:1000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=1024,
        )

        return self._parse_reasoning(response, evidence)

    def _heuristic_reason(self, chain: ReasoningChain) -> ReasoningChain:
        """Heuristic reasoning without LLM."""
        self._step_counter += 1
        step = ReasoningStep(
            step_id=f"step-{self._step_counter}",
            step_number=1,
            reasoning_type=ReasoningType.INDUCTIVE,
            premise="Evidence available: " + ", ".join(
                e.description[:30] for e in chain.evidence[:3]
            ),
            inference="Based on available evidence weight",
            conclusion="Assessment based on evidence strength",
        )

        # Confidence from evidence weights
        if chain.evidence:
            total_weight = sum(e.weight for e in chain.evidence)
            step.confidence = min(1.0, max(0.0, total_weight / max(1, len(chain.evidence))))
        else:
            step.confidence = 0.3

        chain.steps = [step]
        chain.overall_confidence = step.confidence
        chain.final_conclusion = step.conclusion

        return chain

    def _parse_reasoning(
        self,
        response: str,
        evidence: list[Evidence],
    ) -> tuple[list[ReasoningStep], str, float]:
        """Parse LLM reasoning response."""
        import json as json_mod

        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]
            data = json_mod.loads(response.strip())
        except (json_mod.JSONDecodeError, IndexError):
            return [], response[:200], 0.4

        steps = []
        ev_ids = [e.evidence_id for e in evidence]

        for idx, s_data in enumerate(data.get("steps", [])[:10]):
            self._step_counter += 1
            type_str = s_data.get("type", "deductive")
            try:
                r_type = ReasoningType(type_str)
            except ValueError:
                r_type = ReasoningType.DEDUCTIVE

            steps.append(ReasoningStep(
                step_id=f"step-{self._step_counter}",
                step_number=idx + 1,
                reasoning_type=r_type,
                premise=s_data.get("premise", ""),
                inference=s_data.get("inference", ""),
                conclusion=s_data.get("conclusion", ""),
                evidence_ids=ev_ids[:3],
                confidence=s_data.get("confidence", 0.5),
                contradictions=s_data.get("contradictions", []),
            ))

        conclusion = data.get("final_conclusion", "")
        confidence = data.get("overall_confidence", 0.5)

        return steps, conclusion, confidence

    def get_chain(self, chain_id: str) -> ReasoningChain | None:
        return self._chains.get(chain_id)

    def get_stats(self) -> dict[str, Any]:
        return {
            "chains": len(self._chains),
            "evidence": len(self._evidence_store),
            "steps": self._step_counter,
        }
