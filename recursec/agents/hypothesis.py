"""Hypothesis engine — generates and tests security hypotheses.

Models security analysis as a scientific process:
1. Observe target characteristics
2. Generate hypotheses about potential vulnerabilities
3. Design tests to validate/invalidate each hypothesis
4. Execute tests and collect evidence
5. Update hypothesis confidence based on results
6. Generate new hypotheses from discoveries

Each hypothesis has:
- A claim (what vulnerability might exist)
- Supporting evidence
- Contradicting evidence
- A confidence score (Bayesian updated)
- Test procedures
- Current status (unconfirmed, confirmed, rejected, needs_more_data)
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NEEDS_MORE_DATA = "needs_more_data"
    SUPERSEDED = "superseded"


class EvidenceType(str, Enum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


@dataclass
class Evidence:
    """A piece of evidence for or against a hypothesis."""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    evidence_type: EvidenceType = EvidenceType.NEUTRAL
    source: str = ""  # Tool or agent that produced this
    description: str = ""
    raw_data: str = ""
    strength: float = 0.5  # 0.0 = weak, 1.0 = conclusive
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id, "type": self.evidence_type.value,
            "source": self.source, "description": self.description[:200],
            "strength": round(self.strength, 2),
        }


@dataclass
class TestProcedure:
    """A procedure to test a hypothesis."""
    test_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    expected_if_true: str = ""  # What we expect to see if hypothesis is true
    expected_if_false: str = ""  # What we expect if hypothesis is false
    executed: bool = False
    result: str = ""
    outcome: str = ""  # "supports", "contradicts", "inconclusive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.test_id, "description": self.description[:200],
            "tool": self.tool_name, "executed": self.executed,
            "outcome": self.outcome,
        }


@dataclass
class Hypothesis:
    """A security hypothesis about a potential vulnerability."""
    hypothesis_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    claim: str = ""
    category: str = ""  # sqli, xss, rce, misconfig, etc.
    target_component: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    prior_probability: float = 0.3  # Base rate for this type of vuln
    posterior_probability: float = 0.3  # Updated probability
    evidence_for: list[Evidence] = field(default_factory=list)
    evidence_against: list[Evidence] = field(default_factory=list)
    test_procedures: list[TestProcedure] = field(default_factory=list)
    related_hypotheses: list[str] = field(default_factory=list)
    generated_from: str = ""  # hypothesis_id that led to this one
    severity_if_true: str = "medium"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence and update probability using Bayesian update."""
        if evidence.evidence_type == EvidenceType.SUPPORTING:
            self.evidence_for.append(evidence)
        elif evidence.evidence_type == EvidenceType.CONTRADICTING:
            self.evidence_against.append(evidence)

        self._bayesian_update(evidence)
        self.updated_at = time.time()
        self._update_status()

    def _bayesian_update(self, evidence: Evidence) -> None:
        """Update posterior probability using Bayes' theorem.

        P(H|E) = P(E|H) * P(H) / P(E)
        P(E) = P(E|H)*P(H) + P(E|~H)*P(~H)
        """
        p_h = self.posterior_probability

        if evidence.evidence_type == EvidenceType.SUPPORTING:
            # P(E|H) = evidence strength (high for strong supporting evidence)
            p_e_given_h = 0.5 + evidence.strength * 0.5  # Range: 0.5-1.0
            # P(E|~H) = lower for strong evidence (less likely to see this if false)
            p_e_given_not_h = 0.5 - evidence.strength * 0.4  # Range: 0.1-0.5
        elif evidence.evidence_type == EvidenceType.CONTRADICTING:
            p_e_given_h = 0.5 - evidence.strength * 0.4
            p_e_given_not_h = 0.5 + evidence.strength * 0.5
        else:
            return  # Neutral evidence doesn't update

        p_not_h = 1.0 - p_h
        p_e = p_e_given_h * p_h + p_e_given_not_h * p_not_h

        if p_e > 0:
            self.posterior_probability = (p_e_given_h * p_h) / p_e

        # Clamp to reasonable range
        self.posterior_probability = max(0.01, min(0.99, self.posterior_probability))

    def _update_status(self) -> None:
        """Update status based on probability."""
        if self.posterior_probability >= 0.85:
            self.status = HypothesisStatus.CONFIRMED
        elif self.posterior_probability <= 0.1:
            self.status = HypothesisStatus.REJECTED
        elif len(self.evidence_for) + len(self.evidence_against) >= 3:
            if 0.3 <= self.posterior_probability <= 0.7:
                self.status = HypothesisStatus.NEEDS_MORE_DATA
        elif self.test_procedures and all(t.executed for t in self.test_procedures):
            self.status = HypothesisStatus.NEEDS_MORE_DATA

    @property
    def confidence(self) -> float:
        """Confidence in the current status determination."""
        return abs(self.posterior_probability - 0.5) * 2.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id, "claim": self.claim[:200],
            "category": self.category, "status": self.status.value,
            "probability": round(self.posterior_probability, 3),
            "confidence": round(self.confidence, 3),
            "evidence_for": len(self.evidence_for),
            "evidence_against": len(self.evidence_against),
            "tests": len(self.test_procedures),
            "severity": self.severity_if_true,
        }


# ── Prompt Templates ────────────────────────────────────────

GENERATE_HYPOTHESES_PROMPT = """You are a security researcher. Based on the target information, generate hypotheses about potential vulnerabilities.

Target: {target}
Target information: {target_info}
Previous findings: {previous_findings}
Already tested hypotheses: {tested}

Generate 3-5 hypotheses about potential vulnerabilities. For each:
1. A specific, testable claim
2. The vulnerability category
3. The target component
4. Prior probability (base rate for this type)
5. Severity if confirmed
6. How to test it

Respond as JSON:
{{
  "hypotheses": [
    {{
      "claim": "specific testable claim",
      "category": "sqli|xss|rce|ssrf|idor|misconfig|auth|crypto|injection|lfi|etc",
      "target_component": "specific endpoint/service/component",
      "prior_probability": 0.3,
      "severity": "critical|high|medium|low|info",
      "test_procedures": [
        {{
          "description": "what to test",
          "tool": "tool_name",
          "tool_args": {{}},
          "expected_if_true": "what indicates vuln exists",
          "expected_if_false": "what indicates no vuln"
        }}
      ]
    }}
  ]
}}"""

EVALUATE_EVIDENCE_PROMPT = """Evaluate this test result as evidence for/against a hypothesis.

Hypothesis: {claim}
Test performed: {test_description}
Test result: {result}
Expected if true: {expected_true}
Expected if false: {expected_false}

Determine:
1. Does this support or contradict the hypothesis?
2. How strong is this evidence? (0.0-1.0)
3. What additional tests would be useful?

Respond as JSON:
{{
  "verdict": "supporting|contradicting|neutral",
  "strength": 0.X,
  "explanation": "...",
  "additional_tests": ["..."]
}}"""

GENERATE_FOLLOWUP_PROMPT = """A hypothesis has been confirmed. Generate follow-up hypotheses.

Confirmed hypothesis: {claim}
Evidence: {evidence}
Target: {target}

What related vulnerabilities might exist given this finding?
What attack chains could this enable?

Respond as JSON:
{{
  "followup_hypotheses": [
    {{
      "claim": "...",
      "category": "...",
      "target_component": "...",
      "prior_probability": 0.X,
      "severity": "...",
      "relationship": "chain|similar|escalation|lateral"
    }}
  ]
}}"""


class HypothesisEngine:
    """Generates and manages security hypotheses.

    Treats security testing as a scientific process with
    Bayesian hypothesis testing.
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._hypotheses: dict[str, Hypothesis] = {}
        self._log = logger.bind(component="hypothesis_engine")

    async def generate_hypotheses(
        self,
        target: str,
        target_info: dict[str, Any] | None = None,
        previous_findings: list[dict[str, Any]] | None = None,
    ) -> list[Hypothesis]:
        """Generate new hypotheses based on target information."""
        tested = [
            h.claim for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.CONFIRMED, HypothesisStatus.REJECTED)
        ]

        prompt = GENERATE_HYPOTHESES_PROMPT.format(
            target=target,
            target_info=json.dumps(target_info or {})[:2000],
            previous_findings=json.dumps(previous_findings or [])[:2000],
            tested=json.dumps(tested[:10]),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.4,
            max_tokens=4096,
        )

        hypotheses = self._parse_hypotheses(response)
        for h in hypotheses:
            self._hypotheses[h.hypothesis_id] = h

        self._log.info("hypotheses_generated", count=len(hypotheses))
        return hypotheses

    async def evaluate_test_result(
        self,
        hypothesis_id: str,
        test_id: str,
        result: str,
    ) -> Evidence | None:
        """Evaluate a test result as evidence for a hypothesis."""
        hypothesis = self._hypotheses.get(hypothesis_id)
        if not hypothesis:
            return None

        test_proc = None
        for tp in hypothesis.test_procedures:
            if tp.test_id == test_id:
                test_proc = tp
                break

        if not test_proc:
            return None

        prompt = EVALUATE_EVIDENCE_PROMPT.format(
            claim=hypothesis.claim,
            test_description=test_proc.description,
            result=result[:3000],
            expected_true=test_proc.expected_if_true,
            expected_false=test_proc.expected_if_false,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)

        verdict = data.get("verdict", "neutral")
        evidence = Evidence(
            evidence_type=EvidenceType(verdict) if verdict in ("supporting", "contradicting", "neutral") else EvidenceType.NEUTRAL,
            source=test_proc.tool_name,
            description=data.get("explanation", ""),
            raw_data=result[:1000],
            strength=data.get("strength", 0.5),
        )

        hypothesis.add_evidence(evidence)
        test_proc.executed = True
        test_proc.result = result[:1000]
        test_proc.outcome = verdict

        # Generate follow-up hypotheses if confirmed
        if hypothesis.status == HypothesisStatus.CONFIRMED:
            await self._generate_followups(hypothesis)

        return evidence

    async def _generate_followups(self, confirmed: Hypothesis) -> None:
        """Generate follow-up hypotheses from a confirmed finding."""
        prompt = GENERATE_FOLLOWUP_PROMPT.format(
            claim=confirmed.claim,
            evidence=json.dumps([e.to_dict() for e in confirmed.evidence_for[:5]]),
            target=confirmed.target_component,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.4,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        for h_data in data.get("followup_hypotheses", []):
            h = Hypothesis(
                claim=h_data.get("claim", ""),
                category=h_data.get("category", ""),
                target_component=h_data.get("target_component", confirmed.target_component),
                prior_probability=h_data.get("prior_probability", 0.4),
                severity_if_true=h_data.get("severity", "medium"),
                generated_from=confirmed.hypothesis_id,
            )
            confirmed.related_hypotheses.append(h.hypothesis_id)
            self._hypotheses[h.hypothesis_id] = h

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hypothesis_id)

    def get_testable(self) -> list[Hypothesis]:
        """Get hypotheses that need testing."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING, HypothesisStatus.NEEDS_MORE_DATA)
        ]

    def get_confirmed(self) -> list[Hypothesis]:
        """Get confirmed hypotheses."""
        return [h for h in self._hypotheses.values() if h.status == HypothesisStatus.CONFIRMED]

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all hypotheses."""
        by_status: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for h in self._hypotheses.values():
            by_status[h.status.value] = by_status.get(h.status.value, 0) + 1
            by_category[h.category] = by_category.get(h.category, 0) + 1
        return {
            "total": len(self._hypotheses),
            "by_status": by_status,
            "by_category": by_category,
            "highest_probability": max(
                (h.posterior_probability for h in self._hypotheses.values()),
                default=0.0,
            ),
        }

    def _parse_hypotheses(self, response: str) -> list[Hypothesis]:
        """Parse hypotheses from LLM response."""
        data = self._parse_json(response)
        results = []

        for h_data in data.get("hypotheses", []):
            h = Hypothesis(
                claim=h_data.get("claim", ""),
                category=h_data.get("category", ""),
                target_component=h_data.get("target_component", ""),
                prior_probability=h_data.get("prior_probability", 0.3),
                posterior_probability=h_data.get("prior_probability", 0.3),
                severity_if_true=h_data.get("severity", "medium"),
            )

            for tp_data in h_data.get("test_procedures", []):
                tp = TestProcedure(
                    description=tp_data.get("description", ""),
                    tool_name=tp_data.get("tool", ""),
                    tool_args=tp_data.get("tool_args", {}),
                    expected_if_true=tp_data.get("expected_if_true", ""),
                    expected_if_false=tp_data.get("expected_if_false", ""),
                )
                h.test_procedures.append(tp)

            results.append(h)

        return results

    def _parse_json(self, text: str) -> dict[str, Any]:
        """Parse JSON from LLM response."""
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
