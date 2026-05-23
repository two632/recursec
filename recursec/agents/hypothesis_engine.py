"""Hypothesis engine — Bayesian hypothesis generation and testing.

Implements:
1. Hypothesis generation from observations
2. Bayesian confidence updating
3. Evidence tracking and scoring
4. Hypothesis competition (competing explanations)
5. Test plan generation
6. Hypothesis lifecycle management
7. LLM-integrated reasoning prompts
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    OBSERVATION = "observation"
    INFERENCE = "inference"
    CONTRADICTION = "contradiction"
    CORRELATION = "correlation"


class EvidenceStrength(str, Enum):
    STRONG = "strong"         # Direct proof/disproof
    MODERATE = "moderate"     # Circumstantial but significant
    WEAK = "weak"            # Suggestive but not conclusive
    AMBIGUOUS = "ambiguous"  # Could support either way


@dataclass
class Evidence:
    """A piece of evidence for/against a hypothesis."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.OBSERVATION
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    supports: bool = True         # True = supports, False = contradicts
    description: str = ""
    source: str = ""              # Tool or observation source
    likelihood_ratio: float = 1.0  # P(E|H) / P(E|~H)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        direction = "+" if self.supports else "-"
        return {
            "id": self.evidence_id[:10],
            "type": self.evidence_type.value,
            "dir": direction,
            "strength": self.strength.value,
            "lr": round(self.likelihood_ratio, 2),
        }


@dataclass
class Hypothesis:
    """A security hypothesis to test."""
    hypothesis_id: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    statement: str = ""
    category: str = ""
    target: str = ""
    prior_probability: float = 0.5
    current_probability: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    test_plan: list[str] = field(default_factory=list)
    tests_completed: int = 0
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    @property
    def confidence(self) -> float:
        """How confident we are in the current assessment."""
        return abs(self.current_probability - 0.5) * 2

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def supporting_count(self) -> int:
        return sum(1 for e in self.evidence if e.supports)

    @property
    def contradicting_count(self) -> int:
        return sum(1 for e in self.evidence if not e.supports)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id[:10],
            "status": self.status.value,
            "statement": self.statement[:30],
            "prob": round(self.current_probability, 3),
            "conf": round(self.confidence, 2),
            "evidence": f"{self.supporting_count}+/{self.contradicting_count}-",
        }


# ── Likelihood ratio defaults ────────────────────────────────

STRENGTH_LR: dict[str, float] = {
    "strong": 10.0,
    "moderate": 3.0,
    "weak": 1.5,
    "ambiguous": 1.1,
}


class HypothesisEngine:
    """Bayesian hypothesis testing engine.

    Generates hypotheses about security findings,
    updates probabilities with evidence using
    Bayes' theorem, and tracks hypothesis lifecycle.
    """

    # Thresholds for resolution
    SUPPORT_THRESHOLD = 0.85
    REJECT_THRESHOLD = 0.15

    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}
        self._counter = 0
        self._log = logger.bind(component="hypothesis_engine")

    def propose(
        self,
        statement: str,
        category: str = "",
        target: str = "",
        prior: float = 0.5,
        test_plan: list[str] | None = None,
    ) -> Hypothesis:
        """Propose a new hypothesis."""
        self._counter += 1
        h = Hypothesis(
            hypothesis_id=f"hyp-{self._counter}",
            statement=statement,
            category=category,
            target=target,
            prior_probability=prior,
            current_probability=prior,
            test_plan=test_plan or [],
        )
        self._hypotheses[h.hypothesis_id] = h
        return h

    def add_evidence(
        self,
        hypothesis_id: str,
        description: str,
        supports: bool = True,
        evidence_type: EvidenceType = EvidenceType.OBSERVATION,
        strength: EvidenceStrength = EvidenceStrength.MODERATE,
        source: str = "",
    ) -> Evidence | None:
        """Add evidence and update probability."""
        h = self._hypotheses.get(hypothesis_id)
        if not h:
            return None

        # Calculate likelihood ratio
        base_lr = STRENGTH_LR.get(strength.value, 1.5)
        lr = base_lr if supports else 1.0 / base_lr

        ev = Evidence(
            evidence_id=f"ev-{self._counter}-{h.evidence_count + 1}",
            evidence_type=evidence_type,
            strength=strength,
            supports=supports,
            description=description,
            source=source,
            likelihood_ratio=lr,
        )
        h.evidence.append(ev)
        h.tests_completed += 1

        # Bayesian update: P(H|E) = P(E|H)*P(H) / P(E)
        prior = h.current_probability
        posterior = (lr * prior) / (lr * prior + (1 - prior))
        h.current_probability = max(0.001, min(0.999, posterior))

        h.status = HypothesisStatus.TESTING

        # Check thresholds
        if h.current_probability >= self.SUPPORT_THRESHOLD:
            h.status = HypothesisStatus.SUPPORTED
            h.resolved_at = time.time()
        elif h.current_probability <= self.REJECT_THRESHOLD:
            h.status = HypothesisStatus.REJECTED
            h.resolved_at = time.time()

        return ev

    def get_active(self) -> list[Hypothesis]:
        """Get hypotheses still being tested."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]

    def get_supported(self) -> list[Hypothesis]:
        """Get confirmed hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.SUPPORTED
        ]

    def get_competing(self, category: str) -> list[Hypothesis]:
        """Get competing hypotheses in same category."""
        return sorted(
            [h for h in self._hypotheses.values() if h.category == category],
            key=lambda h: h.current_probability,
            reverse=True,
        )

    def build_hypothesis_prompt(self, max_hypotheses: int = 8) -> str:
        """Build hypothesis context for LLM."""
        lines = ["## Hypotheses\n"]

        active = self.get_active()
        if active:
            lines.append("Active hypotheses:")
            for h in sorted(active, key=lambda x: x.current_probability, reverse=True)[:max_hypotheses]:
                prob_bar = _prob_bar(h.current_probability)
                lines.append(
                    f"  {prob_bar} P={h.current_probability:.2f} "
                    f"{h.statement[:40]}"
                )
                if h.test_plan:
                    remaining = h.test_plan[h.tests_completed:]
                    if remaining:
                        lines.append(f"    Next test: {remaining[0][:40]}")

        supported = self.get_supported()
        if supported:
            lines.append(f"\nConfirmed ({len(supported)}):")
            for h in supported[:3]:
                lines.append(f"  [CONFIRMED] {h.statement[:40]}")

        if not active and not supported:
            lines.append("No hypotheses yet. Generate hypotheses from observations.")

        return "\n".join(lines)

    def suggest_hypotheses(self, observation: str) -> list[dict[str, Any]]:
        """Suggest hypotheses based on an observation."""
        suggestions: list[dict[str, Any]] = []

        observation_lower = observation.lower()

        patterns: list[tuple[list[str], str, str, float]] = [
            (
                ["port 80", "port 443", "http", "web"],
                "Target runs a web application with potential web vulnerabilities",
                "web",
                0.6,
            ),
            (
                ["port 22", "ssh"],
                "SSH service may have weak credentials or misconfigurations",
                "ssh",
                0.4,
            ),
            (
                ["port 3306", "mysql", "port 5432", "postgres"],
                "Database service may be externally accessible",
                "database",
                0.5,
            ),
            (
                ["smb", "port 445", "port 139"],
                "SMB service may be vulnerable to EternalBlue or relay attacks",
                "smb",
                0.5,
            ),
            (
                ["outdated", "old version", "eol"],
                "Outdated software likely has known CVEs",
                "patching",
                0.7,
            ),
            (
                ["login", "auth", "password"],
                "Authentication mechanism may have weaknesses",
                "auth",
                0.5,
            ),
        ]

        for keywords, statement, category, prior in patterns:
            if any(kw in observation_lower for kw in keywords):
                suggestions.append({
                    "statement": statement,
                    "category": category,
                    "prior": prior,
                })

        return suggestions

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for h in self._hypotheses.values():
            status_counts[h.status.value] = status_counts.get(h.status.value, 0) + 1

        return {
            "total": len(self._hypotheses),
            "by_status": status_counts,
            "avg_evidence": (
                sum(h.evidence_count for h in self._hypotheses.values()) / len(self._hypotheses)
                if self._hypotheses else 0
            ),
        }


def _prob_bar(prob: float, width: int = 10) -> str:
    """Create a simple probability bar."""
    filled = int(prob * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"
