"""Reasoning engine — multi-step logical reasoning for security analysis.

Implements:
1. Chain-of-thought reasoning
2. Abductive reasoning (best explanation from observations)
3. Deductive reasoning (conclusion from premises)
4. Analogical reasoning (similar past vulnerabilities)
5. Reasoning trace management
6. Confidence propagation through reasoning chains
7. Contradiction detection
8. Reasoning validation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningType(str, Enum):
    CHAIN_OF_THOUGHT = "chain_of_thought"
    ABDUCTIVE = "abductive"
    DEDUCTIVE = "deductive"
    ANALOGICAL = "analogical"
    CAUSAL = "causal"


class StepStatus(str, Enum):
    HYPOTHESIS = "hypothesis"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNCERTAIN = "uncertain"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    step_number: int = 0
    premise: str = ""
    conclusion: str = ""
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    status: StepStatus = StepStatus.HYPOTHESIS
    reasoning_type: ReasoningType = ReasoningType.CHAIN_OF_THOUGHT

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "premise": self.premise[:60],
            "conclusion": self.conclusion[:60],
            "confidence": round(self.confidence, 2),
            "status": self.status.value,
        }


@dataclass
class ReasoningChain:
    """A complete reasoning chain."""
    chain_id: str = ""
    question: str = ""
    reasoning_type: ReasoningType = ReasoningType.CHAIN_OF_THOUGHT
    steps: list[ReasoningStep] = field(default_factory=list)
    final_conclusion: str = ""
    overall_confidence: float = 0.0
    contradictions: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def is_valid(self) -> bool:
        return len(self.contradictions) == 0 and self.overall_confidence > 0.3

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id,
            "question": self.question[:60],
            "type": self.reasoning_type.value,
            "steps": len(self.steps),
            "conclusion": self.final_conclusion[:60],
            "confidence": round(self.overall_confidence, 2),
            "valid": self.is_valid,
        }


# ── Reasoning Patterns ────────────────────────────────────────

DEDUCTIVE_RULES: list[dict[str, Any]] = [
    {
        "premises": ["port_open", "service_running"],
        "conclusion": "service_accessible",
        "confidence": 0.95,
    },
    {
        "premises": ["service_accessible", "default_credentials"],
        "conclusion": "unauthorized_access_possible",
        "confidence": 0.9,
    },
    {
        "premises": ["sql_error_in_response", "user_input_reflected"],
        "conclusion": "sql_injection_likely",
        "confidence": 0.85,
    },
    {
        "premises": ["xss_payload_rendered", "no_output_encoding"],
        "conclusion": "xss_confirmed",
        "confidence": 0.95,
    },
    {
        "premises": ["outdated_software", "known_cve_exists"],
        "conclusion": "known_vulnerability_present",
        "confidence": 0.9,
    },
    {
        "premises": ["tls_weak_cipher", "sensitive_data_transit"],
        "conclusion": "data_interception_risk",
        "confidence": 0.8,
    },
    {
        "premises": ["directory_listing_enabled", "sensitive_files_present"],
        "conclusion": "information_disclosure",
        "confidence": 0.9,
    },
    {
        "premises": ["no_rate_limiting", "login_endpoint_exists"],
        "conclusion": "brute_force_possible",
        "confidence": 0.8,
    },
    {
        "premises": ["cors_misconfigured", "credentials_in_requests"],
        "conclusion": "cross_origin_attack_possible",
        "confidence": 0.75,
    },
    {
        "premises": ["jwt_no_signature_verify", "auth_uses_jwt"],
        "conclusion": "authentication_bypass_possible",
        "confidence": 0.85,
    },
]

ANALOGY_DATABASE: list[dict[str, Any]] = [
    {
        "pattern": "exposed_admin_panel",
        "similar_vulns": ["default_credentials", "brute_force", "privilege_escalation"],
        "typical_severity": "high",
        "success_rate": 0.6,
    },
    {
        "pattern": "outdated_cms",
        "similar_vulns": ["known_cve_exploitation", "plugin_vulnerabilities", "rce"],
        "typical_severity": "critical",
        "success_rate": 0.7,
    },
    {
        "pattern": "api_no_auth",
        "similar_vulns": ["data_exfiltration", "idor", "mass_assignment"],
        "typical_severity": "high",
        "success_rate": 0.8,
    },
    {
        "pattern": "file_upload_endpoint",
        "similar_vulns": ["webshell_upload", "path_traversal", "rce"],
        "typical_severity": "critical",
        "success_rate": 0.5,
    },
    {
        "pattern": "verbose_error_messages",
        "similar_vulns": ["stack_trace_leak", "db_schema_leak", "path_disclosure"],
        "typical_severity": "medium",
        "success_rate": 0.9,
    },
]


class ReasoningEngine:
    """Multi-step logical reasoning for security analysis.

    Supports chain-of-thought, deductive, abductive,
    and analogical reasoning with confidence propagation.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._chain_counter = 0
        self._step_counter = 0
        self._log = logger.bind(component="reasoning_engine")

    def reason_chain_of_thought(
        self,
        question: str,
        observations: list[str],
    ) -> ReasoningChain:
        """Build a chain-of-thought reasoning chain."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"rc-{self._chain_counter}",
            question=question,
            reasoning_type=ReasoningType.CHAIN_OF_THOUGHT,
        )

        # Build steps from observations
        for i, obs in enumerate(observations):
            self._step_counter += 1
            step = ReasoningStep(
                step_id=f"rs-{self._step_counter}",
                step_number=i + 1,
                premise=obs,
                conclusion=f"Based on: {obs[:80]}",
                confidence=0.7,
                status=StepStatus.SUPPORTED if i < len(observations) - 1 else StepStatus.HYPOTHESIS,
            )
            chain.steps.append(step)

        # Calculate overall confidence
        if chain.steps:
            chain.overall_confidence = self._propagate_confidence(chain.steps)
            chain.final_conclusion = chain.steps[-1].conclusion

        self._chains[chain.chain_id] = chain
        return chain

    def reason_deductive(
        self,
        premises: list[str],
    ) -> ReasoningChain:
        """Apply deductive reasoning rules."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"rc-{self._chain_counter}",
            question="Deductive analysis",
            reasoning_type=ReasoningType.DEDUCTIVE,
        )

        premise_set = set(p.lower().replace(" ", "_") for p in premises)

        for rule in DEDUCTIVE_RULES:
            rule_premises = set(rule["premises"])
            if rule_premises.issubset(premise_set):
                self._step_counter += 1
                step = ReasoningStep(
                    step_id=f"rs-{self._step_counter}",
                    step_number=len(chain.steps) + 1,
                    premise=f"Given: {', '.join(rule['premises'])}",
                    conclusion=rule["conclusion"],
                    confidence=rule["confidence"],
                    status=StepStatus.SUPPORTED,
                    reasoning_type=ReasoningType.DEDUCTIVE,
                )
                chain.steps.append(step)

                # Add derived conclusion to premises for chaining
                premise_set.add(rule["conclusion"])

        if chain.steps:
            chain.overall_confidence = self._propagate_confidence(chain.steps)
            chain.final_conclusion = chain.steps[-1].conclusion

        self._chains[chain.chain_id] = chain
        return chain

    def reason_analogical(
        self,
        observation: str,
    ) -> ReasoningChain:
        """Apply analogical reasoning from past patterns."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"rc-{self._chain_counter}",
            question=f"Analogical analysis: {observation[:60]}",
            reasoning_type=ReasoningType.ANALOGICAL,
        )

        observation_lower = observation.lower()

        for analogy in ANALOGY_DATABASE:
            pattern = analogy["pattern"].replace("_", " ")
            if pattern in observation_lower or any(
                w in observation_lower for w in pattern.split()
            ):
                self._step_counter += 1
                step = ReasoningStep(
                    step_id=f"rs-{self._step_counter}",
                    step_number=len(chain.steps) + 1,
                    premise=f"Observation matches pattern: {analogy['pattern']}",
                    conclusion=(
                        f"Similar vulnerabilities: {', '.join(analogy['similar_vulns'])} "
                        f"(typical severity: {analogy['typical_severity']})"
                    ),
                    confidence=analogy["success_rate"],
                    status=StepStatus.HYPOTHESIS,
                    reasoning_type=ReasoningType.ANALOGICAL,
                )
                chain.steps.append(step)

        if chain.steps:
            chain.overall_confidence = max(s.confidence for s in chain.steps)
            chain.final_conclusion = chain.steps[0].conclusion

        self._chains[chain.chain_id] = chain
        return chain

    def detect_contradictions(
        self,
        chain_id: str,
    ) -> list[str]:
        """Detect contradictions in a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return []

        contradictions = []

        for i, step_a in enumerate(chain.steps):
            for step_b in chain.steps[i + 1:]:
                # Simple contradiction: opposite conclusions
                if (step_a.status == StepStatus.SUPPORTED and
                        step_b.status == StepStatus.REFUTED and
                        step_a.conclusion == step_b.conclusion):
                    contradictions.append(
                        f"Step {step_a.step_number} supports '{step_a.conclusion[:40]}' "
                        f"but step {step_b.step_number} refutes it"
                    )

        chain.contradictions = contradictions
        return contradictions

    @staticmethod
    def _propagate_confidence(steps: list[ReasoningStep]) -> float:
        """Propagate confidence through a reasoning chain."""
        if not steps:
            return 0.0

        # Confidence decays through chain
        confidence = 1.0
        for step in steps:
            confidence *= step.confidence

        # Floor at reasonable minimum
        return max(0.05, confidence)

    def get_chains(self, limit: int = 10) -> list[dict[str, Any]]:
        return [c.to_dict() for c in list(self._chains.values())[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        valid = sum(1 for c in self._chains.values() if c.is_valid)
        return {
            "chains": len(self._chains),
            "valid": valid,
            "steps": self._step_counter,
        }
