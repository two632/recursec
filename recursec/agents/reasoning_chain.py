"""Reasoning chain — builds explicit chains of reasoning for agent decisions.

Implements:
1. Chain-of-thought tracking (each reasoning step recorded)
2. Multi-step inference with evidence linking
3. Hypothesis generation and testing
4. Abductive reasoning (best explanation for observations)
5. Deductive reasoning (implications from known facts)
6. Analogical reasoning (similar targets had similar vulns)
7. Reasoning confidence propagation
8. Reasoning visualization for debug
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
    DEDUCTIVE = "deductive"        # If A then B; A is true; therefore B
    INDUCTIVE = "inductive"        # Observed pattern suggests general rule
    ABDUCTIVE = "abductive"        # Best explanation for observations
    ANALOGICAL = "analogical"      # Similar to known case
    CAUSAL = "causal"              # A caused B
    TEMPORAL = "temporal"          # A happened before B; A may enable B


class StepType(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    EVIDENCE = "evidence"
    INFERENCE = "inference"
    CONCLUSION = "conclusion"
    COUNTERARGUMENT = "counterargument"
    REVISION = "revision"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNCERTAIN = "uncertain"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    step_type: StepType = StepType.OBSERVATION
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source: str = ""               # Which tool/model produced this
    depends_on: list[str] = field(default_factory=list)  # Previous step IDs
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id,
            "type": self.step_type.value,
            "content": self.content[:60],
            "confidence": round(self.confidence, 2),
            "depends": len(self.depends_on),
        }


@dataclass
class Hypothesis:
    """A hypothesis about a vulnerability or system behavior."""
    hypothesis_id: str = ""
    statement: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    tests_to_verify: list[str] = field(default_factory=list)

    @property
    def evidence_ratio(self) -> float:
        total = len(self.supporting_evidence) + len(self.contradicting_evidence)
        if total == 0:
            return 0.5
        return len(self.supporting_evidence) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "statement": self.statement[:50],
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
            "support": len(self.supporting_evidence),
            "contra": len(self.contradicting_evidence),
        }


@dataclass
class ReasoningChain:
    """A complete chain of reasoning about a topic."""
    chain_id: str = ""
    topic: str = ""
    reasoning_type: ReasoningType = ReasoningType.DEDUCTIVE
    steps: list[ReasoningStep] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    conclusion: str = ""
    overall_confidence: float = 0.0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def is_complete(self) -> bool:
        return bool(self.conclusion)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id,
            "topic": self.topic[:30],
            "type": self.reasoning_type.value,
            "steps": len(self.steps),
            "hypotheses": len(self.hypotheses),
            "confidence": round(self.overall_confidence, 2),
            "complete": self.is_complete,
        }


# ── Reasoning Templates ──────────────────────────────────────

REASONING_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "sqli_investigation": [
        {"type": "observation", "template": "Input field at {location} reflects user input"},
        {"type": "hypothesis", "template": "Input may be injected into SQL query"},
        {"type": "evidence", "template": "Single quote causes error: {error_msg}"},
        {"type": "inference", "template": "Error message reveals {db_type} database"},
        {"type": "evidence", "template": "Union-based payload returned {extra_data}"},
        {"type": "conclusion", "template": "Confirmed SQL injection: {vuln_type} in {param}"},
    ],
    "auth_bypass_investigation": [
        {"type": "observation", "template": "Authentication endpoint at {location}"},
        {"type": "hypothesis", "template": "Auth may have logical flaws"},
        {"type": "evidence", "template": "Response differs for valid vs invalid users: {diff}"},
        {"type": "inference", "template": "User enumeration possible via {indicator}"},
        {"type": "evidence", "template": "Token lacks proper validation: {detail}"},
        {"type": "conclusion", "template": "Auth bypass via {method}: {impact}"},
    ],
    "ssrf_investigation": [
        {"type": "observation", "template": "URL parameter at {location} fetches remote resources"},
        {"type": "hypothesis", "template": "Server-side request forgery may be possible"},
        {"type": "evidence", "template": "Request to {internal_url} returned {response}"},
        {"type": "inference", "template": "Internal service {service} is reachable"},
        {"type": "evidence", "template": "Cloud metadata at {metadata_url} returned {data}"},
        {"type": "conclusion", "template": "SSRF confirmed: access to {scope}"},
    ],
    "rce_investigation": [
        {"type": "observation", "template": "Endpoint {location} processes user input as code/commands"},
        {"type": "hypothesis", "template": "Remote code execution may be possible"},
        {"type": "evidence", "template": "Time-based payload caused {delay}s delay"},
        {"type": "inference", "template": "Command execution confirmed, OS: {os}"},
        {"type": "evidence", "template": "OOB callback received from {target}"},
        {"type": "conclusion", "template": "RCE confirmed via {method}, running as {user}"},
    ],
}

# ── Analogical Reasoning Database ─────────────────────────────

ANALOGY_PATTERNS: list[dict[str, Any]] = [
    {
        "condition": {"tech": "wordpress", "finding": "outdated_plugin"},
        "inference": "WordPress sites with outdated plugins frequently have RCE via plugin vulnerabilities",
        "confidence": 0.7,
    },
    {
        "condition": {"tech": "spring", "finding": "actuator_exposed"},
        "inference": "Exposed Spring Actuator endpoints often lead to RCE via heapdump or env endpoints",
        "confidence": 0.75,
    },
    {
        "condition": {"tech": "nginx", "finding": "misconfig"},
        "inference": "Nginx misconfigs commonly allow path traversal via off-by-slash or alias misuse",
        "confidence": 0.65,
    },
    {
        "condition": {"tech": "graphql", "finding": "introspection"},
        "inference": "GraphQL with introspection enabled usually has authorization issues on mutations",
        "confidence": 0.6,
    },
    {
        "condition": {"tech": "jwt", "finding": "weak_secret"},
        "inference": "JWT with weak secrets often accompanies other auth issues (no expiry, privilege escalation)",
        "confidence": 0.7,
    },
    {
        "condition": {"tech": "docker", "finding": "socket_exposed"},
        "inference": "Exposed Docker socket allows container escape to host with root access",
        "confidence": 0.9,
    },
    {
        "condition": {"tech": "redis", "finding": "unauth"},
        "inference": "Unauthenticated Redis can be leveraged for RCE via Lua scripting or master-slave replication",
        "confidence": 0.85,
    },
    {
        "condition": {"tech": "s3", "finding": "public"},
        "inference": "Public S3 buckets frequently contain credentials, API keys, or customer data",
        "confidence": 0.7,
    },
]


class ReasoningChainEngine:
    """Builds and manages explicit reasoning chains.

    Tracks chain-of-thought reasoning so the agent can
    explain its decisions, test hypotheses, and build
    confidence in findings through multi-step inference.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._chain_counter = 0
        self._step_counter = 0
        self._hypothesis_counter = 0
        self._log = logger.bind(component="reasoning_chain")

    def start_chain(
        self,
        topic: str,
        reasoning_type: ReasoningType = ReasoningType.DEDUCTIVE,
    ) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"chain-{self._chain_counter}",
            topic=topic,
            reasoning_type=reasoning_type,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(
        self,
        chain_id: str,
        step_type: StepType,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        source: str = "",
        depends_on: list[str] | None = None,
    ) -> ReasoningStep | None:
        """Add a step to a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._step_counter += 1
        step = ReasoningStep(
            step_id=f"step-{self._step_counter}",
            step_type=step_type,
            content=content,
            evidence=evidence or [],
            confidence=confidence,
            source=source,
            depends_on=depends_on or [],
        )
        chain.steps.append(step)

        # Update chain confidence (weighted by step type)
        self._update_chain_confidence(chain)

        return step

    def add_hypothesis(
        self,
        chain_id: str,
        statement: str,
        tests_to_verify: list[str] | None = None,
    ) -> Hypothesis | None:
        """Add a hypothesis to a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._hypothesis_counter += 1
        hypothesis = Hypothesis(
            hypothesis_id=f"hyp-{self._hypothesis_counter}",
            statement=statement,
            tests_to_verify=tests_to_verify or [],
        )
        chain.hypotheses.append(hypothesis)
        return hypothesis

    def update_hypothesis(
        self,
        chain_id: str,
        hypothesis_id: str,
        evidence: str,
        supports: bool = True,
    ) -> Hypothesis | None:
        """Update a hypothesis with new evidence."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        for hyp in chain.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                if supports:
                    hyp.supporting_evidence.append(evidence)
                else:
                    hyp.contradicting_evidence.append(evidence)

                # Update status
                ratio = hyp.evidence_ratio
                if ratio >= 0.7:
                    hyp.status = HypothesisStatus.SUPPORTED
                    hyp.confidence = ratio
                elif ratio <= 0.3:
                    hyp.status = HypothesisStatus.REFUTED
                    hyp.confidence = 1 - ratio
                else:
                    hyp.status = HypothesisStatus.UNCERTAIN
                    hyp.confidence = 0.5

                return hyp

        return None

    def conclude(
        self,
        chain_id: str,
        conclusion: str,
    ) -> ReasoningChain | None:
        """Set the conclusion for a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        chain.conclusion = conclusion
        chain.completed_at = time.time()
        self._update_chain_confidence(chain)
        return chain

    def get_analogies(
        self,
        tech: str,
        finding: str,
    ) -> list[dict[str, Any]]:
        """Get analogical reasoning matches."""
        matches = []
        tech_lower = tech.lower()
        finding_lower = finding.lower()

        for pattern in ANALOGY_PATTERNS:
            cond = pattern["condition"]
            if (cond["tech"] in tech_lower and
                    cond["finding"] in finding_lower):
                matches.append({
                    "inference": pattern["inference"],
                    "confidence": pattern["confidence"],
                })

        return matches

    def get_template(self, template_name: str) -> list[dict[str, Any]]:
        """Get a reasoning template."""
        return REASONING_TEMPLATES.get(template_name, [])

    def build_reasoning_prompt(self, chain_id: str) -> str:
        """Build a prompt showing the reasoning chain for LLM continuation."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [
            f"Reasoning chain: {chain.topic}",
            f"Type: {chain.reasoning_type.value}\n",
        ]

        for step in chain.steps:
            prefix = {
                StepType.OBSERVATION: "OBSERVED",
                StepType.HYPOTHESIS: "HYPOTHESIS",
                StepType.EVIDENCE: "EVIDENCE",
                StepType.INFERENCE: "THEREFORE",
                StepType.CONCLUSION: "CONCLUSION",
                StepType.COUNTERARGUMENT: "BUT",
                StepType.REVISION: "REVISED",
            }.get(step.step_type, "STEP")
            lines.append(
                f"[{prefix}] (conf: {step.confidence:.1f}) {step.content}"
            )

        if chain.hypotheses:
            lines.append("\nHypotheses:")
            for hyp in chain.hypotheses:
                lines.append(
                    f"  [{hyp.status.value}] {hyp.statement} "
                    f"(+{len(hyp.supporting_evidence)}/-{len(hyp.contradicting_evidence)})"
                )

        if not chain.conclusion:
            lines.append(
                "\nBased on the above reasoning, what is the logical next step or conclusion?"
            )

        return "\n".join(lines)

    @staticmethod
    def _update_chain_confidence(chain: ReasoningChain) -> None:
        """Update overall chain confidence."""
        if not chain.steps:
            chain.overall_confidence = 0.0
            return

        weights = {
            StepType.EVIDENCE: 1.5,
            StepType.INFERENCE: 1.2,
            StepType.CONCLUSION: 1.0,
            StepType.OBSERVATION: 0.8,
            StepType.HYPOTHESIS: 0.5,
            StepType.COUNTERARGUMENT: -0.5,
            StepType.REVISION: 0.3,
        }

        total_weight = 0.0
        weighted_conf = 0.0
        for step in chain.steps:
            w = weights.get(step.step_type, 0.5)
            if w > 0:
                weighted_conf += step.confidence * w
                total_weight += abs(w)
            else:
                weighted_conf += (1 - step.confidence) * abs(w)
                total_weight += abs(w)

        chain.overall_confidence = weighted_conf / max(0.01, total_weight)

    def get_chain(self, chain_id: str) -> ReasoningChain | None:
        return self._chains.get(chain_id)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for chain in self._chains.values():
            type_counts[chain.reasoning_type.value] += 1
        return {
            "chains": len(self._chains),
            "complete": sum(1 for c in self._chains.values() if c.is_complete),
            "steps": self._step_counter,
            "hypotheses": self._hypothesis_counter,
            "by_type": dict(type_counts),
        }
