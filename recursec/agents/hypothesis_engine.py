"""Hypothesis engine — forms and tests security hypotheses.

Implements a scientific approach to security assessment:
1. Observation: Collect data from tools and analysis
2. Hypothesis: Form testable security hypotheses
3. Prediction: What would we expect if hypothesis is true?
4. Test: Design and run tests to verify
5. Update: Bayesian update of hypothesis confidence
6. Iterate: Form new hypotheses based on results

Key hypothesis categories:
- Vulnerability presence (e.g., "target is vulnerable to SQLi")
- Configuration weakness (e.g., "SSH allows password auth")
- Exposure risk (e.g., "admin panel is publicly accessible")
- Attack path viability (e.g., "can reach DB through web app")
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


class HypothesisCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    ATTACK_PATH = "attack_path"
    DATA_LEAK = "data_leak"
    AUTH_WEAKNESS = "auth_weakness"
    CRYPTO_WEAKNESS = "crypto_weakness"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class TestDesign:
    """A test to verify or refute a hypothesis."""
    test_id: str = ""
    description: str = ""
    tool: str = ""
    command: str = ""
    expected_if_true: str = ""
    expected_if_false: str = ""
    risk_level: float = 0.3
    completed: bool = False
    result: str = ""
    supports_hypothesis: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.test_id, "tool": self.tool,
            "description": self.description[:80],
            "completed": self.completed,
            "supports": self.supports_hypothesis,
        }


@dataclass
class Hypothesis:
    """A testable security hypothesis."""
    hypothesis_id: str = ""
    statement: str = ""
    category: HypothesisCategory = HypothesisCategory.VULNERABILITY
    target: str = ""
    prior_probability: float = 0.5
    current_probability: float = 0.5
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    tests: list[TestDesign] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "statement": self.statement[:100],
            "category": self.category.value,
            "status": self.status.value,
            "probability": round(self.current_probability, 3),
            "tests": len(self.tests),
            "tests_done": sum(1 for t in self.tests if t.completed),
        }


# ── Generation Prompts ───────────────────────────────────────

GENERATE_HYPOTHESES_PROMPT = """You are a security analyst. Based on the observations below,
generate testable security hypotheses.

Target: {target}
Observations:
{observations}

For each hypothesis, specify:
1. A clear testable statement
2. Category (vulnerability, misconfiguration, exposure, attack_path, data_leak, auth_weakness, crypto_weakness)
3. Prior probability (0-1) based on observations
4. Tests to verify/refute it (tool + command)

Respond as JSON:
{{
  "hypotheses": [
    {{
      "statement": "The target is vulnerable to X",
      "category": "vulnerability",
      "prior_probability": 0.X,
      "tests": [
        {{
          "description": "What to test",
          "tool": "tool_name",
          "command": "full command",
          "expected_if_true": "what we'd see",
          "expected_if_false": "what we'd see",
          "risk_level": 0.X
        }}
      ]
    }}
  ]
}}"""

TEST_EVALUATION_PROMPT = """Evaluate whether this test result supports or refutes the hypothesis.

Hypothesis: {hypothesis}
Test: {test_description}
Expected if true: {expected_true}
Expected if false: {expected_false}

Actual result:
{result}

Respond as JSON:
{{
  "supports_hypothesis": true/false/null,
  "confidence": 0.X,
  "reasoning": "why"
}}"""


class HypothesisEngine:
    """Forms and tests security hypotheses.

    Uses a Bayesian approach to update confidence
    in hypotheses based on test results.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hyp_counter = 0
        self._test_counter = 0
        self._log = logger.bind(component="hypothesis_engine")

    async def generate_hypotheses(
        self,
        target: str,
        observations: list[str],
    ) -> list[Hypothesis]:
        """Generate hypotheses from observations."""
        if self._router:
            return await self._llm_generate(target, observations)
        return self._heuristic_generate(target, observations)

    async def evaluate_test(
        self,
        hypothesis_id: str,
        test_id: str,
        result: str,
    ) -> Hypothesis | None:
        """Evaluate a test result and update hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return None

        test = None
        for t in hyp.tests:
            if t.test_id == test_id:
                test = t
                break

        if not test:
            return None

        # Evaluate
        if self._router:
            supports, confidence = await self._llm_evaluate(hyp, test, result)
        else:
            supports, confidence = self._heuristic_evaluate(test, result)

        test.completed = True
        test.result = result[:500]
        test.supports_hypothesis = supports

        # Bayesian update
        if supports is not None:
            hyp.current_probability = self._bayesian_update(
                prior=hyp.current_probability,
                evidence_supports=supports,
                evidence_strength=confidence,
            )

            if supports:
                hyp.supporting_evidence.append(f"Test {test_id}: {result[:100]}")
            else:
                hyp.contradicting_evidence.append(f"Test {test_id}: {result[:100]}")

        # Update status
        hyp.updated_at = time.time()
        all_done = all(t.completed for t in hyp.tests)

        if all_done:
            if hyp.current_probability > 0.7:
                hyp.status = HypothesisStatus.CONFIRMED
            elif hyp.current_probability < 0.3:
                hyp.status = HypothesisStatus.REFUTED
            else:
                hyp.status = HypothesisStatus.INCONCLUSIVE

        return hyp

    def _bayesian_update(
        self,
        prior: float,
        evidence_supports: bool,
        evidence_strength: float,
    ) -> float:
        """Bayesian update of hypothesis probability."""
        # P(H|E) = P(E|H) * P(H) / P(E)
        # Simplified: adjust prior based on evidence

        if evidence_supports:
            # Stronger evidence → bigger update toward 1.0
            likelihood = 0.5 + (evidence_strength * 0.5)
        else:
            # Evidence against → update toward 0.0
            likelihood = 0.5 - (evidence_strength * 0.5)

        # Bayesian update (simplified)
        numerator = likelihood * prior
        denominator = (likelihood * prior) + ((1 - likelihood) * (1 - prior))

        if denominator == 0:
            return prior

        return min(0.99, max(0.01, numerator / denominator))

    def get_pending_tests(self, hypothesis_id: str) -> list[TestDesign]:
        """Get tests that haven't been run yet."""
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return []
        return [t for t in hyp.tests if not t.completed]

    def get_confirmed(self) -> list[Hypothesis]:
        """Get all confirmed hypotheses."""
        return [h for h in self._hypotheses.values() if h.status == HypothesisStatus.CONFIRMED]

    def get_refuted(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.status == HypothesisStatus.REFUTED]

    def get_active(self) -> list[Hypothesis]:
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]

    # ── Internal ─────────────────────────────────────────

    async def _llm_generate(
        self,
        target: str,
        observations: list[str],
    ) -> list[Hypothesis]:
        """Generate hypotheses using LLM."""
        if not self._router:
            return []

        obs_text = "\n".join(f"  - {o[:100]}" for o in observations[:10])

        prompt = GENERATE_HYPOTHESES_PROMPT.format(
            target=target, observations=obs_text,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=1024,
        )

        return self._parse_hypotheses(response, target)

    def _heuristic_generate(
        self,
        target: str,
        observations: list[str],
    ) -> list[Hypothesis]:
        """Generate common hypotheses heuristically."""
        templates = [
            ("The target has open ports with known vulnerabilities",
             HypothesisCategory.VULNERABILITY, 0.6,
             [("Port scan for known vulnerable services", "nmap", f"nmap -sV --script vuln {target}")]),
            ("The web application is vulnerable to injection attacks",
             HypothesisCategory.VULNERABILITY, 0.4,
             [("SQL injection test", "sqlmap", f"sqlmap -u {target} --batch --risk=1")]),
            ("The target has misconfigured security headers",
             HypothesisCategory.MISCONFIGURATION, 0.7,
             [("Check security headers", "curl", f"curl -sI {target}")]),
            ("The target exposes sensitive information",
             HypothesisCategory.DATA_LEAK, 0.3,
             [("Scan for info disclosure", "nuclei", f"nuclei -u {target} -t exposures/")]),
            ("Authentication mechanisms have weaknesses",
             HypothesisCategory.AUTH_WEAKNESS, 0.4,
             [("Check auth endpoints", "nuclei", f"nuclei -u {target} -t default-logins/")]),
        ]

        hypotheses = []
        for statement, category, prior, tests in templates:
            self._hyp_counter += 1
            hyp_id = f"hyp-{self._hyp_counter}"

            test_designs = []
            for desc, tool, cmd in tests:
                self._test_counter += 1
                test_designs.append(TestDesign(
                    test_id=f"test-{self._test_counter}",
                    description=desc,
                    tool=tool,
                    command=cmd,
                ))

            hyp = Hypothesis(
                hypothesis_id=hyp_id,
                statement=statement,
                category=category,
                target=target,
                prior_probability=prior,
                current_probability=prior,
                tests=test_designs,
            )

            hypotheses.append(hyp)
            self._hypotheses[hyp_id] = hyp

        return hypotheses

    async def _llm_evaluate(
        self,
        hyp: Hypothesis,
        test: TestDesign,
        result: str,
    ) -> tuple[bool | None, float]:
        """Use LLM to evaluate test result."""
        if not self._router:
            return None, 0.5

        prompt = TEST_EVALUATION_PROMPT.format(
            hypothesis=hyp.statement[:200],
            test_description=test.description[:200],
            expected_true=test.expected_if_true[:200],
            expected_false=test.expected_if_false[:200],
            result=result[:500],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=256,
        )

        import json
        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            data = json.loads(response.strip())
            supports = data.get("supports_hypothesis")
            confidence = data.get("confidence", 0.5)
            return supports, confidence
        except (json.JSONDecodeError, IndexError):
            return None, 0.5

    def _heuristic_evaluate(
        self,
        test: TestDesign,
        result: str,
    ) -> tuple[bool | None, float]:
        """Heuristic test evaluation."""
        result_lower = result.lower()

        positive_signals = [
            "vulnerable", "found", "detected", "critical", "high",
            "warning", "exploit", "injection", "bypass",
        ]
        negative_signals = [
            "not vulnerable", "no results", "clean", "secure",
            "timeout", "refused", "denied",
        ]

        positive_count = sum(1 for s in positive_signals if s in result_lower)
        negative_count = sum(1 for s in negative_signals if s in result_lower)

        if positive_count > negative_count:
            return True, min(0.8, 0.4 + positive_count * 0.1)
        elif negative_count > positive_count:
            return False, min(0.8, 0.4 + negative_count * 0.1)

        return None, 0.3

    def _parse_hypotheses(
        self,
        response: str,
        target: str,
    ) -> list[Hypothesis]:
        """Parse LLM hypothesis response."""
        import json

        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            data = json.loads(response.strip())
        except (json.JSONDecodeError, IndexError):
            return []

        hypotheses = []
        for h_data in data.get("hypotheses", [])[:10]:
            self._hyp_counter += 1
            hyp_id = f"hyp-{self._hyp_counter}"

            cat_str = h_data.get("category", "vulnerability")
            try:
                category = HypothesisCategory(cat_str)
            except ValueError:
                category = HypothesisCategory.VULNERABILITY

            tests = []
            for t_data in h_data.get("tests", [])[:5]:
                self._test_counter += 1
                tests.append(TestDesign(
                    test_id=f"test-{self._test_counter}",
                    description=t_data.get("description", ""),
                    tool=t_data.get("tool", ""),
                    command=t_data.get("command", ""),
                    expected_if_true=t_data.get("expected_if_true", ""),
                    expected_if_false=t_data.get("expected_if_false", ""),
                    risk_level=t_data.get("risk_level", 0.3),
                ))

            prior = h_data.get("prior_probability", 0.5)
            hyp = Hypothesis(
                hypothesis_id=hyp_id,
                statement=h_data.get("statement", ""),
                category=category,
                target=target,
                prior_probability=prior,
                current_probability=prior,
                tests=tests,
            )

            hypotheses.append(hyp)
            self._hypotheses[hyp_id] = hyp

        return hypotheses

    def get_stats(self) -> dict[str, Any]:
        return {
            "hypotheses": len(self._hypotheses),
            "confirmed": len(self.get_confirmed()),
            "refuted": len(self.get_refuted()),
            "active": len(self.get_active()),
        }
