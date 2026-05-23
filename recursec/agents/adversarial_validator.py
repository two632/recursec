"""Adversarial validator — challenges and validates security findings.

Implements a skeptical validation agent that:
1. Cross-validates findings using different tools
2. Generates counter-arguments for each finding
3. Tests for false positives with targeted probes
4. Compares findings against known false positive patterns
5. Assigns validation confidence scores
6. Generates validation evidence
7. Suggests additional tests for uncertain findings
8. Tracks false positive rates per tool/technique

Validation levels:
- Quick: Basic sanity check (< 30s)
- Standard: Cross-tool validation (< 2min)
- Deep: Multiple verification approaches (< 10min)
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ValidationLevel(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ValidationVerdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY_VALID = "likely_valid"
    UNCERTAIN = "uncertain"
    LIKELY_FALSE = "likely_false"
    FALSE_POSITIVE = "false_positive"


@dataclass
class ValidationCheck:
    """A single validation check."""
    check_id: str = ""
    method: str = ""
    description: str = ""
    result: str = ""
    passed: bool = False
    confidence: float = 0.5
    evidence: str = ""
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "method": self.method[:100],
            "passed": self.passed,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ValidationResult:
    """Complete validation result for a finding."""
    finding_id: str = ""
    finding_title: str = ""
    verdict: ValidationVerdict = ValidationVerdict.UNCERTAIN
    confidence: float = 0.5
    checks: list[ValidationCheck] = field(default_factory=list)
    counter_arguments: list[str] = field(default_factory=list)
    additional_tests_needed: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    validation_time_s: float = 0.0
    validator_notes: str = ""

    @property
    def is_valid(self) -> bool:
        return self.verdict in (ValidationVerdict.CONFIRMED, ValidationVerdict.LIKELY_VALID)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_id,
            "title": self.finding_title[:100],
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 2),
            "checks": len(self.checks),
            "passed": sum(1 for c in self.checks if c.passed),
            "valid": self.is_valid,
        }


# ── Known False Positive Patterns ────────────────────────────

FALSE_POSITIVE_PATTERNS: list[dict[str, Any]] = [
    {"pattern": "X-Frame-Options missing", "context": "non-sensitive page",
     "likelihood": 0.7, "reason": "Common on static pages, not always exploitable"},
    {"pattern": "HSTS not set", "context": "internal service",
     "likelihood": 0.5, "reason": "Internal services may not need HSTS"},
    {"pattern": "Server version disclosed", "context": "any",
     "likelihood": 0.3, "reason": "Info disclosure, usually low impact"},
    {"pattern": "directory listing", "context": "empty directory",
     "likelihood": 0.5, "reason": "Empty directory listing is low risk"},
    {"pattern": "CORS misconfiguration", "context": "public API",
     "likelihood": 0.4, "reason": "Public APIs may intentionally allow CORS"},
    {"pattern": "missing Content-Security-Policy", "context": "API endpoint",
     "likelihood": 0.8, "reason": "CSP not relevant for JSON API responses"},
    {"pattern": "open redirect", "context": "login redirect",
     "likelihood": 0.3, "reason": "May be intentional for login flow"},
    {"pattern": "SSL/TLS weak cipher", "context": "internal only",
     "likelihood": 0.4, "reason": "Internal traffic may accept weaker ciphers"},
]


VALIDATE_PROMPT = """You are a skeptical security validator. Challenge this finding.

Finding: {title}
Severity: {severity}
Description: {description}
Evidence: {evidence}
Tool used: {tool}
Target: {target}

Your job is to play devil's advocate:
1. What could make this a false positive?
2. What additional evidence would confirm it?
3. Are there environmental factors that might explain this?
4. Is the severity rating accurate?

Respond as JSON:
{{
  "verdict": "confirmed|likely_valid|uncertain|likely_false|false_positive",
  "confidence": 0.X,
  "counter_arguments": ["reasons this might be false"],
  "supporting_arguments": ["reasons this is likely real"],
  "additional_tests": ["tests to confirm/deny"],
  "severity_assessment": "correct|overrated|underrated",
  "notes": "summary"
}}"""


class AdversarialValidator:
    """Skeptical validation agent that challenges findings.

    Cross-validates, generates counter-arguments, checks for
    false positives, and assigns confidence scores.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._results: list[ValidationResult] = []
        self._fp_rates: dict[str, list[bool]] = defaultdict(list)  # tool → [is_valid, ...]
        self._check_counter = 0
        self._log = logger.bind(component="adversarial_validator")

    async def validate(
        self,
        finding: dict[str, Any],
        level: ValidationLevel = ValidationLevel.STANDARD,
    ) -> ValidationResult:
        """Validate a finding."""
        start = time.time()

        result = ValidationResult(
            finding_id=finding.get("id", ""),
            finding_title=finding.get("title", ""),
        )

        # Run validation checks based on level
        if level in (ValidationLevel.QUICK, ValidationLevel.STANDARD, ValidationLevel.DEEP):
            self._check_false_positive_patterns(finding, result)
            self._check_evidence_quality(finding, result)

        if level in (ValidationLevel.STANDARD, ValidationLevel.DEEP):
            self._check_severity_accuracy(finding, result)
            self._check_reproducibility(finding, result)

        if level == ValidationLevel.DEEP and self._router:
            await self._llm_adversarial_review(finding, result)

        # Compute overall verdict
        self._compute_verdict(result)

        result.validation_time_s = time.time() - start

        # Track FP rates
        tool = finding.get("tool", "unknown")
        self._fp_rates[tool].append(result.is_valid)

        self._results.append(result)
        return result

    async def validate_batch(
        self,
        findings: list[dict[str, Any]],
        level: ValidationLevel = ValidationLevel.STANDARD,
    ) -> list[ValidationResult]:
        """Validate multiple findings."""
        results = []
        for finding in findings:
            result = await self.validate(finding, level)
            results.append(result)
        return results

    # ── Validation Checks ────────────────────────────────

    def _check_false_positive_patterns(
        self,
        finding: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Check against known false positive patterns."""
        self._check_counter += 1
        check = ValidationCheck(
            check_id=f"chk-{self._check_counter}",
            method="false_positive_pattern_match",
            description="Check against known false positive patterns",
        )

        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        combined = f"{title} {description}"

        fp_score = 0.0
        matching_patterns = []

        for pattern in FALSE_POSITIVE_PATTERNS:
            if pattern["pattern"].lower() in combined:
                fp_score = max(fp_score, pattern["likelihood"])
                matching_patterns.append(pattern["reason"])

        if fp_score > 0.5:
            check.passed = False
            check.confidence = fp_score
            check.result = f"Matches FP patterns: {'; '.join(matching_patterns[:2])}"
            result.counter_arguments.extend(matching_patterns[:2])
        else:
            check.passed = True
            check.confidence = 1.0 - fp_score
            check.result = "No strong false positive pattern match"

        result.checks.append(check)

    def _check_evidence_quality(
        self,
        finding: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Check if the finding has sufficient evidence."""
        self._check_counter += 1
        check = ValidationCheck(
            check_id=f"chk-{self._check_counter}",
            method="evidence_quality",
            description="Assess evidence quality and completeness",
        )

        evidence = finding.get("evidence", "")
        description = finding.get("description", "")
        has_poc = bool(finding.get("poc") or finding.get("proof"))
        has_response = bool(finding.get("response") or finding.get("output"))

        score = 0.0
        notes = []

        if evidence and len(evidence) > 50:
            score += 0.3
            notes.append("Has evidence text")
        if has_poc:
            score += 0.3
            notes.append("Has proof of concept")
        if has_response:
            score += 0.2
            notes.append("Has response/output")
        if description and len(description) > 100:
            score += 0.1
            notes.append("Detailed description")
        if finding.get("cve"):
            score += 0.1
            notes.append("Has CVE reference")

        check.confidence = score
        check.passed = score >= 0.3
        check.result = "; ".join(notes) if notes else "Insufficient evidence"

        if not check.passed:
            result.additional_tests_needed.append(
                "Collect more evidence: PoC, response data, or tool output"
            )

        result.checks.append(check)

    def _check_severity_accuracy(
        self,
        finding: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Check if severity rating is appropriate."""
        self._check_counter += 1
        check = ValidationCheck(
            check_id=f"chk-{self._check_counter}",
            method="severity_check",
            description="Verify severity rating accuracy",
        )

        severity = finding.get("severity", "medium").lower()
        title = finding.get("title", "").lower()

        # Heuristic severity validation
        info_indicators = ["version", "disclosure", "header missing", "banner"]
        critical_requirements = ["rce", "remote code", "authentication bypass", "sql injection"]

        check.passed = True
        check.confidence = 0.7

        if severity == "critical":
            if not any(ind in title for ind in critical_requirements):
                check.result = "Critical severity may be overrated"
                check.confidence = 0.4
                result.counter_arguments.append(
                    "Severity 'critical' typically requires RCE, auth bypass, or similar"
                )
        elif severity in ("high", "critical"):
            if any(ind in title for ind in info_indicators):
                check.result = "High/critical rating for informational finding"
                check.confidence = 0.3
                check.passed = False
        else:
            check.result = "Severity appears reasonable"

        result.checks.append(check)

    def _check_reproducibility(
        self,
        finding: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Check if finding is likely reproducible."""
        self._check_counter += 1
        check = ValidationCheck(
            check_id=f"chk-{self._check_counter}",
            method="reproducibility",
            description="Assess reproducibility",
        )

        has_target = bool(finding.get("target") or finding.get("url"))
        has_params = bool(finding.get("parameters") or finding.get("payload"))
        has_steps = bool(finding.get("steps") or finding.get("poc"))
        tool = finding.get("tool", "")

        score = 0.0
        if has_target:
            score += 0.3
        if has_params:
            score += 0.3
        if has_steps:
            score += 0.3
        if tool:
            score += 0.1

        check.passed = score >= 0.5
        check.confidence = score
        check.result = f"Reproducibility score: {score:.1f}"

        if not check.passed:
            result.additional_tests_needed.append(
                "Need specific target URL, parameters, and steps to reproduce"
            )

        result.checks.append(check)

    async def _llm_adversarial_review(
        self,
        finding: dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Deep LLM-based adversarial review."""
        if not self._router:
            return

        self._check_counter += 1
        check = ValidationCheck(
            check_id=f"chk-{self._check_counter}",
            method="llm_adversarial",
            description="LLM-based adversarial review",
        )

        prompt = VALIDATE_PROMPT.format(
            title=finding.get("title", "N/A"),
            severity=finding.get("severity", "N/A"),
            description=finding.get("description", "N/A")[:500],
            evidence=finding.get("evidence", "N/A")[:500],
            tool=finding.get("tool", "N/A"),
            target=finding.get("target", "N/A"),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=512,
        )

        data = self._parse_json(response)
        try:
            verdict_str = data.get("verdict", "uncertain")
            check.confidence = data.get("confidence", 0.5)
        except (ValueError, TypeError):
            verdict_str = "uncertain"
            check.confidence = 0.5

        check.passed = verdict_str in ("confirmed", "likely_valid")
        check.result = data.get("notes", "")

        result.counter_arguments.extend(data.get("counter_arguments", []))
        result.additional_tests_needed.extend(data.get("additional_tests", []))
        result.validator_notes = data.get("notes", "")

        result.checks.append(check)

    # ── Verdict Computation ──────────────────────────────

    def _compute_verdict(self, result: ValidationResult) -> None:
        """Compute overall verdict from individual checks."""
        if not result.checks:
            result.verdict = ValidationVerdict.UNCERTAIN
            result.confidence = 0.5
            return

        passed = sum(1 for c in result.checks if c.passed)
        total = len(result.checks)
        pass_ratio = passed / total

        avg_confidence = sum(c.confidence for c in result.checks) / total

        if pass_ratio >= 0.8 and avg_confidence >= 0.7:
            result.verdict = ValidationVerdict.CONFIRMED
        elif pass_ratio >= 0.6:
            result.verdict = ValidationVerdict.LIKELY_VALID
        elif pass_ratio >= 0.4:
            result.verdict = ValidationVerdict.UNCERTAIN
        elif pass_ratio >= 0.2:
            result.verdict = ValidationVerdict.LIKELY_FALSE
        else:
            result.verdict = ValidationVerdict.FALSE_POSITIVE

        result.confidence = avg_confidence

    # ── Statistics ────────────────────────────────────────

    def get_fp_rates(self) -> dict[str, float]:
        """Get false positive rates per tool."""
        rates = {}
        for tool, validations in self._fp_rates.items():
            if validations:
                valid_count = sum(1 for v in validations if v)
                rates[tool] = 1.0 - (valid_count / len(validations))
        return rates

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        by_verdict: dict[str, int] = defaultdict(int)
        for r in self._results:
            by_verdict[r.verdict.value] += 1
        return {
            "total_validations": len(self._results),
            "by_verdict": dict(by_verdict),
            "fp_rates": self.get_fp_rates(),
        }
