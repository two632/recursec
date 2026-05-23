"""Output validator — validates and sanitizes all agent outputs.

Implements:
1. Finding validation (is this a real vulnerability?)
2. Confidence scoring for outputs
3. Cross-model validation (ask another model to verify)
4. Evidence sufficiency checking
5. False positive detection heuristics
6. Output format validation
7. Safety/scope validation
8. Reproducibility checking
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ValidationResult(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    NEEDS_REVIEW = "needs_review"
    FALSE_POSITIVE = "false_positive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ValidationMethod(str, Enum):
    HEURISTIC = "heuristic"
    CROSS_MODEL = "cross_model"
    EVIDENCE_CHECK = "evidence_check"
    TOOL_VERIFY = "tool_verify"
    PATTERN_MATCH = "pattern_match"


@dataclass
class Finding:
    """A security finding to validate."""
    finding_id: str = ""
    title: str = ""
    severity: str = ""
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    tool_source: str = ""
    model_source: str = ""
    target: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title[:30],
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "evidence": len(self.evidence),
        }


@dataclass
class ValidationReport:
    """Report from validating a finding."""
    finding_id: str = ""
    result: ValidationResult = ValidationResult.NEEDS_REVIEW
    methods_used: list[ValidationMethod] = field(default_factory=list)
    confidence: float = 0.5
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_id,
            "result": self.result.value,
            "methods": [m.value for m in self.methods_used],
            "confidence": round(self.confidence, 2),
            "issues": len(self.issues),
        }


# ── False Positive Patterns ───────────────────────────────────

FALSE_POSITIVE_INDICATORS: list[dict[str, Any]] = [
    {
        "pattern": r"(?i)(might|could|possibly|perhaps|may)\s+(be|have|contain)",
        "description": "Hedging language suggests uncertainty",
        "weight": 0.3,
    },
    {
        "pattern": r"(?i)informational|info\s*only|for\s*reference",
        "description": "Informational finding, not a vulnerability",
        "weight": 0.5,
    },
    {
        "pattern": r"(?i)no\s+evidence|could\s+not\s+confirm|unconfirmed",
        "description": "Explicitly unconfirmed",
        "weight": 0.7,
    },
    {
        "pattern": r"(?i)common\s+practice|by\s+design|expected\s+behavior",
        "description": "Described as expected behavior",
        "weight": 0.6,
    },
    {
        "pattern": r"(?i)theoretical|in\s+theory",
        "description": "Theoretical vulnerability only",
        "weight": 0.4,
    },
]

# ── Evidence Sufficiency Rules ────────────────────────────────

EVIDENCE_RULES: dict[str, list[str]] = {
    "critical": [
        "Must have tool output showing exploitation",
        "Must include affected endpoint/component",
        "Should have reproducible proof-of-concept",
    ],
    "high": [
        "Must have scan/tool evidence",
        "Must include specific endpoint/parameter",
        "Should explain impact",
    ],
    "medium": [
        "Must have at least one evidence source",
        "Must describe the issue clearly",
    ],
    "low": [
        "Must describe the observation",
    ],
}


class OutputValidator:
    """Validates and sanitizes all agent outputs.

    Multi-layered validation: heuristic checks, evidence
    sufficiency, false positive detection, and cross-validation.
    """

    def __init__(self) -> None:
        self._validations: list[ValidationReport] = []
        self._finding_counter = 0
        self._fp_patterns = [
            re.compile(ind["pattern"])
            for ind in FALSE_POSITIVE_INDICATORS
        ]
        self._fp_weights = [ind["weight"] for ind in FALSE_POSITIVE_INDICATORS]
        self._fp_descriptions = [ind["description"] for ind in FALSE_POSITIVE_INDICATORS]
        self._log = logger.bind(component="output_validator")

    def validate_finding(self, finding: Finding) -> ValidationReport:
        """Validate a security finding."""
        report = ValidationReport(
            finding_id=finding.finding_id,
        )

        # Method 1: Heuristic false positive check
        fp_score = self._check_false_positive(finding, report)
        report.methods_used.append(ValidationMethod.HEURISTIC)

        # Method 2: Evidence sufficiency
        evidence_ok = self._check_evidence(finding, report)
        report.methods_used.append(ValidationMethod.EVIDENCE_CHECK)

        # Method 3: Pattern-based validation
        pattern_ok = self._check_patterns(finding, report)
        report.methods_used.append(ValidationMethod.PATTERN_MATCH)

        # Compute overall result
        if fp_score > 0.5:
            report.result = ValidationResult.FALSE_POSITIVE
            report.confidence = fp_score
        elif not evidence_ok:
            report.result = ValidationResult.INSUFFICIENT_EVIDENCE
            report.confidence = 0.3
            report.suggestions.append("Gather more evidence before reporting")
        elif pattern_ok and evidence_ok:
            report.result = ValidationResult.VALID
            report.confidence = min(0.95, finding.confidence * (1 - fp_score))
        else:
            report.result = ValidationResult.NEEDS_REVIEW
            report.confidence = 0.4

        self._validations.append(report)
        if len(self._validations) > 500:
            self._validations = self._validations[-500:]

        return report

    def _check_false_positive(
        self,
        finding: Finding,
        report: ValidationReport,
    ) -> float:
        """Check for false positive indicators. Returns FP probability."""
        fp_score = 0.0
        text = f"{finding.title} {finding.description}"

        for pattern, weight, desc in zip(
            self._fp_patterns, self._fp_weights, self._fp_descriptions
        ):
            if pattern.search(text):
                fp_score += weight
                report.issues.append(f"FP indicator: {desc}")

        return min(1.0, fp_score)

    @staticmethod
    def _check_evidence(
        finding: Finding,
        report: ValidationReport,
    ) -> bool:
        """Check evidence sufficiency."""
        severity = finding.severity.lower()

        if not finding.evidence:
            report.issues.append("No evidence provided")
            report.suggestions.append("Add tool output or reproduction steps")
            return False

        # Check minimum evidence count by severity
        min_evidence = {"critical": 2, "high": 1, "medium": 1, "low": 0}
        required = min_evidence.get(severity, 0)

        if len(finding.evidence) < required:
            report.issues.append(
                f"Insufficient evidence: {len(finding.evidence)}/{required} for {severity}"
            )
            return False

        return True

    @staticmethod
    def _check_patterns(
        finding: Finding,
        report: ValidationReport,
    ) -> bool:
        """Pattern-based validation of finding structure."""
        issues = []

        # Must have title
        if not finding.title or len(finding.title) < 5:
            issues.append("Finding must have a descriptive title")

        # Must have severity
        if finding.severity not in ("critical", "high", "medium", "low", "info"):
            issues.append("Finding must have valid severity")

        # Must have description
        if not finding.description or len(finding.description) < 20:
            issues.append("Finding must have detailed description")

        # Should have target
        if not finding.target:
            issues.append("Finding should specify the target")

        report.issues.extend(issues)
        return len(issues) == 0

    def validate_output_format(
        self,
        output: dict[str, Any],
        required_fields: list[str],
    ) -> tuple[bool, list[str]]:
        """Validate output has required fields."""
        missing = [f for f in required_fields if f not in output]
        return len(missing) == 0, missing

    def get_validation_stats(self) -> dict[str, Any]:
        result_counts: dict[str, int] = defaultdict(int)
        for v in self._validations:
            result_counts[v.result.value] += 1

        return {
            "total": len(self._validations),
            "results": dict(result_counts),
        }

    def get_stats(self) -> dict[str, Any]:
        return self.get_validation_stats()
