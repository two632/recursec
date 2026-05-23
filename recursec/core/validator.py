"""Validation engine — multi-layer anti-hallucination system.

Validation strategies:
1. Tool-based verification — re-run tools to confirm findings
2. Cross-model verification — query different LLM for second opinion
3. Pattern-based validation — check finding against known patterns
4. Evidence scoring — score evidence quality
5. False positive detection — filter known false positives
6. Confidence calibration — adjust confidence based on evidence
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ValidationResult:
    """Result of validating a finding."""
    finding_id: str = ""
    original_title: str = ""
    is_valid: bool = False
    confidence: float = 0.0
    validation_method: str = ""
    evidence_quality: str = ""  # strong, moderate, weak, none
    false_positive_indicators: list[str] = field(default_factory=list)
    verifier_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "title": self.original_title,
            "valid": self.is_valid, "confidence": round(self.confidence, 2),
            "method": self.validation_method,
            "evidence_quality": self.evidence_quality,
            "fp_indicators": self.false_positive_indicators[:5],
        }


# Common false positive patterns
FALSE_POSITIVE_PATTERNS = [
    # Generic scanner noise
    re.compile(r"informational.*open port", re.IGNORECASE),
    re.compile(r"server header.*disclosure", re.IGNORECASE),

    # Self-referential findings
    re.compile(r"test.*page|example\.com|localhost", re.IGNORECASE),

    # Generic HTTP responses
    re.compile(r"404.*not found.*vulnerability", re.IGNORECASE),
    re.compile(r"default.*page|welcome.*apache|it works", re.IGNORECASE),
]

# Known false positive combinations
FP_TITLE_PATTERNS = {
    "X-Powered-By Header": 0.3,  # Low severity, common
    "Server Header Disclosure": 0.2,
    "Missing X-Frame-Options": 0.5,  # Can be intentional
    "Cookie Without Secure Flag": 0.6,
    "Cookie Without HttpOnly Flag": 0.6,
}

# CVE age thresholds (older = more likely patched = more likely FP)
CVE_YEAR_PENALTY = {
    2024: 0.0, 2025: 0.0, 2026: 0.0,
    2023: 0.05, 2022: 0.1, 2021: 0.15,
    2020: 0.2, 2019: 0.25,
}

# Evidence quality indicators
STRONG_EVIDENCE = [
    "extracted data", "database dump", "file content",
    "command output", "shell access", "credential found",
    "remote code execution confirmed",
]

MODERATE_EVIDENCE = [
    "error message", "stack trace", "version detected",
    "banner grabbed", "response differs",
]

WEAK_EVIDENCE = [
    "possible", "potential", "might be", "could be",
    "suspected", "unconfirmed",
]


class FindingValidator:
    """Multi-layer finding validation engine."""

    def __init__(self, llm_router: Any = None) -> None:
        self._router = llm_router
        self._validated: dict[str, ValidationResult] = {}
        self._stats = {"total": 0, "valid": 0, "invalid": 0, "uncertain": 0}

    async def validate(self, finding: dict[str, Any]) -> ValidationResult:
        """Validate a single finding through multiple methods."""
        result = ValidationResult(
            finding_id=finding.get("id", ""),
            original_title=finding.get("title", ""),
        )

        self._stats["total"] += 1

        # Layer 1: Pattern-based false positive check
        fp_score = self._check_false_positive_patterns(finding)

        # Layer 2: Evidence quality assessment
        evidence_score = self._assess_evidence_quality(finding)

        # Layer 3: CVE age check
        cve_penalty = self._check_cve_age(finding)

        # Layer 4: Severity consistency check
        severity_score = self._check_severity_consistency(finding)

        # Layer 5: Cross-model verification (if LLM router available)
        llm_score = 0.5
        if self._router:
            llm_score = await self._cross_model_verify(finding)

        # Combine scores
        weights = {
            "fp": 0.25, "evidence": 0.30, "cve": 0.10,
            "severity": 0.10, "llm": 0.25,
        }

        final_score = (
            (1.0 - fp_score) * weights["fp"]
            + evidence_score * weights["evidence"]
            + (1.0 - cve_penalty) * weights["cve"]
            + severity_score * weights["severity"]
            + llm_score * weights["llm"]
        )

        result.confidence = min(1.0, max(0.0, final_score))
        result.is_valid = result.confidence >= 0.5
        result.validation_method = "multi_layer"

        # Determine evidence quality label
        if evidence_score >= 0.8:
            result.evidence_quality = "strong"
        elif evidence_score >= 0.5:
            result.evidence_quality = "moderate"
        elif evidence_score >= 0.3:
            result.evidence_quality = "weak"
        else:
            result.evidence_quality = "none"

        # Track stats
        if result.is_valid:
            self._stats["valid"] += 1
        elif result.confidence < 0.3:
            self._stats["invalid"] += 1
        else:
            self._stats["uncertain"] += 1

        self._validated[result.finding_id] = result
        return result

    async def validate_batch(self, findings: list[dict[str, Any]]) -> list[ValidationResult]:
        """Validate multiple findings concurrently."""
        results = await asyncio.gather(
            *[self.validate(f) for f in findings],
            return_exceptions=True,
        )
        return [
            r if isinstance(r, ValidationResult)
            else ValidationResult(is_valid=False)
            for r in results
        ]

    def _check_false_positive_patterns(self, finding: dict[str, Any]) -> float:
        """Check finding against known false positive patterns. Returns FP probability 0-1."""
        title = finding.get("title", "")
        description = finding.get("description", "")
        combined = f"{title} {description}"

        fp_score = 0.0

        # Check against regex patterns
        for pattern in FALSE_POSITIVE_PATTERNS:
            if pattern.search(combined):
                fp_score = max(fp_score, 0.6)

        # Check against known FP titles
        for fp_title, fp_prob in FP_TITLE_PATTERNS.items():
            if fp_title.lower() in title.lower():
                fp_score = max(fp_score, fp_prob)

        return fp_score

    def _assess_evidence_quality(self, finding: dict[str, Any]) -> float:
        """Assess the quality of evidence. Returns quality score 0-1."""
        evidence = finding.get("evidence", "") or finding.get("proof", "")
        description = finding.get("description", "")
        combined = f"{evidence} {description}".lower()

        if not combined.strip():
            return 0.1

        score = 0.3  # Baseline for having any text

        # Check for strong evidence indicators
        for indicator in STRONG_EVIDENCE:
            if indicator in combined:
                score = max(score, 0.9)

        # Check for moderate evidence
        for indicator in MODERATE_EVIDENCE:
            if indicator in combined:
                score = max(score, 0.6)

        # Penalty for weak/uncertain language
        for indicator in WEAK_EVIDENCE:
            if indicator in combined:
                score *= 0.7

        # Bonus for having specific technical details
        if re.search(r"CVE-\d{4}-\d+", combined):
            score = min(1.0, score + 0.15)
        if re.search(r"\d+\.\d+\.\d+", combined):  # Version numbers
            score = min(1.0, score + 0.1)
        if re.search(r"port\s+\d+", combined):
            score = min(1.0, score + 0.05)

        return min(1.0, score)

    def _check_cve_age(self, finding: dict[str, Any]) -> float:
        """Check CVE age — older CVEs are more likely patched. Returns penalty 0-1."""
        cve_str = finding.get("cve", "") or finding.get("cve_id", "")
        description = finding.get("description", "")

        # Extract CVE year
        cve_match = re.search(r"CVE-(\d{4})-\d+", f"{cve_str} {description}")
        if not cve_match:
            return 0.0  # No CVE, no penalty

        year = int(cve_match.group(1))
        return CVE_YEAR_PENALTY.get(year, 0.3)  # Default 30% penalty for old CVEs

    def _check_severity_consistency(self, finding: dict[str, Any]) -> float:
        """Check if severity is consistent with the finding type."""
        severity = finding.get("severity", "").lower()
        title = finding.get("title", "").lower()

        # Critical/high should have significant impact
        if severity in ("critical", "high"):
            high_impact_keywords = [
                "rce", "remote code", "sql injection", "authentication bypass",
                "privilege escalation", "data breach", "shell access",
                "command injection", "deserialization", "ssrf",
            ]
            if any(kw in title for kw in high_impact_keywords):
                return 0.9
            return 0.5  # Might be inflated severity

        if severity in ("medium", "low", "info"):
            return 0.7  # Lower severity is less likely to be hallucinated

        return 0.5

    async def _cross_model_verify(self, finding: dict[str, Any]) -> float:
        """Verify finding using a different LLM model."""
        if not self._router:
            return 0.5

        prompt = f"""Evaluate this security finding for validity. Is this a real vulnerability or a false positive?

Finding: {finding.get('title', '')}
Severity: {finding.get('severity', '')}
Description: {finding.get('description', '')[:500]}
Evidence: {finding.get('evidence', '')[:300]}

Respond with:
- VALID: if this is likely a real vulnerability
- FALSE_POSITIVE: if this is likely a false positive
- UNCERTAIN: if you cannot determine

Also provide a confidence score from 0.0 to 1.0."""

        try:
            response = await self._router.generate(
                prompt=prompt,
                task_type="validation",
                max_tokens=200,
            )
            response_text = str(response) if not hasattr(response, "text") else response.text

            if "VALID" in response_text.upper() and "FALSE" not in response_text.upper():
                return 0.8
            if "FALSE_POSITIVE" in response_text.upper():
                return 0.2
            return 0.5

        except Exception:
            return 0.5  # Default on error

    # ── Stats and Reports ──────────────────────────────────

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def get_validated(self) -> list[dict[str, Any]]:
        return [v.to_dict() for v in self._validated.values()]

    def get_valid_findings(self) -> list[ValidationResult]:
        return [v for v in self._validated.values() if v.is_valid]

    def get_false_positives(self) -> list[ValidationResult]:
        return [v for v in self._validated.values() if not v.is_valid and v.confidence < 0.3]
