"""Finding correlator — links related findings and identifies patterns.

Analyzes findings to:
1. Deduplicate similar findings
2. Correlate related findings (same root cause)
3. Identify vulnerability chains
4. Detect patterns across targets/services
5. Group by impact and remediation
6. Calculate aggregate risk scores
7. Prioritize based on exploitability
8. Generate correlation reports
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


@dataclass
class CorrelationGroup:
    """A group of correlated findings."""
    group_id: str = ""
    title: str = ""
    root_cause: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    aggregate_severity: str = "medium"
    aggregate_risk: float = 0.5
    affected_targets: list[str] = field(default_factory=list)
    remediation: str = ""
    chain_description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.group_id,
            "title": self.title[:100],
            "root_cause": self.root_cause[:100],
            "findings_count": len(self.findings),
            "severity": self.aggregate_severity,
            "risk": round(self.aggregate_risk, 2),
            "targets": self.affected_targets[:5],
        }


@dataclass
class DeduplicationResult:
    """Result of finding deduplication."""
    original_count: int = 0
    deduplicated_count: int = 0
    duplicates_removed: int = 0
    unique_findings: list[dict[str, Any]] = field(default_factory=list)
    duplicate_groups: list[list[dict[str, Any]]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original_count,
            "unique": self.deduplicated_count,
            "removed": self.duplicates_removed,
        }


@dataclass
class RiskAssessment:
    """Aggregate risk assessment."""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    overall_risk: float = 0.0
    risk_level: str = "medium"
    top_risks: list[str] = field(default_factory=list)
    most_affected_targets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total_findings,
            "critical": self.critical, "high": self.high,
            "medium": self.medium, "low": self.low, "info": self.info,
            "overall_risk": round(self.overall_risk, 2),
            "risk_level": self.risk_level,
        }


SEVERITY_SCORES = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}

CORRELATE_PROMPT = """Analyze these security findings for correlations and patterns.

Findings:
{findings_text}

Identify:
1. Which findings are likely caused by the same root cause?
2. Which findings can be chained together for greater impact?
3. What are the top-priority remediation items?

Respond as JSON:
{{
  "groups": [
    {{
      "title": "group name",
      "root_cause": "underlying cause",
      "finding_indices": [0, 1, 2],
      "severity": "critical|high|medium|low",
      "chain": "how findings chain together",
      "remediation": "how to fix"
    }}
  ],
  "top_risks": ["highest priority items"],
  "patterns": ["observed patterns"]
}}"""


class FindingCorrelator:
    """Correlates, deduplicates, and analyzes security findings.

    Links related findings, identifies root causes,
    and generates aggregate risk assessments.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._groups: list[CorrelationGroup] = []
        self._group_counter = 0
        self._log = logger.bind(component="finding_correlator")

    def deduplicate(self, findings: list[dict[str, Any]]) -> DeduplicationResult:
        """Remove duplicate findings."""
        result = DeduplicationResult(original_count=len(findings))

        seen: dict[str, dict[str, Any]] = {}
        duplicates: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            key = self._finding_key(finding)
            if key in seen:
                duplicates[key].append(finding)
            else:
                seen[key] = finding

        result.unique_findings = list(seen.values())
        result.deduplicated_count = len(result.unique_findings)
        result.duplicates_removed = result.original_count - result.deduplicated_count
        result.duplicate_groups = [
            [seen[k]] + dups for k, dups in duplicates.items()
        ]

        self._log.info(
            "deduplicated",
            original=result.original_count,
            unique=result.deduplicated_count,
        )

        return result

    async def correlate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[CorrelationGroup]:
        """Correlate related findings into groups."""
        # First deduplicate
        dedup = self.deduplicate(findings)
        unique = dedup.unique_findings

        # Heuristic correlation
        groups = self._heuristic_correlate(unique)

        # LLM-enhanced correlation
        if self._router and len(unique) > 1:
            llm_groups = await self._llm_correlate(unique)
            groups = self._merge_groups(groups, llm_groups)

        self._groups.extend(groups)
        return groups

    def assess_risk(self, findings: list[dict[str, Any]]) -> RiskAssessment:
        """Calculate aggregate risk assessment."""
        assessment = RiskAssessment(total_findings=len(findings))

        severity_counts: dict[str, int] = defaultdict(int)
        target_counts: dict[str, int] = defaultdict(int)

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            severity_counts[severity] += 1

            target = finding.get("target", "unknown")
            target_counts[target] += 1

        assessment.critical = severity_counts.get("critical", 0)
        assessment.high = severity_counts.get("high", 0)
        assessment.medium = severity_counts.get("medium", 0)
        assessment.low = severity_counts.get("low", 0)
        assessment.info = severity_counts.get("info", 0)

        # Calculate overall risk
        if findings:
            total_score = sum(
                SEVERITY_SCORES.get(f.get("severity", "medium").lower(), 0.5)
                for f in findings
            )
            assessment.overall_risk = min(1.0, total_score / max(1, len(findings)) + assessment.critical * 0.1)
        else:
            assessment.overall_risk = 0.0

        # Determine risk level
        if assessment.critical > 0 or assessment.overall_risk > 0.8:
            assessment.risk_level = "critical"
        elif assessment.high > 2 or assessment.overall_risk > 0.6:
            assessment.risk_level = "high"
        elif assessment.medium > 5 or assessment.overall_risk > 0.4:
            assessment.risk_level = "medium"
        else:
            assessment.risk_level = "low"

        # Top affected targets
        assessment.most_affected_targets = sorted(
            target_counts.keys(), key=lambda t: -target_counts[t],
        )[:5]

        return assessment

    # ── Heuristic Correlation ────────────────────────────

    def _heuristic_correlate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[CorrelationGroup]:
        """Group findings by heuristic rules."""
        groups: list[CorrelationGroup] = []

        # Group by same target + same vulnerability type
        by_target_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            target = finding.get("target", "unknown")
            vuln_type = self._classify_vuln(finding)
            key = f"{target}:{vuln_type}"
            by_target_type[key].append(finding)

        for key, group_findings in by_target_type.items():
            if len(group_findings) < 2:
                continue

            self._group_counter += 1
            target, vuln_type = key.split(":", 1)

            # Aggregate severity
            severities = [f.get("severity", "medium").lower() for f in group_findings]
            if "critical" in severities:
                agg_sev = "critical"
            elif "high" in severities:
                agg_sev = "high"
            elif "medium" in severities:
                agg_sev = "medium"
            else:
                agg_sev = "low"

            groups.append(CorrelationGroup(
                group_id=f"corr-{self._group_counter}",
                title=f"Multiple {vuln_type} findings on {target}",
                root_cause=f"Likely related {vuln_type} issues",
                findings=group_findings,
                aggregate_severity=agg_sev,
                aggregate_risk=max(
                    SEVERITY_SCORES.get(s, 0.5) for s in severities
                ),
                affected_targets=[target],
            ))

        return groups

    async def _llm_correlate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[CorrelationGroup]:
        """LLM-enhanced correlation."""
        if not self._router:
            return []

        findings_text = "\n".join(
            f"[{i}] [{f.get('severity', 'N/A')}] {f.get('title', 'N/A')} "
            f"(target: {f.get('target', 'N/A')}, tool: {f.get('tool', 'N/A')})"
            for i, f in enumerate(findings[:20])
        )

        prompt = CORRELATE_PROMPT.format(findings_text=findings_text)

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        groups = []

        for g_data in data.get("groups", []):
            self._group_counter += 1
            indices = g_data.get("finding_indices", [])
            group_findings = [
                findings[i] for i in indices
                if isinstance(i, int) and 0 <= i < len(findings)
            ]

            groups.append(CorrelationGroup(
                group_id=f"corr-{self._group_counter}",
                title=g_data.get("title", ""),
                root_cause=g_data.get("root_cause", ""),
                findings=group_findings,
                aggregate_severity=g_data.get("severity", "medium"),
                chain_description=g_data.get("chain", ""),
                remediation=g_data.get("remediation", ""),
            ))

        return groups

    def _merge_groups(
        self,
        groups1: list[CorrelationGroup],
        groups2: list[CorrelationGroup],
    ) -> list[CorrelationGroup]:
        """Merge two sets of correlation groups."""
        # Simple merge: keep all groups, dedup by finding overlap
        merged = list(groups1)
        existing_findings = set()
        for g in groups1:
            for f in g.findings:
                existing_findings.add(self._finding_key(f))

        for g in groups2:
            new_findings = [
                f for f in g.findings
                if self._finding_key(f) not in existing_findings
            ]
            if new_findings or not existing_findings:
                merged.append(g)

        return merged

    def _finding_key(self, finding: dict[str, Any]) -> str:
        """Generate a dedup key for a finding."""
        parts = [
            finding.get("title", ""),
            finding.get("target", ""),
            finding.get("severity", ""),
            finding.get("type", ""),
        ]
        return "|".join(str(p).lower().strip() for p in parts)

    def _classify_vuln(self, finding: dict[str, Any]) -> str:
        """Classify a finding into a vulnerability type."""
        title = finding.get("title", "").lower()
        vuln_type = finding.get("type", "").lower()
        combined = f"{title} {vuln_type}"

        classifications = [
            ("xss", ["xss", "cross-site scripting", "script injection"]),
            ("sqli", ["sql injection", "sqli", "sql "]),
            ("ssrf", ["ssrf", "server-side request"]),
            ("rce", ["rce", "remote code", "command injection", "code execution"]),
            ("auth", ["authentication", "auth bypass", "brute force", "credential"]),
            ("misconfig", ["misconfiguration", "misconfig", "default", "exposed"]),
            ("info_disclosure", ["disclosure", "information leak", "version", "banner"]),
            ("crypto", ["ssl", "tls", "certificate", "cipher", "crypto"]),
            ("injection", ["injection", "ldap", "xpath", "template"]),
            ("access_control", ["access control", "idor", "authorization", "privilege"]),
        ]

        for vuln_class, keywords in classifications:
            if any(kw in combined for kw in keywords):
                return vuln_class

        return "other"

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
        return {
            "correlation_groups": len(self._groups),
            "total_correlated": sum(len(g.findings) for g in self._groups),
        }
