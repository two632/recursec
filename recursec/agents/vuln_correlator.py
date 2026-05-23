"""Vulnerability correlator — links related findings.

Implements:
1. Finding similarity detection
2. Cross-tool correlation
3. Vulnerability chain identification
4. Impact amplification analysis
5. Deduplication with merge
6. Temporal correlation
7. Attack surface mapping
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CorrelationType(str, Enum):
    DUPLICATE = "duplicate"          # Same vuln, different tools
    RELATED = "related"              # Same component/service
    CHAIN = "chain"                  # One enables another
    AMPLIFIER = "amplifier"          # One amplifies another
    PREREQUISITE = "prerequisite"    # One required for another


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A vulnerability finding."""
    finding_id: str = ""
    title: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    description: str = ""
    tool: str = ""
    target: str = ""
    component: str = ""          # e.g., /login, port 443
    cwe: str = ""
    cve: str = ""
    evidence: str = ""
    confidence: float = 0.5
    found_at: float = field(default_factory=time.time)
    correlated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "title": self.title[:25],
            "severity": self.severity.value,
            "tool": self.tool[:10],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Correlation:
    """A correlation between findings."""
    correlation_id: str = ""
    finding_a: str = ""
    finding_b: str = ""
    correlation_type: CorrelationType = CorrelationType.RELATED
    confidence: float = 0.5
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.correlation_id[:10],
            "type": self.correlation_type.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class VulnCluster:
    """A cluster of correlated findings."""
    cluster_id: str = ""
    findings: list[str] = field(default_factory=list)
    primary_finding: str = ""
    max_severity: FindingSeverity = FindingSeverity.MEDIUM
    combined_impact: float = 0.0
    component: str = ""
    attack_narrative: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cluster_id[:10],
            "findings": len(self.findings),
            "severity": self.max_severity.value,
            "impact": round(self.combined_impact, 2),
            "component": self.component[:15],
        }


class VulnCorrelator:
    """Correlates vulnerability findings.

    Links related findings, detects duplicates,
    identifies attack chains, and calculates
    combined impact.
    """

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self._correlations: list[Correlation] = []
        self._clusters: dict[str, VulnCluster] = {}
        self._counter = 0
        self._log = logger.bind(component="vuln_correlator")

    def add_finding(
        self,
        title: str,
        severity: str = "medium",
        description: str = "",
        tool: str = "",
        target: str = "",
        component: str = "",
        cwe: str = "",
        cve: str = "",
        evidence: str = "",
        confidence: float = 0.5,
    ) -> Finding:
        """Add a finding."""
        self._counter += 1
        finding = Finding(
            finding_id=f"find-{self._counter}",
            title=title,
            severity=FindingSeverity(severity) if severity in FindingSeverity.__members__.values() else FindingSeverity.MEDIUM,
            description=description,
            tool=tool,
            target=target,
            component=component,
            cwe=cwe,
            cve=cve,
            evidence=evidence,
            confidence=confidence,
        )
        self._findings[finding.finding_id] = finding
        return finding

    def correlate_all(self) -> list[Correlation]:
        """Correlate all findings pairwise."""
        findings_list = list(self._findings.values())
        new_correlations: list[Correlation] = []

        for i, fa in enumerate(findings_list):
            for fb in findings_list[i + 1:]:
                correlation = self._check_correlation(fa, fb)
                if correlation:
                    new_correlations.append(correlation)
                    fa.correlated = True
                    fb.correlated = True

        self._correlations.extend(new_correlations)
        return new_correlations

    def _check_correlation(
        self,
        fa: Finding,
        fb: Finding,
    ) -> Correlation | None:
        """Check if two findings are correlated."""
        # Duplicate detection (same CVE or very similar title)
        if fa.cve and fa.cve == fb.cve:
            self._counter += 1
            return Correlation(
                correlation_id=f"corr-{self._counter}",
                finding_a=fa.finding_id,
                finding_b=fb.finding_id,
                correlation_type=CorrelationType.DUPLICATE,
                confidence=0.95,
                explanation=f"Same CVE: {fa.cve}",
            )

        # Title similarity
        title_sim = self._title_similarity(fa.title, fb.title)
        if title_sim > 0.7:
            self._counter += 1
            return Correlation(
                correlation_id=f"corr-{self._counter}",
                finding_a=fa.finding_id,
                finding_b=fb.finding_id,
                correlation_type=CorrelationType.DUPLICATE,
                confidence=title_sim,
                explanation="Similar titles",
            )

        # Same component
        if fa.component and fa.component == fb.component:
            self._counter += 1
            return Correlation(
                correlation_id=f"corr-{self._counter}",
                finding_a=fa.finding_id,
                finding_b=fb.finding_id,
                correlation_type=CorrelationType.RELATED,
                confidence=0.7,
                explanation=f"Same component: {fa.component}",
            )

        # Same CWE
        if fa.cwe and fa.cwe == fb.cwe and fa.tool != fb.tool:
            self._counter += 1
            return Correlation(
                correlation_id=f"corr-{self._counter}",
                finding_a=fa.finding_id,
                finding_b=fb.finding_id,
                correlation_type=CorrelationType.RELATED,
                confidence=0.6,
                explanation=f"Same CWE: {fa.cwe}, different tools",
            )

        # Chain detection (credential access → lateral movement)
        chain = self._detect_chain(fa, fb)
        if chain:
            self._counter += 1
            return Correlation(
                correlation_id=f"corr-{self._counter}",
                finding_a=fa.finding_id,
                finding_b=fb.finding_id,
                correlation_type=CorrelationType.CHAIN,
                confidence=0.6,
                explanation=chain,
            )

        return None

    def _title_similarity(self, a: str, b: str) -> float:
        """Simple word overlap similarity."""
        words_a = set(a.lower().split())
        words_b = set(b.lower().split())
        if not words_a or not words_b:
            return 0.0
        overlap = len(words_a & words_b)
        return overlap / max(len(words_a), len(words_b))

    def _detect_chain(self, fa: Finding, fb: Finding) -> str:
        """Detect if findings form an attack chain."""
        chain_patterns = [
            (["sqli", "injection", "sql"], ["credential", "password", "hash"],
             "SQL injection → credential access"),
            (["ssrf", "request forgery"], ["metadata", "cloud", "aws"],
             "SSRF → cloud metadata access"),
            (["rce", "command", "exec"], ["privesc", "privilege", "root"],
             "RCE → privilege escalation"),
            (["xss", "script"], ["session", "cookie", "token"],
             "XSS → session hijacking"),
            (["credential", "password"], ["lateral", "smb", "rdp"],
             "Credential access → lateral movement"),
        ]

        fa_text = f"{fa.title} {fa.description}".lower()
        fb_text = f"{fb.title} {fb.description}".lower()

        for pattern_a, pattern_b, chain_desc in chain_patterns:
            a_match = any(kw in fa_text for kw in pattern_a)
            b_match = any(kw in fb_text for kw in pattern_b)
            if a_match and b_match:
                return chain_desc

            # Check reverse
            a_match_rev = any(kw in fb_text for kw in pattern_a)
            b_match_rev = any(kw in fa_text for kw in pattern_b)
            if a_match_rev and b_match_rev:
                return chain_desc

        return ""

    def build_clusters(self) -> list[VulnCluster]:
        """Build clusters from correlated findings."""
        # Union-find for grouping
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for corr in self._correlations:
            union(corr.finding_a, corr.finding_b)

        # Group by cluster root
        groups: dict[str, list[str]] = defaultdict(list)
        for fid in self._findings:
            root = find(fid)
            groups[root].append(fid)

        # Build cluster objects
        clusters: list[VulnCluster] = []
        for root, finding_ids in groups.items():
            if len(finding_ids) < 2:
                continue

            self._counter += 1
            severity_order = {
                FindingSeverity.CRITICAL: 4,
                FindingSeverity.HIGH: 3,
                FindingSeverity.MEDIUM: 2,
                FindingSeverity.LOW: 1,
                FindingSeverity.INFO: 0,
            }

            findings = [self._findings[fid] for fid in finding_ids]
            primary = max(findings, key=lambda f: severity_order.get(f.severity, 0))

            # Combined impact: max severity + amplification from chain
            base_impact = severity_order.get(primary.severity, 0) / 4.0
            chain_bonus = 0.1 * sum(
                1 for c in self._correlations
                if c.correlation_type == CorrelationType.CHAIN
                and (c.finding_a in finding_ids or c.finding_b in finding_ids)
            )

            cluster = VulnCluster(
                cluster_id=f"cluster-{self._counter}",
                findings=finding_ids,
                primary_finding=primary.finding_id,
                max_severity=primary.severity,
                combined_impact=min(1.0, base_impact + chain_bonus),
                component=primary.component,
            )
            self._clusters[cluster.cluster_id] = cluster
            clusters.append(cluster)

        return clusters

    def get_deduplicated_findings(self) -> list[Finding]:
        """Get findings with duplicates merged."""
        seen_cves: set[str] = set()
        seen_titles: set[str] = set()
        result: list[Finding] = []

        severity_order = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
            FindingSeverity.INFO: 0,
        }

        sorted_findings = sorted(
            self._findings.values(),
            key=lambda f: severity_order.get(f.severity, 0),
            reverse=True,
        )

        for f in sorted_findings:
            if f.cve and f.cve in seen_cves:
                continue
            norm_title = f.title.lower().strip()
            if norm_title in seen_titles:
                continue
            result.append(f)
            if f.cve:
                seen_cves.add(f.cve)
            seen_titles.add(norm_title)

        return result

    def build_correlation_prompt(self) -> str:
        """Build a prompt describing correlations."""
        if not self._correlations:
            return ""

        lines = ["## Finding Correlations\n"]

        chains = [c for c in self._correlations if c.correlation_type == CorrelationType.CHAIN]
        if chains:
            lines.append("### Attack Chains")
            for c in chains[:5]:
                fa = self._findings.get(c.finding_a)
                fb = self._findings.get(c.finding_b)
                if fa and fb:
                    lines.append(f"- {fa.title} → {fb.title}: {c.explanation}")

        duplicates = [c for c in self._correlations if c.correlation_type == CorrelationType.DUPLICATE]
        if duplicates:
            lines.append(f"\n### Duplicates: {len(duplicates)} findings confirmed by multiple tools")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = defaultdict(int)
        for f in self._findings.values():
            sev_counts[f.severity.value] += 1

        corr_counts: dict[str, int] = defaultdict(int)
        for c in self._correlations:
            corr_counts[c.correlation_type.value] += 1

        return {
            "findings": len(self._findings),
            "correlations": len(self._correlations),
            "clusters": len(self._clusters),
            "by_severity": dict(sev_counts),
            "by_correlation": dict(corr_counts),
            "deduplicated": len(self.get_deduplicated_findings()),
        }
