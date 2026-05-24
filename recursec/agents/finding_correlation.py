"""Finding correlation engine — link findings into chains.

Implements:
1. Vulnerability correlation across phases
2. Attack chain construction
3. Impact amplification detection
4. Deduplication with similarity
5. Risk score calculation
6. Correlation prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ChainType(str, Enum):
    LINEAR = "linear"           # A → B → C
    BRANCHING = "branching"     # A → B, A → C
    CONVERGING = "converging"   # A, B → C
    COMPOSITE = "composite"     # Complex graph


SEVERITY_SCORES: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 10.0,
    FindingSeverity.HIGH: 7.0,
    FindingSeverity.MEDIUM: 4.0,
    FindingSeverity.LOW: 2.0,
    FindingSeverity.INFO: 0.5,
}

# Finding types that naturally chain
CHAIN_RULES: list[tuple[str, str, float]] = [
    ("info_disclosure", "credential_theft", 0.8),
    ("credential_theft", "privilege_escalation", 0.9),
    ("sqli", "data_exfiltration", 0.85),
    ("sqli", "rce", 0.7),
    ("ssrf", "metadata_access", 0.9),
    ("metadata_access", "credential_theft", 0.95),
    ("xss", "session_hijack", 0.8),
    ("session_hijack", "account_takeover", 0.9),
    ("lfi", "rce", 0.7),
    ("rce", "privilege_escalation", 0.8),
    ("privilege_escalation", "lateral_movement", 0.9),
    ("lateral_movement", "data_exfiltration", 0.8),
    ("open_port", "service_exploit", 0.6),
    ("misconfig", "info_disclosure", 0.7),
    ("weak_auth", "credential_theft", 0.8),
    ("default_creds", "rce", 0.9),
    ("idor", "data_exfiltration", 0.7),
    ("path_traversal", "lfi", 0.9),
    ("deserialization", "rce", 0.85),
    ("ssti", "rce", 0.9),
]


@dataclass
class Finding:
    """A security finding."""
    finding_id: str = ""
    finding_type: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    title: str = ""
    target: str = ""
    evidence: str = ""
    tool: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)
    correlated: bool = False

    @property
    def score(self) -> float:
        base = SEVERITY_SCORES.get(self.severity, 4.0)
        return base * self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type[:12],
            "severity": self.severity.value[:6],
            "title": self.title[:20],
        }


@dataclass
class AttackChain:
    """A chain of correlated findings."""
    chain_id: str = ""
    chain_type: ChainType = ChainType.LINEAR
    findings: list[str] = field(default_factory=list)
    edges: list[tuple[str, str, float]] = field(default_factory=list)
    total_impact: float = 0.0
    amplification: float = 1.0
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.chain_type.value[:8],
            "steps": len(self.findings),
            "impact": f"{self.total_impact:.1f}",
            "amp": f"{self.amplification:.1f}x",
        }


class FindingCorrelationEngine:
    """Correlate findings into attack chains.

    Links related findings, detects
    impact amplification, and constructs chains.
    """

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self._chains: dict[str, AttackChain] = {}
        self._finding_counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="correlation")

    def add_finding(
        self,
        finding_type: str,
        severity: str,
        title: str,
        target: str = "",
        evidence: str = "",
        tool: str = "",
        confidence: float = 0.5,
    ) -> Finding:
        """Add a new finding."""
        self._finding_counter += 1

        sev = FindingSeverity.MEDIUM
        for s in FindingSeverity:
            if s.value == severity.lower():
                sev = s
                break

        finding = Finding(
            finding_id=f"f-{self._finding_counter}",
            finding_type=finding_type.lower(),
            severity=sev,
            title=title,
            target=target,
            evidence=evidence,
            tool=tool,
            confidence=confidence,
        )
        self._findings[finding.finding_id] = finding

        # Try to correlate
        self._auto_correlate(finding)

        return finding

    def _auto_correlate(self, new_finding: Finding) -> None:
        """Automatically correlate a new finding."""
        for existing in self._findings.values():
            if existing.finding_id == new_finding.finding_id:
                continue

            # Check chain rules
            for src_type, dst_type, strength in CHAIN_RULES:
                if (
                    existing.finding_type == src_type
                    and new_finding.finding_type == dst_type
                ):
                    self._create_or_extend_chain(
                        existing, new_finding, strength,
                    )

                # Reverse check too
                if (
                    new_finding.finding_type == src_type
                    and existing.finding_type == dst_type
                ):
                    self._create_or_extend_chain(
                        new_finding, existing, strength,
                    )

    def _create_or_extend_chain(
        self,
        source: Finding,
        target: Finding,
        strength: float,
    ) -> None:
        """Create or extend an attack chain."""
        # Check if either finding is already in a chain
        for chain in self._chains.values():
            if source.finding_id in chain.findings:
                if target.finding_id not in chain.findings:
                    chain.findings.append(target.finding_id)
                    chain.edges.append(
                        (source.finding_id, target.finding_id, strength)
                    )
                    self._recalculate_chain(chain)
                return

        # Create new chain
        self._chain_counter += 1
        chain = AttackChain(
            chain_id=f"chain-{self._chain_counter}",
            findings=[source.finding_id, target.finding_id],
            edges=[(source.finding_id, target.finding_id, strength)],
        )
        self._recalculate_chain(chain)
        self._chains[chain.chain_id] = chain

        source.correlated = True
        target.correlated = True

    def _recalculate_chain(self, chain: AttackChain) -> None:
        """Recalculate chain impact and amplification."""
        finding_scores = []
        for fid in chain.findings:
            f = self._findings.get(fid)
            if f:
                finding_scores.append(f.score)

        if not finding_scores:
            return

        # Total impact = sum of individual scores
        chain.total_impact = sum(finding_scores)

        # Amplification from chaining
        chain.amplification = 1.0 + (len(chain.findings) - 1) * 0.3

        # Apply edge strengths
        avg_strength = 1.0
        if chain.edges:
            avg_strength = sum(s for _, _, s in chain.edges) / len(chain.edges)
        chain.total_impact *= avg_strength * chain.amplification

        # Determine chain type
        if len(chain.findings) <= 2:
            chain.chain_type = ChainType.LINEAR
        elif len(chain.edges) > len(chain.findings):
            chain.chain_type = ChainType.COMPOSITE
        else:
            chain.chain_type = ChainType.LINEAR

    def deduplicate(self, similarity_threshold: float = 0.8) -> int:
        """Remove duplicate findings."""
        removed = 0
        seen: list[str] = []

        for fid, finding in list(self._findings.items()):
            key = f"{finding.finding_type}:{finding.target}"
            if key in seen:
                del self._findings[fid]
                removed += 1
            else:
                seen.append(key)

        return removed

    def get_risk_score(self) -> float:
        """Calculate overall risk score."""
        if not self._findings:
            return 0.0

        # Base: highest individual finding
        max_finding = max(
            f.score for f in self._findings.values()
        )

        # Chain bonus
        chain_bonus = sum(
            c.total_impact * 0.1
            for c in self._chains.values()
        )

        return min(10.0, max_finding + chain_bonus)

    def build_correlation_prompt(self) -> str:
        """Build correlation context for LLM."""
        lines = ["## Finding Correlation\n"]
        lines.append(f"Findings: {len(self._findings)}")
        lines.append(f"Chains: {len(self._chains)}")
        lines.append(f"Risk: {self.get_risk_score():.1f}/10")

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in self._findings.values():
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        if sev_counts:
            lines.append(
                "Severity: " +
                ", ".join(f"{k}={v}" for k, v in sev_counts.items())
            )

        # Top chains
        if self._chains:
            top = sorted(
                self._chains.values(),
                key=lambda c: c.total_impact,
                reverse=True,
            )[:3]
            lines.append("\nAttack chains:")
            for c in top:
                steps = []
                for fid in c.findings[:4]:
                    f = self._findings.get(fid)
                    if f:
                        steps.append(f.finding_type[:8])
                lines.append(
                    f"  {' → '.join(steps)} "
                    f"(impact={c.total_impact:.1f})"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {}
        for f in self._findings.values():
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        return {
            "findings": len(self._findings),
            "chains": len(self._chains),
            "risk_score": f"{self.get_risk_score():.1f}",
            "by_severity": sev_counts,
            "correlated": sum(1 for f in self._findings.values() if f.correlated),
        }
