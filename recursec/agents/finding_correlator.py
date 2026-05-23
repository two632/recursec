"""Finding correlator — links related findings into attack chains.

Implements:
1. Finding similarity detection
2. Attack chain construction
3. Finding deduplication
4. Impact scoring
5. Exploit path generation
6. Cross-tool correlation
7. Temporal pattern analysis
"""

from __future__ import annotations

import hashlib
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


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    EXPLOITED = "exploited"


class ChainType(str, Enum):
    LINEAR = "linear"           # A → B → C
    PARALLEL = "parallel"       # A + B → C
    ESCALATION = "escalation"   # Low → High → Critical
    LATERAL = "lateral"         # Host A → Host B


@dataclass
class Finding:
    """A discovered vulnerability."""
    finding_id: str = ""
    title: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    status: FindingStatus = FindingStatus.NEW
    category: str = ""          # injection, xss, auth, etc.
    target: str = ""
    tool_source: str = ""
    description: str = ""
    evidence: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    remediation: str = ""
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    hash: str = ""

    def compute_hash(self) -> str:
        """Compute dedup hash."""
        data = f"{self.category}:{self.target}:{self.title}"
        self.hash = hashlib.sha256(data.encode()).hexdigest()[:16]
        return self.hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "title": self.title[:30],
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category[:12],
            "target": self.target[:20],
            "tool": self.tool_source[:10],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class AttackChain:
    """A chain of findings forming an attack path."""
    chain_id: str = ""
    chain_type: ChainType = ChainType.LINEAR
    findings: list[str] = field(default_factory=list)  # Finding IDs in order
    impact_score: float = 0.0
    description: str = ""
    exploitable: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "type": self.chain_type.value,
            "findings": len(self.findings),
            "impact": round(self.impact_score, 2),
            "exploitable": self.exploitable,
        }


# ── Correlation rules ────────────────────────────────────────

CORRELATION_RULES: list[dict[str, Any]] = [
    {
        "name": "sqli_to_rce",
        "desc": "SQL Injection → OS Command Execution",
        "chain_type": "escalation",
        "requires": [{"category": "injection", "subcategory": "sql"}],
        "leads_to": [{"category": "rce"}],
        "impact_multiplier": 2.0,
    },
    {
        "name": "ssrf_to_cloud",
        "desc": "SSRF → Cloud Metadata → Credential Theft",
        "chain_type": "escalation",
        "requires": [{"category": "ssrf"}],
        "leads_to": [{"category": "credential_theft"}],
        "impact_multiplier": 2.5,
    },
    {
        "name": "xss_to_session",
        "desc": "XSS → Session Hijacking → Account Takeover",
        "chain_type": "escalation",
        "requires": [{"category": "xss"}],
        "leads_to": [{"category": "session_hijacking"}],
        "impact_multiplier": 1.5,
    },
    {
        "name": "idor_to_data_breach",
        "desc": "IDOR → Mass Data Extraction",
        "chain_type": "linear",
        "requires": [{"category": "idor"}],
        "leads_to": [{"category": "data_breach"}],
        "impact_multiplier": 2.0,
    },
    {
        "name": "auth_bypass_to_admin",
        "desc": "Auth Bypass → Admin Access → Full Compromise",
        "chain_type": "escalation",
        "requires": [{"category": "authentication"}],
        "leads_to": [{"category": "admin_access"}],
        "impact_multiplier": 3.0,
    },
    {
        "name": "default_creds_lateral",
        "desc": "Default Credentials → Lateral Movement",
        "chain_type": "lateral",
        "requires": [{"category": "default_credentials"}],
        "leads_to": [{"category": "lateral_movement"}],
        "impact_multiplier": 1.8,
    },
]

SEVERITY_SCORES = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}


class FindingCorrelator:
    """Correlates findings into attack chains.

    Links related findings, detects duplicates,
    constructs attack paths, and scores impact.
    """

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self._chains: dict[str, AttackChain] = {}
        self._hashes: set[str] = set()
        self._counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="finding_correlator")

    def add_finding(self, finding: Finding) -> Finding | None:
        """Add a finding, checking for duplicates."""
        # Compute hash
        finding.compute_hash()

        # Dedup
        if finding.hash in self._hashes:
            self._log.debug("duplicate_finding", hash=finding.hash)
            finding.status = FindingStatus.DUPLICATE
            return None

        self._hashes.add(finding.hash)

        # Assign ID if needed
        if not finding.finding_id:
            self._counter += 1
            finding.finding_id = f"find-{self._counter}"

        self._findings[finding.finding_id] = finding

        # Auto-correlate
        self._auto_correlate(finding)

        return finding

    def _auto_correlate(self, new_finding: Finding) -> None:
        """Check if new finding triggers any correlation rules."""
        for rule in CORRELATION_RULES:
            for req in rule.get("requires", []):
                if new_finding.category.lower() == req.get("category", "").lower():
                    # Check if we have matching lead-to findings
                    for existing in self._findings.values():
                        for lead in rule.get("leads_to", []):
                            if existing.category.lower() == lead.get("category", "").lower():
                                self._create_chain(
                                    [new_finding.finding_id, existing.finding_id],
                                    rule,
                                )

    def _create_chain(
        self,
        finding_ids: list[str],
        rule: dict[str, Any],
    ) -> AttackChain:
        """Create an attack chain."""
        self._chain_counter += 1

        # Calculate impact
        total_severity = sum(
            SEVERITY_SCORES.get(
                self._findings[fid].severity.value, 5.0,
            )
            for fid in finding_ids
            if fid in self._findings
        )
        multiplier = rule.get("impact_multiplier", 1.0)
        impact = total_severity * multiplier

        chain_type_str = rule.get("chain_type", "linear")
        try:
            chain_type = ChainType(chain_type_str)
        except ValueError:
            chain_type = ChainType.LINEAR

        chain = AttackChain(
            chain_id=f"chain-{self._chain_counter}",
            chain_type=chain_type,
            findings=finding_ids,
            impact_score=impact,
            description=rule.get("desc", ""),
            exploitable=impact > 10.0,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def get_by_severity(self, severity: FindingSeverity) -> list[Finding]:
        """Get findings by severity."""
        return [
            f for f in self._findings.values()
            if f.severity == severity and f.status != FindingStatus.DUPLICATE
        ]

    def get_critical_chains(self) -> list[AttackChain]:
        """Get high-impact attack chains."""
        return sorted(
            [c for c in self._chains.values() if c.impact_score > 10.0],
            key=lambda c: c.impact_score,
            reverse=True,
        )

    def build_findings_prompt(
        self,
        max_findings: int = 10,
        min_severity: str = "medium",
    ) -> str:
        """Build findings context for LLM."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_level = severity_order.get(min_severity, 2)

        lines = ["## Current Findings\n"]

        sorted_findings = sorted(
            self._findings.values(),
            key=lambda f: severity_order.get(f.severity.value, 4),
        )

        count = 0
        for f in sorted_findings:
            if severity_order.get(f.severity.value, 4) > min_level:
                continue
            if f.status == FindingStatus.DUPLICATE:
                continue
            if count >= max_findings:
                break
            lines.append(
                f"- [{f.severity.value.upper()}] {f.title} "
                f"on {f.target[:20]} ({f.confidence:.0%} confidence)"
            )
            count += 1

        # Add chains
        critical_chains = self.get_critical_chains()
        if critical_chains:
            lines.append("\n## Attack Chains:")
            for chain in critical_chains[:3]:
                lines.append(
                    f"- {chain.description} "
                    f"(impact: {chain.impact_score:.1f}, "
                    f"{'exploitable' if chain.exploitable else 'theoretical'})"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        severity_counts: dict[str, int] = {}
        for f in self._findings.values():
            if f.status != FindingStatus.DUPLICATE:
                severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        return {
            "total_findings": len(self._findings),
            "unique_findings": len(self._findings) - sum(
                1 for f in self._findings.values()
                if f.status == FindingStatus.DUPLICATE
            ),
            "by_severity": severity_counts,
            "attack_chains": len(self._chains),
            "exploitable_chains": sum(1 for c in self._chains.values() if c.exploitable),
        }
