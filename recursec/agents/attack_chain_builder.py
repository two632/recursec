"""Attack chain builder — links findings into exploitation paths.

Implements:
1. Finding graph (nodes=findings, edges=chains)
2. Chain scoring (impact, likelihood, complexity)
3. Automatic chain detection (pattern matching)
4. Kill chain mapping (MITRE ATT&CK phases)
5. Chain visualization (text-based)
6. Chain prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ChainPhase(str, Enum):
    RECON = "reconnaissance"
    RESOURCE_DEV = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIV_ESC = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CRED_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL = "lateral_movement"
    COLLECTION = "collection"
    C2 = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ChainStatus(str, Enum):
    THEORETICAL = "theoretical"    # Not yet validated
    PARTIAL = "partial"            # Some links validated
    VALIDATED = "validated"        # Full chain tested
    EXPLOITED = "exploited"        # Successfully executed


@dataclass
class ChainNode:
    """A node in the attack chain (a finding or step)."""
    node_id: str = ""
    finding_type: str = ""
    description: str = ""
    phase: ChainPhase = ChainPhase.RECON
    severity: str = "medium"
    confidence: float = 0.5
    tools_used: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:10],
            "type": self.finding_type[:15],
            "phase": self.phase.value[:10],
            "sev": self.severity[:4],
        }


@dataclass
class ChainEdge:
    """An edge connecting two chain nodes."""
    source_id: str = ""
    target_id: str = ""
    relationship: str = ""     # "enables", "requires", "leads_to"
    confidence: float = 0.5
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.source_id[:10],
            "to": self.target_id[:10],
            "rel": self.relationship[:8],
        }


@dataclass
class AttackChain:
    """A complete attack chain."""
    chain_id: str = ""
    name: str = ""
    nodes: list[str] = field(default_factory=list)    # Ordered node IDs
    status: ChainStatus = ChainStatus.THEORETICAL
    impact_score: float = 0.0      # 0-10
    likelihood: float = 0.0        # 0-1
    complexity: str = "medium"     # low/medium/high
    description: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def risk_score(self) -> float:
        return self.impact_score * self.likelihood

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "name": self.name[:20],
            "steps": len(self.nodes),
            "status": self.status.value[:8],
            "risk": round(self.risk_score, 1),
        }


# ── Common chain patterns ────────────────────────────────────

CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "Web to Shell",
        "phases": ["initial_access", "execution"],
        "finding_types": [["sqli", "rce", "file_upload", "ssrf"], ["shell", "command_exec"]],
        "impact": 9.0,
    },
    {
        "name": "Cred Harvest to Lateral",
        "phases": ["credential_access", "lateral_movement"],
        "finding_types": [["default_creds", "password_leak", "kerberoast"], ["smb", "rdp", "ssh"]],
        "impact": 8.0,
    },
    {
        "name": "Info Disclosure to Auth Bypass",
        "phases": ["discovery", "initial_access"],
        "finding_types": [["info_disclosure", "debug_enabled"], ["auth_bypass", "idor"]],
        "impact": 7.0,
    },
    {
        "name": "SSRF to Cloud Metadata",
        "phases": ["initial_access", "credential_access"],
        "finding_types": [["ssrf"], ["cloud_metadata", "aws_keys"]],
        "impact": 9.5,
    },
    {
        "name": "SQLi to Data Exfil",
        "phases": ["initial_access", "collection", "exfiltration"],
        "finding_types": [["sqli"], ["database_dump"], ["data_exfil"]],
        "impact": 9.0,
    },
    {
        "name": "Privesc to Domain Admin",
        "phases": ["privilege_escalation", "credential_access", "lateral_movement"],
        "finding_types": [["suid", "sudo_misconfig", "kernel_exploit"], ["mimikatz", "dcsync"], ["domain_admin"]],
        "impact": 10.0,
    },
]


class AttackChainBuilder:
    """Builds and manages attack chains from findings.

    Links individual findings into exploitation paths,
    scores them by risk, and maps to kill chain phases.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, ChainNode] = {}
        self._edges: list[ChainEdge] = []
        self._chains: dict[str, AttackChain] = {}
        self._counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="attack_chain")

    def add_finding(
        self,
        finding_type: str,
        description: str,
        phase: ChainPhase = ChainPhase.RECON,
        severity: str = "medium",
        confidence: float = 0.5,
        tools_used: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ChainNode:
        """Add a finding as a chain node."""
        self._counter += 1
        node = ChainNode(
            node_id=f"node-{self._counter}",
            finding_type=finding_type,
            description=description,
            phase=phase,
            severity=severity,
            confidence=confidence,
            tools_used=tools_used or [],
            metadata=metadata or {},
        )
        self._nodes[node.node_id] = node

        # Auto-detect chains
        self._detect_chains(node)

        return node

    def link(
        self,
        source_id: str,
        target_id: str,
        relationship: str = "leads_to",
        confidence: float = 0.5,
        description: str = "",
    ) -> ChainEdge | None:
        """Link two findings."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        edge = ChainEdge(
            source_id=source_id,
            target_id=target_id,
            relationship=relationship,
            confidence=confidence,
            description=description,
        )
        self._edges.append(edge)
        return edge

    def _detect_chains(self, new_node: ChainNode) -> None:
        """Auto-detect chains when new finding is added."""
        for pattern in CHAIN_PATTERNS:
            # Check if new node matches any phase in the pattern
            for phase_idx, finding_types in enumerate(pattern["finding_types"]):
                if new_node.finding_type in finding_types:
                    # Look for nodes matching other phases
                    self._try_build_chain(pattern, new_node, phase_idx)

    def _try_build_chain(
        self,
        pattern: dict[str, Any],
        trigger_node: ChainNode,
        trigger_phase_idx: int,
    ) -> None:
        """Try to build a chain from a pattern match."""
        phase_nodes: dict[int, list[ChainNode]] = {}
        phase_nodes[trigger_phase_idx] = [trigger_node]

        for phase_idx, finding_types in enumerate(pattern["finding_types"]):
            if phase_idx == trigger_phase_idx:
                continue
            matches = [
                n for n in self._nodes.values()
                if n.finding_type in finding_types and n.node_id != trigger_node.node_id
            ]
            if matches:
                phase_nodes[phase_idx] = matches

        # Need at least 2 phases to form a chain
        if len(phase_nodes) < 2:
            return

        # Build chain
        self._chain_counter += 1
        node_ids: list[str] = []
        for idx in sorted(phase_nodes.keys()):
            node_ids.append(phase_nodes[idx][0].node_id)

        chain = AttackChain(
            chain_id=f"chain-{self._chain_counter}",
            name=pattern["name"],
            nodes=node_ids,
            impact_score=pattern.get("impact", 5.0),
            likelihood=0.5,
            description=f"Auto-detected: {pattern['name']}",
        )
        self._chains[chain.chain_id] = chain

    def get_chains_by_risk(self) -> list[AttackChain]:
        """Get chains sorted by risk score."""
        chains = list(self._chains.values())
        chains.sort(key=lambda c: c.risk_score, reverse=True)
        return chains

    def get_chain_detail(self, chain_id: str) -> dict[str, Any] | None:
        """Get detailed chain info."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        steps: list[dict[str, Any]] = []
        for node_id in chain.nodes:
            node = self._nodes.get(node_id)
            if node:
                steps.append({
                    "id": node.node_id,
                    "type": node.finding_type,
                    "phase": node.phase.value,
                    "severity": node.severity,
                    "description": node.description[:80],
                })

        return {
            "chain": chain.to_dict(),
            "steps": steps,
            "risk_score": round(chain.risk_score, 1),
        }

    def build_chain_prompt(self) -> str:
        """Build attack chain context for LLM."""
        lines = ["## Attack Chains\n"]

        lines.append(f"Findings: {len(self._nodes)} | Chains: {len(self._chains)}")

        top_chains = self.get_chains_by_risk()[:3]
        if top_chains:
            lines.append("\nTop chains by risk:")
            for chain in top_chains:
                lines.append(
                    f"  {chain.name[:25]} — "
                    f"risk={chain.risk_score:.1f} "
                    f"impact={chain.impact_score:.1f} "
                    f"({len(chain.nodes)} steps, {chain.status.value[:8]})"
                )

                # Show steps
                for node_id in chain.nodes[:4]:
                    node = self._nodes.get(node_id)
                    if node:
                        lines.append(f"    → {node.phase.value[:12]}: {node.finding_type[:15]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = {}
        for n in self._nodes.values():
            p = n.phase.value
            phase_counts[p] = phase_counts.get(p, 0) + 1

        return {
            "total_findings": len(self._nodes),
            "total_edges": len(self._edges),
            "total_chains": len(self._chains),
            "by_phase": phase_counts,
            "max_risk": max((c.risk_score for c in self._chains.values()), default=0),
        }
