"""Evidence tracker — maintains chain of evidence for findings.

Implements:
1. Evidence collection from multiple sources
2. Evidence chain (provenance tracking)
3. Evidence strength classification
4. Evidence correlation across findings
5. Evidence timestamping
6. Evidence verification status
7. Evidence export for reports
8. Evidence conflict resolution
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EvidenceType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    SCREENSHOT = "screenshot"
    NETWORK_CAPTURE = "network_capture"
    LOG_ENTRY = "log_entry"
    CODE_SNIPPET = "code_snippet"
    RESPONSE_HEADER = "response_header"
    RESPONSE_BODY = "response_body"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    API_RESPONSE = "api_response"
    AGENT_ANALYSIS = "agent_analysis"
    MANUAL = "manual"


class EvidenceStrength(str, Enum):
    DEFINITIVE = "definitive"      # Conclusive proof
    STRONG = "strong"              # Very likely correct
    MODERATE = "moderate"          # Supports but not conclusive
    WEAK = "weak"                  # Suggestive only
    CIRCUMSTANTIAL = "circumstantial"  # Indirect evidence


@dataclass
class EvidencePiece:
    """A single piece of evidence."""
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.TOOL_OUTPUT
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    source_tool: str = ""
    source_agent: str = ""
    finding_id: str = ""
    target: str = ""
    content: str = ""
    content_hash: str = ""
    verified: bool = False
    verified_by: str = ""
    collected_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "type": self.evidence_type.value,
            "strength": self.strength.value,
            "tool": self.source_tool,
            "finding": self.finding_id,
            "target": self.target[:60],
            "verified": self.verified,
            "content_len": len(self.content),
        }


@dataclass
class EvidenceChain:
    """A chain of evidence supporting a finding."""
    chain_id: str = ""
    finding_id: str = ""
    pieces: list[EvidencePiece] = field(default_factory=list)
    overall_strength: EvidenceStrength = EvidenceStrength.WEAK

    @property
    def strongest(self) -> EvidenceStrength:
        if not self.pieces:
            return EvidenceStrength.WEAK

        strength_order = {
            EvidenceStrength.DEFINITIVE: 4,
            EvidenceStrength.STRONG: 3,
            EvidenceStrength.MODERATE: 2,
            EvidenceStrength.WEAK: 1,
            EvidenceStrength.CIRCUMSTANTIAL: 0,
        }

        best = max(self.pieces, key=lambda p: strength_order.get(p.strength, 0))
        return best.strength

    @property
    def verified_count(self) -> int:
        return sum(1 for p in self.pieces if p.verified)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id, "finding": self.finding_id,
            "pieces": len(self.pieces),
            "strength": self.strongest.value,
            "verified": self.verified_count,
        }


class EvidenceTracker:
    """Maintains chain of evidence for all findings.

    Tracks provenance, verifies evidence, and
    maintains relationships between evidence pieces.
    """

    def __init__(self) -> None:
        self._evidence: dict[str, EvidencePiece] = {}
        self._chains: dict[str, EvidenceChain] = {}
        self._finding_evidence: dict[str, list[str]] = defaultdict(list)  # finding_id -> [evidence_ids]
        self._evidence_counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="evidence_tracker")

    def collect(
        self,
        evidence_type: EvidenceType,
        content: str,
        finding_id: str = "",
        source_tool: str = "",
        source_agent: str = "",
        target: str = "",
        strength: EvidenceStrength = EvidenceStrength.MODERATE,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Collect a piece of evidence."""
        self._evidence_counter += 1
        eid = f"ev-{self._evidence_counter}"

        import hashlib
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        piece = EvidencePiece(
            evidence_id=eid,
            evidence_type=evidence_type,
            strength=strength,
            source_tool=source_tool,
            source_agent=source_agent,
            finding_id=finding_id,
            target=target,
            content=content[:10000],
            content_hash=content_hash,
            metadata=metadata or {},
        )

        self._evidence[eid] = piece

        # Associate with finding
        if finding_id:
            self._finding_evidence[finding_id].append(eid)

        return eid

    def verify(self, evidence_id: str, verified_by: str) -> bool:
        """Mark evidence as verified."""
        piece = self._evidence.get(evidence_id)
        if piece:
            piece.verified = True
            piece.verified_by = verified_by
            return True
        return False

    def build_chain(self, finding_id: str) -> EvidenceChain:
        """Build an evidence chain for a finding."""
        self._chain_counter += 1
        chain_id = f"chain-{self._chain_counter}"

        evidence_ids = self._finding_evidence.get(finding_id, [])
        pieces = [self._evidence[eid] for eid in evidence_ids if eid in self._evidence]

        chain = EvidenceChain(
            chain_id=chain_id,
            finding_id=finding_id,
            pieces=pieces,
        )

        self._chains[chain_id] = chain
        return chain

    def get_for_finding(self, finding_id: str) -> list[EvidencePiece]:
        """Get all evidence for a finding."""
        evidence_ids = self._finding_evidence.get(finding_id, [])
        return [self._evidence[eid] for eid in evidence_ids if eid in self._evidence]

    def correlate(self, finding_id_1: str, finding_id_2: str) -> list[EvidencePiece]:
        """Find shared evidence between two findings."""
        ev1 = set(self._finding_evidence.get(finding_id_1, []))
        ev2 = set(self._finding_evidence.get(finding_id_2, []))
        shared_ids = ev1 & ev2
        return [self._evidence[eid] for eid in shared_ids if eid in self._evidence]

    def find_conflicts(self) -> list[dict[str, Any]]:
        """Find conflicting evidence for the same finding."""
        conflicts = []

        for finding_id, ev_ids in self._finding_evidence.items():
            pieces = [self._evidence[eid] for eid in ev_ids if eid in self._evidence]

            # Look for pieces with different strength classifications
            strengths = {p.strength for p in pieces}
            if EvidenceStrength.DEFINITIVE in strengths and EvidenceStrength.WEAK in strengths:
                conflicts.append({
                    "finding": finding_id,
                    "issue": "Mixed evidence strength (definitive + weak)",
                    "pieces": len(pieces),
                })

        return conflicts

    def export_for_report(self, finding_id: str) -> dict[str, Any]:
        """Export evidence for a report."""
        pieces = self.get_for_finding(finding_id)
        chain = self.build_chain(finding_id)

        return {
            "finding_id": finding_id,
            "chain": chain.to_dict(),
            "evidence": [
                {
                    "type": p.evidence_type.value,
                    "strength": p.strength.value,
                    "tool": p.source_tool,
                    "verified": p.verified,
                    "content": p.content[:200],
                }
                for p in pieces
            ],
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "evidence_pieces": len(self._evidence),
            "chains": len(self._chains),
            "findings_tracked": len(self._finding_evidence),
            "verified": sum(1 for e in self._evidence.values() if e.verified),
        }
