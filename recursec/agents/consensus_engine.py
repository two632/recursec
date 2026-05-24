"""Consensus engine — multi-model voting on findings.

Implements:
1. Finding validation via multiple model opinions
2. Weighted voting (model expertise matters)
3. Confidence aggregation across models
4. Disagreement resolution protocols
5. False positive filtering
6. Severity consensus
7. Consensus prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VoteType(str, Enum):
    CONFIRM = "confirm"        # Finding is valid
    REJECT = "reject"          # Finding is false positive
    UNCERTAIN = "uncertain"    # Not enough info
    ESCALATE = "escalate"      # Needs human review


class ConsensusStatus(str, Enum):
    PENDING = "pending"        # Not enough votes
    CONFIRMED = "confirmed"    # Consensus: valid
    REJECTED = "rejected"      # Consensus: false positive
    DISPUTED = "disputed"      # No consensus
    ESCALATED = "escalated"    # Sent for review


@dataclass
class Vote:
    """A single model's vote on a finding."""
    model_id: str = ""
    vote_type: VoteType = VoteType.UNCERTAIN
    confidence: float = 0.5
    reasoning: str = ""
    severity_opinion: str = ""    # Model's severity assessment
    weight: float = 1.0           # Model expertise weight
    timestamp: float = field(default_factory=time.time)

    @property
    def weighted_score(self) -> float:
        base = {
            VoteType.CONFIRM: 1.0,
            VoteType.REJECT: -1.0,
            VoteType.UNCERTAIN: 0.0,
            VoteType.ESCALATE: 0.5,
        }[self.vote_type]
        return base * self.confidence * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:10],
            "vote": self.vote_type.value[:6],
            "conf": round(self.confidence, 2),
            "sev": self.severity_opinion[:8],
        }


@dataclass
class FindingConsensus:
    """Consensus result for a finding."""
    finding_id: str = ""
    finding_type: str = ""
    finding_detail: str = ""
    votes: list[Vote] = field(default_factory=list)
    status: ConsensusStatus = ConsensusStatus.PENDING
    final_severity: str = ""
    final_confidence: float = 0.0
    resolved_at: float = 0.0

    @property
    def vote_count(self) -> int:
        return len(self.votes)

    @property
    def confirm_ratio(self) -> float:
        if not self.votes:
            return 0.0
        confirms = sum(1 for v in self.votes if v.vote_type == VoteType.CONFIRM)
        return confirms / len(self.votes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "type": self.finding_type[:12],
            "status": self.status.value[:8],
            "votes": self.vote_count,
            "confirm%": f"{self.confirm_ratio:.0%}",
        }


# ── Model expertise weights ──────────────────────────────────

MODEL_EXPERTISE: dict[str, dict[str, float]] = {
    "WhiteRabbitNeo": {"security": 2.0, "exploit": 2.0, "web": 1.8, "network": 1.8},
    "Qwen2.5-Coder-14B": {"code": 2.0, "web": 1.5, "api": 1.5},
    "Qwen2.5-Coder-7B": {"code": 1.8, "web": 1.3},
    "DeepSeek-R1": {"reasoning": 2.0, "analysis": 1.8, "general": 1.5},
    "CodeLlama-13B": {"code": 1.8, "binary": 1.3},
    "CodeLlama-7B": {"code": 1.5},
    "Yi-9B-200K": {"analysis": 1.5, "general": 1.3},
    "Hermes-4": {"general": 1.5, "reasoning": 1.3},
    "Llama-3.1-8B": {"general": 1.3},
    "Dolphin-2.9": {"general": 1.3, "security": 1.2},
    "Mistral-7B": {"general": 1.3, "fast": 1.5},
    "Phi-3.5-mini": {"fast": 1.5, "general": 1.0},
    "DeepSeek-Math": {"analysis": 1.5, "crypto": 1.5},
}


class ConsensusEngine:
    """Multi-model consensus on security findings.

    Collects votes from multiple models, weights them
    by expertise, and determines finding validity.
    """

    def __init__(
        self,
        min_votes: int = 3,
        confirm_threshold: float = 0.6,
        reject_threshold: float = 0.6,
    ) -> None:
        self._findings: dict[str, FindingConsensus] = {}
        self._min_votes = min_votes
        self._confirm_threshold = confirm_threshold
        self._reject_threshold = reject_threshold
        self._counter = 0
        self._log = logger.bind(component="consensus")

    def submit_finding(
        self,
        finding_type: str,
        finding_detail: str,
    ) -> FindingConsensus:
        """Submit a finding for consensus."""
        self._counter += 1
        finding = FindingConsensus(
            finding_id=f"finding-{self._counter}",
            finding_type=finding_type,
            finding_detail=finding_detail,
        )
        self._findings[finding.finding_id] = finding
        return finding

    def cast_vote(
        self,
        finding_id: str,
        model_id: str,
        vote_type: VoteType,
        confidence: float = 0.5,
        reasoning: str = "",
        severity_opinion: str = "",
    ) -> Vote | None:
        """Cast a vote on a finding."""
        finding = self._findings.get(finding_id)
        if not finding:
            return None

        # Determine weight from model expertise
        weight = 1.0
        for model_name, expertise in MODEL_EXPERTISE.items():
            if model_name.lower() in model_id.lower():
                domain = finding.finding_type.split("_")[0] if "_" in finding.finding_type else finding.finding_type
                weight = expertise.get(domain, expertise.get("general", 1.0))
                break

        vote = Vote(
            model_id=model_id,
            vote_type=vote_type,
            confidence=confidence,
            reasoning=reasoning,
            severity_opinion=severity_opinion,
            weight=weight,
        )
        finding.votes.append(vote)

        # Try to resolve
        if finding.vote_count >= self._min_votes:
            self._resolve(finding)

        return vote

    def _resolve(self, finding: FindingConsensus) -> None:
        """Try to resolve consensus."""
        if finding.status != ConsensusStatus.PENDING:
            return

        # Weighted voting
        total_weight = sum(v.weight for v in finding.votes)
        confirm_weight = sum(
            v.weight for v in finding.votes
            if v.vote_type == VoteType.CONFIRM
        )
        reject_weight = sum(
            v.weight for v in finding.votes
            if v.vote_type == VoteType.REJECT
        )

        confirm_ratio = confirm_weight / total_weight if total_weight > 0 else 0
        reject_ratio = reject_weight / total_weight if total_weight > 0 else 0

        if confirm_ratio >= self._confirm_threshold:
            finding.status = ConsensusStatus.CONFIRMED
            # Average confidence of confirming votes
            conf_votes = [v for v in finding.votes if v.vote_type == VoteType.CONFIRM]
            finding.final_confidence = sum(v.confidence for v in conf_votes) / len(conf_votes)
            # Severity: most common opinion
            self._resolve_severity(finding)
        elif reject_ratio >= self._reject_threshold:
            finding.status = ConsensusStatus.REJECTED
            finding.final_confidence = 0.0
        else:
            # Check for escalation
            escalate_count = sum(1 for v in finding.votes if v.vote_type == VoteType.ESCALATE)
            if escalate_count >= 2:
                finding.status = ConsensusStatus.ESCALATED
            else:
                finding.status = ConsensusStatus.DISPUTED

        finding.resolved_at = time.time()

    def _resolve_severity(self, finding: FindingConsensus) -> None:
        """Resolve severity from votes."""
        severities: dict[str, float] = {}
        for vote in finding.votes:
            if vote.severity_opinion and vote.vote_type == VoteType.CONFIRM:
                sev = vote.severity_opinion.lower()
                severities[sev] = severities.get(sev, 0) + vote.weight

        if severities:
            finding.final_severity = max(severities, key=severities.get)  # type: ignore[arg-type]

    def get_confirmed(self) -> list[FindingConsensus]:
        """Get all confirmed findings."""
        return [
            f for f in self._findings.values()
            if f.status == ConsensusStatus.CONFIRMED
        ]

    def get_disputed(self) -> list[FindingConsensus]:
        """Get disputed findings needing resolution."""
        return [
            f for f in self._findings.values()
            if f.status == ConsensusStatus.DISPUTED
        ]

    def build_consensus_prompt(self) -> str:
        """Build consensus context for LLM."""
        lines = ["## Finding Consensus\n"]

        status_counts: dict[str, int] = {}
        for f in self._findings.values():
            s = f.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        lines.append(
            f"Findings: {len(self._findings)} | "
            f"Confirmed: {status_counts.get('confirmed', 0)} | "
            f"Rejected: {status_counts.get('rejected', 0)} | "
            f"Disputed: {status_counts.get('disputed', 0)}"
        )

        # Recent confirmed findings
        confirmed = self.get_confirmed()
        if confirmed:
            lines.append("\nConfirmed findings:")
            for f in confirmed[-3:]:
                lines.append(
                    f"  {f.finding_type[:15]} — "
                    f"sev={f.final_severity[:8]} "
                    f"conf={f.final_confidence:.0%} "
                    f"({f.vote_count} votes)"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for f in self._findings.values():
            s = f.status.value
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "total_findings": len(self._findings),
            "by_status": status_counts,
            "total_votes": sum(f.vote_count for f in self._findings.values()),
        }
