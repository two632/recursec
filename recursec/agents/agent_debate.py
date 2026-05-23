"""Agent debate mechanism — multi-model consensus on findings.

Implements:
1. Adversarial validation (agents argue for/against findings)
2. Multi-model voting (different models independently assess)
3. Confidence aggregation with weighted voting
4. Conflict resolution strategies
5. Debate round management
6. Evidence-based argumentation
7. Final verdict synthesis
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DebateRole(str, Enum):
    PROPOSER = "proposer"         # Argues finding is valid
    CHALLENGER = "challenger"     # Argues finding is invalid
    JUDGE = "judge"               # Makes final determination
    EVIDENCE_GATHERER = "evidence_gatherer"  # Finds supporting data


class VoteType(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY_VALID = "likely_valid"
    UNCERTAIN = "uncertain"
    LIKELY_FALSE = "likely_false"
    FALSE_POSITIVE = "false_positive"


class ConflictResolution(str, Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_VOTE = "weighted_vote"
    UNANIMOUS = "unanimous"
    EXPERT_OVERRIDE = "expert_override"


@dataclass
class DebateArgument:
    """An argument in the debate."""
    argument_id: str = ""
    round_number: int = 0
    role: DebateRole = DebateRole.PROPOSER
    model_id: str = ""
    position: str = ""        # The argument text
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round_number,
            "role": self.role.value,
            "model": self.model_id[:12],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class DebateVote:
    """A vote from a model."""
    model_id: str = ""
    vote: VoteType = VoteType.UNCERTAIN
    confidence: float = 0.5
    weight: float = 1.0       # Model expertise weight
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "vote": self.vote.value,
            "confidence": round(self.confidence, 2),
            "weight": self.weight,
        }


@dataclass
class DebateVerdict:
    """Final verdict from the debate."""
    finding_id: str = ""
    verdict: VoteType = VoteType.UNCERTAIN
    confidence: float = 0.5
    vote_breakdown: dict[str, int] = field(default_factory=dict)
    key_evidence: list[str] = field(default_factory=list)
    dissenting_views: list[str] = field(default_factory=list)
    rounds_conducted: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_id[:10],
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 2),
            "votes": self.vote_breakdown,
            "rounds": self.rounds_conducted,
        }


@dataclass
class Debate:
    """A debate about a finding."""
    debate_id: str = ""
    finding_id: str = ""
    finding_summary: str = ""
    arguments: list[DebateArgument] = field(default_factory=list)
    votes: list[DebateVote] = field(default_factory=list)
    verdict: DebateVerdict | None = None
    max_rounds: int = 3
    current_round: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.debate_id[:10],
            "finding": self.finding_id[:10],
            "round": f"{self.current_round}/{self.max_rounds}",
            "arguments": len(self.arguments),
            "votes": len(self.votes),
        }


# ── Debate prompts ────────────────────────────────────────────

DEBATE_PROMPTS: dict[str, str] = {
    "proposer": (
        "You are arguing that the following security finding is VALID and represents a real vulnerability.\n"
        "Present evidence supporting the finding. Consider:\n"
        "- What tools/tests confirmed this?\n"
        "- How reproducible is it?\n"
        "- What is the potential impact?\n"
        "- Does it match known vulnerability patterns?"
    ),
    "challenger": (
        "You are arguing that the following security finding may be a FALSE POSITIVE.\n"
        "Present evidence challenging the finding. Consider:\n"
        "- Could the tool have misidentified this?\n"
        "- Is the evidence sufficient?\n"
        "- Are there mitigating controls not considered?\n"
        "- Could this be informational rather than a vulnerability?"
    ),
    "judge": (
        "You are the judge reviewing arguments for and against this finding.\n"
        "Weigh the evidence from both sides and make a determination:\n"
        "- Is the evidence compelling?\n"
        "- Which arguments are stronger?\n"
        "- What is your confidence level?\n"
        "- What additional verification would help?"
    ),
}


# ── Model expertise weights for voting ────────────────────────

EXPERTISE_WEIGHTS: dict[str, dict[str, float]] = {
    "whiterabbitneo-7b": {"security": 2.0, "exploitation": 1.8, "default": 1.0},
    "qwen-coder-14b": {"code_analysis": 2.0, "security": 1.3, "default": 1.0},
    "deepseek-r1-7b": {"reasoning": 2.0, "analysis": 1.5, "default": 1.0},
    "hermes-14b": {"general": 1.8, "analysis": 1.5, "default": 1.0},
    "dolphin-8b": {"security": 1.3, "exploitation": 1.2, "default": 1.0},
    "mistral-7b": {"general": 1.5, "default": 1.0},
}


VOTE_SCORES: dict[str, float] = {
    "confirmed": 1.0,
    "likely_valid": 0.75,
    "uncertain": 0.5,
    "likely_false": 0.25,
    "false_positive": 0.0,
}


class AgentDebate:
    """Multi-model debate mechanism for finding validation.

    Multiple models independently assess findings,
    argue for/against validity, and reach consensus
    through structured debate rounds.
    """

    def __init__(
        self,
        max_rounds: int = 3,
        resolution: ConflictResolution = ConflictResolution.WEIGHTED_VOTE,
    ) -> None:
        self._debates: dict[str, Debate] = {}
        self._counter = 0
        self._resolution = resolution
        self._max_rounds = max_rounds
        self._log = logger.bind(component="agent_debate")

    def start_debate(
        self,
        finding_id: str,
        finding_summary: str,
    ) -> Debate:
        """Start a new debate about a finding."""
        self._counter += 1
        debate = Debate(
            debate_id=f"debate-{self._counter}",
            finding_id=finding_id,
            finding_summary=finding_summary,
            max_rounds=self._max_rounds,
        )
        self._debates[debate.debate_id] = debate
        return debate

    def add_argument(
        self,
        debate_id: str,
        role: DebateRole,
        model_id: str,
        position: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
    ) -> DebateArgument | None:
        """Add an argument to the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        arg = DebateArgument(
            argument_id=f"{debate_id}-arg{len(debate.arguments)}",
            round_number=debate.current_round,
            role=role,
            model_id=model_id,
            position=position,
            evidence=evidence or [],
            confidence=confidence,
        )
        debate.arguments.append(arg)
        return arg

    def advance_round(self, debate_id: str) -> bool:
        """Advance to the next debate round."""
        debate = self._debates.get(debate_id)
        if not debate:
            return False

        if debate.current_round >= debate.max_rounds:
            return False

        debate.current_round += 1
        return True

    def cast_vote(
        self,
        debate_id: str,
        model_id: str,
        vote: VoteType,
        confidence: float = 0.5,
        reasoning: str = "",
    ) -> DebateVote | None:
        """Cast a vote in the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        # Get expertise weight
        expertise = EXPERTISE_WEIGHTS.get(model_id, {})
        weight = expertise.get("security", expertise.get("default", 1.0))

        dv = DebateVote(
            model_id=model_id,
            vote=vote,
            confidence=confidence,
            weight=weight,
            reasoning=reasoning,
        )
        debate.votes.append(dv)
        return dv

    def resolve(self, debate_id: str) -> DebateVerdict | None:
        """Resolve the debate and produce a verdict."""
        debate = self._debates.get(debate_id)
        if not debate or not debate.votes:
            return None

        if self._resolution == ConflictResolution.WEIGHTED_VOTE:
            verdict = self._resolve_weighted(debate)
        elif self._resolution == ConflictResolution.MAJORITY_VOTE:
            verdict = self._resolve_majority(debate)
        else:
            verdict = self._resolve_weighted(debate)

        debate.verdict = verdict
        debate.completed_at = time.time()
        return verdict

    def _resolve_weighted(self, debate: Debate) -> DebateVerdict:
        """Resolve using weighted voting."""
        weighted_score = 0.0
        total_weight = 0.0
        vote_counts: dict[str, int] = defaultdict(int)

        for vote in debate.votes:
            score = VOTE_SCORES.get(vote.vote.value, 0.5)
            weighted_score += score * vote.weight * vote.confidence
            total_weight += vote.weight
            vote_counts[vote.vote.value] += 1

        avg_score = weighted_score / max(0.01, total_weight)

        # Map score to verdict
        if avg_score >= 0.8:
            verdict_type = VoteType.CONFIRMED
        elif avg_score >= 0.6:
            verdict_type = VoteType.LIKELY_VALID
        elif avg_score >= 0.4:
            verdict_type = VoteType.UNCERTAIN
        elif avg_score >= 0.2:
            verdict_type = VoteType.LIKELY_FALSE
        else:
            verdict_type = VoteType.FALSE_POSITIVE

        # Collect evidence from proposer arguments
        evidence = []
        dissenting = []
        for arg in debate.arguments:
            if arg.role == DebateRole.PROPOSER:
                evidence.extend(arg.evidence[:2])
            if arg.role == DebateRole.CHALLENGER and arg.confidence > 0.7:
                dissenting.append(arg.position[:80])

        return DebateVerdict(
            finding_id=debate.finding_id,
            verdict=verdict_type,
            confidence=avg_score,
            vote_breakdown=dict(vote_counts),
            key_evidence=evidence[:5],
            dissenting_views=dissenting[:3],
            rounds_conducted=debate.current_round,
        )

    def _resolve_majority(self, debate: Debate) -> DebateVerdict:
        """Resolve using simple majority vote."""
        vote_counts: dict[str, int] = defaultdict(int)
        for vote in debate.votes:
            vote_counts[vote.vote.value] += 1

        if not vote_counts:
            return DebateVerdict(
                finding_id=debate.finding_id,
                verdict=VoteType.UNCERTAIN,
            )

        majority_vote = max(vote_counts, key=lambda v: vote_counts[v])
        total_votes = sum(vote_counts.values())
        confidence = vote_counts[majority_vote] / max(1, total_votes)

        return DebateVerdict(
            finding_id=debate.finding_id,
            verdict=VoteType(majority_vote),
            confidence=confidence,
            vote_breakdown=dict(vote_counts),
            rounds_conducted=debate.current_round,
        )

    def build_debate_prompt(
        self,
        debate_id: str,
        role: DebateRole = DebateRole.PROPOSER,
    ) -> str:
        """Build debate prompt for LLM."""
        debate = self._debates.get(debate_id)
        if not debate:
            return ""

        lines = [
            f"## Finding Debate (Round {debate.current_round})\n",
            f"Finding: {debate.finding_summary}",
            "",
        ]

        # Add role-specific instructions
        role_prompt = DEBATE_PROMPTS.get(role.value, "")
        if role_prompt:
            lines.append(role_prompt)
            lines.append("")

        # Add previous arguments
        if debate.arguments:
            lines.append("## Previous Arguments:")
            for arg in debate.arguments[-6:]:
                lines.append(
                    f"[{arg.role.value}] ({arg.model_id[:10]}, "
                    f"confidence: {arg.confidence:.0%}): "
                    f"{arg.position[:120]}"
                )
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        completed = sum(
            1 for d in self._debates.values()
            if d.verdict is not None
        )
        total_args = sum(len(d.arguments) for d in self._debates.values())
        total_votes = sum(len(d.votes) for d in self._debates.values())

        verdicts: dict[str, int] = defaultdict(int)
        for d in self._debates.values():
            if d.verdict:
                verdicts[d.verdict.verdict.value] += 1

        return {
            "debates": len(self._debates),
            "completed": completed,
            "total_arguments": total_args,
            "total_votes": total_votes,
            "verdicts": dict(verdicts),
        }
