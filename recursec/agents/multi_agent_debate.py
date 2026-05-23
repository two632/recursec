"""Multi-agent debate — adversarial debate for better reasoning.

Implements:
1. Structured debate between agents with different perspectives
2. Proposition-rebuttal-verdict protocol
3. Evidence-based argumentation
4. Majority voting and weighted consensus
5. Devil's advocate mode
6. Debate scoring and quality metrics
7. Iterative refinement through debate rounds
8. Deadlock detection and resolution
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
    PROPOSER = "proposer"
    CHALLENGER = "challenger"
    JUDGE = "judge"
    DEVILS_ADVOCATE = "devils_advocate"
    MEDIATOR = "mediator"


class ArgumentType(str, Enum):
    CLAIM = "claim"
    EVIDENCE = "evidence"
    REBUTTAL = "rebuttal"
    CONCESSION = "concession"
    SYNTHESIS = "synthesis"


class DebateStatus(str, Enum):
    SETUP = "setup"
    IN_PROGRESS = "in_progress"
    VOTING = "voting"
    RESOLVED = "resolved"
    DEADLOCKED = "deadlocked"


class VerdictType(str, Enum):
    PROPOSITION_WINS = "proposition_wins"
    CHALLENGE_WINS = "challenge_wins"
    SYNTHESIS = "synthesis"
    DEADLOCK = "deadlock"


@dataclass
class Argument:
    """An argument made during debate."""
    arg_id: str = ""
    author: str = ""
    role: DebateRole = DebateRole.PROPOSER
    arg_type: ArgumentType = ArgumentType.CLAIM
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    rebuts: str = ""           # ID of argument being rebutted
    strength: float = 0.5      # 0-1 score
    round_num: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.arg_id,
            "author": self.author[:15],
            "role": self.role.value,
            "type": self.arg_type.value,
            "strength": round(self.strength, 2),
            "round": self.round_num,
        }


@dataclass
class DebateParticipant:
    """A participant in the debate."""
    participant_id: str = ""
    name: str = ""
    role: DebateRole = DebateRole.PROPOSER
    model: str = ""
    position: str = ""
    arguments_made: int = 0
    avg_strength: float = 0.0
    concessions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.participant_id,
            "name": self.name[:15],
            "role": self.role.value,
            "model": self.model[:15],
            "args": self.arguments_made,
            "avg_str": round(self.avg_strength, 2),
        }


@dataclass
class DebateRound:
    """A round in the debate."""
    round_num: int = 0
    arguments: list[str] = field(default_factory=list)    # arg IDs
    summary: str = ""
    key_disagreements: list[str] = field(default_factory=list)
    progress: float = 0.0     # 0-1, how close to resolution

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round_num,
            "args": len(self.arguments),
            "progress": round(self.progress, 2),
        }


@dataclass
class Verdict:
    """Final verdict of the debate."""
    verdict_type: VerdictType = VerdictType.DEADLOCK
    winning_position: str = ""
    confidence: float = 0.0
    rationale: str = ""
    dissenting_opinions: list[str] = field(default_factory=list)
    key_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.verdict_type.value,
            "confidence": round(self.confidence, 2),
            "dissents": len(self.dissenting_opinions),
        }


@dataclass
class Debate:
    """A complete debate session."""
    debate_id: str = ""
    topic: str = ""
    status: DebateStatus = DebateStatus.SETUP
    participants: dict[str, DebateParticipant] = field(default_factory=dict)
    arguments: dict[str, Argument] = field(default_factory=dict)
    rounds: list[DebateRound] = field(default_factory=list)
    current_round: int = 0
    max_rounds: int = 5
    verdict: Verdict | None = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.debate_id,
            "topic": self.topic[:30],
            "status": self.status.value,
            "participants": len(self.participants),
            "round": f"{self.current_round}/{self.max_rounds}",
            "args": len(self.arguments),
        }


class MultiAgentDebate:
    """Adversarial debate between agents for better reasoning.

    Uses structured argumentation where agents take opposing
    positions to stress-test hypotheses and findings.
    """

    def __init__(self) -> None:
        self._debates: dict[str, Debate] = {}
        self._debate_counter = 0
        self._arg_counter = 0
        self._participant_counter = 0
        self._log = logger.bind(component="multi_agent_debate")

    def create_debate(
        self,
        topic: str,
        max_rounds: int = 5,
    ) -> Debate:
        """Create a new debate."""
        self._debate_counter += 1
        debate = Debate(
            debate_id=f"debate-{self._debate_counter}",
            topic=topic,
            max_rounds=max_rounds,
        )
        self._debates[debate.debate_id] = debate
        return debate

    def add_participant(
        self,
        debate_id: str,
        name: str,
        role: DebateRole,
        model: str = "",
        position: str = "",
    ) -> DebateParticipant | None:
        """Add a participant to a debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        self._participant_counter += 1
        participant = DebateParticipant(
            participant_id=f"dp-{self._participant_counter}",
            name=name,
            role=role,
            model=model,
            position=position,
        )
        debate.participants[participant.participant_id] = participant
        return participant

    def submit_argument(
        self,
        debate_id: str,
        author_id: str,
        arg_type: ArgumentType,
        content: str,
        evidence: list[str] | None = None,
        rebuts: str = "",
        strength: float = 0.5,
    ) -> Argument | None:
        """Submit an argument to the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        participant = debate.participants.get(author_id)
        if not participant:
            return None

        if debate.status == DebateStatus.SETUP:
            debate.status = DebateStatus.IN_PROGRESS

        self._arg_counter += 1
        arg = Argument(
            arg_id=f"arg-{self._arg_counter}",
            author=author_id,
            role=participant.role,
            arg_type=arg_type,
            content=content,
            evidence=evidence or [],
            rebuts=rebuts,
            strength=strength,
            round_num=debate.current_round,
        )
        debate.arguments[arg.arg_id] = arg

        # Update participant stats
        participant.arguments_made += 1
        total_strength = participant.avg_strength * (participant.arguments_made - 1) + strength
        participant.avg_strength = total_strength / participant.arguments_made

        if arg_type == ArgumentType.CONCESSION:
            participant.concessions += 1

        return arg

    def advance_round(self, debate_id: str) -> DebateRound | None:
        """Advance to the next debate round."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        if debate.current_round >= debate.max_rounds:
            return None

        # Collect arguments for current round
        round_args = [
            arg_id for arg_id, arg in debate.arguments.items()
            if arg.round_num == debate.current_round
        ]

        # Calculate progress
        progress = self._calculate_progress(debate)

        current_round = DebateRound(
            round_num=debate.current_round,
            arguments=round_args,
            progress=progress,
        )
        debate.rounds.append(current_round)

        # Check for deadlock
        if len(debate.rounds) >= 3:
            recent_progress = [r.progress for r in debate.rounds[-3:]]
            if all(abs(p - recent_progress[0]) < 0.05 for p in recent_progress):
                debate.status = DebateStatus.DEADLOCKED
                return current_round

        debate.current_round += 1

        # Check if max rounds reached
        if debate.current_round >= debate.max_rounds:
            debate.status = DebateStatus.VOTING

        return current_round

    def render_verdict(self, debate_id: str) -> Verdict | None:
        """Render a verdict on the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        # Score each position
        proposer_score = 0.0
        challenger_score = 0.0
        proposer_count = 0
        challenger_count = 0

        for arg in debate.arguments.values():
            if arg.role == DebateRole.PROPOSER:
                proposer_score += arg.strength
                proposer_count += 1
            elif arg.role in (DebateRole.CHALLENGER, DebateRole.DEVILS_ADVOCATE):
                challenger_score += arg.strength
                challenger_count += 1

        # Normalize
        if proposer_count > 0:
            proposer_score /= proposer_count
        if challenger_count > 0:
            challenger_score /= challenger_count

        # Account for concessions
        for p in debate.participants.values():
            if p.role == DebateRole.PROPOSER and p.concessions > 0:
                proposer_score -= p.concessions * 0.1
            elif p.role == DebateRole.CHALLENGER and p.concessions > 0:
                challenger_score -= p.concessions * 0.1

        # Determine verdict
        diff = proposer_score - challenger_score

        if abs(diff) < 0.1:
            verdict = Verdict(
                verdict_type=VerdictType.SYNTHESIS,
                confidence=0.5 + abs(diff),
                rationale="Positions are close; synthesis of both views recommended",
            )
        elif diff > 0:
            proposer = next(
                (p for p in debate.participants.values() if p.role == DebateRole.PROPOSER),
                None,
            )
            verdict = Verdict(
                verdict_type=VerdictType.PROPOSITION_WINS,
                winning_position=proposer.position if proposer else "",
                confidence=min(0.95, 0.5 + diff),
                rationale=f"Proposer arguments stronger by {diff:.2f}",
            )
        else:
            challenger = next(
                (p for p in debate.participants.values()
                 if p.role in (DebateRole.CHALLENGER, DebateRole.DEVILS_ADVOCATE)),
                None,
            )
            verdict = Verdict(
                verdict_type=VerdictType.CHALLENGE_WINS,
                winning_position=challenger.position if challenger else "",
                confidence=min(0.95, 0.5 + abs(diff)),
                rationale=f"Challenger arguments stronger by {abs(diff):.2f}",
            )

        # Collect dissenting opinions
        losing_role = DebateRole.CHALLENGER if diff > 0 else DebateRole.PROPOSER
        for arg in debate.arguments.values():
            if arg.role == losing_role and arg.strength >= 0.7:
                verdict.dissenting_opinions.append(arg.content[:100])

        debate.verdict = verdict
        debate.status = DebateStatus.RESOLVED

        return verdict

    @staticmethod
    def _calculate_progress(debate: Debate) -> float:
        """Calculate debate progress toward resolution."""
        if not debate.arguments:
            return 0.0

        # Progress increases with concessions and high-strength arguments
        concession_count = sum(
            1 for arg in debate.arguments.values()
            if arg.arg_type == ArgumentType.CONCESSION
        )
        synthesis_count = sum(
            1 for arg in debate.arguments.values()
            if arg.arg_type == ArgumentType.SYNTHESIS
        )

        base_progress = min(0.5, debate.current_round / max(1, debate.max_rounds))
        concession_bonus = min(0.3, concession_count * 0.1)
        synthesis_bonus = min(0.2, synthesis_count * 0.1)

        return min(1.0, base_progress + concession_bonus + synthesis_bonus)

    def generate_debate_prompt(
        self,
        debate_id: str,
        participant_id: str,
    ) -> str:
        """Generate a prompt for a participant's next argument."""
        debate = self._debates.get(debate_id)
        if not debate:
            return ""

        participant = debate.participants.get(participant_id)
        if not participant:
            return ""

        # Get recent arguments
        recent_args = sorted(
            debate.arguments.values(),
            key=lambda a: (a.round_num, a.arg_id),
        )[-5:]

        history = ""
        for arg in recent_args:
            author = debate.participants.get(arg.author)
            author_name = author.name if author else "Unknown"
            history += f"\n[{author_name} ({arg.role.value})]: {arg.content[:200]}\n"

        role_instruction = {
            DebateRole.PROPOSER: "Defend your position with evidence. Address any rebuttals.",
            DebateRole.CHALLENGER: "Challenge the proposition. Find weaknesses in their argument.",
            DebateRole.DEVILS_ADVOCATE: "Take the opposite position. Stress-test every claim.",
            DebateRole.JUDGE: "Evaluate the strength of arguments from both sides.",
            DebateRole.MEDIATOR: "Find common ground and synthesize positions.",
        }

        return (
            f"Debate topic: {debate.topic}\n\n"
            f"Your role: {participant.role.value}\n"
            f"Your position: {participant.position}\n\n"
            f"Instruction: {role_instruction.get(participant.role, '')}\n\n"
            f"Recent arguments:{history}\n\n"
            f"Provide your response. Include evidence to support your claims."
        )

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for debate in self._debates.values():
            status_counts[debate.status.value] += 1
        return {
            "debates": len(self._debates),
            "by_status": dict(status_counts),
            "total_arguments": sum(
                len(d.arguments) for d in self._debates.values()
            ),
        }
