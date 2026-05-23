"""Agent debate — structured debate between agents for better decisions.

Implements:
1. Structured debate protocols
2. Pro/con argument tracking
3. Judge agent evaluation
4. Multiple debate rounds
5. Evidence-based argumentation
6. Argument strength scoring
7. Debate resolution strategies
8. Debate history for learning
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ArgumentType(str, Enum):
    CLAIM = "claim"
    SUPPORT = "support"
    COUNTER = "counter"
    REBUTTAL = "rebuttal"
    EVIDENCE = "evidence"
    CONCESSION = "concession"


class DebateStatus(str, Enum):
    SETUP = "setup"
    OPENING = "opening"
    ROUNDS = "rounds"
    CLOSING = "closing"
    JUDGING = "judging"
    RESOLVED = "resolved"


@dataclass
class Argument:
    """An argument in a debate."""
    argument_id: str = ""
    agent_id: str = ""
    argument_type: ArgumentType = ArgumentType.CLAIM
    position: str = ""             # Which side: pro, con
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    strength: float = 0.5
    responds_to: str = ""          # Argument ID this responds to
    round_number: int = 1
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.argument_id,
            "agent": self.agent_id[:15],
            "type": self.argument_type.value,
            "position": self.position,
            "content": self.content[:80],
            "strength": round(self.strength, 2),
            "round": self.round_number,
        }


@dataclass
class DebateResolution:
    """Resolution of a debate."""
    winner: str = ""               # pro or con
    confidence: float = 0.5
    reasoning: str = ""
    pro_score: float = 0.0
    con_score: float = 0.0
    key_arguments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "winner": self.winner,
            "confidence": round(self.confidence, 2),
            "pro_score": round(self.pro_score, 2),
            "con_score": round(self.con_score, 2),
        }


@dataclass
class Debate:
    """A structured debate between agents."""
    debate_id: str = ""
    topic: str = ""
    pro_agent: str = ""
    con_agent: str = ""
    judge_agent: str = ""
    arguments: list[Argument] = field(default_factory=list)
    max_rounds: int = 3
    current_round: int = 0
    status: DebateStatus = DebateStatus.SETUP
    resolution: DebateResolution | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def pro_arguments(self) -> list[Argument]:
        return [a for a in self.arguments if a.position == "pro"]

    @property
    def con_arguments(self) -> list[Argument]:
        return [a for a in self.arguments if a.position == "con"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.debate_id,
            "topic": self.topic[:60],
            "status": self.status.value,
            "round": self.current_round,
            "pro_args": len(self.pro_arguments),
            "con_args": len(self.con_arguments),
            "resolved": self.resolution is not None,
        }


class AgentDebate:
    """Structured debate between agents for better decisions.

    Two agents argue pro/con positions, a judge evaluates.
    Used for high-stakes decisions and finding validation.
    """

    def __init__(self) -> None:
        self._debates: dict[str, Debate] = {}
        self._debate_counter = 0
        self._argument_counter = 0
        self._log = logger.bind(component="agent_debate")

    def create_debate(
        self,
        topic: str,
        pro_agent: str,
        con_agent: str,
        judge_agent: str = "",
        max_rounds: int = 3,
    ) -> Debate:
        """Create a new debate."""
        self._debate_counter += 1
        debate = Debate(
            debate_id=f"debate-{self._debate_counter}",
            topic=topic,
            pro_agent=pro_agent,
            con_agent=con_agent,
            judge_agent=judge_agent,
            max_rounds=max_rounds,
        )
        self._debates[debate.debate_id] = debate
        return debate

    def add_argument(
        self,
        debate_id: str,
        agent_id: str,
        argument_type: ArgumentType,
        content: str,
        evidence: list[str] | None = None,
        strength: float = 0.5,
        responds_to: str = "",
    ) -> Argument:
        """Add an argument to the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return Argument()

        self._argument_counter += 1

        # Determine position based on agent
        if agent_id == debate.pro_agent:
            position = "pro"
        elif agent_id == debate.con_agent:
            position = "con"
        else:
            position = "judge"

        argument = Argument(
            argument_id=f"arg-{self._argument_counter}",
            agent_id=agent_id,
            argument_type=argument_type,
            position=position,
            content=content,
            evidence=evidence or [],
            strength=strength,
            responds_to=responds_to,
            round_number=debate.current_round,
        )

        debate.arguments.append(argument)

        if debate.status == DebateStatus.SETUP:
            debate.status = DebateStatus.OPENING
            debate.current_round = 1

        return argument

    def advance_round(self, debate_id: str) -> int:
        """Advance to the next debate round."""
        debate = self._debates.get(debate_id)
        if not debate:
            return 0

        debate.current_round += 1

        if debate.current_round > debate.max_rounds:
            debate.status = DebateStatus.JUDGING

        return debate.current_round

    def judge(self, debate_id: str) -> DebateResolution:
        """Judge the debate and produce a resolution."""
        debate = self._debates.get(debate_id)
        if not debate:
            return DebateResolution()

        debate.status = DebateStatus.JUDGING

        # Score arguments
        pro_score = self._score_position(debate.pro_arguments)
        con_score = self._score_position(debate.con_arguments)

        # Determine winner
        total = pro_score + con_score
        if total == 0:
            winner = "inconclusive"
            confidence = 0.0
        elif pro_score > con_score:
            winner = "pro"
            confidence = pro_score / total
        elif con_score > pro_score:
            winner = "con"
            confidence = con_score / total
        else:
            winner = "tie"
            confidence = 0.5

        # Find key arguments
        all_args = sorted(debate.arguments, key=lambda a: a.strength, reverse=True)
        key_args = [a.content[:80] for a in all_args[:3]]

        resolution = DebateResolution(
            winner=winner,
            confidence=confidence,
            pro_score=pro_score,
            con_score=con_score,
            key_arguments=key_args,
        )

        debate.resolution = resolution
        debate.status = DebateStatus.RESOLVED

        return resolution

    def _score_position(self, arguments: list[Argument]) -> float:
        """Score a debate position."""
        if not arguments:
            return 0.0

        score = 0.0

        for arg in arguments:
            base_score = arg.strength

            # Argument type multipliers
            type_multipliers = {
                ArgumentType.CLAIM: 1.0,
                ArgumentType.SUPPORT: 1.2,
                ArgumentType.EVIDENCE: 1.5,
                ArgumentType.COUNTER: 1.3,
                ArgumentType.REBUTTAL: 1.4,
                ArgumentType.CONCESSION: 0.5,
            }
            multiplier = type_multipliers.get(arg.argument_type, 1.0)

            # Evidence boost
            evidence_boost = min(0.5, len(arg.evidence) * 0.1)

            score += base_score * multiplier + evidence_boost

        return score

    def get_unresolved_arguments(
        self,
        debate_id: str,
    ) -> list[dict[str, Any]]:
        """Get arguments that haven't been responded to."""
        debate = self._debates.get(debate_id)
        if not debate:
            return []

        responded_to = {a.responds_to for a in debate.arguments if a.responds_to}
        unresolved = [
            a for a in debate.arguments
            if a.argument_id not in responded_to
            and a.argument_type in (ArgumentType.CLAIM, ArgumentType.COUNTER)
        ]

        return [a.to_dict() for a in unresolved]

    def get_debate_summary(self, debate_id: str) -> dict[str, Any]:
        """Get a summary of the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return {}

        summary = debate.to_dict()
        if debate.resolution:
            summary["resolution"] = debate.resolution.to_dict()

        return summary

    def get_stats(self) -> dict[str, Any]:
        resolved = sum(1 for d in self._debates.values() if d.resolution)
        return {
            "debates": len(self._debates),
            "resolved": resolved,
            "total_arguments": self._argument_counter,
        }
