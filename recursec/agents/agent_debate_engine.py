"""Agent debate engine — multi-model deliberation for critical decisions.

Implements:
1. Structured debates between multiple LLM agents
2. Argument tracking with evidence
3. Rebuttal and counter-argument chains
4. Voting and consensus mechanisms
5. Judge agent for final decision
6. Debate history for learning
7. Debate prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DebateRole(str, Enum):
    PROPOSER = "proposer"        # Makes initial claim
    OPPONENT = "opponent"        # Challenges claim
    JUDGE = "judge"              # Makes final decision
    WITNESS = "witness"          # Provides evidence


class ArgumentType(str, Enum):
    CLAIM = "claim"
    EVIDENCE = "evidence"
    REBUTTAL = "rebuttal"
    COUNTER = "counter"
    CONCESSION = "concession"
    SYNTHESIS = "synthesis"


class DebateStatus(str, Enum):
    OPENING = "opening"
    ARGUMENTATION = "argumentation"
    REBUTTAL = "rebuttal"
    CLOSING = "closing"
    VERDICT = "verdict"
    COMPLETED = "completed"


class VerdictType(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Argument:
    """A single argument in a debate."""
    arg_id: str = ""
    debate_id: str = ""
    role: DebateRole = DebateRole.PROPOSER
    arg_type: ArgumentType = ArgumentType.CLAIM
    model_id: str = ""
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    references: list[str] = field(default_factory=list)  # Referenced arg_ids
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.arg_id[:8],
            "role": self.role.value[:6],
            "type": self.arg_type.value[:6],
            "model": self.model_id[:12],
            "conf": round(self.confidence, 2),
        }


@dataclass
class Verdict:
    """A debate verdict."""
    verdict_type: VerdictType = VerdictType.INCONCLUSIVE
    judge_model: str = ""
    reasoning: str = ""
    confidence: float = 0.0
    votes: dict[str, bool] = field(default_factory=dict)  # model_id → agree
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        agree = sum(1 for v in self.votes.values() if v)
        disagree = len(self.votes) - agree
        return {
            "verdict": self.verdict_type.value[:8],
            "judge": self.judge_model[:12],
            "conf": round(self.confidence, 2),
            "votes": f"{agree}/{agree + disagree}",
        }


@dataclass
class Debate:
    """A structured debate between models."""
    debate_id: str = ""
    topic: str = ""
    context: str = ""
    status: DebateStatus = DebateStatus.OPENING
    arguments: list[Argument] = field(default_factory=list)
    participants: dict[str, DebateRole] = field(default_factory=dict)
    verdict: Verdict | None = None
    max_rounds: int = 3
    current_round: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def is_complete(self) -> bool:
        return self.status == DebateStatus.COMPLETED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.debate_id[:10],
            "topic": self.topic[:25],
            "status": self.status.value[:8],
            "args": len(self.arguments),
            "round": f"{self.current_round}/{self.max_rounds}",
            "verdict": self.verdict.verdict_type.value if self.verdict else "pending",
        }


class AgentDebateEngine:
    """Multi-model debate for critical security decisions.

    When a finding is ambiguous or high-impact,
    multiple models debate its validity, severity,
    and exploitation potential.
    """

    def __init__(self, max_concurrent: int = 3) -> None:
        self._debates: dict[str, Debate] = {}
        self._counter = 0
        self._max_concurrent = max_concurrent
        self._log = logger.bind(component="debate_engine")

    def create_debate(
        self,
        topic: str,
        context: str = "",
        participants: dict[str, DebateRole] | None = None,
        max_rounds: int = 3,
    ) -> Debate:
        """Create a new debate."""
        self._counter += 1
        debate = Debate(
            debate_id=f"debate-{self._counter}",
            topic=topic,
            context=context,
            participants=participants or {},
            max_rounds=max_rounds,
        )
        self._debates[debate.debate_id] = debate
        return debate

    def add_argument(
        self,
        debate_id: str,
        role: DebateRole,
        arg_type: ArgumentType,
        model_id: str,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        references: list[str] | None = None,
    ) -> Argument | None:
        """Add an argument to a debate."""
        debate = self._debates.get(debate_id)
        if not debate or debate.is_complete:
            return None

        self._counter += 1
        arg = Argument(
            arg_id=f"arg-{self._counter}",
            debate_id=debate_id,
            role=role,
            arg_type=arg_type,
            model_id=model_id,
            content=content,
            evidence=evidence or [],
            confidence=confidence,
            references=references or [],
        )
        debate.arguments.append(arg)

        # Update participant
        if model_id not in debate.participants:
            debate.participants[model_id] = role

        return arg

    def advance_round(self, debate_id: str) -> bool:
        """Advance debate to next round."""
        debate = self._debates.get(debate_id)
        if not debate or debate.is_complete:
            return False

        debate.current_round += 1

        if debate.current_round == 1:
            debate.status = DebateStatus.ARGUMENTATION
        elif debate.current_round == 2:
            debate.status = DebateStatus.REBUTTAL
        elif debate.current_round >= debate.max_rounds:
            debate.status = DebateStatus.CLOSING

        return True

    def submit_verdict(
        self,
        debate_id: str,
        verdict_type: VerdictType,
        judge_model: str,
        reasoning: str = "",
        confidence: float = 0.0,
        votes: dict[str, bool] | None = None,
    ) -> Verdict | None:
        """Submit a verdict for a debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        verdict = Verdict(
            verdict_type=verdict_type,
            judge_model=judge_model,
            reasoning=reasoning,
            confidence=confidence,
            votes=votes or {},
        )
        debate.verdict = verdict
        debate.status = DebateStatus.COMPLETED

        return verdict

    def build_debate_transcript(self, debate_id: str) -> str:
        """Build readable debate transcript."""
        debate = self._debates.get(debate_id)
        if not debate:
            return "No debate found."

        lines = [f"## Debate: {debate.topic}\n"]
        lines.append(f"Status: {debate.status.value} | Round: {debate.current_round}/{debate.max_rounds}")

        for arg in debate.arguments:
            role_label = arg.role.value.upper()
            lines.append(
                f"\n[{role_label}] ({arg.model_id[:12]}, "
                f"conf={arg.confidence:.0%}):"
            )
            lines.append(f"  {arg.content[:100]}")
            if arg.evidence:
                lines.append(f"  Evidence: {', '.join(arg.evidence[:3])}")

        if debate.verdict:
            v = debate.verdict
            lines.append(f"\n[VERDICT] {v.verdict_type.value.upper()}")
            lines.append(f"  Judge: {v.judge_model[:12]} (conf={v.confidence:.0%})")
            if v.reasoning:
                lines.append(f"  Reasoning: {v.reasoning[:100]}")

        return "\n".join(lines)

    def build_debate_prompt(self) -> str:
        """Build debate engine context for LLM."""
        lines = ["## Debate Engine\n"]
        lines.append(f"Total debates: {len(self._debates)}")

        active = [d for d in self._debates.values() if not d.is_complete]
        completed = [d for d in self._debates.values() if d.is_complete]
        lines.append(f"Active: {len(active)} | Completed: {len(completed)}")

        # Recent verdicts
        if completed:
            lines.append("\nRecent verdicts:")
            for d in completed[-3:]:
                if d.verdict:
                    lines.append(
                        f"  {d.topic[:25]} → {d.verdict.verdict_type.value} "
                        f"(conf={d.verdict.confidence:.0%})"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        verdicts: dict[str, int] = {}
        for d in self._debates.values():
            if d.verdict:
                v = d.verdict.verdict_type.value
                verdicts[v] = verdicts.get(v, 0) + 1

        return {
            "total_debates": len(self._debates),
            "total_arguments": sum(len(d.arguments) for d in self._debates.values()),
            "verdicts": verdicts,
        }
