"""Agent debate system — adversarial multi-model debate.

Implements:
1. Structured debate rounds (advocate vs. challenger)
2. Evidence-based argumentation
3. Judge scoring and resolution
4. Debate history and learning
5. Confidence calibration through debate
6. Debate prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DebateRole(str, Enum):
    ADVOCATE = "advocate"       # Supports the proposition
    CHALLENGER = "challenger"   # Challenges the proposition
    JUDGE = "judge"             # Evaluates arguments


class ArgumentStrength(str, Enum):
    STRONG = "strong"           # Clear evidence, logical
    MODERATE = "moderate"       # Some evidence, reasonable
    WEAK = "weak"               # Little evidence, speculative
    FALLACIOUS = "fallacious"   # Logical fallacy detected


class DebateOutcome(str, Enum):
    ADVOCATE_WINS = "advocate_wins"
    CHALLENGER_WINS = "challenger_wins"
    DRAW = "draw"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Argument:
    """A single argument in a debate."""
    argument_id: str = ""
    role: DebateRole = DebateRole.ADVOCATE
    model_id: str = ""
    round_num: int = 0
    claim: str = ""
    evidence: list[str] = field(default_factory=list)
    strength: ArgumentStrength = ArgumentStrength.MODERATE
    rebuts: str = ""           # ID of argument being rebutted
    score: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value[:5],
            "model": self.model_id[:10],
            "round": self.round_num,
            "strength": self.strength.value[:6],
            "score": f"{self.score:.1f}",
        }


@dataclass
class JudgeVerdict:
    """Judge's verdict on a debate."""
    judge_model: str = ""
    advocate_score: float = 0.0
    challenger_score: float = 0.0
    reasoning: str = ""
    outcome: DebateOutcome = DebateOutcome.INCONCLUSIVE
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value[:10],
            "adv": f"{self.advocate_score:.1f}",
            "chl": f"{self.challenger_score:.1f}",
            "conf": f"{self.confidence:.0%}",
        }


@dataclass
class Debate:
    """A complete debate session."""
    debate_id: str = ""
    proposition: str = ""       # What's being debated
    context: str = ""
    advocate_model: str = ""
    challenger_model: str = ""
    judge_model: str = ""
    arguments: list[Argument] = field(default_factory=list)
    max_rounds: int = 3
    current_round: int = 0
    verdict: JudgeVerdict | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def is_complete(self) -> bool:
        return self.verdict is not None

    @property
    def advocate_args(self) -> list[Argument]:
        return [a for a in self.arguments if a.role == DebateRole.ADVOCATE]

    @property
    def challenger_args(self) -> list[Argument]:
        return [a for a in self.arguments if a.role == DebateRole.CHALLENGER]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.debate_id[:10],
            "prop": self.proposition[:25],
            "rounds": f"{self.current_round}/{self.max_rounds}",
            "complete": self.is_complete,
        }


class AgentDebate:
    """Adversarial multi-model debate for critical decisions.

    Pits models against each other in structured debate
    to rigorously test security findings and decisions.
    Uses advocate/challenger/judge roles.
    """

    def __init__(self) -> None:
        self._debates: dict[str, Debate] = {}
        self._debate_counter = 0
        self._argument_counter = 0
        self._log = logger.bind(component="debate")

    def create_debate(
        self,
        proposition: str,
        context: str = "",
        advocate_model: str = "",
        challenger_model: str = "",
        judge_model: str = "",
        max_rounds: int = 3,
    ) -> Debate:
        """Create a new debate."""
        self._debate_counter += 1

        debate = Debate(
            debate_id=f"dbt-{self._debate_counter}",
            proposition=proposition,
            context=context,
            advocate_model=advocate_model,
            challenger_model=challenger_model,
            judge_model=judge_model,
            max_rounds=max_rounds,
        )

        self._debates[debate.debate_id] = debate
        return debate

    def add_argument(
        self,
        debate_id: str,
        role: DebateRole,
        model_id: str,
        claim: str,
        evidence: list[str] | None = None,
        strength: ArgumentStrength = ArgumentStrength.MODERATE,
        rebuts: str = "",
    ) -> Argument | None:
        """Add an argument to the debate."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        self._argument_counter += 1
        arg = Argument(
            argument_id=f"arg-{self._argument_counter}",
            role=role,
            model_id=model_id,
            round_num=debate.current_round,
            claim=claim,
            evidence=evidence or [],
            strength=strength,
            rebuts=rebuts,
        )

        debate.arguments.append(arg)

        # Score based on strength
        strength_scores = {
            ArgumentStrength.STRONG: 0.9,
            ArgumentStrength.MODERATE: 0.6,
            ArgumentStrength.WEAK: 0.3,
            ArgumentStrength.FALLACIOUS: 0.0,
        }
        arg.score = strength_scores.get(strength, 0.5)

        # Evidence bonus
        arg.score = min(1.0, arg.score + len(arg.evidence) * 0.05)

        # Rebuttal bonus
        if rebuts:
            arg.score = min(1.0, arg.score + 0.1)

        return arg

    def advance_round(self, debate_id: str) -> bool:
        """Advance to next debate round."""
        debate = self._debates.get(debate_id)
        if not debate:
            return False

        if debate.current_round >= debate.max_rounds:
            return False

        debate.current_round += 1
        return True

    def render_verdict(
        self,
        debate_id: str,
        judge_model: str = "",
        reasoning: str = "",
    ) -> JudgeVerdict | None:
        """Judge renders final verdict."""
        debate = self._debates.get(debate_id)
        if not debate:
            return None

        # Score each side
        adv_score = sum(a.score for a in debate.advocate_args)
        chl_score = sum(a.score for a in debate.challenger_args)

        # Normalize
        total = adv_score + chl_score + 1e-10
        adv_norm = adv_score / total
        chl_norm = chl_score / total

        # Determine outcome
        if adv_norm > 0.6:
            outcome = DebateOutcome.ADVOCATE_WINS
        elif chl_norm > 0.6:
            outcome = DebateOutcome.CHALLENGER_WINS
        elif abs(adv_norm - chl_norm) < 0.1:
            outcome = DebateOutcome.DRAW
        else:
            outcome = DebateOutcome.INCONCLUSIVE

        verdict = JudgeVerdict(
            judge_model=judge_model or debate.judge_model,
            advocate_score=adv_norm,
            challenger_score=chl_norm,
            reasoning=reasoning,
            outcome=outcome,
            confidence=abs(adv_norm - chl_norm),
        )

        debate.verdict = verdict
        return verdict

    def build_advocate_prompt(self, debate_id: str) -> str:
        """Build prompt for advocate model."""
        debate = self._debates.get(debate_id)
        if not debate:
            return ""

        lines = [
            "You are the ADVOCATE in a security debate.",
            f"Proposition: {debate.proposition}",
            f"Context: {debate.context[:200]}",
            f"Round: {debate.current_round}/{debate.max_rounds}",
            "\nYour role: SUPPORT this proposition with evidence.",
        ]

        # Include challenger's arguments to rebut
        for arg in debate.challenger_args:
            lines.append(f"\nChallenger argued: {arg.claim[:100]}")

        lines.append("\nProvide: claim, evidence, and rebut any challenger arguments.")
        return "\n".join(lines)

    def build_challenger_prompt(self, debate_id: str) -> str:
        """Build prompt for challenger model."""
        debate = self._debates.get(debate_id)
        if not debate:
            return ""

        lines = [
            "You are the CHALLENGER in a security debate.",
            f"Proposition: {debate.proposition}",
            f"Context: {debate.context[:200]}",
            f"Round: {debate.current_round}/{debate.max_rounds}",
            "\nYour role: CHALLENGE this proposition. Find weaknesses.",
        ]

        for arg in debate.advocate_args:
            lines.append(f"\nAdvocate argued: {arg.claim[:100]}")

        lines.append("\nProvide: counterarguments, evidence against, logical weaknesses.")
        return "\n".join(lines)

    def build_judge_prompt(self, debate_id: str) -> str:
        """Build prompt for judge model."""
        debate = self._debates.get(debate_id)
        if not debate:
            return ""

        lines = [
            "You are the JUDGE in a security debate.",
            f"Proposition: {debate.proposition}",
            f"Rounds completed: {debate.current_round}",
            "\nAdvocate arguments:",
        ]

        for arg in debate.advocate_args:
            lines.append(f"  [{arg.strength.value}] {arg.claim[:80]}")

        lines.append("\nChallenger arguments:")
        for arg in debate.challenger_args:
            lines.append(f"  [{arg.strength.value}] {arg.claim[:80]}")

        lines.append("\nRender verdict: which side presented stronger evidence?")
        return "\n".join(lines)

    def build_debate_prompt(self) -> str:
        """Build debate context for LLM."""
        lines = ["## Debate System\n"]
        lines.append(f"Total debates: {len(self._debates)}")

        completed = [d for d in self._debates.values() if d.is_complete]
        active = [d for d in self._debates.values() if not d.is_complete]

        if active:
            lines.append(f"Active: {len(active)}")
            for d in active[:2]:
                lines.append(f"  {d.proposition[:30]} (round {d.current_round}/{d.max_rounds})")

        if completed:
            lines.append(f"Completed: {len(completed)}")
            for d in completed[-3:]:
                v = d.verdict
                if v:
                    lines.append(
                        f"  [{v.outcome.value[:8]}] {d.proposition[:30]} "
                        f"conf={v.confidence:.0%}"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for d in self._debates.values():
            if d.verdict:
                o = d.verdict.outcome.value
                outcome_counts[o] = outcome_counts.get(o, 0) + 1

        return {
            "total_debates": len(self._debates),
            "total_arguments": self._argument_counter,
            "outcomes": outcome_counts,
        }
