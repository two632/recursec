"""Agent debate engine — multi-model adversarial debate.

Implements:
1. Structured debate protocol (advocate vs challenger)
2. Judge model for resolution
3. Evidence-based argumentation
4. Confidence calibration
5. Consensus detection
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
    ADVOCATE = "advocate"       # Argues FOR the finding
    CHALLENGER = "challenger"   # Argues AGAINST
    JUDGE = "judge"             # Makes final decision
    OBSERVER = "observer"       # Provides context


class ArgumentType(str, Enum):
    CLAIM = "claim"             # Initial assertion
    EVIDENCE = "evidence"       # Supporting evidence
    REBUTTAL = "rebuttal"       # Counter-argument
    CONCESSION = "concession"   # Partial agreement
    SYNTHESIS = "synthesis"     # Combined view


class DebateOutcome(str, Enum):
    CONFIRMED = "confirmed"         # Finding is valid
    REJECTED = "rejected"           # Finding is false positive
    MODIFIED = "modified"           # Finding valid but needs adjustment
    INCONCLUSIVE = "inconclusive"   # Needs more evidence
    ESCALATED = "escalated"         # Needs human review


@dataclass
class Argument:
    """A single argument in the debate."""
    argument_id: str = ""
    role: DebateRole = DebateRole.ADVOCATE
    arg_type: ArgumentType = ArgumentType.CLAIM
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    model_name: str = ""
    responds_to: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value[:8],
            "type": self.arg_type.value[:7],
            "conf": f"{self.confidence:.2f}",
            "content": self.content[:25],
        }


@dataclass
class DebateSession:
    """A complete debate session."""
    debate_id: str = ""
    topic: str = ""
    finding: dict[str, Any] = field(default_factory=dict)
    arguments: list[Argument] = field(default_factory=list)
    advocate_model: str = ""
    challenger_model: str = ""
    judge_model: str = ""
    outcome: DebateOutcome = DebateOutcome.INCONCLUSIVE
    final_confidence: float = 0.0
    rounds: int = 0
    max_rounds: int = 3
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic[:20],
            "rounds": self.rounds,
            "outcome": self.outcome.value[:10],
            "conf": f"{self.final_confidence:.2f}",
        }


# Model assignments for debate roles
DEBATE_MODELS: dict[DebateRole, list[str]] = {
    DebateRole.ADVOCATE: ["WhiteRabbitNeo", "Dolphin-2.9"],
    DebateRole.CHALLENGER: ["Qwen2.5-Coder-14B", "Hermes-4-14B"],
    DebateRole.JUDGE: ["DeepSeek-R1", "Hermes-4-14B"],
}


class AgentDebateEngine:
    """Multi-model adversarial debate for findings.

    Uses structured debate to validate critical
    findings through adversarial argumentation.
    """

    def __init__(self, max_rounds: int = 3) -> None:
        self._debates: dict[str, DebateSession] = {}
        self._debate_counter = 0
        self._argument_counter = 0
        self._max_rounds = max_rounds
        self._log = logger.bind(component="debate")

    def start_debate(
        self,
        topic: str,
        finding: dict[str, Any],
        advocate_model: str = "",
        challenger_model: str = "",
        judge_model: str = "",
    ) -> DebateSession:
        """Start a new debate session."""
        self._debate_counter += 1

        if not advocate_model:
            advocate_model = DEBATE_MODELS[DebateRole.ADVOCATE][0]
        if not challenger_model:
            challenger_model = DEBATE_MODELS[DebateRole.CHALLENGER][0]
        if not judge_model:
            judge_model = DEBATE_MODELS[DebateRole.JUDGE][0]

        session = DebateSession(
            debate_id=f"debate-{self._debate_counter}",
            topic=topic,
            finding=finding,
            advocate_model=advocate_model,
            challenger_model=challenger_model,
            judge_model=judge_model,
            max_rounds=self._max_rounds,
        )
        self._debates[session.debate_id] = session
        return session

    def add_argument(
        self,
        debate_id: str,
        role: DebateRole,
        arg_type: ArgumentType,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        model_name: str = "",
        responds_to: str = "",
    ) -> Argument:
        """Add an argument to the debate."""
        self._argument_counter += 1

        arg = Argument(
            argument_id=f"arg-{self._argument_counter}",
            role=role,
            arg_type=arg_type,
            content=content,
            evidence=evidence or [],
            confidence=confidence,
            model_name=model_name,
            responds_to=responds_to,
        )

        session = self._debates.get(debate_id)
        if session:
            session.arguments.append(arg)
            session.rounds = max(
                session.rounds,
                sum(1 for a in session.arguments if a.role == DebateRole.ADVOCATE),
            )

        return arg

    def should_continue(self, debate_id: str) -> bool:
        """Check if the debate should continue."""
        session = self._debates.get(debate_id)
        if not session:
            return False

        # Max rounds reached
        if session.rounds >= session.max_rounds:
            return False

        # Check for early consensus
        if len(session.arguments) >= 4:
            advocate_conf = [
                a.confidence for a in session.arguments
                if a.role == DebateRole.ADVOCATE
            ]
            challenger_conf = [
                a.confidence for a in session.arguments
                if a.role == DebateRole.CHALLENGER
            ]

            if advocate_conf and challenger_conf:
                avg_adv = sum(advocate_conf) / len(advocate_conf)
                avg_cha = sum(challenger_conf) / len(challenger_conf)

                # Strong consensus (both sides agree)
                if abs(avg_adv - avg_cha) < 0.15:
                    return False

                # One side clearly dominant
                if max(avg_adv, avg_cha) > 0.9:
                    return False

        return True

    def resolve(
        self,
        debate_id: str,
        judge_verdict: str = "",
        judge_confidence: float = 0.0,
    ) -> DebateOutcome:
        """Resolve the debate with a judge verdict."""
        session = self._debates.get(debate_id)
        if not session:
            return DebateOutcome.INCONCLUSIVE

        # Calculate from arguments if no judge
        if not judge_confidence:
            judge_confidence = self._calculate_confidence(debate_id)

        # Determine outcome
        if judge_confidence >= 0.8:
            outcome = DebateOutcome.CONFIRMED
        elif judge_confidence >= 0.5:
            outcome = DebateOutcome.MODIFIED
        elif judge_confidence >= 0.3:
            outcome = DebateOutcome.INCONCLUSIVE
        else:
            outcome = DebateOutcome.REJECTED

        session.outcome = outcome
        session.final_confidence = judge_confidence
        session.ended_at = time.time()

        # Add judge argument
        if judge_verdict:
            self.add_argument(
                debate_id,
                DebateRole.JUDGE,
                ArgumentType.SYNTHESIS,
                judge_verdict,
                confidence=judge_confidence,
                model_name=session.judge_model,
            )

        return outcome

    def _calculate_confidence(self, debate_id: str) -> float:
        """Calculate confidence from debate arguments."""
        session = self._debates.get(debate_id)
        if not session or not session.arguments:
            return 0.5

        advocate_strength = 0.0
        challenger_strength = 0.0
        evidence_count = 0

        for arg in session.arguments:
            if arg.role == DebateRole.ADVOCATE:
                advocate_strength += arg.confidence
                evidence_count += len(arg.evidence)
            elif arg.role == DebateRole.CHALLENGER:
                challenger_strength += arg.confidence

        total = advocate_strength + challenger_strength
        if total == 0:
            return 0.5

        # Advocate ratio
        ratio = advocate_strength / total

        # Evidence bonus
        evidence_bonus = min(0.1, evidence_count * 0.02)

        return min(1.0, ratio + evidence_bonus)

    def build_debate_prompt(self, debate_id: str = "") -> str:
        """Build debate context for LLM."""
        if debate_id and debate_id in self._debates:
            return self._build_session_detail(debate_id)

        lines = ["## Debates\n"]
        lines.append(f"Total: {len(self._debates)}")

        confirmed = sum(
            1 for d in self._debates.values()
            if d.outcome == DebateOutcome.CONFIRMED
        )
        rejected = sum(
            1 for d in self._debates.values()
            if d.outcome == DebateOutcome.REJECTED
        )
        lines.append(f"Confirmed: {confirmed}, Rejected: {rejected}")

        # Recent debates
        recent = sorted(
            self._debates.values(),
            key=lambda d: d.started_at,
            reverse=True,
        )[:3]
        for d in recent:
            lines.append(
                f"\n[{d.outcome.value[:8]}] {d.topic[:20]} "
                f"(conf={d.final_confidence:.2f})"
            )

        return "\n".join(lines)

    def _build_session_detail(self, debate_id: str) -> str:
        """Build detailed view of a debate session."""
        session = self._debates.get(debate_id)
        if not session:
            return ""

        lines = [f"## Debate: {session.topic}\n"]
        lines.append(f"Rounds: {session.rounds}/{session.max_rounds}")
        lines.append(f"Outcome: {session.outcome.value}")
        lines.append(f"Confidence: {session.final_confidence:.2f}")

        for arg in session.arguments:
            prefix = {
                DebateRole.ADVOCATE: "ADV",
                DebateRole.CHALLENGER: "CHA",
                DebateRole.JUDGE: "JDG",
                DebateRole.OBSERVER: "OBS",
            }.get(arg.role, "???")
            lines.append(
                f"  [{prefix}] ({arg.confidence:.2f}) "
                f"{arg.content[:35]}"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = {}
        for d in self._debates.values():
            outcome_counts[d.outcome.value] = (
                outcome_counts.get(d.outcome.value, 0) + 1
            )

        return {
            "debates": len(self._debates),
            "total_arguments": sum(
                len(d.arguments) for d in self._debates.values()
            ),
            "by_outcome": outcome_counts,
        }


# Alias for backward compatibility
AgentDebate = AgentDebateEngine
