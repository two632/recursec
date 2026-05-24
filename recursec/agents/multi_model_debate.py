"""Multi-model debate engine — adversarial reasoning with multiple LLMs.

Makes the agent massively more intelligent by:
1. Routing a question to 2-4 different models simultaneously
2. Having each model critique the others' answers
3. Running multiple rounds of debate until consensus or majority
4. Using model-specific strengths (security specialist vs coder vs reasoner)
5. Detecting hallucination through cross-model disagreement
6. Producing higher-quality analysis than any single model

This is the "wisdom of crowds" applied to LLMs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DebateRole(str, Enum):
    PROPOSER = "proposer"
    CRITIC = "critic"
    JUDGE = "judge"
    DEVIL_ADVOCATE = "devil_advocate"


class DebateStatus(str, Enum):
    PENDING = "pending"
    ROUND_IN_PROGRESS = "round_in_progress"
    CONSENSUS_REACHED = "consensus_reached"
    MAJORITY_REACHED = "majority_reached"
    DEADLOCK = "deadlock"
    COMPLETED = "completed"


@dataclass
class DebateArgument:
    """A single argument in a debate."""
    model_id: str = ""
    role: DebateRole = DebateRole.PROPOSER
    round_num: int = 0
    content: str = ""
    confidence: float = 0.5
    key_claims: list[str] = field(default_factory=list)
    critique_of: str = ""
    agreements: list[str] = field(default_factory=list)
    disagreements: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "role": self.role.value[:8],
            "round": self.round_num,
            "conf": f"{self.confidence:.2f}",
            "claims": len(self.key_claims),
        }


@dataclass
class DebateSession:
    """A multi-model debate session."""
    session_id: str = ""
    question: str = ""
    context: str = ""
    participants: list[str] = field(default_factory=list)
    arguments: list[DebateArgument] = field(default_factory=list)
    current_round: int = 0
    max_rounds: int = 3
    status: DebateStatus = DebateStatus.PENDING
    consensus: str = ""
    consensus_confidence: float = 0.0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:8],
            "question": self.question[:25],
            "participants": len(self.participants),
            "round": f"{self.current_round}/{self.max_rounds}",
            "status": self.status.value[:10],
            "consensus_conf": f"{self.consensus_confidence:.2f}",
        }


# Model debate roles based on their strengths
MODEL_DEBATE_ROLES: dict[str, dict[str, Any]] = {
    "whiterabbit": {"primary_role": DebateRole.PROPOSER, "strength": "security_analysis", "weight": 1.5},
    "qwen-coder-14b": {"primary_role": DebateRole.CRITIC, "strength": "code_analysis", "weight": 1.4},
    "deepseek-r1": {"primary_role": DebateRole.JUDGE, "strength": "logical_reasoning", "weight": 1.3},
    "hermes-4-14b": {"primary_role": DebateRole.PROPOSER, "strength": "general_analysis", "weight": 1.2},
    "qwen-coder-7b": {"primary_role": DebateRole.CRITIC, "strength": "code_review", "weight": 1.0},
    "codellama-13b": {"primary_role": DebateRole.CRITIC, "strength": "code_analysis", "weight": 1.0},
    "dolphin": {"primary_role": DebateRole.DEVIL_ADVOCATE, "strength": "uncensored_analysis", "weight": 1.1},
    "mistral": {"primary_role": DebateRole.PROPOSER, "strength": "fast_analysis", "weight": 0.9},
    "llama-3.1-8b": {"primary_role": DebateRole.CRITIC, "strength": "general", "weight": 0.9},
}

# Debate prompts
DEBATE_PROMPT_TEMPLATES: dict[DebateRole, str] = {
    DebateRole.PROPOSER: """You are a security expert making an initial analysis.

Question: {question}
Context: {context}

Provide your analysis with:
1. Your main claims (numbered)
2. Evidence for each claim
3. Confidence level (0-100%)
4. Potential weaknesses in your analysis

Be specific and technical. Focus on actionable findings.""",

    DebateRole.CRITIC: """You are a critical reviewer evaluating another expert's analysis.

Question: {question}
Context: {context}

Previous analysis by {proposer_model}:
{previous_argument}

Your task:
1. List points you AGREE with (and why)
2. List points you DISAGREE with (and why)
3. Identify any HALLUCINATIONS or unsupported claims
4. Add any findings the previous analysis MISSED
5. Your overall confidence in the original analysis (0-100%)

Be rigorous. Challenge every claim that lacks evidence.""",

    DebateRole.JUDGE: """You are a senior security judge evaluating multiple expert analyses.

Question: {question}
Context: {context}

Arguments from different experts:
{all_arguments}

Your task:
1. Identify areas of CONSENSUS (all experts agree)
2. Identify areas of DISAGREEMENT
3. For disagreements, determine which position is most likely correct
4. Produce a FINAL VERDICT with confidence level
5. Flag any potential hallucinations or unsupported claims

Weight each expert's opinion based on their domain expertise.""",

    DebateRole.DEVIL_ADVOCATE: """You are a devil's advocate challenging the emerging consensus.

Question: {question}
Context: {context}

Current consensus:
{consensus_so_far}

Your task:
1. Challenge EVERY assumption in the consensus
2. Propose alternative explanations
3. Identify edge cases or scenarios where the consensus might be wrong
4. Rate the strength of the consensus (0-100%)
5. Suggest what additional investigation could confirm or deny the findings

Be aggressive in your criticism. If it's truly solid, it will survive your challenge.""",
}


class MultiModelDebate:
    """Orchestrates multi-model debates."""

    def __init__(self) -> None:
        self._sessions: dict[str, DebateSession] = {}
        self._session_counter = 0
        self._log = logger.bind(component="multi_model_debate")

    def create_session(
        self,
        question: str,
        context: str = "",
        participants: list[str] | None = None,
        max_rounds: int = 3,
    ) -> DebateSession:
        """Create a new debate session."""
        self._session_counter += 1
        if not participants:
            participants = ["whiterabbit", "deepseek-r1", "qwen-coder-14b"]

        session = DebateSession(
            session_id=f"debate-{self._session_counter}",
            question=question,
            context=context,
            participants=participants,
            max_rounds=max_rounds,
        )
        self._sessions[session.session_id] = session
        return session

    def build_round_prompts(self, session_id: str) -> list[dict[str, Any]]:
        """Build prompts for the next round of debate."""
        session = self._sessions.get(session_id)
        if not session:
            return []

        prompts = []
        round_num = session.current_round

        if round_num == 0:
            # First round: each model makes initial proposal
            for model_id in session.participants:
                role_info = MODEL_DEBATE_ROLES.get(model_id, {"primary_role": DebateRole.PROPOSER})
                prompt = DEBATE_PROMPT_TEMPLATES[DebateRole.PROPOSER].format(
                    question=session.question,
                    context=session.context,
                )
                prompts.append({
                    "model_id": model_id,
                    "role": role_info["primary_role"].value,
                    "prompt": prompt,
                    "round": round_num,
                })
        elif round_num == 1:
            # Second round: each model critiques others
            prev_args = [a for a in session.arguments if a.round_num == 0]
            for model_id in session.participants:
                other_args = [a for a in prev_args if a.model_id != model_id]
                if not other_args:
                    continue
                # Critique the strongest argument from another model
                target_arg = other_args[0]
                prompt = DEBATE_PROMPT_TEMPLATES[DebateRole.CRITIC].format(
                    question=session.question,
                    context=session.context,
                    proposer_model=target_arg.model_id,
                    previous_argument=target_arg.content[:2000],
                )
                prompts.append({
                    "model_id": model_id,
                    "role": "critic",
                    "prompt": prompt,
                    "round": round_num,
                })
        else:
            # Later rounds: judge synthesizes
            all_args_text = ""
            for arg in session.arguments:
                all_args_text += f"\n[{arg.model_id} - Round {arg.round_num}]:\n{arg.content[:1000]}\n"

            # Pick deepest reasoner as judge
            judge = "deepseek-r1" if "deepseek-r1" in session.participants else session.participants[0]
            prompt = DEBATE_PROMPT_TEMPLATES[DebateRole.JUDGE].format(
                question=session.question,
                context=session.context,
                all_arguments=all_args_text[:4000],
            )
            prompts.append({
                "model_id": judge,
                "role": "judge",
                "prompt": prompt,
                "round": round_num,
            })

            # Devil's advocate
            if len(session.participants) > 2:
                devil = "dolphin" if "dolphin" in session.participants else session.participants[-1]
                consensus_text = all_args_text[:2000]
                prompt = DEBATE_PROMPT_TEMPLATES[DebateRole.DEVIL_ADVOCATE].format(
                    question=session.question,
                    context=session.context,
                    consensus_so_far=consensus_text,
                )
                prompts.append({
                    "model_id": devil,
                    "role": "devil_advocate",
                    "prompt": prompt,
                    "round": round_num,
                })

        return prompts

    def record_argument(
        self,
        session_id: str,
        model_id: str,
        role: str,
        content: str,
        confidence: float = 0.5,
        key_claims: list[str] | None = None,
    ) -> DebateArgument:
        """Record an argument from a model."""
        session = self._sessions.get(session_id)
        if not session:
            return DebateArgument()

        arg = DebateArgument(
            model_id=model_id,
            role=DebateRole(role) if role in [r.value for r in DebateRole] else DebateRole.PROPOSER,
            round_num=session.current_round,
            content=content,
            confidence=confidence,
            key_claims=key_claims or [],
        )
        session.arguments.append(arg)
        return arg

    def advance_round(self, session_id: str) -> DebateStatus:
        """Advance to the next round or finalize."""
        session = self._sessions.get(session_id)
        if not session:
            return DebateStatus.DEADLOCK

        session.current_round += 1

        # Check for consensus
        if session.current_round > 1:
            consensus = self._check_consensus(session)
            if consensus:
                session.status = DebateStatus.CONSENSUS_REACHED
                session.consensus = consensus["text"]
                session.consensus_confidence = consensus["confidence"]
                session.completed_at = time.time()
                return session.status

        if session.current_round >= session.max_rounds:
            # Final round: take majority vote
            majority = self._majority_vote(session)
            session.status = DebateStatus.MAJORITY_REACHED
            session.consensus = majority["text"]
            session.consensus_confidence = majority["confidence"]
            session.completed_at = time.time()
            return session.status

        session.status = DebateStatus.ROUND_IN_PROGRESS
        return session.status

    def _check_consensus(self, session: DebateSession) -> dict[str, Any] | None:
        """Check if models have reached consensus."""
        latest = [a for a in session.arguments if a.round_num == session.current_round - 1]
        if len(latest) < 2:
            return None

        # Check confidence convergence
        confidences = [a.confidence for a in latest]
        avg_conf = sum(confidences) / len(confidences)
        spread = max(confidences) - min(confidences)

        if spread < 0.2 and avg_conf > 0.6:
            # High agreement — use highest confidence argument
            best = max(latest, key=lambda a: a.confidence)
            return {"text": best.content, "confidence": avg_conf}
        return None

    def _majority_vote(self, session: DebateSession) -> dict[str, Any]:
        """Take majority vote from all arguments."""
        # Use the last round's arguments
        latest = session.arguments[-len(session.participants):] if session.arguments else []
        if not latest:
            return {"text": "No consensus reached", "confidence": 0.0}

        # Weight by model expertise
        best_score = -1.0
        best_arg = latest[0]
        for arg in latest:
            role_info = MODEL_DEBATE_ROLES.get(arg.model_id, {"weight": 1.0})
            score = arg.confidence * role_info.get("weight", 1.0)
            if score > best_score:
                best_score = score
                best_arg = arg

        return {"text": best_arg.content, "confidence": best_arg.confidence}

    def get_stats(self) -> dict[str, Any]:
        completed = sum(1 for s in self._sessions.values() if s.completed_at > 0)
        return {
            "sessions": len(self._sessions),
            "completed": completed,
            "available_models": list(MODEL_DEBATE_ROLES.keys()),
        }

    def build_debate_summary_prompt(self, session_id: str) -> str:
        """Build a prompt summarizing the debate for inclusion in agent reasoning."""
        session = self._sessions.get(session_id)
        if not session:
            return ""

        lines = [f"## Debate Summary: {session.question[:50]}"]
        lines.append(f"Status: {session.status.value}")
        lines.append(f"Participants: {', '.join(session.participants)}")
        lines.append(f"Rounds: {session.current_round}/{session.max_rounds}")

        if session.consensus:
            lines.append(f"\nConsensus ({session.consensus_confidence:.0%} confidence):")
            lines.append(session.consensus[:500])
        else:
            lines.append("\nNo consensus yet. Arguments:")
            for arg in session.arguments[-3:]:
                lines.append(f"  [{arg.model_id}] ({arg.confidence:.0%}): {arg.content[:100]}")

        return "\n".join(lines)
