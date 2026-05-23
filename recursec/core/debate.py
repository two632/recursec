"""Multi-agent debate and consensus engine.

Implements structured debate between multiple LLM agents to:
- Cross-validate findings (reduce false positives)
- Resolve conflicting assessments
- Build confidence through adversarial review
- Produce higher-quality reasoning through dialectical synthesis

Debate Protocols:
1. Adversarial Review — One agent attacks, another defends
2. Round-Robin — Each agent proposes, others critique
3. Majority Vote — Simple voting on classification
4. Confidence-Weighted — Weighted votes based on domain expertise
5. Dialectical Synthesis — Thesis → Antithesis → Synthesis
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DebateProtocol(str, Enum):
    ADVERSARIAL = "adversarial"
    ROUND_ROBIN = "round_robin"
    MAJORITY_VOTE = "majority_vote"
    CONFIDENCE_WEIGHTED = "confidence_weighted"
    DIALECTICAL = "dialectical"


class DebateRole(str, Enum):
    PROPONENT = "proponent"  # Argues for a finding/conclusion
    OPPONENT = "opponent"    # Argues against / plays devil's advocate
    JUDGE = "judge"          # Evaluates arguments and decides
    EXPERT = "expert"        # Provides domain-specific analysis
    SYNTHESIZER = "synthesizer"  # Combines perspectives


@dataclass
class DebateMessage:
    """A single message in a debate."""
    role: DebateRole
    model_name: str
    content: str
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class DebateRound:
    """A single round of debate."""
    round_num: int
    messages: list[DebateMessage] = field(default_factory=list)
    consensus_reached: bool = False


@dataclass
class DebateResult:
    """Final result of a debate."""
    topic: str
    protocol: DebateProtocol
    rounds: list[DebateRound] = field(default_factory=list)
    final_verdict: str = ""
    confidence: float = 0.0
    participating_models: list[str] = field(default_factory=list)
    dissenting_views: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    consensus: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic,
            "protocol": self.protocol.value,
            "rounds": len(self.rounds),
            "final_verdict": self.final_verdict,
            "confidence": round(self.confidence, 2),
            "participating_models": self.participating_models,
            "dissenting_views": self.dissenting_views,
            "duration_s": round(self.duration_s, 2),
            "consensus": self.consensus,
        }


class DebateEngine:
    """Orchestrates multi-agent debates for security analysis.

    Uses the LLM router to select appropriate models for each debate role.
    """

    def __init__(self, llm_router: Any = None, max_rounds: int = 5) -> None:
        self._router = llm_router
        self._max_rounds = max_rounds
        self._debates: list[DebateResult] = []
        self._stats = {
            "total_debates": 0,
            "consensus_reached": 0,
            "avg_rounds": 0.0,
            "avg_confidence": 0.0,
        }

    async def debate(
        self,
        topic: str,
        context: str = "",
        protocol: DebateProtocol = DebateProtocol.ADVERSARIAL,
        model_names: list[str] | None = None,
    ) -> DebateResult:
        """Run a structured debate on the given topic."""
        start = time.time()

        if protocol == DebateProtocol.ADVERSARIAL:
            result = await self._adversarial_debate(topic, context, model_names)
        elif protocol == DebateProtocol.ROUND_ROBIN:
            result = await self._round_robin_debate(topic, context, model_names)
        elif protocol == DebateProtocol.MAJORITY_VOTE:
            result = await self._majority_vote(topic, context, model_names)
        elif protocol == DebateProtocol.CONFIDENCE_WEIGHTED:
            result = await self._confidence_weighted_vote(topic, context, model_names)
        elif protocol == DebateProtocol.DIALECTICAL:
            result = await self._dialectical_synthesis(topic, context, model_names)
        else:
            result = await self._adversarial_debate(topic, context, model_names)

        result.duration_s = time.time() - start
        self._debates.append(result)
        self._update_stats(result)

        return result

    async def validate_finding(
        self,
        finding_title: str,
        finding_description: str,
        evidence: list[str] | None = None,
    ) -> DebateResult:
        """Use debate to validate a security finding."""
        context = f"Finding: {finding_title}\nDescription: {finding_description}"
        if evidence:
            context += "\nEvidence:\n" + "\n".join(evidence[:5])

        topic = f"Is this finding valid and correctly classified? {finding_title}"
        return await self.debate(topic, context, DebateProtocol.ADVERSARIAL)

    async def _adversarial_debate(
        self, topic: str, context: str, model_names: list[str] | None
    ) -> DebateResult:
        """Proponent defends, opponent attacks, judge decides."""
        result = DebateResult(topic=topic, protocol=DebateProtocol.ADVERSARIAL)

        # Select models for each role
        proponent_model = await self._select_model("security", model_names, 0)
        opponent_model = await self._select_model("reasoning", model_names, 1)
        judge_model = await self._select_model("reasoning", model_names, 2)

        result.participating_models = [proponent_model, opponent_model, judge_model]

        for round_num in range(self._max_rounds):
            debate_round = DebateRound(round_num=round_num)

            # Proponent argues for
            proponent_prompt = self._build_proponent_prompt(topic, context, result.rounds)
            proponent_response = await self._query_model(proponent_model, proponent_prompt)
            debate_round.messages.append(DebateMessage(
                role=DebateRole.PROPONENT,
                model_name=proponent_model,
                content=proponent_response,
                confidence=self._extract_confidence(proponent_response),
            ))

            # Opponent argues against
            opponent_prompt = self._build_opponent_prompt(topic, context, result.rounds, proponent_response)
            opponent_response = await self._query_model(opponent_model, opponent_prompt)
            debate_round.messages.append(DebateMessage(
                role=DebateRole.OPPONENT,
                model_name=opponent_model,
                content=opponent_response,
                confidence=self._extract_confidence(opponent_response),
            ))

            # Judge evaluates
            judge_prompt = self._build_judge_prompt(topic, context, result.rounds, proponent_response, opponent_response)
            judge_response = await self._query_model(judge_model, judge_prompt)
            debate_round.messages.append(DebateMessage(
                role=DebateRole.JUDGE,
                model_name=judge_model,
                content=judge_response,
                confidence=self._extract_confidence(judge_response),
            ))

            result.rounds.append(debate_round)

            # Check if judge reached a decision
            if self._is_conclusive(judge_response):
                debate_round.consensus_reached = True
                break

        result.final_verdict = self._extract_verdict(result)
        result.confidence = self._calculate_debate_confidence(result)
        result.consensus = any(r.consensus_reached for r in result.rounds)

        return result

    async def _round_robin_debate(
        self, topic: str, context: str, model_names: list[str] | None
    ) -> DebateResult:
        """Each model proposes, others critique."""
        result = DebateResult(topic=topic, protocol=DebateProtocol.ROUND_ROBIN)
        models = await self._select_multiple_models(3, model_names)
        result.participating_models = models

        for round_num in range(min(self._max_rounds, 3)):
            debate_round = DebateRound(round_num=round_num)

            # Each model proposes
            proposer = models[round_num % len(models)]
            propose_prompt = f"""As a security expert, analyze this topic and provide your assessment:

Topic: {topic}
Context: {context}

Provide your assessment with confidence level (0-100%).
If previous rounds exist, consider the critiques received."""

            proposal = await self._query_model(proposer, propose_prompt)
            debate_round.messages.append(DebateMessage(
                role=DebateRole.PROPONENT,
                model_name=proposer,
                content=proposal,
                confidence=self._extract_confidence(proposal),
            ))

            # Others critique
            for critic in models:
                if critic == proposer:
                    continue
                critique_prompt = f"""Review this security assessment and provide constructive critique:

Topic: {topic}
Assessment: {proposal}

Point out any flaws, missing considerations, or areas of agreement. Rate your confidence (0-100%)."""

                critique = await self._query_model(critic, critique_prompt)
                debate_round.messages.append(DebateMessage(
                    role=DebateRole.OPPONENT,
                    model_name=critic,
                    content=critique,
                    confidence=self._extract_confidence(critique),
                ))

            result.rounds.append(debate_round)

        result.final_verdict = self._synthesize_round_robin(result)
        result.confidence = self._calculate_debate_confidence(result)
        result.consensus = True

        return result

    async def _majority_vote(
        self, topic: str, context: str, model_names: list[str] | None
    ) -> DebateResult:
        """Simple majority vote across models."""
        result = DebateResult(topic=topic, protocol=DebateProtocol.MAJORITY_VOTE)
        models = await self._select_multiple_models(3, model_names)
        result.participating_models = models

        debate_round = DebateRound(round_num=0)
        votes: list[tuple[str, str, float]] = []

        prompt = f"""As a security expert, vote on this question with YES or NO:

Topic: {topic}
Context: {context}

Respond with:
VOTE: YES or NO
CONFIDENCE: 0-100%
REASONING: Brief explanation"""

        tasks = [self._query_model(model, prompt) for model in models]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for model, response in zip(models, responses):
            if isinstance(response, Exception):
                continue
            debate_round.messages.append(DebateMessage(
                role=DebateRole.EXPERT,
                model_name=model,
                content=response,
                confidence=self._extract_confidence(response),
            ))
            vote = "YES" if "VOTE: YES" in response.upper() or "YES" in response.upper()[:50] else "NO"
            votes.append((model, vote, self._extract_confidence(response)))

        result.rounds.append(debate_round)

        yes_votes = sum(1 for _, v, _ in votes if v == "YES")
        no_votes = sum(1 for _, v, _ in votes if v == "NO")

        result.final_verdict = "YES" if yes_votes > no_votes else "NO"
        result.confidence = max(yes_votes, no_votes) / max(len(votes), 1)
        result.consensus = yes_votes == 0 or no_votes == 0
        result.dissenting_views = [m for m, v, _ in votes if v != result.final_verdict]

        return result

    async def _confidence_weighted_vote(
        self, topic: str, context: str, model_names: list[str] | None
    ) -> DebateResult:
        """Weighted vote based on model confidence and domain expertise."""
        result = await self._majority_vote(topic, context, model_names)
        result.protocol = DebateProtocol.CONFIDENCE_WEIGHTED

        # Re-weight based on confidences
        weighted_yes = 0.0
        weighted_no = 0.0
        for msg in result.rounds[0].messages if result.rounds else []:
            vote = "YES" if "YES" in msg.content.upper()[:50] else "NO"
            weight = msg.confidence
            if vote == "YES":
                weighted_yes += weight
            else:
                weighted_no += weight

        total = weighted_yes + weighted_no
        if total > 0:
            result.final_verdict = "YES" if weighted_yes > weighted_no else "NO"
            result.confidence = max(weighted_yes, weighted_no) / total

        return result

    async def _dialectical_synthesis(
        self, topic: str, context: str, model_names: list[str] | None
    ) -> DebateResult:
        """Thesis → Antithesis → Synthesis."""
        result = DebateResult(topic=topic, protocol=DebateProtocol.DIALECTICAL)
        models = await self._select_multiple_models(3, model_names)
        result.participating_models = models

        debate_round = DebateRound(round_num=0)

        # Thesis
        thesis_prompt = f"""Present a THESIS (affirmative position) on this security topic:
Topic: {topic}
Context: {context}

Present your strongest argument with evidence and confidence level (0-100%)."""

        thesis = await self._query_model(models[0], thesis_prompt)
        debate_round.messages.append(DebateMessage(
            role=DebateRole.PROPONENT,
            model_name=models[0],
            content=thesis,
            confidence=self._extract_confidence(thesis),
        ))

        # Antithesis
        antithesis_prompt = f"""Present an ANTITHESIS (opposing position) to this argument:
Topic: {topic}
Thesis: {thesis}

Challenge the thesis with counter-arguments, alternative explanations, and potential flaws."""

        antithesis = await self._query_model(models[1], antithesis_prompt)
        debate_round.messages.append(DebateMessage(
            role=DebateRole.OPPONENT,
            model_name=models[1],
            content=antithesis,
            confidence=self._extract_confidence(antithesis),
        ))

        # Synthesis
        synthesis_prompt = f"""Create a SYNTHESIS that reconciles these two positions:
Topic: {topic}
Thesis: {thesis}
Antithesis: {antithesis}

Combine the strongest elements of both arguments into a nuanced conclusion.
State your final assessment and confidence level (0-100%)."""

        synthesis = await self._query_model(models[2], synthesis_prompt)
        debate_round.messages.append(DebateMessage(
            role=DebateRole.SYNTHESIZER,
            model_name=models[2],
            content=synthesis,
            confidence=self._extract_confidence(synthesis),
        ))

        debate_round.consensus_reached = True
        result.rounds.append(debate_round)
        result.final_verdict = synthesis
        result.confidence = self._extract_confidence(synthesis)
        result.consensus = True

        return result

    # ── Helper Methods ─────────────────────────────────────

    async def _select_model(self, task_type: str, model_names: list[str] | None, index: int) -> str:
        """Select a model for a debate role."""
        if model_names and index < len(model_names):
            return model_names[index]
        if self._router:
            try:
                model = await self._router.select(task_type=task_type)
                return model.name
            except Exception:
                pass
        return f"model_{index}"

    async def _select_multiple_models(self, count: int, model_names: list[str] | None) -> list[str]:
        """Select multiple diverse models."""
        if model_names:
            return model_names[:count]
        models = []
        task_types = ["security", "reasoning", "general", "code"]
        for i in range(count):
            model = await self._select_model(task_types[i % len(task_types)], None, i)
            models.append(model)
        return models

    async def _query_model(self, model_name: str, prompt: str) -> str:
        """Query a specific model."""
        if self._router:
            try:
                response = await self._router.generate(
                    prompt=prompt,
                    model_name=model_name,
                    max_tokens=1024,
                )
                return response.text if hasattr(response, "text") else str(response)
            except Exception as e:
                return f"[Model {model_name} error: {e}]"
        return f"[No router available for model {model_name}]"

    def _build_proponent_prompt(self, topic: str, context: str, prev_rounds: list[DebateRound]) -> str:
        history = self._format_history(prev_rounds)
        return f"""You are the PROPONENT in a security debate. Argue FOR the following position:

Topic: {topic}
Context: {context}
{history}

Present strong arguments with evidence. Address any previous criticisms.
State your confidence level (0-100%)."""

    def _build_opponent_prompt(self, topic: str, context: str, prev_rounds: list[DebateRound], proponent_arg: str) -> str:
        return f"""You are the OPPONENT (devil's advocate) in a security debate.
Challenge the proponent's argument:

Topic: {topic}
Context: {context}
Proponent's argument: {proponent_arg}

Find weaknesses, alternative explanations, missing evidence, and potential false positives.
State your confidence level (0-100%)."""

    def _build_judge_prompt(self, topic: str, context: str, prev_rounds: list[DebateRound], proponent: str, opponent: str) -> str:
        return f"""You are the JUDGE in a security debate. Evaluate both arguments:

Topic: {topic}
Context: {context}
Proponent: {proponent}
Opponent: {opponent}

Decide: Is the finding VALID, INVALID, or NEEDS MORE EVIDENCE?
State your verdict and confidence level (0-100%).
If you have reached a CONCLUSIVE decision, state "VERDICT: [VALID/INVALID/INCONCLUSIVE]"."""

    def _format_history(self, rounds: list[DebateRound]) -> str:
        if not rounds:
            return ""
        lines = ["\nPrevious debate:"]
        for r in rounds:
            for msg in r.messages:
                lines.append(f"[{msg.role.value}] {msg.content[:300]}")
        return "\n".join(lines)

    def _is_conclusive(self, judge_response: str) -> bool:
        upper = judge_response.upper()
        return "VERDICT:" in upper and ("VALID" in upper or "INVALID" in upper)

    def _extract_verdict(self, result: DebateResult) -> str:
        if result.rounds:
            last_round = result.rounds[-1]
            for msg in reversed(last_round.messages):
                if msg.role == DebateRole.JUDGE:
                    return msg.content
        return "No verdict reached"

    def _extract_confidence(self, text: str) -> float:
        import re
        match = re.search(r"(\d+)\s*%", text)
        if match:
            return min(1.0, int(match.group(1)) / 100.0)
        if "high confidence" in text.lower():
            return 0.85
        if "low confidence" in text.lower():
            return 0.3
        if "medium confidence" in text.lower():
            return 0.6
        return 0.5

    def _calculate_debate_confidence(self, result: DebateResult) -> float:
        all_confidences = []
        for r in result.rounds:
            for msg in r.messages:
                all_confidences.append(msg.confidence)
        return sum(all_confidences) / max(len(all_confidences), 1)

    def _synthesize_round_robin(self, result: DebateResult) -> str:
        all_proposals = []
        for r in result.rounds:
            for msg in r.messages:
                if msg.role == DebateRole.PROPONENT:
                    all_proposals.append(msg.content[:500])
        return " | ".join(all_proposals) if all_proposals else "No proposals made"

    def _update_stats(self, result: DebateResult) -> None:
        self._stats["total_debates"] += 1
        if result.consensus:
            self._stats["consensus_reached"] += 1
        total = self._stats["total_debates"]
        self._stats["avg_rounds"] = (self._stats["avg_rounds"] * (total - 1) + len(result.rounds)) / total
        self._stats["avg_confidence"] = (self._stats["avg_confidence"] * (total - 1) + result.confidence) / total

    def get_stats(self) -> dict[str, Any]:
        return {**self._stats}
