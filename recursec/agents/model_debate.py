"""Multi-model debate — uses multiple LLMs to debate and validate conclusions.

Implements structured debate between different models:
1. Multiple models independently analyze the same question
2. Models review each other's reasoning
3. Models debate disagreements
4. Consensus is built from the debate
5. Final confidence reflects agreement level

This leverages the user's 16 different models — each with
different strengths, biases, and training data — to produce
more reliable conclusions than any single model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class DebatePhase(str, Enum):
    OPENING = "opening"        # Each model states position
    CRITIQUE = "critique"      # Models critique each other
    REBUTTAL = "rebuttal"     # Models defend/update positions
    SYNTHESIS = "synthesis"    # Build consensus
    VERDICT = "verdict"        # Final decision


@dataclass
class DebatePosition:
    """A model's position in a debate."""
    model: str = ""
    position: str = ""
    confidence: float = 0.5
    reasoning: str = ""
    evidence: list[str] = field(default_factory=list)
    updated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "position": self.position[:100],
            "confidence": round(self.confidence, 2),
            "updated": self.updated,
        }


@dataclass
class Critique:
    """A critique of another model's position."""
    critic_model: str = ""
    target_model: str = ""
    agrees: bool = False
    critique: str = ""
    counter_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "critic": self.critic_model,
            "target": self.target_model,
            "agrees": self.agrees,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class DebateResult:
    """Result of a multi-model debate."""
    debate_id: str = ""
    question: str = ""
    positions: list[DebatePosition] = field(default_factory=list)
    critiques: list[Critique] = field(default_factory=list)
    consensus: str = ""
    consensus_confidence: float = 0.0
    agreement_rate: float = 0.0
    models_used: list[str] = field(default_factory=list)
    rounds: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.debate_id,
            "question": self.question[:100],
            "models": len(self.models_used),
            "consensus": self.consensus[:100],
            "confidence": round(self.consensus_confidence, 2),
            "agreement": round(self.agreement_rate, 2),
            "rounds": self.rounds,
        }


# ── Prompts ──────────────────────────────────────────────────

OPENING_PROMPT = """You are a security analyst. Provide your independent analysis.

Question: {question}

Context: {context}

Provide your position:
1. Your conclusion
2. Your confidence (0-1)
3. Your reasoning
4. Key evidence

Respond as JSON:
{{
  "position": "your conclusion",
  "confidence": 0.X,
  "reasoning": "step by step",
  "evidence": ["evidence 1", "evidence 2"]
}}"""

CRITIQUE_PROMPT = """You are a security analyst reviewing another analyst's work.

Question: {question}

Their position:
{other_position}

Their reasoning:
{other_reasoning}

Their evidence:
{other_evidence}

Do you agree or disagree? Provide a critique:
1. Do you agree with their conclusion?
2. What are the strengths of their argument?
3. What are the weaknesses or blind spots?
4. What counter-evidence exists?

Respond as JSON:
{{
  "agrees": true/false,
  "critique": "your detailed critique",
  "counter_evidence": ["counter point 1"],
  "confidence": 0.X
}}"""

SYNTHESIS_PROMPT = """You are synthesizing a security debate between multiple analysts.

Question: {question}

Positions:
{positions_text}

Critiques:
{critiques_text}

Synthesize the debate:
1. What do the analysts agree on?
2. What are the key disagreements?
3. What is the best overall conclusion?
4. How confident should we be?

Respond as JSON:
{{
  "consensus": "the synthesized conclusion",
  "confidence": 0.X,
  "agreements": ["point 1"],
  "disagreements": ["point 1"],
  "reasoning": "why this consensus"
}}"""


class ModelDebate:
    """Orchestrates structured debates between multiple LLM models.

    Uses diverse model perspectives to validate findings,
    reduce bias, and increase confidence in conclusions.
    """

    def __init__(
        self,
        model_router: ModelRouter | None = None,
        debate_models: list[str] | None = None,
    ) -> None:
        self._router = model_router
        self._debate_models = debate_models or [
            "whiterabbit", "deepseek-r1", "qwen-coder-14b",
        ]
        self._debate_counter = 0
        self._log = logger.bind(component="model_debate")

    async def debate(
        self,
        question: str,
        context: str = "",
        max_rounds: int = 2,
    ) -> DebateResult:
        """Run a structured debate between models."""
        start = time.time()
        self._debate_counter += 1
        debate_id = f"debate-{self._debate_counter}"

        result = DebateResult(
            debate_id=debate_id,
            question=question,
            models_used=list(self._debate_models),
        )

        if not self._router:
            result.consensus = "No LLM available for debate"
            return result

        # Phase 1: OPENING — Each model states position
        positions = await self._opening_round(question, context)
        result.positions = positions

        if len(positions) < 2:
            if positions:
                result.consensus = positions[0].position
                result.consensus_confidence = positions[0].confidence
            return result

        # Phase 2: CRITIQUE — Models critique each other
        critiques = await self._critique_round(question, positions)
        result.critiques = critiques

        # Phase 3: REBUTTAL — Models update positions
        if max_rounds > 1 and critiques:
            updated = await self._rebuttal_round(question, positions, critiques)
            result.positions = updated

        # Phase 4: SYNTHESIS — Build consensus
        consensus, confidence, agreement = await self._synthesis(
            question, result.positions, result.critiques,
        )

        result.consensus = consensus
        result.consensus_confidence = confidence
        result.agreement_rate = agreement
        result.rounds = min(max_rounds, 3)
        result.duration_s = time.time() - start

        return result

    async def _opening_round(
        self,
        question: str,
        context: str,
    ) -> list[DebatePosition]:
        """Each model independently states their position."""
        positions = []

        for model_name in self._debate_models:
            prompt = OPENING_PROMPT.format(
                question=question[:300],
                context=context[:500],
            )

            try:
                response = await self._router.generate(
                    messages=[{"role": "user", "content": prompt}],
                    task_type="reasoning",
                    model_hint=model_name,
                    temperature=0.3,
                    max_tokens=512,
                )

                data = self._parse_json(response)
                positions.append(DebatePosition(
                    model=model_name,
                    position=data.get("position", ""),
                    confidence=data.get("confidence", 0.5),
                    reasoning=data.get("reasoning", ""),
                    evidence=data.get("evidence", []),
                ))
            except Exception as e:
                self._log.warning("opening_failed", model=model_name, error=str(e)[:100])

        return positions

    async def _critique_round(
        self,
        question: str,
        positions: list[DebatePosition],
    ) -> list[Critique]:
        """Each model critiques the others' positions."""
        critiques = []

        for i, critic_pos in enumerate(positions):
            for j, target_pos in enumerate(positions):
                if i == j:
                    continue

                prompt = CRITIQUE_PROMPT.format(
                    question=question[:200],
                    other_position=target_pos.position[:200],
                    other_reasoning=target_pos.reasoning[:300],
                    other_evidence=", ".join(target_pos.evidence[:3]),
                )

                try:
                    response = await self._router.generate(
                        messages=[{"role": "user", "content": prompt}],
                        task_type="reasoning",
                        model_hint=critic_pos.model,
                        temperature=0.3,
                        max_tokens=512,
                    )

                    data = self._parse_json(response)
                    critiques.append(Critique(
                        critic_model=critic_pos.model,
                        target_model=target_pos.model,
                        agrees=data.get("agrees", False),
                        critique=data.get("critique", ""),
                        counter_evidence=data.get("counter_evidence", []),
                        confidence=data.get("confidence", 0.5),
                    ))
                except Exception as e:
                    self._log.warning(
                        "critique_failed",
                        critic=critic_pos.model, error=str(e)[:100],
                    )

        return critiques

    async def _rebuttal_round(
        self,
        question: str,
        positions: list[DebatePosition],
        critiques: list[Critique],
    ) -> list[DebatePosition]:
        """Models update positions based on critiques."""
        updated = []

        for pos in positions:
            relevant_critiques = [
                c for c in critiques if c.target_model == pos.model
            ]

            if not relevant_critiques:
                updated.append(pos)
                continue

            # If all critics agree, increase confidence
            all_agree = all(c.agrees for c in relevant_critiques)
            all_disagree = all(not c.agrees for c in relevant_critiques)

            new_pos = DebatePosition(
                model=pos.model,
                position=pos.position,
                confidence=pos.confidence,
                reasoning=pos.reasoning,
                evidence=pos.evidence,
                updated=True,
            )

            if all_agree:
                new_pos.confidence = min(0.95, pos.confidence + 0.1)
            elif all_disagree:
                new_pos.confidence = max(0.1, pos.confidence - 0.2)

            updated.append(new_pos)

        return updated

    async def _synthesis(
        self,
        question: str,
        positions: list[DebatePosition],
        critiques: list[Critique],
    ) -> tuple[str, float, float]:
        """Synthesize debate into consensus."""
        if not self._router:
            return "", 0.0, 0.0

        positions_text = "\n".join(
            f"  {p.model}: {p.position[:100]} (confidence: {p.confidence:.2f})"
            for p in positions
        )

        critiques_text = "\n".join(
            f"  {c.critic_model} → {c.target_model}: {'agrees' if c.agrees else 'disagrees'} — {c.critique[:80]}"
            for c in critiques[:6]
        )

        prompt = SYNTHESIS_PROMPT.format(
            question=question[:200],
            positions_text=positions_text,
            critiques_text=critiques_text or "  No critiques",
        )

        try:
            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=512,
            )

            data = self._parse_json(response)
            consensus = data.get("consensus", "")
            confidence = data.get("confidence", 0.5)
        except Exception:
            consensus = positions[0].position if positions else ""
            confidence = 0.4

        # Calculate agreement rate
        if critiques:
            agreement_rate = sum(1 for c in critiques if c.agrees) / len(critiques)
        else:
            agreement_rate = 1.0 if len(positions) <= 1 else 0.5

        return consensus, confidence, agreement_rate

    def _parse_json(self, text: str) -> dict[str, Any]:
        import json
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        return {
            "debates": self._debate_counter,
            "models": len(self._debate_models),
        }
