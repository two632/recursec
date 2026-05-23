"""Meta-reasoning engine — reasoning about reasoning.

Implements metacognitive capabilities:
1. Strategy selection: Choose the best reasoning strategy for a problem
2. Confidence calibration: Assess how reliable our reasoning is
3. Cognitive load monitoring: Track reasoning complexity
4. Reasoning quality assessment: Evaluate output quality
5. Explanation generation: Explain why a decision was made
6. Uncertainty quantification: Measure what we don't know
7. Reasoning replay: Reconstruct decision chains
8. Second-order reasoning: Think about what we're missing

This is the "thinking about thinking" layer that makes
the agent more self-aware and adaptive.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ReasoningQuality(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    UNRELIABLE = "unreliable"


class UncertaintyType(str, Enum):
    EPISTEMIC = "epistemic"       # Lack of knowledge
    ALEATORIC = "aleatoric"       # Inherent randomness
    MODEL = "model"               # Model limitations
    DATA = "data"                 # Insufficient data
    AMBIGUITY = "ambiguity"       # Multiple interpretations


@dataclass
class StrategyRecommendation:
    """Recommendation for which reasoning strategy to use."""
    strategy: str = ""
    confidence: float = 0.5
    reasoning: str = ""
    alternatives: list[str] = field(default_factory=list)
    estimated_quality: ReasoningQuality = ReasoningQuality.ADEQUATE
    estimated_time_s: float = 0.0
    estimated_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "confidence": round(self.confidence, 3),
            "quality": self.estimated_quality.value,
            "alternatives": self.alternatives[:3],
        }


@dataclass
class ConfidenceAssessment:
    """Assessment of confidence in a conclusion."""
    overall_confidence: float = 0.5
    evidence_strength: float = 0.5
    reasoning_quality: ReasoningQuality = ReasoningQuality.ADEQUATE
    uncertainties: list[dict[str, Any]] = field(default_factory=list)
    calibration_adjustment: float = 0.0  # +/- to adjust raw confidence
    final_confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": round(self.final_confidence, 3),
            "evidence_strength": round(self.evidence_strength, 3),
            "quality": self.reasoning_quality.value,
            "uncertainties": len(self.uncertainties),
            "calibration": round(self.calibration_adjustment, 3),
        }


@dataclass
class CognitiveLoad:
    """Current cognitive load metrics."""
    active_goals: int = 0
    working_memory_usage: float = 0.0
    reasoning_depth: int = 0
    context_complexity: float = 0.0  # Estimated context complexity
    decision_fatigue: float = 0.0    # Accumulated decision load
    overloaded: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "goals": self.active_goals,
            "memory_usage": round(self.working_memory_usage, 2),
            "depth": self.reasoning_depth,
            "complexity": round(self.context_complexity, 2),
            "fatigue": round(self.decision_fatigue, 2),
            "overloaded": self.overloaded,
        }


@dataclass
class ReasoningTrace:
    """A trace of reasoning steps for replay/analysis."""
    trace_id: str = ""
    question: str = ""
    steps: list[dict[str, str]] = field(default_factory=list)
    final_answer: str = ""
    strategy_used: str = ""
    confidence: float = 0.5
    quality: ReasoningQuality = ReasoningQuality.ADEQUATE
    timestamp: float = field(default_factory=time.time)

    def add_step(self, step_type: str, content: str) -> None:
        self.steps.append({
            "type": step_type,
            "content": content,
            "timestamp": str(time.time()),
        })


# ── Prompt Templates ────────────────────────────────────────

STRATEGY_SELECTION_PROMPT = """Select the best reasoning strategy for this problem.

Problem: {problem}
Problem type: {problem_type}
Available strategies:
- chain_of_thought: Step-by-step linear reasoning
- tree_of_thought: Explore multiple paths simultaneously
- debate: Multiple models argue opposing positions
- analogy: Apply known patterns from similar cases
- decomposition: Break into smaller sub-problems
- adversarial: Think from attacker/defender viewpoints
- bayesian: Update beliefs from evidence
- causal: Trace cause-and-effect chains
- abductive: Infer best explanation from evidence

Context: {context}

Respond as JSON:
{{
  "best_strategy": "strategy_name",
  "reasoning": "why this strategy fits",
  "confidence": 0.X,
  "alternatives": ["second_best", "third_best"],
  "estimated_quality": "excellent|good|adequate|poor",
  "estimated_tokens": 5000
}}"""

CONFIDENCE_CALIBRATION_PROMPT = """Assess the confidence level of this conclusion.

Conclusion: {conclusion}
Evidence used: {evidence}
Reasoning chain: {reasoning}
Question asked: {question}

Evaluate:
1. How strong is the evidence?
2. How sound is the reasoning?
3. What uncertainties remain?
4. What could we be wrong about?
5. How should we adjust our raw confidence?

Respond as JSON:
{{
  "evidence_strength": 0.X,
  "reasoning_quality": "excellent|good|adequate|poor|unreliable",
  "uncertainties": [
    {{
      "type": "epistemic|aleatoric|model|data|ambiguity",
      "description": "what we're uncertain about",
      "impact": 0.X
    }}
  ],
  "calibration_adjustment": +/-0.X,
  "final_confidence": 0.X
}}"""

SECOND_ORDER_PROMPT = """Think about what we might be MISSING in this security assessment.

What we know: {known}
What we've tested: {tested}
What we've found: {findings}
Target: {target}

Consider:
1. What assumptions are we making that might be wrong?
2. What attack vectors haven't we considered?
3. What technologies might be hidden that we haven't detected?
4. What would a more experienced pentester look at?
5. Are we falling into any cognitive traps?

Respond as JSON:
{{
  "blind_spots": ["things we might be missing"],
  "untested_assumptions": ["assumptions we're making"],
  "suggested_actions": ["what to do about it"],
  "cognitive_traps": ["biases we might have"],
  "confidence_in_coverage": 0.X
}}"""

EXPLANATION_PROMPT = """Explain this security decision in clear terms.

Decision: {decision}
Context: {context}
Evidence: {evidence}
Alternatives considered: {alternatives}

Generate a clear, concise explanation that:
1. States what was decided
2. Explains why (key reasons)
3. Mentions what alternatives were considered
4. Notes any caveats or limitations

Respond as JSON:
{{
  "summary": "one sentence summary",
  "key_reasons": ["reason 1", "reason 2"],
  "alternatives_rejected": ["why other options weren't chosen"],
  "caveats": ["limitations to be aware of"],
  "confidence": 0.X
}}"""


class MetaReasoningEngine:
    """Meta-reasoning engine — reasoning about reasoning.

    Provides metacognitive capabilities for self-aware,
    adaptive agent behavior.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._traces: list[ReasoningTrace] = []
        self._strategy_history: list[dict[str, Any]] = []
        self._cognitive_state = CognitiveLoad()
        self._calibration_data: list[tuple[float, bool]] = []
        self._log = logger.bind(component="meta_reasoning")

    async def select_strategy(
        self,
        problem: str,
        problem_type: str = "",
        context: str = "",
    ) -> StrategyRecommendation:
        """Select the best reasoning strategy for a problem."""
        if not self._router:
            return self._heuristic_strategy_selection(problem, problem_type)

        prompt = STRATEGY_SELECTION_PROMPT.format(
            problem=problem, problem_type=problem_type,
            context=context[:1000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=512,
        )

        data = self._parse_json(response)
        try:
            quality = ReasoningQuality(data.get("estimated_quality", "adequate"))
        except ValueError:
            quality = ReasoningQuality.ADEQUATE

        rec = StrategyRecommendation(
            strategy=data.get("best_strategy", "chain_of_thought"),
            confidence=data.get("confidence", 0.5),
            reasoning=data.get("reasoning", ""),
            alternatives=data.get("alternatives", []),
            estimated_quality=quality,
            estimated_tokens=data.get("estimated_tokens", 5000),
        )

        self._strategy_history.append({
            "problem_type": problem_type,
            "strategy": rec.strategy,
            "confidence": rec.confidence,
        })

        return rec

    async def calibrate_confidence(
        self,
        conclusion: str,
        evidence: str,
        reasoning: str,
        question: str = "",
        raw_confidence: float = 0.5,
    ) -> ConfidenceAssessment:
        """Calibrate confidence in a conclusion."""
        if not self._router:
            return ConfidenceAssessment(
                overall_confidence=raw_confidence,
                final_confidence=raw_confidence,
            )

        prompt = CONFIDENCE_CALIBRATION_PROMPT.format(
            conclusion=conclusion[:500],
            evidence=evidence[:1000],
            reasoning=reasoning[:1000],
            question=question[:200],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=512,
        )

        data = self._parse_json(response)
        try:
            quality = ReasoningQuality(data.get("reasoning_quality", "adequate"))
        except ValueError:
            quality = ReasoningQuality.ADEQUATE

        assessment = ConfidenceAssessment(
            overall_confidence=raw_confidence,
            evidence_strength=data.get("evidence_strength", 0.5),
            reasoning_quality=quality,
            uncertainties=data.get("uncertainties", []),
            calibration_adjustment=data.get("calibration_adjustment", 0.0),
            final_confidence=data.get("final_confidence", raw_confidence),
        )

        # Apply calibration history correction
        historical_correction = self._get_calibration_correction()
        assessment.final_confidence = max(0.0, min(1.0,
            assessment.final_confidence + historical_correction
        ))

        return assessment

    async def detect_blind_spots(
        self,
        known: list[str],
        tested: list[str],
        findings: list[str],
        target: str,
    ) -> dict[str, Any]:
        """Detect what we might be missing (second-order reasoning)."""
        if not self._router:
            return {"blind_spots": [], "confidence_in_coverage": 0.5}

        prompt = SECOND_ORDER_PROMPT.format(
            known=json.dumps(known[:10])[:1000],
            tested=json.dumps(tested[:10])[:1000],
            findings=json.dumps(findings[:10])[:1000],
            target=target,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=1024,
        )

        return self._parse_json(response)

    async def explain_decision(
        self,
        decision: str,
        context: str = "",
        evidence: str = "",
        alternatives: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate a clear explanation of a decision."""
        if not self._router:
            return {"summary": decision, "key_reasons": [], "confidence": 0.5}

        prompt = EXPLANATION_PROMPT.format(
            decision=decision[:500],
            context=context[:500],
            evidence=evidence[:500],
            alternatives=json.dumps(alternatives or []),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=512,
        )

        return self._parse_json(response)

    # ── Cognitive Load Monitoring ────────────────────────

    def update_cognitive_load(
        self,
        active_goals: int = 0,
        memory_usage: float = 0.0,
        reasoning_depth: int = 0,
    ) -> CognitiveLoad:
        """Update and return current cognitive load."""
        self._cognitive_state.active_goals = active_goals
        self._cognitive_state.working_memory_usage = memory_usage
        self._cognitive_state.reasoning_depth = reasoning_depth

        # Estimate complexity
        self._cognitive_state.context_complexity = (
            active_goals * 0.2 + memory_usage * 0.3 +
            reasoning_depth * 0.2 + self._cognitive_state.decision_fatigue * 0.3
        )

        # Check if overloaded
        self._cognitive_state.overloaded = self._cognitive_state.context_complexity > 0.8

        return self._cognitive_state

    def record_decision(self) -> None:
        """Record that a decision was made (increases fatigue)."""
        self._cognitive_state.decision_fatigue = min(
            1.0, self._cognitive_state.decision_fatigue + 0.02,
        )

    def rest(self) -> None:
        """Reset decision fatigue (e.g., between phases)."""
        self._cognitive_state.decision_fatigue *= 0.5

    # ── Reasoning Traces ─────────────────────────────────

    def start_trace(self, question: str, strategy: str = "") -> ReasoningTrace:
        """Start recording a reasoning trace."""
        trace = ReasoningTrace(
            trace_id=f"trace-{len(self._traces)}",
            question=question,
            strategy_used=strategy,
        )
        self._traces.append(trace)
        return trace

    def complete_trace(
        self,
        trace_id: str,
        answer: str,
        confidence: float = 0.5,
        quality: ReasoningQuality = ReasoningQuality.ADEQUATE,
    ) -> None:
        """Complete a reasoning trace."""
        for trace in self._traces:
            if trace.trace_id == trace_id:
                trace.final_answer = answer
                trace.confidence = confidence
                trace.quality = quality
                break

    def get_trace(self, trace_id: str) -> ReasoningTrace | None:
        for trace in self._traces:
            if trace.trace_id == trace_id:
                return trace
        return None

    # ── Calibration ──────────────────────────────────────

    def record_calibration(self, predicted_confidence: float, was_correct: bool) -> None:
        """Record a calibration data point."""
        self._calibration_data.append((predicted_confidence, was_correct))
        if len(self._calibration_data) > 200:
            self._calibration_data = self._calibration_data[-200:]

    def _get_calibration_correction(self) -> float:
        """Get a correction factor based on historical calibration."""
        if len(self._calibration_data) < 10:
            return 0.0

        # Compare predicted vs. actual
        avg_predicted = sum(c[0] for c in self._calibration_data) / len(self._calibration_data)
        actual_rate = sum(1 for c in self._calibration_data if c[1]) / len(self._calibration_data)

        # If we're overconfident, return negative correction
        return (actual_rate - avg_predicted) * 0.5

    # ── Heuristics ───────────────────────────────────────

    def _heuristic_strategy_selection(
        self,
        problem: str,
        problem_type: str,
    ) -> StrategyRecommendation:
        """Heuristic-based strategy selection (no LLM needed)."""
        problem_lower = problem.lower()

        # Map problem types to strategies
        type_map: dict[str, str] = {
            "vulnerability": "chain_of_thought",
            "exploit": "adversarial",
            "code_review": "decomposition",
            "network": "decomposition",
            "strategy": "debate",
            "planning": "decomposition",
            "classification": "chain_of_thought",
            "investigation": "abductive",
        }

        strategy = type_map.get(problem_type, "chain_of_thought")

        # Keyword-based adjustments
        if "multiple" in problem_lower or "several" in problem_lower:
            strategy = "decomposition"
        if "which" in problem_lower or "choose" in problem_lower:
            strategy = "debate"
        if "why" in problem_lower or "explain" in problem_lower:
            strategy = "causal"

        return StrategyRecommendation(
            strategy=strategy,
            confidence=0.6,
            reasoning="Heuristic selection based on problem type",
            alternatives=["chain_of_thought", "decomposition"],
        )

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        strategy_counts: dict[str, int] = defaultdict(int)
        for entry in self._strategy_history:
            strategy_counts[entry["strategy"]] += 1
        return {
            "traces": len(self._traces),
            "strategy_history": len(self._strategy_history),
            "strategy_distribution": dict(strategy_counts),
            "cognitive_load": self._cognitive_state.to_dict(),
            "calibration_samples": len(self._calibration_data),
        }
