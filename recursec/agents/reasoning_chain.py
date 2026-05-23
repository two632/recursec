"""Reasoning chain engine — structured multi-step reasoning with verification.

Implements chain-of-thought reasoning patterns:
1. Linear chain: Step-by-step reasoning (A → B → C)
2. Branching chain: Multiple possible paths explored
3. Verified chain: Each step verified before proceeding
4. Iterative chain: Loop until convergence
5. Evidence-based: Each claim must cite evidence
6. Adversarial: Generate argument and counter-argument
7. Socratic: Answer through a series of questions

Each chain step produces:
- A thought (the reasoning)
- An action (what to do based on the thought)
- An observation (what happened when we acted)
- A verification (is the observation consistent?)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ChainType(str, Enum):
    LINEAR = "linear"
    VERIFIED = "verified"
    ITERATIVE = "iterative"
    EVIDENCE = "evidence"
    ADVERSARIAL = "adversarial"
    SOCRATIC = "socratic"


class StepStatus(str, Enum):
    PENDING = "pending"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    VERIFYING = "verifying"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ChainStep:
    """A single step in a reasoning chain."""
    step_num: int = 0
    thought: str = ""
    action: str = ""
    observation: str = ""
    verification: str = ""
    status: StepStatus = StepStatus.PENDING
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    counter_argument: str = ""
    questions: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_num,
            "thought": self.thought[:200],
            "action": self.action[:100],
            "observation": self.observation[:200],
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReasoningChainResult:
    """Result of a complete reasoning chain."""
    chain_type: ChainType = ChainType.LINEAR
    question: str = ""
    steps: list[ChainStep] = field(default_factory=list)
    conclusion: str = ""
    overall_confidence: float = 0.5
    converged: bool = False
    iterations: int = 0
    time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.chain_type.value,
            "question": self.question[:200],
            "steps": len(self.steps),
            "conclusion": self.conclusion[:200],
            "confidence": round(self.overall_confidence, 2),
            "converged": self.converged,
            "time_ms": round(self.time_ms, 1),
        }


# ── Prompt Templates ────────────────────────────────────────

COT_STEP_PROMPT = """You are reasoning through a security problem step by step.

Problem: {problem}
Previous reasoning:
{previous_steps}

Step {step_num}: Think about what to do next.

Respond as JSON:
{{
  "thought": "your reasoning for this step",
  "action": "specific action to take or conclusion to draw",
  "confidence": 0.X,
  "is_final": true/false
}}"""

VERIFY_STEP_PROMPT = """Verify this reasoning step for logical errors or false assumptions.

Problem: {problem}
Reasoning step: {thought}
Action proposed: {action}
Evidence available: {evidence}

Check:
1. Is the logic sound?
2. Are there false assumptions?
3. Is the conclusion supported by evidence?
4. What could be wrong?

Respond as JSON:
{{
  "valid": true/false,
  "issues": ["list of issues if any"],
  "corrected_thought": "corrected reasoning if invalid",
  "confidence": 0.X
}}"""

EVIDENCE_STEP_PROMPT = """Make a claim about this security problem and cite evidence.

Problem: {problem}
Previous claims: {previous}
Available evidence: {evidence}

Make one specific, evidence-supported claim.

Respond as JSON:
{{
  "claim": "your specific claim",
  "evidence": ["evidence supporting the claim"],
  "confidence": 0.X,
  "assumptions": ["assumptions this depends on"],
  "is_final": true/false
}}"""

ADVERSARIAL_PROMPT = """Generate an argument AND counter-argument for this security assessment.

Problem: {problem}
Position: {position}
Previous arguments: {previous}

Respond as JSON:
{{
  "argument": "argument for this position",
  "counter_argument": "best counter-argument",
  "evidence_for": ["evidence supporting argument"],
  "evidence_against": ["evidence for counter-argument"],
  "net_confidence": 0.X,
  "is_final": true/false
}}"""

SOCRATIC_PROMPT = """Answer this security question through a series of sub-questions.

Main question: {question}
Previous Q&A:
{previous_qa}

Generate the next question that helps answer the main question,
then answer it.

Respond as JSON:
{{
  "sub_question": "a question that helps answer the main question",
  "answer": "answer to the sub-question",
  "how_it_helps": "how this moves toward answering the main question",
  "confidence": 0.X,
  "main_question_answered": true/false,
  "final_answer": "answer to main question (if answered)"
}}"""


class ReasoningChain:
    """Multi-step reasoning chain engine.

    Implements various chain-of-thought patterns for
    structured security reasoning.
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._log = logger.bind(component="reasoning_chain")

    async def reason(
        self,
        problem: str,
        chain_type: ChainType = ChainType.LINEAR,
        max_steps: int = 8,
        evidence: list[str] | None = None,
        convergence_threshold: float = 0.85,
    ) -> ReasoningChainResult:
        """Run a reasoning chain."""
        start = time.time()

        if chain_type == ChainType.LINEAR:
            result = await self._linear(problem, max_steps)
        elif chain_type == ChainType.VERIFIED:
            result = await self._verified(problem, max_steps)
        elif chain_type == ChainType.EVIDENCE:
            result = await self._evidence_based(problem, max_steps, evidence or [])
        elif chain_type == ChainType.ADVERSARIAL:
            result = await self._adversarial(problem, max_steps)
        elif chain_type == ChainType.SOCRATIC:
            result = await self._socratic(problem, max_steps)
        elif chain_type == ChainType.ITERATIVE:
            result = await self._iterative(problem, max_steps, convergence_threshold)
        else:
            result = await self._linear(problem, max_steps)

        result.time_ms = (time.time() - start) * 1000
        result.chain_type = chain_type
        result.question = problem

        self._log.info(
            "chain_complete",
            type=chain_type.value,
            steps=len(result.steps),
            confidence=round(result.overall_confidence, 2),
        )

        return result

    async def _linear(self, problem: str, max_steps: int) -> ReasoningChainResult:
        """Linear chain-of-thought reasoning."""
        result = ReasoningChainResult()
        steps: list[ChainStep] = []

        for step_num in range(1, max_steps + 1):
            previous = self._format_steps(steps)

            prompt = COT_STEP_PROMPT.format(
                problem=problem,
                previous_steps=previous or "(start)",
                step_num=step_num,
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=512,
            )

            data = self._parse_json(response)
            step = ChainStep(
                step_num=step_num,
                thought=data.get("thought", ""),
                action=data.get("action", ""),
                confidence=data.get("confidence", 0.5),
                status=StepStatus.COMPLETE,
            )
            steps.append(step)

            if data.get("is_final", False):
                result.conclusion = data.get("action", "")
                break

        result.steps = steps
        result.overall_confidence = (
            sum(s.confidence for s in steps) / max(1, len(steps))
        )
        if not result.conclusion and steps:
            result.conclusion = steps[-1].action

        return result

    async def _verified(self, problem: str, max_steps: int) -> ReasoningChainResult:
        """Chain-of-thought with verification at each step."""
        result = ReasoningChainResult()
        steps: list[ChainStep] = []

        for step_num in range(1, max_steps + 1):
            previous = self._format_steps(steps)

            # Generate thought
            prompt = COT_STEP_PROMPT.format(
                problem=problem,
                previous_steps=previous or "(start)",
                step_num=step_num,
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=512,
            )

            data = self._parse_json(response)
            step = ChainStep(
                step_num=step_num,
                thought=data.get("thought", ""),
                action=data.get("action", ""),
                confidence=data.get("confidence", 0.5),
                status=StepStatus.VERIFYING,
            )

            # Verify the step
            verify_prompt = VERIFY_STEP_PROMPT.format(
                problem=problem,
                thought=step.thought,
                action=step.action,
                evidence="N/A",
            )

            verify_response = await self._router.generate(
                messages=[{"role": "user", "content": verify_prompt}],
                task_type="reasoning",
                temperature=0.1,
                max_tokens=256,
            )

            verify_data = self._parse_json(verify_response)
            step.verification = json.dumps(verify_data.get("issues", []))

            if verify_data.get("valid", True):
                step.status = StepStatus.COMPLETE
            else:
                # Use corrected thought
                corrected = verify_data.get("corrected_thought", "")
                if corrected:
                    step.thought = corrected
                step.status = StepStatus.COMPLETE
                step.confidence *= 0.8  # Reduce confidence for corrected steps

            steps.append(step)

            if data.get("is_final", False):
                result.conclusion = step.action
                break

        result.steps = steps
        result.overall_confidence = (
            sum(s.confidence for s in steps) / max(1, len(steps))
        )
        if not result.conclusion and steps:
            result.conclusion = steps[-1].action

        return result

    async def _evidence_based(
        self,
        problem: str,
        max_steps: int,
        evidence: list[str],
    ) -> ReasoningChainResult:
        """Evidence-based reasoning where each claim cites evidence."""
        result = ReasoningChainResult()
        steps: list[ChainStep] = []
        evidence_text = "\n".join(f"- {e[:200]}" for e in evidence[:10])

        for step_num in range(1, max_steps + 1):
            previous = "\n".join(
                f"Claim {s.step_num}: {s.thought[:100]}" for s in steps
            )

            prompt = EVIDENCE_STEP_PROMPT.format(
                problem=problem,
                previous=previous or "(none)",
                evidence=evidence_text or "No specific evidence available",
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=512,
            )

            data = self._parse_json(response)
            step = ChainStep(
                step_num=step_num,
                thought=data.get("claim", ""),
                evidence=data.get("evidence", []),
                confidence=data.get("confidence", 0.5),
                status=StepStatus.COMPLETE,
            )
            steps.append(step)

            if data.get("is_final", False):
                result.conclusion = data.get("claim", "")
                break

        result.steps = steps
        result.overall_confidence = (
            sum(s.confidence for s in steps) / max(1, len(steps))
        )
        return result

    async def _adversarial(self, problem: str, max_steps: int) -> ReasoningChainResult:
        """Adversarial reasoning — argue both sides."""
        result = ReasoningChainResult()
        steps: list[ChainStep] = []

        positions = ["The target is vulnerable", "The target is not vulnerable"]

        for step_num in range(1, max_steps + 1):
            position = positions[step_num % 2]
            previous = "\n".join(
                f"Round {s.step_num}: {s.thought[:80]} | Counter: {s.counter_argument[:80]}"
                for s in steps
            )

            prompt = ADVERSARIAL_PROMPT.format(
                problem=problem,
                position=position,
                previous=previous or "(first round)",
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.3,
                max_tokens=512,
            )

            data = self._parse_json(response)
            step = ChainStep(
                step_num=step_num,
                thought=data.get("argument", ""),
                counter_argument=data.get("counter_argument", ""),
                evidence=data.get("evidence_for", []),
                confidence=data.get("net_confidence", 0.5),
                status=StepStatus.COMPLETE,
            )
            steps.append(step)

            if data.get("is_final", False):
                break

        result.steps = steps
        result.overall_confidence = (
            sum(s.confidence for s in steps) / max(1, len(steps))
        )
        if steps:
            result.conclusion = steps[-1].thought
        return result

    async def _socratic(self, problem: str, max_steps: int) -> ReasoningChainResult:
        """Socratic reasoning — answer through questions."""
        result = ReasoningChainResult()
        steps: list[ChainStep] = []

        for step_num in range(1, max_steps + 1):
            previous_qa = "\n".join(
                f"Q{s.step_num}: {s.questions[0] if s.questions else ''}\n"
                f"A{s.step_num}: {s.observation[:100]}"
                for s in steps
            )

            prompt = SOCRATIC_PROMPT.format(
                question=problem,
                previous_qa=previous_qa or "(start)",
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=512,
            )

            data = self._parse_json(response)
            step = ChainStep(
                step_num=step_num,
                thought=data.get("how_it_helps", ""),
                action=data.get("sub_question", ""),
                observation=data.get("answer", ""),
                questions=[data.get("sub_question", "")],
                confidence=data.get("confidence", 0.5),
                status=StepStatus.COMPLETE,
            )
            steps.append(step)

            if data.get("main_question_answered", False):
                result.conclusion = data.get("final_answer", "")
                result.converged = True
                break

        result.steps = steps
        result.overall_confidence = (
            sum(s.confidence for s in steps) / max(1, len(steps))
        )
        return result

    async def _iterative(
        self,
        problem: str,
        max_steps: int,
        convergence_threshold: float,
    ) -> ReasoningChainResult:
        """Iterative reasoning — loop until convergence."""
        result = ReasoningChainResult()
        steps: list[ChainStep] = []
        last_confidence = 0.0

        for step_num in range(1, max_steps + 1):
            previous = self._format_steps(steps)

            prompt = COT_STEP_PROMPT.format(
                problem=problem,
                previous_steps=previous or "(start)",
                step_num=step_num,
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=max(0.1, 0.3 - step_num * 0.03),  # Decrease temp over iterations
                max_tokens=512,
            )

            data = self._parse_json(response)
            step = ChainStep(
                step_num=step_num,
                thought=data.get("thought", ""),
                action=data.get("action", ""),
                confidence=data.get("confidence", 0.5),
                status=StepStatus.COMPLETE,
            )
            steps.append(step)
            result.iterations = step_num

            # Check convergence
            if step.confidence >= convergence_threshold:
                result.converged = True
                result.conclusion = step.action
                break

            # Check if we're oscillating
            if abs(step.confidence - last_confidence) < 0.05 and step_num > 3:
                result.converged = True
                result.conclusion = step.action
                break

            last_confidence = step.confidence

        result.steps = steps
        result.overall_confidence = (
            sum(s.confidence for s in steps) / max(1, len(steps))
        )
        return result

    # ── Utilities ────────────────────────────────────────

    def _format_steps(self, steps: list[ChainStep]) -> str:
        """Format previous steps for context."""
        return "\n".join(
            f"Step {s.step_num}: {s.thought[:150]}"
            for s in steps[-5:]  # Last 5 steps
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
