"""Extended reasoning strategies — advanced reasoning patterns beyond base engine.

Adds:
- OODA reasoning: Observe-Orient-Decide-Act for tactical decisions
- Adversarial reasoning: Think like an attacker/defender
- Analogical reasoning: Apply known patterns to new situations
- Counterfactual reasoning: "What if" scenarios
- Abductive reasoning: Best explanation from evidence
- Causal reasoning: Cause-and-effect chains
- Temporal reasoning: Time-ordered analysis
- Multi-perspective reasoning: Consider from multiple viewpoints
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


class ExtendedStrategy(str, Enum):
    OODA = "ooda"
    ADVERSARIAL = "adversarial"
    ANALOGICAL = "analogical"
    COUNTERFACTUAL = "counterfactual"
    ABDUCTIVE = "abductive"
    CAUSAL = "causal"
    TEMPORAL = "temporal"
    MULTI_PERSPECTIVE = "multi_perspective"
    RECURSIVE_DECOMPOSITION = "recursive_decomposition"
    CONSTRAINT_PROPAGATION = "constraint_propagation"


@dataclass
class ReasoningResult:
    """Result from extended reasoning."""
    strategy: ExtendedStrategy
    question: str
    answer: str = ""
    confidence: float = 0.0
    reasoning_chain: list[dict[str, str]] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "answer": self.answer[:500],
            "confidence": round(self.confidence, 3),
            "chain_length": len(self.reasoning_chain),
            "alternatives": len(self.alternatives),
            "time_ms": round(self.time_ms, 1),
        }


# ── OODA Reasoning ──────────────────────────────────────

OODA_PROMPT = """Apply the OODA (Observe-Orient-Decide-Act) loop to this security situation.

Situation: {situation}
Available information: {information}
Available actions: {actions}
Constraints: {constraints}

OBSERVE: What do we see? What data is available? What are the key indicators?
ORIENT: How does this fit with what we know? What patterns match? What's the context?
DECIDE: What's the best course of action? Why? What are the alternatives?
ACT: What specific action should we take? What's the expected outcome?

Respond as JSON:
{{
  "observe": {{
    "key_indicators": ["..."],
    "data_quality": "high|medium|low",
    "information_gaps": ["..."]
  }},
  "orient": {{
    "pattern_match": "what known pattern this matches",
    "context": "broader context",
    "mental_model": "how we're framing this situation",
    "biases_to_watch": ["potential cognitive biases"]
  }},
  "decide": {{
    "decision": "what we decided",
    "reasoning": "why",
    "alternatives": ["other options considered"],
    "risk_assessment": "risk of this decision"
  }},
  "act": {{
    "action": "specific action to take",
    "expected_outcome": "what we expect",
    "success_criteria": "how we know it worked",
    "fallback": "what to do if it fails"
  }},
  "confidence": 0.X
}}"""


# ── Adversarial Reasoning ───────────────────────────────

ADVERSARIAL_PROMPT = """Think about this security scenario from BOTH the attacker and defender perspectives.

Scenario: {scenario}
Target: {target}
Known information: {information}

ATTACKER PERSPECTIVE:
- What would I target first?
- What techniques would I use?
- How would I avoid detection?
- What's my end goal?

DEFENDER PERSPECTIVE:
- What are the most critical assets?
- Where are the weakest points?
- What monitoring would catch attacks?
- What mitigations should be in place?

Respond as JSON:
{{
  "attacker": {{
    "priority_targets": ["..."],
    "techniques": ["..."],
    "evasion_methods": ["..."],
    "end_goals": ["..."],
    "likely_attack_path": "step-by-step description"
  }},
  "defender": {{
    "critical_assets": ["..."],
    "weak_points": ["..."],
    "detection_opportunities": ["..."],
    "recommended_mitigations": ["..."],
    "monitoring_priorities": ["..."]
  }},
  "synthesis": {{
    "highest_risk": "the single highest risk scenario",
    "most_impactful_defense": "the single most impactful defensive measure",
    "confidence": 0.X
  }}
}}"""


# ── Analogical Reasoning ────────────────────────────────

ANALOGICAL_PROMPT = """Use analogical reasoning to analyze this security situation.

Current situation: {situation}
Known similar cases: {known_cases}
Target characteristics: {target}

Find analogies from known security incidents, vulnerabilities, or attack patterns.
Map what worked (or failed) in similar situations to the current one.

Respond as JSON:
{{
  "analogies": [
    {{
      "known_case": "description of similar case",
      "similarity": "what's similar",
      "differences": "what's different",
      "lessons": "what we can learn",
      "applies_here": "how this applies to current situation",
      "confidence": 0.X
    }}
  ],
  "synthesis": "overall conclusion from analogical reasoning",
  "recommended_actions": ["based on analogies"],
  "confidence": 0.X
}}"""


# ── Counterfactual Reasoning ────────────────────────────

COUNTERFACTUAL_PROMPT = """Explore counterfactual scenarios for this security assessment.

Current findings: {findings}
Target: {target}
Actions taken: {actions}

For each "what if" scenario, explore what might be different:
1. What if a different initial approach was taken?
2. What if the target had different configurations?
3. What if we missed something important?
4. What if the findings are more severe than they appear?

Respond as JSON:
{{
  "counterfactuals": [
    {{
      "scenario": "what if...",
      "likely_outcome": "what would happen",
      "implications": "what this means for our assessment",
      "probability": 0.X,
      "action_if_true": "what we should do"
    }}
  ],
  "most_concerning": "the single most concerning counterfactual",
  "confidence": 0.X
}}"""


# ── Abductive Reasoning ────────────────────────────────

ABDUCTIVE_PROMPT = """Use abductive reasoning (inference to best explanation) for this security evidence.

Evidence collected: {evidence}
Target: {target}
Context: {context}

What is the BEST EXPLANATION for the observed evidence? Consider:
- What vulnerabilities could produce these symptoms?
- What attack patterns match this evidence?
- What misconfigurations could cause these results?
- Are there alternative explanations?

Respond as JSON:
{{
  "best_explanation": {{
    "hypothesis": "the most likely explanation",
    "supporting_evidence": ["evidence that supports this"],
    "confidence": 0.X,
    "alternative_explanations": [
      {{
        "hypothesis": "alternative",
        "confidence": 0.X,
        "why_less_likely": "reason"
      }}
    ]
  }},
  "recommended_tests": ["tests to confirm the best explanation"],
  "confidence": 0.X
}}"""


# ── Causal Reasoning ────────────────────────────────────

CAUSAL_PROMPT = """Analyze the causal chain in this security scenario.

Observations: {observations}
Known causes: {known_causes}
Target: {target}

Build a causal model:
1. What caused each observation?
2. What are the root causes?
3. What will happen next if nothing is done?
4. What interventions would break the causal chain?

Respond as JSON:
{{
  "causal_chain": [
    {{
      "effect": "what we observe",
      "cause": "what caused it",
      "confidence": 0.X,
      "reversible": true/false
    }}
  ],
  "root_causes": ["fundamental causes"],
  "predicted_consequences": ["what will happen next"],
  "interventions": [
    {{
      "action": "what to do",
      "breaks_chain_at": "which causal link it breaks",
      "effectiveness": 0.X
    }}
  ],
  "confidence": 0.X
}}"""


# ── Multi-Perspective Reasoning ─────────────────────────

MULTI_PERSPECTIVE_PROMPT = """Analyze this security situation from multiple expert perspectives.

Situation: {situation}
Target: {target}

Perspectives to consider:
1. PENTEST EXPERT: Focus on exploitation potential
2. BLUE TEAM: Focus on detection and response
3. COMPLIANCE: Focus on regulatory implications
4. BUSINESS: Focus on business impact
5. DEVELOPER: Focus on root cause in code/config

Respond as JSON:
{{
  "perspectives": [
    {{
      "role": "perspective name",
      "assessment": "their assessment",
      "key_concerns": ["..."],
      "recommendations": ["..."],
      "severity_rating": "critical|high|medium|low"
    }}
  ],
  "consensus": "where all perspectives agree",
  "disagreements": "where perspectives disagree",
  "overall_recommendation": "balanced recommendation",
  "confidence": 0.X
}}"""


# ── Recursive Decomposition ─────────────────────────────

RECURSIVE_DECOMPOSITION_PROMPT = """Recursively decompose this security problem into sub-problems.

Problem: {problem}
Target: {target}
Depth: {depth} (max {max_depth})

Break this into 2-4 smaller sub-problems. For each sub-problem,
indicate if it can be solved directly or needs further decomposition.

Respond as JSON:
{{
  "sub_problems": [
    {{
      "description": "sub-problem description",
      "can_solve_directly": true/false,
      "tools_needed": ["..."],
      "estimated_complexity": "simple|moderate|complex",
      "dependencies": ["indices of sub-problems this depends on"]
    }}
  ],
  "solve_order": [0, 1, 2],
  "parallel_groups": [[0, 1], [2]]
}}"""


class ExtendedReasoning:
    """Extended reasoning strategies for agent intelligence."""

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._log = logger.bind(component="extended_reasoning")
        self._strategy_map = {
            ExtendedStrategy.OODA: self._ooda,
            ExtendedStrategy.ADVERSARIAL: self._adversarial,
            ExtendedStrategy.ANALOGICAL: self._analogical,
            ExtendedStrategy.COUNTERFACTUAL: self._counterfactual,
            ExtendedStrategy.ABDUCTIVE: self._abductive,
            ExtendedStrategy.CAUSAL: self._causal,
            ExtendedStrategy.MULTI_PERSPECTIVE: self._multi_perspective,
            ExtendedStrategy.RECURSIVE_DECOMPOSITION: self._recursive_decomposition,
        }

    async def reason(
        self,
        question: str,
        strategy: ExtendedStrategy,
        context: dict[str, Any] | None = None,
    ) -> ReasoningResult:
        """Execute an extended reasoning strategy."""
        start = time.time()

        handler = self._strategy_map.get(strategy)
        if not handler:
            return ReasoningResult(
                strategy=strategy, question=question,
                answer=f"Strategy {strategy.value} not implemented",
            )

        result = await handler(question, context or {})
        result.time_ms = (time.time() - start) * 1000

        self._log.info(
            "reasoning_complete",
            strategy=strategy.value,
            confidence=round(result.confidence, 2),
            time_ms=round(result.time_ms, 1),
        )

        return result

    async def _ooda(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """OODA loop reasoning."""
        prompt = OODA_PROMPT.format(
            situation=question,
            information=json.dumps(context.get("information", {}))[:2000],
            actions=json.dumps(context.get("available_actions", []))[:1000],
            constraints=json.dumps(context.get("constraints", {}))[:500],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        act_data = data.get("act", {})

        result = ReasoningResult(
            strategy=ExtendedStrategy.OODA,
            question=question,
            answer=act_data.get("action", response),
            confidence=data.get("confidence", 0.5),
        )

        for phase in ["observe", "orient", "decide", "act"]:
            phase_data = data.get(phase, {})
            if phase_data:
                result.reasoning_chain.append({
                    "phase": phase,
                    "content": json.dumps(phase_data)[:500],
                })

        return result

    async def _adversarial(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Adversarial reasoning — attacker vs. defender viewpoints."""
        prompt = ADVERSARIAL_PROMPT.format(
            scenario=question,
            target=context.get("target", ""),
            information=json.dumps(context.get("information", {}))[:2000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.3,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        synthesis = data.get("synthesis", {})

        result = ReasoningResult(
            strategy=ExtendedStrategy.ADVERSARIAL,
            question=question,
            answer=synthesis.get("highest_risk", response),
            confidence=synthesis.get("confidence", 0.5),
        )

        result.reasoning_chain.append({"phase": "attacker", "content": json.dumps(data.get("attacker", {}))[:500]})
        result.reasoning_chain.append({"phase": "defender", "content": json.dumps(data.get("defender", {}))[:500]})
        result.reasoning_chain.append({"phase": "synthesis", "content": json.dumps(synthesis)[:500]})

        return result

    async def _analogical(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Analogical reasoning from known cases."""
        prompt = ANALOGICAL_PROMPT.format(
            situation=question,
            known_cases=json.dumps(context.get("known_cases", []))[:2000],
            target=context.get("target", ""),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        result = ReasoningResult(
            strategy=ExtendedStrategy.ANALOGICAL,
            question=question,
            answer=data.get("synthesis", response),
            confidence=data.get("confidence", 0.5),
        )

        for analogy in data.get("analogies", []):
            result.reasoning_chain.append({
                "case": analogy.get("known_case", ""),
                "lesson": analogy.get("lessons", ""),
                "confidence": analogy.get("confidence", 0.5),
            })

        result.alternatives = data.get("recommended_actions", [])
        return result

    async def _counterfactual(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Counterfactual what-if reasoning."""
        prompt = COUNTERFACTUAL_PROMPT.format(
            findings=json.dumps(context.get("findings", []))[:2000],
            target=context.get("target", ""),
            actions=json.dumps(context.get("actions", []))[:1000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.4,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        result = ReasoningResult(
            strategy=ExtendedStrategy.COUNTERFACTUAL,
            question=question,
            answer=data.get("most_concerning", response),
            confidence=data.get("confidence", 0.5),
        )

        for cf in data.get("counterfactuals", []):
            result.reasoning_chain.append({
                "scenario": cf.get("scenario", ""),
                "outcome": cf.get("likely_outcome", ""),
                "probability": cf.get("probability", 0.5),
            })
            if cf.get("probability", 0) > 0.5:
                result.alternatives.append(cf.get("action_if_true", ""))

        return result

    async def _abductive(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Abductive reasoning — inference to best explanation."""
        prompt = ABDUCTIVE_PROMPT.format(
            evidence=json.dumps(context.get("evidence", []))[:2000],
            target=context.get("target", ""),
            context=json.dumps(context.get("context_info", {}))[:1000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        best = data.get("best_explanation", {})

        result = ReasoningResult(
            strategy=ExtendedStrategy.ABDUCTIVE,
            question=question,
            answer=best.get("hypothesis", response),
            confidence=best.get("confidence", data.get("confidence", 0.5)),
        )

        result.reasoning_chain.append({
            "best_explanation": best.get("hypothesis", ""),
            "evidence": best.get("supporting_evidence", []),
        })

        for alt in best.get("alternative_explanations", []):
            result.alternatives.append(alt.get("hypothesis", ""))

        return result

    async def _causal(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Causal chain reasoning."""
        prompt = CAUSAL_PROMPT.format(
            observations=json.dumps(context.get("observations", []))[:2000],
            known_causes=json.dumps(context.get("known_causes", []))[:1000],
            target=context.get("target", ""),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        result = ReasoningResult(
            strategy=ExtendedStrategy.CAUSAL,
            question=question,
            confidence=data.get("confidence", 0.5),
        )

        root_causes = data.get("root_causes", [])
        result.answer = "; ".join(root_causes) if root_causes else response

        for link in data.get("causal_chain", []):
            result.reasoning_chain.append({
                "cause": link.get("cause", ""),
                "effect": link.get("effect", ""),
                "confidence": link.get("confidence", 0.5),
            })

        for intervention in data.get("interventions", []):
            result.alternatives.append(intervention.get("action", ""))

        return result

    async def _multi_perspective(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Multi-perspective analysis."""
        prompt = MULTI_PERSPECTIVE_PROMPT.format(
            situation=question,
            target=context.get("target", ""),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=4096,
        )

        data = self._parse_json(response)
        result = ReasoningResult(
            strategy=ExtendedStrategy.MULTI_PERSPECTIVE,
            question=question,
            answer=data.get("overall_recommendation", response),
            confidence=data.get("confidence", 0.5),
        )

        for perspective in data.get("perspectives", []):
            result.reasoning_chain.append({
                "role": perspective.get("role", ""),
                "assessment": perspective.get("assessment", ""),
                "severity": perspective.get("severity_rating", ""),
            })

        if data.get("disagreements"):
            result.metadata["disagreements"] = data["disagreements"]

        return result

    async def _recursive_decomposition(self, question: str, context: dict[str, Any]) -> ReasoningResult:
        """Recursive problem decomposition."""
        max_depth = context.get("max_depth", 3)
        target = context.get("target", "")

        sub_problems = await self._decompose(question, target, depth=0, max_depth=max_depth)

        result = ReasoningResult(
            strategy=ExtendedStrategy.RECURSIVE_DECOMPOSITION,
            question=question,
            confidence=0.7,
        )

        for sp in sub_problems:
            result.reasoning_chain.append(sp)

        result.answer = json.dumps(sub_problems)
        return result

    async def _decompose(
        self, problem: str, target: str, depth: int, max_depth: int,
    ) -> list[dict[str, Any]]:
        """Recursively decompose a problem."""
        if depth >= max_depth:
            return [{"problem": problem, "depth": depth, "leaf": True}]

        prompt = RECURSIVE_DECOMPOSITION_PROMPT.format(
            problem=problem, target=target,
            depth=depth, max_depth=max_depth,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        results = []

        for sp in data.get("sub_problems", []):
            entry: dict[str, Any] = {
                "problem": sp.get("description", ""),
                "depth": depth,
                "can_solve_directly": sp.get("can_solve_directly", True),
                "tools_needed": sp.get("tools_needed", []),
                "complexity": sp.get("estimated_complexity", "moderate"),
            }

            if not sp.get("can_solve_directly", True):
                entry["sub_problems"] = await self._decompose(
                    sp.get("description", ""), target,
                    depth + 1, max_depth,
                )

            results.append(entry)

        return results

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
