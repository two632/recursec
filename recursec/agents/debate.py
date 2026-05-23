"""Multi-agent debate system — structured argumentation for better decisions.

Models argue opposing positions and a judge decides:
1. Proposer: Argues FOR a hypothesis/action
2. Opposer: Argues AGAINST, finds weaknesses
3. Judge: Evaluates arguments and decides
4. Fact-checker: Verifies claims with evidence

Debate formats:
- Binary: For/against a single proposition
- Multi-option: Each model argues for a different option
- Devil's advocate: One model always opposes
- Round-robin: Models take turns critiquing
- Structured: Formal claim/evidence/rebuttal format

Uses:
- Vulnerability confirmation (is this a real vuln?)
- Strategy selection (which approach is best?)
- Severity assessment (how critical is this finding?)
- Exploit feasibility (can this actually be exploited?)
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


class DebateFormat(str, Enum):
    BINARY = "binary"
    MULTI_OPTION = "multi_option"
    DEVILS_ADVOCATE = "devils_advocate"
    ROUND_ROBIN = "round_robin"
    STRUCTURED = "structured"


class DebateRole(str, Enum):
    PROPOSER = "proposer"
    OPPOSER = "opposer"
    JUDGE = "judge"
    FACT_CHECKER = "fact_checker"


@dataclass
class Argument:
    """A single argument in the debate."""
    role: DebateRole
    model_type: str = ""
    position: str = ""  # What they're arguing for/against
    claims: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    rebuttals: list[str] = field(default_factory=list)
    confidence: float = 0.5
    round_num: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value, "model": self.model_type,
            "position": self.position[:200],
            "claims": self.claims[:5],
            "evidence": self.evidence[:3],
            "rebuttals": self.rebuttals[:3],
            "confidence": round(self.confidence, 2),
            "round": self.round_num,
        }


@dataclass
class DebateResult:
    """Result of a complete debate."""
    question: str = ""
    debate_format: DebateFormat = DebateFormat.BINARY
    rounds: int = 0
    arguments: list[Argument] = field(default_factory=list)
    verdict: str = ""
    verdict_reasoning: str = ""
    verdict_confidence: float = 0.0
    consensus_reached: bool = False
    key_points_for: list[str] = field(default_factory=list)
    key_points_against: list[str] = field(default_factory=list)
    total_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question[:200],
            "format": self.debate_format.value,
            "rounds": self.rounds,
            "total_arguments": len(self.arguments),
            "verdict": self.verdict[:200],
            "confidence": round(self.verdict_confidence, 2),
            "consensus": self.consensus_reached,
            "time_ms": round(self.total_time_ms, 1),
        }


# ── Prompt Templates ────────────────────────────────────────

PROPOSER_PROMPT = """You are arguing FOR this position. Make the strongest case possible.

Proposition: {proposition}
Context: {context}
{previous_arguments}

Make your case with:
1. Clear claims supported by evidence
2. Logical reasoning
3. If there were previous arguments against, rebut them

Respond as JSON:
{{
  "position": "your position statement",
  "claims": ["claim 1", "claim 2", "claim 3"],
  "evidence": ["evidence supporting each claim"],
  "rebuttals": ["rebuttals to opposing arguments (if any)"],
  "confidence": 0.X
}}"""

OPPOSER_PROMPT = """You are arguing AGAINST this position. Find every weakness.

Proposition: {proposition}
Context: {context}
Arguments for: {for_arguments}

Challenge the proposition:
1. Find logical flaws in the claims
2. Identify missing evidence
3. Present counter-evidence
4. Consider alternative explanations

Respond as JSON:
{{
  "position": "your counter-position",
  "claims": ["counter-claim 1", "counter-claim 2"],
  "evidence": ["evidence against the proposition"],
  "rebuttals": ["rebuttals to the proposer's claims"],
  "weaknesses_found": ["specific weaknesses in the argument"],
  "confidence": 0.X
}}"""

JUDGE_PROMPT = """You are the judge in this security debate. Evaluate the arguments fairly.

Question: {question}
Context: {context}

Arguments FOR:
{for_arguments}

Arguments AGAINST:
{against_arguments}

Evaluate:
1. Which side has stronger evidence?
2. Which claims are well-supported?
3. Which rebuttals are effective?
4. What's the most reasonable conclusion?

Respond as JSON:
{{
  "verdict": "your decision (for/against/nuanced)",
  "reasoning": "detailed reasoning",
  "strong_points_for": ["strongest arguments for"],
  "strong_points_against": ["strongest arguments against"],
  "unresolved": ["questions that remain unresolved"],
  "confidence": 0.X,
  "recommendation": "final recommendation"
}}"""

FACT_CHECK_PROMPT = """Fact-check these claims from a security debate.

Claims to verify:
{claims}

Context: {context}

For each claim, evaluate:
1. Is this technically accurate?
2. Is the evidence cited valid?
3. Are there any logical fallacies?

Respond as JSON:
{{
  "verified": [
    {{
      "claim": "the claim",
      "verdict": "true|false|partially_true|unverifiable",
      "reasoning": "why",
      "corrections": "any corrections needed"
    }}
  ]
}}"""

MULTI_OPTION_PROMPT = """You are advocating for option: {option}

Question: {question}
All options: {all_options}
Context: {context}

Make the strongest case for YOUR option compared to the others.

Respond as JSON:
{{
  "option": "{option}",
  "advantages": ["why this option is best"],
  "disadvantages_of_others": ["why other options are worse"],
  "evidence": ["supporting evidence"],
  "confidence": 0.X
}}"""


class DebateEngine:
    """Multi-model debate system for robust decision making.

    Uses structured argumentation to reach better conclusions
    by having models argue opposing positions.
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._debate_history: list[DebateResult] = []
        self._log = logger.bind(component="debate")

    async def debate_binary(
        self,
        proposition: str,
        context: str = "",
        rounds: int = 3,
        proposer_model: str = "security",
        opposer_model: str = "reasoning",
        judge_model: str = "reasoning",
    ) -> DebateResult:
        """Run a binary (for/against) debate."""
        start = time.time()
        result = DebateResult(
            question=proposition,
            debate_format=DebateFormat.BINARY,
        )

        previous_args = ""
        for_args: list[Argument] = []
        against_args: list[Argument] = []

        for round_num in range(rounds):
            # Proposer argues FOR
            proposer_response = await self._router.generate(
                messages=[{"role": "user", "content": PROPOSER_PROMPT.format(
                    proposition=proposition, context=context,
                    previous_arguments=previous_args,
                )}],
                task_type=proposer_model,
                temperature=0.3,
                max_tokens=1024,
            )

            prop_data = self._parse_json(proposer_response)
            prop_arg = Argument(
                role=DebateRole.PROPOSER,
                model_type=proposer_model,
                position=prop_data.get("position", ""),
                claims=prop_data.get("claims", []),
                evidence=prop_data.get("evidence", []),
                rebuttals=prop_data.get("rebuttals", []),
                confidence=prop_data.get("confidence", 0.5),
                round_num=round_num,
            )
            for_args.append(prop_arg)
            result.arguments.append(prop_arg)

            # Opposer argues AGAINST
            opposer_response = await self._router.generate(
                messages=[{"role": "user", "content": OPPOSER_PROMPT.format(
                    proposition=proposition, context=context,
                    for_arguments=json.dumps(prop_data)[:1500],
                )}],
                task_type=opposer_model,
                temperature=0.3,
                max_tokens=1024,
            )

            opp_data = self._parse_json(opposer_response)
            opp_arg = Argument(
                role=DebateRole.OPPOSER,
                model_type=opposer_model,
                position=opp_data.get("position", ""),
                claims=opp_data.get("claims", []),
                evidence=opp_data.get("evidence", []),
                rebuttals=opp_data.get("rebuttals", []),
                confidence=opp_data.get("confidence", 0.5),
                round_num=round_num,
            )
            against_args.append(opp_arg)
            result.arguments.append(opp_arg)

            # Build previous arguments for next round
            previous_args = f"Previous round - Against: {json.dumps(opp_data)[:500]}"

        # Judge decides
        for_text = "\n".join(
            f"Round {a.round_num}: {json.dumps(a.to_dict())[:300]}"
            for a in for_args
        )
        against_text = "\n".join(
            f"Round {a.round_num}: {json.dumps(a.to_dict())[:300]}"
            for a in against_args
        )

        judge_response = await self._router.generate(
            messages=[{"role": "user", "content": JUDGE_PROMPT.format(
                question=proposition, context=context,
                for_arguments=for_text, against_arguments=against_text,
            )}],
            task_type=judge_model,
            temperature=0.1,
            max_tokens=1024,
        )

        judge_data = self._parse_json(judge_response)
        result.verdict = judge_data.get("verdict", "")
        result.verdict_reasoning = judge_data.get("reasoning", "")
        result.verdict_confidence = judge_data.get("confidence", 0.5)
        result.key_points_for = judge_data.get("strong_points_for", [])
        result.key_points_against = judge_data.get("strong_points_against", [])
        result.rounds = rounds
        result.total_time_ms = (time.time() - start) * 1000

        # Check consensus
        if all(a.confidence > 0.7 for a in for_args) and result.verdict_confidence > 0.7:
            result.consensus_reached = True

        self._debate_history.append(result)
        self._log.info(
            "debate_complete",
            verdict=result.verdict[:50],
            confidence=round(result.verdict_confidence, 2),
        )

        return result

    async def debate_multi_option(
        self,
        question: str,
        options: list[str],
        context: str = "",
        model_types: list[str] | None = None,
    ) -> DebateResult:
        """Debate between multiple options, each with its own advocate."""
        start = time.time()
        result = DebateResult(
            question=question,
            debate_format=DebateFormat.MULTI_OPTION,
        )

        models = model_types or ["security", "reasoning", "code", "general"]

        # Each option gets an advocate
        for idx, option in enumerate(options):
            model_type = models[idx % len(models)]

            response = await self._router.generate(
                messages=[{"role": "user", "content": MULTI_OPTION_PROMPT.format(
                    option=option, question=question,
                    all_options=json.dumps(options),
                    context=context,
                )}],
                task_type=model_type,
                temperature=0.3,
                max_tokens=1024,
            )

            data = self._parse_json(response)
            arg = Argument(
                role=DebateRole.PROPOSER,
                model_type=model_type,
                position=option,
                claims=data.get("advantages", []),
                evidence=data.get("evidence", []),
                confidence=data.get("confidence", 0.5),
            )
            result.arguments.append(arg)

        # Judge selects best option
        args_text = "\n\n".join(
            f"Option '{a.position}':\n{json.dumps(a.to_dict())[:500]}"
            for a in result.arguments
        )

        judge_response = await self._router.generate(
            messages=[{"role": "user", "content": f"""Select the best option from this debate.

Question: {question}
Context: {context}

Arguments:
{args_text}

Respond as JSON:
{{"best_option": "...", "reasoning": "...", "confidence": 0.X}}"""}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=512,
        )

        judge_data = self._parse_json(judge_response)
        result.verdict = judge_data.get("best_option", "")
        result.verdict_reasoning = judge_data.get("reasoning", "")
        result.verdict_confidence = judge_data.get("confidence", 0.5)
        result.rounds = 1
        result.total_time_ms = (time.time() - start) * 1000

        self._debate_history.append(result)
        return result

    async def fact_check(
        self,
        claims: list[str],
        context: str = "",
    ) -> list[dict[str, Any]]:
        """Fact-check a list of claims."""
        prompt = FACT_CHECK_PROMPT.format(
            claims=json.dumps(claims),
            context=context,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        return data.get("verified", [])

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self._debate_history[-limit:]]

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
