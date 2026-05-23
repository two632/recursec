"""Advanced reasoning engine — chain-of-thought, tree-of-thought, multi-model consensus.

This is the brain behind agent decision-making. Instead of simple prompt→response,
this engine implements sophisticated reasoning strategies that dramatically improve
agent intelligence and reduce hallucination.

Strategies:
- Chain-of-Thought (CoT): Linear step-by-step reasoning
- Tree-of-Thought (ToT): Branching exploration with evaluation and pruning
- Self-Consistency: Multiple reasoning paths → majority vote
- Multi-Model Consensus: Ask multiple LLMs → weighted agreement
- Debate: Models argue opposing positions → judge decides
- Reflection: Agent critiques its own reasoning → iterates
- Metacognition: Agent evaluates its own confidence and uncertainty
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ReasoningStrategy(str, Enum):
    CHAIN_OF_THOUGHT = "cot"
    TREE_OF_THOUGHT = "tot"
    SELF_CONSISTENCY = "self_consistency"
    MULTI_MODEL_CONSENSUS = "consensus"
    DEBATE = "debate"
    REFLECTION = "reflection"
    METACOGNITION = "metacognition"
    REACT = "react"
    PLAN_AND_SOLVE = "plan_and_solve"
    STEP_BACK = "step_back"


class ConfidenceLevel(str, Enum):
    VERY_HIGH = "very_high"     # >0.9
    HIGH = "high"               # 0.7-0.9
    MEDIUM = "medium"           # 0.5-0.7
    LOW = "low"                 # 0.3-0.5
    VERY_LOW = "very_low"       # <0.3
    UNKNOWN = "unknown"


@dataclass
class ThoughtNode:
    """A single node in a reasoning tree."""
    id: str
    content: str
    parent_id: str | None = None
    children: list[ThoughtNode] = field(default_factory=list)
    score: float = 0.0
    depth: int = 0
    is_terminal: bool = False
    is_pruned: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    model_used: str = ""
    reasoning_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content[:300],
            "parent_id": self.parent_id,
            "children": [c.to_dict() for c in self.children],
            "score": self.score,
            "depth": self.depth,
            "is_terminal": self.is_terminal,
            "is_pruned": self.is_pruned,
            "model_used": self.model_used,
        }


@dataclass
class ReasoningTrace:
    """Complete trace of a reasoning session."""
    strategy: ReasoningStrategy
    question: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    final_answer: str = ""
    confidence: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    models_used: list[str] = field(default_factory=list)
    total_tokens: int = 0
    total_time_ms: float = 0.0
    tree: ThoughtNode | None = None
    alternatives: list[str] = field(default_factory=list)
    dissenting_views: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "question": self.question[:200],
            "steps": self.steps,
            "final_answer": self.final_answer[:500],
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "models_used": self.models_used,
            "total_tokens": self.total_tokens,
            "total_time_ms": round(self.total_time_ms, 1),
            "num_alternatives": len(self.alternatives),
            "num_dissenting": len(self.dissenting_views),
        }


@dataclass
class ReasoningConfig:
    """Configuration for reasoning engine."""
    default_strategy: ReasoningStrategy = ReasoningStrategy.CHAIN_OF_THOUGHT
    cot_max_steps: int = 10
    tot_max_depth: int = 4
    tot_branching_factor: int = 3
    tot_beam_width: int = 2
    self_consistency_samples: int = 5
    consensus_min_models: int = 2
    consensus_agreement_threshold: float = 0.6
    debate_rounds: int = 3
    reflection_max_iterations: int = 3
    metacognition_threshold: float = 0.5
    cache_enabled: bool = True
    cache_ttl_s: int = 3600


# ── Prompt Templates ────────────────────────────────────────

COT_SYSTEM = """You are an expert security analyst. Think step by step.
For each step:
1. State what you observe or know
2. State what you can infer
3. State what action to take next
4. Explain WHY this is the right action

Be thorough and precise. Show your reasoning at each step.
Format each step as:
STEP N:
OBSERVATION: ...
INFERENCE: ...
ACTION: ...
REASONING: ...
"""

COT_DECOMPOSE = """Break this problem into steps. For each step, explain what needs to be done and why.

Problem: {question}

Context: {context}

Provide your step-by-step plan as a numbered list. Each step should be specific and actionable."""

TOT_EXPAND = """Given the current reasoning state, generate {n} distinct next steps or hypotheses.
Each should be a meaningfully different approach or direction.

Current state: {state}
Problem: {question}
Depth: {depth}/{max_depth}

Generate exactly {n} different next steps. Format as:
OPTION 1: ...
OPTION 2: ...
OPTION 3: ..."""

TOT_EVALUATE = """Evaluate the following reasoning path for solving a security analysis problem.

Problem: {question}
Reasoning path: {path}

Rate this path on a scale of 0.0 to 1.0 based on:
- Correctness: Is the reasoning sound?
- Progress: Does it move toward solving the problem?
- Feasibility: Can this approach actually work?
- Completeness: Does it address all aspects?

Respond with ONLY a JSON object: {{"score": 0.X, "explanation": "brief reason"}}"""

SELF_CONSISTENCY_PROMPT = """Solve this security analysis problem. Think carefully and provide your answer.

Problem: {question}
Context: {context}

Provide your complete analysis and final answer."""

CONSENSUS_MERGE = """Multiple models have analyzed this security problem. Their responses are below.
Synthesize the best answer from all responses, noting any disagreements.

Problem: {question}

{responses}

Provide the synthesized answer, noting confidence level and any areas of disagreement."""

DEBATE_PROPOSE = """You are arguing {position} in a security analysis debate.

Question: {question}
Previous arguments: {history}

Make your strongest argument for your position. Be specific and cite evidence."""

DEBATE_JUDGE = """You are judging a security analysis debate.

Question: {question}

Arguments FOR:
{for_args}

Arguments AGAINST:
{against_args}

Provide your verdict: Which side has the stronger case? Why?
Format: {{"verdict": "for|against|nuanced", "confidence": 0.X, "reasoning": "...", "final_answer": "..."}}"""

REFLECTION_CRITIQUE = """Review your previous analysis for errors, gaps, or weaknesses.

Original question: {question}
Your previous analysis: {analysis}

Identify:
1. Any logical errors or unsupported claims
2. Missing considerations or blind spots
3. Assumptions that should be validated
4. Areas where confidence is low

Then provide an improved analysis addressing these issues."""

METACOGNITION_ASSESS = """Assess your confidence in the following analysis.

Question: {question}
Analysis: {analysis}

For each claim in the analysis, rate your confidence (0.0-1.0) and explain why.
Also identify:
- What you're most certain about and why
- What you're least certain about and why
- What additional information would increase your confidence

Format: {{"overall_confidence": 0.X, "claims": [...], "certain": [...], "uncertain": [...], "needed_info": [...]}}"""

STEP_BACK_ABSTRACT = """Before solving this specific problem, step back and consider the broader principles.

Specific problem: {question}

What are the general principles, patterns, or frameworks that apply here?
What similar problems have standard solutions?
What abstract concepts are relevant?

Provide the high-level analysis first, then apply it to the specific problem."""

PLAN_AND_SOLVE_PLAN = """Create a detailed plan to solve this problem before executing.

Problem: {question}
Available tools: {tools}
Available information: {context}

Create a plan with:
1. What information do we need?
2. What tools should we use and in what order?
3. How do we validate our findings?
4. What are the potential failure modes?
5. What is our success criteria?

Format as a structured JSON plan:
{{"steps": [{{"id": 1, "action": "...", "tool": "...", "depends_on": [], "validates": "..."}}], "success_criteria": "..."}}"""


class ReasoningEngine:
    """Advanced reasoning engine for agent intelligence.

    This engine wraps the model router and implements sophisticated
    reasoning strategies that go far beyond simple prompt→response.
    """

    def __init__(self, model_router: ModelRouter, config: ReasoningConfig | None = None):
        self.router = model_router
        self.config = config or ReasoningConfig()
        self._cache: dict[str, tuple[str, float]] = {}  # hash -> (result, timestamp)
        self._stats = {
            "total_reasoning_calls": 0,
            "cache_hits": 0,
            "total_tokens": 0,
            "strategy_usage": {},
            "avg_confidence": 0.0,
        }

    async def reason(
        self,
        question: str,
        context: str = "",
        strategy: ReasoningStrategy | None = None,
        task_type: str = "reasoning",
        tools: list[str] | None = None,
        system_prompt: str = "",
        **kwargs: Any,
    ) -> ReasoningTrace:
        """Main entry point — reason about a question using the specified strategy."""
        strategy = strategy or self.config.default_strategy
        self._stats["total_reasoning_calls"] += 1
        self._stats["strategy_usage"][strategy.value] = (
            self._stats["strategy_usage"].get(strategy.value, 0) + 1
        )

        # Check cache
        if self.config.cache_enabled:
            cache_key = self._cache_key(question, context, strategy)
            cached = self._get_cached(cache_key)
            if cached:
                self._stats["cache_hits"] += 1
                return cached

        start = time.monotonic()

        if strategy == ReasoningStrategy.CHAIN_OF_THOUGHT:
            trace = await self._chain_of_thought(question, context, task_type, system_prompt)
        elif strategy == ReasoningStrategy.TREE_OF_THOUGHT:
            trace = await self._tree_of_thought(question, context, task_type)
        elif strategy == ReasoningStrategy.SELF_CONSISTENCY:
            trace = await self._self_consistency(question, context, task_type)
        elif strategy == ReasoningStrategy.MULTI_MODEL_CONSENSUS:
            trace = await self._multi_model_consensus(question, context)
        elif strategy == ReasoningStrategy.DEBATE:
            trace = await self._debate(question, context, task_type)
        elif strategy == ReasoningStrategy.REFLECTION:
            trace = await self._reflection(question, context, task_type, system_prompt)
        elif strategy == ReasoningStrategy.METACOGNITION:
            trace = await self._metacognition(question, context, task_type)
        elif strategy == ReasoningStrategy.REACT:
            trace = await self._react(question, context, task_type, tools or [])
        elif strategy == ReasoningStrategy.PLAN_AND_SOLVE:
            trace = await self._plan_and_solve(question, context, task_type, tools or [])
        elif strategy == ReasoningStrategy.STEP_BACK:
            trace = await self._step_back(question, context, task_type)
        else:
            trace = await self._chain_of_thought(question, context, task_type, system_prompt)

        trace.total_time_ms = (time.monotonic() - start) * 1000
        trace.confidence_level = self._classify_confidence(trace.confidence)

        # Update stats
        running_avg = self._stats["avg_confidence"]
        n = self._stats["total_reasoning_calls"]
        self._stats["avg_confidence"] = (running_avg * (n - 1) + trace.confidence) / n

        # Cache result
        if self.config.cache_enabled:
            cache_key = self._cache_key(question, context, strategy)
            self._set_cached(cache_key, trace)

        logger.info(
            "reasoning_complete",
            strategy=strategy.value,
            confidence=round(trace.confidence, 2),
            time_ms=round(trace.total_time_ms, 1),
            steps=len(trace.steps),
        )

        return trace

    # ── Chain of Thought ────────────────────────────────────

    async def _chain_of_thought(
        self, question: str, context: str, task_type: str, system_prompt: str = ""
    ) -> ReasoningTrace:
        """Step-by-step linear reasoning."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.CHAIN_OF_THOUGHT, question=question)

        # Step 1: Decompose the problem
        decompose_prompt = COT_DECOMPOSE.format(question=question, context=context)
        plan = await self.router.generate(
            messages=[
                {"role": "system", "content": system_prompt or COT_SYSTEM},
                {"role": "user", "content": decompose_prompt},
            ],
            task_type=task_type,
            temperature=0.3,
            max_tokens=2048,
        )
        trace.steps.append({"type": "decompose", "content": plan})

        # Step 2: Execute each step with chain-of-thought
        accumulated_reasoning = f"Plan:\n{plan}\n\n"
        for step_num in range(1, self.config.cot_max_steps + 1):
            step_prompt = (
                f"Execute step {step_num} of your plan.\n\n"
                f"Previous reasoning:\n{accumulated_reasoning[-3000:]}\n\n"
                f"What is the result of this step? What do you conclude?"
            )
            step_result = await self.router.generate(
                messages=[
                    {"role": "system", "content": system_prompt or COT_SYSTEM},
                    {"role": "user", "content": step_prompt},
                ],
                task_type=task_type,
                temperature=0.2,
                max_tokens=2048,
            )
            trace.steps.append({"type": f"step_{step_num}", "content": step_result})
            accumulated_reasoning += f"\nStep {step_num}: {step_result}\n"

            # Check if reasoning is complete
            if any(kw in step_result.lower() for kw in [
                "conclusion:", "final answer:", "in summary:", "therefore,",
                "the answer is", "we can conclude", "final assessment:"
            ]):
                break

        # Step 3: Synthesize final answer
        synthesis_prompt = (
            f"Based on all your reasoning steps, provide a final comprehensive answer.\n\n"
            f"Full reasoning:\n{accumulated_reasoning[-4000:]}\n\n"
            f"Provide:\n1. Final answer/conclusion\n2. Confidence level (0.0-1.0)\n3. Key evidence supporting your conclusion"
        )
        final = await self.router.generate(
            messages=[
                {"role": "system", "content": system_prompt or COT_SYSTEM},
                {"role": "user", "content": synthesis_prompt},
            ],
            task_type=task_type,
            temperature=0.1,
            max_tokens=4096,
        )
        trace.final_answer = final
        trace.confidence = self._extract_confidence(final)
        return trace

    # ── Tree of Thought ─────────────────────────────────────

    async def _tree_of_thought(
        self, question: str, context: str, task_type: str
    ) -> ReasoningTrace:
        """Branching exploration with evaluation and pruning (beam search)."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.TREE_OF_THOUGHT, question=question)
        _node_counter = 0

        def make_node(content: str, parent_id: str | None, depth: int) -> ThoughtNode:
            nonlocal _node_counter
            _node_counter += 1
            return ThoughtNode(
                id=f"n{_node_counter}",
                content=content,
                parent_id=parent_id,
                depth=depth,
            )

        root = make_node(f"Problem: {question}\nContext: {context}", None, 0)
        trace.tree = root

        # Beam search: maintain top-k nodes at each depth
        beam = [root]

        for depth in range(1, self.config.tot_max_depth + 1):
            all_children: list[ThoughtNode] = []

            # Expand each node in the beam
            expand_tasks = []
            for node in beam:
                expand_tasks.append(
                    self._tot_expand(question, node, depth, task_type)
                )
            expand_results = await asyncio.gather(*expand_tasks, return_exceptions=True)

            for node, result in zip(beam, expand_results):
                if isinstance(result, list):
                    for child in result:
                        child_node = make_node(child, node.id, depth)
                        node.children.append(child_node)
                        all_children.append(child_node)

            if not all_children:
                break

            # Evaluate all children
            eval_tasks = [
                self._tot_evaluate(question, child, task_type)
                for child in all_children
            ]
            scores = await asyncio.gather(*eval_tasks, return_exceptions=True)

            for child, score in zip(all_children, scores):
                if isinstance(score, float):
                    child.score = score
                else:
                    child.score = 0.0

            # Keep top beam_width nodes
            all_children.sort(key=lambda n: n.score, reverse=True)
            beam = all_children[:self.config.tot_beam_width]

            # Prune low-scoring nodes
            for child in all_children[self.config.tot_beam_width:]:
                child.is_pruned = True

            trace.steps.append({
                "type": f"depth_{depth}",
                "expanded": len(all_children),
                "kept": len(beam),
                "best_score": beam[0].score if beam else 0,
                "best_content": beam[0].content[:200] if beam else "",
            })

        # Select best leaf and synthesize
        if beam:
            best = max(beam, key=lambda n: n.score)
            best.is_terminal = True

            # Build path from root to best
            path_contents = [best.content]
            current = best
            while current.parent_id:
                for node in beam:
                    if node.id == current.parent_id:
                        path_contents.insert(0, node.content)
                        current = node
                        break
                else:
                    break

            trace.final_answer = best.content
            trace.confidence = best.score
            trace.alternatives = [n.content[:200] for n in beam if n != best]

        return trace

    async def _tot_expand(
        self, question: str, node: ThoughtNode, depth: int, task_type: str
    ) -> list[str]:
        """Generate child thoughts for a node."""
        prompt = TOT_EXPAND.format(
            n=self.config.tot_branching_factor,
            state=node.content[:1500],
            question=question,
            depth=depth,
            max_depth=self.config.tot_max_depth,
        )
        response = await self.router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type=task_type,
            temperature=0.7,
            max_tokens=2048,
        )
        # Parse options
        options = []
        for line in response.split("\n"):
            line = line.strip()
            if line.startswith("OPTION") and ":" in line:
                options.append(line.split(":", 1)[1].strip())
        if not options:
            options = [response]
        return options[:self.config.tot_branching_factor]

    async def _tot_evaluate(
        self, question: str, node: ThoughtNode, task_type: str
    ) -> float:
        """Evaluate a thought node's quality."""
        # Build path from root
        path = node.content
        prompt = TOT_EVALUATE.format(question=question, path=path[:2000])

        response = await self.router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=512,
        )
        try:
            data = json.loads(response)
            return float(data.get("score", 0.5))
        except (json.JSONDecodeError, ValueError):
            # Try to extract a number
            import re
            match = re.search(r"(\d+\.?\d*)", response)
            if match:
                val = float(match.group(1))
                return min(val, 1.0)
            return 0.5

    # ── Self-Consistency ────────────────────────────────────

    async def _self_consistency(
        self, question: str, context: str, task_type: str
    ) -> ReasoningTrace:
        """Sample multiple reasoning paths and vote on the answer."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.SELF_CONSISTENCY, question=question)

        prompt = SELF_CONSISTENCY_PROMPT.format(question=question, context=context)

        # Generate multiple samples in parallel
        tasks = [
            self.router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type=task_type,
                temperature=0.7 + (i * 0.05),  # Vary temperature slightly
                max_tokens=4096,
            )
            for i in range(self.config.self_consistency_samples)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        valid_responses = [r for r in responses if isinstance(r, str) and r.strip()]
        trace.alternatives = [r[:300] for r in valid_responses]
        trace.steps = [{"type": f"sample_{i}", "content": r[:500]} for i, r in enumerate(valid_responses)]

        if not valid_responses:
            trace.final_answer = "Unable to generate consistent reasoning."
            trace.confidence = 0.0
            return trace

        # Use the model to synthesize and find the majority answer
        if len(valid_responses) > 1:
            merge_prompt = (
                f"Here are {len(valid_responses)} independent analyses of the same problem.\n\n"
                f"Problem: {question}\n\n"
            )
            for i, resp in enumerate(valid_responses):
                merge_prompt += f"--- Analysis {i+1} ---\n{resp[:1000]}\n\n"
            merge_prompt += (
                "Which analysis is most common/correct? Synthesize the consensus answer.\n"
                "Also note: what do most analyses agree on? Where do they disagree?\n"
                "Rate your confidence (0.0-1.0) in the consensus."
            )

            synthesis = await self.router.generate(
                messages=[{"role": "user", "content": merge_prompt}],
                task_type="reasoning",
                temperature=0.1,
                max_tokens=4096,
            )
            trace.final_answer = synthesis
            trace.confidence = self._extract_confidence(synthesis)
        else:
            trace.final_answer = valid_responses[0]
            trace.confidence = 0.5

        return trace

    # ── Multi-Model Consensus ───────────────────────────────

    async def _multi_model_consensus(
        self, question: str, context: str
    ) -> ReasoningTrace:
        """Query multiple different models and synthesize their answers."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.MULTI_MODEL_CONSENSUS, question=question)

        # Get different model types for diverse perspectives
        model_types = ["security", "reasoning", "code", "general"]
        prompt = (
            f"Analyze this security problem thoroughly:\n\n{question}\n\n"
            f"Context: {context}\n\n"
            f"Provide your analysis, findings, and confidence level."
        )

        tasks = []
        for mt in model_types:
            tasks.append(self.router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type=mt,
                temperature=0.3,
                max_tokens=4096,
            ))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        valid = []
        for mt, resp in zip(model_types, responses):
            if isinstance(resp, str) and resp.strip():
                valid.append((mt, resp))
                trace.models_used.append(mt)

        if not valid:
            trace.final_answer = "No models available for consensus."
            trace.confidence = 0.0
            return trace

        trace.steps = [{"type": f"model_{mt}", "content": resp[:500]} for mt, resp in valid]

        # Synthesize consensus
        response_text = ""
        for mt, resp in valid:
            response_text += f"--- {mt.upper()} Model ---\n{resp[:1500]}\n\n"

        merge_prompt = CONSENSUS_MERGE.format(
            question=question,
            responses=response_text,
        )
        synthesis = await self.router.generate(
            messages=[{"role": "user", "content": merge_prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=4096,
        )

        trace.final_answer = synthesis
        trace.confidence = self._extract_confidence(synthesis)
        if trace.confidence == 0.5:
            # Default: confidence based on agreement
            trace.confidence = min(0.9, 0.5 + (len(valid) * 0.1))

        return trace

    # ── Debate ──────────────────────────────────────────────

    async def _debate(
        self, question: str, context: str, task_type: str
    ) -> ReasoningTrace:
        """Two models argue opposing positions; a judge decides."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.DEBATE, question=question)

        for_args: list[str] = []
        against_args: list[str] = []
        history = ""

        for round_num in range(self.config.debate_rounds):
            # Proponent argues
            for_prompt = DEBATE_PROPOSE.format(
                position="FOR (this is a real vulnerability / valid finding)",
                question=question,
                history=history[-2000:],
            )
            for_arg = await self.router.generate(
                messages=[{"role": "user", "content": for_prompt}],
                task_type=task_type,
                temperature=0.5,
                max_tokens=1024,
            )
            for_args.append(for_arg)
            history += f"\nFOR (round {round_num + 1}): {for_arg}\n"

            # Opponent argues
            against_prompt = DEBATE_PROPOSE.format(
                position="AGAINST (this is a false positive / not exploitable)",
                question=question,
                history=history[-2000:],
            )
            against_arg = await self.router.generate(
                messages=[{"role": "user", "content": against_prompt}],
                task_type=task_type,
                temperature=0.5,
                max_tokens=1024,
            )
            against_args.append(against_arg)
            history += f"\nAGAINST (round {round_num + 1}): {against_arg}\n"

            trace.steps.append({
                "type": f"round_{round_num + 1}",
                "for": for_arg[:300],
                "against": against_arg[:300],
            })

        # Judge
        judge_prompt = DEBATE_JUDGE.format(
            question=question,
            for_args="\n\n".join(for_args)[:3000],
            against_args="\n\n".join(against_args)[:3000],
        )
        verdict_raw = await self.router.generate(
            messages=[{"role": "user", "content": judge_prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=2048,
        )

        trace.steps.append({"type": "verdict", "content": verdict_raw[:500]})

        # Parse verdict
        try:
            verdict = json.loads(verdict_raw)
            trace.final_answer = verdict.get("final_answer", verdict_raw)
            trace.confidence = float(verdict.get("confidence", 0.5))
        except (json.JSONDecodeError, ValueError):
            trace.final_answer = verdict_raw
            trace.confidence = self._extract_confidence(verdict_raw)

        trace.dissenting_views = against_args if "for" in trace.final_answer.lower() else for_args
        return trace

    # ── Reflection ──────────────────────────────────────────

    async def _reflection(
        self, question: str, context: str, task_type: str, system_prompt: str = ""
    ) -> ReasoningTrace:
        """Generate analysis, critique it, then improve iteratively."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.REFLECTION, question=question)

        # Initial analysis
        initial = await self.router.generate(
            messages=[
                {"role": "system", "content": system_prompt or "You are an expert security analyst."},
                {"role": "user", "content": f"Analyze: {question}\nContext: {context}"},
            ],
            task_type=task_type,
            temperature=0.3,
            max_tokens=4096,
        )
        trace.steps.append({"type": "initial_analysis", "content": initial[:500]})

        current_analysis = initial
        for iteration in range(self.config.reflection_max_iterations):
            # Critique
            critique_prompt = REFLECTION_CRITIQUE.format(
                question=question,
                analysis=current_analysis[:3000],
            )
            critique = await self.router.generate(
                messages=[{"role": "user", "content": critique_prompt}],
                task_type="reasoning",
                temperature=0.3,
                max_tokens=4096,
            )
            trace.steps.append({"type": f"critique_{iteration + 1}", "content": critique[:500]})

            # Check if critique indicates no significant issues
            no_issues_indicators = [
                "no significant", "analysis is sound", "well-reasoned",
                "comprehensive", "no major issues", "thorough",
            ]
            if any(ind in critique.lower() for ind in no_issues_indicators):
                break

            # Improve based on critique
            improve_prompt = (
                f"Improve your analysis based on this critique:\n\n"
                f"Original analysis:\n{current_analysis[:2000]}\n\n"
                f"Critique:\n{critique[:2000]}\n\n"
                f"Provide an improved analysis that addresses all issues raised."
            )
            improved = await self.router.generate(
                messages=[
                    {"role": "system", "content": system_prompt or "You are an expert security analyst."},
                    {"role": "user", "content": improve_prompt},
                ],
                task_type=task_type,
                temperature=0.2,
                max_tokens=4096,
            )
            current_analysis = improved
            trace.steps.append({"type": f"improved_{iteration + 1}", "content": improved[:500]})

        trace.final_answer = current_analysis
        trace.confidence = 0.7 + (0.1 * min(len(trace.steps) - 1, 3))  # Higher confidence with more iterations
        return trace

    # ── Metacognition ───────────────────────────────────────

    async def _metacognition(
        self, question: str, context: str, task_type: str
    ) -> ReasoningTrace:
        """Agent assesses its own confidence and identifies uncertainties."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.METACOGNITION, question=question)

        # Generate analysis
        analysis = await self.router.generate(
            messages=[{"role": "user", "content": f"Analyze: {question}\nContext: {context}"}],
            task_type=task_type,
            temperature=0.3,
            max_tokens=4096,
        )
        trace.steps.append({"type": "analysis", "content": analysis[:500]})

        # Metacognitive assessment
        assess_prompt = METACOGNITION_ASSESS.format(
            question=question,
            analysis=analysis[:3000],
        )
        assessment_raw = await self.router.generate(
            messages=[{"role": "user", "content": assess_prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=2048,
        )
        trace.steps.append({"type": "metacognition", "content": assessment_raw[:500]})

        try:
            assessment = json.loads(assessment_raw)
            trace.confidence = float(assessment.get("overall_confidence", 0.5))
            uncertain = assessment.get("uncertain", [])
            trace.dissenting_views = [str(u) for u in uncertain]
        except (json.JSONDecodeError, ValueError):
            trace.confidence = self._extract_confidence(assessment_raw)

        # If confidence is low, do reflection
        if trace.confidence < self.config.metacognition_threshold:
            trace.steps.append({"type": "low_confidence_trigger", "content": "Confidence below threshold, running reflection"})
            reflection_trace = await self._reflection(question, context, task_type)
            trace.final_answer = reflection_trace.final_answer
            trace.confidence = min(trace.confidence + 0.15, reflection_trace.confidence)
            trace.steps.extend(reflection_trace.steps)
        else:
            trace.final_answer = analysis

        return trace

    # ── ReAct ───────────────────────────────────────────────

    async def _react(
        self, question: str, context: str, task_type: str, tools: list[str]
    ) -> ReasoningTrace:
        """Reason + Act loop — thinks about what to do, then does it."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.REACT, question=question)

        tools_str = ", ".join(tools) if tools else "none specified"
        accumulated = ""

        for step in range(1, self.config.cot_max_steps + 1):
            prompt = (
                f"You are solving: {question}\n\n"
                f"Available tools: {tools_str}\n"
                f"Previous steps:\n{accumulated[-3000:]}\n\n"
                f"Step {step}: First THINK about what to do, then specify the ACTION.\n"
                f"Format:\n"
                f"THOUGHT: <your reasoning>\n"
                f"ACTION: <tool_name> <args> OR FINISH <answer>\n"
                f"OBSERVATION: <what you expect/observe>"
            )

            response = await self.router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type=task_type,
                temperature=0.3,
                max_tokens=1024,
            )

            trace.steps.append({"type": f"react_{step}", "content": response[:500]})
            accumulated += f"\nStep {step}:\n{response}\n"

            if "FINISH" in response.upper() or "ACTION: FINISH" in response.upper():
                # Extract final answer after FINISH
                parts = response.upper().split("FINISH", 1)
                if len(parts) > 1:
                    trace.final_answer = parts[1].strip()
                else:
                    trace.final_answer = response
                break

        if not trace.final_answer:
            trace.final_answer = accumulated[-2000:]

        trace.confidence = 0.6
        return trace

    # ── Plan and Solve ──────────────────────────────────────

    async def _plan_and_solve(
        self, question: str, context: str, task_type: str, tools: list[str]
    ) -> ReasoningTrace:
        """Create a plan first, then execute it step by step."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.PLAN_AND_SOLVE, question=question)

        tools_str = ", ".join(tools) if tools else "general analysis tools"

        # Phase 1: Plan
        plan_prompt = PLAN_AND_SOLVE_PLAN.format(
            question=question,
            tools=tools_str,
            context=context,
        )
        plan_raw = await self.router.generate(
            messages=[{"role": "user", "content": plan_prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=2048,
        )
        trace.steps.append({"type": "plan", "content": plan_raw[:500]})

        # Parse plan
        try:
            plan = json.loads(plan_raw)
            steps = plan.get("steps", [])
        except json.JSONDecodeError:
            steps = [{"id": 1, "action": plan_raw}]

        # Phase 2: Execute each step
        accumulated = f"Plan:\n{plan_raw[:2000]}\n\nExecution:\n"
        for step_info in steps[:10]:
            step_desc = step_info.get("action", str(step_info)) if isinstance(step_info, dict) else str(step_info)
            exec_prompt = (
                f"Execute this step of the plan:\n{step_desc}\n\n"
                f"Previous results:\n{accumulated[-2000:]}\n\n"
                f"Provide the result of executing this step."
            )
            result = await self.router.generate(
                messages=[{"role": "user", "content": exec_prompt}],
                task_type=task_type,
                temperature=0.3,
                max_tokens=2048,
            )
            accumulated += f"\nStep result: {result}\n"
            trace.steps.append({"type": f"execute_{step_info.get('id', '?') if isinstance(step_info, dict) else '?'}", "content": result[:500]})

        # Phase 3: Synthesize
        synth_prompt = f"Based on the plan execution results, provide the final answer.\n\n{accumulated[-4000:]}"
        final = await self.router.generate(
            messages=[{"role": "user", "content": synth_prompt}],
            task_type=task_type,
            temperature=0.1,
            max_tokens=4096,
        )
        trace.final_answer = final
        trace.confidence = self._extract_confidence(final)
        if trace.confidence == 0.5:
            trace.confidence = 0.65
        return trace

    # ── Step Back ───────────────────────────────────────────

    async def _step_back(
        self, question: str, context: str, task_type: str
    ) -> ReasoningTrace:
        """Step back to think about high-level principles first."""
        trace = ReasoningTrace(strategy=ReasoningStrategy.STEP_BACK, question=question)

        # Step 1: Abstract reasoning
        abstract_prompt = STEP_BACK_ABSTRACT.format(question=question)
        abstract = await self.router.generate(
            messages=[{"role": "user", "content": abstract_prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=2048,
        )
        trace.steps.append({"type": "abstract", "content": abstract[:500]})

        # Step 2: Apply to specific problem
        apply_prompt = (
            f"Now apply these principles to the specific problem:\n\n"
            f"Principles:\n{abstract[:2000]}\n\n"
            f"Specific problem: {question}\n"
            f"Context: {context}\n\n"
            f"Provide a thorough analysis."
        )
        specific = await self.router.generate(
            messages=[{"role": "user", "content": apply_prompt}],
            task_type=task_type,
            temperature=0.3,
            max_tokens=4096,
        )
        trace.steps.append({"type": "specific", "content": specific[:500]})
        trace.final_answer = specific
        trace.confidence = 0.65
        return trace

    # ── Utility Methods ─────────────────────────────────────

    def _extract_confidence(self, text: str) -> float:
        """Extract a confidence score from text."""
        import re

        # Look for explicit confidence patterns
        patterns = [
            r"confidence[:\s]+(\d+\.?\d*)",
            r"confidence[:\s]+(\d+)%",
            r"(\d+\.?\d*)\s*(?:out of|/)\s*(?:1\.0|1|10)",
            r"confidence level[:\s]+(\d+\.?\d*)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text.lower())
            if match:
                val = float(match.group(1))
                if val > 1.0:
                    val = val / 100.0 if val <= 100 else val / 10.0
                return min(max(val, 0.0), 1.0)

        # Heuristic from language
        high_conf_words = ["certain", "definitely", "clearly", "confirmed", "verified", "proven"]
        low_conf_words = ["uncertain", "possibly", "might", "unclear", "speculation", "may"]
        text_lower = text.lower()

        high_count = sum(1 for w in high_conf_words if w in text_lower)
        low_count = sum(1 for w in low_conf_words if w in text_lower)

        if high_count > low_count:
            return 0.75 + (0.05 * min(high_count, 5))
        elif low_count > high_count:
            return max(0.2, 0.5 - (0.05 * min(low_count, 5)))
        return 0.5

    def _classify_confidence(self, score: float) -> ConfidenceLevel:
        if score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        if score >= 0.7:
            return ConfidenceLevel.HIGH
        if score >= 0.5:
            return ConfidenceLevel.MEDIUM
        if score >= 0.3:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.VERY_LOW

    def _cache_key(self, question: str, context: str, strategy: ReasoningStrategy) -> str:
        data = f"{question}|{context}|{strategy.value}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _get_cached(self, key: str) -> ReasoningTrace | None:
        if key in self._cache:
            result, ts = self._cache[key]
            if time.monotonic() - ts < self.config.cache_ttl_s:
                return result
            del self._cache[key]
        return None

    def _set_cached(self, key: str, trace: ReasoningTrace) -> None:
        self._cache[key] = (trace, time.monotonic())
        # Evict old entries
        if len(self._cache) > 1000:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

    def get_stats(self) -> dict[str, Any]:
        return {**self._stats}


class StrategySelector:
    """Automatically selects the best reasoning strategy for a given question."""

    COMPLEXITY_KEYWORDS = {
        "simple": ["what is", "list", "show", "get", "check"],
        "medium": ["analyze", "explain", "compare", "find vulnerabilities"],
        "complex": ["exploit", "chain", "zero-day", "bypass", "reverse engineer", "full assessment"],
        "critical": ["rce", "remote code execution", "privilege escalation", "supply chain"],
    }

    @staticmethod
    def select(question: str, context: str = "", available_models: int = 1) -> ReasoningStrategy:
        """Select the best strategy based on the question complexity."""
        q_lower = question.lower()

        # Determine complexity
        complexity = "medium"
        for level, keywords in StrategySelector.COMPLEXITY_KEYWORDS.items():
            if any(kw in q_lower for kw in keywords):
                complexity = level

        # Multi-model consensus when we have multiple models
        if available_models >= 3 and complexity in ("complex", "critical"):
            return ReasoningStrategy.MULTI_MODEL_CONSENSUS

        # Debate for ambiguous or controversial findings
        if any(w in q_lower for w in ["false positive", "confirm", "validate", "verify"]):
            return ReasoningStrategy.DEBATE

        # Plan and solve for multi-step tasks
        if any(w in q_lower for w in ["pentest", "full scan", "assessment", "audit"]):
            return ReasoningStrategy.PLAN_AND_SOLVE

        # Tree of thought for complex exploration
        if complexity == "critical":
            return ReasoningStrategy.TREE_OF_THOUGHT

        # Reflection for high-stakes analysis
        if complexity == "complex":
            return ReasoningStrategy.REFLECTION

        # Self-consistency for medium complexity
        if complexity == "medium":
            return ReasoningStrategy.SELF_CONSISTENCY

        # Chain of thought for everything else
        return ReasoningStrategy.CHAIN_OF_THOUGHT
