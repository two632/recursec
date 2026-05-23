"""Master brain — the top-level orchestrator that wires all agent intelligence together.

This is the main entry point for the autonomous agent. It:
1. Receives a high-level goal (e.g., "find vulnerabilities in example.com")
2. Decomposes the goal into a goal tree
3. Spawns specialized agents via the spawner
4. Routes LLM calls through the inference engine
5. Uses the message bus for inter-agent communication
6. Applies reasoning, debate, and consensus for decisions
7. Manages context windows, attention, and resources
8. Learns from experience and reflects on performance
9. Tracks and reports findings
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.agent_coordinator import AgentCoordinator
from recursec.agents.agent_debate import AgentDebate, ArgumentType
from recursec.agents.agent_reflection import AgentReflection
from recursec.agents.agent_spawner import AgentSpawner, SpawnReason
from recursec.agents.attention_mechanism import AttentionMechanism
from recursec.agents.context_manager import ContextManager
from recursec.agents.decision_tree import DecisionTree
from recursec.agents.experience_replay import ExperienceReplay
from recursec.agents.goal_decomposer import GoalDecomposer
from recursec.agents.inference_engine import InferenceEngine
from recursec.agents.knowledge_graph import KnowledgeGraph
from recursec.agents.message_bus import MessageBus
from recursec.agents.output_parser import OutputParser
from recursec.agents.prompt_optimizer import PromptOptimizer
from recursec.agents.reasoning_engine import ReasoningEngine
from recursec.agents.recursive_reasoner import RecursiveReasoner
from recursec.agents.strategy_optimizer import StrategyOptimizer

logger = structlog.get_logger()


class BrainPhase(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    REFLECTING = "reflecting"
    COMPLETED = "completed"


@dataclass
class BrainState:
    """Current state of the master brain."""
    phase: BrainPhase = BrainPhase.IDLE
    goal: str = ""
    target: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    current_depth: int = 0
    max_depth: int = 5
    start_time: float = 0.0
    token_budget: int = 500000
    tokens_used: int = 0
    iterations: int = 0
    max_iterations: int = 100

    @property
    def elapsed_s(self) -> float:
        if self.start_time:
            return time.time() - self.start_time
        return 0.0

    @property
    def budget_remaining(self) -> float:
        if self.token_budget == 0:
            return 0.0
        return max(0.0, 1.0 - self.tokens_used / self.token_budget)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "goal": self.goal[:60],
            "target": self.target[:40],
            "findings": len(self.findings),
            "iterations": self.iterations,
            "tokens_used": self.tokens_used,
            "budget_remaining": round(self.budget_remaining, 2),
            "elapsed_s": round(self.elapsed_s, 1),
        }


class MasterBrain:
    """Top-level orchestrator that wires all agent intelligence together.

    This is the entry point for autonomous operation. Given a goal,
    it orchestrates all subsystems: planning, reasoning, spawning,
    inference, learning, and reporting.
    """

    def __init__(
        self,
        max_depth: int = 5,
        max_iterations: int = 100,
        token_budget: int = 500000,
    ) -> None:
        self._state = BrainState(
            max_depth=max_depth,
            max_iterations=max_iterations,
            token_budget=token_budget,
        )

        # Core subsystems — lazy initialized
        self._inference: InferenceEngine | None = None
        self._spawner: AgentSpawner | None = None
        self._coordinator: AgentCoordinator | None = None
        self._goal_decomposer: GoalDecomposer | None = None
        self._reasoner: RecursiveReasoner | None = None
        self._reasoning_engine: ReasoningEngine | None = None
        self._context_mgr: ContextManager | None = None
        self._attention: AttentionMechanism | None = None
        self._experience: ExperienceReplay | None = None
        self._strategy: StrategyOptimizer | None = None
        self._debate: AgentDebate | None = None
        self._decision: DecisionTree | None = None
        self._reflection: AgentReflection | None = None
        self._prompt_opt: PromptOptimizer | None = None
        self._output_parser: OutputParser | None = None
        self._message_bus: MessageBus | None = None
        self._knowledge: KnowledgeGraph | None = None

        self._log = logger.bind(component="master_brain")

    # ── Lazy initialization ────────────────────────────────────

    @property
    def inference(self) -> InferenceEngine:
        if not self._inference:
            self._inference = InferenceEngine()
        return self._inference

    @property
    def spawner(self) -> AgentSpawner:
        if not self._spawner:
            self._spawner = AgentSpawner(
                max_depth=self._state.max_depth,
                token_budget=self._state.token_budget,
            )
        return self._spawner

    @property
    def coordinator(self) -> AgentCoordinator:
        if not self._coordinator:
            self._coordinator = AgentCoordinator()
        return self._coordinator

    @property
    def goals(self) -> GoalDecomposer:
        if not self._goal_decomposer:
            self._goal_decomposer = GoalDecomposer()
        return self._goal_decomposer

    @property
    def reasoner(self) -> RecursiveReasoner:
        if not self._reasoner:
            self._reasoner = RecursiveReasoner(
                max_depth=self._state.max_depth,
            )
        return self._reasoner

    @property
    def reasoning(self) -> ReasoningEngine:
        if not self._reasoning_engine:
            self._reasoning_engine = ReasoningEngine()
        return self._reasoning_engine

    @property
    def context(self) -> ContextManager:
        if not self._context_mgr:
            self._context_mgr = ContextManager()
        return self._context_mgr

    @property
    def attention(self) -> AttentionMechanism:
        if not self._attention:
            self._attention = AttentionMechanism()
        return self._attention

    @property
    def experience(self) -> ExperienceReplay:
        if not self._experience:
            self._experience = ExperienceReplay()
        return self._experience

    @property
    def strategy(self) -> StrategyOptimizer:
        if not self._strategy:
            self._strategy = StrategyOptimizer()
        return self._strategy

    @property
    def debate(self) -> AgentDebate:
        if not self._debate:
            self._debate = AgentDebate()
        return self._debate

    @property
    def decision(self) -> DecisionTree:
        if not self._decision:
            self._decision = DecisionTree()
        return self._decision

    @property
    def reflection(self) -> AgentReflection:
        if not self._reflection:
            self._reflection = AgentReflection()
        return self._reflection

    @property
    def prompts(self) -> PromptOptimizer:
        if not self._prompt_opt:
            self._prompt_opt = PromptOptimizer()
        return self._prompt_opt

    @property
    def parser(self) -> OutputParser:
        if not self._output_parser:
            self._output_parser = OutputParser()
        return self._output_parser

    @property
    def bus(self) -> MessageBus:
        if not self._message_bus:
            self._message_bus = MessageBus()
        return self._message_bus

    @property
    def knowledge(self) -> KnowledgeGraph:
        if not self._knowledge:
            self._knowledge = KnowledgeGraph()
        return self._knowledge

    # ── Main execution ─────────────────────────────────────────

    async def run(
        self,
        goal: str,
        target: str = "",
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Main entry point: run the agent toward a goal."""
        self._state.goal = goal
        self._state.target = target
        self._state.start_time = time.time()
        self._state.phase = BrainPhase.PLANNING

        self._log.info("brain_starting", goal=goal[:60], target=target[:40])

        try:
            # Phase 1: Plan
            plan = await self._plan(goal, target)

            # Phase 2: Execute plan
            results = await self._execute_plan(plan)

            # Phase 3: Validate
            validated = await self._validate(results)

            # Phase 4: Reflect
            self._state.phase = BrainPhase.REFLECTING
            self._reflect(validated)

            self._state.phase = BrainPhase.COMPLETED

            return {
                "goal": goal,
                "target": target,
                "findings": self._state.findings,
                "tokens_used": self._state.tokens_used,
                "elapsed_s": self._state.elapsed_s,
                "iterations": self._state.iterations,
            }

        except Exception as exc:
            self._log.error("brain_error", error=str(exc)[:200])
            return {
                "goal": goal,
                "target": target,
                "error": str(exc)[:500],
                "findings": self._state.findings,
                "tokens_used": self._state.tokens_used,
            }

    async def _plan(
        self,
        goal: str,
        target: str,
    ) -> dict[str, Any]:
        """Phase 1: Decompose goal and create plan."""
        # Determine template
        template = "assess_web_target" if "web" in goal.lower() or "http" in target.lower() else ""

        # Decompose goal
        root_goal = self.goals.decompose(goal, template=template)

        # Use strategy optimizer to select approach
        strategy = self.strategy.select(category="recon")

        # Add target to knowledge graph
        target_node = self.knowledge.add_node("target", target)

        # Start reasoning session
        reasoning = self.reasoner.start_session(
            goal=goal,
            initial_observations=[f"Target: {target}"],
        )

        # Add to attention
        self.attention.add_item(
            "task", goal,
            security=0.8, urgency=0.7, impact=0.8,
        )

        return {
            "root_goal": root_goal.goal_id,
            "strategy": strategy.strategy_id if strategy else "",
            "target_node": target_node,
            "reasoning_session": reasoning.session_id,
        }

    async def _execute_plan(
        self,
        plan: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Phase 2: Execute the plan by spawning agents."""
        self._state.phase = BrainPhase.RECONNAISSANCE
        results = []

        while self._state.iterations < self._state.max_iterations:
            self._state.iterations += 1

            # Check budget
            if self._state.budget_remaining <= 0:
                break

            # Get next goal
            next_goal = self.goals.select_next()
            if not next_goal:
                break

            # Decide on model
            model_action = self.decision.traverse_tree(
                "model_selection",
                {"task_type": next_goal.goal_type.value},
            )

            # Spawn agent
            request = self.spawner.request_spawn(
                parent_id="master",
                role=next_goal.description[:30],
                task=next_goal.description,
                model_hint=model_action or "hermes-14b",
                spawn_reason=SpawnReason.DECOMPOSITION,
                context={"goal_id": next_goal.goal_id},
            )

            agent = self.spawner.spawn(request)
            if not agent:
                break

            # Run inference for this agent
            prompt = self.prompts.select_prompt(
                task_type="security_analysis",
            )

            system_prompt = prompt.system_prompt if prompt else "You are a security analyst."

            response = await self.inference.infer(
                model_id=agent.model_hint or "hermes-14b",
                messages=[{"role": "user", "content": next_goal.description}],
                system_prompt=system_prompt,
            )

            # Parse output
            parsed = self.parser.parse(response.content)

            # Record experience
            reward = 1.0 if parsed.findings else 0.1
            self.experience.store(
                state={"goal": next_goal.description[:60]},
                action=f"infer:{agent.model_hint}",
                reward=reward,
                agent_id=agent.agent_id,
                model_used=agent.model_hint,
                tokens_used=response.total_tokens,
            )

            # Track tokens
            self._state.tokens_used += response.total_tokens

            # Process findings
            for finding in parsed.findings:
                finding_dict = finding.to_dict()
                self._state.findings.append(finding_dict)

                # Add to knowledge graph
                self.knowledge.add_node(
                    "finding", finding.title[:40],
                    properties=finding_dict,
                )

                # Attention boost
                self.attention.add_item(
                    "finding", finding.title[:40],
                    security=0.9 if finding.severity == "critical" else 0.6,
                    novelty=0.8,
                )

            # Mark goal
            self.goals.achieve(next_goal.goal_id, result={"parsed": parsed.to_dict()})

            # Complete agent
            self.spawner.complete_agent(
                agent.agent_id,
                result=parsed.to_dict(),
                tokens_used=response.total_tokens,
            )

            results.append(parsed.to_dict())

        return results

    async def _validate(
        self,
        results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Phase 3: Validate findings."""
        self._state.phase = BrainPhase.VALIDATION

        if not self._state.findings:
            return results

        # For high-severity findings, use debate to validate
        high_findings = [
            f for f in self._state.findings
            if f.get("severity") in ("critical", "high")
        ]

        for finding in high_findings[:5]:  # Validate top 5
            debate = self.debate.create_debate(
                topic=f"Is this a real vulnerability: {finding.get('title', '')}",
                pro_agent="validator-1",
                con_agent="validator-2",
            )

            # Simulate debate with pro/con arguments
            self.debate.add_argument(
                debate.debate_id, "validator-1",
                ArgumentType.CLAIM,
                f"Evidence supports: {finding.get('title', '')}",
                strength=0.7,
            )
            self.debate.add_argument(
                debate.debate_id, "validator-2",
                ArgumentType.COUNTER,
                "Need additional verification",
                strength=0.5,
            )

            resolution = self.debate.judge(debate.debate_id)

            if resolution.winner == "con":
                finding["validated"] = False
            else:
                finding["validated"] = True

        return results

    def _reflect(self, results: list[dict[str, Any]]) -> None:
        """Phase 4: Reflect on performance."""
        finding_count = len(self._state.findings)
        outcome = "success" if finding_count > 0 else "partial"

        self.reflection.reflect(
            agent_id="master",
            task_description=self._state.goal[:100],
            outcome=outcome,
            predicted_confidence=0.7,
            actual_confidence=min(1.0, finding_count * 0.1),
            duration_s=self._state.elapsed_s,
            tokens_used=self._state.tokens_used,
        )

        # Generate improvement plan
        self.reflection.generate_improvement_plan()

    # ── Status ─────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Get full brain status."""
        status = self._state.to_dict()

        # Add subsystem stats
        if self._inference:
            status["inference"] = self._inference.get_stats()
        if self._spawner:
            status["spawner"] = self._spawner.get_stats()
        if self._knowledge:
            status["knowledge"] = self._knowledge.get_stats()
        if self._experience:
            status["experience"] = self._experience.get_stats()
        if self._attention:
            status["attention"] = self._attention.get_stats()

        return status
