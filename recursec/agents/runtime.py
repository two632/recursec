"""Agent runtime — the main execution loop tying all subsystems together.

This is the top-level orchestration that:
1. Initializes all subsystems (memory, models, tools, agents)
2. Accepts assessment goals
3. Decomposes goals into plans
4. Spawns agents to execute plans
5. Coordinates multi-agent execution
6. Collects and aggregates findings
7. Performs reflection and learning
8. Generates reports
9. Handles graceful shutdown

Lifecycle:
  init → configure → start → [run assessments] → stop

The runtime is the entry point for all RecurSec operations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.adaptive_scheduler import (
    AdaptiveScheduler,
    ScheduledTask,
    SchedulingStrategy,
    TaskPriority,
)
from recursec.agents.budget_manager import BudgetManager
from recursec.agents.consensus import ConsensusEngine
from recursec.agents.findings_aggregator import Finding, FindingsAggregator
from recursec.agents.goal_decomposer import GoalDecomposer, GoalType
from recursec.agents.introspection import AgentIntrospection, EventType
from recursec.agents.knowledge_synthesis import KnowledgeSynthesizer
from recursec.agents.learning import LearningEngine
from recursec.agents.policy_engine import PolicyEngine
from recursec.agents.self_improvement import SelfImprovementEngine
from recursec.agents.spawner import AgentSpec, AgentSpawner, SpawnedAgent
from recursec.agents.vuln_patterns import VulnPatternLibrary
from recursec.memory.episodic_memory import EpisodicMemory
from recursec.memory.working_memory import MemoryItemType, WorkingMemory

logger = structlog.get_logger()


class RuntimeState(str, Enum):
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class RuntimeConfig:
    """Configuration for the agent runtime."""
    # Model paths
    model_dir: str = "~/agent/models/gguf/"
    llama_cpp_path: str = "llama-server"

    # Budgets
    max_tokens: int = 1_000_000
    max_time_s: float = 3600.0
    max_steps: int = 500

    # Agent limits
    max_agents: int = 50
    max_concurrent: int = 10
    max_recursion_depth: int = 5
    default_agent_timeout_s: float = 300.0

    # Memory
    working_memory_capacity: int = 50
    max_semantic_memory_items: int = 50000
    episodic_storage_dir: str = "data/episodes"
    semantic_storage_dir: str = "data/semantic_memory"

    # Scheduling
    scheduling_strategy: str = "adaptive"
    max_queue_size: int = 500

    # Features
    enable_reflection: bool = True
    enable_learning: bool = True
    enable_debate: bool = False  # Expensive — disabled by default
    enable_tree_of_thought: bool = False  # Expensive
    enable_safety_guard: bool = True

    # Persistence
    data_dir: str = "data"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_dir": self.model_dir,
            "max_tokens": self.max_tokens,
            "max_time_s": self.max_time_s,
            "max_agents": self.max_agents,
            "scheduling": self.scheduling_strategy,
        }


@dataclass
class AssessmentResult:
    """Result of a complete assessment."""
    assessment_id: str = ""
    target: str = ""
    goal: str = ""
    goal_type: str = ""
    status: str = "pending"
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    duration_s: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    agents_spawned: int = 0
    tokens_used: int = 0
    phases_completed: list[str] = field(default_factory=list)
    reflection_insights: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id,
            "target": self.target,
            "goal": self.goal[:200],
            "status": self.status,
            "duration_s": round(self.duration_s, 1),
            "total_findings": len(self.findings),
            "by_severity": self.findings_by_severity,
            "agents_spawned": self.agents_spawned,
            "tokens_used": self.tokens_used,
            "phases": self.phases_completed,
        }


class AgentRuntime:
    """The main RecurSec agent runtime.

    Ties together all subsystems into a cohesive execution engine.
    """

    def __init__(self, config: RuntimeConfig | None = None) -> None:
        self._config = config or RuntimeConfig()
        self._state = RuntimeState.UNINITIALIZED
        self._log = logger.bind(component="runtime")

        # Subsystems (initialized in start())
        self._budget_manager: BudgetManager | None = None
        self._spawner: AgentSpawner | None = None
        self._scheduler: AdaptiveScheduler | None = None
        self._findings: FindingsAggregator | None = None
        self._goal_decomposer: GoalDecomposer | None = None
        self._policy: PolicyEngine | None = None
        self._introspection: AgentIntrospection | None = None
        self._consensus: ConsensusEngine | None = None
        self._learning: LearningEngine | None = None
        self._improvement: SelfImprovementEngine | None = None
        self._knowledge: KnowledgeSynthesizer | None = None
        self._vuln_patterns: VulnPatternLibrary | None = None
        self._working_memory: WorkingMemory | None = None
        self._episodic_memory: EpisodicMemory | None = None

        # Runtime state
        self._assessments: list[AssessmentResult] = []
        self._current_assessment: AssessmentResult | None = None
        self._started_at: float = 0.0

    async def start(self) -> None:
        """Initialize all subsystems and prepare for execution."""
        self._state = RuntimeState.INITIALIZING
        self._started_at = time.time()
        self._log.info("runtime_starting")

        try:
            # Initialize core subsystems
            self._budget_manager = BudgetManager(
                global_token_budget=self._config.max_tokens,
                global_time_budget_s=self._config.max_time_s,
                global_step_budget=self._config.max_steps,
            )

            self._spawner = AgentSpawner(
                max_depth=self._config.max_recursion_depth,
                max_total_agents=self._config.max_agents,
                max_concurrent=self._config.max_concurrent,
                default_timeout_s=self._config.default_agent_timeout_s,
            )
            self._spawner.set_executor(self._execute_agent)

            strategy = SchedulingStrategy(self._config.scheduling_strategy)
            self._scheduler = AdaptiveScheduler(
                strategy=strategy,
                max_queue_size=self._config.max_queue_size,
            )

            self._findings = FindingsAggregator()
            self._goal_decomposer = GoalDecomposer()
            self._policy = PolicyEngine()
            self._introspection = AgentIntrospection()
            self._consensus = ConsensusEngine()
            self._vuln_patterns = VulnPatternLibrary()

            # Memory subsystems
            self._working_memory = WorkingMemory(
                capacity=self._config.working_memory_capacity,
            )
            self._episodic_memory = EpisodicMemory(
                storage_dir=self._config.episodic_storage_dir,
            )

            # Learning subsystems
            if self._config.enable_learning:
                self._learning = LearningEngine()
                self._improvement = SelfImprovementEngine(
                    storage_dir=f"{self._config.data_dir}/improvement",
                )

            self._state = RuntimeState.READY
            self._log.info("runtime_ready")

        except Exception as e:
            self._state = RuntimeState.ERROR
            self._log.error("runtime_init_failed", error=str(e))
            raise

    async def run_assessment(
        self,
        target: str,
        goal: str = "",
        goal_type: GoalType = GoalType.FULL_ASSESSMENT,
        scope: dict[str, Any] | None = None,
    ) -> AssessmentResult:
        """Run a complete security assessment."""
        if self._state != RuntimeState.READY:
            raise RuntimeError(f"Runtime not ready: {self._state.value}")

        self._state = RuntimeState.RUNNING
        assessment = AssessmentResult(
            assessment_id=f"assess-{int(time.time())}",
            target=target,
            goal=goal or f"Full security assessment of {target}",
            goal_type=goal_type.value,
            status="running",
        )
        self._current_assessment = assessment

        # Configure scope
        if scope and self._policy:
            self._policy.configure_scope(**scope)

        # Start episodic recording
        if self._episodic_memory:
            self._episodic_memory.start_episode(
                target=target,
                target_type=goal_type.value,
                objective=assessment.goal,
            )

        # Record in introspection
        if self._introspection:
            self._introspection.record(
                EventType.AGENT_START, "runtime",
                {"target": target, "goal": assessment.goal[:100]},
            )

        try:
            # Phase 1: Decompose goal into plan
            if self._goal_decomposer:
                plan = await self._goal_decomposer.decompose(
                    goal=assessment.goal,
                    target=target,
                    goal_type=goal_type,
                )

                # Add plan tasks to scheduler
                if self._scheduler:
                    for task in plan.tasks:
                        scheduled = ScheduledTask(
                            name=task.name,
                            description=task.description,
                            agent_role=task.agent_role,
                            priority=TaskPriority(min(9, max(1, task.priority))),
                            estimated_duration_s=task.estimated_time_s,
                            estimated_tokens=task.estimated_tokens,
                            category=task.phase.value,
                            target=target,
                            context={"tools": task.tools_needed},
                        )
                        self._scheduler.add_task(scheduled)

            # Phase 2: Execute scheduled tasks
            await self._execute_scheduled_tasks(assessment)

            # Phase 3: Correlate findings
            if self._findings:
                await self._findings.correlate_findings()

            # Phase 4: Reflection
            if self._config.enable_reflection and self._improvement:
                # Record assessment performance
                self._improvement.record_performance(
                    task_type=goal_type.value,
                    success=len(assessment.findings) > 0,
                    quality=min(1.0, len(assessment.findings) * 0.1),
                    time_s=time.time() - assessment.started_at,
                )

            assessment.status = "completed"

        except Exception as e:
            assessment.status = "error"
            assessment.error = str(e)
            self._log.error("assessment_error", error=str(e))

        finally:
            assessment.completed_at = time.time()
            assessment.duration_s = assessment.completed_at - assessment.started_at

            # Finalize findings
            if self._findings:
                report = self._findings.generate_report()
                assessment.findings = [f.to_dict() for f in self._findings.get_all()]
                assessment.findings_by_severity = report.by_severity

            # End episode
            if self._episodic_memory:
                self._episodic_memory.end_episode(
                    outcome=assessment.status,
                    findings=assessment.findings,
                )

            # Save learning data
            if self._improvement:
                self._improvement.save()

            if self._spawner:
                assessment.agents_spawned = self._spawner.get_stats().get("total_agents", 0)

            self._assessments.append(assessment)
            self._current_assessment = None
            self._state = RuntimeState.READY

            self._log.info(
                "assessment_complete",
                target=target,
                findings=len(assessment.findings),
                duration_s=round(assessment.duration_s, 1),
            )

        return assessment

    async def _execute_scheduled_tasks(self, assessment: AssessmentResult) -> None:
        """Execute all scheduled tasks using agent spawning."""
        if not self._scheduler or not self._spawner:
            return

        while True:
            # Get next batch of tasks
            batch = self._scheduler.get_next_batch(max_batch=self._config.max_concurrent)
            if not batch:
                break

            # Spawn agents for each task
            specs = []
            for task in batch:
                spec = AgentSpec(
                    role=task.agent_role,
                    goal=f"{task.name}: {task.description}",
                    tools=task.context.get("tools", []),
                    budget_tokens=task.estimated_tokens,
                    budget_time_s=task.estimated_duration_s,
                    priority=task.priority.value,
                )
                specs.append(spec)

            # Execute in parallel
            agents = await self._spawner.spawn_parallel(specs)

            # Process results
            for task, agent in zip(batch, agents):
                findings_count = len(agent.findings)
                if agent.status == "completed":
                    self._scheduler.complete_task(
                        task.task_id,
                        result=agent.result,
                        findings_count=findings_count,
                    )
                    # Add findings
                    if self._findings:
                        for finding_data in agent.findings:
                            finding = Finding(
                                title=finding_data.get("title", ""),
                                description=finding_data.get("description", ""),
                                affected_component=finding_data.get("component", ""),
                                sources=[agent.spec.role],
                            )
                            self._findings.add_finding(finding)

                    assessment.phases_completed.append(task.category)
                else:
                    self._scheduler.fail_task(
                        task.task_id,
                        error=agent.error,
                    )

    async def _execute_agent(self, agent: SpawnedAgent) -> dict[str, Any]:
        """Execute a spawned agent — the core agent loop."""
        # Record in introspection
        if self._introspection:
            self._introspection.record(
                EventType.AGENT_START, agent.agent_id,
                {"role": agent.spec.role, "goal": agent.spec.goal[:100]},
            )

        # Check policy
        if self._policy:
            evaluation = self._policy.evaluate_action(
                action="spawn_agent",
                agent_id=agent.agent_id,
                target=self._current_assessment.target if self._current_assessment else "",
            )
            if not evaluation.allowed:
                return {"error": f"Policy blocked: {evaluation.messages}", "findings": []}

        # Add to working memory
        if self._working_memory:
            self._working_memory.add(
                item_id=f"agent-{agent.agent_id}",
                content=f"Agent {agent.spec.role}: {agent.spec.goal}",
                item_type=MemoryItemType.GOAL,
                importance=0.7,
            )

        # Recall relevant past episodes
        lessons = []
        if self._episodic_memory:
            lessons = self._episodic_memory.get_lessons_for_context(
                target_type=self._current_assessment.goal_type if self._current_assessment else "",
            )

        # Execute agent's goal (simplified — in production, this calls the LLM)
        result: dict[str, Any] = {
            "agent_id": agent.agent_id,
            "role": agent.spec.role,
            "goal": agent.spec.goal,
            "lessons_applied": lessons[:3],
            "findings": [],
            "actions_taken": [],
        }

        # Record completion
        if self._introspection:
            self._introspection.record(
                EventType.AGENT_STOP, agent.agent_id,
                {"findings": len(result.get("findings", []))},
            )

        # Record learning
        if self._improvement:
            self._improvement.record_performance(
                task_type=agent.spec.role,
                success=True,
                quality=0.5,
            )

        return result

    async def stop(self) -> None:
        """Gracefully stop the runtime."""
        self._state = RuntimeState.STOPPING
        self._log.info("runtime_stopping")

        # Save state
        if self._improvement:
            self._improvement.save()

        self._state = RuntimeState.STOPPED
        self._log.info("runtime_stopped", uptime_s=round(time.time() - self._started_at, 1))

    # ── Status & Reporting ───────────────────────────────

    def get_status(self) -> dict[str, Any]:
        status: dict[str, Any] = {
            "state": self._state.value,
            "uptime_s": round(time.time() - self._started_at, 1) if self._started_at else 0,
            "assessments_completed": len(self._assessments),
        }

        if self._current_assessment:
            status["current_assessment"] = self._current_assessment.to_dict()
        if self._spawner:
            status["agents"] = self._spawner.get_stats()
        if self._scheduler:
            status["scheduler"] = self._scheduler.get_queue_status()
        if self._findings:
            status["findings"] = self._findings.get_stats()
        if self._introspection:
            status["introspection"] = self._introspection.get_summary()

        return status

    def get_assessment_history(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._assessments]
