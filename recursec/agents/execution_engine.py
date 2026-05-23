"""Execution engine — the runtime that ties all agent components together.

This is the main entry point for running RecurSec assessments. It:
1. Initializes all subsystems (models, tools, memory, etc.)
2. Creates the coordinator and agent teams
3. Manages the assessment lifecycle
4. Provides the API for the CLI and dashboard
5. Handles graceful shutdown and state persistence

The execution engine is the "main()" of the agent system.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from recursec.agents.budget_manager import BudgetManager, ConvergenceDetector
from recursec.agents.communication import MessageBus
from recursec.agents.context_manager import ContextPool
from recursec.agents.coordinator import AssessmentType, MultiAgentCoordinator
from recursec.agents.hypothesis import HypothesisEngine
from recursec.agents.knowledge_synthesis import KnowledgeSynthesizer
from recursec.agents.learning import LearningEngine
from recursec.agents.planner import HierarchicalPlanner
from recursec.agents.reflection import ReflectionEngine
from recursec.agents.strategy_selector import StrategySelector
from recursec.agents.tool_intelligence import ToolIntelligence

logger = structlog.get_logger()


@dataclass
class EngineConfig:
    """Configuration for the execution engine."""
    # Model configuration
    model_config_path: str = "configs/recursec.yaml"
    # Budget limits
    global_token_limit: int = 2000000
    global_time_limit_s: float = 7200.0
    global_step_limit: int = 1000
    max_concurrent_agents: int = 5
    # Persistence
    data_dir: str = "data"
    learning_dir: str = "data/learning"
    state_file: str = "data/engine_state.json"
    # Features
    enable_learning: bool = True
    enable_reflection: bool = True
    enable_hypothesis: bool = True
    enable_knowledge_graph: bool = True
    enable_ensemble: bool = True
    enable_tool_intelligence: bool = True
    # Assessment defaults
    default_assessment_type: str = "full"
    default_max_cycles_per_agent: int = 50
    default_max_time_per_agent_s: float = 600.0


@dataclass
class EngineState:
    """Persistent state of the execution engine."""
    assessments_completed: int = 0
    total_findings: int = 0
    total_tokens_used: int = 0
    total_runtime_s: float = 0.0
    started_at: float = field(default_factory=time.time)
    last_assessment_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessments_completed": self.assessments_completed,
            "total_findings": self.total_findings,
            "total_tokens_used": self.total_tokens_used,
            "total_runtime_s": round(self.total_runtime_s, 1),
            "uptime_s": round(time.time() - self.started_at, 1),
        }


class ExecutionEngine:
    """The main runtime for RecurSec agent system.

    Orchestrates all subsystems and provides the primary API
    for running security assessments.
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self._config = config or EngineConfig()
        self._state = EngineState()
        self._running = False
        self._log = logger.bind(component="engine")

        # Core components (initialized in start())
        self._model_router: Any = None
        self._tool_registry: Any = None
        self._memory: Any = None
        self._reasoning: Any = None

        # Agent intelligence subsystems
        self._bus = MessageBus()
        self._context_pool = ContextPool()
        self._budget_manager = BudgetManager(
            global_token_limit=self._config.global_token_limit,
            global_time_limit_s=self._config.global_time_limit_s,
            global_step_limit=self._config.global_step_limit,
        )
        self._convergence = ConvergenceDetector()

        # Optional subsystems
        self._learning: LearningEngine | None = None
        self._reflection: ReflectionEngine | None = None
        self._hypothesis: HypothesisEngine | None = None
        self._knowledge: KnowledgeSynthesizer | None = None
        self._strategy: StrategySelector | None = None
        self._tool_intel: ToolIntelligence | None = None
        self._planner: HierarchicalPlanner | None = None
        self._coordinator: MultiAgentCoordinator | None = None

        # Data directory
        Path(self._config.data_dir).mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        """Initialize all subsystems and start the engine."""
        self._log.info("engine_starting")
        self._running = True

        # Initialize core components
        await self._init_core()

        # Initialize intelligence subsystems
        self._init_intelligence()

        # Initialize coordinator
        self._coordinator = MultiAgentCoordinator(
            model_router=self._model_router,
            tool_registry=self._tool_registry,
            memory=self._memory,
            reasoning_engine=self._reasoning,
            learning_engine=self._learning,
            strategy_selector=self._strategy,
            planner=self._planner,
            context_pool=self._context_pool,
            max_concurrent_agents=self._config.max_concurrent_agents,
        )

        # Load persistent state
        self._load_state()

        self._log.info("engine_started")

    async def _init_core(self) -> None:
        """Initialize core components (model router, tools, memory)."""
        # These are lazy imports to avoid circular dependencies
        from recursec.llm.router import ModelRouter
        from recursec.memory.store import MemoryStore
        from recursec.tools.registry import ToolRegistry

        self._model_router = ModelRouter()
        self._tool_registry = ToolRegistry()
        self._memory = MemoryStore()

        # Load model configuration
        config_path = Path(self._config.model_config_path)
        if config_path.exists():
            try:
                import yaml
                with open(config_path) as f:
                    model_config = yaml.safe_load(f)
                if model_config:
                    self._log.info("model_config_loaded", path=str(config_path))
            except ImportError:
                self._log.warning("yaml_not_available, using defaults")
            except Exception as e:
                self._log.warning("model_config_load_failed", error=str(e))

        # Initialize reasoning engine
        from recursec.core.reasoning import ReasoningEngine
        self._reasoning = ReasoningEngine(self._model_router)

    def _init_intelligence(self) -> None:
        """Initialize agent intelligence subsystems."""
        if self._config.enable_learning:
            self._learning = LearningEngine(self._config.learning_dir)

        if self._config.enable_reflection:
            self._reflection = ReflectionEngine(self._model_router)

        if self._config.enable_hypothesis:
            self._hypothesis = HypothesisEngine(self._model_router)

        if self._config.enable_knowledge_graph:
            self._knowledge = KnowledgeSynthesizer(self._model_router)

        if self._config.enable_tool_intelligence:
            self._tool_intel = ToolIntelligence(self._model_router, self._tool_registry)

        self._strategy = StrategySelector(
            learning_engine=self._learning,
        )

        self._planner = HierarchicalPlanner(
            model_router=self._model_router,
            reasoning_engine=self._reasoning,
        )

    async def run_assessment(
        self,
        target: str,
        assessment_type: str = "",
        objective: str = "",
    ) -> dict[str, Any]:
        """Run a security assessment against a target."""
        if not self._coordinator:
            return {"error": "Engine not started. Call start() first."}

        atype = self._parse_assessment_type(assessment_type or self._config.default_assessment_type)
        start_time = time.time()

        self._log.info("assessment_starting", target=target, type=atype.value)

        # Allocate budget
        self._budget_manager.allocate(
            agent_id=f"assessment_{target}",
            token_limit=self._config.global_token_limit // 2,
            time_limit_s=self._config.global_time_limit_s / 2,
        )

        try:
            assessment = await self._coordinator.start_assessment(
                target=target,
                assessment_type=atype,
                objective=objective,
            )

            # Post-assessment processing
            result = assessment.to_dict()

            # Run knowledge synthesis on findings
            if self._knowledge and assessment.all_findings:
                for finding in assessment.all_findings:
                    await self._knowledge.ingest(
                        source=f"assessment_{assessment.assessment_id}",
                        data=json.dumps(finding),
                    )
                patterns = await self._knowledge.detect_patterns()
                result["knowledge_patterns"] = [p.to_dict() for p in patterns]

            # Run macro reflection
            if self._reflection:
                tools_used = list({
                    f.get("tool_source", "")
                    for f in assessment.all_findings
                    if f.get("tool_source")
                })
                reflection = await self._reflection.macro_reflect(
                    target=target,
                    total_actions=sum(1 for _ in assessment.agents.values()),
                    findings=assessment.all_findings,
                    phases_completed=[str(i) for i in range(assessment.current_phase)],
                    total_time_s=time.time() - start_time,
                    tools_used=tools_used,
                    models_used=[],
                )
                result["reflection"] = reflection.to_dict()

            # Record learning
            if self._learning:
                from recursec.agents.learning import Experience
                exp = Experience(
                    experience_id=assessment.assessment_id,
                    agent_id="coordinator",
                    action_type="assessment",
                    target_type=atype.value,
                    success=assessment.status == "completed",
                    quality_score=len(assessment.validated_findings) / max(1, len(assessment.all_findings)),
                    findings_produced=len(assessment.all_findings),
                    time_s=time.time() - start_time,
                )
                self._learning.record(exp)

            # Update engine state
            self._state.assessments_completed += 1
            self._state.total_findings += len(assessment.all_findings)
            self._state.total_runtime_s += time.time() - start_time
            self._state.last_assessment_at = time.time()
            self._save_state()

            return result

        except Exception as e:
            self._log.error("assessment_failed", target=target, error=str(e))
            return {"error": str(e), "target": target}

    async def stop(self) -> None:
        """Gracefully stop the engine."""
        self._log.info("engine_stopping")
        self._running = False
        self._save_state()

        if self._learning:
            self._learning._save()

        self._log.info("engine_stopped", state=self._state.to_dict())

    # ── Query APIs ──────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Get engine status."""
        return {
            "running": self._running,
            "state": self._state.to_dict(),
            "budget": self._budget_manager.get_global_status(),
            "subsystems": {
                "learning": self._learning is not None,
                "reflection": self._reflection is not None,
                "hypothesis": self._hypothesis is not None,
                "knowledge": self._knowledge is not None,
                "strategy": self._strategy is not None,
                "tool_intelligence": self._tool_intel is not None,
                "planner": self._planner is not None,
                "coordinator": self._coordinator is not None,
            },
        }

    def get_knowledge_stats(self) -> dict[str, Any]:
        if self._knowledge:
            return self._knowledge.get_stats()
        return {}

    def get_learning_insights(self) -> dict[str, Any]:
        if self._learning:
            return self._learning.get_insights()
        return {}

    def get_reflection_insights(self) -> list[dict[str, Any]]:
        if self._reflection:
            return self._reflection.get_all_insights()
        return []

    def get_hypothesis_summary(self) -> dict[str, Any]:
        if self._hypothesis:
            return self._hypothesis.get_summary()
        return {}

    # ── Persistence ──────────────────────────────────────────

    def _save_state(self) -> None:
        try:
            state_path = Path(self._config.state_file)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(self._state.to_dict(), indent=2))
        except OSError as e:
            self._log.warning("state_save_failed", error=str(e))

    def _load_state(self) -> None:
        state_path = Path(self._config.state_file)
        if state_path.exists():
            try:
                data = json.loads(state_path.read_text())
                self._state.assessments_completed = data.get("assessments_completed", 0)
                self._state.total_findings = data.get("total_findings", 0)
                self._state.total_tokens_used = data.get("total_tokens_used", 0)
                self._state.total_runtime_s = data.get("total_runtime_s", 0.0)
            except (json.JSONDecodeError, OSError) as e:
                self._log.warning("state_load_failed", error=str(e))

    def _parse_assessment_type(self, text: str) -> AssessmentType:
        try:
            return AssessmentType(text)
        except ValueError:
            return AssessmentType.FULL
