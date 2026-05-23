"""RecurSec agent — the main autonomous security assessment agent.

This is the top-level agent that:
1. Accepts high-level goals ("find vulns in meta.com")
2. Analyzes the target scope
3. Creates an assessment plan
4. Spawns specialist child agents
5. Coordinates their execution
6. Validates findings
7. Correlates results
8. Generates reports
9. Learns from the assessment

This is the brain that ties everything together.

Architecture inspired by:
- Qihoo 360 SEAF: Self-evolving, continuous discovery
- PentAGI: Flow → Task → Subtask with dynamic refinement
- Claude Code: Context → Action → Verify loop
- RecursiveMAS: Recursive agent collaboration
- Agent Zero: Full system access with hierarchical delegation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.adversarial_validator import AdversarialValidator, ValidationLevel
from recursec.agents.agent_config import AgentConfigManager
from recursec.agents.agent_loop import AgentLoop, LoopState
from recursec.agents.convergence_monitor import ConvergenceMonitor
from recursec.agents.decision_engine import DecisionEngine
from recursec.agents.finding_correlator import FindingCorrelator
from recursec.agents.introspection import IntrospectionEngine
from recursec.agents.knowledge_graph import KnowledgeGraph
from recursec.agents.learning_system import Episode, LearningSystem
from recursec.agents.output_formatter import OutputFormat, OutputFormatter
from recursec.agents.recursive_spawner import RecursiveSpawner, SpawnRequest
from recursec.agents.scope_analyzer import ScopeAnalyzer
from recursec.agents.strategy_optimizer import (
    AssessmentStrategy,
    StrategyOptimizer,
)
from recursec.agents.task_planner import TaskPlanner
from recursec.agents.tool_pipeline import ToolPipeline

logger = structlog.get_logger()


class AssessmentStatus(str, Enum):
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    VALIDATING = "validating"
    CORRELATING = "correlating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AssessmentConfig:
    """Configuration for an assessment."""
    target: str = ""
    goal: str = ""
    max_depth: int = 3
    max_agents: int = 20
    max_time_s: float = 1800.0
    max_tokens: int = 500000
    risk_tolerance: float = 0.5
    strategy: AssessmentStrategy = AssessmentStrategy.ADAPTIVE
    output_format: OutputFormat = OutputFormat.JSON
    validate_findings: bool = True
    stealth_mode: bool = False
    tools_allowed: list[str] = field(default_factory=list)
    tools_denied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "goal": self.goal[:100],
            "depth": self.max_depth, "agents": self.max_agents,
            "time": f"{self.max_time_s:.0f}s",
            "strategy": self.strategy.value,
            "stealth": self.stealth_mode,
        }


@dataclass
class AssessmentResult:
    """Complete assessment result."""
    assessment_id: str = ""
    config: AssessmentConfig = field(default_factory=AssessmentConfig)
    status: AssessmentStatus = AssessmentStatus.INITIALIZING
    findings: list[dict[str, Any]] = field(default_factory=list)
    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    correlation_groups: list[dict[str, Any]] = field(default_factory=list)
    report: str = ""
    total_tokens: int = 0
    total_time_s: float = 0.0
    agents_spawned: int = 0
    tools_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id,
            "status": self.status.value,
            "target": self.config.target,
            "findings": len(self.findings),
            "validated": len(self.validated_findings),
            "groups": len(self.correlation_groups),
            "tokens": self.total_tokens,
            "time_s": round(self.total_time_s, 1),
            "agents": self.agents_spawned,
            "tools": len(self.tools_used),
        }


class RecurSecAgent:
    """The main RecurSec autonomous security agent.

    Orchestrates the entire assessment process from
    goal to findings to validated report.
    """

    def __init__(
        self,
        model_router: Any = None,
    ) -> None:
        self._router = model_router

        # Core components
        self._config_manager = AgentConfigManager()
        self._scope_analyzer = ScopeAnalyzer(model_router=model_router)
        self._planner = TaskPlanner(model_router=model_router)
        self._spawner = RecursiveSpawner(max_depth=4, max_total_agents=50)
        self._tool_pipeline = ToolPipeline()
        self._validator = AdversarialValidator(model_router=model_router)
        self._correlator = FindingCorrelator(model_router=model_router)
        self._knowledge_graph = KnowledgeGraph()
        self._learning = LearningSystem()
        self._decision_engine = DecisionEngine(model_router=model_router)
        self._strategy = StrategyOptimizer()
        self._convergence = ConvergenceMonitor()
        self._introspection = IntrospectionEngine()
        self._formatter = OutputFormatter()

        self._assessment_counter = 0
        self._log = logger.bind(component="recursec_agent")

    async def assess(self, config: AssessmentConfig) -> AssessmentResult:
        """Run a complete security assessment."""
        start = time.time()
        self._assessment_counter += 1
        assessment_id = f"assess-{self._assessment_counter}"

        result = AssessmentResult(
            assessment_id=assessment_id,
            config=config,
        )

        self._log.info("assessment_start", id=assessment_id, target=config.target)

        try:
            # 1. INITIALIZE — Analyze scope
            result.status = AssessmentStatus.INITIALIZING
            scope = await self._scope_analyzer.analyze(config.target)
            target_type = scope.target_type if scope else "web_app"

            # Get recommendations from learning system
            self._learning.recommend_tools(target_type)
            recommended_strategy = self._learning.recommend_strategy(target_type)

            if recommended_strategy and config.strategy == AssessmentStrategy.ADAPTIVE:
                self._log.info("using_learned_strategy", strategy=recommended_strategy)

            # 2. PLAN — Create assessment plan
            result.status = AssessmentStatus.PLANNING
            plan = await self._planner.create_plan(
                goal=config.goal or f"Security assessment of {config.target}",
                target=config.target,
                target_type=target_type,
            )

            # 3. EXECUTE — Run the plan
            result.status = AssessmentStatus.EXECUTING

            # Create root coordinator agent
            root = self._spawner.create_root(
                role="coordinator",
                task=config.goal or f"Assess {config.target}",
                target=config.target,
                token_budget=config.max_tokens,
                time_budget_s=config.max_time_s,
            )
            self._spawner.start_agent(root.agent_id)
            result.agents_spawned += 1

            # Execute subtasks
            all_findings: list[dict[str, Any]] = []
            tools_used: set[str] = set()

            while True:
                # Check budget
                elapsed = time.time() - start
                if elapsed > config.max_time_s:
                    self._log.info("time_budget_exhausted")
                    break

                # Get next subtask
                subtask = self._planner.get_next_subtask(plan.plan_id)
                if not subtask:
                    break

                # Spawn child agent for subtask
                role_config = self._config_manager.get_role(subtask.agent_role)
                child = self._spawner.spawn_child(
                    parent_id=root.agent_id,
                    request=SpawnRequest(
                        role=subtask.agent_role or "recon",
                        task=subtask.name,
                        target=subtask.target or config.target,
                        tools=subtask.tools,
                    ),
                )

                if not child:
                    self._planner.fail_subtask(plan.plan_id, subtask.subtask_id, "Could not spawn agent")
                    continue

                result.agents_spawned += 1
                self._spawner.start_agent(child.agent_id)
                self._planner.start_subtask(plan.plan_id, subtask.subtask_id)

                # Run agent loop for this subtask
                loop_state = LoopState(
                    agent_id=child.agent_id,
                    role=child.role,
                    target=child.target,
                    goal=subtask.name,
                    max_steps=role_config.step_budget if role_config else 50,
                    max_tokens=child.token_budget,
                    max_time_s=min(subtask.estimated_time_s * 2, config.max_time_s - elapsed),
                    system_prompt=role_config.system_prompt if role_config else "",
                )

                agent_loop = AgentLoop(
                    model_router=self._router,
                    tool_executor=self._tool_pipeline,
                )

                loop_result = await agent_loop.run(loop_state)

                # Collect results
                subtask_findings = loop_result.findings
                all_findings.extend(subtask_findings)

                for step in loop_result.steps:
                    if step.action and step.action.tool:
                        tools_used.add(step.action.tool)

                # Complete subtask and agent
                self._planner.complete_subtask(
                    plan.plan_id, subtask.subtask_id,
                    findings=subtask_findings,
                )
                self._spawner.complete_agent(
                    child.agent_id,
                    findings=subtask_findings,
                )

                # Update convergence
                self._convergence.record_progress(
                    findings_total=len(all_findings),
                    findings_new=len(subtask_findings),
                    actions_total=loop_result.current_step,
                    tokens_total=loop_result.tokens_used,
                    coverage_areas=len(tools_used),
                    unique_tools=len(tools_used),
                )

                # Check convergence
                signal = self._convergence.get_current_state()
                if signal.state.value == "converged":
                    self._log.info("convergence_reached")
                    break

                # Refine plan periodically
                if plan.refinement_count < 3 and len(all_findings) > 0:
                    await self._planner.refine_plan(plan.plan_id)

            # Mark root as completed
            self._spawner.complete_agent(root.agent_id, findings=all_findings)

            # 4. VALIDATE — Cross-validate findings
            result.status = AssessmentStatus.VALIDATING
            result.findings = all_findings

            if config.validate_findings and all_findings:
                validation_results = await self._validator.validate_batch(
                    all_findings,
                    level=ValidationLevel.STANDARD,
                )
                result.validated_findings = [
                    f for f, v in zip(all_findings, validation_results) if v.is_valid
                ]
            else:
                result.validated_findings = all_findings

            # 5. CORRELATE — Group and analyze findings
            result.status = AssessmentStatus.CORRELATING
            if result.validated_findings:
                groups = await self._correlator.correlate(result.validated_findings)
                result.correlation_groups = [g.to_dict() for g in groups]

            # Add findings to knowledge graph
            for finding in result.validated_findings:
                self._knowledge_graph.add_finding(
                    title=finding.get("title", ""),
                    severity=finding.get("severity", "medium"),
                    target=finding.get("target", config.target),
                    tool=finding.get("tool", ""),
                    cve=finding.get("cve", ""),
                )

            # 6. REPORT — Format output
            result.status = AssessmentStatus.REPORTING
            formatted = self._formatter.format_findings(
                result.validated_findings,
                output_format=config.output_format,
                target=config.target,
                title=f"Security Assessment: {config.target}",
            )
            result.report = formatted.content

            # 7. LEARN — Record episode
            episode = Episode(
                target_type=target_type,
                goal=config.goal or f"Assess {config.target}",
                findings=result.validated_findings,
                total_tokens=result.total_tokens,
                total_time_s=time.time() - start,
                success_rate=len(result.validated_findings) / max(1, len(all_findings)),
                tools_used=list(tools_used),
            )
            self._learning.record_episode(episode)

            result.status = AssessmentStatus.COMPLETED
            result.tools_used = list(tools_used)
            result.total_time_s = time.time() - start

        except Exception as e:
            result.status = AssessmentStatus.FAILED
            result.errors.append(str(e)[:200])
            self._log.error("assessment_failed", error=str(e))

        self._log.info(
            "assessment_complete",
            id=assessment_id,
            status=result.status.value,
            findings=len(result.findings),
            validated=len(result.validated_findings),
            time=f"{result.total_time_s:.1f}s",
        )

        return result

    async def quick_scan(self, target: str) -> AssessmentResult:
        """Quick scan with default settings."""
        return await self.assess(AssessmentConfig(
            target=target,
            goal=f"Quick security scan of {target}",
            max_time_s=300.0,
            max_agents=10,
        ))

    async def deep_scan(self, target: str) -> AssessmentResult:
        """Deep comprehensive scan."""
        return await self.assess(AssessmentConfig(
            target=target,
            goal=f"Comprehensive security assessment of {target}",
            max_time_s=3600.0,
            max_agents=30,
            max_depth=4,
            validate_findings=True,
        ))

    def get_stats(self) -> dict[str, Any]:
        return {
            "assessments": self._assessment_counter,
            "spawner": self._spawner.get_stats(),
            "tools": self._tool_pipeline.get_stats(),
            "learning": self._learning.get_stats(),
            "knowledge_graph": self._knowledge_graph.get_stats(),
        }
