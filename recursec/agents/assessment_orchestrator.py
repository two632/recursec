"""Assessment orchestrator — ties all intelligence systems together.

This is the MASTER orchestrator that composes all the agent brain
modules into a coherent assessment pipeline:

1. Target profiling → strategy selection → tool planning
2. OODA loop driving the autonomous operation
3. Knowledge graph building during assessment
4. Finding correlation and deduplication
5. Experience recording for learning
6. Convergence monitoring for stopping criteria
7. Multi-agent spawning for parallel work
8. Model ensemble for high-confidence decisions
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.adaptive_strategy_selector import (
    AdaptiveStrategySelector,
    SelectionContext,
)
from recursec.agents.advanced_strategy_kb import AdvancedStrategyKB
from recursec.agents.convergence_monitor import ConvergenceMonitor
from recursec.agents.counterfactual_reasoner import CounterfactualReasoner
from recursec.agents.experience_replay import (
    ExperienceOutcome,
    ExperiencePhase,
    ExperienceReplay,
)
from recursec.agents.finding_correlator import (
    FindingCorrelator,
    FindingSeverity,
    RawFinding,
)
from recursec.agents.knowledge_graph import (
    EntityType,
    KnowledgeGraph,
    RelationType,
)
from recursec.agents.model_ensemble import ModelEnsemble
from recursec.agents.ooda_engine import OODAEngine
from recursec.agents.prompt_compiler import PromptCompiler
from recursec.agents.recursive_spawner import RecursiveSpawner
from recursec.agents.target_profiler import TargetProfiler, TargetType
from recursec.agents.tool_execution_planner import ToolExecutionPlanner

logger = structlog.get_logger()


class OrchestratorState(str, Enum):
    IDLE = "idle"
    PROFILING = "profiling"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class AssessmentConfig:
    """Configuration for an assessment run."""
    target: str = ""
    target_type: str = ""
    scope: list[str] = field(default_factory=list)
    max_cycles: int = 100
    token_budget: int = 500000
    time_limit_s: float = 3600.0
    max_agent_depth: int = 5
    enable_exploitation: bool = True
    enable_post_exploit: bool = False
    models: list[str] = field(default_factory=list)
    tools_allowed: list[str] = field(default_factory=list)
    tools_excluded: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:30],
            "type": self.target_type[:20],
            "max_cycles": self.max_cycles,
            "token_budget": self.token_budget,
            "exploit": self.enable_exploitation,
        }


@dataclass
class AssessmentResult:
    """Final result of an assessment."""
    result_id: str = ""
    target: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    attack_chains: int = 0
    tools_used: list[str] = field(default_factory=list)
    strategies_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    cycles_completed: int = 0
    tokens_used: int = 0
    agents_spawned: int = 0

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.result_id,
            "target": self.target[:30],
            "duration_s": round(self.duration_s, 1),
            "findings": {
                "total": self.total_findings,
                "critical": self.critical_findings,
                "high": self.high_findings,
                "medium": self.medium_findings,
                "low": self.low_findings,
                "info": self.info_findings,
            },
            "chains": self.attack_chains,
            "tools": len(self.tools_used),
            "cycles": self.cycles_completed,
            "tokens": self.tokens_used,
            "agents": self.agents_spawned,
        }


class AssessmentOrchestrator:
    """Master orchestrator that composes all agent brain modules.

    Drives a complete autonomous security assessment by:
    1. Profiling the target
    2. Selecting strategies
    3. Planning tool execution
    4. Running OODA loops
    5. Correlating findings
    6. Building knowledge graphs
    7. Recording experiences
    8. Monitoring convergence
    """

    def __init__(self) -> None:
        # Core intelligence modules
        self._strategy_kb = AdvancedStrategyKB()
        self._prompt_compiler = PromptCompiler()
        self._target_profiler = TargetProfiler()
        self._strategy_selector = AdaptiveStrategySelector()
        self._tool_planner = ToolExecutionPlanner()
        self._knowledge_graph = KnowledgeGraph()
        self._finding_correlator = FindingCorrelator()
        self._experience_replay = ExperienceReplay()
        self._convergence_monitor: ConvergenceMonitor | None = None
        self._ooda_engine: OODAEngine | None = None
        self._spawner = RecursiveSpawner()
        self._model_ensemble = ModelEnsemble()
        self._counterfactual = CounterfactualReasoner()

        # Wire up strategy KB to prompt compiler
        self._prompt_compiler.set_strategy_kb(self._strategy_kb)

        # State
        self._state = OrchestratorState.IDLE
        self._config: AssessmentConfig | None = None
        self._result: AssessmentResult | None = None
        self._assessment_counter = 0
        self._log = logger.bind(component="assessment_orchestrator")

    def configure(self, config: AssessmentConfig) -> None:
        """Configure a new assessment."""
        self._config = config
        self._state = OrchestratorState.IDLE

        # Initialize per-assessment modules
        self._convergence_monitor = ConvergenceMonitor(
            token_budget=config.token_budget,
            max_cycles=config.max_cycles,
            time_limit_s=config.time_limit_s,
        )

        self._ooda_engine = OODAEngine(
            max_cycles=config.max_cycles,
            token_budget=config.token_budget,
        )

        self._assessment_counter += 1
        self._result = AssessmentResult(
            result_id=f"assessment-{self._assessment_counter}",
            target=config.target,
            started_at=time.time(),
        )

    def profile_target(self) -> dict[str, Any]:
        """Phase 1: Profile the target."""
        if not self._config:
            return {}

        self._state = OrchestratorState.PROFILING

        target_type = None
        if self._config.target_type:
            try:
                target_type = TargetType(self._config.target_type)
            except ValueError:
                pass

        profile = self._target_profiler.create_profile(
            self._config.target,
            target_type=target_type,
        )

        # Add to knowledge graph
        host_entity = self._knowledge_graph.add_entity(
            EntityType.HOST,
            self._config.target,
            properties={"type": profile.target_type.value},
            discovered_by="target_profiler",
        )

        # Generate profiling prompt for LLM
        profiling_prompt = self._target_profiler.generate_profiling_prompt(
            profile.profile_id
        )

        return {
            "profile": profile.to_dict(),
            "host_entity": host_entity.entity_id,
            "profiling_prompt": profiling_prompt,
            "recommended_strategies": profile.recommended_strategies,
        }

    def select_strategies(
        self,
        target_type: str = "",
        phase: str = "discovery",
    ) -> list[dict[str, Any]]:
        """Phase 2: Select strategies for the assessment."""
        self._state = OrchestratorState.PLANNING

        context = SelectionContext(
            target_type=target_type or (
                self._config.target_type if self._config else ""
            ),
            phase=phase,
        )

        recommendations = self._strategy_selector.select_strategy(
            context, method="ucb1", top_k=5
        )

        return [r.to_dict() for r in recommendations]

    def plan_tools(self, objective: str = "") -> dict[str, Any]:
        """Phase 3: Plan tool execution."""
        if not objective and self._config:
            objective = f"full security assessment of {self._config.target}"

        plan = self._tool_planner.create_plan(
            objective,
            target_info={"target": self._config.target if self._config else ""},
        )

        return plan.to_dict()

    def compile_prompt(
        self,
        role: str,
        task: str,
        data: str = "",
        target_type: str = "",
    ) -> dict[str, Any]:
        """Compile an advanced prompt with strategy injection."""
        prompt = self._prompt_compiler.compile(
            role=role,
            task=task,
            data=data,
            target_type=target_type or (
                self._config.target_type if self._config else ""
            ),
        )
        return prompt.to_dict()

    def ingest_finding(
        self,
        title: str,
        severity: str = "medium",
        target: str = "",
        tool: str = "",
        evidence: str = "",
        cwe_id: str = "",
        confidence: float = 0.5,
    ) -> dict[str, Any]:
        """Ingest a finding from a tool or agent."""
        raw = RawFinding(
            title=title,
            severity=FindingSeverity(severity),
            target=target or (self._config.target if self._config else ""),
            tool=tool,
            evidence=evidence,
            cwe_id=cwe_id,
            confidence=confidence,
        )

        correlated = self._finding_correlator.ingest(raw)

        # Add to knowledge graph
        if correlated.correlation_id:
            vuln_entity = self._knowledge_graph.add_entity(
                EntityType.VULNERABILITY,
                correlated.title,
                properties={
                    "severity": correlated.severity.value,
                    "cwe": correlated.cwe_id,
                    "confidence": correlated.confidence,
                },
                discovered_by=tool,
            )

            # Link to host
            host_entities = self._knowledge_graph.get_entities_by_type(EntityType.HOST)
            for host in host_entities:
                if host.name == correlated.target:
                    self._knowledge_graph.add_relationship(
                        host.entity_id,
                        vuln_entity.entity_id,
                        RelationType.HAS_VULNERABILITY,
                        confidence=correlated.confidence,
                    )

        return correlated.to_dict()

    def run_ooda_cycle(
        self,
        new_findings: int = 0,
        tokens_used: int = 0,
        tool_outputs: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run one OODA cycle."""
        if not self._ooda_engine:
            return {}

        self._state = OrchestratorState.EXECUTING

        # Observe
        observation = self._ooda_engine.observe(
            new_findings=new_findings,
            tool_outputs=tool_outputs,
            errors=errors,
            tokens_used=tokens_used,
        )

        # Orient
        orientation = self._ooda_engine.orient(observation)

        # Decide
        decision = self._ooda_engine.decide(orientation)

        # Record convergence
        if self._convergence_monitor:
            convergence = self._convergence_monitor.record_cycle(
                findings=new_findings,
                tokens_used=tokens_used,
            )
        else:
            convergence = None

        return {
            "cycle": self._ooda_engine.current_cycle,
            "phase": orientation.current_phase.value,
            "mode": orientation.current_mode.value,
            "decision": decision.to_dict(),
            "stagnation": orientation.stagnation_cycles,
            "convergence": convergence.to_dict() if convergence else None,
        }

    def record_experience(
        self,
        strategy: str,
        action: str,
        outcome: str,
        finding_type: str = "",
        finding_severity: str = "",
        tokens: int = 0,
    ) -> dict[str, Any]:
        """Record an experience for learning."""
        exp = self._experience_replay.record(
            phase=ExperiencePhase.ANALYSIS,
            strategy_used=strategy,
            action_taken=action,
            outcome=ExperienceOutcome(outcome),
            finding_type=finding_type,
            finding_severity=finding_severity,
            tokens_spent=tokens,
        )
        return exp.to_dict()

    def finalize(self) -> dict[str, Any]:
        """Finalize the assessment and produce results."""
        self._state = OrchestratorState.REPORTING

        if not self._result:
            return {}

        self._result.completed_at = time.time()

        # Get finding stats
        finding_stats = self._finding_correlator.get_stats()
        sev = finding_stats.get("by_severity", {})
        self._result.total_findings = finding_stats.get("correlated", 0)
        self._result.critical_findings = sev.get("critical", 0)
        self._result.high_findings = sev.get("high", 0)
        self._result.medium_findings = sev.get("medium", 0)
        self._result.low_findings = sev.get("low", 0)
        self._result.info_findings = sev.get("info", 0)

        # Identify attack chains
        chains = self._finding_correlator.identify_chains()
        self._result.attack_chains = len(chains)

        # Get agent stats
        agent_stats = self._spawner.get_stats()
        self._result.agents_spawned = agent_stats.get("total_agents", 0)

        # OODA stats
        if self._ooda_engine:
            ooda_stats = self._ooda_engine.get_stats()
            self._result.cycles_completed = ooda_stats.get("cycles", 0)
            self._result.tokens_used = int(
                str(ooda_stats.get("tokens", "0/0")).split("/")[0]
            )

        self._state = OrchestratorState.COMPLETE

        return self._result.to_dict()

    def get_full_stats(self) -> dict[str, Any]:
        """Get comprehensive stats from all modules."""
        return {
            "state": self._state.value,
            "config": self._config.to_dict() if self._config else None,
            "strategy_kb": self._strategy_kb.get_stats(),
            "target_profiler": self._target_profiler.get_stats(),
            "strategy_selector": self._strategy_selector.get_stats(),
            "tool_planner": self._tool_planner.get_stats(),
            "knowledge_graph": self._knowledge_graph.get_stats(),
            "findings": self._finding_correlator.get_stats(),
            "experience": self._experience_replay.get_stats(),
            "convergence": (
                self._convergence_monitor.get_stats()
                if self._convergence_monitor else None
            ),
            "ooda": (
                self._ooda_engine.get_stats()
                if self._ooda_engine else None
            ),
            "spawner": self._spawner.get_stats(),
            "ensemble": self._model_ensemble.get_stats(),
            "prompt_compiler": self._prompt_compiler.get_stats(),
        }
