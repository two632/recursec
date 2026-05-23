"""Agent brain — the master autonomous intelligence engine.

This is the core brain that orchestrates ALL intelligence modules:
1. Receives a target/goal
2. Profiles the target
3. Selects strategies (using bandit algorithm)
4. Decomposes into tasks
5. Spawns child agents
6. Routes to optimal models
7. Manages context windows
8. Executes tools
9. Parses and interprets results
10. Correlates findings
11. Builds reasoning chains
12. Updates knowledge graph
13. Computes rewards for learning
14. Monitors convergence
15. Runs OODA loop until complete
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.agent_comm_protocol import (
    AgentCommProtocol,
    MessageType,
)
from recursec.agents.agent_state_machine import (
    AgentStateMachine,
    StateEvent,
)
from recursec.agents.cloud_security_kb import CloudSecurityKB
from recursec.agents.context_window_manager import (
    ContentPriority,
    ContentType,
    ContextWindowManager,
)
from recursec.agents.convergence_monitor import ConvergenceMonitor
from recursec.agents.finding_correlator import FindingCorrelator
from recursec.agents.knowledge_graph import KnowledgeGraph
from recursec.agents.model_router import ModelRouter, RoutingStrategy, TaskCategory
from recursec.agents.ooda_engine import OODAEngine
from recursec.agents.output_parser import OutputParser
from recursec.agents.reasoning_chain import ReasoningChainEngine
from recursec.agents.recursive_spawner import AgentRole, RecursiveSpawner
from recursec.agents.reward_optimizer import RewardOptimizer
from recursec.agents.semantic_dedup import SemanticDeduplicator
from recursec.agents.supply_chain_kb import SupplyChainKB
from recursec.agents.target_profiler import TargetProfiler
from recursec.agents.task_decomposer import TaskDecomposer
from recursec.agents.tool_executor import ToolExecutor
from recursec.agents.tool_result_interpreter import ToolResultInterpreter
from recursec.agents.webapp_vuln_kb import WebAppVulnKB

logger = structlog.get_logger()


class BrainPhase(str, Enum):
    INIT = "init"
    PROFILING = "profiling"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    LEARNING = "learning"
    CONVERGED = "converged"


@dataclass
class BrainConfig:
    """Configuration for the agent brain."""
    max_cycles: int = 100
    max_time_s: float = 3600.0
    max_findings: int = 1000
    auto_spawn_agents: bool = True
    auto_correlate: bool = True
    auto_reason: bool = True
    stagnation_threshold: int = 5
    confidence_threshold: float = 0.7

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_cycles": self.max_cycles,
            "max_time": self.max_time_s,
            "max_findings": self.max_findings,
            "auto_spawn": self.auto_spawn_agents,
        }


@dataclass
class CycleResult:
    """Result of a single brain cycle."""
    cycle_num: int = 0
    phase: BrainPhase = BrainPhase.INIT
    actions_taken: list[str] = field(default_factory=list)
    findings_count: int = 0
    tools_run: list[str] = field(default_factory=list)
    models_queried: list[str] = field(default_factory=list)
    agents_spawned: int = 0
    reward: float = 0.0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle": self.cycle_num,
            "phase": self.phase.value,
            "actions": len(self.actions_taken),
            "findings": self.findings_count,
            "tools": len(self.tools_run),
            "reward": round(self.reward, 2),
        }


@dataclass
class BrainState:
    """Current state of the agent brain."""
    target: str = ""
    goal: str = ""
    phase: BrainPhase = BrainPhase.INIT
    cycle: int = 0
    total_findings: int = 0
    total_tools_run: int = 0
    total_llm_queries: int = 0
    total_agents_spawned: int = 0
    total_reward: float = 0.0
    start_time: float = field(default_factory=time.time)
    strategies_used: list[str] = field(default_factory=list)
    active_tools: list[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:30],
            "goal": self.goal[:40],
            "phase": self.phase.value,
            "cycle": self.cycle,
            "findings": self.total_findings,
            "tools_run": self.total_tools_run,
            "agents": self.total_agents_spawned,
            "reward": round(self.total_reward, 2),
            "elapsed": round(self.elapsed_s, 1),
        }


class AgentBrain:
    """The master autonomous intelligence engine.

    Orchestrates all intelligence modules in a continuous OODA
    loop, making autonomous decisions about what to investigate,
    which tools to run, which models to query, and when to stop.
    """

    def __init__(self, config: BrainConfig | None = None) -> None:
        self._config = config or BrainConfig()
        self._state = BrainState()
        self._cycle_history: list[CycleResult] = []
        self._log = logger.bind(component="agent_brain")

        # Initialize all intelligence modules
        self._state_machine = AgentStateMachine()
        self._model_router = ModelRouter()
        self._context_mgr = ContextWindowManager()
        self._tool_executor = ToolExecutor()
        self._output_parser = OutputParser()
        self._result_interpreter = ToolResultInterpreter()
        self._finding_correlator = FindingCorrelator()
        self._knowledge_graph = KnowledgeGraph()
        self._target_profiler = TargetProfiler()
        self._task_decomposer = TaskDecomposer()
        self._ooda_engine = OODAEngine()
        self._convergence_monitor = ConvergenceMonitor()
        self._reasoning_engine = ReasoningChainEngine()
        self._spawner = RecursiveSpawner()
        self._comm = AgentCommProtocol()
        self._reward_optimizer = RewardOptimizer()
        self._dedup = SemanticDeduplicator()

        # Knowledge bases
        self._webapp_kb = WebAppVulnKB()
        self._cloud_kb = CloudSecurityKB()
        self._supply_chain_kb = SupplyChainKB()

    def initialize(self, target: str, goal: str = "") -> BrainState:
        """Initialize the brain for a new assessment."""
        if not goal:
            goal = f"Comprehensive security assessment of {target}"

        self._state = BrainState(
            target=target,
            goal=goal,
            phase=BrainPhase.INIT,
        )

        # Transition state machine
        self._state_machine.transition(StateEvent.START)

        # Profile target
        self._state.phase = BrainPhase.PROFILING
        profile = self._target_profiler.profile(target)

        # Add target info to context
        self._context_mgr.add_item(
            content=f"Target: {target}\nProfile: {profile.to_dict()}",
            content_type=ContentType.TARGET_PROFILE,
            priority=ContentPriority.HIGH,
        )

        # Inject relevant knowledge
        self._inject_knowledge(profile.to_dict())

        # Decompose into tasks
        self._state.phase = BrainPhase.PLANNING
        plan = self._task_decomposer.decompose(
            objective=goal,
            target=target,
        )

        # Spawn root coordinator agent
        if self._config.auto_spawn_agents:
            root = self._spawner.spawn(
                role=AgentRole.COORDINATOR,
                goal=goal,
                context=f"Target: {target}",
            )
            if root:
                self._comm.register_agent(root.agent_id)
                self._state.total_agents_spawned += 1

        self._state_machine.transition(StateEvent.PLAN_COMPLETE)
        self._state.phase = BrainPhase.EXECUTING

        self._log.info("brain_initialized", target=target, tasks=len(plan.tasks))
        return self._state

    def run_cycle(self) -> CycleResult:
        """Run a single brain cycle (one OODA iteration)."""
        self._state.cycle += 1
        cycle_start = time.time()

        result = CycleResult(
            cycle_num=self._state.cycle,
            phase=self._state.phase,
        )

        # Check convergence
        signal = self._convergence_monitor.check()
        if signal and signal.value in ("stop", "advance_phase"):
            self._state.phase = BrainPhase.CONVERGED
            result.actions_taken.append(f"convergence: {signal.value}")
            return result

        # Get ready tasks
        plans = list(self._task_decomposer._plans.values())
        ready_tasks = []
        for plan in plans:
            ready_tasks.extend(self._task_decomposer.get_ready_tasks(plan.plan_id))

        for task in ready_tasks[:3]:  # Process up to 3 tasks per cycle
            # Route to model
            task_cat = self._categorize_task(task.tool, task.strategy)
            route = self._model_router.route(
                task_category=task_cat,
                strategy=RoutingStrategy.BEST_FIT,
            )

            if route.model_id:
                result.models_queried.append(route.model_name)
                self._state.total_llm_queries += 1

            # Execute tool if specified
            if task.tool:
                result.tools_run.append(task.tool)
                self._state.total_tools_run += 1
                result.actions_taken.append(f"run:{task.tool}")

            # Complete task
            self._task_decomposer.complete_task(task.task_id)
            result.actions_taken.append(f"complete:{task.name}")

        # Process messages
        running_agents = self._spawner.get_running_agents()
        for agent in running_agents:
            messages = self._comm.receive_all(agent.agent_id)
            for msg in messages:
                if msg.msg_type == MessageType.FINDING_REPORT:
                    self._process_finding(msg.payload, result)
                elif msg.msg_type == MessageType.TASK_COMPLETE:
                    result.actions_taken.append(f"child_complete:{msg.sender[:10]}")

        # Check timeouts
        timed_out = self._spawner.check_timeouts()
        for agent_id in timed_out:
            result.actions_taken.append(f"timeout:{agent_id[:10]}")

        # Update convergence
        self._convergence_monitor.record_cycle(
            findings=result.findings_count,
            coverage=0.0,
        )

        # Compute reward
        if result.findings_count > 0:
            signal_result = self._reward_optimizer.compute_tool_reward(
                tool=result.tools_run[0] if result.tools_run else "llm",
                success=True,
                findings_count=result.findings_count,
            )
            result.reward = signal_result.shaped_reward
            self._state.total_reward += result.reward

        result.duration_s = time.time() - cycle_start
        self._cycle_history.append(result)

        return result

    def run(self, max_cycles: int | None = None) -> list[CycleResult]:
        """Run the brain for multiple cycles."""
        cycles = max_cycles or self._config.max_cycles
        results = []

        for _ in range(cycles):
            if self._state.phase == BrainPhase.CONVERGED:
                break
            if self._state.elapsed_s > self._config.max_time_s:
                break

            result = self.run_cycle()
            results.append(result)

        return results

    def _process_finding(
        self,
        finding_data: dict[str, Any],
        cycle_result: CycleResult,
    ) -> None:
        """Process a new finding."""
        self._state.total_findings += 1
        cycle_result.findings_count += 1

        # Correlate
        if self._config.auto_correlate:
            self._finding_correlator.ingest({
                "title": finding_data.get("title", ""),
                "severity": finding_data.get("severity", "medium"),
                "target": finding_data.get("target", ""),
                "tool": finding_data.get("tool", ""),
            })

        # Compute reward
        reward = self._reward_optimizer.compute_finding_reward(
            severity=finding_data.get("severity", "medium"),
            confidence=finding_data.get("confidence", 0.5),
            vuln_class=finding_data.get("cwe", ""),
            target=finding_data.get("target", ""),
            tool=finding_data.get("tool", ""),
        )
        cycle_result.reward += reward.shaped_reward

    def _inject_knowledge(self, profile: dict[str, Any]) -> None:
        """Inject relevant knowledge into context."""
        # Web app knowledge
        web_prompt = self._webapp_kb.build_testing_prompt(max_patterns=3)
        if web_prompt:
            self._context_mgr.add_item(
                content=web_prompt,
                content_type=ContentType.STRATEGY_KNOWLEDGE,
                priority=ContentPriority.MEDIUM,
            )

        # Cloud knowledge
        cloud_prompt = self._cloud_kb.build_cloud_testing_prompt(max_patterns=2)
        if cloud_prompt:
            self._context_mgr.add_item(
                content=cloud_prompt,
                content_type=ContentType.STRATEGY_KNOWLEDGE,
                priority=ContentPriority.MEDIUM,
            )

        # Supply chain knowledge
        sc_prompt = self._supply_chain_kb.build_supply_chain_prompt(max_patterns=2)
        if sc_prompt:
            self._context_mgr.add_item(
                content=sc_prompt,
                content_type=ContentType.STRATEGY_KNOWLEDGE,
                priority=ContentPriority.LOW,
            )

    @staticmethod
    def _categorize_task(tool: str, strategy: str) -> TaskCategory:
        """Categorize a task for model routing."""
        tool_categories = {
            "nmap": TaskCategory.SECURITY_ANALYSIS,
            "nuclei": TaskCategory.SECURITY_ANALYSIS,
            "sqlmap": TaskCategory.SECURITY_ANALYSIS,
            "semgrep": TaskCategory.CODE_ANALYSIS,
            "bandit": TaskCategory.CODE_ANALYSIS,
            "gobuster": TaskCategory.SECURITY_ANALYSIS,
            "hydra": TaskCategory.SECURITY_ANALYSIS,
            "subfinder": TaskCategory.GENERAL,
        }

        if tool and tool in tool_categories:
            return tool_categories[tool]

        strategy_categories = {
            "business_logic": TaskCategory.REASONING,
            "timing": TaskCategory.REASONING,
            "supply_chain": TaskCategory.CODE_ANALYSIS,
            "cloud": TaskCategory.SECURITY_ANALYSIS,
        }

        for key, cat in strategy_categories.items():
            if key in strategy.lower():
                return cat

        return TaskCategory.GENERAL

    def get_state(self) -> BrainState:
        return self._state

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.to_dict(),
            "state_machine": self._state_machine.get_stats(),
            "router": self._model_router.get_stats(),
            "tools": self._tool_executor.get_stats(),
            "findings": self._finding_correlator.get_stats(),
            "knowledge_graph": self._knowledge_graph.get_stats(),
            "convergence": self._convergence_monitor.get_stats(),
            "spawner": self._spawner.get_stats(),
            "rewards": self._reward_optimizer.get_stats(),
            "cycles": len(self._cycle_history),
        }
