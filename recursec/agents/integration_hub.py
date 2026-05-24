"""Integration hub — wires ALL modules together.

Central integration point that connects:
1. Intent classification → KB selection → prompt assembly
2. Agent spawning → model routing → execution pipeline
3. Knowledge graph → finding correlation → memory storage
4. Self-reflection → learning → strategy adaptation
5. Autonomous loop → convergence → expansion triggers

This is the brain's brain — it decides HOW to combine
all the intelligence modules for any given task.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class IntegrationMode(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    RECURSIVE = "recursive"
    ENSEMBLE = "ensemble"
    ADAPTIVE = "adaptive"


class ComponentType(str, Enum):
    INTENT_CLASSIFIER = "intent_classifier"
    KB_LOADER = "kb_loader"
    PROMPT_ASSEMBLER = "prompt_assembler"
    MODEL_ROUTER = "model_router"
    AGENT_SPAWNER = "agent_spawner"
    TOOL_ORCHESTRATOR = "tool_orchestrator"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    MEMORY_STORE = "memory_store"
    SELF_REFLECTION = "self_reflection"
    FINDING_CORRELATOR = "finding_correlator"
    EXECUTION_PIPELINE = "execution_pipeline"
    AUTONOMOUS_LOOP = "autonomous_loop"
    TASK_DECOMPOSER = "task_decomposer"
    MODEL_ENSEMBLE = "model_ensemble"
    CONTEXT_COMPRESSOR = "context_compressor"
    SAFETY_GUARD = "safety_guard"


@dataclass
class ComponentConfig:
    """Configuration for an integration component."""
    component_type: ComponentType = ComponentType.INTENT_CLASSIFIER
    enabled: bool = True
    priority: int = 5
    timeout_s: float = 30.0
    max_retries: int = 2
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.component_type.value,
            "enabled": self.enabled,
            "priority": self.priority,
        }


@dataclass
class IntegrationPlan:
    """A plan for how to integrate components for a task."""
    plan_id: str = ""
    mode: IntegrationMode = IntegrationMode.SEQUENTIAL
    components: list[ComponentConfig] = field(default_factory=list)
    data_flow: list[tuple[str, str]] = field(default_factory=list)
    estimated_duration_s: float = 0.0
    token_budget: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id[:8],
            "mode": self.mode.value,
            "components": len(self.components),
            "flows": len(self.data_flow),
        }


# Task complexity → integration mode
COMPLEXITY_MODE_MAP: dict[str, IntegrationMode] = {
    "trivial": IntegrationMode.SEQUENTIAL,
    "simple": IntegrationMode.SEQUENTIAL,
    "moderate": IntegrationMode.PARALLEL,
    "complex": IntegrationMode.RECURSIVE,
    "expert": IntegrationMode.ENSEMBLE,
    "unknown": IntegrationMode.ADAPTIVE,
}

# Integration mode → required components
MODE_COMPONENTS: dict[IntegrationMode, list[ComponentType]] = {
    IntegrationMode.SEQUENTIAL: [
        ComponentType.INTENT_CLASSIFIER,
        ComponentType.KB_LOADER,
        ComponentType.PROMPT_ASSEMBLER,
        ComponentType.MODEL_ROUTER,
        ComponentType.TOOL_ORCHESTRATOR,
    ],
    IntegrationMode.PARALLEL: [
        ComponentType.INTENT_CLASSIFIER,
        ComponentType.KB_LOADER,
        ComponentType.PROMPT_ASSEMBLER,
        ComponentType.MODEL_ROUTER,
        ComponentType.AGENT_SPAWNER,
        ComponentType.TOOL_ORCHESTRATOR,
        ComponentType.FINDING_CORRELATOR,
    ],
    IntegrationMode.RECURSIVE: [
        ComponentType.INTENT_CLASSIFIER,
        ComponentType.TASK_DECOMPOSER,
        ComponentType.KB_LOADER,
        ComponentType.PROMPT_ASSEMBLER,
        ComponentType.MODEL_ROUTER,
        ComponentType.AGENT_SPAWNER,
        ComponentType.TOOL_ORCHESTRATOR,
        ComponentType.KNOWLEDGE_GRAPH,
        ComponentType.FINDING_CORRELATOR,
        ComponentType.MEMORY_STORE,
    ],
    IntegrationMode.ENSEMBLE: [
        ComponentType.INTENT_CLASSIFIER,
        ComponentType.KB_LOADER,
        ComponentType.PROMPT_ASSEMBLER,
        ComponentType.MODEL_ENSEMBLE,
        ComponentType.AGENT_SPAWNER,
        ComponentType.TOOL_ORCHESTRATOR,
        ComponentType.KNOWLEDGE_GRAPH,
        ComponentType.FINDING_CORRELATOR,
        ComponentType.SELF_REFLECTION,
        ComponentType.MEMORY_STORE,
    ],
    IntegrationMode.ADAPTIVE: [
        ComponentType.INTENT_CLASSIFIER,
        ComponentType.TASK_DECOMPOSER,
        ComponentType.KB_LOADER,
        ComponentType.PROMPT_ASSEMBLER,
        ComponentType.MODEL_ROUTER,
        ComponentType.MODEL_ENSEMBLE,
        ComponentType.AGENT_SPAWNER,
        ComponentType.TOOL_ORCHESTRATOR,
        ComponentType.KNOWLEDGE_GRAPH,
        ComponentType.FINDING_CORRELATOR,
        ComponentType.SELF_REFLECTION,
        ComponentType.MEMORY_STORE,
        ComponentType.AUTONOMOUS_LOOP,
        ComponentType.CONTEXT_COMPRESSOR,
        ComponentType.SAFETY_GUARD,
    ],
}

# Data flow connections between components
COMPONENT_DATA_FLOWS: list[tuple[ComponentType, ComponentType, str]] = [
    (ComponentType.INTENT_CLASSIFIER, ComponentType.KB_LOADER, "intent → kb_selection"),
    (ComponentType.INTENT_CLASSIFIER, ComponentType.MODEL_ROUTER, "intent → model_preference"),
    (ComponentType.INTENT_CLASSIFIER, ComponentType.AGENT_SPAWNER, "intent → role_selection"),
    (ComponentType.INTENT_CLASSIFIER, ComponentType.TASK_DECOMPOSER, "intent → decomposition"),
    (ComponentType.KB_LOADER, ComponentType.PROMPT_ASSEMBLER, "knowledge → prompt_context"),
    (ComponentType.PROMPT_ASSEMBLER, ComponentType.MODEL_ROUTER, "prompt → llm_request"),
    (ComponentType.PROMPT_ASSEMBLER, ComponentType.MODEL_ENSEMBLE, "prompt → multi_model"),
    (ComponentType.MODEL_ROUTER, ComponentType.TOOL_ORCHESTRATOR, "llm_output → tool_calls"),
    (ComponentType.MODEL_ENSEMBLE, ComponentType.TOOL_ORCHESTRATOR, "consensus → tool_calls"),
    (ComponentType.TOOL_ORCHESTRATOR, ComponentType.KNOWLEDGE_GRAPH, "results → graph_update"),
    (ComponentType.TOOL_ORCHESTRATOR, ComponentType.FINDING_CORRELATOR, "results → correlation"),
    (ComponentType.TOOL_ORCHESTRATOR, ComponentType.MEMORY_STORE, "results → memory"),
    (ComponentType.FINDING_CORRELATOR, ComponentType.KNOWLEDGE_GRAPH, "correlations → edges"),
    (ComponentType.FINDING_CORRELATOR, ComponentType.SELF_REFLECTION, "findings → review"),
    (ComponentType.SELF_REFLECTION, ComponentType.AUTONOMOUS_LOOP, "reflection → loop_action"),
    (ComponentType.AUTONOMOUS_LOOP, ComponentType.INTENT_CLASSIFIER, "next_action → new_intent"),
    (ComponentType.KNOWLEDGE_GRAPH, ComponentType.PROMPT_ASSEMBLER, "graph_context → prompt"),
    (ComponentType.MEMORY_STORE, ComponentType.PROMPT_ASSEMBLER, "memory → prompt_context"),
    (ComponentType.TASK_DECOMPOSER, ComponentType.AGENT_SPAWNER, "subtasks → child_agents"),
    (ComponentType.AGENT_SPAWNER, ComponentType.MODEL_ROUTER, "agent → model_assignment"),
    (ComponentType.CONTEXT_COMPRESSOR, ComponentType.PROMPT_ASSEMBLER, "compressed → context"),
    (ComponentType.SAFETY_GUARD, ComponentType.TOOL_ORCHESTRATOR, "safety_check → execution"),
]


# Intent → complexity estimation heuristics
INTENT_COMPLEXITY: dict[str, str] = {
    "recon": "simple",
    "subdomain_enum": "simple",
    "port_scan": "simple",
    "web_vuln_scan": "moderate",
    "api_security": "moderate",
    "code_audit": "moderate",
    "network_pentest": "complex",
    "cloud_audit": "moderate",
    "mobile_pentest": "complex",
    "wireless_pentest": "complex",
    "social_engineering": "moderate",
    "phishing": "moderate",
    "osint": "simple",
    "cryptanalysis": "expert",
    "forensics": "complex",
    "incident_response": "complex",
    "malware_analysis": "expert",
    "exploit_dev": "expert",
    "privesc": "moderate",
    "lateral_movement": "complex",
    "container_security": "moderate",
    "iot_security": "complex",
    "supply_chain": "complex",
    "compliance": "moderate",
    "threat_hunt": "complex",
    "red_team": "expert",
    "blue_team": "complex",
    "bug_bounty": "moderate",
    "full_pentest": "expert",
    "general_security": "moderate",
}


class IntegrationHub:
    """Central integration engine.

    Wires all intelligence modules together based on
    task requirements, complexity, and available resources.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="integration_hub")
        self._plan_counter = 0
        self._component_registry: dict[ComponentType, ComponentConfig] = {}
        self._active_plans: list[IntegrationPlan] = []
        self._initialize_defaults()

    def _initialize_defaults(self) -> None:
        """Set up default component configurations."""
        defaults: list[tuple[ComponentType, int, float]] = [
            (ComponentType.INTENT_CLASSIFIER, 10, 5.0),
            (ComponentType.KB_LOADER, 9, 10.0),
            (ComponentType.PROMPT_ASSEMBLER, 8, 5.0),
            (ComponentType.MODEL_ROUTER, 7, 30.0),
            (ComponentType.AGENT_SPAWNER, 7, 10.0),
            (ComponentType.TOOL_ORCHESTRATOR, 6, 120.0),
            (ComponentType.KNOWLEDGE_GRAPH, 5, 5.0),
            (ComponentType.MEMORY_STORE, 5, 5.0),
            (ComponentType.SELF_REFLECTION, 4, 15.0),
            (ComponentType.FINDING_CORRELATOR, 4, 10.0),
            (ComponentType.EXECUTION_PIPELINE, 3, 300.0),
            (ComponentType.AUTONOMOUS_LOOP, 2, 600.0),
            (ComponentType.TASK_DECOMPOSER, 8, 10.0),
            (ComponentType.MODEL_ENSEMBLE, 6, 60.0),
            (ComponentType.CONTEXT_COMPRESSOR, 7, 5.0),
            (ComponentType.SAFETY_GUARD, 10, 3.0),
        ]
        for ctype, priority, timeout in defaults:
            self._component_registry[ctype] = ComponentConfig(
                component_type=ctype,
                priority=priority,
                timeout_s=timeout,
            )

    def create_plan(
        self,
        intent_value: str,
        token_budget: int = 8192,
    ) -> IntegrationPlan:
        """Create an integration plan for a given intent."""
        self._plan_counter += 1
        complexity = INTENT_COMPLEXITY.get(intent_value, "moderate")
        mode = COMPLEXITY_MODE_MAP.get(complexity, IntegrationMode.ADAPTIVE)

        required = MODE_COMPONENTS.get(mode, [])
        components = []
        for ctype in required:
            config = self._component_registry.get(ctype)
            if config and config.enabled:
                components.append(config)

        # Sort by priority (higher first)
        components.sort(key=lambda c: c.priority, reverse=True)

        # Build data flows for active components
        active_types = {c.component_type for c in components}
        flows = [
            (src.value, tgt.value)
            for src, tgt, _desc in COMPONENT_DATA_FLOWS
            if src in active_types and tgt in active_types
        ]

        # Estimate duration
        est_duration = sum(c.timeout_s for c in components) * 0.3

        plan = IntegrationPlan(
            plan_id=f"plan-{self._plan_counter}",
            mode=mode,
            components=components,
            data_flow=flows,
            estimated_duration_s=est_duration,
            token_budget=token_budget,
        )

        self._active_plans.append(plan)
        if len(self._active_plans) > 100:
            self._active_plans = self._active_plans[-50:]

        return plan

    def get_data_flow(
        self,
        plan: IntegrationPlan,
    ) -> list[dict[str, str]]:
        """Get the data flow graph for a plan."""
        return [
            {"from": src, "to": tgt}
            for src, tgt in plan.data_flow
        ]

    def get_execution_order(
        self,
        plan: IntegrationPlan,
    ) -> list[ComponentType]:
        """Get topological execution order for plan components."""
        # Build dependency graph from data flows
        active_types = {c.component_type for c in plan.components}
        deps: dict[ComponentType, set[ComponentType]] = {
            ct: set() for ct in active_types
        }

        for src, tgt, _desc in COMPONENT_DATA_FLOWS:
            if src in active_types and tgt in active_types:
                deps[tgt].add(src)

        # Topological sort
        order: list[ComponentType] = []
        visited: set[ComponentType] = set()

        def visit(node: ComponentType) -> None:
            if node in visited:
                return
            visited.add(node)
            for dep in deps.get(node, set()):
                visit(dep)
            order.append(node)

        for node in active_types:
            visit(node)

        return order

    def build_system_prompt(
        self,
        intent_value: str,
        kbs: list[str] | None = None,
    ) -> str:
        """Build a comprehensive system prompt with all context."""
        plan = self.create_plan(intent_value)
        lines = [
            "You are an autonomous security agent.",
            f"Task type: {intent_value}",
            f"Integration mode: {plan.mode.value}",
            f"Active components: {len(plan.components)}",
            f"Data flows: {len(plan.data_flow)}",
            "",
        ]

        if kbs:
            lines.append(f"Knowledge domains loaded: {', '.join(kbs[:10])}")
            lines.append("")

        order = self.get_execution_order(plan)
        lines.append("Execution order:")
        for idx, ctype in enumerate(order, 1):
            lines.append(f"  {idx}. {ctype.value}")

        lines.append("")
        lines.append("Follow this execution pipeline precisely.")
        lines.append("Use all available knowledge domains.")
        lines.append("Report findings with severity and confidence.")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        """Get integration hub statistics."""
        return {
            "total_plans": self._plan_counter,
            "active_plans": len(self._active_plans),
            "registered_components": len(self._component_registry),
            "enabled_components": sum(
                1 for c in self._component_registry.values()
                if c.enabled
            ),
        }
