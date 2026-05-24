"""Master agent — the single entry point that orchestrates everything.

This is the top-level agent that a user interacts with.
Given any input like "find vulnerabilities in example.com",
it autonomously:
1. Classifies intent
2. Selects knowledge domains
3. Creates execution plan
4. Assembles optimal prompts
5. Routes to best LLM
6. Reasons about approach
7. Executes tools
8. Analyzes outputs
9. Correlates findings
10. Builds attack chains
11. Validates with different model
12. Learns from experience
13. Generates report

All components are wired together here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AgentConfig:
    """Master agent configuration."""
    max_depth: int = 5
    token_budget: int = 65536
    timeout_s: float = 3600.0
    stealth_mode: bool = False
    validation_enabled: bool = True
    learning_enabled: bool = True
    multi_model_debate: bool = False
    debate_rounds: int = 3
    max_tools_per_phase: int = 5
    max_findings_before_report: int = 50
    parallel_agents: int = 3
    auto_exploit: bool = False
    safe_mode: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.max_depth,
            "budget": self.token_budget,
            "timeout": f"{self.timeout_s:.0f}s",
            "stealth": self.stealth_mode,
            "validate": self.validation_enabled,
            "learn": self.learning_enabled,
            "debate": self.multi_model_debate,
        }


@dataclass
class AgentState:
    """Current state of the master agent."""
    session_id: str = ""
    task_id: str = ""
    phase: str = "idle"
    intent: str = ""
    target: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    tools_executed: list[str] = field(default_factory=list)
    kbs_loaded: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    started_at: float = field(default_factory=time.time)
    errors: list[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "session": self.session_id[:8],
            "phase": self.phase[:12],
            "intent": self.intent[:15],
            "findings": len(self.findings),
            "by_sev": self.finding_count_by_severity,
            "tools": len(self.tools_executed),
            "tokens": self.tokens_used,
            "elapsed": f"{self.elapsed_s:.0f}s",
        }


class MasterAgent:
    """The master agent — top-level orchestrator."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        self._config = config or AgentConfig()
        self._state = AgentState()
        self._log = logger.bind(component="master_agent")

        # Lazy-load components to avoid circular imports
        self._intent_classifier = None
        self._kb_registry = None
        self._prompt_assembler = None
        self._llm_engine = None
        self._reasoning_engine = None
        self._task_executor = None
        self._autonomous_controller = None
        self._experience_replay = None
        self._strategy_optimizer = None
        self._knowledge_graph = None
        self._agent_protocol = None

    def _get_intent_classifier(self) -> Any:
        if self._intent_classifier is None:
            try:
                from recursec.agents.intent_classifier import IntentClassifier
                self._intent_classifier = IntentClassifier()
            except ImportError:
                self._log.warning("intent_classifier_unavailable")
        return self._intent_classifier

    def _get_kb_registry(self) -> Any:
        if self._kb_registry is None:
            try:
                from recursec.agents import kb_registry
                self._kb_registry = kb_registry
            except ImportError:
                self._log.warning("kb_registry_unavailable")
        return self._kb_registry

    def _get_prompt_assembler(self) -> Any:
        if self._prompt_assembler is None:
            try:
                from recursec.agents.prompt_assembler import PromptAssembler
                self._prompt_assembler = PromptAssembler()
            except ImportError:
                self._log.warning("prompt_assembler_unavailable")
        return self._prompt_assembler

    def _get_llm_engine(self) -> Any:
        if self._llm_engine is None:
            try:
                from recursec.agents.llm_connection_engine import LLMConnectionEngine
                self._llm_engine = LLMConnectionEngine()
            except ImportError:
                self._log.warning("llm_engine_unavailable")
        return self._llm_engine

    def _get_reasoning_engine(self) -> Any:
        if self._reasoning_engine is None:
            try:
                from recursec.agents.reasoning_engine import ReasoningEngine
                self._reasoning_engine = ReasoningEngine()
            except ImportError:
                self._log.warning("reasoning_engine_unavailable")
        return self._reasoning_engine

    def _get_task_executor(self) -> Any:
        if self._task_executor is None:
            try:
                from recursec.agents.task_executor import TaskExecutor
                self._task_executor = TaskExecutor()
            except ImportError:
                self._log.warning("task_executor_unavailable")
        return self._task_executor

    def _get_autonomous_controller(self) -> Any:
        if self._autonomous_controller is None:
            try:
                from recursec.agents.autonomous_controller import AutonomousController
                self._autonomous_controller = AutonomousController()
            except ImportError:
                self._log.warning("autonomous_controller_unavailable")
        return self._autonomous_controller

    def classify_intent(self, user_input: str) -> dict[str, Any]:
        """Step 1: Classify user intent."""
        self._state.phase = "intent_classification"
        classifier = self._get_intent_classifier()
        if not classifier:
            return {"intent": "general_security", "confidence": 0.5}

        result = classifier.classify(user_input)
        self._state.intent = result.primary_intent.value if hasattr(result.primary_intent, 'value') else str(result.primary_intent)
        return {
            "intent": self._state.intent,
            "confidence": result.confidence,
            "secondary": [s.value if hasattr(s, 'value') else str(s) for s in (result.secondary_intents or [])],
            "entities": result.extracted_entities,
            "recommended_kbs": result.recommended_kbs,
            "recommended_model": result.recommended_model,
        }

    def select_knowledge(self, intent: str, entities: dict[str, list[str]] | None = None) -> list[str]:
        """Step 2: Select relevant knowledge bases."""
        self._state.phase = "knowledge_selection"
        registry = self._get_kb_registry()
        if not registry:
            return []

        kbs = registry.get_kbs_for_intent(intent)
        domain_names = [kb.domain for kb in kbs[:10]]
        self._state.kbs_loaded = domain_names
        return domain_names

    def create_execution_plan(
        self,
        target: str,
        intent: str,
        kb_domains: list[str],
    ) -> dict[str, Any]:
        """Step 3: Create execution plan."""
        self._state.phase = "planning"
        self._state.target = target
        executor = self._get_task_executor()
        if not executor:
            return {"phases": ["scanning", "reporting"]}

        plan = executor.create_plan(
            target=target,
            task_type=intent,
            token_budget=self._config.token_budget,
        )
        return plan.to_dict()

    def assemble_prompt(
        self,
        role: str,
        phase: str,
        user_input: str,
        kb_domains: list[str],
        model_context_size: int = 8192,
    ) -> dict[str, Any]:
        """Step 4: Assemble optimal prompt."""
        self._state.phase = "prompt_assembly"
        assembler = self._get_prompt_assembler()
        if not assembler:
            return {"system": f"You are a {role} agent.", "user": user_input}

        result = assembler.assemble(
            role=role,
            phase=phase,
            intent=self._state.intent,
            user_input=user_input,
            kb_domains=kb_domains,
            model_context_size=model_context_size,
        )
        return result.to_dict()

    def route_to_model(self, task_type: str, required_context: int = 4096) -> dict[str, Any]:
        """Step 5: Route to optimal LLM."""
        self._state.phase = "model_routing"
        engine = self._get_llm_engine()
        if not engine:
            return {"model": "mistral-7b", "reason": "default"}

        decision = engine.route_request(
            task_type=task_type,
            required_context=required_context,
        )
        model = decision.selected_model
        if model not in self._state.models_used:
            self._state.models_used.append(model)
        return decision.to_dict()

    def reason(
        self,
        mode: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Step 6: LLM reasoning."""
        self._state.phase = "reasoning"
        engine = self._get_reasoning_engine()
        if not engine:
            return {"action": "scan", "reasoning": "default approach"}

        from recursec.agents.reasoning_engine import ReasoningMode
        try:
            reasoning_mode = ReasoningMode(mode)
        except ValueError:
            reasoning_mode = ReasoningMode.CHAIN_OF_THOUGHT

        prompt = engine.get_reasoning_prompt(reasoning_mode, context)
        model = engine.get_model_for_mode(reasoning_mode)

        step = engine.create_step(
            mode=reasoning_mode,
            thought=f"Reasoning in {mode} mode",
            action="pending_llm_response",
        )

        return {
            "prompt": prompt[:200],
            "model": model,
            "step_id": step.step_id,
        }

    def record_finding(self, finding: dict[str, Any]) -> None:
        """Record a security finding."""
        self._state.findings.append(finding)

    def record_tool_execution(self, tool_name: str) -> None:
        """Record a tool execution."""
        if tool_name not in self._state.tools_executed:
            self._state.tools_executed.append(tool_name)

    def get_status(self) -> dict[str, Any]:
        """Get current agent status."""
        return {
            "state": self._state.to_dict(),
            "config": self._config.to_dict(),
            "components": {
                "intent_classifier": self._intent_classifier is not None,
                "kb_registry": self._kb_registry is not None,
                "prompt_assembler": self._prompt_assembler is not None,
                "llm_engine": self._llm_engine is not None,
                "reasoning_engine": self._reasoning_engine is not None,
                "task_executor": self._task_executor is not None,
                "autonomous_controller": self._autonomous_controller is not None,
            },
        }

    def build_agent_prompt(self) -> str:
        """Build a comprehensive prompt summarizing agent state for LLM."""
        lines = ["## Master Agent Status\n"]
        state = self._state

        lines.append(f"Phase: {state.phase}")
        lines.append(f"Intent: {state.intent}")
        lines.append(f"Target: {state.target}")
        lines.append(f"Elapsed: {state.elapsed_s:.0f}s")
        lines.append(f"Tokens: {state.tokens_used}")

        if state.findings:
            lines.append(f"\nFindings ({len(state.findings)}):")
            sev_counts = state.finding_count_by_severity
            for sev, count in sorted(sev_counts.items()):
                lines.append(f"  {sev}: {count}")

        if state.kbs_loaded:
            lines.append(f"\nKBs: {', '.join(state.kbs_loaded[:8])}")
        if state.models_used:
            lines.append(f"Models: {', '.join(state.models_used[:5])}")
        if state.tools_executed:
            lines.append(f"Tools: {', '.join(state.tools_executed[:10])}")

        if state.errors:
            lines.append(f"\nErrors ({len(state.errors)}):")
            for err in state.errors[-3:]:
                lines.append(f"  ! {err[:80]}")

        return "\n".join(lines)
