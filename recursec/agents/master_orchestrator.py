"""Master orchestrator — the central brain that coordinates all subsystems.

This is the top-level agent that:
1. Receives a target and goal from the user
2. Analyzes the target (target_analyzer)
3. Creates a threat model (threat_modeler)
4. Generates hypotheses (hypothesis_engine)
5. Plans the assessment (task_planner, workflow_engine)
6. Manages the state machine
7. Spawns recursive agents (recursive_spawner)
8. Executes tools (tool_executor)
9. Validates findings (adversarial_validator, model_debate)
10. Enriches findings (vuln_intelligence)
11. Generates reports (report_formatter)
12. Learns from the assessment (meta_learning, learning_system)
13. Manages checkpoints (checkpoint)
14. Publishes events (event_bus)
15. Manages scope (scope_manager)
16. Monitors convergence (convergence_monitor)

This is the agent that the user interacts with.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class OrchestratorConfig:
    """Configuration for the master orchestrator."""
    target: str = ""
    goal: str = ""
    max_time_s: float = 3600.0
    max_agents: int = 30
    max_depth: int = 5
    validate_findings: bool = True
    deep_mode: bool = False
    stealth_mode: bool = False
    risk_threshold: float = 0.3
    strategy: str = "adaptive"
    scope_includes: list[str] = field(default_factory=list)
    scope_excludes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "goal": self.goal[:100],
            "max_time_s": self.max_time_s,
            "max_agents": self.max_agents,
            "strategy": self.strategy,
            "deep": self.deep_mode,
        }


@dataclass
class OrchestratorResult:
    """Result of a complete orchestrated assessment."""
    target: str = ""
    goal: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    enriched_findings: list[dict[str, Any]] = field(default_factory=list)
    threat_model: dict[str, Any] = field(default_factory=dict)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    report_path: str = ""
    agents_spawned: int = 0
    tools_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    duration_s: float = 0.0
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "findings": len(self.findings),
            "validated": len(self.validated_findings),
            "enriched": len(self.enriched_findings),
            "agents": self.agents_spawned,
            "tools": len(self.tools_used),
            "tokens": self.tokens_used,
            "duration_s": round(self.duration_s, 1),
            "success": self.success,
        }


class MasterOrchestrator:
    """Central brain coordinating all RecurSec subsystems.

    This is the entry point for all assessments.
    It coordinates between 15+ subsystems to produce
    comprehensive security assessments.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="orchestrator")

        # Lazy-loaded subsystems
        self._router = None
        self._target_analyzer = None
        self._threat_modeler = None
        self._hypothesis_engine = None
        self._task_planner = None
        self._workflow_engine = None
        self._state_machine = None
        self._tool_executor = None
        self._exploit_planner = None
        self._vuln_intel = None
        self._reasoning = None
        self._debate = None
        self._memory = None
        self._meta_learning = None
        self._checkpoint_mgr = None
        self._event_bus = None
        self._scope_manager = None
        self._session_manager = None
        self._report_formatter = None
        self._prompt_engine = None
        self._agent_pool = None

    def _ensure_subsystems(self) -> None:
        """Lazy-initialize all subsystems."""
        if self._router is not None:
            return

        from recursec.llm.advanced_router import AdvancedRouter
        from recursec.agents.target_analyzer import TargetAnalyzer
        from recursec.agents.threat_modeler import ThreatModeler
        from recursec.agents.hypothesis_engine import HypothesisEngine
        from recursec.agents.task_planner import TaskPlanner
        from recursec.agents.workflow_engine import WorkflowEngine
        from recursec.agents.state_machine import AgentStateMachine
        from recursec.agents.tool_executor import ToolExecutor
        from recursec.agents.exploit_planner import ExploitPlanner
        from recursec.agents.vuln_intelligence import VulnIntelligence
        from recursec.agents.reasoning_chain import ReasoningEngine
        from recursec.agents.model_debate import ModelDebate
        from recursec.agents.agent_memory import AgentMemory
        from recursec.agents.meta_learning import MetaLearning
        from recursec.agents.checkpoint import CheckpointManager
        from recursec.agents.event_bus import EventBus
        from recursec.agents.scope_manager import ScopeManager
        from recursec.agents.session_manager import SessionManager
        from recursec.reporting.formatter import ReportFormatter
        from recursec.agents.prompt_engine import PromptEngine
        from recursec.agents.agent_pool import AgentPool

        self._router = AdvancedRouter()
        self._target_analyzer = TargetAnalyzer(model_router=self._router)
        self._threat_modeler = ThreatModeler(model_router=self._router)
        self._hypothesis_engine = HypothesisEngine(model_router=self._router)
        self._task_planner = TaskPlanner(model_router=self._router)
        self._workflow_engine = WorkflowEngine()
        self._state_machine = AgentStateMachine()
        self._tool_executor = ToolExecutor()
        self._exploit_planner = ExploitPlanner(model_router=self._router)
        self._vuln_intel = VulnIntelligence(model_router=self._router)
        self._reasoning = ReasoningEngine(model_router=self._router)
        self._debate = ModelDebate(model_router=self._router)
        self._memory = AgentMemory()
        self._meta_learning = MetaLearning()
        self._checkpoint_mgr = CheckpointManager()
        self._event_bus = EventBus()
        self._scope_manager = ScopeManager()
        self._session_manager = SessionManager()
        self._report_formatter = ReportFormatter()
        self._prompt_engine = PromptEngine()
        self._agent_pool = AgentPool()

    async def run(self, config: OrchestratorConfig) -> OrchestratorResult:
        """Run a complete orchestrated assessment."""
        self._ensure_subsystems()

        start = time.time()
        result = OrchestratorResult(
            target=config.target,
            goal=config.goal,
        )

        # Create session
        session = self._session_manager.create_session(
            target=config.target, goal=config.goal,
        )
        self._session_manager.start_session(session.session_id)

        try:
            # Phase 1: Setup scope
            await self._setup_scope(config)
            self._state_machine.transition(
                self._get_event_type("start"),
            )

            # Phase 2: Target analysis
            self._state_machine.transition(self._get_event_type("complete"))
            profile = await self._target_analyzer.analyze(config.target)
            self._memory.store_knowledge(
                f"Target {config.target} is type {profile.target_type.value}",
                tags=["target", "profile"],
            )

            # Phase 3: Threat modeling
            threat_model = await self._threat_modeler.model_target(
                target=config.target,
                target_type=profile.target_type.value,
                technologies=profile.tech_stack.technologies,
            )
            result.threat_model = threat_model.to_dict()

            # Phase 4: Generate hypotheses
            observations = [
                f"Target type: {profile.target_type.value}",
                f"Entry points: {len(profile.entry_points)}",
                f"Risk profile: {profile.risk_profile}",
            ]
            hypotheses = await self._hypothesis_engine.generate_hypotheses(
                target=config.target, observations=observations,
            )
            result.hypotheses = [h.to_dict() for h in hypotheses]

            # Phase 5: Plan assessment
            self._state_machine.transition(self._get_event_type("complete"))
            await self._task_planner.create_plan(
                target=config.target,
                target_type=profile.target_type.value,
            )

            # Phase 6: Execute workflow
            self._state_machine.transition(self._get_event_type("complete"))
            wf = self._workflow_engine.create_workflow(
                template_name=profile.target_type.value,
                parameters={"target": config.target},
            )
            wf_result = await self._workflow_engine.execute(wf.workflow_id)

            # Phase 7: Collect findings from tool outputs
            all_findings = self._extract_findings(wf_result)

            # Phase 8: Execute tool scans
            self._state_machine.transition(self._get_event_type("complete"))
            tool_findings = await self._run_tools(config, profile)
            all_findings.extend(tool_findings)

            # Phase 9: Validate findings
            if config.validate_findings and all_findings:
                self._state_machine.transition(self._get_event_type("complete"))
                validated = await self._validate_findings(all_findings)
                result.validated_findings = validated
            else:
                result.validated_findings = all_findings

            # Phase 10: Enrich findings
            enriched = await self._vuln_intel.enrich_batch(all_findings)
            result.enriched_findings = [e.to_dict() for e in enriched]

            # Phase 11: Exploit planning (if deep mode)
            if config.deep_mode:
                self._state_machine.transition(self._get_event_type("complete"))
                exploit_plans = await self._exploit_planner.create_plans_for_findings(
                    all_findings,
                )
                for plan_data in exploit_plans:
                    result.findings.append(plan_data.to_dict())

            # Phase 12: Generate report
            self._state_machine.transition(self._get_event_type("complete"))
            report = self._report_formatter.generate(
                target=config.target,
                findings=all_findings,
                validated=result.validated_findings,
            )
            path = self._report_formatter.save_json(report)
            self._report_formatter.save_markdown(report)
            result.report_path = str(path)

            # Phase 13: Learn
            self._meta_learning.record_strategy_outcome(
                strategy=config.strategy,
                target_type=profile.target_type.value,
                findings=len(all_findings),
                critical=sum(1 for f in all_findings if f.get("severity") == "critical"),
                time_s=time.time() - start,
                success=True,
            )

            result.findings = all_findings
            result.success = True

            # Complete session
            self._session_manager.complete_session(
                session.session_id,
                findings=all_findings,
                validated=result.validated_findings,
            )

        except Exception as e:
            self._log.error("orchestration_failed", error=str(e)[:200])
            result.success = False
            self._session_manager.fail_session(session.session_id, str(e)[:200])

        result.duration_s = time.time() - start
        return result

    async def quick_scan(self, target: str) -> OrchestratorResult:
        """Run a quick scan (faster, less thorough)."""
        config = OrchestratorConfig(
            target=target,
            goal=f"Quick security scan of {target}",
            max_time_s=600.0,
            max_agents=10,
            validate_findings=False,
        )
        return await self.run(config)

    async def deep_assess(self, target: str, goal: str = "") -> OrchestratorResult:
        """Run a deep assessment (slower, more thorough)."""
        config = OrchestratorConfig(
            target=target,
            goal=goal or f"Deep security assessment of {target}",
            max_time_s=7200.0,
            max_agents=50,
            deep_mode=True,
            validate_findings=True,
        )
        return await self.run(config)

    async def _setup_scope(self, config: OrchestratorConfig) -> None:
        """Setup assessment scope."""
        self._scope_manager.add_target(config.target)
        for include in config.scope_includes:
            self._scope_manager.add_target(include)
        for exclude in config.scope_excludes:
            self._scope_manager.add_exclusion(exclude)

    async def _run_tools(
        self,
        config: OrchestratorConfig,
        profile: Any,
    ) -> list[dict[str, Any]]:
        """Run recommended tools against the target."""
        findings = []
        tools = profile.recommended_tools[:5]

        for tool_name in tools:
            if not self._tool_executor.is_tool_available(tool_name):
                continue

            cmd = self._build_tool_command(tool_name, config.target)
            if not cmd:
                continue

            result = await self._tool_executor.execute(
                command=cmd, tool_name=tool_name,
            )

            if result.success and result.stdout:
                extracted = self._parse_tool_output(tool_name, result.stdout, config.target)
                findings.extend(extracted)

        return findings

    async def _validate_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Validate findings using multi-model debate."""
        validated = []

        for finding in findings[:20]:
            title = finding.get("title", "")
            severity = finding.get("severity", "info")

            if severity in ("critical", "high"):
                # High-severity findings get full debate
                debate_result = await self._debate.debate(
                    question=f"Is this finding valid? {title}",
                    context=str(finding)[:300],
                )
                if debate_result.consensus_confidence > 0.5:
                    finding["validated"] = True
                    finding["validation_confidence"] = debate_result.consensus_confidence
                    validated.append(finding)
            else:
                # Lower severity just gets reasoning
                chain = await self._reasoning.reason_about_finding(finding)
                if chain.overall_confidence > 0.4:
                    finding["validated"] = True
                    finding["validation_confidence"] = chain.overall_confidence
                    validated.append(finding)

        return validated

    def _build_tool_command(self, tool: str, target: str) -> str:
        """Build a tool command for a target."""
        commands = {
            "nmap": f"nmap -sV -sC -T4 {target}",
            "nuclei": f"nuclei -u {target} -severity critical,high,medium -silent",
            "nikto": f"nikto -h {target} -maxtime 300",
            "httpx": f"echo {target} | httpx -silent -tech-detect",
            "subfinder": f"subfinder -d {target} -silent",
            "ffuf": f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -t 50",
            "whatweb": f"whatweb {target}",
            "curl": f"curl -sI {target}",
        }
        return commands.get(tool, "")

    def _parse_tool_output(
        self,
        tool: str,
        output: str,
        target: str,
    ) -> list[dict[str, Any]]:
        """Extract findings from tool output."""
        findings = []

        if tool == "nuclei":
            for line in output.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    findings.append({
                        "title": " ".join(parts[:-1])[:100],
                        "severity": self._detect_severity(line),
                        "target": target,
                        "tool": "nuclei",
                        "evidence": line[:200],
                    })

        elif tool == "nmap":
            for line in output.splitlines():
                if "open" in line and "/" in line:
                    findings.append({
                        "title": f"Open port: {line.strip()[:60]}",
                        "severity": "info",
                        "target": target,
                        "tool": "nmap",
                        "evidence": line.strip(),
                    })

        return findings

    def _detect_severity(self, text: str) -> str:
        """Detect severity from tool output text."""
        text_lower = text.lower()
        if "critical" in text_lower:
            return "critical"
        if "high" in text_lower:
            return "high"
        if "medium" in text_lower:
            return "medium"
        if "low" in text_lower:
            return "low"
        return "info"

    def _extract_findings(self, wf_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract findings from workflow results."""
        findings = []
        for step_id, step_result in wf_result.get("results", {}).items():
            if isinstance(step_result, dict) and "findings" in step_result:
                findings.extend(step_result["findings"])
        return findings

    def _get_event_type(self, name: str) -> Any:
        from recursec.agents.state_machine import EventType
        try:
            return EventType(name)
        except ValueError:
            return EventType.COMPLETE

    def get_stats(self) -> dict[str, Any]:
        self._ensure_subsystems()
        return {
            "subsystems": {
                "router": self._router.get_stats(),
                "memory": self._memory.get_stats(),
                "meta_learning": self._meta_learning.get_stats(),
                "sessions": self._session_manager.get_stats(),
                "agent_pool": self._agent_pool.get_stats(),
            }
        }
