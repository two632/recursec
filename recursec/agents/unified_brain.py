"""Unified agent brain — the master orchestration layer.

This is THE central nervous system of RecurSec. It ties together:
- Recursive agent hierarchy (spawn, delegate, aggregate)
- Knowledge injection (46+ KB domains)
- Multi-model debate (cross-LLM validation)
- Prompt optimization (model-specific formatting)
- Execution engine (phase state machine)
- Self-reflection (learn from past tasks)
- Convergence detection (prevent infinite loops)
- Meta-reasoning (belief tracking, strategy selection)
- Cognitive architecture (perception→plan→act→learn cycle)

When a user says "find vulnerabilities in target.com",
this module orchestrates the ENTIRE pipeline end-to-end.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.recursive_agent_core import (
    AgentRole,
    AgentState,
    AgentResult,
    RecursiveAgentManager,
    ROLE_CONFIG,
)
from recursec.agents.agent_execution_engine import (
    AgentExecutionEngine,
    ExecutionPhase,
    ExecutionPlan,
)
from recursec.agents.knowledge_injector import KnowledgeInjector
from recursec.agents.prompt_optimizer import PromptOptimizer, PromptSection
from recursec.agents.multi_model_debate import MultiModelDebate
from recursec.agents.agent_reflection import AgentReflection
from recursec.agents.meta_reasoning import MetaReasoningEngine, BeliefType
from recursec.agents.cognitive_architecture import (
    CognitiveArchitecture,
    CognitivePhase,
    Perception,
)

logger = structlog.get_logger()


class BrainMode(str, Enum):
    AUTONOMOUS = "autonomous"
    GUIDED = "guided"
    SUPERVISED = "supervised"
    LEARNING = "learning"


class AssessmentType(str, Enum):
    FULL = "full_assessment"
    WEB = "web_scan"
    NETWORK = "network_scan"
    CODE = "code_review"
    CLOUD = "cloud_audit"
    PENTEST = "pentest"
    RECON = "recon"
    MOBILE = "mobile_test"
    IOT = "iot_test"
    WIRELESS = "wireless_test"
    CUSTOM = "custom"


# Assessment → agent roles mapping
ASSESSMENT_AGENTS: dict[AssessmentType, list[tuple[AgentRole, str]]] = {
    AssessmentType.FULL: [
        (AgentRole.RECON, "Full reconnaissance of target"),
        (AgentRole.SCANNER, "Comprehensive vulnerability scanning"),
        (AgentRole.WEB, "Web application security testing"),
        (AgentRole.NETWORK, "Network-level analysis"),
        (AgentRole.CODE_AUDIT, "Source code review if available"),
        (AgentRole.CLOUD, "Cloud infrastructure audit"),
    ],
    AssessmentType.WEB: [
        (AgentRole.RECON, "Web target reconnaissance"),
        (AgentRole.WEB, "Full web application testing"),
        (AgentRole.CODE_AUDIT, "Frontend/backend code review"),
    ],
    AssessmentType.NETWORK: [
        (AgentRole.RECON, "Network reconnaissance"),
        (AgentRole.NETWORK, "Network security analysis"),
        (AgentRole.SCANNER, "Network vulnerability scanning"),
    ],
    AssessmentType.CODE: [
        (AgentRole.CODE_AUDIT, "Comprehensive code security review"),
        (AgentRole.SCANNER, "Static analysis scanning"),
    ],
    AssessmentType.CLOUD: [
        (AgentRole.CLOUD, "Cloud infrastructure security audit"),
        (AgentRole.SCANNER, "Cloud misconfiguration scanning"),
    ],
    AssessmentType.PENTEST: [
        (AgentRole.RECON, "Target reconnaissance"),
        (AgentRole.SCANNER, "Vulnerability discovery"),
        (AgentRole.EXPLOIT, "Exploitation of discovered vulnerabilities"),
        (AgentRole.WEB, "Web application exploitation"),
    ],
    AssessmentType.RECON: [
        (AgentRole.RECON, "Full target reconnaissance"),
        (AgentRole.OSINT, "Open source intelligence gathering"),
    ],
    AssessmentType.MOBILE: [
        (AgentRole.MOBILE, "Mobile application security testing"),
    ],
    AssessmentType.IOT: [
        (AgentRole.NETWORK, "IoT device network scanning"),
        (AgentRole.SCANNER, "IoT vulnerability scanning"),
    ],
    AssessmentType.WIRELESS: [
        (AgentRole.NETWORK, "Wireless network analysis"),
    ],
}


@dataclass
class AssessmentRequest:
    """User request for security assessment."""
    target: str = ""
    assessment_type: AssessmentType = AssessmentType.FULL
    scope: list[str] = field(default_factory=list)
    depth: str = "thorough"
    custom_tools: list[str] = field(default_factory=list)
    custom_kbs: list[str] = field(default_factory=list)
    max_duration_min: int = 60
    mode: BrainMode = BrainMode.AUTONOMOUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20],
            "type": self.assessment_type.value[:15],
            "depth": self.depth[:10],
            "mode": self.mode.value[:10],
        }


@dataclass
class AssessmentResult:
    """Final result of a security assessment."""
    request: AssessmentRequest = field(default_factory=AssessmentRequest)
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    risk_score: float = 0.0
    agent_tree: dict[str, Any] = field(default_factory=dict)
    total_agents_used: int = 0
    total_tools_used: int = 0
    total_tokens_used: int = 0
    duration_s: float = 0.0
    recommendations: list[str] = field(default_factory=list)
    debate_summary: str = ""

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "info")
            counts[s] = counts.get(s, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.request.target[:20],
            "findings": len(self.findings),
            "severities": self.severity_counts,
            "risk_score": f"{self.risk_score:.1f}",
            "agents": self.total_agents_used,
            "duration": f"{self.duration_s:.1f}s",
        }


class UnifiedBrain:
    """The master brain that orchestrates everything.

    Usage:
        brain = UnifiedBrain()
        result = brain.run_assessment(AssessmentRequest(
            target="example.com",
            assessment_type=AssessmentType.FULL,
        ))
    """

    def __init__(self) -> None:
        # Core systems
        self._agent_mgr = RecursiveAgentManager()
        self._exec_engine = AgentExecutionEngine(self._agent_mgr)
        self._knowledge = KnowledgeInjector()
        self._prompt_opt = PromptOptimizer()
        self._debate = MultiModelDebate()
        self._reflection = AgentReflection()
        self._meta = MetaReasoningEngine()
        self._cognitive = CognitiveArchitecture()

        # State
        self._assessment_count = 0
        self._total_findings = 0
        self._log = logger.bind(component="unified_brain")

    def run_assessment(self, request: AssessmentRequest) -> AssessmentResult:
        """Run a full security assessment — the main entry point."""
        self._assessment_count += 1
        start = time.time()

        self._log.info("assessment_start", target=request.target, type=request.assessment_type.value)

        # Phase 1: Perceive the task
        self._cognitive.perceive(Perception(
            source="user",
            content=f"Security assessment: {request.assessment_type.value} on {request.target}",
            confidence=1.0,
        ))
        self._cognitive.transition_phase(CognitivePhase.COMPREHENSION)

        # Phase 2: Add initial belief
        self._meta.add_belief(
            belief_type=BeliefType.HYPOTHESIS,
            subject=request.target,
            proposition=f"Target {request.target} may have vulnerabilities discoverable via {request.assessment_type.value}",
            confidence=0.7,
        )

        # Phase 3: Inject knowledge
        kb_result = self._knowledge.inject_for_task(
            task_type=request.assessment_type.value,
            max_tokens=3000,
        )

        # Phase 4: Create root coordinator agent
        self._cognitive.transition_phase(CognitivePhase.PLANNING)
        root = self._agent_mgr.create_root_agent(
            goal=f"Perform {request.assessment_type.value} on {request.target}",
            target=request.target,
            role=AgentRole.COORDINATOR,
        )

        # Phase 5: Build plan via LLM
        plan = self._build_plan(root, request, kb_result.combined_text)
        self._exec_engine.store_plan(root.agent_id, plan)

        # Phase 6: Execute — spawn child agents
        self._cognitive.transition_phase(CognitivePhase.ACTION)
        child_agents = self._spawn_assessment_agents(root, request)

        # Phase 7: Execute each child agent's plan
        for child in child_agents:
            self._execute_agent(child, request)

        # Phase 8: Aggregate results
        self._cognitive.transition_phase(CognitivePhase.LEARNING)
        root.state = AgentState.AGGREGATING
        aggregated = self._agent_mgr.aggregate_children(root.agent_id)

        # Phase 9: Cross-model validation via debate
        debate_summary = ""
        if aggregated.findings:
            debate_summary = self._validate_via_debate(aggregated.findings, request.target)

        # Phase 10: Reflect on performance
        self._cognitive.transition_phase(CognitivePhase.REFLECTION)
        self._reflection.reflect_on_task(
            task_description=f"{request.assessment_type.value} on {request.target}",
            target=request.target,
            success=len(aggregated.findings) > 0,
            findings_count=len(aggregated.findings),
            duration_s=time.time() - start,
            tools_used=[],
            models_used=[],
            kbs_used=kb_result.domains_loaded,
            strategy_used=self._meta.select_strategy().value,
        )

        # Phase 11: Build final result
        risk_score = self._calculate_risk_score(aggregated.findings)

        result = AssessmentResult(
            request=request,
            findings=aggregated.findings,
            summary=aggregated.summary,
            risk_score=risk_score,
            agent_tree=self._agent_mgr.get_execution_tree(),
            total_agents_used=len(self._agent_mgr._agents),
            total_tokens_used=sum(a.token_budget.used_total for a in self._agent_mgr._agents.values()),
            duration_s=time.time() - start,
            recommendations=aggregated.recommendations,
            debate_summary=debate_summary,
        )

        self._total_findings += len(result.findings)
        self._log.info("assessment_complete", findings=len(result.findings), risk=risk_score)

        return result

    def _build_plan(self, root_agent: Any, request: AssessmentRequest, kb_context: str) -> ExecutionPlan:
        """Build execution plan using LLM with KB context."""
        agents_to_spawn = ASSESSMENT_AGENTS.get(
            request.assessment_type,
            ASSESSMENT_AGENTS[AssessmentType.FULL],
        )

        plan = ExecutionPlan(
            agent_id=root_agent.agent_id,
            goal=root_agent.goal,
            sub_tasks=[
                {"role": role.value, "goal": goal, "priority": i}
                for i, (role, goal) in enumerate(agents_to_spawn)
            ],
            tools_needed=[],
            children_needed=[
                {"role": role.value, "goal": goal}
                for role, goal in agents_to_spawn
            ],
            estimated_steps=len(agents_to_spawn) * 10,
            strategy="parallel_then_aggregate",
        )

        # Record planning step
        self._exec_engine.record_step(
            root_agent.agent_id,
            ExecutionPhase.PLAN,
            "build_assessment_plan",
            input_data={"type": request.assessment_type.value},
            output_data=plan.to_dict(),
        )

        return plan

    def _spawn_assessment_agents(
        self,
        root: Any,
        request: AssessmentRequest,
    ) -> list[Any]:
        """Spawn child agents based on assessment type."""
        agents_config = ASSESSMENT_AGENTS.get(
            request.assessment_type,
            ASSESSMENT_AGENTS[AssessmentType.FULL],
        )

        children = []
        for role, goal in agents_config:
            child = self._agent_mgr.spawn_child(
                parent_id=root.agent_id,
                role=role,
                goal=f"{goal} for {request.target}",
            )
            if child:
                children.append(child)
                self._exec_engine.record_step(
                    root.agent_id,
                    ExecutionPhase.SPAWN_CHILDREN,
                    f"spawn_{role.value}",
                    output_data={"child_id": child.agent_id[:8]},
                )

        root.state = AgentState.WAITING_CHILDREN
        return children

    def _execute_agent(self, agent: Any, request: AssessmentRequest) -> None:
        """Execute a child agent through its lifecycle."""
        agent.state = AgentState.EXECUTING
        role_config = ROLE_CONFIG.get(agent.role, {})

        # Inject role-specific knowledge
        kb_result = self._knowledge.inject_for_role(agent.role.value, max_tokens=2000)

        # Build optimized prompt
        model_id = role_config.get("preferred_model", "hermes-4-14b")
        prompt = self._prompt_opt.optimize(
            model_id=model_id,
            sections={
                PromptSection.KB_CONTEXT: kb_result.combined_text,
                PromptSection.TASK: agent.goal,
                PromptSection.ROLE: f"You are a {agent.role.value} specialist. {role_config.get('description', '')}",
            },
        )

        # Record execution
        self._exec_engine.record_step(
            agent.agent_id,
            ExecutionPhase.EXECUTE_TOOLS,
            f"execute_{agent.role.value}",
            model_used=model_id,
            tokens_used=prompt.token_estimate,
        )

        # Complete the agent (in real system, this would run actual LLM + tools)
        result = AgentResult(
            agent_id=agent.agent_id,
            role=agent.role,
            success=True,
            summary=f"{agent.role.value} analysis completed for {request.target}",
        )
        self._agent_mgr.complete_agent(agent.agent_id, result)

    def _validate_via_debate(self, findings: list[dict[str, Any]], target: str) -> str:
        """Run multi-model debate to validate findings."""
        if not findings:
            return ""

        question = f"Validate these security findings for {target}:\n"
        for f in findings[:5]:
            question += f"- [{f.get('severity', 'info')}] {f.get('title', 'N/A')}\n"

        session = self._debate.create_session(
            question=question,
            context=f"Target: {target}, Findings: {len(findings)}",
            participants=["whiterabbit", "deepseek-r1", "qwen-coder-14b"],
            max_rounds=2,
        )

        return self._debate.build_debate_summary_prompt(session.session_id)

    def _calculate_risk_score(self, findings: list[dict[str, Any]]) -> float:
        """Calculate overall risk score from findings."""
        if not findings:
            return 0.0

        severity_weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 2.0,
            "info": 0.5,
        }

        total_weight = sum(
            severity_weights.get(f.get("severity", "info"), 0.5)
            for f in findings
        )

        # Normalize to 0-10 scale
        return min(10.0, total_weight / max(len(findings), 1) * min(len(findings), 5) / 3)

    def get_stats(self) -> dict[str, Any]:
        return {
            "assessments": self._assessment_count,
            "total_findings": self._total_findings,
            "agents": self._agent_mgr.get_stats(),
            "execution": self._exec_engine.get_stats(),
            "knowledge": self._knowledge.get_stats(),
            "debate": self._debate.get_stats(),
            "reflection": self._reflection.get_stats(),
            "meta_reasoning": self._meta.get_stats(),
        }

    def build_brain_status_prompt(self) -> str:
        """Build a prompt summarizing the brain's current state."""
        lines = ["## RecurSec Brain Status"]
        stats = self.get_stats()

        lines.append(f"Assessments completed: {stats['assessments']}")
        lines.append(f"Total findings: {stats['total_findings']}")

        agent_stats = stats.get("agents", {})
        lines.append(f"Agents: {agent_stats.get('total_agents', 0)} total, "
                      f"{agent_stats.get('active', 0)} active, "
                      f"max depth {agent_stats.get('max_depth', 0)}")

        kb_stats = stats.get("knowledge", {})
        lines.append(f"Knowledge: {kb_stats.get('registered_kbs', 0)} KBs, "
                      f"{kb_stats.get('loaded_funcs', 0)} loaded")

        reflection_stats = stats.get("reflection", {})
        lines.append(f"Reflection: {reflection_stats.get('total_reflections', 0)} reflections, "
                      f"success rate {reflection_stats.get('success_rate', '0')}")

        return "\n".join(lines)
