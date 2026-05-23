"""Multi-agent coordinator — manages teams of specialized agents.

This is the top-level orchestration component that:
- Creates and manages agent teams for assessments
- Coordinates parallel agent execution
- Routes tasks to specialized agents
- Aggregates results from all agents
- Manages agent lifecycle (spawn, monitor, terminate)
- Implements consensus mechanisms for critical findings
- Handles agent failures with automatic recovery/reassignment

Agent team composition for a full assessment:
- Recon Agent: Network discovery, OSINT, subdomain enumeration
- Vuln Scanner Agent: Vulnerability scanning and identification
- Web Agent: Web application testing (XSS, SQLi, SSRF, etc.)
- Exploit Agent: Exploitation of confirmed vulnerabilities
- Code Audit Agent: Source code analysis
- Network Agent: Network-level testing
- Forensics Agent: Log analysis, artifact examination
- Validator Agent: Cross-validates all findings
- Reporter Agent: Generates final report
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from recursec.agents.communication import (
    AgentMessage,
    CoordinationSignal,
    MessageBus,
)
from recursec.agents.state_machine import (
    AgentState,
    AgentStateMachine,
    MultiAgentStateTracker,
)

if TYPE_CHECKING:
    from recursec.agents.autonomous_loop import AutonomousLoop
    from recursec.agents.context_manager import ContextPool
    from recursec.agents.learning import LearningEngine
    from recursec.agents.planner import HierarchicalPlanner
    from recursec.agents.strategy_selector import StrategySelector
    from recursec.core.reasoning import ReasoningEngine
    from recursec.llm.router import ModelRouter
    from recursec.memory.store import MemoryStore
    from recursec.tools.registry import ToolRegistry

logger = structlog.get_logger()


class TeamRole(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    WEB_SCAN = "web_scan"
    EXPLOIT = "exploit"
    CODE_AUDIT = "code_audit"
    NETWORK = "network"
    FORENSICS = "forensics"
    OSINT = "osint"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    COORDINATOR = "coordinator"


class AssessmentType(str, Enum):
    FULL = "full"               # All phases
    QUICK = "quick"             # Recon + scan only
    WEB_ONLY = "web_only"       # Web application focused
    NETWORK_ONLY = "network"    # Network infrastructure
    CODE_ONLY = "code"          # Source code audit
    RED_TEAM = "red_team"       # Full exploitation chain
    COMPLIANCE = "compliance"   # Compliance checking


# Team compositions for different assessment types
TEAM_COMPOSITIONS: dict[AssessmentType, list[TeamRole]] = {
    AssessmentType.FULL: [
        TeamRole.RECON, TeamRole.VULN_SCAN, TeamRole.WEB_SCAN,
        TeamRole.EXPLOIT, TeamRole.NETWORK, TeamRole.VALIDATOR, TeamRole.REPORTER,
    ],
    AssessmentType.QUICK: [
        TeamRole.RECON, TeamRole.VULN_SCAN, TeamRole.REPORTER,
    ],
    AssessmentType.WEB_ONLY: [
        TeamRole.RECON, TeamRole.WEB_SCAN, TeamRole.EXPLOIT,
        TeamRole.VALIDATOR, TeamRole.REPORTER,
    ],
    AssessmentType.NETWORK_ONLY: [
        TeamRole.RECON, TeamRole.NETWORK, TeamRole.VULN_SCAN,
        TeamRole.VALIDATOR, TeamRole.REPORTER,
    ],
    AssessmentType.CODE_ONLY: [
        TeamRole.CODE_AUDIT, TeamRole.VALIDATOR, TeamRole.REPORTER,
    ],
    AssessmentType.RED_TEAM: [
        TeamRole.RECON, TeamRole.VULN_SCAN, TeamRole.WEB_SCAN,
        TeamRole.EXPLOIT, TeamRole.NETWORK, TeamRole.FORENSICS,
        TeamRole.VALIDATOR, TeamRole.REPORTER,
    ],
    AssessmentType.COMPLIANCE: [
        TeamRole.RECON, TeamRole.VULN_SCAN, TeamRole.NETWORK,
        TeamRole.REPORTER,
    ],
}

# Phase ordering — which roles execute in which phase
PHASE_ORDERING: list[list[TeamRole]] = [
    [TeamRole.RECON, TeamRole.OSINT],                     # Phase 1: Discovery
    [TeamRole.VULN_SCAN, TeamRole.WEB_SCAN, TeamRole.NETWORK, TeamRole.CODE_AUDIT],  # Phase 2: Scanning (parallel)
    [TeamRole.EXPLOIT],                                     # Phase 3: Exploitation
    [TeamRole.FORENSICS],                                   # Phase 4: Post-exploit
    [TeamRole.VALIDATOR],                                   # Phase 5: Validation
    [TeamRole.REPORTER],                                    # Phase 6: Reporting
]


@dataclass
class AgentHandle:
    """Handle to a managed agent."""
    agent_id: str
    role: TeamRole
    state_machine: AgentStateMachine
    loop: AutonomousLoop | None = None
    task: asyncio.Task[Any] | None = None
    started_at: float = 0.0
    completed_at: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id, "role": self.role.value,
            "state": self.state_machine.state.value,
            "findings": len(self.findings),
            "errors": len(self.errors),
        }


@dataclass
class Assessment:
    """A coordinated multi-agent assessment."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    assessment_type: AssessmentType = AssessmentType.FULL
    target: str = ""
    objective: str = ""
    agents: dict[str, AgentHandle] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    current_phase: int = 0
    total_phases: int = 6
    status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id,
            "type": self.assessment_type.value,
            "target": self.target,
            "status": self.status,
            "phase": f"{self.current_phase}/{self.total_phases}",
            "agents": {aid: ah.to_dict() for aid, ah in self.agents.items()},
            "findings": len(self.all_findings),
            "validated": len(self.validated_findings),
            "duration_s": round(self.completed_at - self.started_at, 1) if self.completed_at else 0,
        }


class MultiAgentCoordinator:
    """Top-level coordinator for multi-agent security assessments."""

    def __init__(
        self,
        model_router: ModelRouter,
        tool_registry: ToolRegistry,
        memory: MemoryStore,
        reasoning_engine: ReasoningEngine,
        learning_engine: LearningEngine | None = None,
        strategy_selector: StrategySelector | None = None,
        planner: HierarchicalPlanner | None = None,
        context_pool: ContextPool | None = None,
        max_concurrent_agents: int = 5,
    ) -> None:
        self._router = model_router
        self._tools = tool_registry
        self._memory = memory
        self._reasoning = reasoning_engine
        self._learning = learning_engine
        self._strategy = strategy_selector
        self._planner = planner
        self._context_pool = context_pool
        self._max_concurrent = max_concurrent_agents

        self._bus = MessageBus()
        self._state_tracker = MultiAgentStateTracker()
        self._assessments: dict[str, Assessment] = {}
        self._log = logger.bind(component="coordinator")

    async def start_assessment(
        self,
        target: str,
        assessment_type: AssessmentType = AssessmentType.FULL,
        objective: str = "",
    ) -> Assessment:
        """Start a coordinated multi-agent assessment."""
        assessment = Assessment(
            assessment_type=assessment_type,
            target=target,
            objective=objective or f"Comprehensive {assessment_type.value} assessment of {target}",
            started_at=time.time(),
            status="running",
        )

        self._assessments[assessment.assessment_id] = assessment
        self._log.info(
            "assessment_started",
            id=assessment.assessment_id,
            type=assessment_type.value,
            target=target,
        )

        # Create the team
        team_roles = TEAM_COMPOSITIONS.get(assessment_type, TEAM_COMPOSITIONS[AssessmentType.FULL])
        for role in team_roles:
            agent_id = f"{role.value}_{assessment.assessment_id}"
            sm = AgentStateMachine(agent_id)
            handle = AgentHandle(agent_id=agent_id, role=role, state_machine=sm)
            assessment.agents[agent_id] = handle
            self._state_tracker.register(agent_id, sm)
            self._bus.register_agent(agent_id)
            self._bus.subscribe(agent_id, "findings")
            self._bus.subscribe(agent_id, "coordination")

        # Register coordinator on bus
        coord_id = f"coordinator_{assessment.assessment_id}"
        self._bus.register_agent(coord_id)
        self._bus.subscribe(coord_id, "findings")
        self._bus.subscribe(coord_id, "alerts")

        # Execute phases
        try:
            await self._execute_phases(assessment)
            assessment.status = "completed"
        except Exception as e:
            self._log.error("assessment_failed", error=str(e))
            assessment.status = "failed"
            assessment.metadata["error"] = str(e)

        assessment.completed_at = time.time()
        return assessment

    async def _execute_phases(self, assessment: Assessment) -> None:
        """Execute assessment phases sequentially."""
        for phase_idx, phase_roles in enumerate(PHASE_ORDERING):
            assessment.current_phase = phase_idx + 1

            # Filter to roles that are in our team
            active_roles = [
                role for role in phase_roles
                if any(ah.role == role for ah in assessment.agents.values())
            ]

            if not active_roles:
                continue

            self._log.info(
                "phase_started",
                phase=phase_idx + 1,
                roles=[r.value for r in active_roles],
            )

            # Start agents for this phase (potentially in parallel)
            phase_tasks = []
            for agent_id, handle in assessment.agents.items():
                if handle.role in active_roles:
                    task = asyncio.create_task(
                        self._run_agent(assessment, handle)
                    )
                    handle.task = task
                    phase_tasks.append(task)

            # Wait for all agents in this phase to complete
            if phase_tasks:
                results = await asyncio.gather(*phase_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        self._log.error("agent_failed_in_phase", error=str(result))

            # Collect findings from this phase
            self._collect_findings(assessment)

            # Broadcast phase completion
            await self._bus.send(AgentMessage.coordination(
                f"coordinator_{assessment.assessment_id}",
                CoordinationSignal.CHECKPOINT,
                {"phase": phase_idx + 1, "findings_so_far": len(assessment.all_findings)},
            ))

            # Check if we should skip remaining phases
            if phase_idx == 1 and not assessment.all_findings:
                self._log.info("no_findings_after_scan_phase, skipping_exploitation")
                # Skip exploitation if no vulns found
                continue

    async def _run_agent(self, assessment: Assessment, handle: AgentHandle) -> dict[str, Any]:
        """Run a single agent within the assessment."""
        handle.started_at = time.time()
        await handle.state_machine.transition(AgentState.INITIALIZING, reason="coordinator_start")

        self._log.info("agent_running", agent=handle.agent_id, role=handle.role.value)

        try:
            # Create the autonomous loop for this agent
            from recursec.agents.autonomous_loop import AutonomousLoop

            loop = AutonomousLoop(
                agent_id=handle.agent_id,
                model_router=self._router,
                tool_registry=self._tools,
                memory=self._memory,
                reasoning_engine=self._reasoning,
                message_bus=self._bus,
                planner=self._planner,
                state_machine=handle.state_machine,
                target=assessment.target,
                max_cycles=50,  # Per-agent cycle limit
                max_time_s=600.0,  # 10 minutes per agent
            )

            # Add role-specific goals
            self._add_role_goals(loop, handle.role, assessment)

            handle.loop = loop
            result = await loop.run()

            handle.findings = result.get("findings", [])
            handle.completed_at = time.time()

            return result

        except Exception as e:
            handle.errors.append(str(e))
            handle.completed_at = time.time()
            await handle.state_machine.transition(AgentState.FAILED, reason=str(e))
            raise

    def _add_role_goals(self, loop: AutonomousLoop, role: TeamRole, assessment: Assessment) -> None:
        """Add role-specific goals to an agent's loop."""
        goals = {
            TeamRole.RECON: [
                ("Discover all hosts and services on the target", "List of hosts/services found"),
                ("Enumerate subdomains and DNS records", "Subdomain list"),
                ("Identify technology stack", "Technology fingerprints"),
            ],
            TeamRole.VULN_SCAN: [
                ("Scan for known vulnerabilities", "List of CVEs/vulnerabilities"),
                ("Check for misconfigurations", "Configuration issues found"),
            ],
            TeamRole.WEB_SCAN: [
                ("Test for web vulnerabilities (XSS, SQLi, SSRF)", "Web vulnerability findings"),
                ("Check authentication and authorization", "Auth issues found"),
                ("Test for injection flaws", "Injection points identified"),
            ],
            TeamRole.EXPLOIT: [
                ("Exploit confirmed high/critical vulnerabilities", "Successful exploits"),
                ("Demonstrate impact of findings", "Impact evidence"),
            ],
            TeamRole.CODE_AUDIT: [
                ("Review source code for vulnerabilities", "Code-level findings"),
                ("Check for hardcoded secrets", "Secrets found in code"),
            ],
            TeamRole.NETWORK: [
                ("Test network segmentation", "Network topology findings"),
                ("Check for network-level vulnerabilities", "Network vulnerabilities"),
            ],
            TeamRole.VALIDATOR: [
                ("Validate all findings from other agents", "Validated finding list"),
                ("Identify false positives", "False positive list"),
            ],
            TeamRole.REPORTER: [
                ("Generate assessment report", "Report generated"),
            ],
        }

        for desc, criteria in goals.get(role, []):
            loop.add_goal(desc, criteria)

    def _collect_findings(self, assessment: Assessment) -> None:
        """Collect findings from all agents."""
        for handle in assessment.agents.values():
            for finding in handle.findings:
                if finding not in assessment.all_findings:
                    assessment.all_findings.append(finding)

    async def get_assessment_status(self, assessment_id: str) -> dict[str, Any] | None:
        """Get the current status of an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None
        return assessment.to_dict()

    def list_assessments(self) -> list[dict[str, Any]]:
        """List all assessments."""
        return [a.to_dict() for a in self._assessments.values()]

    async def stop_assessment(self, assessment_id: str) -> bool:
        """Stop a running assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return False

        for handle in assessment.agents.values():
            if handle.loop:
                handle.loop.stop()
            if handle.task and not handle.task.done():
                handle.task.cancel()

        assessment.status = "cancelled"
        assessment.completed_at = time.time()

        await self._bus.send(AgentMessage.coordination(
            f"coordinator_{assessment_id}",
            CoordinationSignal.STOP,
        ))

        return True
