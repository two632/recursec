"""Orchestrator — The master brain of RecurSec.

Coordinates the entire security assessment pipeline:
1. Receives high-level objectives (e.g., "pentest example.com")
2. Plans the assessment using reasoning models
3. Decomposes into phases (recon → scan → exploit → post-exploit → report)
4. Spawns specialized agent teams via RecursiveSpawner
5. Monitors progress, adjusts strategy, handles failures
6. Aggregates findings and builds attack chains
7. Produces final assessment report
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from recursec.agents.recursive_spawner import (
    AgentResult,
    AgentTask,
    RecursiveSpawner,
    TaskPriority,
)

logger = structlog.get_logger()


class AssessmentPhase(str, Enum):
    PLANNING = "planning"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    COMPLETED = "completed"


@dataclass
class Objective:
    """A high-level security objective."""
    objective_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    target: str = ""
    scope: list[str] = field(default_factory=list)  # allowed targets
    excluded: list[str] = field(default_factory=list)  # excluded targets
    scan_types: list[str] = field(default_factory=list)  # full, web, network, code
    max_severity: str = "critical"  # maximum exploitation severity allowed
    time_budget_s: float = 3600.0
    aggressive: bool = False


@dataclass
class PhaseResult:
    """Result of an assessment phase."""
    phase: AssessmentPhase
    agent_result: AgentResult | None = None
    duration_s: float = 0.0
    findings_count: int = 0
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "duration_s": round(self.duration_s, 2),
            "findings_count": self.findings_count,
            "status": self.status,
        }


@dataclass
class Assessment:
    """A complete security assessment."""
    assessment_id: str = field(default_factory=lambda: f"assess_{uuid.uuid4().hex[:8]}")
    objective: Objective = field(default_factory=Objective)
    current_phase: AssessmentPhase = AssessmentPhase.PLANNING
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    status: str = "running"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.assessment_id,
            "target": self.objective.target,
            "current_phase": self.current_phase.value,
            "phases": {k: v.to_dict() for k, v in self.phase_results.items()},
            "total_findings": len(self.all_findings),
            "attack_chains": len(self.attack_chains),
            "elapsed_s": round((self.end_time or time.time()) - self.start_time, 2),
            "status": self.status,
        }


class Orchestrator:
    """Master orchestrator for security assessments.

    Uses recursive agent spawning to decompose objectives into specialized tasks,
    coordinates the assessment pipeline, and aggregates results.
    """

    def __init__(
        self,
        llm_router: Any = None,
        max_depth: int = 5,
        max_concurrent_agents: int = 10,
    ) -> None:
        self._router = llm_router
        self._spawner = RecursiveSpawner(
            llm_router=llm_router,
            max_depth=max_depth,
            max_concurrent=max_concurrent_agents,
        )
        self._assessments: dict[str, Assessment] = {}
        self._running: dict[str, asyncio.Task[None]] = {}

    async def start_assessment(self, objective: Objective) -> Assessment:
        """Start a new security assessment."""
        assessment = Assessment(objective=objective)
        self._assessments[assessment.assessment_id] = assessment

        logger.info("assessment_started",
                     id=assessment.assessment_id,
                     target=objective.target)

        # Run assessment in background
        task = asyncio.create_task(self._run_assessment(assessment))
        self._running[assessment.assessment_id] = task

        return assessment

    async def _run_assessment(self, assessment: Assessment) -> None:
        """Run the full assessment pipeline."""
        try:
            # Phase 1: Planning
            await self._phase_planning(assessment)

            # Phase 2: Reconnaissance
            await self._phase_recon(assessment)

            # Phase 3: Vulnerability Scanning
            await self._phase_scanning(assessment)

            # Phase 4: Exploitation (if findings warrant it)
            if self._should_exploit(assessment):
                await self._phase_exploitation(assessment)

            # Phase 5: Post-Exploitation (if exploits succeeded)
            if self._has_successful_exploits(assessment):
                await self._phase_post_exploit(assessment)

            # Phase 6: Reporting
            await self._phase_reporting(assessment)

            assessment.current_phase = AssessmentPhase.COMPLETED
            assessment.status = "completed"

        except Exception as e:
            assessment.status = "failed"
            logger.error("assessment_failed", id=assessment.assessment_id, error=str(e))

        finally:
            assessment.end_time = time.time()

    async def _phase_planning(self, assessment: Assessment) -> None:
        """Planning phase — analyze objective and create execution plan."""
        assessment.current_phase = AssessmentPhase.PLANNING
        start = time.time()

        # Use reasoning model to plan the assessment
        plan_task = AgentTask(
            description=f"Plan security assessment for: {assessment.objective.description}",
            task_type="reasoning",
            target=assessment.objective.target,
            parameters={
                "scope": assessment.objective.scope,
                "scan_types": assessment.objective.scan_types,
            },
            priority=TaskPriority.CRITICAL,
            max_depth=2,
        )

        result = await self._spawner.execute_task(plan_task)

        phase_result = PhaseResult(
            phase=AssessmentPhase.PLANNING,
            agent_result=result,
            duration_s=time.time() - start,
            status="completed",
        )
        assessment.phase_results["planning"] = phase_result

        logger.info("phase_completed", phase="planning", duration=phase_result.duration_s)

    async def _phase_recon(self, assessment: Assessment) -> None:
        """Reconnaissance phase — discover attack surface."""
        assessment.current_phase = AssessmentPhase.RECON
        start = time.time()

        recon_task = AgentTask(
            description=f"Reconnaissance: Discover attack surface for {assessment.objective.target}",
            task_type="recon",
            target=assessment.objective.target,
            parameters={"aggressive": assessment.objective.aggressive},
            priority=TaskPriority.HIGH,
            max_depth=3,
            timeout_s=min(assessment.objective.time_budget_s * 0.3, 1200),
        )

        result = await self._spawner.execute_task(recon_task)

        # Collect recon findings
        assessment.all_findings.extend(result.findings)
        for child in result.child_results:
            assessment.all_findings.extend(child.findings)

        phase_result = PhaseResult(
            phase=AssessmentPhase.RECON,
            agent_result=result,
            duration_s=time.time() - start,
            findings_count=result.total_findings(),
            status="completed",
        )
        assessment.phase_results["recon"] = phase_result

        logger.info("phase_completed", phase="recon",
                     findings=phase_result.findings_count,
                     duration=round(phase_result.duration_s, 1))

    async def _phase_scanning(self, assessment: Assessment) -> None:
        """Vulnerability scanning phase."""
        assessment.current_phase = AssessmentPhase.SCANNING
        start = time.time()

        # Create scanning tasks based on recon results
        scan_tasks: list[AgentTask] = []

        # Always run vulnerability scan
        scan_tasks.append(AgentTask(
            description=f"Vulnerability scanning: {assessment.objective.target}",
            task_type="vuln_scan",
            target=assessment.objective.target,
            priority=TaskPriority.HIGH,
            max_depth=3,
            timeout_s=min(assessment.objective.time_budget_s * 0.3, 1800),
        ))

        # Web scan if applicable
        if "web" in assessment.objective.scan_types or not assessment.objective.scan_types:
            scan_tasks.append(AgentTask(
                description=f"Web application scanning: {assessment.objective.target}",
                task_type="web_scan",
                target=assessment.objective.target,
                priority=TaskPriority.HIGH,
                max_depth=3,
                timeout_s=min(assessment.objective.time_budget_s * 0.2, 1200),
            ))

        # Code audit if applicable
        if "code" in assessment.objective.scan_types:
            scan_tasks.append(AgentTask(
                description=f"Code audit: {assessment.objective.target}",
                task_type="code_audit",
                target=assessment.objective.target,
                priority=TaskPriority.MEDIUM,
                max_depth=3,
            ))

        # Execute scanning tasks concurrently
        results = await asyncio.gather(
            *[self._spawner.execute_task(t) for t in scan_tasks],
            return_exceptions=True,
        )

        total_findings = 0
        for result in results:
            if isinstance(result, AgentResult):
                assessment.all_findings.extend(result.findings)
                total_findings += result.total_findings()

        phase_result = PhaseResult(
            phase=AssessmentPhase.SCANNING,
            duration_s=time.time() - start,
            findings_count=total_findings,
            status="completed",
        )
        assessment.phase_results["scanning"] = phase_result

        logger.info("phase_completed", phase="scanning",
                     findings=total_findings,
                     duration=round(phase_result.duration_s, 1))

    async def _phase_exploitation(self, assessment: Assessment) -> None:
        """Exploitation phase — verify and exploit findings."""
        assessment.current_phase = AssessmentPhase.EXPLOITATION
        start = time.time()

        # Get high-severity findings to exploit
        exploitable = [
            f for f in assessment.all_findings
            if f.get("severity") in ("critical", "high")
        ]

        if not exploitable:
            assessment.phase_results["exploitation"] = PhaseResult(
                phase=AssessmentPhase.EXPLOITATION,
                duration_s=0, status="skipped",
            )
            return

        exploit_task = AgentTask(
            description=f"Exploit verification for {len(exploitable)} findings",
            task_type="exploit",
            target=assessment.objective.target,
            parameters={"findings": exploitable[:10]},
            priority=TaskPriority.MEDIUM,
            max_depth=3,
            timeout_s=min(assessment.objective.time_budget_s * 0.2, 1200),
        )

        result = await self._spawner.execute_task(exploit_task)
        assessment.all_findings.extend(result.findings)

        phase_result = PhaseResult(
            phase=AssessmentPhase.EXPLOITATION,
            agent_result=result,
            duration_s=time.time() - start,
            findings_count=result.total_findings(),
            status="completed",
        )
        assessment.phase_results["exploitation"] = phase_result

    async def _phase_post_exploit(self, assessment: Assessment) -> None:
        """Post-exploitation phase — lateral movement, persistence, data access."""
        assessment.current_phase = AssessmentPhase.POST_EXPLOIT
        start = time.time()

        task = AgentTask(
            description="Post-exploitation: enumerate access, check lateral movement",
            task_type="reasoning",
            target=assessment.objective.target,
            parameters={"findings": assessment.all_findings[-20:]},
            priority=TaskPriority.LOW,
            max_depth=2,
        )

        result = await self._spawner.execute_task(task)

        phase_result = PhaseResult(
            phase=AssessmentPhase.POST_EXPLOIT,
            agent_result=result,
            duration_s=time.time() - start,
            findings_count=result.total_findings(),
            status="completed",
        )
        assessment.phase_results["post_exploit"] = phase_result

    async def _phase_reporting(self, assessment: Assessment) -> None:
        """Reporting phase — generate final assessment report."""
        assessment.current_phase = AssessmentPhase.REPORTING
        start = time.time()

        # Deduplicate and sort findings
        assessment.all_findings = self._deduplicate_findings(assessment.all_findings)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        assessment.all_findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "info"), 99)
        )

        # Build attack chains
        assessment.attack_chains = self._build_attack_chains(assessment.all_findings)

        phase_result = PhaseResult(
            phase=AssessmentPhase.REPORTING,
            duration_s=time.time() - start,
            findings_count=len(assessment.all_findings),
            status="completed",
        )
        assessment.phase_results["reporting"] = phase_result

    def _should_exploit(self, assessment: Assessment) -> bool:
        """Determine if exploitation phase should run."""
        return any(
            f.get("severity") in ("critical", "high")
            for f in assessment.all_findings
        )

    def _has_successful_exploits(self, assessment: Assessment) -> bool:
        """Check if any exploits were successful."""
        exploit_result = assessment.phase_results.get("exploitation")
        if not exploit_result or not exploit_result.agent_result:
            return False
        return any(
            f.get("exploited") or f.get("verified")
            for f in exploit_result.agent_result.findings
        )

    def _deduplicate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate findings by title."""
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for f in findings:
            key = f.get("title", "") + f.get("target", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _build_attack_chains(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build attack chains from related findings."""
        chains: list[dict[str, Any]] = []
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]

        # Simple chain building: connect critical and high findings
        for crit in critical:
            chain_findings = [crit]
            for h in high:
                # Link if same target/category
                if (h.get("target") == crit.get("target") or
                        h.get("category") == crit.get("category")):
                    chain_findings.append(h)

            if len(chain_findings) > 1:
                chains.append({
                    "entry_point": crit.get("title", "Unknown"),
                    "steps": [f.get("title", "") for f in chain_findings],
                    "severity": "critical",
                    "impact": f"Chain of {len(chain_findings)} linked vulnerabilities",
                })

        return chains

    # ── Public API ─────────────────────────────────────────

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        assessment = self._assessments.get(assessment_id)
        return assessment.to_dict() if assessment else None

    def list_assessments(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._assessments.values()]

    def get_spawner_stats(self) -> dict[str, Any]:
        return self._spawner.get_stats()

    async def cancel_assessment(self, assessment_id: str) -> bool:
        task = self._running.get(assessment_id)
        if task:
            task.cancel()
            assessment = self._assessments.get(assessment_id)
            if assessment:
                assessment.status = "cancelled"
            return True
        return False
