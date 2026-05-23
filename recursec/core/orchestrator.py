"""Advanced Orchestrator — the decision brain that decomposes, delegates, and assembles.

This is the top-level intelligence layer. It takes high-level objectives like
"pentest 192.168.1.0/24" and recursively decomposes them into specialized sub-tasks,
routes them to the right agents, manages dependencies, handles failures, and
assembles results into coherent attack chains and reports.

Key capabilities:
- Task decomposition with dependency graphs
- Parallel execution of independent sub-tasks
- Dynamic re-planning based on intermediate results
- Adaptive strategy selection based on target type
- Budget and resource management (tokens, time, depth)
- Finding correlation across agents
- Automatic exploitation chain assembly
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from recursec.core.models import (
    AgentRole,
    AgentTask,
    Severity,
    Target,
    TaskStatus,
    Vulnerability,
)
from recursec.core.reasoning import ReasoningEngine, ReasoningStrategy

if TYPE_CHECKING:
    from recursec.core.attack_chain import AttackChainBuilder
    from recursec.llm.router import ModelRouter
    from recursec.memory.embeddings import VectorMemory
    from recursec.memory.store import MemoryStore
    from recursec.tools.registry import ToolRegistry

logger = structlog.get_logger()


class TaskPhase(str, Enum):
    """Phases of a security assessment."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    REPORTING = "reporting"


class OrchestratorMode(str, Enum):
    """How the orchestrator should operate."""
    FULL_AUTO = "full_auto"           # Fully autonomous, all phases
    GUIDED = "guided"                 # User approves each phase
    RECON_ONLY = "recon_only"         # Only reconnaissance
    VULN_ONLY = "vuln_only"           # Only vulnerability scanning
    EXPLOIT_ONLY = "exploit_only"     # Only exploitation (requires prior findings)
    PASSIVE = "passive"               # No active scanning, OSINT only
    TARGETED = "targeted"             # Focus on specific vulnerability types


@dataclass
class TaskNode:
    """A node in the task dependency graph."""
    task: AgentTask
    depends_on: list[str] = field(default_factory=list)  # task IDs
    blocks: list[str] = field(default_factory=list)       # task IDs that depend on this
    phase: TaskPhase = TaskPhase.RECONNAISSANCE
    priority: int = 5
    estimated_time_s: float = 60.0
    actual_time_s: float = 0.0
    retry_count: int = 0
    max_retries: int = 3

    @property
    def is_ready(self) -> bool:
        return len(self.depends_on) == 0

    @property
    def is_complete(self) -> bool:
        return self.task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED)


@dataclass
class TaskGraph:
    """Directed acyclic graph of tasks with dependency management."""
    nodes: dict[str, TaskNode] = field(default_factory=dict)
    execution_order: list[str] = field(default_factory=list)

    def add_task(self, node: TaskNode) -> None:
        self.nodes[node.task.id] = node

    def add_dependency(self, task_id: str, depends_on_id: str) -> None:
        if task_id in self.nodes and depends_on_id in self.nodes:
            self.nodes[task_id].depends_on.append(depends_on_id)
            self.nodes[depends_on_id].blocks.append(task_id)

    def get_ready_tasks(self) -> list[TaskNode]:
        """Get all tasks that have no unfinished dependencies."""
        ready = []
        for node in self.nodes.values():
            if node.is_complete or node.task.status == TaskStatus.RUNNING:
                continue
            # Check if all dependencies are complete
            deps_met = all(
                self.nodes[dep_id].is_complete
                for dep_id in node.depends_on
                if dep_id in self.nodes
            )
            if deps_met:
                ready.append(node)
        return sorted(ready, key=lambda n: n.priority)

    def mark_complete(self, task_id: str) -> list[str]:
        """Mark a task complete and return IDs of newly unblocked tasks."""
        if task_id not in self.nodes:
            return []
        node = self.nodes[task_id]
        unblocked = []
        for blocked_id in node.blocks:
            blocked_node = self.nodes.get(blocked_id)
            if blocked_node:
                # Remove this dependency
                if task_id in blocked_node.depends_on:
                    blocked_node.depends_on.remove(task_id)
                if blocked_node.is_ready:
                    unblocked.append(blocked_id)
        return unblocked

    def get_stats(self) -> dict[str, Any]:
        total = len(self.nodes)
        completed = sum(1 for n in self.nodes.values() if n.task.status == TaskStatus.COMPLETED)
        failed = sum(1 for n in self.nodes.values() if n.task.status == TaskStatus.FAILED)
        running = sum(1 for n in self.nodes.values() if n.task.status == TaskStatus.RUNNING)
        pending = total - completed - failed - running
        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "pending": pending,
            "progress": round(completed / max(total, 1) * 100, 1),
        }


@dataclass
class OrchestratorConfig:
    """Configuration for the orchestrator."""
    mode: OrchestratorMode = OrchestratorMode.FULL_AUTO
    max_parallel_agents: int = 5
    max_total_tasks: int = 100
    max_depth: int = 5
    timeout_per_task_s: float = 300.0
    timeout_total_s: float = 3600.0
    token_budget: int = 500000
    auto_exploit: bool = True
    auto_report: bool = True
    min_finding_confidence: float = 0.5
    replan_on_failure: bool = True
    phases: list[TaskPhase] = field(default_factory=lambda: list(TaskPhase))
    target_vuln_types: list[str] = field(default_factory=list)  # For targeted mode


# ── Target Analysis Templates ──────────────────────────────

DECOMPOSE_TEMPLATE = """You are RecurSec's orchestration brain. Given a security assessment objective,
decompose it into specific sub-tasks for specialized agents.

OBJECTIVE: {objective}
TARGET: {target_type} — {target_value}
MODE: {mode}
ALLOWED PHASES: {phases}

AVAILABLE AGENT ROLES:
- recon: Network/host discovery, port scanning, service enumeration
- vuln_scanner: Vulnerability scanning with nuclei, nmap scripts, nikto
- web_scanner: Web application testing (SQLi, XSS, SSRF, SSTI, LFI, auth bypass)
- exploit: Exploit development and execution
- post_exploit: Post-exploitation, privilege escalation, persistence
- code_auditor: Source code review (SAST), dependency auditing
- network_scanner: Deep network analysis, MITM detection, protocol analysis
- osint: Open-source intelligence, subdomain enum, email harvesting
- fuzzer: Fuzzing APIs, protocols, file formats
- crypto_analyst: Cryptographic weakness analysis
- cloud_scanner: Cloud misconfiguration (AWS, Azure, GCP)
- forensics: Digital forensics, log analysis, artifact collection

CONTEXT FROM PREVIOUS FINDINGS:
{context}

Generate a task decomposition as JSON:
{{
  "analysis": "Brief analysis of the target and approach",
  "tasks": [
    {{
      "role": "agent_role",
      "objective": "specific task description",
      "depends_on": [],
      "phase": "reconnaissance|enumeration|vulnerability_analysis|exploitation|post_exploitation|reporting",
      "priority": 1-10,
      "estimated_time_s": 60
    }}
  ],
  "reasoning": "Why this decomposition"
}}"""

REPLAN_TEMPLATE = """Based on intermediate results, adjust the plan.

ORIGINAL OBJECTIVE: {objective}
TARGET: {target_value}

COMPLETED TASKS:
{completed}

CURRENT FINDINGS:
{findings}

FAILED TASKS:
{failed}

Should we:
1. Add new tasks based on findings?
2. Adjust priorities?
3. Skip certain phases?
4. Focus on specific findings for exploitation?

Generate additional tasks or modifications as JSON:
{{
  "analysis": "What the findings tell us",
  "new_tasks": [...],
  "skip_tasks": [],
  "priority_changes": {{}}
}}"""

FINDING_CORRELATION_TEMPLATE = """Analyze these findings from multiple agents and identify attack chains.

FINDINGS:
{findings}

For each potential attack chain:
1. What is the entry point?
2. What vulnerabilities can be chained?
3. What is the maximum impact?
4. What is the confidence level?

Format as JSON:
{{
  "chains": [
    {{
      "name": "chain description",
      "steps": ["step1", "step2"],
      "entry_point": "...",
      "impact": "critical|high|medium|low",
      "confidence": 0.0-1.0
    }}
  ],
  "recommended_exploits": ["..."]
}}"""


class Orchestrator:
    """The master orchestration engine.

    This is the highest-level intelligence in RecurSec. It:
    1. Receives high-level objectives
    2. Analyzes the target to determine the best approach
    3. Decomposes into a DAG of specialized agent tasks
    4. Executes tasks in dependency order with parallel execution
    5. Re-plans based on intermediate findings
    6. Correlates findings across agents into attack chains
    7. Manages budgets (tokens, time, depth)
    8. Produces final reports
    """

    def __init__(
        self,
        model_router: ModelRouter,
        tool_registry: ToolRegistry,
        memory: MemoryStore,
        reasoning_engine: ReasoningEngine | None = None,
        chain_builder: AttackChainBuilder | None = None,
        vector_memory: VectorMemory | None = None,
        config: OrchestratorConfig | None = None,
    ):
        self.router = model_router
        self.tools = tool_registry
        self.memory = memory
        self.reasoning = reasoning_engine or ReasoningEngine(model_router)
        self.chain_builder = chain_builder
        self.vector_memory = vector_memory
        self.config = config or OrchestratorConfig()
        self._task_graph = TaskGraph()
        self._all_findings: list[Vulnerability] = []
        self._tokens_used = 0
        self._start_time = 0.0
        self._completed_tasks: list[AgentTask] = []
        self._failed_tasks: list[AgentTask] = []

    async def execute_objective(
        self,
        objective: str,
        target: Target,
    ) -> dict[str, Any]:
        """Main entry point — execute a high-level security objective."""
        self._start_time = time.monotonic()
        self._task_graph = TaskGraph()
        self._all_findings = []
        self._completed_tasks = []
        self._failed_tasks = []

        logger.info("orchestrator_start", objective=objective[:100], target=target.value)

        # Phase 1: Analyze and decompose
        task_graph = await self._decompose_objective(objective, target)

        # Phase 2: Execute task graph
        await self._execute_graph(task_graph, target)

        # Phase 3: Correlate findings
        correlation = await self._correlate_findings()

        # Phase 4: Re-plan if needed
        if self.config.replan_on_failure and self._failed_tasks:
            new_tasks = await self._replan(objective, target)
            if new_tasks:
                await self._execute_graph(self._task_graph, target)

        # Phase 5: Build attack chains
        chains = self._build_attack_chains()

        # Phase 6: Generate report
        report = await self._generate_report(objective, target)

        elapsed = time.monotonic() - self._start_time
        logger.info(
            "orchestrator_complete",
            objective=objective[:80],
            tasks_total=len(self._task_graph.nodes),
            tasks_completed=len(self._completed_tasks),
            tasks_failed=len(self._failed_tasks),
            findings=len(self._all_findings),
            chains=len(chains),
            elapsed_s=round(elapsed, 1),
        )

        return {
            "objective": objective,
            "target": target.model_dump(),
            "stats": self._task_graph.get_stats(),
            "findings": [f.model_dump() for f in self._all_findings],
            "attack_chains": chains,
            "correlation": correlation,
            "report": report,
            "elapsed_s": round(elapsed, 1),
        }

    async def _decompose_objective(
        self, objective: str, target: Target
    ) -> TaskGraph:
        """Use LLM to decompose the objective into a task dependency graph."""
        # Get context from vector memory
        context = ""
        if self.vector_memory:
            similar = await self.vector_memory.search_similar_findings(objective)
            if similar:
                context = "Previous similar findings:\n"
                for s in similar[:5]:
                    context += f"  - {s.get('text', '')[:200]}\n"

        # Use reasoning engine for decomposition
        prompt = DECOMPOSE_TEMPLATE.format(
            objective=objective,
            target_type=target.target_type,
            target_value=target.value,
            mode=self.config.mode.value,
            phases=", ".join(p.value for p in self.config.phases),
            context=context or "None (first scan)",
        )

        trace = await self.reasoning.reason(
            question=prompt,
            strategy=ReasoningStrategy.PLAN_AND_SOLVE,
            task_type="reasoning",
        )

        # Parse the decomposition
        tasks = self._parse_decomposition(trace.final_answer, target)

        # Build dependency graph
        graph = TaskGraph()
        for task_node in tasks:
            graph.add_task(task_node)

        # Wire up dependencies
        for node in tasks:
            for dep_desc in node.depends_on:
                # Find the task that matches the dependency description
                for other in tasks:
                    if other.task.id != node.task.id and dep_desc in other.task.objective.lower():
                        graph.add_dependency(node.task.id, other.task.id)

        self._task_graph = graph
        logger.info("decomposition_complete", total_tasks=len(graph.nodes))
        return graph

    def _parse_decomposition(
        self, response: str, target: Target
    ) -> list[TaskNode]:
        """Parse LLM decomposition into task nodes."""
        import json

        nodes: list[TaskNode] = []

        # Try to parse JSON
        try:
            # Find JSON in response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(response[start:end])
                tasks = data.get("tasks", [])
                for t in tasks:
                    role_str = t.get("role", "recon")
                    try:
                        role = AgentRole(role_str)
                    except ValueError:
                        role = AgentRole.RECON

                    agent_task = AgentTask(
                        agent_role=role,
                        objective=t.get("objective", ""),
                        target=target,
                        priority=t.get("priority", 5),
                        max_depth=self.config.max_depth,
                    )

                    phase_str = t.get("phase", "reconnaissance")
                    try:
                        phase = TaskPhase(phase_str)
                    except ValueError:
                        phase = TaskPhase.RECONNAISSANCE

                    node = TaskNode(
                        task=agent_task,
                        depends_on=t.get("depends_on", []),
                        phase=phase,
                        priority=t.get("priority", 5),
                        estimated_time_s=t.get("estimated_time_s", 60),
                    )
                    nodes.append(node)
        except json.JSONDecodeError:
            pass

        # If parsing fails, create default tasks based on mode
        if not nodes:
            nodes = self._default_decomposition(target)

        return nodes

    def _default_decomposition(self, target: Target) -> list[TaskNode]:
        """Fallback decomposition when LLM parsing fails."""
        nodes: list[TaskNode] = []

        if target.target_type in ("host", "network_range"):
            # Network target → standard pentest flow
            phases = [
                (AgentRole.RECON, "Discover live hosts and open ports", TaskPhase.RECONNAISSANCE, 1),
                (AgentRole.NETWORK_SCANNER, "Deep service enumeration and protocol analysis", TaskPhase.ENUMERATION, 2),
                (AgentRole.VULN_SCANNER, "Scan for known vulnerabilities", TaskPhase.VULNERABILITY_ANALYSIS, 3),
                (AgentRole.OSINT, "Gather OSINT on target services", TaskPhase.RECONNAISSANCE, 2),
            ]
            if self.config.auto_exploit:
                phases.append(
                    (AgentRole.EXPLOIT, "Attempt exploitation of discovered vulnerabilities", TaskPhase.EXPLOITATION, 4)
                )

        elif target.target_type == "url":
            # Web target → web app testing
            phases = [
                (AgentRole.RECON, "Discover subdomains, technologies, and endpoints", TaskPhase.RECONNAISSANCE, 1),
                (AgentRole.WEB_SCANNER, "Test for web vulnerabilities (SQLi, XSS, SSRF, etc.)", TaskPhase.VULNERABILITY_ANALYSIS, 2),
                (AgentRole.FUZZER, "Fuzz API endpoints and parameters", TaskPhase.VULNERABILITY_ANALYSIS, 3),
                (AgentRole.VULN_SCANNER, "Run vulnerability scanners against web app", TaskPhase.VULNERABILITY_ANALYSIS, 2),
            ]

        elif target.target_type == "code_repo":
            # Code → static analysis
            phases = [
                (AgentRole.CODE_AUDITOR, "Static code analysis for security vulnerabilities", TaskPhase.VULNERABILITY_ANALYSIS, 1),
                (AgentRole.CODE_AUDITOR, "Dependency audit for known CVEs", TaskPhase.VULNERABILITY_ANALYSIS, 1),
                (AgentRole.CRYPTO_ANALYST, "Review cryptographic implementations", TaskPhase.VULNERABILITY_ANALYSIS, 2),
            ]

        elif target.target_type == "api":
            # API → API-specific testing
            phases = [
                (AgentRole.RECON, "Discover API endpoints and documentation", TaskPhase.RECONNAISSANCE, 1),
                (AgentRole.WEB_SCANNER, "Test API for injection and auth bypass", TaskPhase.VULNERABILITY_ANALYSIS, 2),
                (AgentRole.FUZZER, "Fuzz API endpoints with mutations", TaskPhase.VULNERABILITY_ANALYSIS, 2),
            ]

        else:
            phases = [
                (AgentRole.RECON, f"Reconnaissance on {target.value}", TaskPhase.RECONNAISSANCE, 1),
                (AgentRole.VULN_SCANNER, f"Vulnerability scan on {target.value}", TaskPhase.VULNERABILITY_ANALYSIS, 2),
            ]

        for role, obj, phase, priority in phases:
            task = AgentTask(
                agent_role=role,
                objective=obj,
                target=target,
                priority=priority,
                max_depth=self.config.max_depth,
            )
            node = TaskNode(task=task, phase=phase, priority=priority)
            nodes.append(node)

        return nodes

    async def _execute_graph(self, graph: TaskGraph, target: Target) -> None:
        """Execute the task graph respecting dependencies and parallelism."""
        sem = asyncio.Semaphore(self.config.max_parallel_agents)
        running_tasks: dict[str, asyncio.Task[AgentTask]] = {}

        while True:
            # Check budget
            elapsed = time.monotonic() - self._start_time
            if elapsed > self.config.timeout_total_s:
                logger.warning("orchestrator_timeout", elapsed_s=round(elapsed, 1))
                break
            if len(self._completed_tasks) + len(self._failed_tasks) >= self.config.max_total_tasks:
                logger.warning("orchestrator_max_tasks_reached")
                break

            # Get ready tasks
            ready = graph.get_ready_tasks()

            # Launch ready tasks
            for node in ready:
                if node.task.id in running_tasks:
                    continue
                if node.task.status != TaskStatus.PENDING:
                    continue

                node.task.status = TaskStatus.RUNNING
                task_coro = self._run_agent_task(node, sem)
                running_tasks[node.task.id] = asyncio.create_task(task_coro)

            if not running_tasks:
                # Check if all tasks are done
                stats = graph.get_stats()
                if stats["pending"] == 0:
                    break
                # Deadlock detection
                if stats["running"] == 0 and stats["pending"] > 0:
                    logger.error("orchestrator_deadlock", stats=stats)
                    break

            # Wait for at least one task to complete
            if running_tasks:
                done, _ = await asyncio.wait(
                    running_tasks.values(),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for completed_task in done:
                    result = completed_task.result()
                    if isinstance(result, AgentTask):
                        # Find and remove from running
                        for tid, atask in list(running_tasks.items()):
                            if atask is completed_task:
                                del running_tasks[tid]
                                # Mark complete in graph
                                graph.mark_complete(tid)
                                break

    async def _run_agent_task(self, node: TaskNode, sem: asyncio.Semaphore) -> AgentTask:
        """Run a single agent task with timeout and error handling."""
        from recursec.agents.factory import AgentFactory

        async with sem:
            start = time.monotonic()
            task = node.task

            logger.info(
                "agent_task_starting",
                task_id=task.id,
                role=task.agent_role.value,
                objective=task.objective[:80],
            )

            try:
                agent = AgentFactory.create(
                    role=task.agent_role,
                    model_router=self.router,
                    tool_registry=self.tools,
                    memory=self.memory,
                )

                result = await asyncio.wait_for(
                    agent.run(task),
                    timeout=self.config.timeout_per_task_s,
                )

                node.actual_time_s = time.monotonic() - start

                # Collect findings
                if result.findings:
                    self._all_findings.extend(result.findings)
                    # Store in vector memory
                    if self.vector_memory:
                        for f in result.findings:
                            await self.vector_memory.add_finding(f.model_dump())
                    # Add to chain builder
                    if self.chain_builder:
                        for f in result.findings:
                            self.chain_builder.add_finding(f, agent_role=task.agent_role.value)

                self._completed_tasks.append(result)

                logger.info(
                    "agent_task_complete",
                    task_id=task.id,
                    status=result.status.value,
                    findings=len(result.findings),
                    time_s=round(node.actual_time_s, 1),
                )
                return result

            except asyncio.TimeoutError:
                task.status = TaskStatus.FAILED
                task.error = f"Timeout after {self.config.timeout_per_task_s}s"
                self._failed_tasks.append(task)
                logger.error("agent_task_timeout", task_id=task.id)
                return task

            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                self._failed_tasks.append(task)
                logger.error("agent_task_error", task_id=task.id, error=str(e))

                # Retry logic
                if node.retry_count < node.max_retries:
                    node.retry_count += 1
                    task.status = TaskStatus.PENDING
                    logger.info("agent_task_retry", task_id=task.id, retry=node.retry_count)

                return task

    async def _correlate_findings(self) -> dict[str, Any]:
        """Use LLM to correlate findings from multiple agents."""
        if not self._all_findings:
            return {"chains": [], "recommended_exploits": []}

        findings_text = ""
        for f in self._all_findings[:30]:
            findings_text += (
                f"- [{f.severity.value}] {f.title}: {f.description[:150]} "
                f"(component: {f.affected_component}, confidence: {f.confidence})\n"
            )

        prompt = FINDING_CORRELATION_TEMPLATE.format(findings=findings_text)

        trace = await self.reasoning.reason(
            question=prompt,
            strategy=ReasoningStrategy.CHAIN_OF_THOUGHT,
            task_type="security",
        )

        # Parse correlation
        import json
        try:
            start = trace.final_answer.find("{")
            end = trace.final_answer.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(trace.final_answer[start:end])
        except json.JSONDecodeError:
            pass

        return {"chains": [], "analysis": trace.final_answer[:1000]}

    async def _replan(self, objective: str, target: Target) -> list[TaskNode]:
        """Re-plan based on completed/failed tasks and findings."""
        completed_text = ""
        for t in self._completed_tasks[-10:]:
            completed_text += f"- [{t.agent_role.value}] {t.objective[:100]}: {t.status.value}, {len(t.findings)} findings\n"

        findings_text = ""
        for f in self._all_findings[-15:]:
            findings_text += f"- [{f.severity.value}] {f.title}\n"

        failed_text = ""
        for t in self._failed_tasks[-5:]:
            failed_text += f"- [{t.agent_role.value}] {t.objective[:100]}: {t.error}\n"

        prompt = REPLAN_TEMPLATE.format(
            objective=objective,
            target_value=target.value,
            completed=completed_text or "None",
            findings=findings_text or "None",
            failed=failed_text or "None",
        )

        response = await self.router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=2048,
        )

        new_nodes = self._parse_decomposition(response, target)
        for node in new_nodes:
            self._task_graph.add_task(node)

        logger.info("replan_complete", new_tasks=len(new_nodes))
        return new_nodes

    def _build_attack_chains(self) -> list[dict[str, Any]]:
        """Build attack chains from all findings."""
        if self.chain_builder:
            chains = self.chain_builder.build_chains()
            return [c.model_dump() for c in chains]
        return []

    async def _generate_report(self, objective: str, target: Target) -> dict[str, Any]:
        """Generate a summary report."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._all_findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        return {
            "objective": objective,
            "target": target.value,
            "summary": {
                "total_findings": len(self._all_findings),
                "severity_counts": severity_counts,
                "tasks_executed": len(self._completed_tasks),
                "tasks_failed": len(self._failed_tasks),
                "elapsed_s": round(time.monotonic() - self._start_time, 1),
            },
            "critical_findings": [
                f.model_dump() for f in self._all_findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ][:20],
        }

    def get_status(self) -> dict[str, Any]:
        return {
            "graph": self._task_graph.get_stats(),
            "findings": len(self._all_findings),
            "elapsed_s": round(time.monotonic() - self._start_time, 1) if self._start_time else 0,
            "completed_tasks": len(self._completed_tasks),
            "failed_tasks": len(self._failed_tasks),
        }
