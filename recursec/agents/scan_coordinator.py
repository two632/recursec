"""Scan coordinator — orchestrates multi-phase security scanning.

Manages the full scanning lifecycle:
1. Pre-scan: Scope analysis, tool selection, strategy planning
2. Discovery: Passive and active reconnaissance
3. Enumeration: Service detection, technology fingerprinting
4. Vulnerability scanning: Multi-tool scanning with dedup
5. Validation: Cross-validate findings
6. Post-scan: Result aggregation, reporting, learning

Coordinates multiple agents and tools for comprehensive
coverage while avoiding redundancy.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ScanPhase(str, Enum):
    PRE_SCAN = "pre_scan"
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    POST_SCAN = "post_scan"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanTask:
    """A task within a scan phase."""
    task_id: str = ""
    phase: ScanPhase = ScanPhase.DISCOVERY
    name: str = ""
    description: str = ""
    tool: str = ""
    agent_role: str = ""
    target: str = ""
    command_args: list[str] = field(default_factory=list)
    status: PhaseStatus = PhaseStatus.PENDING
    priority: int = 5
    dependencies: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "phase": self.phase.value,
            "name": self.name[:100], "tool": self.tool,
            "status": self.status.value, "findings": len(self.findings),
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class PhaseResult:
    """Result of a scan phase."""
    phase: ScanPhase = ScanPhase.DISCOVERY
    status: PhaseStatus = PhaseStatus.PENDING
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_total: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0
    coverage_areas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "tasks": f"{self.tasks_completed}/{self.tasks_total}",
            "findings": len(self.findings),
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class ScanPlan:
    """Complete scan plan."""
    plan_id: str = ""
    target: str = ""
    goal: str = ""
    phases: list[ScanPhase] = field(default_factory=list)
    tasks: dict[str, ScanTask] = field(default_factory=dict)
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    current_phase: ScanPhase = ScanPhase.PRE_SCAN
    total_findings: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id, "target": self.target,
            "phases": [p.value for p in self.phases],
            "current": self.current_phase.value,
            "tasks": len(self.tasks),
            "findings": self.total_findings,
        }


# ── Default Scan Templates ───────────────────────────────────

WEB_SCAN_TEMPLATE: list[dict[str, Any]] = [
    # Discovery
    {"phase": "discovery", "name": "Subdomain enumeration",
     "tool": "subfinder", "agent": "recon", "priority": 9},
    {"phase": "discovery", "name": "HTTP probing",
     "tool": "httpx", "agent": "recon", "priority": 8,
     "deps": ["Subdomain enumeration"]},
    {"phase": "discovery", "name": "Web crawling",
     "tool": "katana", "agent": "recon", "priority": 7},
    # Enumeration
    {"phase": "enumeration", "name": "Technology fingerprinting",
     "tool": "whatweb", "agent": "recon", "priority": 8},
    {"phase": "enumeration", "name": "Directory bruteforce",
     "tool": "gobuster", "agent": "web_scan", "priority": 7},
    {"phase": "enumeration", "name": "Parameter discovery",
     "tool": "ffuf", "agent": "web_scan", "priority": 6},
    # Vulnerability
    {"phase": "vulnerability", "name": "Template-based scanning",
     "tool": "nuclei", "agent": "vuln_scan", "priority": 9},
    {"phase": "vulnerability", "name": "Web vulnerability scan",
     "tool": "nikto", "agent": "vuln_scan", "priority": 7},
    {"phase": "vulnerability", "name": "XSS detection",
     "tool": "dalfox", "agent": "web_scan", "priority": 8},
    {"phase": "vulnerability", "name": "SQL injection testing",
     "tool": "sqlmap", "agent": "exploit", "priority": 8},
    # Validation
    {"phase": "validation", "name": "Cross-validate findings",
     "tool": "custom", "agent": "validator", "priority": 9},
]

NETWORK_SCAN_TEMPLATE: list[dict[str, Any]] = [
    {"phase": "discovery", "name": "Port scan (fast)",
     "tool": "masscan", "agent": "recon", "priority": 9},
    {"phase": "discovery", "name": "Port scan (detailed)",
     "tool": "nmap", "agent": "recon", "priority": 8,
     "deps": ["Port scan (fast)"]},
    {"phase": "enumeration", "name": "Service version detection",
     "tool": "nmap", "agent": "recon", "priority": 8},
    {"phase": "enumeration", "name": "SMB enumeration",
     "tool": "enum4linux", "agent": "network", "priority": 7},
    {"phase": "enumeration", "name": "SSL/TLS testing",
     "tool": "testssl", "agent": "network", "priority": 7},
    {"phase": "vulnerability", "name": "Vulnerability scanning",
     "tool": "nuclei", "agent": "vuln_scan", "priority": 9},
    {"phase": "vulnerability", "name": "NSE script scanning",
     "tool": "nmap", "agent": "vuln_scan", "priority": 7},
    {"phase": "validation", "name": "Cross-validate findings",
     "tool": "custom", "agent": "validator", "priority": 9},
]

CODE_SCAN_TEMPLATE: list[dict[str, Any]] = [
    {"phase": "discovery", "name": "Repository analysis",
     "tool": "custom", "agent": "code_audit", "priority": 9},
    {"phase": "enumeration", "name": "Dependency enumeration",
     "tool": "trivy", "agent": "code_audit", "priority": 8},
    {"phase": "enumeration", "name": "Secret scanning",
     "tool": "gitleaks", "agent": "code_audit", "priority": 9},
    {"phase": "vulnerability", "name": "Static analysis",
     "tool": "semgrep", "agent": "code_audit", "priority": 9},
    {"phase": "vulnerability", "name": "Python security lint",
     "tool": "bandit", "agent": "code_audit", "priority": 7},
    {"phase": "vulnerability", "name": "Dependency vulnerabilities",
     "tool": "trivy", "agent": "code_audit", "priority": 8},
    {"phase": "validation", "name": "Cross-validate findings",
     "tool": "custom", "agent": "validator", "priority": 9},
]


class ScanCoordinator:
    """Orchestrates multi-phase security scanning.

    Plans, coordinates, and tracks scanning across
    multiple phases, tools, and agents.
    """

    def __init__(self) -> None:
        self._plans: dict[str, ScanPlan] = {}
        self._plan_counter = 0
        self._log = logger.bind(component="scan_coordinator")

    def create_plan(
        self,
        target: str,
        target_type: str = "web",
        goal: str = "",
        phases: list[ScanPhase] | None = None,
    ) -> ScanPlan:
        """Create a scan plan for a target."""
        self._plan_counter += 1
        plan_id = f"scan-{self._plan_counter}"

        if not phases:
            phases = [
                ScanPhase.DISCOVERY,
                ScanPhase.ENUMERATION,
                ScanPhase.VULNERABILITY,
                ScanPhase.VALIDATION,
            ]

        plan = ScanPlan(
            plan_id=plan_id,
            target=target,
            goal=goal or f"Security assessment of {target}",
            phases=phases,
        )

        # Select template
        if target_type == "web":
            template = WEB_SCAN_TEMPLATE
        elif target_type == "network":
            template = NETWORK_SCAN_TEMPLATE
        elif target_type == "code":
            template = CODE_SCAN_TEMPLATE
        else:
            template = WEB_SCAN_TEMPLATE

        # Build tasks from template
        task_counter = 0
        name_to_id: dict[str, str] = {}

        for task_data in template:
            task_counter += 1
            task_id = f"{plan_id}-task-{task_counter}"

            try:
                phase = ScanPhase(task_data["phase"])
            except ValueError:
                phase = ScanPhase.DISCOVERY

            # Resolve dependencies
            deps = []
            for dep_name in task_data.get("deps", []):
                if dep_name in name_to_id:
                    deps.append(name_to_id[dep_name])

            task = ScanTask(
                task_id=task_id,
                phase=phase,
                name=task_data.get("name", ""),
                tool=task_data.get("tool", ""),
                agent_role=task_data.get("agent", ""),
                target=target,
                priority=task_data.get("priority", 5),
                dependencies=deps,
            )

            plan.tasks[task_id] = task
            name_to_id[task.name] = task_id

        self._plans[plan_id] = plan
        return plan

    def get_phase_tasks(
        self,
        plan_id: str,
        phase: ScanPhase,
    ) -> list[ScanTask]:
        """Get all tasks for a phase, sorted by priority."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []
        tasks = [t for t in plan.tasks.values() if t.phase == phase]
        tasks.sort(key=lambda t: -t.priority)
        return tasks

    def get_ready_tasks(self, plan_id: str) -> list[ScanTask]:
        """Get tasks ready to execute (deps met, pending)."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        ready = []
        for task in plan.tasks.values():
            if task.status != PhaseStatus.PENDING:
                continue
            if task.phase != plan.current_phase:
                continue
            deps_met = all(
                plan.tasks.get(dep, ScanTask()).status == PhaseStatus.COMPLETED
                for dep in task.dependencies
            )
            if deps_met:
                ready.append(task)

        ready.sort(key=lambda t: -t.priority)
        return ready

    def start_task(self, plan_id: str, task_id: str) -> bool:
        """Mark a task as running."""
        plan = self._plans.get(plan_id)
        if not plan:
            return False
        task = plan.tasks.get(task_id)
        if not task:
            return False
        task.status = PhaseStatus.RUNNING
        task.started_at = time.time()
        return True

    def complete_task(
        self,
        plan_id: str,
        task_id: str,
        findings: list[dict[str, Any]] | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Mark a task as completed."""
        plan = self._plans.get(plan_id)
        if not plan:
            return
        task = plan.tasks.get(task_id)
        if not task:
            return

        task.status = PhaseStatus.COMPLETED
        task.completed_at = time.time()
        task.findings = findings or []
        task.result = result or {}
        plan.total_findings += len(task.findings)

    def fail_task(self, plan_id: str, task_id: str, error: str = "") -> None:
        """Mark a task as failed."""
        plan = self._plans.get(plan_id)
        if not plan:
            return
        task = plan.tasks.get(task_id)
        if not task:
            return
        task.status = PhaseStatus.FAILED
        task.completed_at = time.time()
        task.error = error

    def advance_phase(self, plan_id: str) -> ScanPhase | None:
        """Advance to the next phase if current is complete."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        # Check if current phase is complete
        current_tasks = [t for t in plan.tasks.values() if t.phase == plan.current_phase]
        all_done = all(
            t.status in (PhaseStatus.COMPLETED, PhaseStatus.FAILED, PhaseStatus.SKIPPED)
            for t in current_tasks
        )

        if not all_done:
            return plan.current_phase

        # Record phase result
        completed = sum(1 for t in current_tasks if t.status == PhaseStatus.COMPLETED)
        failed = sum(1 for t in current_tasks if t.status == PhaseStatus.FAILED)
        phase_findings = []
        for t in current_tasks:
            phase_findings.extend(t.findings)

        plan.phase_results[plan.current_phase.value] = PhaseResult(
            phase=plan.current_phase,
            status=PhaseStatus.COMPLETED,
            tasks_completed=completed,
            tasks_failed=failed,
            tasks_total=len(current_tasks),
            findings=phase_findings,
        )

        # Find next phase
        phase_idx = plan.phases.index(plan.current_phase) if plan.current_phase in plan.phases else -1
        if phase_idx + 1 < len(plan.phases):
            plan.current_phase = plan.phases[phase_idx + 1]
            return plan.current_phase

        plan.completed_at = time.time()
        return None

    def get_plan(self, plan_id: str) -> ScanPlan | None:
        return self._plans.get(plan_id)

    def get_all_findings(self, plan_id: str) -> list[dict[str, Any]]:
        """Get all findings across all tasks."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []
        findings = []
        for task in plan.tasks.values():
            findings.extend(task.findings)
        return findings

    def get_progress(self, plan_id: str) -> dict[str, Any]:
        """Get overall scan progress."""
        plan = self._plans.get(plan_id)
        if not plan:
            return {}
        total = len(plan.tasks)
        completed = sum(1 for t in plan.tasks.values() if t.status == PhaseStatus.COMPLETED)
        running = sum(1 for t in plan.tasks.values() if t.status == PhaseStatus.RUNNING)
        failed = sum(1 for t in plan.tasks.values() if t.status == PhaseStatus.FAILED)
        return {
            "plan": plan_id,
            "target": plan.target,
            "phase": plan.current_phase.value,
            "progress": round(completed / max(1, total), 2),
            "tasks": {"total": total, "completed": completed, "running": running, "failed": failed},
            "findings": plan.total_findings,
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "plans": len(self._plans),
            "total_tasks": sum(len(p.tasks) for p in self._plans.values()),
            "total_findings": sum(p.total_findings for p in self._plans.values()),
        }
