"""Workflow engine — state-machine-based assessment execution.

Implements:
1. Workflow definition (phases, transitions)
2. Phase execution with pre/post conditions
3. Adaptive phase ordering
4. Workflow checkpointing and resume
5. Cross-phase data flow
6. Workflow prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PhaseType(str, Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    LATERAL_MOVE = "lateral_move"
    PRIVESC = "privesc"
    DATA_COLLECTION = "data_collection"
    REPORTING = "reporting"
    VALIDATION = "validation"
    CLEANUP = "cleanup"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    PAUSED = "paused"


@dataclass
class PhaseResult:
    """Output from a completed phase."""
    findings: list[dict[str, Any]] = field(default_factory=list)
    targets_discovered: list[str] = field(default_factory=list)
    credentials_found: int = 0
    vulns_found: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": len(self.findings),
            "targets": len(self.targets_discovered),
            "vulns": self.vulns_found,
            "tokens": self.tokens_used,
        }


@dataclass
class WorkflowPhase:
    """A phase in a workflow."""
    phase_id: str = ""
    phase_type: PhaseType = PhaseType.RECON
    name: str = ""
    status: PhaseStatus = PhaseStatus.PENDING
    depends_on: list[str] = field(default_factory=list)
    agent_role: str = ""
    tools_needed: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    result: PhaseResult | None = None
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.started_at == 0:
            return 0.0
        end = self.completed_at if self.completed_at > 0 else time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.phase_id[:10],
            "type": self.phase_type.value[:8],
            "status": self.status.value[:6],
            "deps": len(self.depends_on),
        }


@dataclass
class Workflow:
    """A complete assessment workflow."""
    workflow_id: str = ""
    name: str = ""
    target: str = ""
    phases: list[WorkflowPhase] = field(default_factory=list)
    current_phase_idx: int = -1
    status: PhaseStatus = PhaseStatus.PENDING
    created_at: float = field(default_factory=time.time)
    checkpoint: dict[str, Any] = field(default_factory=dict)

    @property
    def progress(self) -> float:
        if not self.phases:
            return 0.0
        completed = sum(1 for p in self.phases if p.status == PhaseStatus.COMPLETED)
        return completed / len(self.phases)

    @property
    def total_findings(self) -> int:
        return sum(
            len(p.result.findings)
            for p in self.phases
            if p.result
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.workflow_id[:10],
            "name": self.name[:20],
            "target": self.target[:15],
            "progress": f"{self.progress:.0%}",
            "findings": self.total_findings,
        }


# ── Pre-built workflow templates ──────────────────────────────

WORKFLOW_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full_pentest": [
        {"type": "recon", "name": "Passive Recon", "role": "osint", "tools": ["subfinder", "amass", "theHarvester"]},
        {"type": "enumeration", "name": "Active Enumeration", "role": "recon", "tools": ["nmap", "masscan"], "deps": ["phase-1"]},
        {"type": "vuln_scan", "name": "Vulnerability Scanning", "role": "vuln_scan", "tools": ["nuclei", "nikto", "nessus"], "deps": ["phase-2"]},
        {"type": "web_audit", "name": "Web Application Audit", "role": "web_audit", "tools": ["burpsuite", "sqlmap", "ffuf"], "deps": ["phase-2"]},
        {"type": "exploitation", "name": "Exploitation", "role": "exploit", "tools": ["metasploit"], "deps": ["phase-3", "phase-4"]},
        {"type": "post_exploit", "name": "Post-Exploitation", "role": "exploit", "tools": ["mimikatz", "bloodhound"], "deps": ["phase-5"]},
        {"type": "lateral_move", "name": "Lateral Movement", "role": "network", "tools": ["crackmapexec"], "deps": ["phase-6"]},
        {"type": "privesc", "name": "Privilege Escalation", "role": "exploit", "tools": ["linpeas", "winpeas"], "deps": ["phase-5"]},
        {"type": "validation", "name": "Finding Validation", "role": "validator", "deps": ["phase-5", "phase-7", "phase-8"]},
        {"type": "reporting", "name": "Report Generation", "role": "reporter", "deps": ["phase-9"]},
    ],
    "web_pentest": [
        {"type": "recon", "name": "Web Recon", "role": "recon", "tools": ["subfinder", "httpx"]},
        {"type": "enumeration", "name": "Content Discovery", "role": "web_audit", "tools": ["ffuf", "gobuster"], "deps": ["phase-1"]},
        {"type": "vuln_scan", "name": "Web Vuln Scan", "role": "vuln_scan", "tools": ["nuclei", "nikto"], "deps": ["phase-1"]},
        {"type": "web_audit", "name": "Manual Testing", "role": "web_audit", "tools": ["burpsuite", "sqlmap", "xsstrike"], "deps": ["phase-2", "phase-3"]},
        {"type": "exploitation", "name": "Web Exploitation", "role": "exploit", "deps": ["phase-4"]},
        {"type": "validation", "name": "Validation", "role": "validator", "deps": ["phase-5"]},
        {"type": "reporting", "name": "Report", "role": "reporter", "deps": ["phase-6"]},
    ],
    "internal_pentest": [
        {"type": "recon", "name": "Network Discovery", "role": "recon", "tools": ["nmap", "arp-scan"]},
        {"type": "enumeration", "name": "Service Enumeration", "role": "recon", "tools": ["nmap"], "deps": ["phase-1"]},
        {"type": "vuln_scan", "name": "Vulnerability Assessment", "role": "vuln_scan", "tools": ["nuclei", "nessus"], "deps": ["phase-2"]},
        {"type": "exploitation", "name": "Initial Access", "role": "exploit", "deps": ["phase-3"]},
        {"type": "privesc", "name": "Privilege Escalation", "role": "exploit", "tools": ["linpeas", "winpeas"], "deps": ["phase-4"]},
        {"type": "lateral_move", "name": "Lateral Movement", "role": "network", "tools": ["crackmapexec", "bloodhound"], "deps": ["phase-5"]},
        {"type": "post_exploit", "name": "Domain Dominance", "role": "exploit", "tools": ["mimikatz"], "deps": ["phase-6"]},
        {"type": "validation", "name": "Validation", "role": "validator", "deps": ["phase-4", "phase-5", "phase-6", "phase-7"]},
        {"type": "reporting", "name": "Report", "role": "reporter", "deps": ["phase-8"]},
    ],
}


class WorkflowEngine:
    """State-machine-based assessment workflow execution.

    Manages workflow phases, dependencies, data flow,
    and checkpointing for security assessments.
    """

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._workflow_counter = 0
        self._log = logger.bind(component="workflow")

    def create_workflow(
        self,
        name: str = "",
        target: str = "",
        template: str = "full_pentest",
    ) -> Workflow:
        """Create a workflow from template."""
        self._workflow_counter += 1
        wf_id = f"wf-{self._workflow_counter}"

        phases_data = WORKFLOW_TEMPLATES.get(template, [])
        phases: list[WorkflowPhase] = []

        for i, spec in enumerate(phases_data):
            phase = WorkflowPhase(
                phase_id=f"phase-{i + 1}",
                phase_type=PhaseType(spec["type"]),
                name=spec.get("name", spec["type"]),
                agent_role=spec.get("role", ""),
                tools_needed=spec.get("tools", []),
                depends_on=spec.get("deps", []),
            )
            phases.append(phase)

        workflow = Workflow(
            workflow_id=wf_id,
            name=name or template,
            target=target,
            phases=phases,
        )

        self._workflows[wf_id] = workflow
        return workflow

    def get_ready_phases(self, workflow_id: str) -> list[WorkflowPhase]:
        """Get phases whose dependencies are met."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return []

        ready = []
        completed_ids = {p.phase_id for p in wf.phases if p.status == PhaseStatus.COMPLETED}

        for phase in wf.phases:
            if phase.status != PhaseStatus.PENDING:
                continue
            deps_met = all(d in completed_ids for d in phase.depends_on)
            if deps_met:
                ready.append(phase)

        return ready

    def start_phase(self, workflow_id: str, phase_id: str) -> bool:
        """Mark a phase as started."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return False

        for phase in wf.phases:
            if phase.phase_id == phase_id:
                phase.status = PhaseStatus.RUNNING
                phase.started_at = time.time()
                return True
        return False

    def complete_phase(
        self,
        workflow_id: str,
        phase_id: str,
        result: PhaseResult | None = None,
        status: PhaseStatus = PhaseStatus.COMPLETED,
    ) -> list[WorkflowPhase]:
        """Complete a phase and return newly ready phases."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return []

        for phase in wf.phases:
            if phase.phase_id == phase_id:
                phase.status = status
                phase.completed_at = time.time()
                phase.result = result
                break

        # Check if workflow is complete
        all_done = all(
            p.status in (PhaseStatus.COMPLETED, PhaseStatus.SKIPPED, PhaseStatus.FAILED)
            for p in wf.phases
        )
        if all_done:
            wf.status = PhaseStatus.COMPLETED

        return self.get_ready_phases(workflow_id)

    def checkpoint(self, workflow_id: str) -> dict[str, Any]:
        """Create a checkpoint for resume."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return {}

        return {
            "workflow_id": wf.workflow_id,
            "progress": wf.progress,
            "phases": [
                {
                    "id": p.phase_id,
                    "status": p.status.value,
                    "findings": len(p.result.findings) if p.result else 0,
                }
                for p in wf.phases
            ],
        }

    def build_workflow_prompt(self, workflow_id: str = "") -> str:
        """Build workflow context for LLM."""
        if workflow_id and workflow_id in self._workflows:
            wf = self._workflows[workflow_id]
            return self._format_workflow(wf)

        lines = ["## Workflows\n"]
        lines.append(f"Total: {len(self._workflows)}")
        for wf in self._workflows.values():
            lines.append(f"  {wf.name[:15]} → {wf.progress:.0%}")
        return "\n".join(lines)

    def _format_workflow(self, wf: Workflow) -> str:
        """Format workflow for LLM."""
        lines = [f"## Workflow: {wf.name}\n"]
        lines.append(f"Target: {wf.target}")
        lines.append(f"Progress: {wf.progress:.0%} | Findings: {wf.total_findings}")

        for phase in wf.phases:
            icon = {
                PhaseStatus.COMPLETED: "[done]",
                PhaseStatus.RUNNING: "[>>>]",
                PhaseStatus.PENDING: "[   ]",
                PhaseStatus.FAILED: "[ERR]",
                PhaseStatus.SKIPPED: "[skip]",
            }.get(phase.status, "[?]")

            findings = ""
            if phase.result:
                findings = f" (f={len(phase.result.findings)})"

            lines.append(f"  {icon} {phase.name}{findings}")

        ready = self.get_ready_phases(wf.workflow_id)
        if ready:
            lines.append(f"\nReady: {', '.join(p.name for p in ready)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_findings = 0
        for wf in self._workflows.values():
            total_findings += wf.total_findings

        return {
            "workflows": len(self._workflows),
            "total_findings": total_findings,
            "templates": list(WORKFLOW_TEMPLATES.keys()),
        }
