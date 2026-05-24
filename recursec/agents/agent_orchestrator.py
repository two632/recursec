"""Agent orchestrator — top-level coordinator.

Wires together all agent subsystems:
1. Task reception and decomposition
2. Agent spawning with role assignment
3. Knowledge injection via dynamic selector
4. Model routing per task type
5. Communication bus coordination
6. Result aggregation and reporting
7. Budget tracking and convergence
8. Orchestrator prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OrchestratorState(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    AGGREGATING = "aggregating"
    REPORTING = "reporting"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class AssessmentType(str, Enum):
    FULL = "full"                  # Full security assessment
    WEB = "web"                    # Web application
    NETWORK = "network"            # Network infrastructure
    CLOUD = "cloud"                # Cloud environment
    MOBILE = "mobile"              # Mobile application
    CODE = "code"                  # Source code review
    RED_TEAM = "red_team"          # Red team engagement
    COMPLIANCE = "compliance"      # Compliance check
    INCIDENT = "incident"          # Incident response
    RECON = "recon"                # Reconnaissance only


@dataclass
class AssessmentTask:
    """A top-level assessment task."""
    task_id: str = ""
    target: str = ""
    assessment_type: AssessmentType = AssessmentType.FULL
    scope: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    max_depth: int = 4
    token_budget: int = 500000
    time_limit_s: float = 3600.0
    system_prompt: str = ""
    custom_config: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "target": self.target[:20],
            "type": self.assessment_type.value[:8],
            "depth": self.max_depth,
            "budget": self.token_budget,
        }


@dataclass
class AssessmentPhase:
    """A phase in the assessment."""
    phase_id: str = ""
    name: str = ""
    description: str = ""
    agent_roles: list[str] = field(default_factory=list)
    knowledge_domains: list[str] = field(default_factory=list)
    tools_needed: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    status: str = "pending"
    findings_count: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.phase_id[:8],
            "name": self.name[:15],
            "status": self.status[:6],
            "findings": self.findings_count,
        }


# ── Assessment phase templates ───────────────────────────────

PHASE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "full": [
        {
            "name": "Passive Recon",
            "desc": "OSINT, DNS, certificate transparency, WHOIS",
            "roles": ["recon"],
            "knowledge": ["network", "threat_intel"],
            "tools": ["amass", "subfinder", "theHarvester", "whois", "dig"],
            "depends": [],
        },
        {
            "name": "Active Recon",
            "desc": "Port scanning, service enumeration, web crawling",
            "roles": ["recon"],
            "knowledge": ["network", "web_security"],
            "tools": ["nmap", "masscan", "httpx", "whatweb"],
            "depends": ["Passive Recon"],
        },
        {
            "name": "Vulnerability Scanning",
            "desc": "Automated vulnerability scanning across discovered services",
            "roles": ["vuln_scan"],
            "knowledge": ["web_security", "exploitation", "detection"],
            "tools": ["nuclei", "nikto", "wpscan", "testssl"],
            "depends": ["Active Recon"],
        },
        {
            "name": "Web Application Testing",
            "desc": "Deep web application security testing",
            "roles": ["web_audit"],
            "knowledge": ["web_security", "exploitation", "advanced_strategy"],
            "tools": ["sqlmap", "ffuf", "burp", "zap"],
            "depends": ["Active Recon"],
        },
        {
            "name": "Exploitation",
            "desc": "Validate and exploit confirmed vulnerabilities",
            "roles": ["exploit", "validator"],
            "knowledge": ["exploitation", "red_team", "zeroday"],
            "tools": ["metasploit", "sqlmap", "hydra"],
            "depends": ["Vulnerability Scanning", "Web Application Testing"],
        },
        {
            "name": "Post-Exploitation",
            "desc": "Lateral movement, privilege escalation, persistence",
            "roles": ["exploit"],
            "knowledge": ["lateral_movement", "persistence", "active_directory"],
            "tools": ["bloodhound", "mimikatz", "linpeas"],
            "depends": ["Exploitation"],
        },
        {
            "name": "Reporting",
            "desc": "Aggregate findings and generate report",
            "roles": ["reporter"],
            "knowledge": ["compliance"],
            "tools": [],
            "depends": ["Post-Exploitation"],
        },
    ],
    "web": [
        {
            "name": "Web Recon",
            "desc": "Crawling, tech stack, endpoints, JS analysis",
            "roles": ["recon"],
            "knowledge": ["web_security"],
            "tools": ["httpx", "whatweb", "katana", "gau"],
            "depends": [],
        },
        {
            "name": "Web Scanning",
            "desc": "Automated DAST scanning",
            "roles": ["vuln_scan"],
            "knowledge": ["web_security", "detection"],
            "tools": ["nuclei", "nikto", "zap"],
            "depends": ["Web Recon"],
        },
        {
            "name": "Manual Testing",
            "desc": "OWASP methodology manual testing",
            "roles": ["web_audit"],
            "knowledge": ["web_security", "exploitation", "advanced_strategy"],
            "tools": ["sqlmap", "ffuf", "burp"],
            "depends": ["Web Recon"],
        },
        {
            "name": "Validation",
            "desc": "Cross-validate findings",
            "roles": ["validator"],
            "knowledge": ["web_security"],
            "tools": [],
            "depends": ["Web Scanning", "Manual Testing"],
        },
    ],
    "network": [
        {
            "name": "Network Discovery",
            "desc": "Host discovery, port scanning",
            "roles": ["recon"],
            "knowledge": ["network"],
            "tools": ["nmap", "masscan", "arp-scan"],
            "depends": [],
        },
        {
            "name": "Service Enumeration",
            "desc": "Service/version detection, banner grabbing",
            "roles": ["recon"],
            "knowledge": ["network"],
            "tools": ["nmap", "amap"],
            "depends": ["Network Discovery"],
        },
        {
            "name": "Vulnerability Assessment",
            "desc": "CVE scanning, misconfiguration checks",
            "roles": ["vuln_scan"],
            "knowledge": ["network", "exploitation"],
            "tools": ["nmap", "nuclei", "nessus"],
            "depends": ["Service Enumeration"],
        },
        {
            "name": "Exploitation",
            "desc": "Exploit confirmed vulnerabilities",
            "roles": ["exploit"],
            "knowledge": ["exploitation", "lateral_movement"],
            "tools": ["metasploit", "hydra"],
            "depends": ["Vulnerability Assessment"],
        },
    ],
    "recon": [
        {
            "name": "OSINT",
            "desc": "Open source intelligence gathering",
            "roles": ["recon"],
            "knowledge": ["threat_intel"],
            "tools": ["theHarvester", "shodan", "censys"],
            "depends": [],
        },
        {
            "name": "DNS Enumeration",
            "desc": "Subdomain discovery, DNS records",
            "roles": ["recon"],
            "knowledge": ["network"],
            "tools": ["amass", "subfinder", "dig", "dnsrecon"],
            "depends": [],
        },
        {
            "name": "Port Scanning",
            "desc": "Comprehensive port scanning",
            "roles": ["recon"],
            "knowledge": ["network"],
            "tools": ["nmap", "masscan"],
            "depends": ["DNS Enumeration"],
        },
    ],
}


class AgentOrchestrator:
    """Top-level orchestrator that coordinates all subsystems.

    Receives assessment tasks, decomposes into phases,
    spawns agents, injects knowledge, routes to models,
    and aggregates results.
    """

    def __init__(self) -> None:
        self._state = OrchestratorState.IDLE
        self._tasks: dict[str, AssessmentTask] = {}
        self._phases: dict[str, list[AssessmentPhase]] = {}
        self._findings: list[dict[str, Any]] = []
        self._counter = 0
        self._token_used = 0
        self._start_time = 0.0
        self._log = logger.bind(component="orchestrator")

    def submit_task(
        self,
        target: str,
        assessment_type: AssessmentType = AssessmentType.FULL,
        scope: list[str] | None = None,
        exclusions: list[str] | None = None,
        max_depth: int = 4,
        token_budget: int = 500000,
        time_limit_s: float = 3600.0,
        system_prompt: str = "",
        custom_config: dict[str, Any] | None = None,
    ) -> AssessmentTask:
        """Submit a new assessment task."""
        self._counter += 1
        task = AssessmentTask(
            task_id=f"task-{self._counter}",
            target=target,
            assessment_type=assessment_type,
            scope=scope or [],
            exclusions=exclusions or [],
            max_depth=max_depth,
            token_budget=token_budget,
            time_limit_s=time_limit_s,
            system_prompt=system_prompt,
            custom_config=custom_config or {},
        )
        self._tasks[task.task_id] = task
        self._state = OrchestratorState.PLANNING

        # Decompose into phases
        phases = self._decompose(task)
        self._phases[task.task_id] = phases

        return task

    def _decompose(self, task: AssessmentTask) -> list[AssessmentPhase]:
        """Decompose task into phases."""
        template_key = task.assessment_type.value
        template = PHASE_TEMPLATES.get(template_key, PHASE_TEMPLATES["full"])

        phases: list[AssessmentPhase] = []
        for i, spec in enumerate(template):
            self._counter += 1
            phase = AssessmentPhase(
                phase_id=f"phase-{self._counter}",
                name=spec["name"],
                description=spec["desc"],
                agent_roles=spec.get("roles", []),
                knowledge_domains=spec.get("knowledge", []),
                tools_needed=spec.get("tools", []),
                depends_on=spec.get("depends", []),
            )
            phases.append(phase)

        return phases

    def get_next_phase(self, task_id: str) -> AssessmentPhase | None:
        """Get the next executable phase."""
        phases = self._phases.get(task_id, [])
        completed = {p.name for p in phases if p.status == "completed"}

        for phase in phases:
            if phase.status != "pending":
                continue
            # Check dependencies
            if all(dep in completed for dep in phase.depends_on):
                return phase
        return None

    def start_phase(self, task_id: str, phase_id: str) -> bool:
        """Mark a phase as started."""
        phases = self._phases.get(task_id, [])
        for phase in phases:
            if phase.phase_id == phase_id:
                phase.status = "running"
                phase.started_at = time.time()
                self._state = OrchestratorState.EXECUTING
                return True
        return False

    def complete_phase(
        self,
        task_id: str,
        phase_id: str,
        findings: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Mark a phase as completed with findings."""
        phases = self._phases.get(task_id, [])
        for phase in phases:
            if phase.phase_id == phase_id:
                phase.status = "completed"
                phase.completed_at = time.time()
                phase.findings_count = len(findings) if findings else 0
                if findings:
                    self._findings.extend(findings)
                return True
        return False

    def is_complete(self, task_id: str) -> bool:
        """Check if all phases are complete."""
        phases = self._phases.get(task_id, [])
        return all(p.status == "completed" for p in phases)

    def build_orchestrator_prompt(self, task_id: str = "") -> str:
        """Build orchestrator context for LLM."""
        lines = ["## Orchestrator\n"]

        lines.append(f"State: {self._state.value} | Tasks: {len(self._tasks)} | Findings: {len(self._findings)}")

        if task_id and task_id in self._tasks:
            task = self._tasks[task_id]
            lines.append(f"\nTask: {task.target[:20]} ({task.assessment_type.value})")
            lines.append(f"Budget: {self._token_used}/{task.token_budget} tokens")

            phases = self._phases.get(task_id, [])
            completed = sum(1 for p in phases if p.status == "completed")
            running = sum(1 for p in phases if p.status == "running")
            pending = sum(1 for p in phases if p.status == "pending")
            lines.append(f"Phases: {completed} done, {running} running, {pending} pending")

            for phase in phases:
                status_icon = {"completed": "[+]", "running": "[>]", "pending": "[ ]"}.get(phase.status, "[?]")
                lines.append(f"  {status_icon} {phase.name[:20]} ({phase.findings_count} findings)")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        all_phases = [p for ps in self._phases.values() for p in ps]
        return {
            "state": self._state.value,
            "tasks": len(self._tasks),
            "phases": len(all_phases),
            "findings": len(self._findings),
            "tokens_used": self._token_used,
        }
