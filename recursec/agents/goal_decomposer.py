"""Goal decomposition engine — intelligent breakdown of high-level goals.

Converts abstract security objectives into concrete, executable plans:
1. Parse the high-level goal into structured objectives
2. Identify required capabilities and prerequisites
3. Decompose into phases (recon → analysis → exploitation → reporting)
4. Generate tasks for each phase with dependencies
5. Assign tasks to appropriate agent roles
6. Estimate resource requirements per task
7. Identify parallelization opportunities
8. Handle replanning when obstacles are encountered

Decomposition strategies:
- Template-based: Use known assessment templates
- LLM-guided: Let reasoning model decompose novel goals
- Hybrid: Template + LLM for customization
- Iterative: Start shallow, deepen as needed
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class GoalType(str, Enum):
    FULL_ASSESSMENT = "full_assessment"
    WEB_PENTEST = "web_pentest"
    NETWORK_PENTEST = "network_pentest"
    CODE_AUDIT = "code_audit"
    CLOUD_ASSESSMENT = "cloud_assessment"
    API_SECURITY = "api_security"
    MOBILE_SECURITY = "mobile_security"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    RED_TEAM = "red_team"
    CUSTOM = "custom"


class PhaseType(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    VALIDATION = "validation"


@dataclass
class Objective:
    """A measurable objective within a goal."""
    objective_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    measurable_criteria: str = ""
    priority: int = 5
    required_capabilities: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    estimated_effort: str = "medium"  # low, medium, high
    assigned_phase: PhaseType = PhaseType.RECONNAISSANCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.objective_id,
            "description": self.description[:200],
            "criteria": self.measurable_criteria[:100],
            "priority": self.priority,
            "phase": self.assigned_phase.value,
            "effort": self.estimated_effort,
        }


@dataclass
class PlanTask:
    """A concrete task in the execution plan."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    name: str = ""
    description: str = ""
    agent_role: str = ""
    phase: PhaseType = PhaseType.RECONNAISSANCE
    tools_needed: list[str] = field(default_factory=list)
    model_preference: str = ""
    dependencies: list[str] = field(default_factory=list)
    parallel_group: int = 0
    estimated_tokens: int = 5000
    estimated_time_s: float = 60.0
    priority: int = 5
    context_from_objectives: list[str] = field(default_factory=list)
    success_criteria: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id, "name": self.name[:100],
            "agent": self.agent_role, "phase": self.phase.value,
            "tools": self.tools_needed[:5],
            "deps": self.dependencies,
            "parallel_group": self.parallel_group,
            "priority": self.priority,
        }


@dataclass
class ExecutionPlan:
    """Complete execution plan for a goal."""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    goal: str = ""
    goal_type: GoalType = GoalType.CUSTOM
    target: str = ""
    objectives: list[Objective] = field(default_factory=list)
    tasks: list[PlanTask] = field(default_factory=list)
    phases: list[PhaseType] = field(default_factory=list)
    estimated_total_time_s: float = 0.0
    estimated_total_tokens: int = 0
    created_at: float = field(default_factory=time.time)

    def get_phase_tasks(self, phase: PhaseType) -> list[PlanTask]:
        return [t for t in self.tasks if t.phase == phase]

    def get_parallel_groups(self) -> dict[int, list[PlanTask]]:
        groups: dict[int, list[PlanTask]] = {}
        for task in self.tasks:
            groups.setdefault(task.parallel_group, []).append(task)
        return groups

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id, "goal": self.goal[:200],
            "type": self.goal_type.value, "target": self.target,
            "objectives": len(self.objectives),
            "tasks": len(self.tasks),
            "phases": [p.value for p in self.phases],
            "est_time_s": self.estimated_total_time_s,
            "est_tokens": self.estimated_total_tokens,
        }


# ── Assessment Templates ────────────────────────────────────

PHASE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_pentest": [
        {
            "phase": "reconnaissance",
            "tasks": [
                {"name": "Subdomain enumeration", "agent": "recon", "tools": ["subfinder", "amass", "assetfinder"]},
                {"name": "Technology fingerprinting", "agent": "recon", "tools": ["whatweb", "wappalyzer", "httpx"]},
                {"name": "Directory/file discovery", "agent": "recon", "tools": ["gobuster", "ffuf", "dirsearch"]},
                {"name": "JavaScript analysis", "agent": "recon", "tools": ["linkfinder", "secretfinder"]},
                {"name": "API endpoint discovery", "agent": "recon", "tools": ["katana", "hakrawler"]},
            ],
        },
        {
            "phase": "enumeration",
            "tasks": [
                {"name": "Port scanning", "agent": "recon", "tools": ["nmap", "masscan"]},
                {"name": "Service enumeration", "agent": "recon", "tools": ["nmap"]},
                {"name": "Virtual host discovery", "agent": "recon", "tools": ["ffuf"]},
                {"name": "Web application mapping", "agent": "web_scan", "tools": ["burp", "zap"]},
            ],
        },
        {
            "phase": "vulnerability_analysis",
            "tasks": [
                {"name": "Automated vulnerability scanning", "agent": "vuln_scan", "tools": ["nuclei", "nikto"]},
                {"name": "SQL injection testing", "agent": "exploit", "tools": ["sqlmap"]},
                {"name": "XSS testing", "agent": "exploit", "tools": ["dalfox", "xsser"]},
                {"name": "Authentication testing", "agent": "exploit", "tools": ["hydra", "patator"]},
                {"name": "SSRF testing", "agent": "exploit", "tools": ["ssrfmap"]},
                {"name": "Code review (if available)", "agent": "code_audit", "tools": ["semgrep", "bandit"]},
            ],
        },
        {
            "phase": "exploitation",
            "tasks": [
                {"name": "Exploit confirmed vulnerabilities", "agent": "exploit", "tools": ["metasploit", "custom"]},
                {"name": "Chain vulnerabilities", "agent": "exploit", "tools": ["custom"]},
                {"name": "Privilege escalation", "agent": "exploit", "tools": ["linpeas", "winpeas"]},
            ],
        },
        {
            "phase": "reporting",
            "tasks": [
                {"name": "Compile findings", "agent": "reporter", "tools": ["custom"]},
                {"name": "Validate all findings", "agent": "validator", "tools": ["custom"]},
            ],
        },
    ],
    "network_pentest": [
        {
            "phase": "reconnaissance",
            "tasks": [
                {"name": "Network range discovery", "agent": "recon", "tools": ["nmap", "masscan"]},
                {"name": "Host discovery", "agent": "recon", "tools": ["nmap", "arp-scan"]},
                {"name": "OSINT gathering", "agent": "osint", "tools": ["shodan", "censys"]},
            ],
        },
        {
            "phase": "enumeration",
            "tasks": [
                {"name": "Full port scan", "agent": "recon", "tools": ["nmap", "masscan"]},
                {"name": "Service version detection", "agent": "recon", "tools": ["nmap"]},
                {"name": "SMB enumeration", "agent": "network", "tools": ["enum4linux", "smbclient"]},
                {"name": "SNMP enumeration", "agent": "network", "tools": ["snmpwalk", "onesixtyone"]},
                {"name": "DNS enumeration", "agent": "network", "tools": ["dig", "dnsenum"]},
            ],
        },
        {
            "phase": "vulnerability_analysis",
            "tasks": [
                {"name": "Network vulnerability scanning", "agent": "vuln_scan", "tools": ["nmap", "nuclei"]},
                {"name": "Default credential testing", "agent": "exploit", "tools": ["hydra", "crackmapexec"]},
                {"name": "SSL/TLS analysis", "agent": "network", "tools": ["testssl", "sslscan"]},
            ],
        },
        {
            "phase": "exploitation",
            "tasks": [
                {"name": "Exploit network services", "agent": "exploit", "tools": ["metasploit"]},
                {"name": "Lateral movement", "agent": "exploit", "tools": ["crackmapexec", "impacket"]},
                {"name": "Privilege escalation", "agent": "exploit", "tools": ["linpeas", "winpeas"]},
            ],
        },
    ],
    "code_audit": [
        {
            "phase": "reconnaissance",
            "tasks": [
                {"name": "Codebase structure analysis", "agent": "code_audit", "tools": ["custom"]},
                {"name": "Dependency analysis", "agent": "code_audit", "tools": ["custom"]},
                {"name": "Technology identification", "agent": "code_audit", "tools": ["custom"]},
            ],
        },
        {
            "phase": "vulnerability_analysis",
            "tasks": [
                {"name": "Static analysis — SAST", "agent": "code_audit", "tools": ["semgrep", "bandit", "codeql"]},
                {"name": "Secret detection", "agent": "code_audit", "tools": ["trufflehog", "gitleaks"]},
                {"name": "Dependency vulnerability check", "agent": "code_audit", "tools": ["trivy", "grype"]},
                {"name": "Custom pattern analysis", "agent": "code_audit", "tools": ["custom"]},
                {"name": "Manual code review (critical paths)", "agent": "code_audit", "tools": ["custom"]},
            ],
        },
        {
            "phase": "validation",
            "tasks": [
                {"name": "Validate findings", "agent": "validator", "tools": ["custom"]},
                {"name": "False positive analysis", "agent": "validator", "tools": ["custom"]},
            ],
        },
    ],
}


DECOMPOSE_PROMPT = """Decompose this security assessment goal into objectives and tasks.

Goal: {goal}
Target: {target}
Goal type: {goal_type}
Available agent roles: {agent_roles}
Constraints: {constraints}

Create a structured execution plan with:
1. Clear objectives with measurable criteria
2. Concrete tasks assigned to agent roles
3. Task dependencies and parallelization opportunities
4. Estimated effort and resource needs

Respond as JSON:
{{
  "objectives": [
    {{
      "description": "what to achieve",
      "criteria": "how to measure success",
      "priority": 1-10,
      "phase": "reconnaissance|enumeration|vulnerability_analysis|exploitation|post_exploitation|reporting|validation",
      "effort": "low|medium|high"
    }}
  ],
  "tasks": [
    {{
      "name": "task name",
      "description": "what to do",
      "agent_role": "recon|vuln_scan|exploit|code_audit|network|osint|web_scan|validator|reporter",
      "phase": "phase_name",
      "tools": ["tool names"],
      "dependencies": ["task indices this depends on"],
      "parallel_group": 0,
      "estimated_tokens": 5000,
      "estimated_time_s": 60,
      "priority": 1-10,
      "success_criteria": "how to know this succeeded"
    }}
  ],
  "phases": ["ordered list of phases"]
}}"""


class GoalDecomposer:
    """Decomposes high-level security goals into executable plans.

    Combines template-based and LLM-guided decomposition for
    both common and novel assessment types.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._plans: dict[str, ExecutionPlan] = {}
        self._log = logger.bind(component="goal_decomposer")

    async def decompose(
        self,
        goal: str,
        target: str,
        goal_type: GoalType = GoalType.CUSTOM,
        constraints: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        """Decompose a goal into an execution plan."""
        # Try template-based first for known goal types
        template_key = self._get_template_key(goal_type)
        if template_key and template_key in PHASE_TEMPLATES:
            plan = self._from_template(goal, target, goal_type, template_key)
        elif self._router:
            plan = await self._from_llm(goal, target, goal_type, constraints or {})
        else:
            plan = self._default_plan(goal, target, goal_type)

        # Estimate totals
        plan.estimated_total_time_s = sum(t.estimated_time_s for t in plan.tasks)
        plan.estimated_total_tokens = sum(t.estimated_tokens for t in plan.tasks)

        self._plans[plan.plan_id] = plan
        self._log.info(
            "goal_decomposed",
            goal_type=goal_type.value,
            tasks=len(plan.tasks),
            phases=len(plan.phases),
        )

        return plan

    def _from_template(
        self,
        goal: str,
        target: str,
        goal_type: GoalType,
        template_key: str,
    ) -> ExecutionPlan:
        """Build plan from a template."""
        plan = ExecutionPlan(goal=goal, target=target, goal_type=goal_type)
        template = PHASE_TEMPLATES[template_key]

        task_idx = 0
        for phase_data in template:
            phase_name = phase_data["phase"]
            try:
                phase = PhaseType(phase_name)
            except ValueError:
                continue

            if phase not in plan.phases:
                plan.phases.append(phase)

            for task_data in phase_data["tasks"]:
                task = PlanTask(
                    name=task_data["name"],
                    description=task_data["name"],
                    agent_role=task_data.get("agent", "recon"),
                    phase=phase,
                    tools_needed=task_data.get("tools", []),
                    parallel_group=task_idx // 3,  # Group tasks in threes for parallelism
                    priority=5,
                    estimated_time_s=120.0,
                    estimated_tokens=10000,
                )
                plan.tasks.append(task)
                task_idx += 1

        return plan

    async def _from_llm(
        self,
        goal: str,
        target: str,
        goal_type: GoalType,
        constraints: dict[str, Any],
    ) -> ExecutionPlan:
        """Build plan using LLM reasoning."""
        if not self._router:
            return self._default_plan(goal, target, goal_type)

        agent_roles = [
            "recon", "vuln_scan", "exploit", "code_audit",
            "network", "osint", "web_scan", "validator", "reporter",
        ]

        prompt = DECOMPOSE_PROMPT.format(
            goal=goal, target=target,
            goal_type=goal_type.value,
            agent_roles=", ".join(agent_roles),
            constraints=json.dumps(constraints)[:500],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.2,
            max_tokens=4096,
        )

        data = self._parse_json(response)
        plan = ExecutionPlan(goal=goal, target=target, goal_type=goal_type)

        # Parse objectives
        for obj_data in data.get("objectives", []):
            try:
                phase = PhaseType(obj_data.get("phase", "reconnaissance"))
            except ValueError:
                phase = PhaseType.RECONNAISSANCE

            objective = Objective(
                description=obj_data.get("description", ""),
                measurable_criteria=obj_data.get("criteria", ""),
                priority=obj_data.get("priority", 5),
                assigned_phase=phase,
                estimated_effort=obj_data.get("effort", "medium"),
            )
            plan.objectives.append(objective)

        # Parse tasks
        for task_data in data.get("tasks", []):
            try:
                phase = PhaseType(task_data.get("phase", "reconnaissance"))
            except ValueError:
                phase = PhaseType.RECONNAISSANCE

            task = PlanTask(
                name=task_data.get("name", ""),
                description=task_data.get("description", ""),
                agent_role=task_data.get("agent_role", "recon"),
                phase=phase,
                tools_needed=task_data.get("tools", []),
                parallel_group=task_data.get("parallel_group", 0),
                estimated_tokens=task_data.get("estimated_tokens", 5000),
                estimated_time_s=task_data.get("estimated_time_s", 60),
                priority=task_data.get("priority", 5),
                success_criteria=task_data.get("success_criteria", ""),
            )
            plan.tasks.append(task)

        # Parse phases
        for phase_name in data.get("phases", []):
            try:
                plan.phases.append(PhaseType(phase_name))
            except ValueError:
                continue

        if not plan.phases:
            plan.phases = [PhaseType.RECONNAISSANCE, PhaseType.VULNERABILITY_ANALYSIS, PhaseType.REPORTING]

        return plan

    def _default_plan(
        self,
        goal: str,
        target: str,
        goal_type: GoalType,
    ) -> ExecutionPlan:
        """Generate a default plan when no template or LLM is available."""
        plan = ExecutionPlan(goal=goal, target=target, goal_type=goal_type)
        plan.phases = [
            PhaseType.RECONNAISSANCE,
            PhaseType.ENUMERATION,
            PhaseType.VULNERABILITY_ANALYSIS,
            PhaseType.REPORTING,
        ]

        plan.tasks = [
            PlanTask(name="Initial reconnaissance", agent_role="recon", phase=PhaseType.RECONNAISSANCE),
            PlanTask(name="Service enumeration", agent_role="recon", phase=PhaseType.ENUMERATION),
            PlanTask(name="Vulnerability scanning", agent_role="vuln_scan", phase=PhaseType.VULNERABILITY_ANALYSIS),
            PlanTask(name="Generate report", agent_role="reporter", phase=PhaseType.REPORTING),
        ]

        return plan

    def _get_template_key(self, goal_type: GoalType) -> str:
        return {
            GoalType.WEB_PENTEST: "web_pentest",
            GoalType.NETWORK_PENTEST: "network_pentest",
            GoalType.CODE_AUDIT: "code_audit",
        }.get(goal_type, "")

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        return self._plans.get(plan_id)

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
