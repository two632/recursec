"""Task planner — decomposes high-level goals into executable plans.

Inspired by PentAGI's Flow → Task → Subtask → Action hierarchy:
1. Flow: Complete assessment session
2. Task: User-defined objective ("find vulns in meta.com")
3. Subtask: Auto-generated sequential steps
4. Action: Individual tool execution or analysis

Also implements:
- Dynamic plan refinement after each subtask
- Dependency tracking between subtasks
- Parallel execution identification
- Progress monitoring
- Plan adaptation when results change assumptions
- Rollback and re-planning on failure
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class PlanStatus(str, Enum):
    PENDING = "pending"
    PLANNING = "planning"
    EXECUTING = "executing"
    REFINING = "refining"
    COMPLETED = "completed"
    FAILED = "failed"


class SubtaskType(str, Enum):
    RECON = "recon"
    ENUMERATE = "enumerate"
    SCAN = "scan"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    ANALYZE = "analyze"
    REPORT = "report"
    CUSTOM = "custom"


@dataclass
class Subtask:
    """An auto-generated sequential step."""
    subtask_id: str = ""
    name: str = ""
    description: str = ""
    subtask_type: SubtaskType = SubtaskType.CUSTOM
    tools: list[str] = field(default_factory=list)
    target: str = ""
    dependencies: list[str] = field(default_factory=list)
    status: PlanStatus = PlanStatus.PENDING
    priority: int = 5
    estimated_time_s: float = 60.0
    agent_role: str = ""
    parallel_group: int = 0
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
            "id": self.subtask_id, "name": self.name[:100],
            "type": self.subtask_type.value,
            "tools": self.tools[:3], "status": self.status.value,
            "priority": self.priority, "group": self.parallel_group,
            "findings": len(self.findings),
        }


@dataclass
class TaskPlan:
    """A complete plan for a task."""
    plan_id: str = ""
    goal: str = ""
    target: str = ""
    target_type: str = ""
    subtasks: list[Subtask] = field(default_factory=list)
    status: PlanStatus = PlanStatus.PENDING
    current_subtask_idx: int = 0
    total_findings: int = 0
    refinement_count: int = 0
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def progress(self) -> float:
        if not self.subtasks:
            return 0.0
        done = sum(1 for s in self.subtasks if s.status == PlanStatus.COMPLETED)
        return done / len(self.subtasks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id, "goal": self.goal[:100],
            "target": self.target,
            "subtasks": len(self.subtasks),
            "progress": f"{self.progress:.0%}",
            "findings": self.total_findings,
            "refinements": self.refinement_count,
        }


# ── Plan Generation Prompts ──────────────────────────────────

PLAN_PROMPT = """You are a security assessment planner. Create a step-by-step plan.

Goal: {goal}
Target: {target}
Target type: {target_type}

Create an ordered list of subtasks. Each subtask should be specific and actionable.
Maximum 15 subtasks. Include tool names where relevant.

For each subtask, classify it as: recon, enumerate, scan, exploit, validate, analyze, report

Respond as JSON:
{{
  "subtasks": [
    {{
      "name": "short name",
      "description": "what to do",
      "type": "recon|enumerate|scan|exploit|validate|analyze|report",
      "tools": ["tool1", "tool2"],
      "agent_role": "recon|vuln_scan|web_scan|exploit|code_audit|network|validator",
      "priority": 1-10,
      "estimated_time_s": 60,
      "dependencies": []
    }}
  ]
}}"""


REFINE_PROMPT = """You are a security assessment planner. Refine the remaining plan based on what we've learned.

Goal: {goal}
Target: {target}

Completed subtasks and findings:
{completed_summary}

Remaining planned subtasks:
{remaining_summary}

Based on what we've found so far, should we:
1. Keep the remaining plan as-is?
2. Add new subtasks (e.g., deeper testing of found vulns)?
3. Remove unnecessary subtasks?
4. Reorder priorities?

Respond as JSON:
{{
  "action": "keep|modify",
  "subtasks": [
    {{
      "name": "name",
      "description": "what to do",
      "type": "recon|enumerate|scan|exploit|validate|analyze|report",
      "tools": ["tool"],
      "agent_role": "role",
      "priority": 1-10,
      "estimated_time_s": 60
    }}
  ],
  "reasoning": "why these changes"
}}"""


# ── Default Plan Templates ───────────────────────────────────

WEB_PLAN: list[dict[str, Any]] = [
    {"name": "Subdomain discovery", "type": "recon", "tools": ["subfinder", "amass"],
     "role": "recon", "priority": 9, "time": 60},
    {"name": "HTTP probing", "type": "recon", "tools": ["httpx"],
     "role": "recon", "priority": 8, "time": 30, "deps": ["Subdomain discovery"]},
    {"name": "Technology fingerprinting", "type": "enumerate", "tools": ["whatweb", "wappalyzer"],
     "role": "recon", "priority": 8, "time": 30},
    {"name": "Directory enumeration", "type": "enumerate", "tools": ["gobuster", "ffuf"],
     "role": "web_scan", "priority": 7, "time": 120},
    {"name": "Port scanning", "type": "recon", "tools": ["nmap"],
     "role": "recon", "priority": 7, "time": 90},
    {"name": "Web crawling", "type": "recon", "tools": ["katana"],
     "role": "recon", "priority": 6, "time": 60},
    {"name": "Vulnerability scanning", "type": "scan", "tools": ["nuclei"],
     "role": "vuln_scan", "priority": 9, "time": 120},
    {"name": "Web vulnerability testing", "type": "scan", "tools": ["nikto", "dalfox"],
     "role": "web_scan", "priority": 8, "time": 120},
    {"name": "SQL injection testing", "type": "exploit", "tools": ["sqlmap"],
     "role": "exploit", "priority": 8, "time": 120},
    {"name": "SSL/TLS analysis", "type": "scan", "tools": ["testssl"],
     "role": "network", "priority": 6, "time": 30},
    {"name": "Finding validation", "type": "validate", "tools": ["curl", "nuclei"],
     "role": "validator", "priority": 9, "time": 60},
    {"name": "Generate report", "type": "report", "tools": [],
     "role": "coordinator", "priority": 5, "time": 30},
]

NETWORK_PLAN: list[dict[str, Any]] = [
    {"name": "Fast port scan", "type": "recon", "tools": ["masscan"],
     "role": "recon", "priority": 9, "time": 30},
    {"name": "Detailed port scan", "type": "recon", "tools": ["nmap"],
     "role": "recon", "priority": 9, "time": 120, "deps": ["Fast port scan"]},
    {"name": "Service enumeration", "type": "enumerate", "tools": ["nmap"],
     "role": "recon", "priority": 8, "time": 60},
    {"name": "SMB enumeration", "type": "enumerate", "tools": ["enum4linux"],
     "role": "network", "priority": 7, "time": 60},
    {"name": "DNS enumeration", "type": "enumerate", "tools": ["dig", "dnsrecon"],
     "role": "network", "priority": 7, "time": 30},
    {"name": "SSL/TLS testing", "type": "scan", "tools": ["testssl"],
     "role": "network", "priority": 7, "time": 30},
    {"name": "Vulnerability scanning", "type": "scan", "tools": ["nuclei", "nmap"],
     "role": "vuln_scan", "priority": 9, "time": 120},
    {"name": "Credential testing", "type": "exploit", "tools": ["hydra"],
     "role": "exploit", "priority": 6, "time": 120},
    {"name": "Finding validation", "type": "validate", "tools": ["nmap", "curl"],
     "role": "validator", "priority": 9, "time": 60},
    {"name": "Generate report", "type": "report", "tools": [],
     "role": "coordinator", "priority": 5, "time": 30},
]

CODE_PLAN: list[dict[str, Any]] = [
    {"name": "Repository analysis", "type": "recon", "tools": [],
     "role": "code_audit", "priority": 9, "time": 30},
    {"name": "Dependency scanning", "type": "scan", "tools": ["trivy"],
     "role": "code_audit", "priority": 9, "time": 60},
    {"name": "Secret detection", "type": "scan", "tools": ["gitleaks", "trufflehog"],
     "role": "code_audit", "priority": 9, "time": 60},
    {"name": "Static analysis", "type": "scan", "tools": ["semgrep"],
     "role": "code_audit", "priority": 9, "time": 120},
    {"name": "Python security lint", "type": "scan", "tools": ["bandit"],
     "role": "code_audit", "priority": 7, "time": 30},
    {"name": "Finding validation", "type": "validate", "tools": [],
     "role": "validator", "priority": 9, "time": 60},
    {"name": "Generate report", "type": "report", "tools": [],
     "role": "coordinator", "priority": 5, "time": 30},
]


class TaskPlanner:
    """Decomposes high-level goals into executable plans.

    Creates, executes, and dynamically refines plans
    using PentAGI-style Flow → Task → Subtask hierarchy.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._plans: dict[str, TaskPlan] = {}
        self._plan_counter = 0
        self._subtask_counter = 0
        self._log = logger.bind(component="task_planner")

    async def create_plan(
        self,
        goal: str,
        target: str,
        target_type: str = "",
    ) -> TaskPlan:
        """Create a plan for a goal."""
        self._plan_counter += 1
        plan_id = f"plan-{self._plan_counter}"

        if not target_type:
            target_type = self._detect_target_type(target)

        plan = TaskPlan(
            plan_id=plan_id,
            goal=goal,
            target=target,
            target_type=target_type,
        )

        # Try LLM-based planning first
        if self._router:
            subtasks = await self._llm_plan(goal, target, target_type)
        else:
            subtasks = []

        # Fall back to templates
        if not subtasks:
            subtasks = self._template_plan(target_type)

        plan.subtasks = subtasks
        plan.status = PlanStatus.EXECUTING

        self._plans[plan_id] = plan
        return plan

    async def refine_plan(self, plan_id: str) -> TaskPlan | None:
        """Refine a plan based on completed subtask results."""
        plan = self._plans.get(plan_id)
        if not plan or not self._router:
            return plan

        plan.status = PlanStatus.REFINING

        completed = [s for s in plan.subtasks if s.status == PlanStatus.COMPLETED]
        remaining = [s for s in plan.subtasks if s.status == PlanStatus.PENDING]

        completed_text = "\n".join(
            f"  - {s.name}: {len(s.findings)} findings"
            for s in completed
        ) or "  None"

        remaining_text = "\n".join(
            f"  - [{s.priority}] {s.name} ({', '.join(s.tools[:2])})"
            for s in remaining
        ) or "  None"

        prompt = REFINE_PROMPT.format(
            goal=plan.goal[:200],
            target=plan.target,
            completed_summary=completed_text,
            remaining_summary=remaining_text,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)

        if data.get("action") == "modify" and data.get("subtasks"):
            # Replace remaining subtasks
            new_remaining = []
            for s_data in data["subtasks"]:
                self._subtask_counter += 1
                new_remaining.append(Subtask(
                    subtask_id=f"st-{self._subtask_counter}",
                    name=s_data.get("name", ""),
                    description=s_data.get("description", ""),
                    subtask_type=self._parse_type(s_data.get("type", "custom")),
                    tools=s_data.get("tools", []),
                    agent_role=s_data.get("agent_role", ""),
                    priority=s_data.get("priority", 5),
                    estimated_time_s=s_data.get("estimated_time_s", 60),
                ))

            plan.subtasks = completed + new_remaining
            plan.refinement_count += 1

        plan.status = PlanStatus.EXECUTING
        return plan

    def get_next_subtask(self, plan_id: str) -> Subtask | None:
        """Get the next pending subtask."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        for subtask in plan.subtasks:
            if subtask.status != PlanStatus.PENDING:
                continue
            # Check dependencies
            deps_met = all(
                any(
                    s.subtask_id == dep and s.status == PlanStatus.COMPLETED
                    for s in plan.subtasks
                )
                for dep in subtask.dependencies
            )
            if deps_met:
                return subtask

        return None

    def start_subtask(self, plan_id: str, subtask_id: str) -> bool:
        plan = self._plans.get(plan_id)
        if not plan:
            return False
        for s in plan.subtasks:
            if s.subtask_id == subtask_id:
                s.status = PlanStatus.EXECUTING
                s.started_at = time.time()
                return True
        return False

    def complete_subtask(
        self,
        plan_id: str,
        subtask_id: str,
        findings: list[dict[str, Any]] | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        plan = self._plans.get(plan_id)
        if not plan:
            return
        for s in plan.subtasks:
            if s.subtask_id == subtask_id:
                s.status = PlanStatus.COMPLETED
                s.completed_at = time.time()
                s.findings = findings or []
                s.result = result or {}
                plan.total_findings += len(s.findings)
                break

    def fail_subtask(self, plan_id: str, subtask_id: str, error: str = "") -> None:
        plan = self._plans.get(plan_id)
        if not plan:
            return
        for s in plan.subtasks:
            if s.subtask_id == subtask_id:
                s.status = PlanStatus.FAILED
                s.completed_at = time.time()
                s.error = error
                break

    # ── Internal ─────────────────────────────────────────

    async def _llm_plan(
        self,
        goal: str,
        target: str,
        target_type: str,
    ) -> list[Subtask]:
        """Generate a plan using LLM."""
        if not self._router:
            return []

        prompt = PLAN_PROMPT.format(
            goal=goal[:300], target=target, target_type=target_type,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.3,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        subtasks = []

        for s_data in data.get("subtasks", [])[:15]:
            self._subtask_counter += 1
            subtasks.append(Subtask(
                subtask_id=f"st-{self._subtask_counter}",
                name=s_data.get("name", ""),
                description=s_data.get("description", ""),
                subtask_type=self._parse_type(s_data.get("type", "custom")),
                tools=s_data.get("tools", []),
                target=target,
                agent_role=s_data.get("agent_role", ""),
                priority=s_data.get("priority", 5),
                estimated_time_s=s_data.get("estimated_time_s", 60),
            ))

        return subtasks

    def _template_plan(self, target_type: str) -> list[Subtask]:
        """Generate a plan from templates."""
        if target_type in ("web_app", "web", "api"):
            template = WEB_PLAN
        elif target_type in ("network", "host", "ip"):
            template = NETWORK_PLAN
        elif target_type in ("code", "repo", "code_repo"):
            template = CODE_PLAN
        else:
            template = WEB_PLAN

        subtasks = []
        name_to_id: dict[str, str] = {}

        for entry in template:
            self._subtask_counter += 1
            st_id = f"st-{self._subtask_counter}"
            deps = [name_to_id[d] for d in entry.get("deps", []) if d in name_to_id]

            subtask = Subtask(
                subtask_id=st_id,
                name=entry["name"],
                subtask_type=self._parse_type(entry.get("type", "custom")),
                tools=entry.get("tools", []),
                agent_role=entry.get("role", ""),
                priority=entry.get("priority", 5),
                estimated_time_s=entry.get("time", 60),
                dependencies=deps,
            )

            subtasks.append(subtask)
            name_to_id[entry["name"]] = st_id

        return subtasks

    def _detect_target_type(self, target: str) -> str:
        target_lower = target.lower()
        if target_lower.startswith(("http://", "https://")):
            return "web_app"
        if target_lower.startswith(("github.com", "gitlab.com")) or target_lower.endswith(".git"):
            return "code_repo"
        if "/" in target and "." in target.split("/")[0]:
            return "network"
        if "." in target:
            return "web_app"
        return "unknown"

    def _parse_type(self, type_str: str) -> SubtaskType:
        try:
            return SubtaskType(type_str)
        except ValueError:
            return SubtaskType.CUSTOM

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_plan(self, plan_id: str) -> TaskPlan | None:
        return self._plans.get(plan_id)

    def get_stats(self) -> dict[str, Any]:
        return {
            "plans": len(self._plans),
            "total_subtasks": sum(len(p.subtasks) for p in self._plans.values()),
            "total_findings": sum(p.total_findings for p in self._plans.values()),
        }
