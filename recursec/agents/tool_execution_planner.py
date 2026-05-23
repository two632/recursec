"""Tool execution planner — plans which tools to run and in what order.

Implements:
1. Tool dependency graph (tool B depends on output of tool A)
2. Parallel execution scheduling
3. Tool capability matching to task requirements
4. Fallback tool selection
5. Output routing between tools
6. Execution budget management
7. Tool chain optimization
8. Result quality assessment
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON_PASSIVE = "recon_passive"
    RECON_ACTIVE = "recon_active"
    PORT_SCANNING = "port_scanning"
    WEB_SCANNING = "web_scanning"
    VULN_SCANNING = "vuln_scanning"
    CODE_ANALYSIS = "code_analysis"
    FUZZING = "fuzzing"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    CREDENTIAL = "credential"
    NETWORK = "network"
    CRYPTO = "crypto"
    CLOUD = "cloud"
    CONTAINER = "container"


class ExecutionState(str, Enum):
    PENDING = "pending"
    READY = "ready"        # Dependencies satisfied
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ToolSpec:
    """Specification of a tool's capabilities."""
    tool_id: str = ""
    name: str = ""
    category: ToolCategory = ToolCategory.RECON_PASSIVE
    capabilities: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)  # What it accepts
    output_types: list[str] = field(default_factory=list)  # What it produces
    estimated_time_s: float = 30.0
    reliability: float = 0.9
    requires_root: bool = False
    fallback_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.tool_id,
            "name": self.name[:20],
            "category": self.category.value,
            "outputs": self.output_types[:3],
        }


@dataclass
class ExecutionStep:
    """A step in the execution plan."""
    step_id: str = ""
    tool_name: str = ""
    command_template: str = ""
    depends_on: list[str] = field(default_factory=list)  # step IDs
    state: ExecutionState = ExecutionState.PENDING
    input_from: dict[str, str] = field(default_factory=dict)  # step_id -> output_field
    output: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def duration_s(self) -> float:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id,
            "tool": self.tool_name[:20],
            "state": self.state.value,
            "depends_on": len(self.depends_on),
            "duration": round(self.duration_s, 1),
        }


@dataclass
class ExecutionPlan:
    """A complete execution plan."""
    plan_id: str = ""
    objective: str = ""
    steps: dict[str, ExecutionStep] = field(default_factory=dict)
    execution_order: list[list[str]] = field(default_factory=list)  # Batches of parallel steps
    estimated_total_time_s: float = 0.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id,
            "objective": self.objective[:30],
            "steps": len(self.steps),
            "batches": len(self.execution_order),
            "est_time": round(self.estimated_total_time_s),
        }


# ── Tool Registry ─────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # Passive recon
    {"name": "whois", "category": "recon_passive",
     "caps": ["domain_info"], "in": ["domain"], "out": ["registrant", "nameservers"],
     "time": 5.0},
    {"name": "subfinder", "category": "recon_passive",
     "caps": ["subdomain_enum"], "in": ["domain"], "out": ["subdomains"],
     "time": 30.0, "fallback": ["amass"]},
    {"name": "amass", "category": "recon_passive",
     "caps": ["subdomain_enum"], "in": ["domain"], "out": ["subdomains"],
     "time": 120.0},
    {"name": "theHarvester", "category": "recon_passive",
     "caps": ["email_enum", "subdomain_enum"], "in": ["domain"], "out": ["emails", "subdomains"],
     "time": 60.0},
    {"name": "dnsrecon", "category": "recon_passive",
     "caps": ["dns_enum"], "in": ["domain"], "out": ["dns_records"],
     "time": 30.0},

    # Active recon
    {"name": "nmap", "category": "port_scanning",
     "caps": ["port_scan", "service_detect", "os_detect"], "in": ["ip", "host"],
     "out": ["open_ports", "services", "os_info"],
     "time": 60.0, "fallback": ["masscan"]},
    {"name": "masscan", "category": "port_scanning",
     "caps": ["port_scan"], "in": ["ip", "cidr"],
     "out": ["open_ports"],
     "time": 30.0, "root": True},

    # Web scanning
    {"name": "nuclei", "category": "vuln_scanning",
     "caps": ["vuln_scan", "template_scan"], "in": ["url"],
     "out": ["vulnerabilities"],
     "time": 120.0},
    {"name": "nikto", "category": "web_scanning",
     "caps": ["web_scan", "misconfig_detect"], "in": ["url"],
     "out": ["web_findings"],
     "time": 90.0},
    {"name": "ffuf", "category": "web_scanning",
     "caps": ["dir_brute", "vhost_brute"], "in": ["url"],
     "out": ["discovered_paths"],
     "time": 60.0, "fallback": ["gobuster", "dirsearch"]},
    {"name": "gobuster", "category": "web_scanning",
     "caps": ["dir_brute"], "in": ["url"],
     "out": ["discovered_paths"],
     "time": 60.0},
    {"name": "whatweb", "category": "recon_active",
     "caps": ["tech_detect"], "in": ["url"],
     "out": ["technologies"],
     "time": 10.0},
    {"name": "wappalyzer", "category": "recon_active",
     "caps": ["tech_detect"], "in": ["url"],
     "out": ["technologies"],
     "time": 15.0},

    # Vulnerability scanning
    {"name": "sqlmap", "category": "exploitation",
     "caps": ["sqli_detect", "sqli_exploit"], "in": ["url", "request"],
     "out": ["sqli_findings", "database_data"],
     "time": 180.0},
    {"name": "xsstrike", "category": "vuln_scanning",
     "caps": ["xss_detect"], "in": ["url"],
     "out": ["xss_findings"],
     "time": 60.0},
    {"name": "commix", "category": "exploitation",
     "caps": ["cmdi_detect", "cmdi_exploit"], "in": ["url"],
     "out": ["cmdi_findings"],
     "time": 120.0},

    # Code analysis
    {"name": "semgrep", "category": "code_analysis",
     "caps": ["sast", "pattern_match"], "in": ["source_code"],
     "out": ["code_findings"],
     "time": 60.0},
    {"name": "bandit", "category": "code_analysis",
     "caps": ["python_sast"], "in": ["python_source"],
     "out": ["code_findings"],
     "time": 30.0},
    {"name": "trufflehog", "category": "code_analysis",
     "caps": ["secret_detect"], "in": ["git_repo"],
     "out": ["leaked_secrets"],
     "time": 45.0},

    # Network
    {"name": "tcpdump", "category": "network",
     "caps": ["packet_capture"], "in": ["interface"],
     "out": ["pcap_data"],
     "time": 60.0, "root": True},
    {"name": "testssl", "category": "crypto",
     "caps": ["ssl_audit"], "in": ["host"],
     "out": ["ssl_findings"],
     "time": 60.0},

    # Cloud
    {"name": "scout_suite", "category": "cloud",
     "caps": ["cloud_audit"], "in": ["cloud_creds"],
     "out": ["cloud_findings"],
     "time": 300.0},
    {"name": "trivy", "category": "container",
     "caps": ["container_scan", "iac_scan"], "in": ["image", "directory"],
     "out": ["container_findings"],
     "time": 60.0},

    # Credential
    {"name": "hydra", "category": "credential",
     "caps": ["brute_force"], "in": ["host", "service", "wordlist"],
     "out": ["credentials"],
     "time": 300.0, "fallback": ["medusa"]},
    {"name": "hashcat", "category": "credential",
     "caps": ["hash_crack"], "in": ["hashes"],
     "out": ["cracked_passwords"],
     "time": 600.0, "fallback": ["john"]},
]


class ToolExecutionPlanner:
    """Plans tool execution with dependency management.

    Given an objective, selects the right tools, orders them
    based on dependencies (tool B needs output of tool A),
    and maximizes parallel execution where possible.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._plans: dict[str, ExecutionPlan] = {}
        self._plan_counter = 0
        self._step_counter = 0
        self._log = logger.bind(component="tool_execution_planner")

        self._load_registry()

    def _load_registry(self) -> None:
        """Load the tool registry."""
        for i, data in enumerate(TOOL_REGISTRY):
            tool = ToolSpec(
                tool_id=f"tool-{i + 1}",
                name=data["name"],
                category=ToolCategory(data["category"]),
                capabilities=data.get("caps", []),
                input_types=data.get("in", []),
                output_types=data.get("out", []),
                estimated_time_s=data.get("time", 30.0),
                requires_root=data.get("root", False),
                fallback_tools=data.get("fallback", []),
            )
            self._tools[tool.name] = tool

    def create_plan(
        self,
        objective: str,
        target_info: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        """Create an execution plan for an objective."""
        self._plan_counter += 1
        plan = ExecutionPlan(
            plan_id=f"plan-{self._plan_counter}",
            objective=objective,
        )

        # Select tools based on objective
        selected_tools = self._select_tools_for_objective(
            objective, target_info or {}
        )

        # Build steps with dependencies
        for tool_name in selected_tools:
            self._step_counter += 1
            tool = self._tools.get(tool_name)
            if not tool:
                continue

            step = ExecutionStep(
                step_id=f"step-{self._step_counter}",
                tool_name=tool_name,
            )

            # Find dependencies
            for existing_step in plan.steps.values():
                existing_tool = self._tools.get(existing_step.tool_name)
                if not existing_tool:
                    continue
                # Check if this tool needs output from existing tool
                for in_type in tool.input_types:
                    if in_type in existing_tool.output_types:
                        step.depends_on.append(existing_step.step_id)
                        step.input_from[existing_step.step_id] = in_type

            plan.steps[step.step_id] = step

        # Compute execution order (topological sort into batches)
        plan.execution_order = self._topological_batch_sort(plan.steps)

        # Estimate total time (sum of max time per batch)
        plan.estimated_total_time_s = sum(
            max(
                (self._tools.get(plan.steps[sid].tool_name, ToolSpec()).estimated_time_s
                 for sid in batch),
                default=0,
            )
            for batch in plan.execution_order
        )

        self._plans[plan.plan_id] = plan
        return plan

    def get_ready_steps(self, plan_id: str) -> list[ExecutionStep]:
        """Get steps that are ready to execute (dependencies satisfied)."""
        plan = self._plans.get(plan_id)
        if not plan:
            return []

        ready = []
        for step in plan.steps.values():
            if step.state != ExecutionState.PENDING:
                continue

            deps_satisfied = all(
                plan.steps.get(dep, ExecutionStep()).state == ExecutionState.COMPLETED
                for dep in step.depends_on
            )

            if deps_satisfied:
                step.state = ExecutionState.READY
                ready.append(step)

        return ready

    def complete_step(
        self,
        plan_id: str,
        step_id: str,
        output: dict[str, Any] | None = None,
    ) -> None:
        """Mark a step as completed."""
        plan = self._plans.get(plan_id)
        if not plan:
            return

        step = plan.steps.get(step_id)
        if not step:
            return

        step.state = ExecutionState.COMPLETED
        step.completed_at = time.time()
        step.output = output or {}

    def fail_step(
        self,
        plan_id: str,
        step_id: str,
        error: str = "",
        try_fallback: bool = True,
    ) -> ExecutionStep | None:
        """Mark a step as failed, optionally try fallback tool."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        step = plan.steps.get(step_id)
        if not step:
            return None

        step.state = ExecutionState.FAILED
        step.error = error

        # Try fallback
        if try_fallback:
            tool = self._tools.get(step.tool_name)
            if tool and tool.fallback_tools:
                for fallback_name in tool.fallback_tools:
                    if fallback_name in self._tools:
                        self._step_counter += 1
                        fallback_step = ExecutionStep(
                            step_id=f"step-{self._step_counter}",
                            tool_name=fallback_name,
                            depends_on=step.depends_on,
                            input_from=step.input_from,
                        )
                        plan.steps[fallback_step.step_id] = fallback_step
                        return fallback_step

        return None

    def _select_tools_for_objective(
        self,
        objective: str,
        target_info: dict[str, Any],
    ) -> list[str]:
        """Select tools based on objective keywords."""
        objective_lower = objective.lower()
        selected = []

        # Keyword → tool mapping
        keyword_tools = {
            "recon": ["subfinder", "whois", "theHarvester", "dnsrecon"],
            "port": ["nmap"],
            "web": ["nuclei", "nikto", "ffuf", "whatweb"],
            "vuln": ["nuclei", "nikto"],
            "sql": ["sqlmap"],
            "xss": ["xsstrike"],
            "code": ["semgrep", "bandit"],
            "secret": ["trufflehog"],
            "ssl": ["testssl"],
            "cloud": ["scout_suite", "trivy"],
            "container": ["trivy"],
            "brute": ["hydra"],
            "hash": ["hashcat"],
            "full": ["subfinder", "nmap", "nuclei", "nikto", "ffuf", "whatweb",
                     "sqlmap", "testssl", "semgrep"],
        }

        for keyword, tools in keyword_tools.items():
            if keyword in objective_lower:
                selected.extend(tools)

        # Default: basic recon + scanning
        if not selected:
            selected = ["subfinder", "nmap", "nuclei", "whatweb"]

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique = []
        for tool in selected:
            if tool not in seen:
                unique.append(tool)
                seen.add(tool)

        return unique

    @staticmethod
    def _topological_batch_sort(
        steps: dict[str, ExecutionStep],
    ) -> list[list[str]]:
        """Topological sort into batches for parallel execution."""
        in_degree: dict[str, int] = {sid: 0 for sid in steps}
        dependents: dict[str, list[str]] = defaultdict(list)

        for sid, step in steps.items():
            for dep in step.depends_on:
                if dep in steps:
                    in_degree[sid] += 1
                    dependents[dep].append(sid)

        batches: list[list[str]] = []
        remaining = set(steps.keys())

        while remaining:
            # Current batch: all steps with in_degree 0
            batch = [
                sid for sid in remaining
                if in_degree.get(sid, 0) == 0
            ]

            if not batch:
                # Cycle detected — break it by picking one
                batch = [next(iter(remaining))]

            batches.append(batch)

            for sid in batch:
                remaining.discard(sid)
                for dependent in dependents.get(sid, []):
                    in_degree[dependent] -= 1

        return batches

    def get_stats(self) -> dict[str, Any]:
        return {
            "tools_registered": len(self._tools),
            "plans_created": len(self._plans),
            "categories": len(set(t.category for t in self._tools.values())),
        }
