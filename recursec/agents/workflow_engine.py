"""Workflow engine — dependency-aware parallel task execution.

Manages complex multi-step security workflows:
1. Define workflows as directed acyclic graphs (DAGs)
2. Automatically parallelize independent steps
3. Handle dependencies between steps
4. Conditional branching based on results
5. Retry failed steps with backoff
6. Checkpoint/resume for long-running workflows
7. Dynamic step insertion based on findings
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StepStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StepType(str, Enum):
    TOOL = "tool"
    LLM_REASONING = "llm_reasoning"
    ANALYSIS = "analysis"
    DECISION = "decision"
    SPAWN_AGENT = "spawn_agent"
    CHECKPOINT = "checkpoint"
    CONDITIONAL = "conditional"


@dataclass
class WorkflowStep:
    """A single step in a workflow."""
    step_id: str = ""
    name: str = ""
    step_type: StepType = StepType.TOOL
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    retries: int = 0
    max_retries: int = 2
    timeout_s: float = 300.0
    condition: str = ""
    on_success: list[str] = field(default_factory=list)
    on_failure: list[str] = field(default_factory=list)
    model_id: str = ""
    kb_domains: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:8],
            "name": self.name[:15],
            "type": self.step_type.value[:6],
            "status": self.status.value[:6],
            "deps": len(self.dependencies),
        }


@dataclass
class Workflow:
    """A complete workflow with steps and dependencies."""
    workflow_id: str = ""
    name: str = ""
    description: str = ""
    steps: dict[str, WorkflowStep] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        statuses = {}
        for step in self.steps.values():
            key = step.status.value
            statuses[key] = statuses.get(key, 0) + 1
        return {
            "id": self.workflow_id[:8],
            "name": self.name[:15],
            "steps": len(self.steps),
            "statuses": statuses,
            "findings": len(self.findings),
        }


# Predefined workflow templates
WORKFLOW_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_full_scan": [
        {"id": "recon_dns", "name": "DNS Recon", "type": "tool", "tool": "dig", "deps": []},
        {"id": "recon_sub", "name": "Subdomain Enum", "type": "tool", "tool": "subfinder", "deps": []},
        {"id": "recon_tech", "name": "Tech Fingerprint", "type": "tool", "tool": "whatweb", "deps": []},
        {"id": "port_scan", "name": "Port Scan", "type": "tool", "tool": "nmap", "deps": ["recon_dns"]},
        {"id": "web_scan", "name": "Web Vuln Scan", "type": "tool", "tool": "nuclei", "deps": ["recon_tech"]},
        {"id": "dir_fuzz", "name": "Directory Fuzz", "type": "tool", "tool": "ffuf", "deps": ["recon_tech"]},
        {"id": "analyze", "name": "Analyze Results", "type": "llm_reasoning", "model": "whiterabbit", "deps": ["port_scan", "web_scan", "dir_fuzz"]},
        {"id": "deep_scan", "name": "Deep Scan", "type": "conditional", "condition": "findings > 0", "deps": ["analyze"]},
        {"id": "sqli_test", "name": "SQLi Test", "type": "tool", "tool": "sqlmap", "deps": ["deep_scan"]},
        {"id": "report", "name": "Generate Report", "type": "llm_reasoning", "model": "hermes-4-14b", "deps": ["sqli_test", "analyze"]},
    ],
    "network_pentest": [
        {"id": "host_disc", "name": "Host Discovery", "type": "tool", "tool": "nmap", "deps": []},
        {"id": "port_scan", "name": "Full Port Scan", "type": "tool", "tool": "masscan", "deps": ["host_disc"]},
        {"id": "svc_enum", "name": "Service Enum", "type": "tool", "tool": "nmap", "deps": ["port_scan"]},
        {"id": "vuln_scan", "name": "Vuln Scan", "type": "tool", "tool": "nuclei", "deps": ["svc_enum"]},
        {"id": "smb_enum", "name": "SMB Enum", "type": "tool", "tool": "crackmapexec", "deps": ["svc_enum"]},
        {"id": "analyze", "name": "Analyze", "type": "llm_reasoning", "model": "whiterabbit", "deps": ["vuln_scan", "smb_enum"]},
        {"id": "exploit", "name": "Exploit", "type": "spawn_agent", "deps": ["analyze"]},
        {"id": "report", "name": "Report", "type": "llm_reasoning", "model": "hermes-4-14b", "deps": ["exploit"]},
    ],
    "code_review": [
        {"id": "clone", "name": "Clone Repo", "type": "tool", "tool": "git", "deps": []},
        {"id": "secrets", "name": "Secret Scan", "type": "tool", "tool": "gitleaks", "deps": ["clone"]},
        {"id": "sast", "name": "SAST Scan", "type": "tool", "tool": "semgrep", "deps": ["clone"]},
        {"id": "deps", "name": "Dep Scan", "type": "tool", "tool": "trivy", "deps": ["clone"]},
        {"id": "llm_review", "name": "LLM Code Review", "type": "llm_reasoning", "model": "qwen-coder-14b", "deps": ["clone"], "kb": ["advanced_discovery"]},
        {"id": "analyze", "name": "Correlate", "type": "llm_reasoning", "model": "deepseek-r1", "deps": ["secrets", "sast", "deps", "llm_review"]},
        {"id": "report", "name": "Report", "type": "llm_reasoning", "model": "hermes-4-14b", "deps": ["analyze"]},
    ],
}


class WorkflowEngine:
    """Executes workflows with dependency management."""

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._workflow_counter = 0
        self._log = logger.bind(component="workflow_engine")

    def create_from_template(
        self,
        template_name: str,
        target: str = "",
        name: str = "",
    ) -> Workflow | None:
        """Create a workflow from a template."""
        template = WORKFLOW_TEMPLATES.get(template_name)
        if not template:
            return None

        self._workflow_counter += 1
        workflow = Workflow(
            workflow_id=f"wf-{self._workflow_counter}",
            name=name or template_name,
            description=f"Auto-generated from template '{template_name}' for target '{target}'",
        )

        for step_def in template:
            step = WorkflowStep(
                step_id=step_def["id"],
                name=step_def["name"],
                step_type=StepType(step_def["type"]),
                tool_name=step_def.get("tool", ""),
                dependencies=step_def.get("deps", []),
                tool_args={"target": target} if target else {},
                model_id=step_def.get("model", ""),
                kb_domains=step_def.get("kb", []),
                condition=step_def.get("condition", ""),
            )
            workflow.steps[step.step_id] = step

        self._workflows[workflow.workflow_id] = workflow
        return workflow

    def create_custom(
        self,
        name: str,
        steps: list[dict[str, Any]],
    ) -> Workflow:
        """Create a custom workflow."""
        self._workflow_counter += 1
        workflow = Workflow(
            workflow_id=f"wf-{self._workflow_counter}",
            name=name,
        )
        for step_def in steps:
            step = WorkflowStep(
                step_id=step_def.get("id", f"step-{len(workflow.steps)}"),
                name=step_def.get("name", ""),
                step_type=StepType(step_def.get("type", "tool")),
                tool_name=step_def.get("tool", ""),
                dependencies=step_def.get("deps", []),
                tool_args=step_def.get("args", {}),
                model_id=step_def.get("model", ""),
                kb_domains=step_def.get("kb", []),
            )
            workflow.steps[step.step_id] = step
        self._workflows[workflow.workflow_id] = workflow
        return workflow

    def get_ready_steps(self, workflow_id: str) -> list[WorkflowStep]:
        """Get steps whose dependencies are all completed."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return []

        ready = []
        for step in workflow.steps.values():
            if step.status != StepStatus.PENDING:
                continue
            deps_met = all(
                workflow.steps.get(dep_id, WorkflowStep()).status == StepStatus.COMPLETED
                for dep_id in step.dependencies
            )
            if deps_met:
                step.status = StepStatus.READY
                ready.append(step)
        return ready

    def complete_step(
        self,
        workflow_id: str,
        step_id: str,
        result: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Mark a step as completed."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return
        step = workflow.steps.get(step_id)
        if not step:
            return
        step.status = StepStatus.COMPLETED
        step.result = result
        step.completed_at = time.time()
        if findings:
            workflow.findings.extend(findings)

        # Check if workflow is done
        all_done = all(
            s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED)
            for s in workflow.steps.values()
        )
        if all_done:
            workflow.status = StepStatus.COMPLETED
            workflow.completed_at = time.time()

    def fail_step(
        self,
        workflow_id: str,
        step_id: str,
        error: str,
    ) -> bool:
        """Mark a step as failed. Returns True if retryable."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False
        step = workflow.steps.get(step_id)
        if not step:
            return False
        step.retries += 1
        if step.retries <= step.max_retries:
            step.status = StepStatus.PENDING
            return True
        step.status = StepStatus.FAILED
        step.result = {"error": error}
        return False

    def add_dynamic_step(
        self,
        workflow_id: str,
        after_step_id: str,
        new_step: dict[str, Any],
    ) -> WorkflowStep | None:
        """Dynamically add a step based on findings."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return None
        step = WorkflowStep(
            step_id=new_step.get("id", f"dyn-{len(workflow.steps)}"),
            name=new_step.get("name", "Dynamic step"),
            step_type=StepType(new_step.get("type", "tool")),
            tool_name=new_step.get("tool", ""),
            dependencies=[after_step_id],
            tool_args=new_step.get("args", {}),
        )
        workflow.steps[step.step_id] = step
        return step

    def get_execution_order(self, workflow_id: str) -> list[list[str]]:
        """Get topologically sorted execution layers (parallel groups)."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return []

        layers: list[list[str]] = []
        completed: set[str] = set()

        while len(completed) < len(workflow.steps):
            layer = []
            for step_id, step in workflow.steps.items():
                if step_id in completed:
                    continue
                if all(dep in completed for dep in step.dependencies):
                    layer.append(step_id)
            if not layer:
                break  # Circular dependency or error
            layers.append(layer)
            completed.update(layer)
        return layers

    def get_stats(self) -> dict[str, Any]:
        return {
            "workflows": len(self._workflows),
            "templates": list(WORKFLOW_TEMPLATES.keys()),
        }

    def build_workflow_prompt(self, workflow_id: str = "") -> str:
        """Build LLM prompt with workflow state."""
        if workflow_id and workflow_id in self._workflows:
            wf = self._workflows[workflow_id]
            lines = [f"## Workflow: {wf.name}"]
            for step in wf.steps.values():
                dep_str = f" (after {','.join(step.dependencies)})" if step.dependencies else ""
                lines.append(f"  [{step.status.value}] {step.name}{dep_str}")
            lines.append(f"Findings so far: {len(wf.findings)}")
            return "\n".join(lines)
        lines = ["## Workflow Engine"]
        lines.append(f"Templates: {', '.join(WORKFLOW_TEMPLATES.keys())}")
        lines.append(f"Active workflows: {len(self._workflows)}")
        return "\n".join(lines)
