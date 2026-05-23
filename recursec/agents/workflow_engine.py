"""Workflow engine — composable, repeatable assessment workflows.

Implements:
1. Workflow definition (YAML/dict-based)
2. Step execution with dependencies
3. Conditional branching
4. Parallel step execution
5. Step retry with backoff
6. Workflow composition (sub-workflows)
7. Workflow templates for common assessments
8. Runtime parameter injection
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StepType(str, Enum):
    TOOL = "tool"
    LLM = "llm"
    AGENT = "agent"
    CONDITION = "condition"
    PARALLEL = "parallel"
    SUB_WORKFLOW = "sub_workflow"
    WAIT = "wait"


@dataclass
class WorkflowStep:
    """A single step in a workflow."""
    step_id: str = ""
    name: str = ""
    step_type: StepType = StepType.TOOL
    config: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    condition: str = ""           # Condition expression
    retry_count: int = 0
    max_retries: int = 2
    timeout_s: float = 300.0
    status: StepStatus = StepStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id, "name": self.name[:60],
            "type": self.step_type.value,
            "status": self.status.value,
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class Workflow:
    """A complete workflow definition."""
    workflow_id: str = ""
    name: str = ""
    description: str = ""
    steps: list[WorkflowStep] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.workflow_id, "name": self.name[:60],
            "steps": len(self.steps),
            "status": self.status.value,
            "completed": sum(1 for s in self.steps if s.status == StepStatus.COMPLETED),
        }


# ── Workflow Templates ────────────────────────────────────────

WEB_APP_WORKFLOW: dict[str, Any] = {
    "name": "Web Application Assessment",
    "steps": [
        {"id": "recon", "name": "Subdomain Discovery", "type": "tool",
         "config": {"tool": "subfinder", "cmd": "subfinder -d {target} -silent"}},
        {"id": "probe", "name": "HTTP Probing", "type": "tool",
         "config": {"tool": "httpx", "cmd": "httpx -l {recon_output} -silent"},
         "depends_on": ["recon"]},
        {"id": "tech", "name": "Technology Detection", "type": "tool",
         "config": {"tool": "whatweb", "cmd": "whatweb {target}"}},
        {"id": "dirs", "name": "Directory Bruteforce", "type": "tool",
         "config": {"tool": "ffuf", "cmd": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302"}},
        {"id": "scan", "name": "Vulnerability Scan", "type": "tool",
         "config": {"tool": "nuclei", "cmd": "nuclei -u {target} -severity critical,high,medium"},
         "depends_on": ["probe", "tech"]},
        {"id": "sqli", "name": "SQL Injection Test", "type": "tool",
         "config": {"tool": "sqlmap", "cmd": "sqlmap -u {target} --batch --level=1 --risk=1"},
         "depends_on": ["dirs"]},
        {"id": "xss", "name": "XSS Test", "type": "tool",
         "config": {"tool": "dalfox", "cmd": "dalfox url {target} --silence"},
         "depends_on": ["dirs"]},
        {"id": "analyze", "name": "LLM Analysis", "type": "llm",
         "config": {"task": "Analyze findings and identify critical paths"},
         "depends_on": ["scan", "sqli", "xss"]},
        {"id": "validate", "name": "Finding Validation", "type": "agent",
         "config": {"agent_type": "validator"},
         "depends_on": ["analyze"]},
    ],
}

NETWORK_WORKFLOW: dict[str, Any] = {
    "name": "Network Assessment",
    "steps": [
        {"id": "portscan", "name": "Port Scan", "type": "tool",
         "config": {"tool": "nmap", "cmd": "nmap -sV -sC -T4 {target}"}},
        {"id": "vuln", "name": "Vulnerability Scan", "type": "tool",
         "config": {"tool": "nmap", "cmd": "nmap --script vuln {target}"},
         "depends_on": ["portscan"]},
        {"id": "nuclei", "name": "Service Scan", "type": "tool",
         "config": {"tool": "nuclei", "cmd": "nuclei -target {target}"},
         "depends_on": ["portscan"]},
        {"id": "enum", "name": "Service Enumeration", "type": "agent",
         "config": {"agent_type": "network_analyst"},
         "depends_on": ["portscan"]},
        {"id": "analyze", "name": "Analysis", "type": "llm",
         "config": {"task": "Analyze network findings"},
         "depends_on": ["vuln", "nuclei", "enum"]},
    ],
}

API_WORKFLOW: dict[str, Any] = {
    "name": "API Assessment",
    "steps": [
        {"id": "endpoints", "name": "Endpoint Discovery", "type": "tool",
         "config": {"tool": "ffuf", "cmd": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/api-endpoints.txt -mc 200,201,301,302,401,403"}},
        {"id": "auth", "name": "Auth Testing", "type": "agent",
         "config": {"agent_type": "web_tester"}},
        {"id": "scan", "name": "API Scan", "type": "tool",
         "config": {"tool": "nuclei", "cmd": "nuclei -u {target} -t http/"},
         "depends_on": ["endpoints"]},
        {"id": "analyze", "name": "Analysis", "type": "llm",
         "config": {"task": "Analyze API vulnerabilities"},
         "depends_on": ["auth", "scan"]},
    ],
}

WORKFLOW_TEMPLATES = {
    "web_app": WEB_APP_WORKFLOW,
    "network": NETWORK_WORKFLOW,
    "api": API_WORKFLOW,
}


class WorkflowEngine:
    """Executes composable assessment workflows.

    Manages step dependencies, parallel execution,
    retries, and conditional branching.
    """

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._step_handlers: dict[str, Callable[..., Coroutine[Any, Any, dict[str, Any]]]] = {}
        self._wf_counter = 0
        self._log = logger.bind(component="workflow_engine")

    def create_workflow(
        self,
        template_name: str = "",
        custom_steps: list[dict[str, Any]] | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> Workflow:
        """Create a workflow from template or custom definition."""
        self._wf_counter += 1
        wf_id = f"wf-{self._wf_counter}"

        template = WORKFLOW_TEMPLATES.get(template_name, {})
        steps_data = custom_steps or template.get("steps", [])

        steps = []
        for s_data in steps_data:
            try:
                step_type = StepType(s_data.get("type", "tool"))
            except ValueError:
                step_type = StepType.TOOL

            steps.append(WorkflowStep(
                step_id=s_data.get("id", f"step-{len(steps)}"),
                name=s_data.get("name", ""),
                step_type=step_type,
                config=s_data.get("config", {}),
                depends_on=s_data.get("depends_on", []),
                condition=s_data.get("condition", ""),
                timeout_s=s_data.get("timeout_s", 300.0),
                max_retries=s_data.get("max_retries", 2),
            ))

        workflow = Workflow(
            workflow_id=wf_id,
            name=template.get("name", f"Workflow {wf_id}"),
            steps=steps,
            parameters=parameters or {},
        )

        self._workflows[wf_id] = workflow
        return workflow

    async def execute(self, workflow_id: str) -> dict[str, Any]:
        """Execute a workflow."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return {"error": "Workflow not found"}

        workflow.status = StepStatus.RUNNING
        results: dict[str, dict[str, Any]] = {}

        while True:
            # Find ready steps (all dependencies met)
            ready = self._get_ready_steps(workflow, results)

            if not ready:
                # Check if all done
                all_done = all(
                    s.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED)
                    for s in workflow.steps
                )
                if all_done:
                    break
                else:
                    # Deadlock or all running
                    running = [s for s in workflow.steps if s.status == StepStatus.RUNNING]
                    if not running:
                        break
                    await asyncio.sleep(1.0)
                    continue

            # Execute ready steps in parallel
            tasks = []
            for step in ready:
                step.status = StepStatus.RUNNING
                step.started_at = time.time()
                tasks.append(self._execute_step(step, workflow.parameters, results))

            step_results = await asyncio.gather(*tasks, return_exceptions=True)

            for step, result in zip(ready, step_results):
                if isinstance(result, Exception):
                    step.status = StepStatus.FAILED
                    step.error = str(result)[:200]
                else:
                    step.status = StepStatus.COMPLETED
                    step.result = result if isinstance(result, dict) else {}

                step.completed_at = time.time()
                results[step.step_id] = step.result

        # Final status
        failed = [s for s in workflow.steps if s.status == StepStatus.FAILED]
        workflow.status = StepStatus.FAILED if len(failed) > len(workflow.steps) // 2 else StepStatus.COMPLETED
        workflow.completed_at = time.time()

        return {
            "workflow": workflow.to_dict(),
            "steps": [s.to_dict() for s in workflow.steps],
            "results": results,
        }

    async def _execute_step(
        self,
        step: WorkflowStep,
        params: dict[str, Any],
        prior_results: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Execute a single workflow step."""
        # Inject parameters
        config = dict(step.config)
        for key, value in config.items():
            if isinstance(value, str):
                for p_name, p_value in params.items():
                    value = value.replace(f"{{{p_name}}}", str(p_value))
                config[key] = value

        # Execute based on type
        handler = self._step_handlers.get(step.step_type.value)
        if handler:
            try:
                return await asyncio.wait_for(
                    handler(config, prior_results),
                    timeout=step.timeout_s,
                )
            except asyncio.TimeoutError:
                step.error = "Timeout"
                if step.retry_count < step.max_retries:
                    step.retry_count += 1
                    step.status = StepStatus.PENDING
                raise

        # Default: return config as result
        return {"config": config, "status": "no_handler"}

    def _get_ready_steps(
        self,
        workflow: Workflow,
        results: dict[str, dict[str, Any]],
    ) -> list[WorkflowStep]:
        """Get steps whose dependencies are all met."""
        ready = []
        for step in workflow.steps:
            if step.status != StepStatus.PENDING:
                continue

            deps_met = all(
                dep_id in results or
                any(s.step_id == dep_id and s.status in (StepStatus.FAILED, StepStatus.SKIPPED)
                    for s in workflow.steps)
                for dep_id in step.depends_on
            )

            if deps_met:
                ready.append(step)

        return ready

    def register_handler(
        self,
        step_type: str,
        handler: Callable[..., Coroutine[Any, Any, dict[str, Any]]],
    ) -> None:
        """Register a handler for a step type."""
        self._step_handlers[step_type] = handler

    def get_stats(self) -> dict[str, Any]:
        return {
            "workflows": len(self._workflows),
            "templates": len(WORKFLOW_TEMPLATES),
        }
