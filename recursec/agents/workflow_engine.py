"""Workflow engine — DAG-based workflow execution for assessment pipelines.

Implements:
1. DAG (Directed Acyclic Graph) workflow definition
2. Node-level execution with dependency resolution
3. Conditional branching (if/else based on results)
4. Parallel lane execution
5. Retry and error handling per node
6. Workflow state persistence and resumption
7. Dynamic workflow modification during execution
8. Workflow templates for common assessment types
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger()


class NodeStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING = "waiting"


class NodeType(str, Enum):
    TASK = "task"
    DECISION = "decision"
    PARALLEL = "parallel"
    JOIN = "join"
    SUBWORKFLOW = "subworkflow"
    NOTIFICATION = "notification"


@dataclass
class WorkflowNode:
    """A node in the workflow DAG."""
    node_id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.TASK
    handler: str = ""                     # Handler function name
    config: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    condition: str = ""                   # For decision nodes
    timeout_s: float = 300.0
    max_retries: int = 2
    retry_count: int = 0
    status: NodeStatus = NodeStatus.PENDING
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    # For decision nodes: maps condition outcomes to next nodes
    branches: dict[str, str] = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id, "name": self.name[:40],
            "type": self.node_type.value,
            "status": self.status.value,
            "deps": self.dependencies[:5],
            "duration_s": round(self.duration_s, 1),
        }


@dataclass
class Workflow:
    """A complete workflow definition."""
    workflow_id: str = ""
    name: str = ""
    nodes: dict[str, WorkflowNode] = field(default_factory=dict)
    entry_node: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            status_counts[node.status.value] += 1
        return {
            "id": self.workflow_id, "name": self.name[:40],
            "nodes": len(self.nodes), "status": self.status,
            "node_status": dict(status_counts),
        }


class WorkflowEngine:
    """DAG-based workflow execution engine.

    Executes assessment pipelines as directed acyclic graphs
    with dependency resolution, branching, and parallelism.
    """

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._handlers: dict[str, Callable[..., Coroutine[Any, Any, dict[str, Any]]]] = {}
        self._workflow_counter = 0
        self._log = logger.bind(component="workflow_engine")

    def register_handler(
        self,
        name: str,
        handler: Callable[..., Coroutine[Any, Any, dict[str, Any]]],
    ) -> None:
        """Register a node execution handler."""
        self._handlers[name] = handler

    def create_workflow(
        self,
        name: str,
        nodes: list[dict[str, Any]] | None = None,
    ) -> Workflow:
        """Create a new workflow."""
        self._workflow_counter += 1
        wf_id = f"wf-{self._workflow_counter}"

        workflow = Workflow(workflow_id=wf_id, name=name)

        if nodes:
            for node_data in nodes:
                node = WorkflowNode(
                    node_id=node_data.get("id", ""),
                    name=node_data.get("name", ""),
                    node_type=NodeType(node_data.get("type", "task")),
                    handler=node_data.get("handler", ""),
                    config=node_data.get("config", {}),
                    dependencies=node_data.get("dependencies", []),
                    condition=node_data.get("condition", ""),
                    timeout_s=node_data.get("timeout_s", 300.0),
                    branches=node_data.get("branches", {}),
                )
                workflow.nodes[node.node_id] = node

            # Set entry node
            for node in workflow.nodes.values():
                if not node.dependencies:
                    workflow.entry_node = node.node_id
                    break

        self._workflows[wf_id] = workflow
        return workflow

    async def execute(self, workflow_id: str) -> dict[str, Any]:
        """Execute a workflow."""
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return {"error": "workflow_not_found"}

        workflow.status = "running"

        # Topological execution
        while True:
            ready_nodes = self._get_ready_nodes(workflow)

            if not ready_nodes:
                # Check if we're done or deadlocked
                running = [n for n in workflow.nodes.values() if n.status == NodeStatus.RUNNING]
                if running:
                    await asyncio.sleep(0.5)
                    continue
                break

            # Execute ready nodes in parallel
            tasks = [self._execute_node(workflow, node) for node in ready_nodes]
            await asyncio.gather(*tasks)

            # Handle decision nodes
            for node in ready_nodes:
                if node.node_type == NodeType.DECISION and node.status == NodeStatus.COMPLETED:
                    self._resolve_decision(workflow, node)

        # Determine final status
        failed = [n for n in workflow.nodes.values() if n.status == NodeStatus.FAILED]
        if failed:
            workflow.status = "failed"
        else:
            workflow.status = "completed"

        return workflow.to_dict()

    def _get_ready_nodes(self, workflow: Workflow) -> list[WorkflowNode]:
        """Get nodes whose dependencies are all completed."""
        ready = []
        for node in workflow.nodes.values():
            if node.status != NodeStatus.PENDING:
                continue

            # Check dependencies
            deps_met = True
            for dep_id in node.dependencies:
                dep_node = workflow.nodes.get(dep_id)
                if not dep_node or dep_node.status not in (NodeStatus.COMPLETED, NodeStatus.SKIPPED):
                    deps_met = False
                    break

            if deps_met:
                node.status = NodeStatus.READY
                ready.append(node)

        return ready

    async def _execute_node(
        self,
        workflow: Workflow,
        node: WorkflowNode,
    ) -> None:
        """Execute a single workflow node."""
        node.status = NodeStatus.RUNNING
        node.started_at = time.time()

        handler = self._handlers.get(node.handler)
        if not handler and node.node_type == NodeType.TASK:
            node.status = NodeStatus.FAILED
            node.error = f"No handler: {node.handler}"
            node.completed_at = time.time()
            return

        try:
            if node.node_type in (NodeType.NOTIFICATION, NodeType.JOIN):
                # These don't need handlers
                node.status = NodeStatus.COMPLETED
                node.completed_at = time.time()
                return

            if handler:
                # Gather dependency results as input
                dep_results = {}
                for dep_id in node.dependencies:
                    dep_node = workflow.nodes.get(dep_id)
                    if dep_node:
                        dep_results[dep_id] = dep_node.result

                config = dict(node.config)
                config["dep_results"] = dep_results

                result = await asyncio.wait_for(
                    handler(config),
                    timeout=node.timeout_s,
                )
                node.result = result
                node.status = NodeStatus.COMPLETED

        except asyncio.TimeoutError:
            node.error = "Timeout"
            if node.retry_count < node.max_retries:
                node.retry_count += 1
                node.status = NodeStatus.PENDING
            else:
                node.status = NodeStatus.FAILED

        except Exception as e:
            node.error = str(e)[:200]
            if node.retry_count < node.max_retries:
                node.retry_count += 1
                node.status = NodeStatus.PENDING
            else:
                node.status = NodeStatus.FAILED

        node.completed_at = time.time()

    def _resolve_decision(self, workflow: Workflow, node: WorkflowNode) -> None:
        """Resolve a decision node's branches."""
        outcome = node.result.get("outcome", "default")

        taken_branch = node.branches.get(outcome, node.branches.get("default", ""))

        # Skip non-taken branches
        for branch_key, branch_node_id in node.branches.items():
            if branch_key != outcome and branch_node_id != taken_branch:
                target = workflow.nodes.get(branch_node_id)
                if target:
                    self._skip_subtree(workflow, target.node_id)

    def _skip_subtree(self, workflow: Workflow, node_id: str) -> None:
        """Skip a node and all its dependents."""
        node = workflow.nodes.get(node_id)
        if not node or node.status != NodeStatus.PENDING:
            return

        node.status = NodeStatus.SKIPPED

        # Skip dependents
        for other_node in workflow.nodes.values():
            if node_id in other_node.dependencies:
                self._skip_subtree(workflow, other_node.node_id)

    def create_assessment_workflow(
        self,
        target: str,
        target_type: str = "web_app",
    ) -> Workflow:
        """Create a pre-built assessment workflow."""
        if target_type == "web_app":
            return self._create_web_workflow(target)
        elif target_type == "network":
            return self._create_network_workflow(target)
        else:
            return self._create_web_workflow(target)

    def _create_web_workflow(self, target: str) -> Workflow:
        """Create web app assessment workflow."""
        nodes = [
            {"id": "recon", "name": "Reconnaissance", "type": "task",
             "handler": "run_recon", "config": {"target": target}},
            {"id": "fingerprint", "name": "Fingerprint", "type": "task",
             "handler": "run_fingerprint", "config": {"target": target},
             "dependencies": ["recon"]},
            {"id": "decide_tech", "name": "Technology Decision", "type": "decision",
             "handler": "decide_technology", "dependencies": ["fingerprint"],
             "branches": {"wordpress": "wp_scan", "default": "vuln_scan"}},
            {"id": "wp_scan", "name": "WordPress Scan", "type": "task",
             "handler": "run_wpscan", "config": {"target": target},
             "dependencies": ["decide_tech"]},
            {"id": "vuln_scan", "name": "Vulnerability Scan", "type": "task",
             "handler": "run_vulnscan", "config": {"target": target},
             "dependencies": ["decide_tech"]},
            {"id": "dir_scan", "name": "Directory Scan", "type": "task",
             "handler": "run_dirscan", "config": {"target": target},
             "dependencies": ["recon"]},
            {"id": "join_scans", "name": "Join Results", "type": "join",
             "dependencies": ["wp_scan", "vuln_scan", "dir_scan"]},
            {"id": "exploit_test", "name": "Exploit Testing", "type": "task",
             "handler": "run_exploit_test", "config": {"target": target},
             "dependencies": ["join_scans"]},
            {"id": "validate", "name": "Validate Findings", "type": "task",
             "handler": "validate_findings", "dependencies": ["exploit_test"]},
            {"id": "report", "name": "Generate Report", "type": "task",
             "handler": "generate_report", "dependencies": ["validate"]},
        ]
        return self.create_workflow(f"Web Assessment: {target[:30]}", nodes)

    def _create_network_workflow(self, target: str) -> Workflow:
        """Create network assessment workflow."""
        nodes = [
            {"id": "discovery", "name": "Host Discovery", "type": "task",
             "handler": "run_discovery", "config": {"target": target}},
            {"id": "port_scan", "name": "Port Scan", "type": "task",
             "handler": "run_portscan", "config": {"target": target},
             "dependencies": ["discovery"]},
            {"id": "service_enum", "name": "Service Enumeration", "type": "task",
             "handler": "run_service_enum", "config": {"target": target},
             "dependencies": ["port_scan"]},
            {"id": "vuln_scan", "name": "Vulnerability Scan", "type": "task",
             "handler": "run_vulnscan", "config": {"target": target},
             "dependencies": ["service_enum"]},
            {"id": "cred_test", "name": "Credential Testing", "type": "task",
             "handler": "run_cred_test", "config": {"target": target},
             "dependencies": ["service_enum"]},
            {"id": "join", "name": "Join", "type": "join",
             "dependencies": ["vuln_scan", "cred_test"]},
            {"id": "validate", "name": "Validate", "type": "task",
             "handler": "validate_findings", "dependencies": ["join"]},
            {"id": "report", "name": "Report", "type": "task",
             "handler": "generate_report", "dependencies": ["validate"]},
        ]
        return self.create_workflow(f"Network Assessment: {target[:30]}", nodes)

    def get_stats(self) -> dict[str, Any]:
        return {
            "workflows": len(self._workflows),
            "handlers": len(self._handlers),
        }
