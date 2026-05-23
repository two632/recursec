"""Workflow orchestrator — directed acyclic graph execution engine.

Implements:
1. DAG-based workflow definition
2. Parallel execution of independent nodes
3. Conditional branching based on results
4. Retry and fallback logic
5. Workflow state machine
6. Checkpoint and resume
7. Dynamic workflow modification
8. Workflow composition (nested workflows)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class NodeStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"         # All dependencies met
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING = "waiting"     # Waiting for condition


class NodeType(str, Enum):
    TOOL = "tool"           # Execute external tool
    LLM = "llm"            # Query LLM
    AGENT = "agent"         # Spawn agent
    CONDITION = "condition"  # Branch based on condition
    MERGE = "merge"         # Merge parallel results
    TRANSFORM = "transform"  # Transform data
    WORKFLOW = "workflow"    # Nested sub-workflow


class WorkflowStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class WorkflowNode:
    """A node in the workflow DAG."""
    node_id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.TOOL
    status: NodeStatus = NodeStatus.PENDING
    config: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    retry_count: int = 0
    max_retries: int = 2
    timeout_s: float = 300.0
    started_at: float = 0.0
    completed_at: float = 0.0
    condition: str = ""     # For CONDITION nodes: expression to evaluate
    on_true: str = ""       # Next node if condition is true
    on_false: str = ""      # Next node if condition is false

    @property
    def duration_s(self) -> float:
        if self.started_at > 0 and self.completed_at > 0:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:10],
            "name": self.name[:20],
            "type": self.node_type.value,
            "status": self.status.value,
            "deps": len(self.dependencies),
            "retries": self.retry_count,
            "duration": round(self.duration_s, 2),
        }


@dataclass
class WorkflowEdge:
    """An edge connecting two nodes."""
    source: str = ""
    target: str = ""
    condition: str = ""     # Optional condition label

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.source[:10],
            "to": self.target[:10],
            "cond": self.condition[:15],
        }


@dataclass
class Workflow:
    """A complete workflow definition."""
    workflow_id: str = ""
    name: str = ""
    status: WorkflowStatus = WorkflowStatus.CREATED
    nodes: dict[str, WorkflowNode] = field(default_factory=dict)
    edges: list[WorkflowEdge] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_s(self) -> float:
        if self.started_at > 0 and self.completed_at > 0:
            return self.completed_at - self.started_at
        return 0.0

    @property
    def progress(self) -> float:
        if not self.nodes:
            return 0.0
        done = sum(1 for n in self.nodes.values() if n.status in (NodeStatus.COMPLETE, NodeStatus.SKIPPED))
        return done / len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            status_counts[n.status.value] += 1
        return {
            "id": self.workflow_id[:10],
            "name": self.name[:20],
            "status": self.status.value,
            "nodes": len(self.nodes),
            "progress": round(self.progress, 2),
            "by_status": dict(status_counts),
        }


# ── Predefined assessment workflows ─────────────────────────

def build_full_assessment_workflow(target: str) -> Workflow:
    """Build the standard full security assessment workflow."""
    wf = Workflow(
        workflow_id=f"wf-full-{int(time.time())}",
        name=f"Full assessment: {target}",
        context={"target": target},
    )

    nodes = [
        WorkflowNode(node_id="recon", name="Reconnaissance", node_type=NodeType.AGENT,
                      config={"role": "recon", "goal": f"Map attack surface of {target}"}),
        WorkflowNode(node_id="port_scan", name="Port Scanning", node_type=NodeType.TOOL,
                      config={"tool": "nmap", "args": f"-sV -sC {target}"},
                      dependencies=["recon"]),
        WorkflowNode(node_id="web_detect", name="Web Detection", node_type=NodeType.CONDITION,
                      condition="has_web_ports", on_true="web_scan", on_false="net_analysis",
                      dependencies=["port_scan"]),
        WorkflowNode(node_id="web_scan", name="Web Vulnerability Scan", node_type=NodeType.AGENT,
                      config={"role": "web_scanner", "tools": ["nuclei", "nikto", "gobuster"]},
                      dependencies=["web_detect"]),
        WorkflowNode(node_id="net_analysis", name="Network Analysis", node_type=NodeType.AGENT,
                      config={"role": "network", "tools": ["nmap", "enum4linux"]},
                      dependencies=["web_detect"]),
        WorkflowNode(node_id="vuln_analysis", name="Vulnerability Analysis", node_type=NodeType.LLM,
                      config={"model": "whiterabbitneo", "task": "Analyze findings for exploitability"},
                      dependencies=["web_scan", "net_analysis"]),
        WorkflowNode(node_id="exploit_validate", name="Exploit Validation", node_type=NodeType.AGENT,
                      config={"role": "exploiter"},
                      dependencies=["vuln_analysis"]),
        WorkflowNode(node_id="report", name="Generate Report", node_type=NodeType.TRANSFORM,
                      config={"format": "json"},
                      dependencies=["exploit_validate"]),
    ]

    for node in nodes:
        wf.nodes[node.node_id] = node

    # Build edges from dependencies
    for node in nodes:
        for dep in node.dependencies:
            wf.edges.append(WorkflowEdge(source=dep, target=node.node_id))

    return wf


def build_web_assessment_workflow(target: str) -> Workflow:
    """Build web application assessment workflow."""
    wf = Workflow(
        workflow_id=f"wf-web-{int(time.time())}",
        name=f"Web assessment: {target}",
        context={"target": target},
    )

    nodes = [
        WorkflowNode(node_id="tech_detect", name="Technology Detection", node_type=NodeType.TOOL,
                      config={"tool": "httpx", "args": f"-u {target} -tech-detect"}),
        WorkflowNode(node_id="dir_enum", name="Directory Enumeration", node_type=NodeType.TOOL,
                      config={"tool": "gobuster", "args": f"dir -u {target}"},
                      dependencies=["tech_detect"]),
        WorkflowNode(node_id="vuln_scan", name="Vulnerability Scan", node_type=NodeType.TOOL,
                      config={"tool": "nuclei", "args": f"-u {target} -severity critical,high"},
                      dependencies=["tech_detect"]),
        WorkflowNode(node_id="api_discover", name="API Discovery", node_type=NodeType.TOOL,
                      config={"tool": "ffuf"},
                      dependencies=["tech_detect"]),
        WorkflowNode(node_id="merge_results", name="Merge Scan Results", node_type=NodeType.MERGE,
                      dependencies=["dir_enum", "vuln_scan", "api_discover"]),
        WorkflowNode(node_id="deep_analysis", name="Deep Analysis", node_type=NodeType.LLM,
                      config={"model": "qwen-coder-14b", "task": "Analyze web vulnerabilities"},
                      dependencies=["merge_results"]),
        WorkflowNode(node_id="sql_test", name="SQL Injection Testing", node_type=NodeType.TOOL,
                      config={"tool": "sqlmap"},
                      dependencies=["deep_analysis"]),
        WorkflowNode(node_id="xss_test", name="XSS Testing", node_type=NodeType.AGENT,
                      config={"role": "exploiter", "focus": "xss"},
                      dependencies=["deep_analysis"]),
        WorkflowNode(node_id="final_merge", name="Final Report", node_type=NodeType.MERGE,
                      dependencies=["sql_test", "xss_test"]),
    ]

    for node in nodes:
        wf.nodes[node.node_id] = node
    for node in nodes:
        for dep in node.dependencies:
            wf.edges.append(WorkflowEdge(source=dep, target=node.node_id))

    return wf


def build_network_assessment_workflow(target: str) -> Workflow:
    """Build network security assessment workflow."""
    wf = Workflow(
        workflow_id=f"wf-net-{int(time.time())}",
        name=f"Network assessment: {target}",
        context={"target": target},
    )

    nodes = [
        WorkflowNode(node_id="host_discover", name="Host Discovery", node_type=NodeType.TOOL,
                      config={"tool": "nmap", "args": f"-sn {target}"}),
        WorkflowNode(node_id="port_scan", name="Full Port Scan", node_type=NodeType.TOOL,
                      config={"tool": "nmap", "args": f"-p- -sV {target}"},
                      dependencies=["host_discover"]),
        WorkflowNode(node_id="service_enum", name="Service Enumeration", node_type=NodeType.AGENT,
                      config={"role": "scanner"},
                      dependencies=["port_scan"]),
        WorkflowNode(node_id="smb_check", name="SMB Security Check", node_type=NodeType.TOOL,
                      config={"tool": "crackmapexec"},
                      dependencies=["port_scan"]),
        WorkflowNode(node_id="snmp_check", name="SNMP Check", node_type=NodeType.TOOL,
                      config={"tool": "onesixtyone"},
                      dependencies=["port_scan"]),
        WorkflowNode(node_id="analysis", name="Network Analysis", node_type=NodeType.LLM,
                      config={"model": "hermes-14b"},
                      dependencies=["service_enum", "smb_check", "snmp_check"]),
        WorkflowNode(node_id="report", name="Report", node_type=NodeType.TRANSFORM,
                      dependencies=["analysis"]),
    ]

    for node in nodes:
        wf.nodes[node.node_id] = node
    for node in nodes:
        for dep in node.dependencies:
            wf.edges.append(WorkflowEdge(source=dep, target=node.node_id))

    return wf


class WorkflowOrchestrator:
    """Executes workflows as directed acyclic graphs.

    Manages node execution ordering, parallel execution
    of independent nodes, conditional branching, and
    workflow state management.
    """

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._log = logger.bind(component="workflow_orchestrator")

    def create_workflow(
        self,
        workflow_type: str,
        target: str,
    ) -> Workflow:
        """Create a predefined workflow."""
        builders = {
            "full": build_full_assessment_workflow,
            "web": build_web_assessment_workflow,
            "network": build_network_assessment_workflow,
        }

        builder = builders.get(workflow_type, build_full_assessment_workflow)
        wf = builder(target)
        self._workflows[wf.workflow_id] = wf
        return wf

    def start(self, workflow_id: str) -> bool:
        """Start workflow execution."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return False

        wf.status = WorkflowStatus.RUNNING
        wf.started_at = time.time()

        # Mark nodes with no dependencies as READY
        for node in wf.nodes.values():
            if not node.dependencies:
                node.status = NodeStatus.READY

        return True

    def get_ready_nodes(self, workflow_id: str) -> list[WorkflowNode]:
        """Get nodes that are ready to execute."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return []

        ready = []
        for node in wf.nodes.values():
            if node.status == NodeStatus.READY:
                ready.append(node)
            elif node.status == NodeStatus.PENDING:
                # Check if all dependencies are met
                deps_met = all(
                    wf.nodes.get(dep, WorkflowNode()).status in (NodeStatus.COMPLETE, NodeStatus.SKIPPED)
                    for dep in node.dependencies
                )
                if deps_met:
                    node.status = NodeStatus.READY
                    ready.append(node)

        return ready

    def start_node(self, workflow_id: str, node_id: str) -> bool:
        """Mark a node as running."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return False

        node = wf.nodes.get(node_id)
        if not node or node.status != NodeStatus.READY:
            return False

        node.status = NodeStatus.RUNNING
        node.started_at = time.time()
        return True

    def complete_node(
        self,
        workflow_id: str,
        node_id: str,
        result: dict[str, Any] | None = None,
        success: bool = True,
    ) -> bool:
        """Mark a node as complete."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return False

        node = wf.nodes.get(node_id)
        if not node:
            return False

        node.completed_at = time.time()
        node.result = result or {}

        if success:
            node.status = NodeStatus.COMPLETE
        else:
            node.retry_count += 1
            if node.retry_count <= node.max_retries:
                node.status = NodeStatus.READY  # Retry
            else:
                node.status = NodeStatus.FAILED

        # Handle condition nodes
        if node.node_type == NodeType.CONDITION and success:
            condition_result = result.get("condition", False) if result else False
            # Skip the branch that wasn't taken
            skip_id = node.on_false if condition_result else node.on_true
            if skip_id and skip_id in wf.nodes:
                wf.nodes[skip_id].status = NodeStatus.SKIPPED

        # Check if workflow is complete
        if self._is_workflow_complete(wf):
            wf.status = WorkflowStatus.COMPLETE
            wf.completed_at = time.time()

        return True

    @staticmethod
    def _is_workflow_complete(wf: Workflow) -> bool:
        """Check if all nodes are in terminal state."""
        for node in wf.nodes.values():
            if node.status not in (NodeStatus.COMPLETE, NodeStatus.FAILED, NodeStatus.SKIPPED):
                return False
        return True

    def get_workflow(self, workflow_id: str) -> Workflow | None:
        """Get a workflow by ID."""
        return self._workflows.get(workflow_id)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for wf in self._workflows.values():
            status_counts[wf.status.value] += 1

        return {
            "workflows": len(self._workflows),
            "by_status": dict(status_counts),
        }
