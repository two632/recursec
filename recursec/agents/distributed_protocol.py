"""Distributed agent protocol — inter-process agent communication.

Enables RecurSec agents to run across multiple processes/machines:
1. Agent discovery (register/unregister on shared bus)
2. Task delegation over network (HTTP/WebSocket)
3. Result streaming (incremental findings)
4. Heartbeat monitoring
5. Load-based routing
6. Agent migration between hosts
7. Shared state synchronization
8. Event-driven architecture with pub/sub

This allows scaling beyond a single machine — run different agent
roles on different GPUs/machines with different LLMs.
"""

from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class NodeState(str, Enum):
    ONLINE = "online"
    BUSY = "busy"
    OVERLOADED = "overloaded"
    OFFLINE = "offline"
    DRAINING = "draining"


class EventType(str, Enum):
    AGENT_REGISTERED = "agent_registered"
    AGENT_UNREGISTERED = "agent_unregistered"
    TASK_SUBMITTED = "task_submitted"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    FINDING_DISCOVERED = "finding_discovered"
    HEARTBEAT = "heartbeat"
    STATE_SYNC = "state_sync"
    LOAD_REPORT = "load_report"
    CUSTOM = "custom"


@dataclass
class AgentNode:
    """A registered agent node in the distributed system."""
    node_id: str = field(default_factory=lambda: f"node-{uuid.uuid4().hex[:8]}")
    host: str = "localhost"
    port: int = 8200
    roles: list[str] = field(default_factory=list)
    models_available: list[str] = field(default_factory=list)
    state: NodeState = NodeState.ONLINE
    current_tasks: int = 0
    max_tasks: int = 4
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    gpu_usage: float = 0.0
    last_heartbeat: float = field(default_factory=time.time)
    registered_at: float = field(default_factory=time.time)
    capabilities: dict[str, Any] = field(default_factory=dict)

    @property
    def load_score(self) -> float:
        """0.0 = idle, 1.0 = fully loaded."""
        task_load = self.current_tasks / max(self.max_tasks, 1)
        return (task_load * 0.4 + self.cpu_usage * 0.3 + self.memory_usage * 0.2 + self.gpu_usage * 0.1)

    @property
    def is_available(self) -> bool:
        return self.state in (NodeState.ONLINE,) and self.current_tasks < self.max_tasks

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id[:8],
            "host": f"{self.host}:{self.port}",
            "state": self.state.value[:8],
            "load": f"{self.load_score:.2f}",
            "tasks": f"{self.current_tasks}/{self.max_tasks}",
            "roles": self.roles[:3],
        }


@dataclass
class DistributedEvent:
    """An event in the distributed event bus."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    event_type: EventType = EventType.CUSTOM
    source_node: str = ""
    target_node: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ttl_s: float = 300.0

    @property
    def expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl_s

    def to_json(self) -> str:
        return json.dumps({
            "id": self.event_id,
            "type": self.event_type.value,
            "source": self.source_node,
            "target": self.target_node,
            "payload": self.payload,
            "ts": self.timestamp,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id[:8],
            "type": self.event_type.value[:15],
            "source": self.source_node[:8],
        }


@dataclass
class TaskDelegation:
    """A task delegated to a remote agent node."""
    delegation_id: str = field(default_factory=lambda: f"del-{uuid.uuid4().hex[:8]}")
    task_description: str = ""
    target: str = ""
    required_role: str = ""
    required_model: str = ""
    priority: int = 5
    assigned_node: str = ""
    state: str = "pending"
    result: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.delegation_id[:8],
            "task": self.task_description[:25],
            "role": self.required_role[:10],
            "node": self.assigned_node[:8],
            "state": self.state[:10],
        }


# ─── Event Bus (Pub/Sub) ───

class EventBus:
    """In-process event bus with publish/subscribe."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Any]] = defaultdict(list)
        self._history: list[DistributedEvent] = []
        self._max_history = 1000

    def subscribe(self, event_type: EventType, callback: Any) -> None:
        """Subscribe to an event type."""
        self._subscribers[event_type].append(callback)

    def publish(self, event: DistributedEvent) -> None:
        """Publish an event to all subscribers."""
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-500:]

        for callback in self._subscribers.get(event.event_type, []):
            try:
                callback(event)
            except Exception:
                pass

    def get_history(self, event_type: EventType | None = None, limit: int = 50) -> list[dict[str, Any]]:
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in events[-limit:]]


# ─── Node Registry ───

class NodeRegistry:
    """Manages registration of agent nodes."""

    def __init__(self) -> None:
        self._nodes: dict[str, AgentNode] = {}
        self._log = logger.bind(component="node_registry")

    def register(self, node: AgentNode) -> None:
        """Register a new agent node."""
        self._nodes[node.node_id] = node
        self._log.info("node_registered", node=node.node_id, host=node.host)

    def unregister(self, node_id: str) -> None:
        """Unregister an agent node."""
        if node_id in self._nodes:
            del self._nodes[node_id]

    def heartbeat(self, node_id: str, metrics: dict[str, float] | None = None) -> None:
        """Update heartbeat for a node."""
        node = self._nodes.get(node_id)
        if node:
            node.last_heartbeat = time.time()
            if metrics:
                node.cpu_usage = metrics.get("cpu", node.cpu_usage)
                node.memory_usage = metrics.get("memory", node.memory_usage)
                node.gpu_usage = metrics.get("gpu", node.gpu_usage)

    def get_available_nodes(self, role: str = "", model: str = "") -> list[AgentNode]:
        """Get available nodes, optionally filtered by role or model."""
        nodes = [n for n in self._nodes.values() if n.is_available]
        if role:
            nodes = [n for n in nodes if role in n.roles]
        if model:
            nodes = [n for n in nodes if model in n.models_available]
        return sorted(nodes, key=lambda n: n.load_score)

    def get_best_node(self, role: str = "", model: str = "") -> AgentNode | None:
        """Get the least loaded available node."""
        nodes = self.get_available_nodes(role, model)
        return nodes[0] if nodes else None

    def check_health(self, timeout_s: float = 60.0) -> list[str]:
        """Check for unhealthy nodes (missed heartbeats)."""
        now = time.time()
        unhealthy = []
        for node_id, node in self._nodes.items():
            if now - node.last_heartbeat > timeout_s:
                node.state = NodeState.OFFLINE
                unhealthy.append(node_id)
        return unhealthy

    def get_stats(self) -> dict[str, Any]:
        total = len(self._nodes)
        online = sum(1 for n in self._nodes.values() if n.state == NodeState.ONLINE)
        busy = sum(1 for n in self._nodes.values() if n.state == NodeState.BUSY)
        return {
            "total_nodes": total,
            "online": online,
            "busy": busy,
            "offline": total - online - busy,
        }


# ─── Load Balancer ───

class LoadBalancer:
    """Routes tasks to optimal nodes based on load and capabilities."""

    def __init__(self, registry: NodeRegistry) -> None:
        self._registry = registry
        self._round_robin_idx: dict[str, int] = {}
        self._log = logger.bind(component="load_balancer")

    def route_task(self, delegation: TaskDelegation) -> AgentNode | None:
        """Find the best node for a task."""
        # Strategy 1: Least loaded node with required role
        node = self._registry.get_best_node(
            role=delegation.required_role,
            model=delegation.required_model,
        )
        if node:
            return node

        # Strategy 2: Any available node
        node = self._registry.get_best_node()
        return node

    def route_by_model(self, model_id: str) -> AgentNode | None:
        """Route to a node that has a specific model loaded."""
        return self._registry.get_best_node(model=model_id)


# ─── Distributed Agent Manager ───

class DistributedAgentManager:
    """Manages the distributed agent network."""

    def __init__(self) -> None:
        self._registry = NodeRegistry()
        self._bus = EventBus()
        self._balancer = LoadBalancer(self._registry)
        self._delegations: dict[str, TaskDelegation] = {}
        self._log = logger.bind(component="distributed_manager")

        # Auto-subscribe to events
        self._bus.subscribe(EventType.TASK_COMPLETED, self._on_task_completed)
        self._bus.subscribe(EventType.HEARTBEAT, self._on_heartbeat)

    def register_node(
        self,
        host: str = "localhost",
        port: int = 8200,
        roles: list[str] | None = None,
        models: list[str] | None = None,
        max_tasks: int = 4,
    ) -> AgentNode:
        """Register a new agent node."""
        node = AgentNode(
            host=host,
            port=port,
            roles=roles or ["general"],
            models_available=models or [],
            max_tasks=max_tasks,
        )
        self._registry.register(node)

        self._bus.publish(DistributedEvent(
            event_type=EventType.AGENT_REGISTERED,
            source_node=node.node_id,
            payload=node.to_dict(),
        ))
        return node

    def delegate_task(
        self,
        description: str,
        target: str = "",
        role: str = "",
        model: str = "",
        priority: int = 5,
    ) -> TaskDelegation:
        """Delegate a task to the best available node."""
        delegation = TaskDelegation(
            task_description=description,
            target=target,
            required_role=role,
            required_model=model,
            priority=priority,
        )

        # Find best node
        node = self._balancer.route_task(delegation)
        if node:
            delegation.assigned_node = node.node_id
            delegation.state = "assigned"
            node.current_tasks += 1
            if node.current_tasks >= node.max_tasks:
                node.state = NodeState.BUSY

            self._bus.publish(DistributedEvent(
                event_type=EventType.TASK_SUBMITTED,
                source_node="manager",
                target_node=node.node_id,
                payload=delegation.to_dict(),
            ))
        else:
            delegation.state = "queued"

        self._delegations[delegation.delegation_id] = delegation
        return delegation

    def complete_delegation(self, delegation_id: str, result: dict[str, Any]) -> None:
        """Mark a delegation as complete."""
        delegation = self._delegations.get(delegation_id)
        if delegation:
            delegation.state = "completed"
            delegation.result = result
            delegation.completed_at = time.time()

            # Free up the node
            node = self._registry._nodes.get(delegation.assigned_node)
            if node:
                node.current_tasks = max(0, node.current_tasks - 1)
                if node.state == NodeState.BUSY and node.current_tasks < node.max_tasks:
                    node.state = NodeState.ONLINE

    def _on_task_completed(self, event: DistributedEvent) -> None:
        """Handle task completion events."""
        del_id = event.payload.get("delegation_id", "")
        if del_id:
            self.complete_delegation(del_id, event.payload.get("result", {}))

    def _on_heartbeat(self, event: DistributedEvent) -> None:
        """Handle heartbeat events."""
        self._registry.heartbeat(
            event.source_node,
            event.payload.get("metrics"),
        )

    def get_stats(self) -> dict[str, Any]:
        total_del = len(self._delegations)
        completed = sum(1 for d in self._delegations.values() if d.state == "completed")
        return {
            "registry": self._registry.get_stats(),
            "delegations": total_del,
            "completed": completed,
            "event_history": len(self._bus._history),
        }

    def build_cluster_prompt(self) -> str:
        """Build LLM prompt with cluster status."""
        lines = ["## Distributed Cluster Status"]
        stats = self._registry.get_stats()
        lines.append(f"Nodes: {stats['total_nodes']} total, {stats['online']} online, {stats['busy']} busy")

        nodes = list(self._registry._nodes.values())
        if nodes:
            lines.append("\nAvailable nodes:")
            for node in sorted(nodes, key=lambda n: n.load_score)[:5]:
                lines.append(f"  - {node.node_id[:8]} ({node.host}:{node.port}) "
                             f"load={node.load_score:.2f} roles={','.join(node.roles[:3])}")

        pending = [d for d in self._delegations.values() if d.state == "queued"]
        if pending:
            lines.append(f"\nQueued tasks: {len(pending)}")

        return "\n".join(lines)
