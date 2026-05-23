"""World model — agent's internal model of the target environment.

Maintains a rich representation of the target being assessed:
1. Target topology (hosts, services, endpoints)
2. Technology stack detection
3. Attack surface mapping
4. Access level tracking
5. State transitions (what changed after actions)
6. Prediction of action outcomes
7. Uncertainty tracking
8. Environment simulation for planning
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class HostStatus(str, Enum):
    UNKNOWN = "unknown"
    UP = "up"
    DOWN = "down"
    FILTERED = "filtered"


class ServiceStatus(str, Enum):
    UNKNOWN = "unknown"
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class AccessLevel(str, Enum):
    NONE = "none"
    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    ROOT = "root"


@dataclass
class Host:
    """A host in the target environment."""
    host_id: str = ""
    address: str = ""
    hostname: str = ""
    os_guess: str = ""
    status: HostStatus = HostStatus.UNKNOWN
    services: list[str] = field(default_factory=list)
    access_level: AccessLevel = AccessLevel.NONE
    findings: list[str] = field(default_factory=list)
    last_scanned: float = 0.0
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.host_id,
            "address": self.address[:20],
            "hostname": self.hostname[:25],
            "os": self.os_guess[:20],
            "status": self.status.value,
            "services": len(self.services),
            "access": self.access_level.value,
            "findings": len(self.findings),
        }


@dataclass
class Service:
    """A service running on a host."""
    service_id: str = ""
    host_id: str = ""
    port: int = 0
    protocol: str = "tcp"
    name: str = ""
    version: str = ""
    status: ServiceStatus = ServiceStatus.UNKNOWN
    technology_stack: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.service_id,
            "port": self.port,
            "proto": self.protocol,
            "name": self.name[:15],
            "version": self.version[:15],
            "status": self.status.value,
            "tech": self.technology_stack[:3],
            "endpoints": len(self.endpoints),
        }


@dataclass
class Endpoint:
    """A web endpoint."""
    endpoint_id: str = ""
    service_id: str = ""
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    parameters: list[str] = field(default_factory=list)
    technology: str = ""
    findings: list[str] = field(default_factory=list)
    tested: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.endpoint_id,
            "url": self.url[:40],
            "method": self.method,
            "status": self.status_code,
            "params": len(self.parameters),
            "tested": self.tested,
        }


@dataclass
class StateTransition:
    """A state transition caused by an action."""
    transition_id: str = ""
    action: str = ""
    before_state: dict[str, Any] = field(default_factory=dict)
    after_state: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.transition_id,
            "action": self.action[:30],
            "changes": len(self.after_state),
        }


@dataclass
class ActionOutcomePrediction:
    """Predicted outcome of an action."""
    action: str = ""
    target: str = ""
    predicted_success: float = 0.5
    predicted_findings: int = 0
    predicted_cost_tokens: int = 500
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action[:30],
            "target": self.target[:20],
            "success_prob": round(self.predicted_success, 2),
            "findings": self.predicted_findings,
        }


class WorldModel:
    """Agent's internal model of the target environment.

    Maintains topology, services, endpoints, access levels,
    and can predict outcomes of actions.
    """

    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}
        self._services: dict[str, Service] = {}
        self._endpoints: dict[str, Endpoint] = {}
        self._transitions: list[StateTransition] = []
        self._action_outcomes: dict[str, list[bool]] = defaultdict(list)
        self._host_counter = 0
        self._service_counter = 0
        self._endpoint_counter = 0
        self._transition_counter = 0
        self._log = logger.bind(component="world_model")

    def add_host(
        self,
        address: str,
        hostname: str = "",
        os_guess: str = "",
        status: HostStatus = HostStatus.UP,
    ) -> Host:
        """Add or update a host."""
        # Check if host already exists by address
        for host in self._hosts.values():
            if host.address == address:
                if hostname:
                    host.hostname = hostname
                if os_guess:
                    host.os_guess = os_guess
                host.status = status
                host.last_scanned = time.time()
                return host

        self._host_counter += 1
        host = Host(
            host_id=f"host-{self._host_counter}",
            address=address,
            hostname=hostname,
            os_guess=os_guess,
            status=status,
            last_scanned=time.time(),
        )
        self._hosts[host.host_id] = host
        return host

    def add_service(
        self,
        host_id: str,
        port: int,
        protocol: str = "tcp",
        name: str = "",
        version: str = "",
        technology_stack: list[str] | None = None,
    ) -> Service:
        """Add or update a service."""
        # Check if service already exists
        for svc in self._services.values():
            if svc.host_id == host_id and svc.port == port and svc.protocol == protocol:
                if name:
                    svc.name = name
                if version:
                    svc.version = version
                if technology_stack:
                    svc.technology_stack = list(set(svc.technology_stack + technology_stack))
                return svc

        self._service_counter += 1
        svc = Service(
            service_id=f"svc-{self._service_counter}",
            host_id=host_id,
            port=port,
            protocol=protocol,
            name=name,
            version=version,
            technology_stack=technology_stack or [],
            status=ServiceStatus.OPEN,
        )
        self._services[svc.service_id] = svc

        # Link to host
        host = self._hosts.get(host_id)
        if host and svc.service_id not in host.services:
            host.services.append(svc.service_id)

        return svc

    def add_endpoint(
        self,
        service_id: str,
        url: str,
        method: str = "GET",
        status_code: int = 200,
        content_type: str = "",
        parameters: list[str] | None = None,
    ) -> Endpoint:
        """Add a web endpoint."""
        self._endpoint_counter += 1
        ep = Endpoint(
            endpoint_id=f"ep-{self._endpoint_counter}",
            service_id=service_id,
            url=url,
            method=method,
            status_code=status_code,
            content_type=content_type,
            parameters=parameters or [],
        )
        self._endpoints[ep.endpoint_id] = ep

        # Link to service
        svc = self._services.get(service_id)
        if svc and ep.endpoint_id not in svc.endpoints:
            svc.endpoints.append(ep.endpoint_id)

        return ep

    def record_action(
        self,
        action: str,
        changes: dict[str, Any],
    ) -> StateTransition:
        """Record a state transition caused by an action."""
        self._transition_counter += 1
        transition = StateTransition(
            transition_id=f"tr-{self._transition_counter}",
            action=action,
            after_state=changes,
        )
        self._transitions.append(transition)

        if len(self._transitions) > 500:
            self._transitions = self._transitions[-500:]

        return transition

    def record_action_outcome(
        self,
        action_type: str,
        success: bool,
    ) -> None:
        """Record the outcome of an action type for learning."""
        self._action_outcomes[action_type].append(success)
        if len(self._action_outcomes[action_type]) > 100:
            self._action_outcomes[action_type] = self._action_outcomes[action_type][-100:]

    def predict_action(
        self,
        action: str,
        target: str = "",
    ) -> ActionOutcomePrediction:
        """Predict the outcome of an action based on history."""
        outcomes = self._action_outcomes.get(action, [])
        if outcomes:
            success_rate = sum(outcomes) / len(outcomes)
        else:
            success_rate = 0.5  # Prior

        # Adjust based on target knowledge
        host_knowledge = 0
        for host in self._hosts.values():
            if target in host.address or target in host.hostname:
                host_knowledge = len(host.services) * 0.05

        predicted_success = min(1.0, success_rate + host_knowledge)

        return ActionOutcomePrediction(
            action=action,
            target=target,
            predicted_success=predicted_success,
            predicted_findings=max(0, int(predicted_success * 3)),
            reasoning=f"Based on {len(outcomes)} past outcomes",
        )

    def get_attack_surface(self) -> dict[str, Any]:
        """Get a summary of the known attack surface."""
        total_endpoints = len(self._endpoints)
        untested = sum(1 for ep in self._endpoints.values() if not ep.tested)
        total_params = sum(len(ep.parameters) for ep in self._endpoints.values())

        return {
            "hosts": len(self._hosts),
            "services": len(self._services),
            "endpoints": total_endpoints,
            "untested_endpoints": untested,
            "total_parameters": total_params,
            "technologies": list(set(
                tech
                for svc in self._services.values()
                for tech in svc.technology_stack
            ))[:20],
        }

    def get_host_map(self) -> list[dict[str, Any]]:
        return [h.to_dict() for h in self._hosts.values()]

    def get_stats(self) -> dict[str, Any]:
        return {
            "hosts": len(self._hosts),
            "services": len(self._services),
            "endpoints": len(self._endpoints),
            "transitions": len(self._transitions),
        }
