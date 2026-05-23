"""Emergent vulnerability discovery — finds bugs in system interactions.

Implements Gen-5 vulnerability discovery:
1. Distributed system interaction mapping
2. Cache coherence attack detection
3. Eventual consistency exploitation
4. Microservice chain analysis
5. Race condition in distributed flows
6. Cascading failure detection (chaos/butterfly)
7. State machine cross-service analysis
8. Temporal coupling detection
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class InteractionType(str, Enum):
    SYNC_HTTP = "sync_http"
    ASYNC_MESSAGE = "async_message"
    SHARED_DB = "shared_db"
    SHARED_CACHE = "shared_cache"
    EVENT_STREAM = "event_stream"
    GRPC = "grpc"
    WEBSOCKET = "websocket"


class EmergentVulnType(str, Enum):
    CACHE_DESYNC = "cache_desync"
    RACE_ACROSS_SERVICES = "race_across_services"
    CONSISTENCY_WINDOW = "consistency_window"
    CASCADING_FAILURE = "cascading_failure"
    STATE_DESYNC = "state_desync"
    TEMPORAL_COUPLING = "temporal_coupling"
    TRUST_BOUNDARY_GAP = "trust_boundary_gap"
    BACKPRESSURE_OVERFLOW = "backpressure_overflow"


@dataclass
class ServiceNode:
    """A service in the distributed system."""
    service_id: str = ""
    name: str = ""
    technology: str = ""
    endpoints: list[str] = field(default_factory=list)
    shared_state: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    cache_layer: str = ""
    consistency_model: str = ""    # "strong", "eventual", "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.service_id,
            "name": self.name[:20],
            "tech": self.technology[:15],
            "endpoints": len(self.endpoints),
            "deps": len(self.dependencies),
            "consistency": self.consistency_model[:10],
        }


@dataclass
class ServiceInteraction:
    """An interaction between two services."""
    interaction_id: str = ""
    source: str = ""
    target: str = ""
    interaction_type: InteractionType = InteractionType.SYNC_HTTP
    latency_ms: int = 0
    shared_resource: str = ""
    is_idempotent: bool = True
    has_retry: bool = False
    timeout_ms: int = 5000

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.interaction_id,
            "src": self.source[:15],
            "tgt": self.target[:15],
            "type": self.interaction_type.value,
            "latency": self.latency_ms,
        }


@dataclass
class EmergentVulnerability:
    """A vulnerability that emerges from system interactions."""
    vuln_id: str = ""
    vuln_type: EmergentVulnType = EmergentVulnType.CACHE_DESYNC
    title: str = ""
    description: str = ""
    involved_services: list[str] = field(default_factory=list)
    involved_interactions: list[str] = field(default_factory=list)
    trigger_sequence: list[str] = field(default_factory=list)
    timing_window_ms: int = 0
    severity: str = "high"
    exploitability: str = ""
    detection_method: str = ""
    mitigation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id,
            "type": self.vuln_type.value,
            "title": self.title[:30],
            "severity": self.severity,
            "services": len(self.involved_services),
            "timing_ms": self.timing_window_ms,
        }


@dataclass
class InteractionPath:
    """A path through the service graph."""
    path_id: str = ""
    services: list[str] = field(default_factory=list)
    interactions: list[str] = field(default_factory=list)
    total_latency_ms: int = 0
    shared_resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path_id,
            "hops": len(self.services),
            "latency": self.total_latency_ms,
            "shared": len(self.shared_resources),
        }


class EmergentVulnDiscovery:
    """Finds vulnerabilities in system interactions.

    Discovers bugs that only appear when multiple services
    interact in unexpected ways — emergent properties not
    present in any single component.
    """

    def __init__(self) -> None:
        self._services: dict[str, ServiceNode] = {}
        self._interactions: dict[str, ServiceInteraction] = {}
        self._vulnerabilities: list[EmergentVulnerability] = []
        self._paths: list[InteractionPath] = []
        self._svc_counter = 0
        self._int_counter = 0
        self._vuln_counter = 0
        self._path_counter = 0
        self._log = logger.bind(component="emergent_vuln_discovery")

    def add_service(
        self,
        name: str,
        technology: str = "",
        endpoints: list[str] | None = None,
        shared_state: list[str] | None = None,
        dependencies: list[str] | None = None,
        cache_layer: str = "",
        consistency_model: str = "strong",
    ) -> ServiceNode:
        """Register a service in the system map."""
        self._svc_counter += 1
        svc = ServiceNode(
            service_id=f"svc-{self._svc_counter}",
            name=name,
            technology=technology,
            endpoints=endpoints or [],
            shared_state=shared_state or [],
            dependencies=dependencies or [],
            cache_layer=cache_layer,
            consistency_model=consistency_model,
        )
        self._services[svc.service_id] = svc
        return svc

    def add_interaction(
        self,
        source: str,
        target: str,
        interaction_type: InteractionType = InteractionType.SYNC_HTTP,
        latency_ms: int = 50,
        shared_resource: str = "",
        is_idempotent: bool = True,
        has_retry: bool = False,
    ) -> ServiceInteraction:
        """Register an interaction between services."""
        self._int_counter += 1
        interaction = ServiceInteraction(
            interaction_id=f"int-{self._int_counter}",
            source=source,
            target=target,
            interaction_type=interaction_type,
            latency_ms=latency_ms,
            shared_resource=shared_resource,
            is_idempotent=is_idempotent,
            has_retry=has_retry,
        )
        self._interactions[interaction.interaction_id] = interaction
        return interaction

    def analyze(self) -> list[EmergentVulnerability]:
        """Run full emergent vulnerability analysis."""
        findings = []

        findings.extend(self._check_cache_desync())
        findings.extend(self._check_consistency_windows())
        findings.extend(self._check_race_conditions())
        findings.extend(self._check_cascading_failures())
        findings.extend(self._check_state_desync())
        findings.extend(self._check_temporal_coupling())
        findings.extend(self._check_trust_boundary_gaps())
        findings.extend(self._check_backpressure())

        self._vulnerabilities.extend(findings)
        return findings

    def _check_cache_desync(self) -> list[EmergentVulnerability]:
        """Check for cache coherence attacks."""
        findings = []

        # Find services with cache layers
        cached_services = [
            svc for svc in self._services.values()
            if svc.cache_layer
        ]

        # Find interactions that could cause desync
        for svc in cached_services:
            writers = [
                inter for inter in self._interactions.values()
                if inter.target == svc.service_id
                and inter.interaction_type in (InteractionType.SYNC_HTTP, InteractionType.GRPC)
            ]
            if writers:
                self._vuln_counter += 1
                findings.append(EmergentVulnerability(
                    vuln_id=f"ev-{self._vuln_counter}",
                    vuln_type=EmergentVulnType.CACHE_DESYNC,
                    title=f"Cache desync in {svc.name}",
                    description=(
                        f"Service {svc.name} uses {svc.cache_layer} cache. "
                        f"Write via one path may not invalidate cache read from another path. "
                        f"Attacker can exploit stale cached data."
                    ),
                    involved_services=[svc.service_id] + [w.source for w in writers],
                    timing_window_ms=100,
                    severity="high",
                    exploitability="Send update, immediately read via cached path before invalidation",
                    detection_method="Send update then read within <100ms from different path",
                    mitigation="Implement cache invalidation on write, use read-through cache",
                ))

        return findings

    def _check_consistency_windows(self) -> list[EmergentVulnerability]:
        """Check for eventual consistency exploitation windows."""
        findings = []

        eventual_services = [
            svc for svc in self._services.values()
            if svc.consistency_model == "eventual"
        ]

        for svc in eventual_services:
            if svc.shared_state:
                self._vuln_counter += 1
                findings.append(EmergentVulnerability(
                    vuln_id=f"ev-{self._vuln_counter}",
                    vuln_type=EmergentVulnType.CONSISTENCY_WINDOW,
                    title=f"Eventual consistency window in {svc.name}",
                    description=(
                        f"Service {svc.name} uses eventual consistency for: "
                        f"{', '.join(svc.shared_state[:3])}. During propagation delay, "
                        f"reads from different replicas return different values."
                    ),
                    involved_services=[svc.service_id],
                    severity="high",
                    detection_method="Write to one endpoint, read from another within propagation window",
                    mitigation="Use linearizable reads for security-critical operations",
                ))

        return findings

    def _check_race_conditions(self) -> list[EmergentVulnerability]:
        """Check for race conditions across service boundaries."""
        findings = []

        # Find non-idempotent interactions sharing resources
        shared_resources: dict[str, list[ServiceInteraction]] = defaultdict(list)
        for inter in self._interactions.values():
            if inter.shared_resource:
                shared_resources[inter.shared_resource].append(inter)

        for resource, interactions in shared_resources.items():
            if len(interactions) >= 2:
                non_idempotent = [i for i in interactions if not i.is_idempotent]
                if non_idempotent:
                    self._vuln_counter += 1
                    services_involved = list({
                        i.source for i in interactions
                    } | {i.target for i in interactions})
                    findings.append(EmergentVulnerability(
                        vuln_id=f"ev-{self._vuln_counter}",
                        vuln_type=EmergentVulnType.RACE_ACROSS_SERVICES,
                        title=f"Cross-service race on {resource}",
                        description=(
                            f"Multiple services access shared resource '{resource}' "
                            f"with non-idempotent operations. Concurrent access "
                            f"from different service paths can corrupt state."
                        ),
                        involved_services=services_involved,
                        involved_interactions=[i.interaction_id for i in interactions],
                        timing_window_ms=max(i.latency_ms for i in interactions),
                        severity="critical",
                        detection_method="Send concurrent requests through different service paths",
                        mitigation="Implement distributed locking or optimistic concurrency control",
                    ))

        return findings

    def _check_cascading_failures(self) -> list[EmergentVulnerability]:
        """Check for cascading failure paths."""
        findings = []

        # Find services with many dependents (high fan-in)
        dependent_count: dict[str, int] = defaultdict(int)
        for inter in self._interactions.values():
            dependent_count[inter.target] += 1

        critical_services = [
            (svc_id, count) for svc_id, count in dependent_count.items()
            if count >= 3
        ]

        for svc_id, count in critical_services:
            svc = self._services.get(svc_id)
            svc_name = svc.name if svc else svc_id

            # Check if retries configured (retry storms)
            retry_interactions = [
                i for i in self._interactions.values()
                if i.target == svc_id and i.has_retry
            ]

            if retry_interactions:
                self._vuln_counter += 1
                findings.append(EmergentVulnerability(
                    vuln_id=f"ev-{self._vuln_counter}",
                    vuln_type=EmergentVulnType.CASCADING_FAILURE,
                    title=f"Cascade risk via {svc_name}",
                    description=(
                        f"Service {svc_name} has {count} dependents, "
                        f"{len(retry_interactions)} with retry logic. "
                        f"If {svc_name} slows down, retries amplify load, "
                        f"causing cascading failure across all dependents."
                    ),
                    involved_services=[svc_id] + [i.source for i in retry_interactions],
                    severity="high",
                    detection_method="Inject latency into critical service, observe cascading effects",
                    mitigation="Implement circuit breakers, exponential backoff, bulkheads",
                ))

        return findings

    def _check_state_desync(self) -> list[EmergentVulnerability]:
        """Check for state desynchronization across services."""
        findings = []

        # Find services sharing state
        state_groups: dict[str, list[str]] = defaultdict(list)
        for svc in self._services.values():
            for state in svc.shared_state:
                state_groups[state].append(svc.service_id)

        for state, svc_ids in state_groups.items():
            if len(svc_ids) >= 2:
                self._vuln_counter += 1
                findings.append(EmergentVulnerability(
                    vuln_id=f"ev-{self._vuln_counter}",
                    vuln_type=EmergentVulnType.STATE_DESYNC,
                    title=f"State desync on '{state}'",
                    description=(
                        f"Shared state '{state}' accessed by {len(svc_ids)} services. "
                        f"Without distributed transactions, updates via one service "
                        f"may not be visible to others, creating exploitable windows."
                    ),
                    involved_services=svc_ids,
                    severity="high",
                    detection_method="Modify state via one service, read via another",
                    mitigation="Use saga pattern or distributed transactions",
                ))

        return findings

    def _check_temporal_coupling(self) -> list[EmergentVulnerability]:
        """Check for temporal coupling vulnerabilities."""
        findings = []

        # Find synchronous chains longer than 3 hops
        paths = self._find_sync_chains()
        for path in paths:
            if len(path) >= 3:
                self._vuln_counter += 1
                total_latency = sum(
                    inter.latency_ms
                    for inter in self._interactions.values()
                    if inter.interaction_id in path
                )
                findings.append(EmergentVulnerability(
                    vuln_id=f"ev-{self._vuln_counter}",
                    vuln_type=EmergentVulnType.TEMPORAL_COUPLING,
                    title=f"Deep sync chain ({len(path)} hops)",
                    description=(
                        f"Synchronous chain of {len(path)} service calls. "
                        f"Total latency ~{total_latency}ms. Any service failure "
                        f"in the chain blocks the entire request."
                    ),
                    timing_window_ms=total_latency,
                    severity="medium",
                    detection_method="Trace request through chain, measure total latency",
                    mitigation="Break chain with async messaging where possible",
                ))

        return findings

    def _check_trust_boundary_gaps(self) -> list[EmergentVulnerability]:
        """Check for missing auth between internal services."""
        findings = []

        for inter in self._interactions.values():
            src = self._services.get(inter.source)
            tgt = self._services.get(inter.target)
            if not src or not tgt:
                continue

            # Check if an exposed service can reach internal ones
            exposed_sources = [
                svc for svc in self._services.values()
                if svc.service_id == inter.source and any(
                    e.startswith("/") for e in svc.endpoints
                )
            ]
            if exposed_sources:
                # Check if the target has internal-only endpoints
                if tgt.endpoints and not any(
                    ep.startswith("http") for ep in tgt.endpoints
                ):
                    self._vuln_counter += 1
                    findings.append(EmergentVulnerability(
                        vuln_id=f"ev-{self._vuln_counter}",
                        vuln_type=EmergentVulnType.TRUST_BOUNDARY_GAP,
                        title=f"Trust gap: {src.name} → {tgt.name}",
                        description=(
                            f"Exposed service {src.name} can reach internal "
                            f"service {tgt.name} without additional auth. "
                            f"Compromising {src.name} gives access to {tgt.name}."
                        ),
                        involved_services=[src.service_id, tgt.service_id],
                        severity="high",
                        detection_method="Map internal service access from compromised exposed service",
                        mitigation="Implement mTLS and service mesh authorization policies",
                    ))

        return findings

    def _check_backpressure(self) -> list[EmergentVulnerability]:
        """Check for backpressure/overflow conditions."""
        findings = []

        for inter in self._interactions.values():
            if inter.interaction_type == InteractionType.ASYNC_MESSAGE:
                src = self._services.get(inter.source)
                src_name = src.name if src else inter.source

                self._vuln_counter += 1
                findings.append(EmergentVulnerability(
                    vuln_id=f"ev-{self._vuln_counter}",
                    vuln_type=EmergentVulnType.BACKPRESSURE_OVERFLOW,
                    title=f"Message queue overflow risk from {src_name}",
                    description=(
                        f"Async message flow from {src_name} to {inter.target}. "
                        f"If producer outpaces consumer, queue grows unbounded. "
                        f"Attacker can flood producer to exhaust queue memory."
                    ),
                    involved_services=[inter.source, inter.target],
                    severity="medium",
                    detection_method="Send burst of messages, monitor queue depth growth",
                    mitigation="Implement dead letter queue, max queue size, rate limiting",
                ))

        return findings

    def _find_sync_chains(self) -> list[list[str]]:
        """Find synchronous call chains."""
        sync_interactions = [
            i for i in self._interactions.values()
            if i.interaction_type in (InteractionType.SYNC_HTTP, InteractionType.GRPC)
        ]

        adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for inter in sync_interactions:
            adj[inter.source].append((inter.target, inter.interaction_id))

        chains: list[list[str]] = []
        for start in adj:
            self._dfs_chains(start, adj, [], set(), chains)

        return chains

    def _dfs_chains(
        self,
        node: str,
        adj: dict[str, list[tuple[str, str]]],
        current: list[str],
        visited: set[str],
        results: list[list[str]],
    ) -> None:
        """DFS to find chains."""
        if node in visited:
            return
        visited.add(node)

        for target, inter_id in adj.get(node, []):
            new_path = current + [inter_id]
            if len(new_path) >= 3:
                results.append(new_path)
            if len(new_path) < 10:
                self._dfs_chains(target, adj, new_path, visited, results)

        visited.discard(node)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for vuln in self._vulnerabilities:
            type_counts[vuln.vuln_type.value] += 1
        return {
            "services": len(self._services),
            "interactions": len(self._interactions),
            "vulnerabilities": len(self._vulnerabilities),
            "by_type": dict(type_counts),
        }
