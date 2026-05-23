"""Swarm coordinator — multi-agent swarm intelligence with emergent behavior.

Goes beyond simple coordination to implement true swarm intelligence:
1. Stigmergy (indirect communication through shared state)
2. Pheromone trails (reinforced paths in attack surface)
3. Emergent specialization (agents self-organize into roles)
4. Collective decision making
5. Swarm-level convergence detection
6. Dynamic topology (agents form/dissolve teams)
7. Load-aware work distribution
8. Swarm health monitoring
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SwarmRole(str, Enum):
    SCOUT = "scout"              # Fast, lightweight recon
    WORKER = "worker"            # Standard task execution
    SPECIALIST = "specialist"    # Deep analysis on specific area
    VALIDATOR = "validator"      # Cross-checks findings
    COORDINATOR = "coordinator"  # Sub-swarm leader
    SENTINEL = "sentinel"        # Monitors for anomalies/scope violations


class SwarmSignal(str, Enum):
    FINDING = "finding"          # Found something interesting
    BLOCKED = "blocked"          # Hit a wall
    FERTILE = "fertile"          # Area is rich for exploration
    DANGER = "danger"            # Scope violation or safety issue
    CONVERGED = "converged"      # This area is exhausted
    HELP = "help"                # Need assistance


@dataclass
class PheromoneTrail:
    """A pheromone trail on the attack surface."""
    trail_id: str = ""
    location: str = ""           # URL, port, service, etc.
    signal: SwarmSignal = SwarmSignal.FINDING
    strength: float = 1.0
    deposited_by: str = ""
    deposited_at: float = field(default_factory=time.time)
    decay_rate: float = 0.01     # Strength lost per second

    @property
    def current_strength(self) -> float:
        age = time.time() - self.deposited_at
        return max(0, self.strength * math.exp(-self.decay_rate * age))

    @property
    def is_active(self) -> bool:
        return self.current_strength > 0.05

    def reinforce(self, amount: float = 0.3) -> None:
        """Reinforce the pheromone trail."""
        self.strength = min(2.0, self.strength + amount)
        self.deposited_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.trail_id,
            "location": self.location[:30],
            "signal": self.signal.value,
            "strength": round(self.current_strength, 3),
            "by": self.deposited_by[:10],
        }


@dataclass
class SwarmAgent:
    """An agent in the swarm."""
    agent_id: str = ""
    role: SwarmRole = SwarmRole.WORKER
    model_id: str = ""
    current_task: str = ""
    current_location: str = ""   # What part of attack surface
    findings_count: int = 0
    tokens_used: int = 0
    energy: float = 1.0          # Decreases with work, recharges
    specialization_scores: dict[str, float] = field(default_factory=dict)
    team_id: str = ""
    active: bool = True
    spawned_at: float = field(default_factory=time.time)

    @property
    def efficiency(self) -> float:
        if self.tokens_used == 0:
            return 0.0
        return self.findings_count / (self.tokens_used / 1000.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "role": self.role.value,
            "model": self.model_id[:15],
            "task": self.current_task[:25],
            "findings": self.findings_count,
            "energy": round(self.energy, 2),
            "team": self.team_id[:10],
        }


@dataclass
class SwarmTeam:
    """A dynamic team within the swarm."""
    team_id: str = ""
    purpose: str = ""
    leader_id: str = ""
    member_ids: list[str] = field(default_factory=list)
    target_location: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    formed_at: float = field(default_factory=time.time)
    dissolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.team_id,
            "purpose": self.purpose[:30],
            "leader": self.leader_id[:10],
            "members": len(self.member_ids),
            "findings": len(self.findings),
        }


# ── Role → Model Mapping ──────────────────────────────────────

ROLE_MODEL_MAP: dict[SwarmRole, list[str]] = {
    SwarmRole.SCOUT: ["mistral-7b", "phi-3.5-mini", "functiongemma-270m"],
    SwarmRole.WORKER: ["llama-8b", "dolphin-8b", "mistral-7b"],
    SwarmRole.SPECIALIST: ["whiterabbitneo-7b", "qwen-coder-14b", "deepseek-r1-7b"],
    SwarmRole.VALIDATOR: ["hermes-14b", "qwen-coder-7b"],
    SwarmRole.COORDINATOR: ["deepseek-r1-7b", "hermes-14b"],
    SwarmRole.SENTINEL: ["llama-guard-1b", "hermes-14b"],
}


class SwarmCoordinator:
    """Multi-agent swarm intelligence with emergent behavior.

    Manages a swarm of agents that self-organize using
    pheromone trails, stigmergy, and collective intelligence.
    """

    def __init__(
        self,
        max_agents: int = 30,
        max_teams: int = 10,
    ) -> None:
        self._agents: dict[str, SwarmAgent] = {}
        self._teams: dict[str, SwarmTeam] = {}
        self._pheromones: dict[str, list[PheromoneTrail]] = defaultdict(list)
        self._shared_state: dict[str, Any] = {}
        self._agent_counter = 0
        self._team_counter = 0
        self._trail_counter = 0
        self._max_agents = max_agents
        self._max_teams = max_teams
        self._log = logger.bind(component="swarm_coordinator")

    def spawn_agent(
        self,
        role: SwarmRole = SwarmRole.WORKER,
        model_id: str = "",
        task: str = "",
    ) -> SwarmAgent | None:
        """Spawn a new agent into the swarm."""
        active_count = sum(1 for a in self._agents.values() if a.active)
        if active_count >= self._max_agents:
            return None

        self._agent_counter += 1

        if not model_id:
            models = ROLE_MODEL_MAP.get(role, ["mistral-7b"])
            model_id = models[0]

        agent = SwarmAgent(
            agent_id=f"sw-{self._agent_counter}",
            role=role,
            model_id=model_id,
            current_task=task,
        )

        self._agents[agent.agent_id] = agent
        return agent

    def spawn_swarm(
        self,
        task: str,
        scout_count: int = 3,
        worker_count: int = 5,
        specialist_count: int = 2,
        validator_count: int = 1,
    ) -> list[SwarmAgent]:
        """Spawn a complete swarm for a task."""
        agents = []

        for _ in range(scout_count):
            agent = self.spawn_agent(SwarmRole.SCOUT, task=f"scout: {task}")
            if agent:
                agents.append(agent)

        for _ in range(worker_count):
            agent = self.spawn_agent(SwarmRole.WORKER, task=f"work: {task}")
            if agent:
                agents.append(agent)

        for _ in range(specialist_count):
            agent = self.spawn_agent(SwarmRole.SPECIALIST, task=f"specialize: {task}")
            if agent:
                agents.append(agent)

        for _ in range(validator_count):
            agent = self.spawn_agent(SwarmRole.VALIDATOR, task=f"validate: {task}")
            if agent:
                agents.append(agent)

        # Spawn coordinator
        coord = self.spawn_agent(SwarmRole.COORDINATOR, task=f"coordinate: {task}")
        if coord:
            agents.append(coord)

        # Spawn sentinel
        sentinel = self.spawn_agent(SwarmRole.SENTINEL, task=f"monitor: {task}")
        if sentinel:
            agents.append(sentinel)

        return agents

    def deposit_pheromone(
        self,
        agent_id: str,
        location: str,
        signal: SwarmSignal,
        strength: float = 1.0,
    ) -> PheromoneTrail:
        """Agent deposits a pheromone at a location."""
        self._trail_counter += 1
        trail = PheromoneTrail(
            trail_id=f"ph-{self._trail_counter}",
            location=location,
            signal=signal,
            strength=strength,
            deposited_by=agent_id,
        )
        self._pheromones[location].append(trail)
        return trail

    def read_pheromones(self, location: str) -> dict[str, float]:
        """Read pheromone levels at a location."""
        trails = self._pheromones.get(location, [])
        signal_strengths: dict[str, float] = defaultdict(float)

        for trail in trails:
            if trail.is_active:
                signal_strengths[trail.signal.value] += trail.current_strength

        return dict(signal_strengths)

    def get_attractive_locations(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get locations with strong positive pheromones."""
        location_scores: dict[str, float] = {}

        for location, trails in self._pheromones.items():
            score = 0.0
            for trail in trails:
                if not trail.is_active:
                    continue
                if trail.signal in (SwarmSignal.FINDING, SwarmSignal.FERTILE):
                    score += trail.current_strength
                elif trail.signal in (SwarmSignal.DANGER, SwarmSignal.CONVERGED):
                    score -= trail.current_strength * 0.5
            location_scores[location] = score

        sorted_locs = sorted(location_scores.items(), key=lambda x: x[1], reverse=True)
        return [
            {"location": loc, "score": round(score, 3)}
            for loc, score in sorted_locs[:limit]
            if score > 0
        ]

    def form_team(
        self,
        purpose: str,
        target_location: str,
        member_count: int = 3,
    ) -> SwarmTeam | None:
        """Dynamically form a team around a purpose."""
        if len(self._teams) >= self._max_teams:
            return None

        self._team_counter += 1
        team = SwarmTeam(
            team_id=f"tm-{self._team_counter}",
            purpose=purpose,
            target_location=target_location,
        )

        # Find available agents
        idle_agents = [
            a for a in self._agents.values()
            if a.active and not a.team_id and a.energy > 0.3
        ]

        # Assign coordinator as leader
        coords = [a for a in idle_agents if a.role == SwarmRole.COORDINATOR]
        if coords:
            leader = coords[0]
            leader.team_id = team.team_id
            team.leader_id = leader.agent_id
            team.member_ids.append(leader.agent_id)
            idle_agents = [a for a in idle_agents if a.agent_id != leader.agent_id]

        # Fill with workers/specialists
        for agent in idle_agents[:member_count]:
            agent.team_id = team.team_id
            team.member_ids.append(agent.agent_id)

        self._teams[team.team_id] = team
        return team

    def dissolve_team(self, team_id: str) -> None:
        """Dissolve a team."""
        team = self._teams.get(team_id)
        if not team:
            return

        for member_id in team.member_ids:
            agent = self._agents.get(member_id)
            if agent:
                agent.team_id = ""

        team.dissolved = True

    def assign_task(
        self,
        agent_id: str,
        task: str,
        location: str = "",
    ) -> None:
        """Assign a task to an agent."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.current_task = task
            agent.current_location = location

    def report_finding(
        self,
        agent_id: str,
        location: str,
        finding: dict[str, Any],
    ) -> None:
        """Agent reports a finding."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.findings_count += 1

        # Deposit finding pheromone
        self.deposit_pheromone(agent_id, location, SwarmSignal.FINDING, strength=1.5)

        # If in a team, add to team findings
        if agent and agent.team_id:
            team = self._teams.get(agent.team_id)
            if team:
                team.findings.append(finding)

        # Update shared state
        findings = self._shared_state.get("findings", [])
        findings.append(finding)
        self._shared_state["findings"] = findings[-100:]

    def consume_energy(self, agent_id: str, amount: float = 0.05) -> None:
        """Consume agent energy (e.g., after work)."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.energy = max(0, agent.energy - amount)
            if agent.energy <= 0:
                agent.active = False

    def recharge_agent(self, agent_id: str, amount: float = 0.2) -> None:
        """Recharge an agent's energy."""
        agent = self._agents.get(agent_id)
        if agent:
            agent.energy = min(1.0, agent.energy + amount)
            if not agent.active and agent.energy > 0.3:
                agent.active = True

    def cleanup_pheromones(self) -> int:
        """Remove expired pheromones."""
        removed = 0
        for location in list(self._pheromones.keys()):
            active = [t for t in self._pheromones[location] if t.is_active]
            removed += len(self._pheromones[location]) - len(active)
            if active:
                self._pheromones[location] = active
            else:
                del self._pheromones[location]
        return removed

    def get_swarm_health(self) -> dict[str, Any]:
        """Get swarm health status."""
        active = [a for a in self._agents.values() if a.active]
        avg_energy = sum(a.energy for a in active) / max(1, len(active))

        role_counts: dict[str, int] = defaultdict(int)
        for agent in active:
            role_counts[agent.role.value] += 1

        return {
            "active_agents": len(active),
            "avg_energy": round(avg_energy, 2),
            "roles": dict(role_counts),
            "teams": sum(1 for t in self._teams.values() if not t.dissolved),
            "pheromone_locations": len(self._pheromones),
            "total_findings": sum(a.findings_count for a in self._agents.values()),
        }

    def get_stats(self) -> dict[str, Any]:
        return self.get_swarm_health()
