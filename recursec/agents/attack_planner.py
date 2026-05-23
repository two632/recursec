"""Attack path planner — constructs multi-step attack chains.

Models the target as a graph of assets and access levels, then uses
LLM reasoning + graph algorithms to find optimal attack paths.

Concepts:
- AttackSurface: Known endpoints, services, and assets
- AccessLevel: Current access (none, user, admin, system)
- AttackStep: A single action that may change access level
- AttackPath: A sequence of steps from initial access to objective
- AttackGraph: DAG of all known possible attack paths

The planner:
1. Maps the attack surface from recon data
2. Generates candidate attack steps using LLMs
3. Evaluates feasibility of each step
4. Constructs optimal paths using graph search
5. Prioritizes paths by impact/feasibility ratio
6. Updates graph as new information is discovered
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class AccessLevel(int, Enum):
    NONE = 0
    ANONYMOUS = 1
    AUTHENTICATED = 2
    USER = 3
    PRIVILEGED = 4
    ADMIN = 5
    SYSTEM = 6
    ROOT = 7


class AssetType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    DATABASE = "database"
    CREDENTIAL = "credential"
    FILE = "file"
    NETWORK_SEGMENT = "network_segment"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"


class StepCategory(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Asset:
    """A target asset in the attack surface."""
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    asset_type: AssetType = AssetType.HOST
    address: str = ""  # IP, URL, hostname
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    current_access: AccessLevel = AccessLevel.NONE
    vulnerabilities: list[str] = field(default_factory=list)
    connected_to: list[str] = field(default_factory=list)  # asset_ids
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.asset_id, "name": self.name,
            "type": self.asset_type.value, "address": self.address,
            "ports": self.ports, "services": self.services,
            "access": self.current_access.value,
            "vulns": len(self.vulnerabilities),
            "connections": len(self.connected_to),
        }


@dataclass
class AttackStep:
    """A single step in an attack path."""
    step_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    category: StepCategory = StepCategory.INITIAL_ACCESS
    source_asset: str = ""  # Starting asset_id
    target_asset: str = ""  # Target asset_id
    required_access: AccessLevel = AccessLevel.NONE
    grants_access: AccessLevel = AccessLevel.NONE
    tool: str = ""
    technique: str = ""  # MITRE ATT&CK technique ID
    difficulty: float = 0.5  # 0.0 = trivial, 1.0 = very hard
    reliability: float = 0.5  # 0.0 = unreliable, 1.0 = guaranteed
    stealth: float = 0.5  # 0.0 = noisy, 1.0 = silent
    impact: float = 0.5  # 0.0 = minimal, 1.0 = devastating
    prerequisites: list[str] = field(default_factory=list)  # step_ids
    vulnerability_id: str = ""  # CVE or finding ID
    executed: bool = False
    success: bool = False

    @property
    def feasibility_score(self) -> float:
        """Combined feasibility: reliability * (1 - difficulty)."""
        return self.reliability * (1.0 - self.difficulty * 0.5)

    @property
    def risk_score(self) -> float:
        """Risk = impact * feasibility."""
        return self.impact * self.feasibility_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id, "name": self.name,
            "category": self.category.value,
            "source": self.source_asset, "target": self.target_asset,
            "access_required": self.required_access.value,
            "access_grants": self.grants_access.value,
            "tool": self.tool, "technique": self.technique,
            "difficulty": round(self.difficulty, 2),
            "reliability": round(self.reliability, 2),
            "feasibility": round(self.feasibility_score, 2),
            "risk": round(self.risk_score, 2),
        }


@dataclass
class AttackPath:
    """A sequence of attack steps from entry to objective."""
    path_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    entry_point: str = ""  # Starting asset
    objective: str = ""  # Goal description
    max_access_achieved: AccessLevel = AccessLevel.NONE
    total_risk: float = 0.0
    total_feasibility: float = 0.0
    status: str = "proposed"  # proposed, executing, completed, failed

    def calculate_scores(self) -> None:
        """Calculate path-level scores from steps."""
        if not self.steps:
            return
        # Path feasibility is the product of individual step feasibilities
        self.total_feasibility = 1.0
        self.total_risk = 0.0
        for step in self.steps:
            self.total_feasibility *= step.feasibility_score
            self.total_risk = max(self.total_risk, step.risk_score)
        self.max_access_achieved = max(
            (s.grants_access for s in self.steps),
            default=AccessLevel.NONE,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path_id, "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "entry": self.entry_point, "objective": self.objective,
            "max_access": self.max_access_achieved.value,
            "feasibility": round(self.total_feasibility, 3),
            "risk": round(self.total_risk, 3),
            "status": self.status,
        }


class AttackSurface:
    """Models the target's attack surface as a graph."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._steps: dict[str, AttackStep] = {}
        self._adjacency: dict[str, list[str]] = defaultdict(list)  # asset_id → [step_ids]

    def add_asset(self, asset: Asset) -> str:
        self._assets[asset.asset_id] = asset
        return asset.asset_id

    def add_step(self, step: AttackStep) -> str:
        self._steps[step.step_id] = step
        if step.source_asset:
            self._adjacency[step.source_asset].append(step.step_id)
        return step.step_id

    def get_asset(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def get_steps_from(self, asset_id: str) -> list[AttackStep]:
        """Get all attack steps originating from an asset."""
        return [
            self._steps[sid]
            for sid in self._adjacency.get(asset_id, [])
            if sid in self._steps
        ]

    def get_reachable_assets(self, from_asset: str, current_access: AccessLevel) -> list[Asset]:
        """Get assets reachable from a given asset with current access level."""
        reachable = []
        for step_id in self._adjacency.get(from_asset, []):
            step = self._steps.get(step_id)
            if step and step.required_access.value <= current_access.value:
                target = self._assets.get(step.target_asset)
                if target:
                    reachable.append(target)
        return reachable

    def find_paths(
        self,
        start: str,
        target_access: AccessLevel = AccessLevel.ROOT,
        max_depth: int = 10,
    ) -> list[AttackPath]:
        """Find all attack paths from start to target access level using BFS."""
        paths: list[AttackPath] = []

        queue: deque[tuple[str, AccessLevel, list[AttackStep]]] = deque()
        queue.append((start, AccessLevel.NONE, []))
        visited: set[tuple[str, int]] = set()

        while queue:
            current_asset, current_access, path_steps = queue.popleft()

            if current_access.value >= target_access.value and path_steps:
                attack_path = AttackPath(
                    name=f"Path from {start} to {target_access.name}",
                    steps=list(path_steps),
                    entry_point=start,
                    objective=f"Achieve {target_access.name} access",
                )
                attack_path.calculate_scores()
                paths.append(attack_path)
                continue

            if len(path_steps) >= max_depth:
                continue

            state = (current_asset, current_access.value)
            if state in visited:
                continue
            visited.add(state)

            for step in self.get_steps_from(current_asset):
                if step.required_access.value <= current_access.value:
                    new_access = max(current_access, step.grants_access, key=lambda x: x.value)
                    queue.append((
                        step.target_asset or current_asset,
                        new_access,
                        [*path_steps, step],
                    ))

        # Sort by feasibility (highest first)
        paths.sort(key=lambda p: -p.total_feasibility)
        return paths

    def get_summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        for a in self._assets.values():
            by_type[a.asset_type.value] += 1
        return {
            "total_assets": len(self._assets),
            "total_steps": len(self._steps),
            "by_asset_type": dict(by_type),
        }


# ── Prompt Templates ──────────────────────────────────────

MAP_SURFACE_PROMPT = """Given these reconnaissance results, identify the target's attack surface.

Target: {target}
Recon data: {recon_data}

List all discovered assets as JSON:
{{
  "assets": [
    {{
      "name": "descriptive name",
      "type": "host|service|endpoint|database|credential|file",
      "address": "IP/URL/path",
      "ports": [80, 443],
      "services": ["nginx", "mysql"],
      "technologies": ["php", "wordpress"],
      "connections": ["asset_names that this connects to"]
    }}
  ]
}}"""

GENERATE_STEPS_PROMPT = """Given these assets and vulnerabilities, generate possible attack steps.

Assets: {assets}
Known vulnerabilities: {vulns}
Current access level: {access_level}

For each possible attack, provide:
{{
  "steps": [
    {{
      "name": "step name",
      "description": "what this does",
      "category": "initial_access|execution|privilege_escalation|lateral_movement|credential_access",
      "source_asset": "asset_name",
      "target_asset": "asset_name",
      "required_access": 0-7,
      "grants_access": 0-7,
      "tool": "tool_name",
      "technique": "T1190",
      "difficulty": 0.0-1.0,
      "reliability": 0.0-1.0,
      "stealth": 0.0-1.0,
      "impact": 0.0-1.0
    }}
  ]
}}"""

PRIORITIZE_PATHS_PROMPT = """Given these attack paths, prioritize them by risk and feasibility.

Paths:
{paths}

Objective: {objective}
Constraints: {constraints}

Rank the paths and explain your reasoning. Respond as JSON:
{{
  "ranked_paths": [
    {{
      "path_index": 0,
      "score": 0.0-1.0,
      "reasoning": "why this path",
      "recommended": true/false
    }}
  ]
}}"""


class AttackPathPlanner:
    """Plans multi-step attack paths using LLM reasoning + graph algorithms."""

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._surface = AttackSurface()
        self._paths: list[AttackPath] = []
        self._log = logger.bind(component="attack_planner")

    async def map_surface(self, target: str, recon_data: dict[str, Any]) -> AttackSurface:
        """Map the attack surface from reconnaissance data."""
        prompt = MAP_SURFACE_PROMPT.format(
            target=target,
            recon_data=json.dumps(recon_data)[:4000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.2,
            max_tokens=4096,
        )

        data = self._parse_json(response)
        name_to_id: dict[str, str] = {}

        for asset_data in data.get("assets", []):
            asset = Asset(
                name=asset_data.get("name", ""),
                asset_type=self._parse_asset_type(asset_data.get("type", "host")),
                address=asset_data.get("address", ""),
                ports=asset_data.get("ports", []),
                services=asset_data.get("services", []),
                technologies=asset_data.get("technologies", []),
            )
            aid = self._surface.add_asset(asset)
            name_to_id[asset.name] = aid

        # Resolve connections
        for asset_data in data.get("assets", []):
            name = asset_data.get("name", "")
            aid = name_to_id.get(name)
            if aid:
                asset = self._surface.get_asset(aid)
                if asset:
                    for conn_name in asset_data.get("connections", []):
                        conn_id = name_to_id.get(conn_name)
                        if conn_id:
                            asset.connected_to.append(conn_id)

        self._log.info("surface_mapped", assets=len(self._surface._assets))
        return self._surface

    async def generate_attack_steps(
        self,
        vulnerabilities: list[dict[str, Any]] | None = None,
        current_access: AccessLevel = AccessLevel.NONE,
    ) -> list[AttackStep]:
        """Generate possible attack steps from current position."""
        assets_desc = json.dumps([
            a.to_dict() for a in self._surface._assets.values()
        ])[:3000]

        prompt = GENERATE_STEPS_PROMPT.format(
            assets=assets_desc,
            vulns=json.dumps(vulnerabilities or [])[:2000],
            access_level=current_access.value,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.3,
            max_tokens=4096,
        )

        data = self._parse_json(response)
        steps = []

        for step_data in data.get("steps", []):
            step = AttackStep(
                name=step_data.get("name", ""),
                description=step_data.get("description", ""),
                category=self._parse_category(step_data.get("category", "initial_access")),
                tool=step_data.get("tool", ""),
                technique=step_data.get("technique", ""),
                difficulty=step_data.get("difficulty", 0.5),
                reliability=step_data.get("reliability", 0.5),
                stealth=step_data.get("stealth", 0.5),
                impact=step_data.get("impact", 0.5),
            )

            # Resolve asset references
            for asset in self._surface._assets.values():
                if asset.name == step_data.get("source_asset"):
                    step.source_asset = asset.asset_id
                if asset.name == step_data.get("target_asset"):
                    step.target_asset = asset.asset_id

            try:
                step.required_access = AccessLevel(step_data.get("required_access", 0))
                step.grants_access = AccessLevel(step_data.get("grants_access", 0))
            except ValueError:
                pass

            self._surface.add_step(step)
            steps.append(step)

        self._log.info("steps_generated", count=len(steps))
        return steps

    async def find_attack_paths(
        self,
        entry_asset_id: str = "",
        target_access: AccessLevel = AccessLevel.ROOT,
        max_paths: int = 5,
    ) -> list[AttackPath]:
        """Find optimal attack paths."""
        # If no entry specified, use all external-facing assets
        start_assets = []
        if entry_asset_id:
            start_assets = [entry_asset_id]
        else:
            start_assets = [
                a.asset_id for a in self._surface._assets.values()
                if a.asset_type in (AssetType.HOST, AssetType.SERVICE, AssetType.ENDPOINT)
            ]

        all_paths: list[AttackPath] = []
        for start in start_assets:
            paths = self._surface.find_paths(start, target_access)
            all_paths.extend(paths)

        # Sort by feasibility and deduplicate
        all_paths.sort(key=lambda p: -p.total_feasibility)
        self._paths = all_paths[:max_paths]

        self._log.info("paths_found", total=len(all_paths), selected=len(self._paths))
        return self._paths

    async def prioritize_paths(
        self,
        paths: list[AttackPath] | None = None,
        objective: str = "achieve maximum access",
        constraints: dict[str, Any] | None = None,
    ) -> list[tuple[AttackPath, float]]:
        """Use LLM to prioritize attack paths."""
        target_paths = paths or self._paths
        if not target_paths:
            return []

        paths_desc = json.dumps([p.to_dict() for p in target_paths[:10]])[:4000]

        prompt = PRIORITIZE_PATHS_PROMPT.format(
            paths=paths_desc,
            objective=objective,
            constraints=json.dumps(constraints or {}),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        ranked: list[tuple[AttackPath, float]] = []

        for ranking in data.get("ranked_paths", []):
            idx = ranking.get("path_index", 0)
            score = ranking.get("score", 0.5)
            if 0 <= idx < len(target_paths):
                ranked.append((target_paths[idx], score))

        ranked.sort(key=lambda x: -x[1])
        return ranked

    def get_surface_summary(self) -> dict[str, Any]:
        return self._surface.get_summary()

    def get_paths(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._paths]

    def _parse_asset_type(self, text: str) -> AssetType:
        try:
            return AssetType(text)
        except ValueError:
            return AssetType.HOST

    def _parse_category(self, text: str) -> StepCategory:
        try:
            return StepCategory(text)
        except ValueError:
            return StepCategory.INITIAL_ACCESS

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
