"""Reconnaissance orchestrator — automated attack surface mapping.

Implements:
1. Subdomain discovery pipeline
2. Port scanning coordination
3. Technology fingerprinting
4. Service enumeration
5. Content discovery
6. Certificate transparency search
7. DNS record analysis
8. OSINT correlation
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReconPhase(str, Enum):
    DNS = "dns"
    SUBDOMAIN = "subdomain"
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    TECH_DETECT = "tech_detect"
    CONTENT_DISC = "content_discovery"
    OSINT = "osint"
    CERT_TRANS = "cert_transparency"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    CERTIFICATE = "certificate"
    EMAIL = "email"


@dataclass
class DiscoveredAsset:
    """An asset found during reconnaissance."""
    asset_id: str = ""
    asset_type: AssetType = AssetType.DOMAIN
    value: str = ""
    parent: str = ""          # Parent asset that led to discovery
    source: str = ""          # Tool/technique that found it
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.asset_id[:10],
            "type": self.asset_type.value,
            "value": self.value[:40],
            "source": self.source[:15],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReconTask:
    """A reconnaissance task to execute."""
    task_id: str = ""
    phase: ReconPhase = ReconPhase.DNS
    tool: str = ""
    target: str = ""
    args: str = ""
    status: str = "pending"
    result: dict[str, Any] = field(default_factory=dict)
    assets_found: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.started_at > 0 and self.completed_at > 0:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:10],
            "phase": self.phase.value,
            "tool": self.tool[:12],
            "status": self.status[:8],
            "assets": self.assets_found,
        }


@dataclass
class AttackSurface:
    """Complete attack surface profile."""
    target: str = ""
    domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    certificates: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_assets(self) -> int:
        return (
            len(self.domains) + len(self.subdomains) + len(self.ips) +
            sum(len(ports) for ports in self.open_ports.values()) +
            len(self.services) + len(self.technologies) +
            len(self.endpoints) + len(self.emails)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:30],
            "domains": len(self.domains),
            "subdomains": len(self.subdomains),
            "ips": len(self.ips),
            "open_ports": sum(len(p) for p in self.open_ports.values()),
            "services": len(self.services),
            "technologies": len(self.technologies),
            "endpoints": len(self.endpoints),
            "emails": len(self.emails),
            "total": self.total_assets,
        }


# ── Recon tool configurations ───────────────────────────────

RECON_TOOLS: dict[str, dict[str, Any]] = {
    "subfinder": {
        "phase": "subdomain",
        "cmd": "subfinder -d {domain} -silent",
        "output": "newline_delimited",
        "timeout": 120,
    },
    "amass": {
        "phase": "subdomain",
        "cmd": "amass enum -passive -d {domain}",
        "output": "newline_delimited",
        "timeout": 300,
    },
    "crt_sh": {
        "phase": "cert_transparency",
        "cmd": "curl -s 'https://crt.sh/?q=%.{domain}&output=json'",
        "output": "json",
        "timeout": 30,
    },
    "nmap_discovery": {
        "phase": "port_scan",
        "cmd": "nmap -sn {target}",
        "output": "nmap",
        "timeout": 120,
    },
    "nmap_full": {
        "phase": "port_scan",
        "cmd": "nmap -sV -sC -p- {target}",
        "output": "nmap",
        "timeout": 900,
    },
    "nmap_top1000": {
        "phase": "port_scan",
        "cmd": "nmap -sV -sC {target}",
        "output": "nmap",
        "timeout": 300,
    },
    "httpx": {
        "phase": "tech_detect",
        "cmd": "httpx -u {target} -tech-detect -status-code -title -silent",
        "output": "json",
        "timeout": 60,
    },
    "gobuster": {
        "phase": "content_discovery",
        "cmd": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q",
        "output": "newline_delimited",
        "timeout": 300,
    },
    "ffuf": {
        "phase": "content_discovery",
        "cmd": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/common.txt -mc 200,301,302,403 -s",
        "output": "newline_delimited",
        "timeout": 300,
    },
    "fierce": {
        "phase": "dns",
        "cmd": "fierce --domain {domain}",
        "output": "text",
        "timeout": 120,
    },
    "dnsrecon": {
        "phase": "dns",
        "cmd": "dnsrecon -d {domain} -t std",
        "output": "text",
        "timeout": 120,
    },
    "theHarvester": {
        "phase": "osint",
        "cmd": "theHarvester -d {domain} -b all -l 200",
        "output": "text",
        "timeout": 300,
    },
    "wafw00f": {
        "phase": "tech_detect",
        "cmd": "wafw00f {target}",
        "output": "text",
        "timeout": 30,
    },
}


class ReconOrchestrator:
    """Orchestrates reconnaissance for attack surface mapping.

    Coordinates multiple recon tools in a pipeline,
    collects discovered assets, and builds a comprehensive
    attack surface profile.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, ReconTask] = {}
        self._assets: dict[str, DiscoveredAsset] = {}
        self._surfaces: dict[str, AttackSurface] = {}
        self._counter = 0
        self._log = logger.bind(component="recon_orchestrator")

    def plan_recon(
        self,
        target: str,
        scope: str = "full",
    ) -> list[ReconTask]:
        """Plan reconnaissance tasks for a target."""
        tasks = []

        if scope in ("full", "subdomain"):
            for tool in ("subfinder", "amass", "crt_sh"):
                self._counter += 1
                task = ReconTask(
                    task_id=f"recon-{self._counter}",
                    phase=ReconPhase.SUBDOMAIN,
                    tool=tool,
                    target=target,
                    args=RECON_TOOLS[tool]["cmd"].format(domain=target, target=target),
                )
                tasks.append(task)
                self._tasks[task.task_id] = task

        if scope in ("full", "ports"):
            self._counter += 1
            task = ReconTask(
                task_id=f"recon-{self._counter}",
                phase=ReconPhase.PORT_SCAN,
                tool="nmap_top1000",
                target=target,
                args=RECON_TOOLS["nmap_top1000"]["cmd"].format(target=target),
            )
            tasks.append(task)
            self._tasks[task.task_id] = task

        if scope in ("full", "dns"):
            for tool in ("fierce", "dnsrecon"):
                self._counter += 1
                task = ReconTask(
                    task_id=f"recon-{self._counter}",
                    phase=ReconPhase.DNS,
                    tool=tool,
                    target=target,
                    args=RECON_TOOLS[tool]["cmd"].format(domain=target, target=target),
                )
                tasks.append(task)
                self._tasks[task.task_id] = task

        if scope in ("full", "web"):
            for tool in ("httpx", "gobuster", "wafw00f"):
                self._counter += 1
                task = ReconTask(
                    task_id=f"recon-{self._counter}",
                    phase=ReconPhase.TECH_DETECT if tool in ("httpx", "wafw00f") else ReconPhase.CONTENT_DISC,
                    tool=tool,
                    target=target,
                    args=RECON_TOOLS[tool]["cmd"].format(target=target, domain=target),
                )
                tasks.append(task)
                self._tasks[task.task_id] = task

        if scope == "full":
            self._counter += 1
            task = ReconTask(
                task_id=f"recon-{self._counter}",
                phase=ReconPhase.OSINT,
                tool="theHarvester",
                target=target,
                args=RECON_TOOLS["theHarvester"]["cmd"].format(domain=target, target=target),
            )
            tasks.append(task)
            self._tasks[task.task_id] = task

        # Initialize attack surface
        if target not in self._surfaces:
            self._surfaces[target] = AttackSurface(target=target)

        return tasks

    def record_asset(
        self,
        target: str,
        asset_type: AssetType,
        value: str,
        source: str = "",
        parent: str = "",
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> DiscoveredAsset:
        """Record a discovered asset."""
        self._counter += 1

        asset = DiscoveredAsset(
            asset_id=f"asset-{self._counter}",
            asset_type=asset_type,
            value=value,
            source=source,
            parent=parent,
            confidence=confidence,
            metadata=metadata or {},
        )

        self._assets[asset.asset_id] = asset

        # Update attack surface
        surface = self._surfaces.get(target)
        if surface:
            self._update_surface(surface, asset)

        return asset

    def _update_surface(self, surface: AttackSurface, asset: DiscoveredAsset) -> None:
        """Update attack surface with new asset."""
        val = asset.value
        if asset.asset_type == AssetType.DOMAIN and val not in surface.domains:
            surface.domains.append(val)
        elif asset.asset_type == AssetType.SUBDOMAIN and val not in surface.subdomains:
            surface.subdomains.append(val)
        elif asset.asset_type == AssetType.IP and val not in surface.ips:
            surface.ips.append(val)
        elif asset.asset_type == AssetType.TECHNOLOGY and val not in surface.technologies:
            surface.technologies.append(val)
        elif asset.asset_type == AssetType.ENDPOINT and val not in surface.endpoints:
            surface.endpoints.append(val)
        elif asset.asset_type == AssetType.EMAIL and val not in surface.emails:
            surface.emails.append(val)

    def complete_task(
        self,
        task_id: str,
        result: dict[str, Any] | None = None,
        assets_found: int = 0,
        success: bool = True,
    ) -> bool:
        """Mark a recon task as complete."""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.completed_at = time.time()
        task.result = result or {}
        task.assets_found = assets_found
        task.status = "complete" if success else "failed"

        return True

    def get_surface(self, target: str) -> AttackSurface | None:
        """Get attack surface for a target."""
        return self._surfaces.get(target)

    def build_recon_prompt(self, target: str) -> str:
        """Build recon context prompt for the agent."""
        surface = self._surfaces.get(target)
        if not surface:
            return f"No reconnaissance data available for {target}."

        lines = [f"## Attack Surface: {target}\n"]
        if surface.subdomains:
            lines.append(f"Subdomains ({len(surface.subdomains)}):")
            for sub in surface.subdomains[:10]:
                lines.append(f"  - {sub}")
        if surface.ips:
            lines.append(f"IPs: {', '.join(surface.ips[:10])}")
        if surface.technologies:
            lines.append(f"Technologies: {', '.join(surface.technologies[:10])}")
        if surface.open_ports:
            lines.append("Open ports:")
            for ip, ports in list(surface.open_ports.items())[:5]:
                lines.append(f"  {ip}: {', '.join(str(p) for p in ports[:20])}")
        if surface.endpoints:
            lines.append(f"Endpoints ({len(surface.endpoints)}):")
            for ep in surface.endpoints[:10]:
                lines.append(f"  - {ep}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = defaultdict(int)
        for task in self._tasks.values():
            phase_counts[task.phase.value] += 1

        type_counts: dict[str, int] = defaultdict(int)
        for asset in self._assets.values():
            type_counts[asset.asset_type.value] += 1

        return {
            "tasks": len(self._tasks),
            "assets": len(self._assets),
            "surfaces": len(self._surfaces),
            "by_phase": dict(phase_counts),
            "by_type": dict(type_counts),
        }
