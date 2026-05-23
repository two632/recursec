"""Tool selection intelligence — choose the right tool for the job.

Given a task, selects the optimal tool(s) based on:
1. Task type matching (what kind of task?)
2. Target compatibility (does the tool work with this target?)
3. Tool capabilities (what can this tool do?)
4. Historical performance (how well did it work before?)
5. Resource cost (tokens, time, compute)
6. Complementarity (which tools cover each other's gaps?)
7. Current availability (is the tool installed and ready?)
8. Stealth requirements (how noisy is the tool?)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class ToolFit(str, Enum):
    PERFECT = "perfect"     # Exactly right tool
    GOOD = "good"           # Good match
    ADEQUATE = "adequate"   # Will work but not optimal
    POOR = "poor"           # Bad match
    INCOMPATIBLE = "incompatible"  # Won't work


@dataclass
class ToolProfile:
    """Profile of a tool's capabilities and performance history."""
    name: str = ""
    categories: list[str] = field(default_factory=list)
    target_types: list[str] = field(default_factory=list)  # web, network, code, etc.
    capabilities: list[str] = field(default_factory=list)
    noise_level: float = 0.5     # 0=silent, 1=very noisy
    avg_time_s: float = 60.0
    avg_quality: float = 0.5
    times_used: int = 0
    successes: int = 0
    failures: int = 0
    avg_findings: float = 0.0
    installed: bool = False
    requires_auth: bool = False
    complementary_tools: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        total = self.successes + self.failures
        return self.successes / max(1, total)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "categories": self.categories[:3],
            "targets": self.target_types[:3],
            "noise": round(self.noise_level, 2),
            "success_rate": round(self.success_rate, 2),
            "avg_quality": round(self.avg_quality, 2),
            "installed": self.installed,
        }


@dataclass
class ToolRecommendation:
    """A recommendation to use a specific tool."""
    tool_name: str = ""
    fit: ToolFit = ToolFit.ADEQUATE
    score: float = 0.0
    reasoning: str = ""
    suggested_args: list[str] = field(default_factory=list)
    expected_time_s: float = 60.0
    complementary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "fit": self.fit.value,
            "score": round(self.score, 3),
            "reasoning": self.reasoning[:100],
            "args": self.suggested_args[:5],
        }


@dataclass
class ToolSelectionResult:
    """Result of tool selection."""
    task: str = ""
    recommendations: list[ToolRecommendation] = field(default_factory=list)
    primary_tool: str = ""
    secondary_tools: list[str] = field(default_factory=list)
    total_estimated_time_s: float = 0.0
    selection_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task[:100],
            "primary": self.primary_tool,
            "secondary": self.secondary_tools[:3],
            "recommendations": len(self.recommendations),
            "time_ms": round(self.selection_time_ms, 1),
        }


# ── Built-in Tool Knowledge ─────────────────────────────────

TOOL_KNOWLEDGE: list[dict[str, Any]] = [
    # Recon
    {"name": "nmap", "categories": ["recon", "port_scan", "service_detection"],
     "targets": ["network", "host", "ip"], "noise": 0.6,
     "capabilities": ["port_scan", "service_version", "os_detection", "scripts"]},
    {"name": "masscan", "categories": ["recon", "port_scan"],
     "targets": ["network", "ip_range"], "noise": 0.8,
     "capabilities": ["fast_port_scan"]},
    {"name": "subfinder", "categories": ["recon", "subdomain"],
     "targets": ["domain"], "noise": 0.1,
     "capabilities": ["subdomain_discovery"]},
    {"name": "amass", "categories": ["recon", "subdomain", "osint"],
     "targets": ["domain"], "noise": 0.2,
     "capabilities": ["subdomain_discovery", "dns_enum"]},
    {"name": "httpx", "categories": ["recon", "web_probe"],
     "targets": ["url", "domain"], "noise": 0.3,
     "capabilities": ["http_probe", "tech_detect"]},
    {"name": "katana", "categories": ["recon", "crawler"],
     "targets": ["url", "web"], "noise": 0.4,
     "capabilities": ["web_crawl", "endpoint_discovery", "js_crawl"]},
    {"name": "whatweb", "categories": ["recon", "fingerprint"],
     "targets": ["url", "web"], "noise": 0.2,
     "capabilities": ["tech_fingerprint"]},

    # Scanners
    {"name": "nuclei", "categories": ["scanner", "vuln_scan"],
     "targets": ["url", "web", "network"], "noise": 0.5,
     "capabilities": ["vuln_detection", "template_scan", "cve_check"]},
    {"name": "nikto", "categories": ["scanner", "web_scan"],
     "targets": ["url", "web"], "noise": 0.7,
     "capabilities": ["web_vuln_scan", "misconfig_check"]},

    # Web exploitation
    {"name": "sqlmap", "categories": ["exploit", "web", "injection"],
     "targets": ["url", "web", "api"], "noise": 0.6,
     "capabilities": ["sqli_detection", "sqli_exploitation", "db_dump"]},
    {"name": "dalfox", "categories": ["exploit", "web", "xss"],
     "targets": ["url", "web"], "noise": 0.4,
     "capabilities": ["xss_detection", "xss_exploitation"]},
    {"name": "gobuster", "categories": ["recon", "web", "bruteforce"],
     "targets": ["url", "web"], "noise": 0.6,
     "capabilities": ["dir_bruteforce", "dns_bruteforce", "vhost_bruteforce"]},
    {"name": "ffuf", "categories": ["recon", "web", "fuzzing"],
     "targets": ["url", "web", "api"], "noise": 0.5,
     "capabilities": ["fuzzing", "dir_bruteforce", "param_fuzzing"]},

    # Code analysis
    {"name": "semgrep", "categories": ["code_audit", "sast"],
     "targets": ["code", "repo"], "noise": 0.0,
     "capabilities": ["static_analysis", "pattern_matching", "vuln_detection"]},
    {"name": "bandit", "categories": ["code_audit", "sast"],
     "targets": ["python_code"], "noise": 0.0,
     "capabilities": ["python_security_lint"]},
    {"name": "trivy", "categories": ["code_audit", "sca"],
     "targets": ["code", "container", "repo"], "noise": 0.0,
     "capabilities": ["dependency_scan", "container_scan", "cve_check"]},
    {"name": "gitleaks", "categories": ["code_audit", "secret_scan"],
     "targets": ["code", "repo"], "noise": 0.0,
     "capabilities": ["secret_detection", "credential_scan"]},

    # Network
    {"name": "hydra", "categories": ["brute_force", "network"],
     "targets": ["network", "service", "web"], "noise": 0.9,
     "capabilities": ["password_brute", "login_brute"]},
    {"name": "enum4linux", "categories": ["recon", "network", "smb"],
     "targets": ["network", "windows"], "noise": 0.5,
     "capabilities": ["smb_enum", "user_enum", "share_enum"]},
    {"name": "testssl", "categories": ["scanner", "network", "tls"],
     "targets": ["network", "web"], "noise": 0.2,
     "capabilities": ["ssl_check", "cipher_check", "cert_check"]},
]

# Task → tool mapping
TASK_TOOL_MAP: dict[str, list[str]] = {
    "port_scan": ["nmap", "masscan"],
    "subdomain": ["subfinder", "amass"],
    "web_crawl": ["katana", "httpx"],
    "vuln_scan": ["nuclei", "nikto"],
    "sqli": ["sqlmap"],
    "xss": ["dalfox"],
    "dir_bruteforce": ["gobuster", "ffuf"],
    "code_audit": ["semgrep", "bandit"],
    "secret_scan": ["gitleaks", "trufflehog"],
    "dependency_scan": ["trivy", "grype"],
    "password_brute": ["hydra"],
    "smb_enum": ["enum4linux"],
    "ssl_check": ["testssl", "sslscan"],
    "fingerprint": ["whatweb", "httpx"],
}

TOOL_SELECT_PROMPT = """Select the best tools for this security task.

Task: {task}
Target: {target}
Target type: {target_type}
Available tools: {available}
Constraints: {constraints}

Consider: effectiveness, noise level, speed, and complementarity.

Respond as JSON:
{{
  "primary_tool": "tool_name",
  "primary_args": ["suggested", "arguments"],
  "primary_reasoning": "why this tool",
  "secondary_tools": [
    {{
      "tool": "name",
      "args": ["args"],
      "reasoning": "why"
    }}
  ]
}}"""


class ToolSelector:
    """Intelligent tool selection engine.

    Matches tasks to tools using knowledge base, performance
    history, and optionally LLM reasoning.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._profiles: dict[str, ToolProfile] = {}
        self._selection_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="tool_selector")

        self._load_knowledge()

    def _load_knowledge(self) -> None:
        """Load built-in tool knowledge."""
        for tool_data in TOOL_KNOWLEDGE:
            profile = ToolProfile(
                name=tool_data["name"],
                categories=tool_data.get("categories", []),
                target_types=tool_data.get("targets", []),
                capabilities=tool_data.get("capabilities", []),
                noise_level=tool_data.get("noise", 0.5),
            )
            self._profiles[profile.name] = profile

    async def select(
        self,
        task: str,
        target: str = "",
        target_type: str = "",
        stealth_required: bool = False,
        max_tools: int = 3,
        available_only: bool = True,
    ) -> ToolSelectionResult:
        """Select the best tool(s) for a task."""
        start = time.time()

        # Heuristic selection
        recommendations = self._heuristic_select(
            task, target_type, stealth_required, available_only,
        )

        # LLM-enhanced selection if available
        if self._router and not recommendations:
            recommendations = await self._llm_select(
                task, target, target_type,
                [p.name for p in self._profiles.values()],
            )

        # Sort and limit
        recommendations.sort(key=lambda r: -r.score)
        recommendations = recommendations[:max_tools]

        result = ToolSelectionResult(
            task=task,
            recommendations=recommendations,
            primary_tool=recommendations[0].tool_name if recommendations else "",
            secondary_tools=[r.tool_name for r in recommendations[1:]],
            total_estimated_time_s=sum(r.expected_time_s for r in recommendations),
            selection_time_ms=(time.time() - start) * 1000,
        )

        self._selection_history.append(result.to_dict())
        return result

    def record_result(
        self,
        tool_name: str,
        success: bool,
        quality: float = 0.5,
        findings_count: int = 0,
        time_s: float = 0.0,
    ) -> None:
        """Record tool usage result for learning."""
        profile = self._profiles.get(tool_name)
        if not profile:
            return

        profile.times_used += 1
        if success:
            profile.successes += 1
        else:
            profile.failures += 1

        n = profile.times_used
        profile.avg_quality = (profile.avg_quality * (n - 1) + quality) / n
        profile.avg_findings = (profile.avg_findings * (n - 1) + findings_count) / n
        if time_s > 0:
            profile.avg_time_s = (profile.avg_time_s * (n - 1) + time_s) / n

    def _heuristic_select(
        self,
        task: str,
        target_type: str,
        stealth: bool,
        available_only: bool,
    ) -> list[ToolRecommendation]:
        """Heuristic-based tool selection."""
        task_lower = task.lower()
        recommendations = []

        for profile in self._profiles.values():
            if available_only and not profile.installed:
                continue

            score = 0.0
            reasons = []

            # Category match
            for cat in profile.categories:
                if cat in task_lower:
                    score += 0.3
                    reasons.append(f"Category match: {cat}")

            # Target type match
            if target_type:
                if target_type in profile.target_types:
                    score += 0.2
                    reasons.append(f"Target compatible: {target_type}")

            # Capability match
            for cap in profile.capabilities:
                if cap.replace("_", " ") in task_lower or cap in task_lower:
                    score += 0.2
                    reasons.append(f"Capability: {cap}")

            # Task map match
            for task_key, tools in TASK_TOOL_MAP.items():
                if task_key in task_lower and profile.name in tools:
                    score += 0.25
                    reasons.append(f"Task map: {task_key}")

            # Stealth preference
            if stealth and profile.noise_level > 0.7:
                score *= 0.5
                reasons.append("Penalty: too noisy")

            # Historical performance
            if profile.times_used > 0:
                score += profile.success_rate * 0.1
                score += min(0.1, profile.avg_findings * 0.02)

            if score > 0.1:
                fit = ToolFit.PERFECT if score > 0.6 else ToolFit.GOOD if score > 0.4 else ToolFit.ADEQUATE
                recommendations.append(ToolRecommendation(
                    tool_name=profile.name,
                    fit=fit,
                    score=score,
                    reasoning="; ".join(reasons[:3]),
                    expected_time_s=profile.avg_time_s,
                    complementary=profile.complementary_tools,
                ))

        return recommendations

    async def _llm_select(
        self,
        task: str,
        target: str,
        target_type: str,
        available: list[str],
    ) -> list[ToolRecommendation]:
        """LLM-based tool selection."""
        if not self._router:
            return []

        prompt = TOOL_SELECT_PROMPT.format(
            task=task, target=target,
            target_type=target_type,
            available=", ".join(available[:20]),
            constraints="None",
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="tool_selection",
            temperature=0.1,
            max_tokens=512,
        )

        data = self._parse_json(response)
        recommendations = []

        primary = data.get("primary_tool", "")
        if primary:
            recommendations.append(ToolRecommendation(
                tool_name=primary,
                fit=ToolFit.GOOD,
                score=0.8,
                reasoning=data.get("primary_reasoning", ""),
                suggested_args=data.get("primary_args", []),
            ))

        for sec in data.get("secondary_tools", []):
            recommendations.append(ToolRecommendation(
                tool_name=sec.get("tool", ""),
                fit=ToolFit.ADEQUATE,
                score=0.5,
                reasoning=sec.get("reasoning", ""),
                suggested_args=sec.get("args", []),
            ))

        return recommendations

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        return {
            "profiles": len(self._profiles),
            "selections": len(self._selection_history),
            "installed": sum(1 for p in self._profiles.values() if p.installed),
        }
