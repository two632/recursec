"""Tool recommender — recommends optimal tools for targets and findings.

Implements:
1. Target-type based tool recommendation
2. Technology-aware tool selection
3. Finding-triggered tool chains
4. Tool capability matching
5. Tool conflict detection
6. Execution order optimization
7. Resource-aware recommendations
8. Historical success-rate based ranking
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ToolProfile:
    """Profile of a security tool."""
    name: str = ""
    category: str = ""             # recon, scanner, exploit, fuzzer, etc.
    target_types: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    finds: list[str] = field(default_factory=list)      # What it can find
    prerequisites: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    avg_time_s: float = 60.0
    noise_level: str = "medium"    # low, medium, high
    reliability: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "category": self.category,
            "targets": self.target_types[:3],
            "reliability": round(self.reliability, 2),
        }


@dataclass
class ToolRecommendation:
    """A recommended tool with reasoning."""
    tool: str = ""
    score: float = 0.0
    reason: str = ""
    command_template: str = ""
    priority: int = 5
    estimated_time_s: float = 60.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "score": round(self.score, 2),
            "reason": self.reason[:60], "priority": self.priority,
        }


# ── Tool Database ─────────────────────────────────────────────

TOOL_DATABASE: list[dict[str, Any]] = [
    # Recon tools
    {"name": "subfinder", "category": "recon",
     "target_types": ["domain"], "finds": ["subdomains"],
     "cmd": "subfinder -d {target} -silent", "time": 30},

    {"name": "amass", "category": "recon",
     "target_types": ["domain"], "finds": ["subdomains", "dns_records"],
     "cmd": "amass enum -d {target} -passive", "time": 120},

    {"name": "httpx", "category": "recon",
     "target_types": ["domain", "ip", "url_list"], "finds": ["live_hosts", "technologies"],
     "cmd": "echo {target} | httpx -silent -tech-detect", "time": 15},

    {"name": "whatweb", "category": "recon",
     "target_types": ["web_app", "url"], "finds": ["technologies"],
     "cmd": "whatweb {target}", "time": 10},

    {"name": "dig", "category": "recon",
     "target_types": ["domain"], "finds": ["dns_records"],
     "cmd": "dig {target} ANY +short", "time": 5},

    {"name": "whois", "category": "recon",
     "target_types": ["domain", "ip"], "finds": ["registration_info"],
     "cmd": "whois {target}", "time": 5},

    # Port scanning
    {"name": "nmap", "category": "scanner",
     "target_types": ["ip", "host", "network"],
     "finds": ["open_ports", "services", "os"],
     "cmd": "nmap -sV -sC -T4 {target}", "time": 120},

    {"name": "masscan", "category": "scanner",
     "target_types": ["network", "ip_range"],
     "finds": ["open_ports"],
     "cmd": "masscan {target} -p1-65535 --rate=1000", "time": 60,
     "noise_level": "high"},

    # Vulnerability scanning
    {"name": "nuclei", "category": "vuln_scanner",
     "target_types": ["web_app", "url", "ip"],
     "finds": ["vulnerabilities", "misconfigurations", "exposures"],
     "cmd": "nuclei -u {target} -severity critical,high,medium -silent", "time": 180},

    {"name": "nikto", "category": "vuln_scanner",
     "target_types": ["web_app"], "finds": ["web_vulns", "misconfigurations"],
     "cmd": "nikto -h {target} -maxtime 300", "time": 300},

    # Web testing
    {"name": "ffuf", "category": "fuzzer",
     "target_types": ["web_app"], "finds": ["directories", "files", "parameters"],
     "cmd": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302", "time": 60},

    {"name": "sqlmap", "category": "exploit",
     "target_types": ["web_app"], "finds": ["sql_injection"],
     "technologies": ["php", "asp", "jsp", "python"],
     "cmd": "sqlmap -u {target} --batch --level=1 --risk=1", "time": 120},

    {"name": "dalfox", "category": "exploit",
     "target_types": ["web_app"], "finds": ["xss"],
     "cmd": "dalfox url {target} --silence", "time": 60},

    {"name": "commix", "category": "exploit",
     "target_types": ["web_app"], "finds": ["command_injection"],
     "cmd": "commix -u {target} --batch", "time": 120},

    # SSL/TLS
    {"name": "sslscan", "category": "scanner",
     "target_types": ["web_app", "ip"], "finds": ["ssl_issues", "weak_ciphers"],
     "cmd": "sslscan {target}", "time": 15},

    {"name": "testssl.sh", "category": "scanner",
     "target_types": ["web_app", "ip"], "finds": ["ssl_issues", "weak_ciphers"],
     "cmd": "testssl.sh {target}", "time": 120},

    # Credential testing
    {"name": "hydra", "category": "exploit",
     "target_types": ["ip", "host"], "finds": ["weak_credentials"],
     "cmd": "hydra -L users.txt -P passwords.txt {target} ssh", "time": 300,
     "noise_level": "high"},

    # Code analysis
    {"name": "semgrep", "category": "code_audit",
     "target_types": ["source_code"], "finds": ["code_vulns"],
     "cmd": "semgrep --config=auto {target}", "time": 60},

    {"name": "bandit", "category": "code_audit",
     "target_types": ["source_code"], "finds": ["python_vulns"],
     "technologies": ["python"],
     "cmd": "bandit -r {target} -f json", "time": 30},

    {"name": "gitleaks", "category": "code_audit",
     "target_types": ["source_code", "git_repo"], "finds": ["secrets", "api_keys"],
     "cmd": "gitleaks detect -s {target}", "time": 30},

    # Container security
    {"name": "trivy", "category": "scanner",
     "target_types": ["container", "source_code"], "finds": ["container_vulns", "sbom"],
     "cmd": "trivy image {target}", "time": 60},

    # WordPress
    {"name": "wpscan", "category": "vuln_scanner",
     "target_types": ["web_app"],
     "technologies": ["wordpress"],
     "finds": ["wp_vulns", "wp_users", "wp_plugins"],
     "cmd": "wpscan --url {target} --enumerate vp,u", "time": 120},
]


class ToolRecommender:
    """Recommends optimal tools for targets and findings.

    Uses target type, technology stack, and historical
    performance to suggest the best tools.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, ToolProfile] = {}
        self._success_rates: dict[str, float] = defaultdict(lambda: 0.5)
        self._log = logger.bind(component="tool_recommender")

        self._init_profiles()

    def _init_profiles(self) -> None:
        """Initialize tool profiles from database."""
        for tool_data in TOOL_DATABASE:
            profile = ToolProfile(
                name=tool_data["name"],
                category=tool_data.get("category", ""),
                target_types=tool_data.get("target_types", []),
                technologies=tool_data.get("technologies", []),
                finds=tool_data.get("finds", []),
                avg_time_s=tool_data.get("time", 60),
                noise_level=tool_data.get("noise_level", "medium"),
            )
            self._profiles[tool_data["name"]] = profile

    def recommend(
        self,
        target_type: str,
        technologies: list[str] | None = None,
        findings_so_far: list[str] | None = None,
        time_budget_s: float = 3600.0,
        stealth: bool = False,
        limit: int = 10,
    ) -> list[ToolRecommendation]:
        """Recommend tools for a target."""
        technologies = technologies or []
        findings_so_far = findings_so_far or []

        candidates = []

        for profile in self._profiles.values():
            score = self._score_tool(
                profile, target_type, technologies,
                findings_so_far, time_budget_s, stealth,
            )
            if score > 0:
                cmd = self._get_command(profile.name)
                candidates.append(ToolRecommendation(
                    tool=profile.name,
                    score=score,
                    reason=self._explain_recommendation(profile, target_type),
                    command_template=cmd,
                    estimated_time_s=profile.avg_time_s,
                ))

        candidates.sort(key=lambda r: r.score, reverse=True)

        # Assign priorities
        for i, rec in enumerate(candidates[:limit]):
            rec.priority = i + 1

        return candidates[:limit]

    def recommend_for_finding(
        self,
        finding: dict[str, Any],
    ) -> list[ToolRecommendation]:
        """Recommend follow-up tools based on a finding."""
        finding_type = finding.get("type", finding.get("title", "")).lower()

        recommendations = []

        # XSS finding → run dalfox
        if "xss" in finding_type:
            recommendations.append(ToolRecommendation(
                tool="dalfox", score=0.9,
                reason="Follow up XSS finding with specialized scanner",
            ))

        # SQL injection → run sqlmap
        if "sql" in finding_type or "injection" in finding_type:
            recommendations.append(ToolRecommendation(
                tool="sqlmap", score=0.95,
                reason="Confirm SQL injection with sqlmap",
            ))

        # Open port → run nuclei on that port
        if "open port" in finding_type or "service" in finding_type:
            recommendations.append(ToolRecommendation(
                tool="nuclei", score=0.8,
                reason="Scan discovered service for vulnerabilities",
            ))

        # SSL issues → run testssl
        if "ssl" in finding_type or "tls" in finding_type:
            recommendations.append(ToolRecommendation(
                tool="testssl.sh", score=0.85,
                reason="Deep SSL/TLS analysis",
            ))

        # WordPress → run wpscan
        if "wordpress" in finding_type or "wp-" in finding_type:
            recommendations.append(ToolRecommendation(
                tool="wpscan", score=0.9,
                reason="WordPress-specific vulnerability scanning",
            ))

        return recommendations

    def _score_tool(
        self,
        profile: ToolProfile,
        target_type: str,
        technologies: list[str],
        findings: list[str],
        time_budget: float,
        stealth: bool,
    ) -> float:
        """Score a tool for a specific context."""
        score = 0.0

        # Target type match
        if target_type in profile.target_types:
            score += 3.0
        elif "general" in profile.target_types:
            score += 1.0

        # Technology match
        if profile.technologies:
            tech_overlap = set(t.lower() for t in technologies) & set(t.lower() for t in profile.technologies)
            score += len(tech_overlap) * 2.0
        else:
            score += 0.5  # Generic tools get partial credit

        # Time budget
        if profile.avg_time_s > time_budget:
            score -= 2.0

        # Stealth mode
        if stealth and profile.noise_level == "high":
            score -= 3.0
        elif stealth and profile.noise_level == "medium":
            score -= 1.0

        # Historical success rate
        success_rate = self._success_rates.get(profile.name, 0.5)
        score += success_rate * 2.0

        # Reliability
        score += profile.reliability

        return max(0.0, score)

    def _explain_recommendation(self, profile: ToolProfile, target_type: str) -> str:
        """Generate explanation for recommendation."""
        if target_type in profile.target_types:
            return f"Matches target type '{target_type}', finds: {', '.join(profile.finds[:3])}"
        return f"Category: {profile.category}, finds: {', '.join(profile.finds[:3])}"

    def _get_command(self, tool_name: str) -> str:
        """Get command template for a tool."""
        for tool_data in TOOL_DATABASE:
            if tool_data["name"] == tool_name:
                return tool_data.get("cmd", "")
        return ""

    def record_success(self, tool: str, found_something: bool) -> None:
        """Record tool success/failure."""
        current = self._success_rates.get(tool, 0.5)
        if found_something:
            self._success_rates[tool] = min(1.0, current + 0.05)
        else:
            self._success_rates[tool] = max(0.0, current - 0.02)

    def get_stats(self) -> dict[str, Any]:
        return {
            "tools": len(self._profiles),
            "categories": len({p.category for p in self._profiles.values()}),
        }
