"""Target profiler — builds comprehensive profiles of assessment targets.

Before the agent starts attacking, it needs to understand what
it's dealing with. This module:
1. Classifies target type (web app, network, host, code repo, cloud, API)
2. Identifies technology stack
3. Maps attack surface
4. Determines scope boundaries
5. Prioritizes attack vectors
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetType(str, Enum):
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    NETWORK_HOST = "network_host"
    NETWORK_RANGE = "network_range"
    CODE_REPO = "code_repo"
    CLOUD_ACCOUNT = "cloud_account"
    DOMAIN = "domain"
    MOBILE_APP = "mobile_app"
    CONTAINER = "container"
    IOT_DEVICE = "iot_device"
    UNKNOWN = "unknown"


class TechnologyStack(str, Enum):
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    DJANGO = "django"
    FLASK = "flask"
    RAILS = "rails"
    SPRING = "spring"
    WORDPRESS = "wordpress"
    REACT = "react"
    ANGULAR = "angular"
    DOTNET = "dotnet"
    PHP = "php"
    JAVA = "java"
    PYTHON = "python"
    GOLANG = "golang"
    UNKNOWN = "unknown"


@dataclass
class TargetProfile:
    """Comprehensive profile of an assessment target."""
    target_input: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    resolved_targets: list[str] = field(default_factory=list)
    technology_stack: list[TechnologyStack] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: list[dict[str, str]] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    attack_surface: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    recommended_kbs: list[str] = field(default_factory=list)
    recommended_model: str = ""
    priority_vectors: list[str] = field(default_factory=list)
    scope_notes: str = ""
    risk_level: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.target_input[:20],
            "type": self.target_type.value[:10],
            "resolved": len(self.resolved_targets),
            "stack": [s.value[:6] for s in self.technology_stack[:3]],
            "ports": len(self.open_ports),
            "risk": self.risk_level[:4],
        }


# Target type detection patterns
TARGET_PATTERNS: list[tuple[str, TargetType]] = [
    (r'^https?://.*(/api/|/v\d+/|/graphql)', TargetType.API_ENDPOINT),
    (r'^https?://', TargetType.WEB_APP),
    (r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', TargetType.NETWORK_HOST),
    (r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', TargetType.NETWORK_RANGE),
    (r'^(github|gitlab|bitbucket)\.', TargetType.CODE_REPO),
    (r'^arn:aws:|^projects/.*/', TargetType.CLOUD_ACCOUNT),
    (r'^[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+$', TargetType.DOMAIN),
    (r'\.apk$|\.ipa$', TargetType.MOBILE_APP),
    (r'^(docker|container|k8s|pod):', TargetType.CONTAINER),
]

# Target type → recommended tools
TYPE_TOOL_MAP: dict[TargetType, list[str]] = {
    TargetType.WEB_APP: ["nuclei", "nikto", "sqlmap", "ffuf", "whatweb", "wappalyzer"],
    TargetType.API_ENDPOINT: ["nuclei", "ffuf", "sqlmap", "postman", "burpsuite"],
    TargetType.NETWORK_HOST: ["nmap", "masscan", "enum4linux", "crackmapexec"],
    TargetType.NETWORK_RANGE: ["nmap", "masscan", "responder"],
    TargetType.CODE_REPO: ["semgrep", "gitleaks", "bandit", "codeql"],
    TargetType.CLOUD_ACCOUNT: ["prowler", "scoutsuite", "trivy"],
    TargetType.DOMAIN: ["subfinder", "amass", "dig", "whois", "whatweb", "nmap"],
    TargetType.MOBILE_APP: ["apktool", "frida", "objection", "mobsf"],
    TargetType.CONTAINER: ["trivy", "grype", "docker-bench"],
    TargetType.IOT_DEVICE: ["nmap", "binwalk", "firmwalker"],
}

# Target type → recommended KBs
TYPE_KB_MAP: dict[TargetType, list[str]] = {
    TargetType.WEB_APP: ["web_vuln", "xss", "ssrf", "deserialization", "business_logic", "api_gateway"],
    TargetType.API_ENDPOINT: ["api_gateway", "web_vuln", "business_logic"],
    TargetType.NETWORK_HOST: ["network", "lateral_movement", "privesc", "windows", "linux"],
    TargetType.NETWORK_RANGE: ["network", "lateral_movement", "active_directory"],
    TargetType.CODE_REPO: ["supply_chain", "devsecops", "advanced_discovery"],
    TargetType.CLOUD_ACCOUNT: ["cloud", "container_k8s", "serverless", "zero_trust"],
    TargetType.DOMAIN: ["dns", "network", "web_vuln"],
    TargetType.MOBILE_APP: ["mobile", "api_gateway"],
    TargetType.CONTAINER: ["container_k8s", "cloud"],
    TargetType.IOT_DEVICE: ["iot_ics", "firmware", "wireless"],
}

# Target type → recommended model
TYPE_MODEL_MAP: dict[TargetType, str] = {
    TargetType.WEB_APP: "whiterabbit",
    TargetType.API_ENDPOINT: "whiterabbit",
    TargetType.NETWORK_HOST: "whiterabbit",
    TargetType.NETWORK_RANGE: "phi-3.5-mini",
    TargetType.CODE_REPO: "qwen-coder-14b",
    TargetType.CLOUD_ACCOUNT: "hermes-4-14b",
    TargetType.DOMAIN: "phi-3.5-mini",
    TargetType.MOBILE_APP: "qwen-coder-14b",
    TargetType.CONTAINER: "hermes-4-14b",
    TargetType.IOT_DEVICE: "whiterabbit",
}


class TargetProfiler:
    """Profiles assessment targets."""

    def __init__(self) -> None:
        self._profiles: list[TargetProfile] = []
        self._log = logger.bind(component="target_profiler")

    def classify_target(self, target_input: str) -> TargetType:
        """Classify the target type from input string."""
        for pattern, target_type in TARGET_PATTERNS:
            if re.search(pattern, target_input, re.IGNORECASE):
                return target_type
        return TargetType.UNKNOWN

    def profile(self, target_input: str) -> TargetProfile:
        """Create a comprehensive profile for a target."""
        target_type = self.classify_target(target_input)

        profile = TargetProfile(
            target_input=target_input,
            target_type=target_type,
            resolved_targets=[target_input],
            recommended_tools=TYPE_TOOL_MAP.get(target_type, []),
            recommended_kbs=TYPE_KB_MAP.get(target_type, []),
            recommended_model=TYPE_MODEL_MAP.get(target_type, "mistral-7b"),
        )

        # Add priority attack vectors
        if target_type == TargetType.WEB_APP:
            profile.priority_vectors = ["SQL injection", "XSS", "Authentication bypass", "SSRF", "IDOR", "File upload", "Business logic"]
            profile.attack_surface = ["HTTP endpoints", "Form inputs", "API parameters", "Headers", "Cookies", "File uploads", "WebSockets"]
        elif target_type == TargetType.API_ENDPOINT:
            profile.priority_vectors = ["Auth bypass", "BOLA/IDOR", "SQL injection", "Rate limit bypass", "Mass assignment", "SSRF"]
            profile.attack_surface = ["API endpoints", "Query params", "Request body", "Headers", "Auth tokens"]
        elif target_type in (TargetType.NETWORK_HOST, TargetType.NETWORK_RANGE):
            profile.priority_vectors = ["Open ports", "Service vulns", "Default creds", "SMB/RDP", "Privilege escalation"]
            profile.attack_surface = ["TCP ports", "UDP ports", "Services", "Shares", "Web interfaces"]
        elif target_type == TargetType.CODE_REPO:
            profile.priority_vectors = ["Hardcoded secrets", "SQL injection", "Command injection", "Dependency vulns", "Logic bugs"]
            profile.attack_surface = ["Source code", "Dependencies", "CI/CD configs", "Infrastructure as Code"]
        elif target_type == TargetType.DOMAIN:
            profile.priority_vectors = ["Subdomain takeover", "Open ports", "Web vulns", "DNS misconfig", "Email security"]
            profile.attack_surface = ["Subdomains", "MX records", "NS records", "Web servers", "APIs"]

        self._profiles.append(profile)
        return profile

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for p in self._profiles:
            key = p.target_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        return {"total_profiles": len(self._profiles), "by_type": type_counts}

    def build_profiler_prompt(self) -> str:
        """Build LLM prompt with profiling info."""
        if not self._profiles:
            return "## Target Profiler\nNo targets profiled yet."
        latest = self._profiles[-1]
        lines = ["## Target Profile"]
        lines.append(f"Target: {latest.target_input}")
        lines.append(f"Type: {latest.target_type.value}")
        lines.append(f"Priority vectors: {', '.join(latest.priority_vectors[:5])}")
        lines.append(f"Tools: {', '.join(latest.recommended_tools[:5])}")
        lines.append(f"KBs: {', '.join(latest.recommended_kbs[:5])}")
        return "\n".join(lines)
