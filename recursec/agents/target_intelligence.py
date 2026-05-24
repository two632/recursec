"""Target intelligence system — comprehensive target profiling.

Before any scanning begins, this module builds a rich profile:
1. Target classification (web app, network, cloud, mobile, API)
2. Technology fingerprinting (from headers, responses, DNS)
3. Historical data lookup (past scans, known vulns)
4. Threat landscape (industry-specific threats)
5. Compliance requirements (PCI, HIPAA, SOC2 based on industry)
6. Attack surface estimation
7. Risk profile generation
8. Recommended scan strategy
9. Scope definition and constraints
10. Priority target identification

This is what allows the agent to make intelligent decisions
BEFORE spending time on tools.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TargetType(str, Enum):
    WEB_APP = "web_application"
    API = "api"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    SOURCE_CODE = "source_code"
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    UNKNOWN = "unknown"


class IndustryType(str, Enum):
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    ECOMMERCE = "ecommerce"
    TECH = "tech"
    EDUCATION = "education"
    MEDIA = "media"
    MANUFACTURING = "manufacturing"
    ENERGY = "energy"
    TELECOM = "telecom"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TechnologyFingerprint:
    """Detected technology."""
    name: str = ""
    category: str = ""
    version: str = ""
    confidence: float = 0.5
    cpe: str = ""
    known_vulns: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "cat": self.category[:10],
            "ver": self.version[:10],
            "conf": f"{self.confidence:.0%}",
            "vulns": self.known_vulns,
        }


@dataclass
class ScanStrategy:
    """Recommended scanning strategy."""
    tools: list[str] = field(default_factory=list)
    order: list[str] = field(default_factory=list)
    parallel_groups: list[list[str]] = field(default_factory=list)
    aggressive: bool = False
    stealth: bool = False
    estimated_duration_min: int = 30
    focus_areas: list[str] = field(default_factory=list)
    skip_areas: list[str] = field(default_factory=list)
    models_recommended: list[str] = field(default_factory=list)
    kb_domains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": self.tools[:5],
            "duration": f"{self.estimated_duration_min}min",
            "focus": self.focus_areas[:3],
            "kbs": self.kb_domains[:3],
        }


@dataclass
class TargetProfile:
    """Comprehensive profile of a scan target."""
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    industry: IndustryType = IndustryType.UNKNOWN
    risk_level: RiskLevel = RiskLevel.MEDIUM
    technologies: list[TechnologyFingerprint] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    known_vulns: list[str] = field(default_factory=list)
    compliance_requirements: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    scan_strategy: ScanStrategy = field(default_factory=ScanStrategy)
    notes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:25],
            "type": self.target_type.value[:15],
            "industry": self.industry.value[:10],
            "risk": self.risk_level.value[:8],
            "techs": len(self.technologies),
            "ports": len(self.open_ports),
            "subdomains": len(self.subdomains),
        }


# Technology detection patterns
TECH_SIGNATURES: dict[str, dict[str, str]] = {
    "Apache": {"header": "Apache", "category": "web_server"},
    "Nginx": {"header": "nginx", "category": "web_server"},
    "IIS": {"header": "Microsoft-IIS", "category": "web_server"},
    "Express": {"header": "Express", "category": "framework"},
    "Django": {"header": "wsgiref", "category": "framework"},
    "Rails": {"header": "X-Powered-By: Phusion Passenger", "category": "framework"},
    "WordPress": {"body": "wp-content", "category": "cms"},
    "Drupal": {"header": "X-Drupal-Cache", "category": "cms"},
    "Joomla": {"body": "/media/jui/", "category": "cms"},
    "React": {"body": "__NEXT_DATA__", "category": "frontend"},
    "Vue.js": {"body": "__VUE__", "category": "frontend"},
    "Angular": {"body": "ng-version", "category": "frontend"},
    "PHP": {"header": "X-Powered-By: PHP", "category": "language"},
    "ASP.NET": {"header": "X-AspNet-Version", "category": "language"},
    "Java": {"header": "X-Powered-By: Servlet", "category": "language"},
    "Cloudflare": {"header": "cf-ray", "category": "cdn"},
    "AWS": {"header": "x-amz-", "category": "cloud"},
    "Azure": {"header": "x-ms-", "category": "cloud"},
}

# Industry → compliance mapping
INDUSTRY_COMPLIANCE: dict[IndustryType, list[str]] = {
    IndustryType.FINANCE: ["PCI DSS", "SOX", "GLBA", "SOC 2"],
    IndustryType.HEALTHCARE: ["HIPAA", "HITECH", "SOC 2"],
    IndustryType.GOVERNMENT: ["FISMA", "FedRAMP", "NIST 800-53"],
    IndustryType.ECOMMERCE: ["PCI DSS", "GDPR", "CCPA"],
    IndustryType.TECH: ["SOC 2", "ISO 27001", "GDPR"],
    IndustryType.EDUCATION: ["FERPA", "COPPA"],
    IndustryType.ENERGY: ["NERC CIP", "IEC 62443"],
    IndustryType.TELECOM: ["SOC 2", "ISO 27001"],
}

# Industry → threat actors mapping
INDUSTRY_THREATS: dict[IndustryType, list[str]] = {
    IndustryType.FINANCE: ["FIN7", "Carbanak", "Lazarus Group", "Magecart"],
    IndustryType.HEALTHCARE: ["Ryuk", "Conti", "BlackCat/ALPHV"],
    IndustryType.GOVERNMENT: ["APT28", "APT29", "Lazarus", "Turla"],
    IndustryType.ECOMMERCE: ["Magecart", "FIN6", "Scattered Spider"],
    IndustryType.TECH: ["APT41", "Lapsus$", "Scattered Spider"],
    IndustryType.ENERGY: ["Sandworm", "Dragonfly", "Triton/TRISIS actors"],
}

# Target type → KB domains
TARGET_KB_MAP: dict[TargetType, list[str]] = {
    TargetType.WEB_APP: ["web_vuln", "xss", "ssrf", "business_logic", "api_gateway"],
    TargetType.API: ["api_gateway", "web_vuln", "business_logic"],
    TargetType.NETWORK: ["network", "dns", "lateral_movement"],
    TargetType.CLOUD: ["cloud", "container_k8s", "serverless", "zero_trust"],
    TargetType.MOBILE: ["mobile"],
    TargetType.IOT: ["iot_ics", "firmware"],
    TargetType.SOURCE_CODE: ["web_vuln", "supply_chain", "devsecops"],
}

# Target type → recommended tools
TARGET_TOOL_MAP: dict[TargetType, list[str]] = {
    TargetType.WEB_APP: ["httpx", "nuclei", "ffuf", "sqlmap", "dalfox", "gobuster"],
    TargetType.API: ["httpx", "nuclei", "ffuf"],
    TargetType.NETWORK: ["nmap", "masscan", "nuclei"],
    TargetType.CLOUD: ["prowler", "scoutsuite", "trivy"],
    TargetType.DOMAIN: ["subfinder", "amass", "httpx", "nmap"],
    TargetType.IP_RANGE: ["nmap", "masscan", "nuclei"],
    TargetType.SOURCE_CODE: ["semgrep", "bandit", "gitleaks", "trivy"],
}

# Target type → recommended models
TARGET_MODEL_MAP: dict[TargetType, list[str]] = {
    TargetType.WEB_APP: ["whiterabbit", "qwen-coder-14b", "deepseek-r1"],
    TargetType.API: ["whiterabbit", "qwen-coder-7b"],
    TargetType.NETWORK: ["whiterabbit", "mistral-7b"],
    TargetType.CLOUD: ["hermes-4-14b", "deepseek-r1"],
    TargetType.SOURCE_CODE: ["qwen-coder-14b", "yi-9b-200k", "codellama-13b"],
}


class TargetIntelligence:
    """Builds comprehensive target profiles before scanning."""

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._log = logger.bind(component="target_intel")

    def profile_target(self, target: str, hints: dict[str, Any] | None = None) -> TargetProfile:
        """Build a comprehensive profile for a target."""
        profile = TargetProfile(target=target)

        # Classify target type
        profile.target_type = self._classify_target(target, hints)

        # Detect industry
        profile.industry = self._detect_industry(target, hints)

        # Set compliance requirements
        profile.compliance_requirements = INDUSTRY_COMPLIANCE.get(profile.industry, [])

        # Set threat actors
        profile.threat_actors = INDUSTRY_THREATS.get(profile.industry, [])

        # Build scan strategy
        profile.scan_strategy = self._build_strategy(profile)

        # Assess risk
        profile.risk_level = self._assess_risk(profile)

        self._profiles[target] = profile
        return profile

    def _classify_target(self, target: str, hints: dict[str, Any] | None = None) -> TargetType:
        """Classify what type of target this is."""
        if hints and "type" in hints:
            try:
                return TargetType(hints["type"])
            except ValueError:
                pass

        target_lower = target.lower()

        # URL-based detection
        if target_lower.startswith("http://") or target_lower.startswith("https://"):
            if "/api/" in target_lower or "api." in target_lower:
                return TargetType.API
            return TargetType.WEB_APP

        # IP range detection
        if "/" in target and any(c.isdigit() for c in target):
            return TargetType.IP_RANGE

        # Single IP
        parts = target.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return TargetType.NETWORK

        # Domain
        if "." in target:
            return TargetType.DOMAIN

        # Path (could be source code)
        if "/" in target or "\\" in target:
            return TargetType.SOURCE_CODE

        return TargetType.UNKNOWN

    def _detect_industry(self, target: str, hints: dict[str, Any] | None = None) -> IndustryType:
        """Detect industry from target name."""
        if hints and "industry" in hints:
            try:
                return IndustryType(hints["industry"])
            except ValueError:
                pass

        target_lower = target.lower()
        industry_keywords: dict[IndustryType, list[str]] = {
            IndustryType.FINANCE: ["bank", "financial", "pay", "credit", "trade", "invest"],
            IndustryType.HEALTHCARE: ["health", "medical", "hospital", "clinic", "pharma"],
            IndustryType.GOVERNMENT: ["gov", "mil", "state", "federal"],
            IndustryType.ECOMMERCE: ["shop", "store", "buy", "cart", "commerce"],
            IndustryType.EDUCATION: ["edu", "university", "school", "learn"],
            IndustryType.ENERGY: ["energy", "power", "utility", "oil", "gas"],
            IndustryType.TELECOM: ["telecom", "mobile", "wireless", "carrier"],
        }

        for industry, keywords in industry_keywords.items():
            if any(kw in target_lower for kw in keywords):
                return industry

        return IndustryType.UNKNOWN

    def _build_strategy(self, profile: TargetProfile) -> ScanStrategy:
        """Build optimal scan strategy for the target."""
        tools = TARGET_TOOL_MAP.get(profile.target_type, ["nmap", "nuclei"])
        models = TARGET_MODEL_MAP.get(profile.target_type, ["whiterabbit"])
        kb_domains = TARGET_KB_MAP.get(profile.target_type, ["web_vuln"])

        # Parallel groups
        parallel_groups = []
        recon_tools = [t for t in tools if t in ["subfinder", "amass", "httpx", "nmap", "masscan"]]
        scan_tools = [t for t in tools if t in ["nuclei", "nikto", "ffuf", "gobuster"]]
        exploit_tools = [t for t in tools if t in ["sqlmap", "dalfox"]]

        if recon_tools:
            parallel_groups.append(recon_tools)
        if scan_tools:
            parallel_groups.append(scan_tools)
        if exploit_tools:
            parallel_groups.append(exploit_tools)

        # Focus areas based on industry
        focus_areas = []
        if profile.industry == IndustryType.FINANCE:
            focus_areas = ["authentication", "encryption", "api_security", "business_logic"]
        elif profile.industry == IndustryType.HEALTHCARE:
            focus_areas = ["data_protection", "access_control", "audit_logging"]
        elif profile.industry == IndustryType.ECOMMERCE:
            focus_areas = ["payment_security", "session_management", "cart_manipulation"]
        else:
            focus_areas = ["injection", "authentication", "authorization"]

        return ScanStrategy(
            tools=tools,
            order=["recon", "enumeration", "scanning", "exploitation", "reporting"],
            parallel_groups=parallel_groups,
            estimated_duration_min=30 + len(tools) * 5,
            focus_areas=focus_areas,
            models_recommended=models,
            kb_domains=kb_domains,
        )

    def _assess_risk(self, profile: TargetProfile) -> RiskLevel:
        """Assess overall risk level."""
        risk_score = 5.0

        # Industry risk
        high_risk_industries = [IndustryType.FINANCE, IndustryType.HEALTHCARE, IndustryType.GOVERNMENT]
        if profile.industry in high_risk_industries:
            risk_score += 2.0

        # Known vulns
        if profile.known_vulns:
            risk_score += min(3.0, len(profile.known_vulns) * 0.5)

        # Threat actors
        if profile.threat_actors:
            risk_score += 1.0

        if risk_score >= 8:
            return RiskLevel.CRITICAL
        if risk_score >= 6:
            return RiskLevel.HIGH
        if risk_score >= 4:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def add_technology(self, target: str, tech: TechnologyFingerprint) -> None:
        """Add a detected technology to the profile."""
        profile = self._profiles.get(target)
        if profile:
            profile.technologies.append(tech)

    def build_intel_prompt(self, target: str) -> str:
        """Build LLM prompt with target intelligence."""
        profile = self._profiles.get(target)
        if not profile:
            return ""

        lines = [f"## Target Intelligence: {target}"]
        lines.append(f"Type: {profile.target_type.value}")
        lines.append(f"Industry: {profile.industry.value}")
        lines.append(f"Risk: {profile.risk_level.value}")

        if profile.compliance_requirements:
            lines.append(f"Compliance: {', '.join(profile.compliance_requirements[:3])}")

        if profile.threat_actors:
            lines.append(f"Threat actors: {', '.join(profile.threat_actors[:3])}")

        strategy = profile.scan_strategy
        lines.append(f"\nRecommended tools: {', '.join(strategy.tools[:5])}")
        lines.append(f"Focus areas: {', '.join(strategy.focus_areas[:3])}")
        lines.append(f"KB domains: {', '.join(strategy.kb_domains[:3])}")

        if profile.technologies:
            lines.append("\nDetected technologies:")
            for tech in profile.technologies[:5]:
                lines.append(f"  - {tech.name} ({tech.category}) v{tech.version}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "profiles": len(self._profiles),
        }
