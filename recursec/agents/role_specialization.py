"""Agent role specialization — define agent personas.

Implements:
1. Role definitions with capabilities
2. System prompts per role
3. Model preferences per role
4. Tool permissions per role
5. Role composition for multi-agent
6. Role prompt for LLM
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentRole(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    ANALYST = "analyst"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    CODE_AUDITOR = "code_auditor"
    OSINT = "osint"
    NETWORK = "network"
    WEB = "web"
    CLOUD = "cloud"
    FORENSICS = "forensics"
    COORDINATOR = "coordinator"
    PLANNER = "planner"
    REPORTER = "reporter"


@dataclass
class RoleDefinition:
    """Definition of an agent role."""
    role: AgentRole = AgentRole.SCANNER
    display_name: str = ""
    system_prompt: str = ""
    preferred_models: list[str] = field(default_factory=list)
    fallback_models: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    kb_domains: list[str] = field(default_factory=list)
    max_tokens: int = 4096
    temperature: float = 0.3
    capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value[:10],
            "model": self.preferred_models[0][:15] if self.preferred_models else "",
            "tools": len(self.allowed_tools),
        }


ROLE_CATALOG: dict[str, dict[str, Any]] = {
    "recon": {
        "name": "Reconnaissance Agent",
        "prompt": (
            "You are a reconnaissance specialist. Your job is to map "
            "the target's attack surface comprehensively. Enumerate subdomains, "
            "IP ranges, open ports, services, technologies, and exposed assets. "
            "Be thorough but stealthy. Report all findings structured."
        ),
        "models": ["Mistral-7B", "Llama-3.1-8B"],
        "fallback": ["Phi-3.5-mini"],
        "tools": [
            "nmap", "masscan", "subfinder", "amass", "dnsx",
            "httpx", "whatweb", "wappalyzer", "shodan",
        ],
        "kb": ["recon", "osint", "network"],
        "caps": ["subdomain_enum", "port_scan", "service_detection"],
        "temp": 0.2,
    },
    "scanner": {
        "name": "Vulnerability Scanner Agent",
        "prompt": (
            "You are a vulnerability scanner specialist. Run comprehensive "
            "scans against identified targets. Use nuclei for template-based "
            "detection, nikto for web servers, and specialized scanners. "
            "Verify findings and rate severity accurately."
        ),
        "models": ["WhiteRabbitNeo-7B", "Dolphin-2.9"],
        "fallback": ["Mistral-7B"],
        "tools": [
            "nuclei", "nikto", "nessus", "trivy", "grype",
            "wpscan", "sqlmap", "xsstrike",
        ],
        "kb": ["web_vuln", "network_vuln", "cve"],
        "caps": ["vuln_scan", "template_scan", "web_scan"],
        "temp": 0.2,
    },
    "analyst": {
        "name": "Security Analyst Agent",
        "prompt": (
            "You are a security analyst. Analyze scan results, correlate "
            "findings, identify false positives, and determine exploitability. "
            "Use chain-of-thought reasoning to connect findings into attack "
            "paths. Rate risk accurately with evidence."
        ),
        "models": ["DeepSeek-R1", "Hermes-4-14B"],
        "fallback": ["Qwen2.5-Coder-14B"],
        "tools": [],
        "kb": ["analysis", "correlation", "risk"],
        "caps": ["finding_analysis", "correlation", "risk_assessment"],
        "temp": 0.3,
    },
    "exploiter": {
        "name": "Exploitation Agent",
        "prompt": (
            "You are an exploitation specialist. Given confirmed vulnerabilities, "
            "develop and execute exploitation strategies. Use existing tools "
            "(metasploit, sqlmap, etc.) for exploitation. Verify impact. "
            "Document proof-of-concept carefully."
        ),
        "models": ["WhiteRabbitNeo-7B", "Dolphin-2.9"],
        "fallback": ["Qwen2.5-Coder-14B"],
        "tools": [
            "metasploit", "sqlmap", "burp", "hydra",
            "hashcat", "john", "responder",
        ],
        "kb": ["exploit", "privesc", "lateral"],
        "caps": ["exploitation", "post_exploit", "privesc"],
        "temp": 0.2,
    },
    "validator": {
        "name": "Validation Agent",
        "prompt": (
            "You are a validation specialist. Your job is to verify findings "
            "from other agents. Check for false positives by independently "
            "confirming each vulnerability. Challenge assumptions. "
            "Use different tools and approaches than the original finder."
        ),
        "models": ["DeepSeek-R1", "Qwen2.5-Coder-7B"],
        "fallback": ["Hermes-4-14B"],
        "tools": ["nuclei", "curl", "httpx", "nmap"],
        "kb": ["validation", "false_positive"],
        "caps": ["finding_validation", "false_positive_detection"],
        "temp": 0.1,
    },
    "code_auditor": {
        "name": "Code Audit Agent",
        "prompt": (
            "You are a source code auditor. Analyze source code for "
            "vulnerabilities: SQL injection, XSS, command injection, "
            "insecure deserialization, hardcoded secrets, authentication "
            "flaws. Use static analysis tools and manual review."
        ),
        "models": ["Qwen2.5-Coder-14B", "CodeLlama-13B"],
        "fallback": ["Qwen2.5-Coder-7B", "CodeLlama-7B"],
        "tools": ["semgrep", "bandit", "codeql", "sonarqube"],
        "kb": ["code_vuln", "secure_coding", "injection"],
        "caps": ["static_analysis", "code_review", "taint_analysis"],
        "temp": 0.2,
        "max_tokens": 32768,
    },
    "osint": {
        "name": "OSINT Agent",
        "prompt": (
            "You are an open-source intelligence specialist. Gather "
            "publicly available information about targets: emails, "
            "employee names, leaked credentials, exposed documents, "
            "technology stack, organizational structure."
        ),
        "models": ["Llama-3.1-8B", "Mistral-7B"],
        "fallback": ["Phi-3.5-mini"],
        "tools": [
            "theHarvester", "recon-ng", "maltego",
            "sherlock", "spiderfoot",
        ],
        "kb": ["osint", "social_engineering"],
        "caps": ["email_enum", "credential_search", "tech_detection"],
        "temp": 0.3,
    },
    "network": {
        "name": "Network Security Agent",
        "prompt": (
            "You are a network security specialist. Analyze network "
            "topology, identify misconfigurations, test for MITM, "
            "assess segmentation, check encryption, and evaluate "
            "firewall rules."
        ),
        "models": ["Mistral-7B", "WhiteRabbitNeo-7B"],
        "fallback": ["Llama-3.1-8B"],
        "tools": [
            "nmap", "masscan", "bettercap", "responder",
            "wireshark", "tcpdump",
        ],
        "kb": ["network_attack", "mitm", "firewall"],
        "caps": ["network_scan", "traffic_analysis", "mitm"],
        "temp": 0.2,
    },
    "web": {
        "name": "Web Application Agent",
        "prompt": (
            "You are a web application security specialist. Test for "
            "OWASP Top 10, business logic flaws, authentication issues, "
            "session management, input validation, and access control. "
            "Use both automated and manual testing approaches."
        ),
        "models": ["WhiteRabbitNeo-7B", "Qwen2.5-Coder-14B"],
        "fallback": ["Dolphin-2.9"],
        "tools": [
            "burp", "nuclei", "sqlmap", "ffuf", "nikto",
            "wappalyzer", "xsstrike",
        ],
        "kb": ["web_vuln", "owasp", "api", "cache"],
        "caps": ["web_scan", "auth_test", "injection_test"],
        "temp": 0.2,
    },
    "cloud": {
        "name": "Cloud Security Agent",
        "prompt": (
            "You are a cloud security specialist. Assess AWS, Azure, "
            "and GCP environments for misconfigurations, overprivileged "
            "IAM, exposed storage, and compliance gaps."
        ),
        "models": ["Hermes-4-14B", "Mistral-7B"],
        "fallback": ["Llama-3.1-8B"],
        "tools": [
            "prowler", "scoutsuite", "pacu", "cloudfox",
            "steampipe",
        ],
        "kb": ["cloud", "iam", "serverless"],
        "caps": ["cloud_scan", "iam_audit", "storage_check"],
        "temp": 0.2,
    },
    "coordinator": {
        "name": "Coordinator Agent",
        "prompt": (
            "You are the master coordinator. Orchestrate multiple "
            "specialist agents, decompose complex tasks, track progress, "
            "manage resources, and synthesize results. Make high-level "
            "strategic decisions about assessment direction."
        ),
        "models": ["DeepSeek-R1", "Hermes-4-14B"],
        "fallback": ["Qwen2.5-Coder-14B"],
        "tools": [],
        "kb": ["orchestration", "planning"],
        "caps": ["task_decomposition", "agent_management", "strategy"],
        "temp": 0.4,
    },
    "planner": {
        "name": "Planning Agent",
        "prompt": (
            "You are a strategic planner. Create detailed assessment "
            "plans, estimate complexity, select optimal tools and "
            "approaches, and adapt plans based on findings."
        ),
        "models": ["DeepSeek-R1", "Yi-9B-200K"],
        "fallback": ["Hermes-4-14B"],
        "tools": [],
        "kb": ["planning", "methodology"],
        "caps": ["plan_generation", "complexity_estimation"],
        "temp": 0.3,
    },
    "reporter": {
        "name": "Report Generation Agent",
        "prompt": (
            "You are a report generator. Create clear, actionable "
            "security reports from findings. Include executive summary, "
            "technical details, risk ratings, and remediation steps."
        ),
        "models": ["Mistral-7B", "Llama-3.1-8B"],
        "fallback": ["Phi-3.5-mini"],
        "tools": [],
        "kb": ["reporting", "compliance"],
        "caps": ["report_gen", "summary"],
        "temp": 0.3,
    },
}


class RoleSpecializationEngine:
    """Manage agent role specializations.

    Defines roles, assigns capabilities,
    and generates role-specific configurations.
    """

    def __init__(self) -> None:
        self._roles: dict[AgentRole, RoleDefinition] = {}
        self._log = logger.bind(component="roles")
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load role catalog."""
        for role_key, data in ROLE_CATALOG.items():
            role = AgentRole(role_key) if role_key in AgentRole.__members__.values() else AgentRole.SCANNER
            for r in AgentRole:
                if r.value == role_key:
                    role = r
                    break

            defn = RoleDefinition(
                role=role,
                display_name=data.get("name", ""),
                system_prompt=data.get("prompt", ""),
                preferred_models=data.get("models", []),
                fallback_models=data.get("fallback", []),
                allowed_tools=data.get("tools", []),
                kb_domains=data.get("kb", []),
                max_tokens=data.get("max_tokens", 4096),
                temperature=data.get("temp", 0.3),
                capabilities=data.get("caps", []),
            )
            self._roles[role] = defn

    def get_role(self, role: AgentRole) -> RoleDefinition | None:
        """Get role definition."""
        return self._roles.get(role)

    def get_system_prompt(self, role: AgentRole) -> str:
        """Get system prompt for role."""
        defn = self._roles.get(role)
        return defn.system_prompt if defn else ""

    def get_model_for_role(self, role: AgentRole) -> str:
        """Get preferred model for role."""
        defn = self._roles.get(role)
        if defn and defn.preferred_models:
            return defn.preferred_models[0]
        return "Mistral-7B"

    def compose_team(
        self,
        target_type: str,
    ) -> list[AgentRole]:
        """Compose optimal team for target type."""
        teams = {
            "web_app": [
                AgentRole.COORDINATOR, AgentRole.RECON,
                AgentRole.WEB, AgentRole.ANALYST,
                AgentRole.VALIDATOR,
            ],
            "api": [
                AgentRole.COORDINATOR, AgentRole.RECON,
                AgentRole.WEB, AgentRole.CODE_AUDITOR,
                AgentRole.VALIDATOR,
            ],
            "network": [
                AgentRole.COORDINATOR, AgentRole.RECON,
                AgentRole.NETWORK, AgentRole.SCANNER,
                AgentRole.EXPLOITER,
            ],
            "cloud": [
                AgentRole.COORDINATOR, AgentRole.CLOUD,
                AgentRole.ANALYST, AgentRole.VALIDATOR,
            ],
            "full": [
                AgentRole.COORDINATOR, AgentRole.PLANNER,
                AgentRole.RECON, AgentRole.SCANNER,
                AgentRole.WEB, AgentRole.NETWORK,
                AgentRole.ANALYST, AgentRole.EXPLOITER,
                AgentRole.VALIDATOR, AgentRole.REPORTER,
            ],
        }
        return teams.get(target_type, teams["web_app"])

    def build_role_prompt(self) -> str:
        """Build role overview for LLM."""
        lines = ["## Roles\n"]
        lines.append(f"Available: {len(self._roles)}")

        for role, defn in self._roles.items():
            lines.append(
                f"  {defn.display_name[:18]} "
                f"({defn.preferred_models[0][:12]})"
                if defn.preferred_models else
                f"  {defn.display_name[:18]}"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "roles": len(self._roles),
            "total_tools": sum(
                len(d.allowed_tools) for d in self._roles.values()
            ),
        }
