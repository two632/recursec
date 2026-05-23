"""Agent configuration system — defines agent roles, capabilities, and behaviors.

Provides:
1. Role-based configuration (recon, vuln_scan, exploit, etc.)
2. Model assignment per role
3. Tool access control per role
4. Prompt templates per role
5. Budget allocation per role
6. Behavior policies per role
7. Dynamic configuration updates
8. Configuration validation
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class RoleConfig:
    """Configuration for an agent role."""
    role: str = ""
    display_name: str = ""
    description: str = ""

    # Model preferences
    preferred_model: str = ""
    fallback_models: list[str] = field(default_factory=list)
    model_temperature: float = 0.2
    max_tokens: int = 2048

    # Tool access
    allowed_tools: list[str] = field(default_factory=list)
    dangerous_tools_allowed: bool = False

    # Budgets
    token_budget: int = 50000
    step_budget: int = 100
    time_budget_s: float = 300.0
    max_children: int = 5
    max_depth: int = 3

    # Behavior
    system_prompt: str = ""
    task_prompt_template: str = ""
    output_format: str = "json"  # json, text, structured
    verbosity: str = "normal"    # minimal, normal, detailed
    risk_tolerance: float = 0.5
    auto_validate: bool = True

    # Specializations
    specialties: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role, "name": self.display_name,
            "model": self.preferred_model,
            "tools": len(self.allowed_tools),
            "token_budget": self.token_budget,
            "max_children": self.max_children,
            "specialties": self.specialties[:3],
        }


# ── Default Role Configurations ──────────────────────────────

DEFAULT_ROLES: dict[str, dict[str, Any]] = {
    "coordinator": {
        "display_name": "Coordinator",
        "description": "Orchestrates other agents, plans strategy, decomposes tasks",
        "preferred_model": "deepseek-r1",
        "fallback_models": ["hermes", "llama3"],
        "model_temperature": 0.3,
        "allowed_tools": [],
        "token_budget": 100000,
        "step_budget": 200,
        "time_budget_s": 600.0,
        "max_children": 10,
        "max_depth": 0,
        "risk_tolerance": 0.3,
        "specialties": ["planning", "coordination", "strategy"],
        "system_prompt": (
            "You are a security assessment coordinator. Your role is to plan "
            "and coordinate the assessment by delegating to specialist agents. "
            "Analyze the target, create a plan, and assign tasks."
        ),
    },
    "recon": {
        "display_name": "Reconnaissance Agent",
        "description": "Discovers subdomains, open ports, technologies, and attack surface",
        "preferred_model": "mistral",
        "fallback_models": ["llama3", "phi35"],
        "model_temperature": 0.1,
        "allowed_tools": ["nmap", "masscan", "subfinder", "amass", "httpx",
                          "katana", "whatweb", "dig", "whois"],
        "token_budget": 30000,
        "step_budget": 50,
        "time_budget_s": 300.0,
        "max_children": 3,
        "risk_tolerance": 0.2,
        "specialties": ["recon", "discovery", "enumeration"],
        "system_prompt": (
            "You are a reconnaissance specialist. Discover as much information "
            "about the target as possible: subdomains, open ports, technologies, "
            "services, and potential entry points. Be thorough but efficient."
        ),
    },
    "vuln_scan": {
        "display_name": "Vulnerability Scanner Agent",
        "description": "Runs vulnerability scans and analyzes results",
        "preferred_model": "whiterabbit",
        "fallback_models": ["qwen-coder-14b", "dolphin"],
        "model_temperature": 0.2,
        "allowed_tools": ["nuclei", "nikto", "wpscan", "testssl"],
        "token_budget": 50000,
        "step_budget": 80,
        "time_budget_s": 600.0,
        "max_children": 3,
        "risk_tolerance": 0.4,
        "specialties": ["vulnerability", "scanning", "detection"],
        "system_prompt": (
            "You are a vulnerability scanning specialist. Use available scanners "
            "to identify vulnerabilities. Analyze scan results, identify true "
            "positives, and classify findings by severity."
        ),
    },
    "web_scan": {
        "display_name": "Web Application Scanner Agent",
        "description": "Tests web applications for OWASP Top 10 and more",
        "preferred_model": "whiterabbit",
        "fallback_models": ["dolphin", "qwen-coder-7b"],
        "model_temperature": 0.2,
        "allowed_tools": ["sqlmap", "dalfox", "gobuster", "ffuf", "curl"],
        "dangerous_tools_allowed": True,
        "token_budget": 50000,
        "step_budget": 100,
        "time_budget_s": 600.0,
        "max_children": 3,
        "risk_tolerance": 0.5,
        "specialties": ["web", "xss", "sqli", "ssrf", "injection"],
        "system_prompt": (
            "You are a web application security specialist. Test for XSS, SQL "
            "injection, SSRF, path traversal, authentication issues, and other "
            "OWASP Top 10 vulnerabilities. Validate findings with proof-of-concept."
        ),
    },
    "exploit": {
        "display_name": "Exploitation Agent",
        "description": "Develops and executes exploits to prove vulnerability impact",
        "preferred_model": "whiterabbit",
        "fallback_models": ["dolphin", "qwen-coder-14b"],
        "model_temperature": 0.2,
        "allowed_tools": ["sqlmap", "hydra", "metasploit", "curl"],
        "dangerous_tools_allowed": True,
        "token_budget": 40000,
        "step_budget": 60,
        "time_budget_s": 300.0,
        "max_children": 2,
        "risk_tolerance": 0.7,
        "specialties": ["exploitation", "payload", "privilege_escalation"],
        "system_prompt": (
            "You are an exploitation specialist. Develop and execute exploits "
            "to prove the impact of discovered vulnerabilities. Always validate "
            "your exploits are safe and controlled."
        ),
    },
    "code_audit": {
        "display_name": "Code Audit Agent",
        "description": "Performs static analysis and code review",
        "preferred_model": "qwen-coder-14b",
        "fallback_models": ["qwen-coder-7b", "codellama-13b"],
        "model_temperature": 0.1,
        "allowed_tools": ["semgrep", "bandit", "trivy", "gitleaks", "trufflehog"],
        "token_budget": 60000,
        "step_budget": 80,
        "time_budget_s": 600.0,
        "max_children": 3,
        "risk_tolerance": 0.1,
        "specialties": ["code_analysis", "sast", "secret_detection"],
        "system_prompt": (
            "You are a code security auditor. Perform thorough static analysis "
            "to identify vulnerabilities, insecure patterns, hardcoded secrets, "
            "and dependency issues. Use the long-context model for large codebases."
        ),
    },
    "network": {
        "display_name": "Network Agent",
        "description": "Tests network services and protocols",
        "preferred_model": "mistral",
        "fallback_models": ["llama3", "dolphin"],
        "model_temperature": 0.2,
        "allowed_tools": ["nmap", "enum4linux", "testssl", "dig", "tcpdump"],
        "token_budget": 40000,
        "step_budget": 60,
        "time_budget_s": 300.0,
        "max_children": 2,
        "risk_tolerance": 0.4,
        "specialties": ["network", "smb", "dns", "tls", "protocols"],
        "system_prompt": (
            "You are a network security specialist. Test network services, "
            "protocols, and configurations for vulnerabilities."
        ),
    },
    "validator": {
        "display_name": "Validation Agent",
        "description": "Cross-validates findings and reduces false positives",
        "preferred_model": "deepseek-r1",
        "fallback_models": ["hermes", "qwen-coder-14b"],
        "model_temperature": 0.1,
        "allowed_tools": ["curl", "nmap", "nuclei"],
        "token_budget": 30000,
        "step_budget": 50,
        "time_budget_s": 300.0,
        "max_children": 0,
        "risk_tolerance": 0.1,
        "auto_validate": False,
        "specialties": ["validation", "verification", "analysis"],
        "system_prompt": (
            "You are a skeptical security validator. Your job is to challenge "
            "and verify findings from other agents. Check for false positives, "
            "validate evidence, and confirm severity ratings."
        ),
    },
    "osint": {
        "display_name": "OSINT Agent",
        "description": "Gathers open source intelligence",
        "preferred_model": "yi-200k",
        "fallback_models": ["hermes", "llama3"],
        "model_temperature": 0.2,
        "allowed_tools": ["whois", "dig", "curl"],
        "token_budget": 30000,
        "step_budget": 40,
        "time_budget_s": 300.0,
        "max_children": 2,
        "risk_tolerance": 0.1,
        "specialties": ["osint", "intelligence", "research"],
        "system_prompt": (
            "You are an OSINT specialist. Gather open-source intelligence "
            "about the target: domain info, DNS records, leaked data, "
            "technology stack, and organizational information."
        ),
    },
}


class AgentConfigManager:
    """Manages agent role configurations.

    Provides role-based configuration for agent creation,
    model assignment, and behavior policies.
    """

    def __init__(self, config_path: str = "data/agent_config.json") -> None:
        self._config_path = Path(config_path)
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        self._roles: dict[str, RoleConfig] = {}
        self._log = logger.bind(component="agent_config")

        self._load_defaults()
        self._load_custom()

    def _load_defaults(self) -> None:
        """Load default role configurations."""
        for role_name, role_data in DEFAULT_ROLES.items():
            config = RoleConfig(
                role=role_name,
                display_name=role_data.get("display_name", role_name),
                description=role_data.get("description", ""),
                preferred_model=role_data.get("preferred_model", ""),
                fallback_models=role_data.get("fallback_models", []),
                model_temperature=role_data.get("model_temperature", 0.2),
                allowed_tools=role_data.get("allowed_tools", []),
                dangerous_tools_allowed=role_data.get("dangerous_tools_allowed", False),
                token_budget=role_data.get("token_budget", 50000),
                step_budget=role_data.get("step_budget", 100),
                time_budget_s=role_data.get("time_budget_s", 300.0),
                max_children=role_data.get("max_children", 5),
                max_depth=role_data.get("max_depth", 3),
                risk_tolerance=role_data.get("risk_tolerance", 0.5),
                auto_validate=role_data.get("auto_validate", True),
                specialties=role_data.get("specialties", []),
                system_prompt=role_data.get("system_prompt", ""),
            )
            self._roles[role_name] = config

    def _load_custom(self) -> None:
        """Load custom configurations from disk."""
        if not self._config_path.exists():
            return
        try:
            data = json.loads(self._config_path.read_text())
            for role_name, overrides in data.items():
                if role_name in self._roles:
                    config = self._roles[role_name]
                    for key, value in overrides.items():
                        if hasattr(config, key):
                            setattr(config, key, value)
                else:
                    config = RoleConfig(role=role_name, **overrides)
                    self._roles[role_name] = config
        except (json.JSONDecodeError, OSError):
            pass

    def get_role(self, role: str) -> RoleConfig | None:
        return self._roles.get(role)

    def get_all_roles(self) -> dict[str, RoleConfig]:
        return dict(self._roles)

    def add_role(self, config: RoleConfig) -> None:
        self._roles[config.role] = config

    def update_role(self, role: str, overrides: dict[str, Any]) -> bool:
        config = self._roles.get(role)
        if not config:
            return False
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return True

    def save(self) -> None:
        """Persist custom configurations."""
        try:
            data = {
                name: config.to_dict()
                for name, config in self._roles.items()
            }
            self._config_path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def get_stats(self) -> dict[str, Any]:
        return {
            "roles": len(self._roles),
            "role_names": list(self._roles.keys()),
        }
