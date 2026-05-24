"""Unified brain — integrates ALL intelligence modules.

The central intelligence that wires together:
1. Knowledge bases → prompt assembly
2. Memory systems → context injection
3. Reasoning engines → decision making
4. Planning → task generation
5. Model routing → optimal LLM selection
6. Finding correlation → attack chain building
7. Role management → agent specialization
8. Learning → reward-driven improvement

This is the core that makes the agent "know everything"
for any given task.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskIntent(str, Enum):
    FULL_ASSESSMENT = "full_assessment"
    WEB_PENTEST = "web_pentest"
    NETWORK_PENTEST = "network_pentest"
    CODE_AUDIT = "code_audit"
    CLOUD_AUDIT = "cloud_audit"
    MOBILE_TEST = "mobile_test"
    AD_ASSESSMENT = "ad_assessment"
    OSINT = "osint"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE = "compliance"
    EXPLOIT_DEV = "exploit_dev"
    RED_TEAM = "red_team"
    UNKNOWN = "unknown"


class BrainState(str, Enum):
    IDLE = "idle"
    UNDERSTANDING = "understanding"
    PLANNING = "planning"
    KNOWLEDGE_LOADING = "knowledge_loading"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    LEARNING = "learning"
    REPORTING = "reporting"


# Intent → required KB domains
INTENT_KB_MAP: dict[TaskIntent, list[str]] = {
    TaskIntent.FULL_ASSESSMENT: [
        "recon", "web_vuln", "network_attack", "privesc",
        "cloud_native", "identity_sso", "compliance",
    ],
    TaskIntent.WEB_PENTEST: [
        "web_vuln", "xss", "ssrf", "sqli", "deserialization",
        "api_gateway", "web_cache", "business_logic",
    ],
    TaskIntent.NETWORK_PENTEST: [
        "network_attack", "privesc", "lateral_movement",
        "active_directory", "wireless",
    ],
    TaskIntent.CODE_AUDIT: [
        "code_vuln", "deserialization", "injection",
        "crypto", "secure_coding",
    ],
    TaskIntent.CLOUD_AUDIT: [
        "cloud_native", "devsecops", "compliance",
        "container", "serverless",
    ],
    TaskIntent.MOBILE_TEST: [
        "mobile_security", "api_gateway", "crypto",
        "reverse_engineering",
    ],
    TaskIntent.AD_ASSESSMENT: [
        "active_directory", "kerberos", "identity_sso",
        "privesc", "lateral_movement",
    ],
    TaskIntent.OSINT: [
        "osint", "social_engineering", "email_phishing",
        "recon",
    ],
    TaskIntent.INCIDENT_RESPONSE: [
        "incident_response", "forensics", "malware",
        "network_attack",
    ],
    TaskIntent.COMPLIANCE: [
        "compliance", "cloud_native", "devsecops",
        "identity_sso",
    ],
    TaskIntent.EXPLOIT_DEV: [
        "binary_exploit", "deserialization", "privesc",
        "web_vuln",
    ],
    TaskIntent.RED_TEAM: [
        "recon", "social_engineering", "email_phishing",
        "privesc", "lateral_movement", "active_directory",
        "network_attack", "web_vuln",
    ],
}

# Intent → required agent roles
INTENT_ROLE_MAP: dict[TaskIntent, list[str]] = {
    TaskIntent.FULL_ASSESSMENT: [
        "coordinator", "planner", "recon", "scanner",
        "web", "network", "analyst", "exploiter",
        "validator", "reporter",
    ],
    TaskIntent.WEB_PENTEST: [
        "coordinator", "recon", "web", "analyst",
        "exploiter", "validator",
    ],
    TaskIntent.NETWORK_PENTEST: [
        "coordinator", "recon", "network", "scanner",
        "exploiter", "validator",
    ],
    TaskIntent.CODE_AUDIT: [
        "coordinator", "code_auditor", "analyst",
        "validator",
    ],
    TaskIntent.CLOUD_AUDIT: [
        "coordinator", "cloud", "analyst", "validator",
    ],
    TaskIntent.MOBILE_TEST: [
        "coordinator", "recon", "analyst", "validator",
    ],
    TaskIntent.AD_ASSESSMENT: [
        "coordinator", "recon", "network", "exploiter",
        "validator",
    ],
    TaskIntent.OSINT: [
        "coordinator", "osint", "analyst",
    ],
    TaskIntent.INCIDENT_RESPONSE: [
        "coordinator", "forensics", "analyst", "reporter",
    ],
    TaskIntent.COMPLIANCE: [
        "coordinator", "analyst", "reporter",
    ],
    TaskIntent.EXPLOIT_DEV: [
        "coordinator", "code_auditor", "exploiter",
        "validator",
    ],
    TaskIntent.RED_TEAM: [
        "coordinator", "planner", "recon", "osint",
        "web", "network", "exploiter", "validator",
    ],
}

# Intent → model preferences (primary, reasoning, validation)
INTENT_MODEL_MAP: dict[TaskIntent, dict[str, str]] = {
    TaskIntent.FULL_ASSESSMENT: {
        "primary": "WhiteRabbitNeo-7B",
        "reasoning": "DeepSeek-R1",
        "validation": "Qwen2.5-Coder-14B",
        "planning": "Hermes-4-14B",
    },
    TaskIntent.WEB_PENTEST: {
        "primary": "WhiteRabbitNeo-7B",
        "reasoning": "DeepSeek-R1",
        "validation": "Dolphin-2.9",
        "code": "Qwen2.5-Coder-14B",
    },
    TaskIntent.CODE_AUDIT: {
        "primary": "Qwen2.5-Coder-14B",
        "reasoning": "DeepSeek-R1",
        "validation": "CodeLlama-13B",
        "long_context": "Yi-9B-200K",
    },
    TaskIntent.CLOUD_AUDIT: {
        "primary": "Hermes-4-14B",
        "reasoning": "DeepSeek-R1",
        "validation": "Mistral-7B",
    },
    TaskIntent.RED_TEAM: {
        "primary": "WhiteRabbitNeo-7B",
        "reasoning": "DeepSeek-R1",
        "uncensored": "Dolphin-2.9",
        "planning": "Hermes-4-14B",
    },
}

# Intent → phase sequence
INTENT_PHASES: dict[TaskIntent, list[str]] = {
    TaskIntent.FULL_ASSESSMENT: [
        "recon", "enumeration", "scanning", "analysis",
        "exploitation", "post_exploit", "validation", "reporting",
    ],
    TaskIntent.WEB_PENTEST: [
        "recon", "crawling", "scanning", "analysis",
        "exploitation", "validation", "reporting",
    ],
    TaskIntent.NETWORK_PENTEST: [
        "recon", "port_scan", "service_enum", "vuln_scan",
        "exploitation", "privesc", "lateral", "reporting",
    ],
    TaskIntent.CODE_AUDIT: [
        "setup", "static_analysis", "manual_review",
        "finding_validation", "reporting",
    ],
    TaskIntent.CLOUD_AUDIT: [
        "iam_review", "config_audit", "network_review",
        "storage_audit", "compliance_check", "reporting",
    ],
    TaskIntent.RED_TEAM: [
        "osint", "recon", "initial_access", "persistence",
        "privesc", "lateral", "objective", "reporting",
    ],
}

# Keywords for intent classification
INTENT_KEYWORDS: dict[TaskIntent, list[str]] = {
    TaskIntent.WEB_PENTEST: [
        "web", "website", "webapp", "http", "api", "url",
        "owasp", "xss", "sqli", "injection",
    ],
    TaskIntent.NETWORK_PENTEST: [
        "network", "port", "firewall", "switch", "router",
        "subnet", "ip range", "internal",
    ],
    TaskIntent.CODE_AUDIT: [
        "code", "source", "review", "audit", "static analysis",
        "repository", "github", "gitlab",
    ],
    TaskIntent.CLOUD_AUDIT: [
        "aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda",
        "iam", "kubernetes", "container",
    ],
    TaskIntent.MOBILE_TEST: [
        "mobile", "android", "ios", "apk", "ipa", "app",
    ],
    TaskIntent.AD_ASSESSMENT: [
        "active directory", "ad", "domain", "kerberos",
        "ldap", "windows", "dc",
    ],
    TaskIntent.OSINT: [
        "osint", "reconnaissance", "gather info", "email",
        "employee", "social",
    ],
    TaskIntent.INCIDENT_RESPONSE: [
        "incident", "breach", "compromise", "forensic",
        "investigate", "malware",
    ],
    TaskIntent.COMPLIANCE: [
        "compliance", "pci", "hipaa", "soc2", "iso",
        "nist", "audit",
    ],
    TaskIntent.EXPLOIT_DEV: [
        "exploit", "buffer overflow", "rop", "shellcode",
        "binary", "reverse",
    ],
    TaskIntent.RED_TEAM: [
        "red team", "adversary", "simulate", "attack",
        "compromise", "campaign",
    ],
    TaskIntent.FULL_ASSESSMENT: [
        "full", "comprehensive", "everything", "complete",
        "pentest", "assessment", "hack",
    ],
}


@dataclass
class BrainDecision:
    """A decision made by the unified brain."""
    intent: TaskIntent = TaskIntent.UNKNOWN
    confidence: float = 0.0
    kb_domains: list[str] = field(default_factory=list)
    roles_needed: list[str] = field(default_factory=list)
    models: dict[str, str] = field(default_factory=dict)
    phases: list[str] = field(default_factory=list)
    tools_recommended: list[str] = field(default_factory=list)
    max_agents: int = 3
    max_depth: int = 3
    estimated_time_min: int = 30
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent.value[:12],
            "conf": f"{self.confidence:.2f}",
            "roles": len(self.roles_needed),
            "phases": len(self.phases),
            "time": f"{self.estimated_time_min}m",
        }


@dataclass
class BrainContext:
    """Current brain context state."""
    state: BrainState = BrainState.IDLE
    current_target: str = ""
    current_intent: TaskIntent = TaskIntent.UNKNOWN
    active_agents: int = 0
    findings_count: int = 0
    phase_index: int = 0
    total_tokens_used: int = 0
    started_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value[:8],
            "target": self.current_target[:15],
            "agents": self.active_agents,
            "findings": self.findings_count,
        }


class UnifiedBrain:
    """Central intelligence integrating all modules.

    Understands tasks, selects knowledge, plans
    execution, routes to models, and learns
    from results. This is what makes the agent
    intelligent for ANY security task.
    """

    def __init__(self) -> None:
        self._context = BrainContext()
        self._decisions: list[BrainDecision] = []
        self._log = logger.bind(component="brain")

    def classify_intent(self, task: str) -> tuple[TaskIntent, float]:
        """Classify the user's task intent."""
        lower = task.lower()
        scores: dict[TaskIntent, float] = {}

        for intent, keywords in INTENT_KEYWORDS.items():
            score = 0.0
            for keyword in keywords:
                if keyword in lower:
                    score += 1.0

            if score > 0:
                scores[intent] = score / len(keywords)

        if not scores:
            return TaskIntent.FULL_ASSESSMENT, 0.3

        best = max(scores, key=scores.get)  # type: ignore[arg-type]
        return best, min(1.0, scores[best] * 2)

    def understand_task(self, task: str, target: str = "") -> BrainDecision:
        """Fully understand a task and produce a decision."""
        self._context.state = BrainState.UNDERSTANDING

        # Classify intent
        intent, confidence = self.classify_intent(task)

        # Get required knowledge domains
        kb_domains = INTENT_KB_MAP.get(intent, [])

        # Get required roles
        roles = INTENT_ROLE_MAP.get(intent, ["coordinator", "scanner"])

        # Get model preferences
        models = INTENT_MODEL_MAP.get(
            intent,
            {"primary": "WhiteRabbitNeo-7B", "reasoning": "DeepSeek-R1"},
        )

        # Get phase sequence
        phases = INTENT_PHASES.get(
            intent,
            ["recon", "scanning", "analysis", "reporting"],
        )

        # Estimate resources
        max_agents = min(8, len(roles))
        max_depth = 3 if intent in (
            TaskIntent.FULL_ASSESSMENT, TaskIntent.RED_TEAM,
        ) else 2

        # Estimate time
        time_estimates = {
            TaskIntent.FULL_ASSESSMENT: 120,
            TaskIntent.WEB_PENTEST: 60,
            TaskIntent.NETWORK_PENTEST: 90,
            TaskIntent.CODE_AUDIT: 45,
            TaskIntent.CLOUD_AUDIT: 60,
            TaskIntent.MOBILE_TEST: 45,
            TaskIntent.AD_ASSESSMENT: 90,
            TaskIntent.OSINT: 30,
            TaskIntent.INCIDENT_RESPONSE: 120,
            TaskIntent.COMPLIANCE: 60,
            TaskIntent.EXPLOIT_DEV: 60,
            TaskIntent.RED_TEAM: 180,
        }
        est_time = time_estimates.get(intent, 60)

        # Select tools based on intent and phases
        tools = self._select_tools_for_intent(intent)

        decision = BrainDecision(
            intent=intent,
            confidence=confidence,
            kb_domains=kb_domains,
            roles_needed=roles,
            models=models,
            phases=phases,
            tools_recommended=tools,
            max_agents=max_agents,
            max_depth=max_depth,
            estimated_time_min=est_time,
            reasoning=f"Classified as {intent.value} with {confidence:.0%} confidence",
        )

        self._decisions.append(decision)
        self._context.current_intent = intent
        self._context.current_target = target
        self._context.state = BrainState.PLANNING

        return decision

    def _select_tools_for_intent(self, intent: TaskIntent) -> list[str]:
        """Select tools based on intent."""
        tool_map: dict[TaskIntent, list[str]] = {
            TaskIntent.WEB_PENTEST: [
                "nuclei", "sqlmap", "ffuf", "nikto", "burp",
                "xsstrike", "wappalyzer", "httpx",
            ],
            TaskIntent.NETWORK_PENTEST: [
                "nmap", "masscan", "responder", "crackmapexec",
                "impacket", "bettercap", "wireshark",
            ],
            TaskIntent.CODE_AUDIT: [
                "semgrep", "bandit", "codeql", "sonarqube",
                "trufflehog", "gitleaks",
            ],
            TaskIntent.CLOUD_AUDIT: [
                "prowler", "scoutsuite", "pacu", "cloudfox",
                "trivy", "steampipe",
            ],
            TaskIntent.MOBILE_TEST: [
                "mobsf", "apktool", "jadx", "frida",
                "objection", "drozer",
            ],
            TaskIntent.AD_ASSESSMENT: [
                "bloodhound", "impacket", "rubeus",
                "crackmapexec", "mimikatz", "kerbrute",
            ],
            TaskIntent.OSINT: [
                "theHarvester", "recon-ng", "sherlock",
                "spiderfoot", "maltego",
            ],
            TaskIntent.FULL_ASSESSMENT: [
                "nmap", "nuclei", "sqlmap", "ffuf", "burp",
                "masscan", "semgrep", "prowler", "httpx",
            ],
            TaskIntent.RED_TEAM: [
                "nmap", "nuclei", "sqlmap", "responder",
                "crackmapexec", "impacket", "bloodhound",
                "burp", "metasploit",
            ],
        }
        return tool_map.get(intent, ["nmap", "nuclei", "httpx"])

    def build_system_prompt(
        self,
        decision: BrainDecision,
        role: str = "coordinator",
    ) -> str:
        """Build the complete system prompt for an agent.

        This is where ALL knowledge gets injected
        into the LLM context.
        """
        lines: list[str] = []

        # Role identity
        lines.append(f"# Role: {role.upper()}")
        lines.append(f"Task: {decision.intent.value}")
        lines.append("")

        # Phase awareness
        if decision.phases:
            lines.append(f"## Phases: {' → '.join(decision.phases)}")
            lines.append("")

        # Available tools
        if decision.tools_recommended:
            lines.append("## Tools")
            for tool in decision.tools_recommended:
                lines.append(f"  - {tool}")
            lines.append("")

        # Team awareness
        if decision.roles_needed:
            lines.append("## Team")
            for r in decision.roles_needed:
                lines.append(f"  - {r}")
            lines.append("")

        # Model routing info
        if decision.models:
            lines.append("## Models")
            for purpose, model in decision.models.items():
                lines.append(f"  {purpose}: {model}")
            lines.append("")

        # Constraints
        lines.append("## Constraints")
        lines.append(f"  Max agents: {decision.max_agents}")
        lines.append(f"  Max depth: {decision.max_depth}")
        lines.append(f"  Time budget: ~{decision.estimated_time_min}min")

        return "\n".join(lines)

    def get_next_action(self) -> dict[str, Any]:
        """Determine the next action the agent should take."""
        if not self._decisions:
            return {"action": "await_task", "reason": "No task assigned"}

        decision = self._decisions[-1]
        phase_idx = self._context.phase_index

        if phase_idx >= len(decision.phases):
            return {"action": "complete", "reason": "All phases done"}

        current_phase = decision.phases[phase_idx]

        return {
            "action": "execute_phase",
            "phase": current_phase,
            "phase_index": phase_idx,
            "total_phases": len(decision.phases),
            "tools": self._select_tools_for_intent(decision.intent),
            "model": decision.models.get("primary", "WhiteRabbitNeo-7B"),
        }

    def advance_phase(self) -> str:
        """Move to the next phase."""
        self._context.phase_index += 1
        if self._decisions:
            decision = self._decisions[-1]
            if self._context.phase_index < len(decision.phases):
                return decision.phases[self._context.phase_index]
        return "complete"

    def record_finding(self) -> None:
        """Record that a finding was discovered."""
        self._context.findings_count += 1

    def build_brain_prompt(self) -> str:
        """Build brain state context for LLM."""
        lines = ["## Brain State\n"]
        lines.append(f"State: {self._context.state.value}")
        lines.append(f"Intent: {self._context.current_intent.value}")
        lines.append(f"Target: {self._context.current_target[:20]}")
        lines.append(f"Agents: {self._context.active_agents}")
        lines.append(f"Findings: {self._context.findings_count}")
        lines.append(f"Decisions: {len(self._decisions)}")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._context.state.value,
            "intent": self._context.current_intent.value,
            "decisions": len(self._decisions),
            "findings": self._context.findings_count,
        }
