"""Dynamic knowledge selector — picks KBs to inject based on task.

Implements:
1. Task analysis to determine relevant knowledge domains
2. Knowledge base registry with metadata
3. Token-budget-aware selection (fit within prompt limit)
4. Priority ranking of knowledge sources
5. Combined prompt assembly from multiple KBs
6. Historical effectiveness tracking
7. Selector prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class KnowledgeDomain(str, Enum):
    WEB_SECURITY = "web_security"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    CODE_AUDIT = "code_audit"
    EXPLOITATION = "exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    SOCIAL_ENGINEERING = "social_engineering"
    MALWARE = "malware"
    FORENSICS = "forensics"
    AI_ML = "ai_ml"
    CONTAINER = "container"
    ACTIVE_DIRECTORY = "active_directory"
    HARDWARE = "hardware"
    RED_TEAM = "red_team"
    COMPLIANCE = "compliance"
    THREAT_INTEL = "threat_intel"
    SUPPLY_CHAIN = "supply_chain"
    ZERODAY = "zeroday"
    DETECTION = "detection"
    INCIDENT_RESPONSE = "incident_response"
    ADVANCED_STRATEGY = "advanced_strategy"


@dataclass
class KBEntry:
    """A registered knowledge base."""
    domain: KnowledgeDomain = KnowledgeDomain.WEB_SECURITY
    kb_name: str = ""
    build_method: str = ""      # Name of build_*_prompt method
    avg_tokens: int = 500       # Average token count of prompt
    relevance_keywords: list[str] = field(default_factory=list)
    priority: int = 5           # 1=highest, 10=lowest
    times_used: int = 0
    times_effective: int = 0

    @property
    def effectiveness(self) -> float:
        if self.times_used == 0:
            return 0.5
        return self.times_effective / self.times_used

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain.value[:12],
            "name": self.kb_name[:15],
            "priority": self.priority,
            "eff": f"{self.effectiveness:.0%}",
        }


# ── KB registry with relevance keywords ─────────────────────

KB_REGISTRY: list[dict[str, Any]] = [
    {
        "domain": "web_security", "name": "WebApp Security KB",
        "method": "build_webapp_prompt", "tokens": 600, "priority": 2,
        "keywords": ["web", "http", "xss", "sqli", "injection", "owasp", "csrf", "ssrf", "ssti", "cookie", "session", "html", "javascript", "api", "rest"],
    },
    {
        "domain": "network", "name": "Network Security KB",
        "method": "build_network_prompt", "tokens": 500, "priority": 3,
        "keywords": ["network", "tcp", "udp", "port", "scan", "nmap", "firewall", "router", "switch", "vlan", "dns", "dhcp", "arp", "subnet"],
    },
    {
        "domain": "cloud", "name": "Cloud Security KB",
        "method": "build_cloud_prompt", "tokens": 600, "priority": 3,
        "keywords": ["aws", "azure", "gcp", "cloud", "s3", "ec2", "iam", "lambda", "kubernetes", "terraform", "serverless", "bucket"],
    },
    {
        "domain": "mobile", "name": "Mobile Security KB",
        "method": "build_mobile_prompt", "tokens": 550, "priority": 4,
        "keywords": ["android", "ios", "apk", "mobile", "frida", "objection", "ipa", "swift", "kotlin", "smali", "ble", "nfc"],
    },
    {
        "domain": "exploitation", "name": "Exploitation KB",
        "method": "build_exploitation_prompt", "tokens": 600, "priority": 2,
        "keywords": ["exploit", "buffer", "overflow", "rop", "shellcode", "payload", "rce", "privilege", "escalation", "bypass"],
    },
    {
        "domain": "lateral_movement", "name": "Lateral Movement KB",
        "method": "build_lateral_prompt", "tokens": 550, "priority": 3,
        "keywords": ["lateral", "pivot", "psexec", "wmi", "winrm", "rdp", "ssh", "pass-the-hash", "mimikatz", "domain"],
    },
    {
        "domain": "persistence", "name": "Persistence KB",
        "method": "build_persistence_prompt", "tokens": 550, "priority": 4,
        "keywords": ["persistence", "backdoor", "rootkit", "registry", "scheduled", "task", "service", "cron", "webshell", "implant"],
    },
    {
        "domain": "social_engineering", "name": "Social Engineering KB",
        "method": "build_social_prompt", "tokens": 500, "priority": 5,
        "keywords": ["phishing", "social", "pretexting", "vishing", "impersonation", "human", "email", "call"],
    },
    {
        "domain": "malware", "name": "Malware Analysis KB",
        "method": "build_malware_prompt", "tokens": 550, "priority": 3,
        "keywords": ["malware", "virus", "trojan", "ransomware", "backdoor", "reverse", "engineering", "binary", "pe", "elf"],
    },
    {
        "domain": "forensics", "name": "Forensics KB",
        "method": "build_forensics_prompt", "tokens": 550, "priority": 4,
        "keywords": ["forensics", "evidence", "memory", "disk", "timeline", "volatility", "acquisition", "chain", "custody"],
    },
    {
        "domain": "ai_ml", "name": "AI/ML Security KB",
        "method": "build_aiml_prompt", "tokens": 550, "priority": 4,
        "keywords": ["ai", "ml", "llm", "model", "prompt", "injection", "adversarial", "poisoning", "extraction"],
    },
    {
        "domain": "container", "name": "Container Security KB",
        "method": "build_container_prompt", "tokens": 550, "priority": 3,
        "keywords": ["docker", "container", "kubernetes", "k8s", "pod", "helm", "image", "registry", "escape"],
    },
    {
        "domain": "active_directory", "name": "Active Directory KB",
        "method": "build_ad_prompt", "tokens": 600, "priority": 2,
        "keywords": ["active", "directory", "ad", "ldap", "kerberos", "ntlm", "domain", "gpo", "bloodhound", "dcsync"],
    },
    {
        "domain": "hardware", "name": "Hardware Security KB",
        "method": "build_hardware_prompt", "tokens": 550, "priority": 5,
        "keywords": ["hardware", "firmware", "uefi", "bios", "jtag", "spi", "uart", "embedded", "iot", "side-channel"],
    },
    {
        "domain": "red_team", "name": "Red Team Ops KB",
        "method": "build_redteam_prompt", "tokens": 600, "priority": 2,
        "keywords": ["red", "team", "c2", "command", "control", "exfiltration", "adversary", "simulation", "engagement"],
    },
    {
        "domain": "compliance", "name": "Compliance KB",
        "method": "build_compliance_prompt", "tokens": 550, "priority": 6,
        "keywords": ["pci", "hipaa", "gdpr", "soc2", "nist", "compliance", "regulation", "audit", "standard"],
    },
    {
        "domain": "threat_intel", "name": "Threat Intel KB",
        "method": "build_threat_intel_prompt", "tokens": 550, "priority": 3,
        "keywords": ["threat", "intelligence", "ioc", "apt", "hunting", "misp", "stix", "indicator"],
    },
    {
        "domain": "supply_chain", "name": "Supply Chain KB",
        "method": "build_supply_chain_prompt", "tokens": 550, "priority": 3,
        "keywords": ["supply", "chain", "dependency", "package", "npm", "pypi", "sbom", "typosquat", "pipeline"],
    },
    {
        "domain": "zeroday", "name": "Zero-Day Research KB",
        "method": "build_zeroday_prompt", "tokens": 600, "priority": 2,
        "keywords": ["zero", "day", "0day", "fuzzing", "variant", "crash", "vulnerability", "research", "codeql"],
    },
    {
        "domain": "detection", "name": "Detection Engineering KB",
        "method": "build_detection_prompt", "tokens": 550, "priority": 3,
        "keywords": ["detection", "evasion", "edr", "waf", "ids", "ips", "siem", "sigma", "bypass"],
    },
    {
        "domain": "incident_response", "name": "Incident Response KB",
        "method": "build_ir_prompt", "tokens": 550, "priority": 3,
        "keywords": ["incident", "response", "containment", "recovery", "evidence", "triage", "ir"],
    },
    {
        "domain": "advanced_strategy", "name": "Advanced Strategy KB",
        "method": "build_strategy_prompt", "tokens": 600, "priority": 2,
        "keywords": ["strategy", "emergent", "timing", "logic", "business", "advanced", "approach"],
    },
]


class DynamicKnowledgeSelector:
    """Selects relevant KBs to inject into agent prompts.

    Analyzes task text, matches against KB keywords,
    ranks by priority and relevance, fits within
    token budget.
    """

    def __init__(self, token_budget: int = 3000) -> None:
        self._entries: list[KBEntry] = []
        self._token_budget = token_budget
        self._selection_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="knowledge_selector")
        self._load_registry()

    def _load_registry(self) -> None:
        """Load KB registry."""
        for spec in KB_REGISTRY:
            try:
                domain = KnowledgeDomain(spec["domain"])
            except ValueError:
                continue
            entry = KBEntry(
                domain=domain,
                kb_name=spec["name"],
                build_method=spec["method"],
                avg_tokens=spec.get("tokens", 500),
                relevance_keywords=spec.get("keywords", []),
                priority=spec.get("priority", 5),
            )
            self._entries.append(entry)

    def select(
        self,
        task_text: str,
        max_kbs: int = 5,
        token_budget: int = 0,
    ) -> list[KBEntry]:
        """Select relevant KBs for a task."""
        budget = token_budget or self._token_budget
        task_lower = task_text.lower()
        task_words = set(task_lower.split())

        scored: list[tuple[float, KBEntry]] = []
        for entry in self._entries:
            # Keyword match score
            matches = sum(
                1 for kw in entry.relevance_keywords
                if kw in task_lower
            )
            if matches == 0:
                # Check word-level overlap
                kw_set = set(entry.relevance_keywords)
                overlap = len(task_words & kw_set)
                if overlap == 0:
                    continue
                matches = overlap

            # Relevance score
            relevance = matches / len(entry.relevance_keywords) if entry.relevance_keywords else 0

            # Priority bonus (lower number = higher priority)
            priority_bonus = (10 - entry.priority) / 10

            # Effectiveness bonus
            eff_bonus = entry.effectiveness * 0.2

            score = relevance * 0.5 + priority_bonus * 0.3 + eff_bonus * 0.2
            scored.append((score, entry))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        # Fit within token budget
        selected: list[KBEntry] = []
        used_tokens = 0
        for _score, entry in scored:
            if len(selected) >= max_kbs:
                break
            if used_tokens + entry.avg_tokens > budget:
                continue
            selected.append(entry)
            used_tokens += entry.avg_tokens

        # Track selection
        self._selection_history.append({
            "task": task_text[:50],
            "selected": [e.kb_name for e in selected],
            "token_est": used_tokens,
            "time": time.time(),
        })

        return selected

    def record_effectiveness(
        self,
        domain: KnowledgeDomain,
        was_effective: bool,
    ) -> None:
        """Record whether a KB was effective for a task."""
        for entry in self._entries:
            if entry.domain == domain:
                entry.times_used += 1
                if was_effective:
                    entry.times_effective += 1
                break

    def build_selector_prompt(self) -> str:
        """Build selector context for LLM."""
        lines = ["## Knowledge Selector\n"]

        lines.append(f"Available KBs: {len(self._entries)}")
        lines.append(f"Token budget: {self._token_budget}")

        # List domains
        domains = sorted(set(e.domain.value for e in self._entries))
        lines.append(f"Domains: {', '.join(d[:10] for d in domains[:10])}")

        # Recent selections
        if self._selection_history:
            lines.append("\nRecent selections:")
            for sel in self._selection_history[-3:]:
                kbs = ", ".join(s[:12] for s in sel["selected"][:3])
                lines.append(f"  {sel['task'][:25]} → [{kbs}]")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        domain_counts: dict[str, int] = {}
        for entry in self._entries:
            domain_counts[entry.domain.value] = domain_counts.get(entry.domain.value, 0) + 1

        return {
            "total_kbs": len(self._entries),
            "selections": len(self._selection_history),
            "domains": len(domain_counts),
        }
