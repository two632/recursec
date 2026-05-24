"""Deep task intent classification engine.

Classifies user input into specific actionable intents
with confidence scores, then maps to KB domains, agent
roles, model preferences, and execution phases.

Unlike the basic UnifiedBrain classifier, this uses
multi-signal classification: keyword matching, pattern
recognition, entity extraction, and context from
previous tasks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskIntent(str, Enum):
    RECON = "recon"
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCAN = "port_scan"
    WEB_VULN_SCAN = "web_vuln_scan"
    API_SECURITY = "api_security"
    CODE_AUDIT = "code_audit"
    NETWORK_PENTEST = "network_pentest"
    CLOUD_AUDIT = "cloud_audit"
    MOBILE_PENTEST = "mobile_pentest"
    WIRELESS_PENTEST = "wireless_pentest"
    SOCIAL_ENGINEERING = "social_engineering"
    PHISHING = "phishing"
    OSINT = "osint"
    CRYPTANALYSIS = "cryptanalysis"
    FORENSICS = "forensics"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    EXPLOIT_DEV = "exploit_dev"
    PRIVESC = "privesc"
    LATERAL_MOVEMENT = "lateral_movement"
    CONTAINER_SECURITY = "container_security"
    IOT_SECURITY = "iot_security"
    SUPPLY_CHAIN = "supply_chain"
    COMPLIANCE = "compliance"
    THREAT_HUNT = "threat_hunt"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    BUG_BOUNTY = "bug_bounty"
    FULL_PENTEST = "full_pentest"
    GENERAL_SECURITY = "general_security"


@dataclass
class IntentSignal:
    """A signal contributing to intent classification."""
    signal_type: str = ""
    intent: TaskIntent = TaskIntent.GENERAL_SECURITY
    confidence: float = 0.0
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.signal_type[:8],
            "intent": self.intent.value[:12],
            "conf": f"{self.confidence:.2f}",
        }


@dataclass
class ClassificationResult:
    """Result of intent classification."""
    primary_intent: TaskIntent = TaskIntent.GENERAL_SECURITY
    confidence: float = 0.0
    secondary_intents: list[tuple[TaskIntent, float]] = field(default_factory=list)
    signals: list[IntentSignal] = field(default_factory=list)
    extracted_entities: dict[str, list[str]] = field(default_factory=dict)
    recommended_kbs: list[str] = field(default_factory=list)
    recommended_roles: list[str] = field(default_factory=list)
    recommended_model: str = ""
    recommended_phases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.primary_intent.value,
            "confidence": f"{self.confidence:.2f}",
            "secondary": len(self.secondary_intents),
            "entities": {k: len(v) for k, v in self.extracted_entities.items()},
            "kbs": len(self.recommended_kbs),
            "roles": len(self.recommended_roles),
        }


# Keyword → intent mapping with weights
KEYWORD_SIGNALS: dict[str, list[tuple[TaskIntent, float]]] = {
    "recon": [(TaskIntent.RECON, 0.8), (TaskIntent.OSINT, 0.3)],
    "reconnaissance": [(TaskIntent.RECON, 0.9)],
    "subdomain": [(TaskIntent.SUBDOMAIN_ENUM, 0.9)],
    "subfinder": [(TaskIntent.SUBDOMAIN_ENUM, 0.9)],
    "amass": [(TaskIntent.SUBDOMAIN_ENUM, 0.8)],
    "port scan": [(TaskIntent.PORT_SCAN, 0.9)],
    "nmap": [(TaskIntent.PORT_SCAN, 0.8), (TaskIntent.NETWORK_PENTEST, 0.3)],
    "masscan": [(TaskIntent.PORT_SCAN, 0.8)],
    "web vuln": [(TaskIntent.WEB_VULN_SCAN, 0.9)],
    "xss": [(TaskIntent.WEB_VULN_SCAN, 0.8), (TaskIntent.BUG_BOUNTY, 0.3)],
    "sqli": [(TaskIntent.WEB_VULN_SCAN, 0.8)],
    "sql injection": [(TaskIntent.WEB_VULN_SCAN, 0.9)],
    "sqlmap": [(TaskIntent.WEB_VULN_SCAN, 0.8)],
    "nuclei": [(TaskIntent.WEB_VULN_SCAN, 0.7)],
    "api": [(TaskIntent.API_SECURITY, 0.7)],
    "swagger": [(TaskIntent.API_SECURITY, 0.8)],
    "graphql": [(TaskIntent.API_SECURITY, 0.8)],
    "rest api": [(TaskIntent.API_SECURITY, 0.9)],
    "code audit": [(TaskIntent.CODE_AUDIT, 0.9)],
    "code review": [(TaskIntent.CODE_AUDIT, 0.9)],
    "semgrep": [(TaskIntent.CODE_AUDIT, 0.8)],
    "bandit": [(TaskIntent.CODE_AUDIT, 0.7)],
    "sast": [(TaskIntent.CODE_AUDIT, 0.8)],
    "network": [(TaskIntent.NETWORK_PENTEST, 0.6)],
    "pentest": [(TaskIntent.FULL_PENTEST, 0.7), (TaskIntent.NETWORK_PENTEST, 0.3)],
    "penetration test": [(TaskIntent.FULL_PENTEST, 0.9)],
    "cloud": [(TaskIntent.CLOUD_AUDIT, 0.7)],
    "aws": [(TaskIntent.CLOUD_AUDIT, 0.8)],
    "azure": [(TaskIntent.CLOUD_AUDIT, 0.8)],
    "gcp": [(TaskIntent.CLOUD_AUDIT, 0.8)],
    "prowler": [(TaskIntent.CLOUD_AUDIT, 0.8)],
    "mobile": [(TaskIntent.MOBILE_PENTEST, 0.8)],
    "android": [(TaskIntent.MOBILE_PENTEST, 0.8)],
    "ios": [(TaskIntent.MOBILE_PENTEST, 0.8)],
    "apk": [(TaskIntent.MOBILE_PENTEST, 0.9)],
    "wireless": [(TaskIntent.WIRELESS_PENTEST, 0.8)],
    "wifi": [(TaskIntent.WIRELESS_PENTEST, 0.9)],
    "bluetooth": [(TaskIntent.WIRELESS_PENTEST, 0.7)],
    "social engineering": [(TaskIntent.SOCIAL_ENGINEERING, 0.9)],
    "phishing": [(TaskIntent.PHISHING, 0.9), (TaskIntent.SOCIAL_ENGINEERING, 0.4)],
    "osint": [(TaskIntent.OSINT, 0.9)],
    "sherlock": [(TaskIntent.OSINT, 0.7)],
    "theharvester": [(TaskIntent.OSINT, 0.8)],
    "crypto": [(TaskIntent.CRYPTANALYSIS, 0.7)],
    "cipher": [(TaskIntent.CRYPTANALYSIS, 0.8)],
    "hash": [(TaskIntent.CRYPTANALYSIS, 0.6)],
    "hashcat": [(TaskIntent.CRYPTANALYSIS, 0.8)],
    "forensics": [(TaskIntent.FORENSICS, 0.9)],
    "volatility": [(TaskIntent.FORENSICS, 0.9)],
    "autopsy": [(TaskIntent.FORENSICS, 0.8)],
    "incident": [(TaskIntent.INCIDENT_RESPONSE, 0.8)],
    "breach": [(TaskIntent.INCIDENT_RESPONSE, 0.7)],
    "malware": [(TaskIntent.MALWARE_ANALYSIS, 0.9)],
    "reverse engineer": [(TaskIntent.MALWARE_ANALYSIS, 0.7)],
    "ghidra": [(TaskIntent.MALWARE_ANALYSIS, 0.8)],
    "exploit": [(TaskIntent.EXPLOIT_DEV, 0.7)],
    "buffer overflow": [(TaskIntent.EXPLOIT_DEV, 0.9)],
    "rop": [(TaskIntent.EXPLOIT_DEV, 0.8)],
    "privilege escalation": [(TaskIntent.PRIVESC, 0.9)],
    "privesc": [(TaskIntent.PRIVESC, 0.9)],
    "linpeas": [(TaskIntent.PRIVESC, 0.8)],
    "winpeas": [(TaskIntent.PRIVESC, 0.8)],
    "lateral movement": [(TaskIntent.LATERAL_MOVEMENT, 0.9)],
    "pivoting": [(TaskIntent.LATERAL_MOVEMENT, 0.7)],
    "psexec": [(TaskIntent.LATERAL_MOVEMENT, 0.8)],
    "docker": [(TaskIntent.CONTAINER_SECURITY, 0.7)],
    "kubernetes": [(TaskIntent.CONTAINER_SECURITY, 0.9)],
    "k8s": [(TaskIntent.CONTAINER_SECURITY, 0.9)],
    "container": [(TaskIntent.CONTAINER_SECURITY, 0.8)],
    "iot": [(TaskIntent.IOT_SECURITY, 0.9)],
    "firmware": [(TaskIntent.IOT_SECURITY, 0.7)],
    "scada": [(TaskIntent.IOT_SECURITY, 0.8)],
    "supply chain": [(TaskIntent.SUPPLY_CHAIN, 0.9)],
    "dependency": [(TaskIntent.SUPPLY_CHAIN, 0.6)],
    "compliance": [(TaskIntent.COMPLIANCE, 0.9)],
    "pci": [(TaskIntent.COMPLIANCE, 0.8)],
    "hipaa": [(TaskIntent.COMPLIANCE, 0.8)],
    "gdpr": [(TaskIntent.COMPLIANCE, 0.8)],
    "threat hunt": [(TaskIntent.THREAT_HUNT, 0.9)],
    "hunting": [(TaskIntent.THREAT_HUNT, 0.7)],
    "red team": [(TaskIntent.RED_TEAM, 0.9)],
    "blue team": [(TaskIntent.BLUE_TEAM, 0.9)],
    "detection": [(TaskIntent.BLUE_TEAM, 0.5)],
    "bug bounty": [(TaskIntent.BUG_BOUNTY, 0.9)],
    "hackerone": [(TaskIntent.BUG_BOUNTY, 0.8)],
    "bugcrowd": [(TaskIntent.BUG_BOUNTY, 0.8)],
    "vulnerability": [(TaskIntent.WEB_VULN_SCAN, 0.4), (TaskIntent.FULL_PENTEST, 0.3)],
    "hack": [(TaskIntent.FULL_PENTEST, 0.5), (TaskIntent.RED_TEAM, 0.3)],
    "find vulns": [(TaskIntent.FULL_PENTEST, 0.7), (TaskIntent.WEB_VULN_SCAN, 0.5)],
    "security audit": [(TaskIntent.FULL_PENTEST, 0.6), (TaskIntent.COMPLIANCE, 0.4)],
}

# Intent → recommended KB domains
INTENT_KB_MAP: dict[TaskIntent, list[str]] = {
    TaskIntent.RECON: ["web_vuln", "network", "osint", "dns"],
    TaskIntent.SUBDOMAIN_ENUM: ["web_vuln", "dns", "osint"],
    TaskIntent.PORT_SCAN: ["network", "web_vuln"],
    TaskIntent.WEB_VULN_SCAN: ["web_vuln", "xss", "ssrf", "deserialization", "api_gateway", "business_logic"],
    TaskIntent.API_SECURITY: ["api_gateway", "web_vuln", "business_logic"],
    TaskIntent.CODE_AUDIT: ["code_audit", "devsecops"],
    TaskIntent.NETWORK_PENTEST: ["network", "lateral_movement", "privesc", "active_directory"],
    TaskIntent.CLOUD_AUDIT: ["cloud", "container_k8s", "serverless"],
    TaskIntent.MOBILE_PENTEST: ["mobile", "api_gateway", "web_vuln"],
    TaskIntent.WIRELESS_PENTEST: ["wireless", "network"],
    TaskIntent.SOCIAL_ENGINEERING: ["social_engineering", "phishing", "insider_threat"],
    TaskIntent.PHISHING: ["phishing", "social_engineering", "email"],
    TaskIntent.OSINT: ["osint", "social_engineering", "threat_intel"],
    TaskIntent.CRYPTANALYSIS: ["crypto", "web_vuln"],
    TaskIntent.FORENSICS: ["forensics", "malware_analysis", "threat_intel"],
    TaskIntent.INCIDENT_RESPONSE: ["incident_response", "forensics", "threat_intel", "evasion"],
    TaskIntent.MALWARE_ANALYSIS: ["malware_analysis", "forensics", "binary_exploitation"],
    TaskIntent.EXPLOIT_DEV: ["binary_exploitation", "web_vuln"],
    TaskIntent.PRIVESC: ["privesc", "active_directory", "lateral_movement"],
    TaskIntent.LATERAL_MOVEMENT: ["lateral_movement", "active_directory", "network"],
    TaskIntent.CONTAINER_SECURITY: ["container_k8s", "cloud", "supply_chain"],
    TaskIntent.IOT_SECURITY: ["iot_ics", "firmware", "wireless", "network"],
    TaskIntent.SUPPLY_CHAIN: ["supply_chain", "devsecops", "code_audit"],
    TaskIntent.COMPLIANCE: ["compliance", "cloud", "devsecops"],
    TaskIntent.THREAT_HUNT: ["threat_intel", "evasion", "forensics", "incident_response"],
    TaskIntent.RED_TEAM: [
        "evasion", "lateral_movement", "privesc", "web_vuln",
        "network", "social_engineering", "active_directory",
    ],
    TaskIntent.BLUE_TEAM: [
        "threat_intel", "incident_response", "forensics",
        "evasion", "compliance",
    ],
    TaskIntent.BUG_BOUNTY: [
        "web_vuln", "api_gateway", "ssrf", "xss",
        "business_logic", "deserialization",
    ],
    TaskIntent.FULL_PENTEST: [
        "web_vuln", "network", "cloud", "api_gateway",
        "privesc", "lateral_movement", "active_directory",
    ],
    TaskIntent.GENERAL_SECURITY: ["web_vuln", "network", "cloud"],
}

# Intent → recommended agent roles
INTENT_ROLE_MAP: dict[TaskIntent, list[str]] = {
    TaskIntent.RECON: ["recon", "osint"],
    TaskIntent.SUBDOMAIN_ENUM: ["recon"],
    TaskIntent.PORT_SCAN: ["scanner", "recon"],
    TaskIntent.WEB_VULN_SCAN: ["web", "scanner", "validator"],
    TaskIntent.API_SECURITY: ["web", "code_auditor"],
    TaskIntent.CODE_AUDIT: ["code_auditor", "validator"],
    TaskIntent.NETWORK_PENTEST: ["network", "scanner", "exploiter"],
    TaskIntent.CLOUD_AUDIT: ["cloud", "validator"],
    TaskIntent.MOBILE_PENTEST: ["web", "code_auditor"],
    TaskIntent.WIRELESS_PENTEST: ["network", "scanner"],
    TaskIntent.SOCIAL_ENGINEERING: ["osint", "analyst"],
    TaskIntent.PHISHING: ["osint", "web"],
    TaskIntent.OSINT: ["osint", "analyst"],
    TaskIntent.CRYPTANALYSIS: ["analyst", "code_auditor"],
    TaskIntent.FORENSICS: ["forensics", "analyst"],
    TaskIntent.INCIDENT_RESPONSE: ["forensics", "analyst", "validator"],
    TaskIntent.MALWARE_ANALYSIS: ["forensics", "code_auditor"],
    TaskIntent.EXPLOIT_DEV: ["exploiter", "code_auditor"],
    TaskIntent.PRIVESC: ["exploiter", "scanner"],
    TaskIntent.LATERAL_MOVEMENT: ["network", "exploiter"],
    TaskIntent.CONTAINER_SECURITY: ["cloud", "scanner"],
    TaskIntent.IOT_SECURITY: ["scanner", "network", "code_auditor"],
    TaskIntent.SUPPLY_CHAIN: ["code_auditor", "validator"],
    TaskIntent.COMPLIANCE: ["validator", "analyst", "reporter"],
    TaskIntent.THREAT_HUNT: ["analyst", "forensics"],
    TaskIntent.RED_TEAM: ["coordinator", "recon", "web", "network", "exploiter"],
    TaskIntent.BLUE_TEAM: ["analyst", "forensics", "validator"],
    TaskIntent.BUG_BOUNTY: ["web", "scanner", "validator", "recon"],
    TaskIntent.FULL_PENTEST: ["coordinator", "recon", "scanner", "web", "network", "exploiter", "validator", "reporter"],
    TaskIntent.GENERAL_SECURITY: ["coordinator", "analyst"],
}

# Intent → preferred model type
INTENT_MODEL_MAP: dict[TaskIntent, str] = {
    TaskIntent.RECON: "general",
    TaskIntent.SUBDOMAIN_ENUM: "general",
    TaskIntent.PORT_SCAN: "general",
    TaskIntent.WEB_VULN_SCAN: "security",
    TaskIntent.API_SECURITY: "code",
    TaskIntent.CODE_AUDIT: "code",
    TaskIntent.NETWORK_PENTEST: "security",
    TaskIntent.CLOUD_AUDIT: "code",
    TaskIntent.MOBILE_PENTEST: "code",
    TaskIntent.WIRELESS_PENTEST: "security",
    TaskIntent.SOCIAL_ENGINEERING: "general",
    TaskIntent.PHISHING: "general",
    TaskIntent.OSINT: "general",
    TaskIntent.CRYPTANALYSIS: "reasoning",
    TaskIntent.FORENSICS: "reasoning",
    TaskIntent.INCIDENT_RESPONSE: "reasoning",
    TaskIntent.MALWARE_ANALYSIS: "reasoning",
    TaskIntent.EXPLOIT_DEV: "security",
    TaskIntent.PRIVESC: "security",
    TaskIntent.LATERAL_MOVEMENT: "security",
    TaskIntent.CONTAINER_SECURITY: "code",
    TaskIntent.IOT_SECURITY: "security",
    TaskIntent.SUPPLY_CHAIN: "code",
    TaskIntent.COMPLIANCE: "general",
    TaskIntent.THREAT_HUNT: "reasoning",
    TaskIntent.RED_TEAM: "security",
    TaskIntent.BLUE_TEAM: "reasoning",
    TaskIntent.BUG_BOUNTY: "security",
    TaskIntent.FULL_PENTEST: "security",
    TaskIntent.GENERAL_SECURITY: "general",
}

# Entity extraction patterns
ENTITY_PATTERNS: dict[str, str] = {
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "cidr": r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s]+",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "cve": r"CVE-\d{4}-\d{4,}",
    "port": r"\bport\s+(\d{1,5})\b",
    "file_path": r"(?:/[\w.-]+)+",
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
}


class IntentClassifier:
    """Multi-signal intent classification engine."""

    def __init__(self) -> None:
        self._log = logger.bind(component="intent_classifier")
        self._history: list[ClassificationResult] = []

    def classify(self, user_input: str) -> ClassificationResult:
        """Classify user input into actionable intents."""
        normalized = user_input.lower().strip()
        signals: list[IntentSignal] = []

        # Signal 1: Keyword matching
        for keyword, intents in KEYWORD_SIGNALS.items():
            if keyword in normalized:
                for intent, weight in intents:
                    signals.append(IntentSignal(
                        signal_type="keyword",
                        intent=intent,
                        confidence=weight,
                        source=keyword,
                    ))

        # Signal 2: Entity extraction
        entities: dict[str, list[str]] = {}
        for entity_type, pattern in ENTITY_PATTERNS.items():
            matches = re.findall(pattern, user_input)
            if matches:
                entities[entity_type] = matches
                # Boost intents based on entity types
                if entity_type in ("ip_address", "cidr"):
                    signals.append(IntentSignal(
                        signal_type="entity",
                        intent=TaskIntent.PORT_SCAN,
                        confidence=0.4,
                        source=f"found {entity_type}",
                    ))
                    signals.append(IntentSignal(
                        signal_type="entity",
                        intent=TaskIntent.NETWORK_PENTEST,
                        confidence=0.3,
                        source=f"found {entity_type}",
                    ))
                elif entity_type == "domain":
                    signals.append(IntentSignal(
                        signal_type="entity",
                        intent=TaskIntent.RECON,
                        confidence=0.4,
                        source="found domain",
                    ))
                    signals.append(IntentSignal(
                        signal_type="entity",
                        intent=TaskIntent.WEB_VULN_SCAN,
                        confidence=0.3,
                        source="found domain",
                    ))
                elif entity_type == "url":
                    signals.append(IntentSignal(
                        signal_type="entity",
                        intent=TaskIntent.WEB_VULN_SCAN,
                        confidence=0.5,
                        source="found URL",
                    ))
                elif entity_type == "cve":
                    signals.append(IntentSignal(
                        signal_type="entity",
                        intent=TaskIntent.EXPLOIT_DEV,
                        confidence=0.5,
                        source="found CVE",
                    ))

        # Signal 3: Context from history
        if self._history:
            last = self._history[-1]
            # Boost related intents
            related = self._get_related_intents(last.primary_intent)
            for intent in related:
                signals.append(IntentSignal(
                    signal_type="context",
                    intent=intent,
                    confidence=0.2,
                    source=f"follows {last.primary_intent.value}",
                ))

        # Aggregate signals per intent
        intent_scores: dict[TaskIntent, float] = {}
        for signal in signals:
            current = intent_scores.get(signal.intent, 0.0)
            intent_scores[signal.intent] = current + signal.confidence

        # Default fallback
        if not intent_scores:
            intent_scores[TaskIntent.GENERAL_SECURITY] = 0.3

        # Sort by score
        sorted_intents = sorted(
            intent_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        primary = sorted_intents[0]
        # Normalize confidence to [0, 1]
        max_possible = max(primary[1], 1.0)
        normalized_conf = min(primary[1] / max_possible, 1.0)

        result = ClassificationResult(
            primary_intent=primary[0],
            confidence=normalized_conf,
            secondary_intents=sorted_intents[1:5],
            signals=signals,
            extracted_entities=entities,
            recommended_kbs=INTENT_KB_MAP.get(primary[0], []),
            recommended_roles=INTENT_ROLE_MAP.get(primary[0], []),
            recommended_model=INTENT_MODEL_MAP.get(primary[0], "general"),
            recommended_phases=self._get_phases(primary[0]),
        )

        self._history.append(result)
        if len(self._history) > 50:
            self._history = self._history[-25:]

        return result

    def _get_related_intents(
        self, intent: TaskIntent,
    ) -> list[TaskIntent]:
        """Get intents that commonly follow a given intent."""
        follow_map: dict[TaskIntent, list[TaskIntent]] = {
            TaskIntent.RECON: [TaskIntent.PORT_SCAN, TaskIntent.SUBDOMAIN_ENUM],
            TaskIntent.SUBDOMAIN_ENUM: [TaskIntent.PORT_SCAN, TaskIntent.WEB_VULN_SCAN],
            TaskIntent.PORT_SCAN: [TaskIntent.WEB_VULN_SCAN, TaskIntent.NETWORK_PENTEST],
            TaskIntent.WEB_VULN_SCAN: [TaskIntent.EXPLOIT_DEV, TaskIntent.BUG_BOUNTY],
            TaskIntent.NETWORK_PENTEST: [TaskIntent.PRIVESC, TaskIntent.LATERAL_MOVEMENT],
            TaskIntent.PRIVESC: [TaskIntent.LATERAL_MOVEMENT],
            TaskIntent.LATERAL_MOVEMENT: [TaskIntent.PRIVESC],
            TaskIntent.FORENSICS: [TaskIntent.INCIDENT_RESPONSE, TaskIntent.MALWARE_ANALYSIS],
        }
        return follow_map.get(intent, [])

    def _get_phases(self, intent: TaskIntent) -> list[str]:
        """Get recommended execution phases for an intent."""
        phase_map: dict[TaskIntent, list[str]] = {
            TaskIntent.RECON: ["recon", "analysis", "reporting"],
            TaskIntent.SUBDOMAIN_ENUM: ["recon", "validation"],
            TaskIntent.PORT_SCAN: ["scanning", "analysis"],
            TaskIntent.WEB_VULN_SCAN: ["scanning", "validation", "analysis", "reporting"],
            TaskIntent.API_SECURITY: ["recon", "scanning", "validation", "reporting"],
            TaskIntent.CODE_AUDIT: ["analysis", "validation", "reporting"],
            TaskIntent.NETWORK_PENTEST: ["recon", "scanning", "exploitation", "post_exploit", "reporting"],
            TaskIntent.CLOUD_AUDIT: ["recon", "scanning", "analysis", "reporting"],
            TaskIntent.FULL_PENTEST: [
                "recon", "scanning", "enumeration", "exploitation",
                "post_exploit", "lateral_movement", "reporting",
            ],
            TaskIntent.RED_TEAM: [
                "recon", "initial_access", "execution", "persistence",
                "privesc", "lateral_movement", "exfiltration", "reporting",
            ],
            TaskIntent.BUG_BOUNTY: ["recon", "scanning", "validation", "reporting"],
            TaskIntent.INCIDENT_RESPONSE: [
                "detection", "containment", "evidence",
                "eradication", "recovery", "post_incident",
            ],
            TaskIntent.FORENSICS: ["acquisition", "analysis", "reporting"],
        }
        return phase_map.get(intent, ["analysis", "reporting"])

    def get_stats(self) -> dict[str, Any]:
        """Get classifier statistics."""
        intent_freq: dict[str, int] = {}
        for result in self._history:
            key = result.primary_intent.value
            intent_freq[key] = intent_freq.get(key, 0) + 1
        return {
            "classifications": len(self._history),
            "intent_frequency": intent_freq,
        }
