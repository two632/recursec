"""Knowledge aggregator — unified query interface across all KBs.

Implements:
1. Registry of all knowledge bases
2. Unified query by domain, category, keyword
3. Cross-KB pattern correlation
4. Relevance-scored retrieval
5. Token-aware context assembly
6. Aggregator prompt for LLM
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class KBEntry:
    """A registered knowledge base."""
    kb_id: str = ""
    name: str = ""
    domain: str = ""
    pattern_count: int = 0
    categories: list[str] = field(default_factory=list)
    build_prompt_fn: str = ""    # Method name to call
    keywords: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.kb_id[:12],
            "name": self.name[:20],
            "domain": self.domain[:10],
            "patterns": self.pattern_count,
        }


@dataclass
class QueryResult:
    """Result from a knowledge query."""
    kb_id: str = ""
    domain: str = ""
    prompt_text: str = ""
    relevance: float = 0.0
    token_estimate: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "kb": self.kb_id[:12],
            "domain": self.domain[:10],
            "relevance": f"{self.relevance:.0%}",
            "tokens": self.token_estimate,
        }


# ── KB registry ──────────────────────────────────────────────

KB_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "web_security", "name": "Web Security KB",
        "domain": "web", "module": "web_vuln_kb",
        "prompt_fn": "build_web_prompt",
        "categories": ["xss", "sqli", "ssrf", "auth", "api"],
        "keywords": ["web", "http", "api", "xss", "sql", "injection", "cookie", "session", "csrf", "cors"],
    },
    {
        "id": "osint", "name": "OSINT KB",
        "domain": "recon", "module": "osint_kb",
        "prompt_fn": "build_osint_prompt",
        "categories": ["subdomain", "email", "social", "infrastructure", "darkweb"],
        "keywords": ["osint", "recon", "subdomain", "email", "social", "domain", "dns", "whois"],
    },
    {
        "id": "social_engineering", "name": "Social Engineering KB",
        "domain": "social", "module": "social_engineering_kb",
        "prompt_fn": "build_se_prompt",
        "categories": ["phishing", "pretexting", "physical", "vishing", "influence"],
        "keywords": ["phishing", "social", "pretexting", "vishing", "smishing", "spear"],
    },
    {
        "id": "ics_scada", "name": "ICS/SCADA KB",
        "domain": "ics", "module": "ics_scada_kb",
        "prompt_fn": "build_ics_prompt",
        "categories": ["protocols", "scada", "plc", "network_seg", "sis"],
        "keywords": ["ics", "scada", "plc", "modbus", "dnp3", "opc", "industrial", "hmi"],
    },
    {
        "id": "container_security", "name": "Container Security KB",
        "domain": "container", "module": "container_security_kb",
        "prompt_fn": "build_container_prompt",
        "categories": ["docker", "kubernetes", "images", "runtime", "mesh"],
        "keywords": ["docker", "kubernetes", "k8s", "container", "pod", "helm", "registry"],
    },
    {
        "id": "malware_analysis", "name": "Malware Analysis KB",
        "domain": "malware", "module": "malware_analysis_kb",
        "prompt_fn": "build_malware_prompt",
        "categories": ["static", "dynamic", "reverse", "classification", "anti_analysis"],
        "keywords": ["malware", "virus", "trojan", "ransomware", "pe", "elf", "sandbox", "yara"],
    },
    {
        "id": "ai_ml_security", "name": "AI/ML Security KB",
        "domain": "ai", "module": "ai_ml_security_kb",
        "prompt_fn": "build_aiml_prompt",
        "categories": ["llm", "adversarial", "model_stealing", "poisoning", "supply_chain"],
        "keywords": ["ai", "ml", "llm", "prompt", "adversarial", "model", "training", "inference"],
    },
    {
        "id": "forensics", "name": "Digital Forensics KB",
        "domain": "forensics", "module": "forensics_kb",
        "prompt_fn": "build_forensics_prompt",
        "categories": ["disk", "memory", "network", "logs", "anti_forensics"],
        "keywords": ["forensics", "memory", "disk", "timeline", "volatility", "autopsy", "evidence"],
    },
    {
        "id": "red_team", "name": "Red Team KB",
        "domain": "redteam", "module": "red_team_kb",
        "prompt_fn": "build_redteam_prompt",
        "categories": ["methodology", "initial_access", "lateral", "persistence", "c2"],
        "keywords": ["red", "team", "lateral", "persistence", "c2", "beacon", "implant"],
    },
    {
        "id": "threat_intel", "name": "Threat Intelligence KB",
        "domain": "intel", "module": "threat_intel_kb",
        "prompt_fn": "build_threat_intel_prompt",
        "categories": ["actors", "ioc", "feeds", "modeling", "hunting"],
        "keywords": ["threat", "intel", "apt", "ioc", "stix", "mitre", "hunt", "actor"],
    },
    {
        "id": "compliance", "name": "Compliance KB",
        "domain": "compliance", "module": "compliance_kb",
        "prompt_fn": "build_compliance_prompt",
        "categories": ["pci", "hipaa", "soc2", "iso27001", "nist"],
        "keywords": ["compliance", "pci", "hipaa", "soc2", "iso", "nist", "audit", "regulation"],
    },
    {
        "id": "cloud_security", "name": "Cloud Security KB",
        "domain": "cloud", "module": "cloud_security_kb",
        "prompt_fn": "build_cloud_prompt",
        "categories": ["aws", "azure", "gcp", "multi_cloud", "serverless"],
        "keywords": ["aws", "azure", "gcp", "cloud", "s3", "iam", "lambda", "serverless"],
    },
    {
        "id": "wireless", "name": "Wireless Security KB",
        "domain": "wireless", "module": "wireless_security_kb",
        "prompt_fn": "build_wireless_prompt",
        "categories": ["wifi", "bluetooth", "rfid", "wids", "rogue_ap"],
        "keywords": ["wifi", "wireless", "bluetooth", "rfid", "nfc", "wpa", "aircrack"],
    },
    {
        "id": "privesc", "name": "Privilege Escalation KB",
        "domain": "privesc", "module": "privilege_escalation_kb",
        "prompt_fn": "build_privesc_prompt",
        "categories": ["linux", "windows", "ad", "container", "cloud_privesc"],
        "keywords": ["privesc", "privilege", "escalation", "suid", "sudo", "token", "potato", "kerberos"],
    },
    {
        "id": "mobile", "name": "Mobile Security KB",
        "domain": "mobile", "module": "mobile_security_kb",
        "prompt_fn": "build_mobile_prompt",
        "categories": ["android", "ios", "api", "malware", "reverse"],
        "keywords": ["mobile", "android", "ios", "apk", "ipa", "frida", "adb", "objection"],
    },
    {
        "id": "active_directory", "name": "Active Directory KB",
        "domain": "ad", "module": "active_directory_kb",
        "prompt_fn": "build_ad_prompt",
        "categories": ["enumeration", "kerberos", "acl", "delegation", "trust"],
        "keywords": ["ad", "active", "directory", "kerberos", "ldap", "bloodhound", "domain"],
    },
    {
        "id": "advanced_strategy", "name": "Advanced Strategy KB",
        "domain": "strategy", "module": "advanced_strategy_kb",
        "prompt_fn": "build_strategy_prompt",
        "categories": ["timing", "race", "business_logic", "emergent", "supply_chain"],
        "keywords": ["strategy", "timing", "race", "logic", "emergent", "supply", "chain"],
    },
]


class KnowledgeAggregator:
    """Unified query interface across all knowledge bases.

    Provides relevance-scored retrieval and token-aware
    context assembly from all registered KBs.
    """

    def __init__(self, chars_per_token: float = 3.5) -> None:
        self._kbs: dict[str, KBEntry] = {}
        self._chars_per_token = chars_per_token
        self._query_count = 0
        self._log = logger.bind(component="kb_aggregator")
        self._load_registry()

    def _load_registry(self) -> None:
        """Load KB registry."""
        for spec in KB_REGISTRY:
            entry = KBEntry(
                kb_id=spec["id"],
                name=spec["name"],
                domain=spec["domain"],
                categories=spec.get("categories", []),
                build_prompt_fn=spec.get("prompt_fn", ""),
                keywords=spec.get("keywords", []),
            )
            self._kbs[entry.kb_id] = entry

    def query(
        self,
        keywords: list[str] | None = None,
        domains: list[str] | None = None,
        categories: list[str] | None = None,
        max_results: int = 5,
    ) -> list[QueryResult]:
        """Query across all KBs by relevance."""
        self._query_count += 1
        scored: list[tuple[float, KBEntry]] = []

        for entry in self._kbs.values():
            score = 0.0

            # Domain match
            if domains:
                if entry.domain in domains:
                    score += 1.0

            # Category match
            if categories:
                matches = set(entry.categories) & set(categories)
                score += len(matches) * 0.5

            # Keyword match
            if keywords:
                kw_lower = [k.lower() for k in keywords]
                for kw in kw_lower:
                    for entry_kw in entry.keywords:
                        if kw in entry_kw or entry_kw in kw:
                            score += 0.3

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: list[QueryResult] = []

        for score, entry in scored[:max_results]:
            results.append(QueryResult(
                kb_id=entry.kb_id,
                domain=entry.domain,
                prompt_text="",      # Actual text loaded lazily
                relevance=min(1.0, score / 2.0),
            ))

        return results

    def get_domains(self) -> list[str]:
        """Get all registered domains."""
        return list(set(e.domain for e in self._kbs.values()))

    def get_all_categories(self) -> dict[str, list[str]]:
        """Get all categories by domain."""
        result: dict[str, list[str]] = {}
        for entry in self._kbs.values():
            result.setdefault(entry.domain, []).extend(entry.categories)
        return result

    def build_aggregator_prompt(self, task_description: str = "") -> str:
        """Build aggregator context showing available knowledge."""
        lines = ["## Knowledge Base Registry\n"]
        lines.append(f"Total KBs: {len(self._kbs)} | Queries: {self._query_count}")
        lines.append("")

        for entry in self._kbs.values():
            cats = ", ".join(entry.categories[:3])
            lines.append(f"  [{entry.domain[:8]}] {entry.name[:20]} ({cats})")

        if task_description:
            # Suggest relevant KBs
            words = task_description.lower().split()
            relevant = self.query(keywords=words, max_results=3)
            if relevant:
                lines.append("\nSuggested for current task:")
                for r in relevant:
                    lines.append(f"  → {r.kb_id} (relevance: {r.relevance:.0%})")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        domains = self.get_domains()
        total_cats = sum(len(e.categories) for e in self._kbs.values())

        return {
            "total_kbs": len(self._kbs),
            "domains": len(domains),
            "total_categories": total_cats,
            "queries": self._query_count,
        }
