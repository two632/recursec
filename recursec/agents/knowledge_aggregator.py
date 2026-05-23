"""Knowledge aggregator — unified KB access for agent prompts.

Implements:
1. Registry of all knowledge bases
2. Dynamic KB selection based on target/context
3. Combined prompt construction from multiple KBs
4. Knowledge relevance scoring
5. Token-aware KB truncation
6. Knowledge base statistics
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class KBReference:
    """Reference to a registered knowledge base."""
    kb_id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    relevance_tags: list[str] = field(default_factory=list)
    pattern_count: int = 0
    priority: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.kb_id,
            "name": self.name[:20],
            "category": self.category[:12],
            "patterns": self.pattern_count,
            "priority": self.priority,
        }


@dataclass
class KnowledgeQuery:
    """A query for relevant knowledge."""
    target_type: str = ""
    technologies: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    vuln_categories: list[str] = field(default_factory=list)
    assessment_phase: str = ""
    max_kbs: int = 5
    max_tokens: int = 4000

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_type[:10],
            "tech": self.technologies[:3],
            "phase": self.assessment_phase[:12],
            "max_kbs": self.max_kbs,
        }


# ── Knowledge base registry ──────────────────────────────────

KB_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "web_vuln", "name": "Web Vulnerabilities",
        "category": "web",
        "desc": "SQLi, XSS, SSRF, SSTI, business logic testing",
        "tags": ["web", "injection", "xss", "sqli", "ssrf", "ssti", "http", "html", "javascript"],
        "patterns": 5, "priority": 8,
    },
    {
        "id": "api_security", "name": "API Security",
        "category": "api",
        "desc": "REST, GraphQL, gRPC, WebSocket testing",
        "tags": ["api", "rest", "graphql", "grpc", "websocket", "jwt", "oauth", "json"],
        "patterns": 4, "priority": 7,
    },
    {
        "id": "network_security", "name": "Network Security",
        "category": "network",
        "desc": "Recon, exploitation, pivoting, protocol attacks, lateral movement",
        "tags": ["network", "tcp", "udp", "smb", "ssh", "rdp", "dns", "nmap", "pivot"],
        "patterns": 5, "priority": 8,
    },
    {
        "id": "cloud_security", "name": "Cloud Security",
        "category": "cloud",
        "desc": "AWS, Azure, GCP, Kubernetes, serverless testing",
        "tags": ["cloud", "aws", "azure", "gcp", "kubernetes", "k8s", "docker", "serverless"],
        "patterns": 5, "priority": 7,
    },
    {
        "id": "container_security", "name": "Container Security",
        "category": "container",
        "desc": "Docker, runtime, escape, supply chain testing",
        "tags": ["container", "docker", "kubernetes", "k8s", "escape", "runtime", "registry"],
        "patterns": 4, "priority": 6,
    },
    {
        "id": "wireless_security", "name": "Wireless Security",
        "category": "wireless",
        "desc": "WiFi, Bluetooth, RFID, SDR testing",
        "tags": ["wireless", "wifi", "bluetooth", "ble", "rfid", "nfc", "sdr", "wpa"],
        "patterns": 4, "priority": 5,
    },
    {
        "id": "iot_security", "name": "IoT Security",
        "category": "iot",
        "desc": "Smart home, ICS/SCADA, automotive, medical device testing",
        "tags": ["iot", "scada", "modbus", "mqtt", "coap", "zigbee", "can", "medical"],
        "patterns": 5, "priority": 5,
    },
    {
        "id": "web3_security", "name": "Web3/Blockchain Security",
        "category": "web3",
        "desc": "Smart contracts, DeFi, bridges, NFT testing",
        "tags": ["web3", "blockchain", "solidity", "ethereum", "defi", "nft", "smart_contract"],
        "patterns": 4, "priority": 5,
    },
    {
        "id": "privesc", "name": "Privilege Escalation",
        "category": "privesc",
        "desc": "Linux, Windows, database, application privilege escalation",
        "tags": ["privesc", "linux", "windows", "suid", "sudo", "kernel", "registry", "uac"],
        "patterns": 4, "priority": 7,
    },
    {
        "id": "active_directory", "name": "Active Directory",
        "category": "ad",
        "desc": "AD enumeration, Kerberos attacks, domain persistence",
        "tags": ["ad", "active_directory", "kerberos", "ldap", "ntlm", "domain", "gpo"],
        "patterns": 5, "priority": 7,
    },
    {
        "id": "social_engineering", "name": "Social Engineering",
        "category": "se",
        "desc": "Phishing, OSINT, pretexting, physical security",
        "tags": ["social_engineering", "phishing", "osint", "pretexting", "vishing"],
        "patterns": 4, "priority": 4,
    },
    {
        "id": "secrets_detection", "name": "Secrets Detection",
        "category": "secrets",
        "desc": "API keys, credentials, tokens in source code",
        "tags": ["secrets", "api_key", "credentials", "tokens", "password", "leak"],
        "patterns": 25, "priority": 6,
    },
    {
        "id": "advanced_strategy", "name": "Advanced Strategies",
        "category": "strategy",
        "desc": "Emergent complexity, timing, AI-specific, supply chain attacks",
        "tags": ["advanced", "strategy", "timing", "ai", "supply_chain", "race_condition"],
        "patterns": 10, "priority": 6,
    },
    {
        "id": "mobile_security", "name": "Mobile Security",
        "category": "mobile",
        "desc": "Android, iOS application security testing",
        "tags": ["mobile", "android", "ios", "apk", "ipa", "smali", "frida"],
        "patterns": 4, "priority": 5,
    },
    {
        "id": "red_team_tactics", "name": "Red Team Tactics",
        "category": "red_team",
        "desc": "C2, evasion, persistence, MITRE ATT&CK techniques",
        "tags": ["red_team", "c2", "evasion", "persistence", "mitre", "attck"],
        "patterns": 6, "priority": 6,
    },
]


class KnowledgeAggregator:
    """Aggregates knowledge from multiple knowledge bases.

    Selects and combines relevant knowledge for agent
    prompts based on target, context, and assessment phase.
    """

    def __init__(self) -> None:
        self._registry: dict[str, KBReference] = {}
        self._log = logger.bind(component="knowledge_aggregator")
        self._query_count = 0
        self._load_registry()

    def _load_registry(self) -> None:
        """Load the KB registry."""
        for entry in KB_REGISTRY:
            ref = KBReference(
                kb_id=entry["id"],
                name=entry["name"],
                category=entry.get("category", ""),
                description=entry.get("desc", ""),
                relevance_tags=entry.get("tags", []),
                pattern_count=entry.get("patterns", 0),
                priority=entry.get("priority", 5),
            )
            self._registry[ref.kb_id] = ref

    def select_knowledge(
        self,
        query: KnowledgeQuery,
    ) -> list[KBReference]:
        """Select relevant knowledge bases for a query."""
        self._query_count += 1
        scored: list[tuple[float, KBReference]] = []

        for ref in self._registry.values():
            score = self._score_relevance(ref, query)
            if score > 0:
                scored.append((score, ref))

        scored.sort(key=lambda x: (-x[0], -x[1].priority))
        return [ref for _, ref in scored[:query.max_kbs]]

    def _score_relevance(
        self,
        ref: KBReference,
        query: KnowledgeQuery,
    ) -> float:
        """Score how relevant a KB is to a query."""
        score = 0.0

        # Target type match
        target_category_map: dict[str, list[str]] = {
            "web": ["web", "api", "secrets", "strategy"],
            "network": ["network", "privesc", "ad", "strategy"],
            "api": ["api", "web", "secrets"],
            "cloud": ["cloud", "container", "secrets"],
            "code": ["secrets", "web", "strategy"],
            "iot": ["iot", "wireless", "network"],
            "mobile": ["mobile", "api", "secrets"],
            "ad": ["ad", "network", "privesc"],
        }

        relevant_cats = target_category_map.get(query.target_type, [])
        if ref.category in relevant_cats:
            score += 2.0

        # Technology tag overlap
        query_tags = set()
        for tech in query.technologies:
            query_tags.add(tech.lower())
        for proto in query.protocols:
            query_tags.add(proto.lower())
        for cat in query.vuln_categories:
            query_tags.add(cat.lower())

        tag_overlap = len(query_tags & set(ref.relevance_tags))
        score += tag_overlap * 0.5

        # Phase relevance
        phase_kb_map: dict[str, list[str]] = {
            "reconnaissance": ["network_security", "api_security", "active_directory"],
            "scanning": ["web_vuln", "api_security", "secrets_detection", "advanced_strategy"],
            "exploitation": ["web_vuln", "privesc", "network_security", "advanced_strategy"],
            "validation": [],
            "post_exploitation": ["privesc", "active_directory", "network_security"],
        }
        phase_kbs = phase_kb_map.get(query.assessment_phase, [])
        if ref.kb_id in phase_kbs:
            score += 1.5

        # Base priority
        score += ref.priority * 0.1

        return score

    def build_aggregated_prompt(
        self,
        query: KnowledgeQuery,
        kb_prompts: dict[str, str] | None = None,
    ) -> str:
        """Build an aggregated knowledge prompt."""
        selected = self.select_knowledge(query)
        if not selected:
            return ""

        lines = ["## Injected Security Knowledge\n"]
        total_chars = 0
        max_chars = query.max_tokens * 4  # rough char estimate

        for ref in selected:
            if total_chars >= max_chars:
                break

            # Use provided prompt or generate reference
            if kb_prompts and ref.kb_id in kb_prompts:
                prompt = kb_prompts[ref.kb_id]
            else:
                prompt = f"### {ref.name}\n{ref.description}\nPatterns: {ref.pattern_count}\n"

            # Truncate if needed
            remaining = max_chars - total_chars
            if len(prompt) > remaining:
                prompt = prompt[:remaining] + "\n[... truncated]"

            lines.append(prompt)
            total_chars += len(prompt)

        return "\n".join(lines)

    def get_all_kbs(self) -> list[KBReference]:
        """Get all registered knowledge bases."""
        return sorted(
            self._registry.values(),
            key=lambda r: r.priority,
            reverse=True,
        )

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        total_patterns = 0
        for ref in self._registry.values():
            cat_counts[ref.category] += 1
            total_patterns += ref.pattern_count

        return {
            "knowledge_bases": len(self._registry),
            "total_patterns": total_patterns,
            "queries": self._query_count,
            "by_category": dict(cat_counts),
        }
