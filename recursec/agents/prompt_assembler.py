"""Prompt assembler — builds optimal LLM prompts from all KBs.

This is the critical integration layer that takes:
1. Task intent
2. Current phase
3. Target info
4. Memory/findings
5. Available KB patterns
...and assembles the OPTIMAL prompt for the LLM.

The agent's intelligence comes from what knowledge
gets injected into the LLM's context window.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


# All KB domains with their module references
KB_REGISTRY: dict[str, dict[str, Any]] = {
    # Web vulnerabilities
    "web_vuln": {
        "module": "advanced_strategy_kb",
        "builder": "build_strategy_prompt",
        "tags": ["web", "owasp", "injection", "auth"],
    },
    "xss": {
        "module": "xss_deep_kb",
        "builder": "build_xss_prompt",
        "tags": ["web", "xss", "scripting", "client"],
    },
    "ssrf": {
        "module": "ssrf_deep_kb",
        "builder": "build_ssrf_prompt",
        "tags": ["web", "ssrf", "server", "metadata"],
    },
    "sqli": {
        "module": "sqli_kb",
        "builder": "build_sqli_prompt",
        "tags": ["web", "sql", "injection", "database"],
    },
    "deserialization": {
        "module": "deserialization_kb",
        "builder": "build_deser_prompt",
        "tags": ["web", "rce", "deserialization"],
    },
    "api_gateway": {
        "module": "api_gateway_kb",
        "builder": "build_apigateway_prompt",
        "tags": ["web", "api", "rest", "graphql"],
    },
    "web_cache": {
        "module": "web_cache_cdn_kb",
        "builder": "build_webcache_prompt",
        "tags": ["web", "cache", "cdn", "poisoning"],
    },
    # Network
    "network_attack": {
        "module": "network_attack_kb",
        "builder": "build_network_attack_prompt",
        "tags": ["network", "mitm", "dns", "arp"],
    },
    "active_directory": {
        "module": "active_directory_kb",
        "builder": "build_ad_prompt",
        "tags": ["network", "ad", "windows", "kerberos"],
    },
    # Identity
    "identity_sso": {
        "module": "identity_sso_kb",
        "builder": "build_identity_prompt",
        "tags": ["identity", "saml", "oauth", "sso"],
    },
    # Cloud
    "cloud_native": {
        "module": "cloud_native_kb",
        "builder": "build_cloud_native_prompt",
        "tags": ["cloud", "aws", "azure", "gcp"],
    },
    # DevSecOps
    "devsecops": {
        "module": "devsecops_kb",
        "builder": "build_devsecops_prompt",
        "tags": ["cicd", "pipeline", "iac", "supply_chain"],
    },
    # Exploitation
    "privesc": {
        "module": "privesc_deep_kb",
        "builder": "build_privesc_prompt",
        "tags": ["exploit", "privesc", "linux", "windows"],
    },
    "binary_exploit": {
        "module": "binary_exploit_kb",
        "builder": "build_binary_exploit_prompt",
        "tags": ["exploit", "binary", "rop", "heap"],
    },
    # Mobile
    "mobile_security": {
        "module": "mobile_security_kb",
        "builder": "build_mobile_prompt",
        "tags": ["mobile", "android", "ios", "app"],
    },
    # IoT/ICS
    "iot_ics": {
        "module": "iot_ics_kb",
        "builder": "build_iot_ics_prompt",
        "tags": ["iot", "ics", "scada", "firmware"],
    },
    # Blockchain
    "blockchain": {
        "module": "blockchain_kb",
        "builder": "build_blockchain_prompt",
        "tags": ["blockchain", "smart_contract", "defi"],
    },
    # Email/Social
    "email_phishing": {
        "module": "email_phishing_kb",
        "builder": "build_email_prompt",
        "tags": ["email", "phishing", "social"],
    },
    # Compliance
    "compliance": {
        "module": "compliance_deep_kb",
        "builder": "build_compliance_prompt",
        "tags": ["compliance", "pci", "hipaa", "nist"],
    },
    # Incident Response
    "incident_response": {
        "module": "incident_response_kb",
        "builder": "build_ir_prompt",
        "tags": ["incident", "forensics", "response"],
    },
}

# Phase → most relevant KB domains
PHASE_KB_RELEVANCE: dict[str, list[str]] = {
    "recon": ["network_attack", "active_directory", "cloud_native"],
    "enumeration": ["web_vuln", "api_gateway", "network_attack"],
    "scanning": [
        "web_vuln", "xss", "ssrf", "sqli", "deserialization",
        "api_gateway", "network_attack", "cloud_native",
    ],
    "analysis": [
        "web_vuln", "xss", "ssrf", "sqli", "privesc",
        "identity_sso", "compliance",
    ],
    "exploitation": [
        "privesc", "binary_exploit", "deserialization",
        "xss", "ssrf", "sqli", "active_directory",
    ],
    "post_exploit": [
        "privesc", "active_directory", "network_attack",
    ],
    "validation": ["web_vuln", "compliance"],
    "reporting": ["compliance", "incident_response"],
}

# Target type → most relevant KB domains
TARGET_KB_RELEVANCE: dict[str, list[str]] = {
    "web": ["web_vuln", "xss", "ssrf", "sqli", "deserialization", "api_gateway", "web_cache"],
    "api": ["api_gateway", "web_vuln", "sqli", "identity_sso"],
    "network": ["network_attack", "active_directory", "privesc"],
    "cloud": ["cloud_native", "devsecops", "identity_sso"],
    "mobile": ["mobile_security", "api_gateway"],
    "iot": ["iot_ics"],
    "blockchain": ["blockchain"],
    "ad": ["active_directory", "identity_sso", "privesc"],
}


@dataclass
class PromptSection:
    """A section of the assembled prompt."""
    name: str = ""
    content: str = ""
    token_count: int = 0
    priority: int = 5
    source_kb: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "tokens": self.token_count,
            "pri": self.priority,
        }


@dataclass
class AssembledPrompt:
    """A fully assembled prompt."""
    sections: list[PromptSection] = field(default_factory=list)
    total_tokens: int = 0
    max_tokens: int = 4096
    kb_domains_used: list[str] = field(default_factory=list)
    assembled_at: float = field(default_factory=time.time)

    @property
    def text(self) -> str:
        return "\n\n".join(s.content for s in self.sections if s.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sections": len(self.sections),
            "tokens": self.total_tokens,
            "kbs": len(self.kb_domains_used),
        }


class PromptAssembler:
    """Assemble optimal prompts from all knowledge.

    Selects the right KB domains, compresses
    them to fit the token budget, and produces
    the best possible prompt for the LLM.
    """

    def __init__(self, default_max_tokens: int = 4096) -> None:
        self._default_max = default_max_tokens
        self._assemblies = 0
        self._log = logger.bind(component="assembler")

    def select_kb_domains(
        self,
        intent: str = "",
        phase: str = "",
        target_type: str = "",
        explicit_domains: list[str] | None = None,
    ) -> list[str]:
        """Select relevant KB domains for the task."""
        domains: list[str] = []

        # Explicit domains first
        if explicit_domains:
            domains.extend(explicit_domains)

        # Phase-relevant domains
        if phase:
            phase_domains = PHASE_KB_RELEVANCE.get(phase, [])
            for d in phase_domains:
                if d not in domains:
                    domains.append(d)

        # Target-relevant domains
        if target_type:
            target_domains = TARGET_KB_RELEVANCE.get(target_type, [])
            for d in target_domains:
                if d not in domains:
                    domains.append(d)

        # If nothing selected, use general web+network
        if not domains:
            domains = ["web_vuln", "network_attack", "privesc"]

        return domains

    def assemble(
        self,
        system_prompt: str = "",
        task_description: str = "",
        target_info: str = "",
        memory_context: str = "",
        findings_context: str = "",
        reasoning_context: str = "",
        kb_domains: list[str] | None = None,
        phase: str = "",
        target_type: str = "",
        max_tokens: int = 0,
    ) -> AssembledPrompt:
        """Assemble a complete prompt."""
        self._assemblies += 1
        budget = max_tokens or self._default_max

        sections: list[PromptSection] = []

        # System prompt (highest priority)
        if system_prompt:
            sections.append(PromptSection(
                name="system",
                content=system_prompt,
                token_count=len(system_prompt) // 4,
                priority=10,
            ))

        # Task description
        if task_description:
            sections.append(PromptSection(
                name="task",
                content=f"## Task\n{task_description}",
                token_count=len(task_description) // 4,
                priority=9,
            ))

        # Target info
        if target_info:
            sections.append(PromptSection(
                name="target",
                content=f"## Target\n{target_info}",
                token_count=len(target_info) // 4,
                priority=8,
            ))

        # Findings context
        if findings_context:
            sections.append(PromptSection(
                name="findings",
                content=f"## Current Findings\n{findings_context}",
                token_count=len(findings_context) // 4,
                priority=7,
            ))

        # Reasoning context
        if reasoning_context:
            sections.append(PromptSection(
                name="reasoning",
                content=reasoning_context,
                token_count=len(reasoning_context) // 4,
                priority=6,
            ))

        # Memory context
        if memory_context:
            sections.append(PromptSection(
                name="memory",
                content=f"## Memory\n{memory_context}",
                token_count=len(memory_context) // 4,
                priority=5,
            ))

        # Knowledge base sections
        selected_domains = kb_domains or self.select_kb_domains(
            phase=phase, target_type=target_type,
        )
        domains_used: list[str] = []

        for domain in selected_domains:
            kb_info = KB_REGISTRY.get(domain)
            if not kb_info:
                continue

            # Generate placeholder KB content reference
            builder = kb_info.get("builder", "")
            kb_header = f"[KB: {domain} via {builder}]"

            sections.append(PromptSection(
                name=f"kb_{domain}",
                content=kb_header,
                token_count=50,
                priority=4,
                source_kb=domain,
            ))
            domains_used.append(domain)

        # Sort by priority (highest first)
        sections.sort(key=lambda s: s.priority, reverse=True)

        # Trim to budget
        total = 0
        kept: list[PromptSection] = []
        for section in sections:
            if total + section.token_count <= budget:
                kept.append(section)
                total += section.token_count
            elif section.priority >= 8:
                # High priority sections always included
                kept.append(section)
                total += section.token_count

        result = AssembledPrompt(
            sections=kept,
            total_tokens=total,
            max_tokens=budget,
            kb_domains_used=domains_used,
        )

        return result

    def get_all_kb_domains(self) -> list[str]:
        """Get all registered KB domains."""
        return list(KB_REGISTRY.keys())

    def get_kb_tags(self, domain: str) -> list[str]:
        """Get tags for a KB domain."""
        info = KB_REGISTRY.get(domain)
        return info.get("tags", []) if info else []

    def search_kb_by_tag(self, tag: str) -> list[str]:
        """Find KB domains by tag."""
        results: list[str] = []
        for domain, info in KB_REGISTRY.items():
            if tag.lower() in [t.lower() for t in info.get("tags", [])]:
                results.append(domain)
        return results

    def build_assembler_prompt(self) -> str:
        """Build assembler stats for LLM."""
        lines = ["## Prompt Assembly\n"]
        lines.append(f"KBs available: {len(KB_REGISTRY)}")
        lines.append(f"Assemblies: {self._assemblies}")
        lines.append(f"Domains: {', '.join(list(KB_REGISTRY.keys())[:8])}")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "kb_domains": len(KB_REGISTRY),
            "assemblies": self._assemblies,
        }
