"""Knowledge injector — dynamically loads and injects KB context into prompts.

This is the bridge between the KB registry (46+ domains) and the prompt
assembly pipeline. For each agent task, it:
1. Determines which KB domains are relevant based on task/role/intent
2. Loads the KB build functions dynamically
3. Assembles focused knowledge context within token budget
4. Prioritizes most relevant patterns for the specific task
5. Handles KB dependencies (e.g., web_vuln depends on xss, ssrf)
6. Caches loaded KBs for reuse across agents
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import structlog

from recursec.agents.kb_registry import KB_REGISTRY, KBEntry, get_kbs_for_tags

logger = structlog.get_logger()


@dataclass
class InjectedKnowledge:
    """Knowledge ready for prompt injection."""
    domain: str = ""
    content: str = ""
    token_estimate: int = 0
    pattern_count: int = 0
    priority: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "tokens": f"~{self.token_estimate}",
            "patterns": self.pattern_count,
            "priority": self.priority,
        }


@dataclass
class InjectionResult:
    """Result of a knowledge injection operation."""
    total_tokens: int = 0
    domains_loaded: list[str] = field(default_factory=list)
    domains_skipped: list[str] = field(default_factory=list)
    combined_text: str = ""
    injection_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": f"~{self.total_tokens}",
            "loaded": len(self.domains_loaded),
            "skipped": len(self.domains_skipped),
            "time_ms": f"{self.injection_time_ms:.0f}",
        }


# Task type → relevant KB domains mapping
TASK_KB_MAPPING: dict[str, list[str]] = {
    "web_scan": ["web_vuln", "xss", "ssrf", "api_gateway", "business_logic", "web_cache", "deserialization"],
    "network_scan": ["network", "dns", "lateral_movement"],
    "code_review": ["web_vuln", "deserialization", "supply_chain", "devsecops"],
    "cloud_audit": ["cloud", "container_k8s", "serverless", "zero_trust"],
    "mobile_test": ["mobile", "api_gateway"],
    "pentest": ["red_team", "privesc", "lateral_movement", "evasion", "active_directory"],
    "recon": ["network", "dns", "social_engineering", "threat_intel"],
    "exploit": ["binary_exploitation", "web_vuln", "privesc", "advanced_discovery"],
    "iot_test": ["iot_ics", "firmware", "scada", "wireless"],
    "forensics": ["forensics", "incident_response", "threat_intel"],
    "full_assessment": ["web_vuln", "network", "cloud", "red_team", "advanced_discovery", "advanced_strategy"],
    "wireless_test": ["wireless", "rf", "network"],
    "automotive_test": ["automotive", "hardware", "rf"],
    "satellite_test": ["satellite", "rf", "wireless"],
    "crypto_audit": ["crypto", "quantum"],
    "scada_test": ["scada", "iot_ics", "network"],
}

# Role → default KB domains
ROLE_KB_MAPPING: dict[str, list[str]] = {
    "coordinator": ["advanced_discovery", "advanced_strategy", "red_team"],
    "recon": ["network", "dns", "social_engineering"],
    "scanner": ["web_vuln", "network", "cloud"],
    "exploit": ["binary_exploitation", "web_vuln", "privesc", "advanced_discovery"],
    "code_audit": ["web_vuln", "deserialization", "supply_chain"],
    "web": ["web_vuln", "xss", "ssrf", "api_gateway", "business_logic"],
    "network": ["network", "dns", "lateral_movement"],
    "osint": ["social_engineering", "threat_intel"],
    "cloud": ["cloud", "container_k8s", "serverless"],
    "mobile": ["mobile", "api_gateway"],
    "forensics": ["forensics", "incident_response"],
    "validator": ["web_vuln"],
    "planner": ["advanced_discovery", "advanced_strategy", "red_team"],
    "researcher": ["ai_ml_security", "quantum", "automotive", "satellite"],
}


class KnowledgeInjector:
    """Dynamically loads and injects KB context into agent prompts."""

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}  # domain → built prompt text
        self._build_funcs: dict[str, Callable[..., str]] = {}
        self._load_count = 0
        self._cache_hits = 0
        self._log = logger.bind(component="knowledge_injector")

    def inject_for_task(
        self,
        task_type: str,
        max_tokens: int = 3000,
        focus: str | None = None,
    ) -> InjectionResult:
        """Inject knowledge for a specific task type."""
        domains = TASK_KB_MAPPING.get(task_type, ["web_vuln", "network"])
        return self._inject_domains(domains, max_tokens, focus)

    def inject_for_role(
        self,
        role: str,
        max_tokens: int = 3000,
        focus: str | None = None,
    ) -> InjectionResult:
        """Inject knowledge for a specific agent role."""
        domains = ROLE_KB_MAPPING.get(role, ["web_vuln"])
        return self._inject_domains(domains, max_tokens, focus)

    def inject_for_tags(
        self,
        tags: list[str],
        max_tokens: int = 3000,
    ) -> InjectionResult:
        """Inject knowledge based on tag search."""
        entries = get_kbs_for_tags(tags)
        domains = [e.domain for e in entries]
        return self._inject_domains(domains, max_tokens)

    def inject_specific(
        self,
        domains: list[str],
        max_tokens: int = 3000,
        focus: str | None = None,
    ) -> InjectionResult:
        """Inject specific KB domains."""
        return self._inject_domains(domains, max_tokens, focus)

    def _inject_domains(
        self,
        domains: list[str],
        max_tokens: int,
        focus: str | None = None,
    ) -> InjectionResult:
        """Load and combine KB content for specified domains."""
        start = time.time()
        result = InjectionResult()

        # Sort by priority
        domain_entries: list[tuple[str, KBEntry]] = []
        for d in domains:
            entry = KB_REGISTRY.get(d)
            if entry:
                domain_entries.append((d, entry))
        domain_entries.sort(key=lambda x: x[1].priority, reverse=True)

        # Load each domain within budget
        budget_per_domain = max_tokens // max(len(domain_entries), 1)
        parts: list[str] = []
        total_tokens = 0

        for domain, entry in domain_entries:
            if total_tokens >= max_tokens:
                result.domains_skipped.append(domain)
                continue

            content = self._load_domain(domain, entry, focus)
            if not content:
                result.domains_skipped.append(domain)
                continue

            # Truncate to budget
            chars_budget = budget_per_domain * 4
            if len(content) > chars_budget:
                content = content[:chars_budget] + "\n[...more patterns available]"

            token_est = len(content) // 4
            if total_tokens + token_est > max_tokens:
                # Trim to fit
                remaining = max_tokens - total_tokens
                content = content[:remaining * 4]
                token_est = remaining

            parts.append(content)
            total_tokens += token_est
            result.domains_loaded.append(domain)

        result.combined_text = "\n\n".join(parts)
        result.total_tokens = total_tokens
        result.injection_time_ms = (time.time() - start) * 1000
        return result

    def _load_domain(self, domain: str, entry: KBEntry, focus: str | None = None) -> str:
        """Load a single KB domain's content."""
        # Check cache
        cache_key = f"{domain}:{focus or 'all'}"
        if cache_key in self._cache:
            self._cache_hits += 1
            return self._cache[cache_key]

        # Try to load build function
        build_func = self._get_build_func(entry)
        if not build_func:
            return ""

        try:
            if focus:
                content = build_func(focus_type=focus, max_patterns=3)
            else:
                content = build_func(max_patterns=5)
        except TypeError:
            try:
                content = build_func()
            except Exception:
                return ""
        except Exception:
            return ""

        self._cache[cache_key] = content
        self._load_count += 1
        return content

    def _get_build_func(self, entry: KBEntry) -> Callable[..., str] | None:
        """Dynamically load the build function for a KB."""
        if entry.domain in self._build_funcs:
            return self._build_funcs[entry.domain]

        try:
            module = importlib.import_module(entry.module_path)
            func = getattr(module, entry.build_func_name, None)
            if func:
                self._build_funcs[entry.domain] = func
                return func
        except (ImportError, AttributeError):
            pass
        return None

    def clear_cache(self) -> None:
        """Clear the KB content cache."""
        self._cache.clear()

    def get_stats(self) -> dict[str, Any]:
        return {
            "registered_kbs": len(KB_REGISTRY),
            "loaded_funcs": len(self._build_funcs),
            "cache_size": len(self._cache),
            "load_count": self._load_count,
            "cache_hits": self._cache_hits,
            "available_task_types": list(TASK_KB_MAPPING.keys()),
        }
