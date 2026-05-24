"""Knowledge base registry — master index of all KB domains.

Central registry mapping all 50+ KB domains to their
build_*_prompt() functions, metadata, and relationships.
Used by the prompt assembler to select and load relevant
knowledge for any task.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class KBEntry:
    """A registered knowledge base entry."""
    domain: str = ""
    module_path: str = ""
    build_func_name: str = ""
    description: str = ""
    pattern_count: int = 5
    related_domains: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    priority: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "patterns": self.pattern_count,
            "related": len(self.related_domains),
            "priority": self.priority,
        }


# Master registry of all knowledge bases
KB_REGISTRY: dict[str, KBEntry] = {
    "web_vuln": KBEntry(
        domain="web_vuln", module_path="recursec.agents.web_vuln_kb",
        build_func_name="build_web_vuln_prompt", description="Web application vulnerabilities (OWASP Top 10)",
        pattern_count=5, related_domains=["xss", "ssrf", "api_gateway", "deserialization", "business_logic"],
        tags=["web", "owasp", "injection", "auth"], priority=9,
    ),
    "xss": KBEntry(
        domain="xss", module_path="recursec.agents.xss_deep_kb",
        build_func_name="build_xss_deep_prompt", description="Cross-site scripting (reflected, stored, DOM, bypass)",
        pattern_count=5, related_domains=["web_vuln", "business_logic"],
        tags=["web", "xss", "injection", "browser"], priority=8,
    ),
    "ssrf": KBEntry(
        domain="ssrf", module_path="recursec.agents.ssrf_deep_kb",
        build_func_name="build_ssrf_deep_prompt", description="Server-side request forgery (cloud metadata, protocol smuggling)",
        pattern_count=5, related_domains=["web_vuln", "cloud"],
        tags=["web", "ssrf", "cloud", "metadata"], priority=8,
    ),
    "deserialization": KBEntry(
        domain="deserialization", module_path="recursec.agents.deserialization_kb",
        build_func_name="build_deserialization_prompt", description="Insecure deserialization (Java, PHP, Python, .NET, Ruby)",
        pattern_count=5, related_domains=["web_vuln", "code_audit"],
        tags=["web", "rce", "deserialization"], priority=8,
    ),
    "api_gateway": KBEntry(
        domain="api_gateway", module_path="recursec.agents.api_gateway_kb",
        build_func_name="build_api_gateway_prompt", description="API gateway security (REST, GraphQL, gRPC, WebSocket)",
        pattern_count=5, related_domains=["web_vuln", "business_logic"],
        tags=["api", "graphql", "auth", "rate_limit"], priority=8,
    ),
    "business_logic": KBEntry(
        domain="business_logic", module_path="recursec.agents.business_logic_kb",
        build_func_name="build_business_logic_prompt", description="Business logic flaws (auth, authz, payment, workflow, rate abuse)",
        pattern_count=5, related_domains=["web_vuln", "api_gateway"],
        tags=["logic", "auth", "payment", "workflow"], priority=9,
    ),
    "web_cache": KBEntry(
        domain="web_cache", module_path="recursec.agents.web_cache_kb",
        build_func_name="build_web_cache_prompt", description="Web cache poisoning, CDN bypass, ESI injection",
        pattern_count=5, related_domains=["web_vuln"],
        tags=["cache", "cdn", "smuggling"], priority=6,
    ),
    "network": KBEntry(
        domain="network", module_path="recursec.agents.network_attack_kb",
        build_func_name="build_network_attack_prompt", description="Network-level attacks (MITM, ARP, DNS, protocol)",
        pattern_count=5, related_domains=["lateral_movement", "wireless"],
        tags=["network", "mitm", "protocol"], priority=8,
    ),
    "lateral_movement": KBEntry(
        domain="lateral_movement", module_path="recursec.agents.lateral_movement_kb",
        build_func_name="build_lateral_movement_prompt", description="Post-compromise lateral movement (Windows, Linux, cloud, relay)",
        pattern_count=5, related_domains=["network", "active_directory", "privesc"],
        tags=["lateral", "pivoting", "relay", "post_exploit"], priority=8,
    ),
    "active_directory": KBEntry(
        domain="active_directory", module_path="recursec.agents.active_directory_kb",
        build_func_name="build_active_directory_prompt", description="Active Directory attacks (Kerberos, LDAP, GPO, trust)",
        pattern_count=5, related_domains=["lateral_movement", "privesc", "windows"],
        tags=["ad", "kerberos", "ldap", "windows"], priority=9,
    ),
    "privesc": KBEntry(
        domain="privesc", module_path="recursec.agents.privesc_kb",
        build_func_name="build_privesc_prompt", description="Privilege escalation (Linux, Windows, misconfigurations)",
        pattern_count=5, related_domains=["lateral_movement", "linux", "windows"],
        tags=["privesc", "suid", "sudo", "kernel"], priority=9,
    ),
    "cloud": KBEntry(
        domain="cloud", module_path="recursec.agents.cloud_security_kb",
        build_func_name="build_cloud_security_prompt", description="Cloud security (AWS, Azure, GCP, multi-cloud)",
        pattern_count=5, related_domains=["container_k8s", "serverless"],
        tags=["cloud", "aws", "azure", "gcp", "iam"], priority=8,
    ),
    "container_k8s": KBEntry(
        domain="container_k8s", module_path="recursec.agents.container_k8s_kb",
        build_func_name="build_container_k8s_prompt", description="Container/K8s security (escape, RBAC, network, secrets)",
        pattern_count=5, related_domains=["cloud", "supply_chain"],
        tags=["docker", "k8s", "container", "escape"], priority=8,
    ),
    "serverless": KBEntry(
        domain="serverless", module_path="recursec.agents.serverless_kb",
        build_func_name="build_serverless_prompt", description="Serverless security (Lambda, Functions, injection, IAM)",
        pattern_count=5, related_domains=["cloud"],
        tags=["lambda", "serverless", "faas"], priority=7,
    ),
    "mobile": KBEntry(
        domain="mobile", module_path="recursec.agents.mobile_security_kb",
        build_func_name="build_mobile_security_prompt", description="Mobile security (Android, iOS, API, reverse engineering)",
        pattern_count=5, related_domains=["api_gateway", "web_vuln"],
        tags=["mobile", "android", "ios", "apk"], priority=7,
    ),
    "wireless": KBEntry(
        domain="wireless", module_path="recursec.agents.wireless_security_kb",
        build_func_name="build_wireless_prompt", description="Wireless security (WiFi, Bluetooth, RFID, SDR, cellular)",
        pattern_count=5, related_domains=["network", "iot_ics"],
        tags=["wireless", "wifi", "bluetooth", "rfid"], priority=7,
    ),
    "iot_ics": KBEntry(
        domain="iot_ics", module_path="recursec.agents.iot_ics_security_kb",
        build_func_name="build_iot_ics_prompt", description="IoT/ICS security (SCADA, firmware, protocols, smart home)",
        pattern_count=5, related_domains=["wireless", "firmware", "network"],
        tags=["iot", "ics", "scada", "firmware"], priority=7,
    ),
    "firmware": KBEntry(
        domain="firmware", module_path="recursec.agents.firmware_kb",
        build_func_name="build_firmware_prompt", description="Firmware security (extraction, bootloader, debug, OTA, embedded OS)",
        pattern_count=5, related_domains=["iot_ics", "binary_exploitation"],
        tags=["firmware", "embedded", "bootloader", "jtag"], priority=7,
    ),
    "binary_exploitation": KBEntry(
        domain="binary_exploitation", module_path="recursec.agents.binary_exploitation_kb",
        build_func_name="build_binary_exploitation_prompt", description="Binary exploitation (stack, heap, ROP, format string)",
        pattern_count=5, related_domains=["firmware", "privesc"],
        tags=["binary", "bof", "rop", "heap"], priority=8,
    ),
    "identity_sso": KBEntry(
        domain="identity_sso", module_path="recursec.agents.identity_sso_kb",
        build_func_name="build_identity_sso_prompt", description="Identity/SSO attacks (SAML, OAuth, LDAP, Kerberos, MFA bypass)",
        pattern_count=5, related_domains=["web_vuln", "active_directory"],
        tags=["identity", "saml", "oauth", "sso", "mfa"], priority=8,
    ),
    "supply_chain": KBEntry(
        domain="supply_chain", module_path="recursec.agents.supply_chain_kb",
        build_func_name="build_supply_chain_prompt", description="Supply chain attacks (dependency confusion, CI/CD, repo, build)",
        pattern_count=5, related_domains=["devsecops", "code_audit"],
        tags=["supply_chain", "npm", "pypi", "cicd"], priority=8,
    ),
    "devsecops": KBEntry(
        domain="devsecops", module_path="recursec.agents.devsecops_kb",
        build_func_name="build_devsecops_prompt", description="DevSecOps practices (SAST, DAST, SCA, secrets, IaC)",
        pattern_count=5, related_domains=["supply_chain", "code_audit"],
        tags=["devsecops", "sast", "dast", "secrets"], priority=7,
    ),
    "compliance": KBEntry(
        domain="compliance", module_path="recursec.agents.compliance_kb",
        build_func_name="build_compliance_prompt", description="Compliance frameworks (PCI DSS, HIPAA, GDPR, SOC2, ISO27001)",
        pattern_count=5, related_domains=["cloud", "devsecops"],
        tags=["compliance", "pci", "hipaa", "gdpr"], priority=6,
    ),
    "forensics": KBEntry(
        domain="forensics", module_path="recursec.agents.forensics_kb",

        build_func_name="build_forensics_prompt", description="Digital forensics (memory, disk, network, malware, anti-forensics)",
        pattern_count=5, related_domains=["incident_response", "threat_intel"],
        tags=["forensics", "memory", "volatility", "disk"], priority=7,
    ),
    "incident_response": KBEntry(
        domain="incident_response", module_path="recursec.agents.incident_response_kb",
        build_func_name="build_incident_response_prompt", description="Incident response (detection, containment, evidence, eradication)",
        pattern_count=5, related_domains=["forensics", "threat_intel"],
        tags=["ir", "detection", "containment", "eradication"], priority=8,
    ),
    "threat_intel": KBEntry(
        domain="threat_intel", module_path="recursec.agents.threat_intel_kb",
        build_func_name="build_threat_intel_prompt", description="Threat intelligence (MITRE ATT&CK, IoC, actors, kill chain)",
        pattern_count=5, related_domains=["incident_response", "forensics"],
        tags=["threat_intel", "mitre", "ioc", "ttp"], priority=7,
    ),
    "insider_threat": KBEntry(
        domain="insider_threat", module_path="recursec.agents.insider_threat_kb",
        build_func_name="build_insider_threat_prompt", description="Insider threat (detection, exfiltration, privilege abuse)",
        pattern_count=5, related_domains=["threat_intel"],
        tags=["insider", "exfiltration", "privilege_abuse"], priority=6,
    ),
    "evasion": KBEntry(
        domain="evasion", module_path="recursec.agents.evasion_kb",
        build_func_name="build_evasion_prompt", description="Detection evasion (AV/EDR, WAF, IDS/IPS, log cleanup)",
        pattern_count=5, related_domains=["red_team"],
        tags=["evasion", "av", "edr", "waf", "ids"], priority=7,
    ),
    "red_team": KBEntry(
        domain="red_team", module_path="recursec.agents.red_team_kb",
        build_func_name="build_red_team_prompt", description="Red team operations (initial access, persistence, C2, objectives)",
        pattern_count=5, related_domains=["evasion", "lateral_movement", "privesc"],
        tags=["red_team", "c2", "persistence", "initial_access"], priority=9,
    ),
    "ai_ml_security": KBEntry(
        domain="ai_ml_security", module_path="recursec.agents.ai_ml_security_kb",
        build_func_name="build_ai_ml_security_prompt", description="AI/ML security (adversarial, extraction, poisoning, LLM attacks)",
        pattern_count=5, related_domains=["web_vuln"],
        tags=["ai", "ml", "adversarial", "llm", "prompt_injection"], priority=7,
    ),
    "blockchain": KBEntry(
        domain="blockchain", module_path="recursec.agents.blockchain_security_kb",
        build_func_name="build_blockchain_prompt", description="Blockchain security (smart contracts, DeFi, wallet, consensus)",
        pattern_count=5, related_domains=["crypto"],
        tags=["blockchain", "smart_contract", "defi", "web3"], priority=6,
    ),
    "physical": KBEntry(
        domain="physical", module_path="recursec.agents.physical_security_kb",
        build_func_name="build_physical_security_prompt", description="Physical security (access control, social eng, signals, surveillance)",
        pattern_count=5, related_domains=["wireless"],
        tags=["physical", "badge", "rfid", "social_engineering"], priority=5,
    ),
    "dns": KBEntry(
        domain="dns", module_path="recursec.agents.dns_security_kb",
        build_func_name="build_dns_security_prompt", description="DNS security (zone transfer, spoofing, tunneling, rebinding, DNSSEC)",
        pattern_count=5, related_domains=["network"],
        tags=["dns", "tunneling", "spoofing", "rebinding"], priority=7,
    ),
    "windows": KBEntry(
        domain="windows", module_path="recursec.agents.windows_security_kb",
        build_func_name="build_windows_security_prompt", description="Windows security (AD, creds, privesc, persistence, lateral)",
        pattern_count=5, related_domains=["active_directory", "lateral_movement"],
        tags=["windows", "ad", "mimikatz", "psexec"], priority=8,
    ),
    "linux": KBEntry(
        domain="linux", module_path="recursec.agents.linux_security_kb",
        build_func_name="build_linux_security_prompt", description="Linux security (privesc, persistence, creds, container escape, hardening)",
        pattern_count=5, related_domains=["privesc", "container_k8s"],
        tags=["linux", "suid", "cron", "kernel"], priority=8,
    ),
    "advanced_discovery": KBEntry(
        domain="advanced_discovery", module_path="recursec.agents.advanced_discovery_kb",
        build_func_name="build_advanced_discovery_prompt", description="Advanced discovery (Mythos/BigSleep/SAILOR: git mining, variant, hypothesis, hybrid, chaining)",
        pattern_count=5, related_domains=["code_audit", "binary_exploitation"],
        tags=["discovery", "mythos", "bigsleep", "variant", "zero_day"], priority=10,
    ),
    "advanced_strategy": KBEntry(
        domain="advanced_strategy", module_path="recursec.agents.advanced_strategy_kb",
        build_func_name="build_advanced_strategy_prompt", description="Advanced attack strategies (emergent complexity, timing, AI-specific)",
        pattern_count=5, related_domains=["advanced_discovery"],
        tags=["strategy", "advanced", "emergent"], priority=8,
    ),
    "zero_trust": KBEntry(
        domain="zero_trust", module_path="recursec.agents.zero_trust_kb",
        build_func_name="build_zero_trust_prompt", description="Zero trust architecture assessment (identity, devices, network, apps, data)",
        pattern_count=5, related_domains=["cloud", "identity_sso"],
        tags=["zero_trust", "microsegmentation", "identity", "ztna"], priority=7,
    ),
    "crypto": KBEntry(
        domain="crypto", module_path="recursec.agents.crypto_security_kb",
        build_func_name="build_crypto_security_prompt", description="Cryptography attacks (weak ciphers, key management, TLS, implementation, hashing)",
        pattern_count=5, related_domains=["web_vuln", "network"],
        tags=["crypto", "tls", "ssl", "cipher", "hash", "key_management"], priority=8,
    ),
    "social_engineering": KBEntry(
        domain="social_engineering", module_path="recursec.agents.social_engineering_kb",
        build_func_name="build_social_engineering_prompt", description="Social engineering (phishing, pretexting, OSINT, vishing, physical)",
        pattern_count=5, related_domains=["physical", "red_team"],
        tags=["social_engineering", "phishing", "osint", "vishing"], priority=7,
    ),
    "hardware": KBEntry(
        domain="hardware", module_path="recursec.agents.hardware_security_kb",
        build_func_name="build_hardware_security_prompt", description="Hardware security (side-channel, fault injection, debug, chip-level)",
        pattern_count=5, related_domains=["iot_ics", "firmware"],
        tags=["hardware", "side_channel", "jtag", "swd", "fault_injection"], priority=6,
    ),
    "automotive": KBEntry(
        domain="automotive", module_path="recursec.agents.automotive_security_kb",
        build_func_name="build_automotive_security_prompt", description="Automotive security (CAN bus, ECU, V2X, infotainment, ADAS)",
        pattern_count=5, related_domains=["iot_ics", "hardware", "wireless"],
        tags=["automotive", "can", "ecu", "v2x", "adas"], priority=6,
    ),
    "satellite": KBEntry(
        domain="satellite", module_path="recursec.agents.satellite_security_kb",
        build_func_name="build_satellite_security_prompt", description="Satellite/space security (ground station, link, GNSS, user terminal)",
        pattern_count=5, related_domains=["rf", "wireless"],
        tags=["satellite", "space", "gnss", "gps", "vsat"], priority=5,
    ),
    "quantum": KBEntry(
        domain="quantum", module_path="recursec.agents.quantum_security_kb",
        build_func_name="build_quantum_security_prompt", description="Quantum security (Shor/Grover attacks, PQC transition, QKD, harvest-now)",
        pattern_count=4, related_domains=["crypto"],
        tags=["quantum", "pqc", "post_quantum", "shor", "grover"], priority=6,
    ),
    "scada": KBEntry(
        domain="scada", module_path="recursec.agents.scada_security_kb",
        build_func_name="build_scada_security_prompt", description="SCADA/ICS deep (PLC, DCS, HMI, industrial protocols, safety systems/TRITON)",
        pattern_count=5, related_domains=["iot_ics", "network"],
        tags=["scada", "plc", "dcs", "hmi", "modbus", "safety"], priority=7,
    ),
    "rf": KBEntry(
        domain="rf", module_path="recursec.agents.rf_security_kb",
        build_func_name="build_rf_security_prompt", description="RF security (SDR, protocol exploitation, jamming, replay, signal injection)",
        pattern_count=5, related_domains=["wireless", "satellite"],
        tags=["rf", "sdr", "jamming", "replay", "signal"], priority=6,
    ),
    "medical_device": KBEntry(
        domain="medical_device", module_path="recursec.agents.medical_device_kb",
        build_func_name="build_medical_device_prompt", description="Medical device/healthcare security (infusion pumps, EHR, HL7, DICOM, PACS)",
        pattern_count=5, related_domains=["iot_ics", "network"],
        tags=["medical", "healthcare", "hl7", "dicom", "hipaa", "device"], priority=7,
    ),
    "telecom": KBEntry(
        domain="telecom", module_path="recursec.agents.telecom_security_kb",
        build_func_name="build_telecom_security_prompt", description="Telecom security (SS7, Diameter, SIP/VoIP, 5G, baseband exploitation)",
        pattern_count=5, related_domains=["wireless", "rf"],
        tags=["telecom", "ss7", "sip", "voip", "5g", "baseband"], priority=7,
    ),
    "election": KBEntry(
        domain="election", module_path="recursec.agents.election_security_kb",
        build_func_name="build_election_security_prompt", description="Election/voting system security (DRE, voter registration, disinformation)",
        pattern_count=4, related_domains=["physical"],
        tags=["election", "voting", "democracy", "disinformation"], priority=5,
    ),
    "maritime": KBEntry(
        domain="maritime", module_path="recursec.agents.maritime_security_kb",
        build_func_name="build_maritime_security_prompt", description="Maritime/port security (AIS spoofing, ECDIS, GMDSS, port infrastructure)",
        pattern_count=4, related_domains=["satellite", "rf"],
        tags=["maritime", "ship", "ais", "port", "navigation"], priority=5,
    ),
}


def get_kbs_for_tags(tags: list[str]) -> list[KBEntry]:
    """Get all KBs matching any of the given tags."""
    results = []
    for entry in KB_REGISTRY.values():
        if any(t in entry.tags for t in tags):
            results.append(entry)
    return sorted(results, key=lambda e: e.priority, reverse=True)


def get_kbs_for_intent(intent: str) -> list[KBEntry]:
    """Get all KBs relevant to a task intent."""
    from recursec.agents.intent_classifier import INTENT_KB_MAP, TaskIntent
    try:
        task_intent = TaskIntent(intent)
    except ValueError:
        return list(KB_REGISTRY.values())[:10]

    kb_domains = INTENT_KB_MAP.get(task_intent, [])
    results = []
    for domain in kb_domains:
        if domain in KB_REGISTRY:
            results.append(KB_REGISTRY[domain])
    # Also add related domains
    seen = {e.domain for e in results}
    for entry in results[:]:
        for related in entry.related_domains[:2]:
            if related not in seen and related in KB_REGISTRY:
                results.append(KB_REGISTRY[related])
                seen.add(related)
    return sorted(results, key=lambda e: e.priority, reverse=True)


def get_all_domains() -> list[str]:
    """Get all registered KB domain names."""
    return sorted(KB_REGISTRY.keys())


def get_registry_stats() -> dict[str, Any]:
    """Get registry statistics."""
    all_tags: set[str] = set()
    for entry in KB_REGISTRY.values():
        all_tags.update(entry.tags)
    return {
        "total_kbs": len(KB_REGISTRY),
        "total_patterns": sum(e.pattern_count for e in KB_REGISTRY.values()),
        "unique_tags": len(all_tags),
        "avg_priority": sum(e.priority for e in KB_REGISTRY.values()) / max(len(KB_REGISTRY), 1),
    }
