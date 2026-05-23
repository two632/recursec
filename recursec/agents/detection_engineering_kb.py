"""Detection engineering knowledge base.

Deep knowledge about detection and evasion:
1. SIEM detection rules (Sigma, Splunk, KQL)
2. EDR evasion techniques
3. WAF bypass strategies
4. IDS/IPS evasion
5. Logging and monitoring gaps
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class DetectionPattern:
    """A detection engineering pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


DETECTION_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "det-001", "name": "SIEM Detection Rules",
        "category": "siem", "severity": "high",
        "desc": "SIEM detection rules and alerting.",
        "detection": (
            "SIEM DETECTION RULES:\n"
            "SIGMA (Universal Format):\n"
            "  title: Suspicious PowerShell Execution\n"
            "  logsource:\n"
            "    product: windows\n"
            "    service: powershell\n"
            "  detection:\n"
            "    selection:\n"
            "      ScriptBlockText|contains:\n"
            "        - 'Invoke-Expression'\n"
            "        - 'IEX'\n"
            "        - 'DownloadString'\n"
            "    condition: selection\n"
            "  level: high\n"
            "  # Convert: sigmac --target splunk rule.yml\n"
            "SPLUNK SPL:\n"
            "  index=main sourcetype=WinEventLog:Security EventCode=4625\n"
            "  | stats count by src_ip\n"
            "  | where count > 10\n"
            "  # Brute force detection\n"
            "KQL (Azure Sentinel):\n"
            "  SecurityEvent\n"
            "  | where EventID == 4688\n"
            "  | where Process has_any ('mimikatz', 'procdump')\n"
            "  | project TimeGenerated, Computer, Account\n"
            "ELASTIC:\n"
            "  - Match on process.name and event.action\n"
            "  - MITRE ATT&CK mapping\n"
            "  - Detection rules repository\n"
            "KEY DETECTIONS:\n"
            "  - Credential dumping (4672, 4648)\n"
            "  - Lateral movement (4624 Type 3)\n"
            "  - Persistence (7045, 4698)\n"
            "  - Exfiltration (DNS tunneling, large POST)\n"
            "  - C2 beaconing (regular intervals)"
        ),
        "tools": ["sigma", "splunk"],
    },
    {
        "id": "det-002", "name": "EDR Evasion",
        "category": "edr", "severity": "critical",
        "desc": "EDR detection and evasion techniques.",
        "detection": (
            "EDR EVASION:\n"
            "AMSI BYPASS:\n"
            "  # Patching amsi.dll in memory\n"
            "  # AmsiScanBuffer returns clean\n"
            "  # String concatenation to avoid signatures\n"
            "  # Reflection-based loading\n"
            "ETW PATCHING:\n"
            "  # Patch EtwEventWrite to return\n"
            "  # Disable .NET ETW provider\n"
            "  # Prevents CLR telemetry\n"
            "SYSCALL EVASION:\n"
            "  # Direct syscalls (avoid ntdll hooks)\n"
            "  # SysWhispers: Generate syscall stubs\n"
            "  # HellsGate: Dynamic syscall resolution\n"
            "  # Halo's Gate: Walk PAGE_EXECUTE stubs\n"
            "UNHOOKING:\n"
            "  # Read clean ntdll from disk\n"
            "  # Map clean ntdll over hooked one\n"
            "  # Per-function unhooking\n"
            "  # Module stomping\n"
            "INJECTION:\n"
            "  # Process hollowing\n"
            "  # Thread hijacking\n"
            "  # APC injection\n"
            "  # Callback-based (SetTimer, EnumWindows)\n"
            "  # Phantom DLL hollowing\n"
            "EVASION TESTING:\n"
            "  # ScareCrow (payload obfuscation)\n"
            "  # Donut (shellcode converter)\n"
            "  # NimHollow (Nim-based PE loader)\n"
            "  # Check: VirusTotal, antiscan.me\n"
            "  # DefenderCheck: Find exact detection byte"
        ),
        "tools": ["scarecrow", "donut"],
    },
    {
        "id": "det-003", "name": "WAF Bypass",
        "category": "waf", "severity": "high",
        "desc": "Web Application Firewall bypass techniques.",
        "detection": (
            "WAF BYPASS:\n"
            "ENCODING:\n"
            "  - URL encoding: %27 → '\n"
            "  - Double encoding: %2527 → %27 → '\n"
            "  - Unicode: \\u0027 → '\n"
            "  - HTML entities: &#x27; &#39;\n"
            "  - Hex: 0x27\n"
            "  - Overlong UTF-8\n"
            "SQL INJECTION:\n"
            "  - Case variation: SeLeCt, sElEcT\n"
            "  - Comments: SEL/**/ECT, SE/**_**/LECT\n"
            "  - Concat: 'SEL' + 'ECT'\n"
            "  - Alternative keywords: GROUP_CONCAT, INTO OUTFILE\n"
            "  - Scientific notation: 1e0union\n"
            "  - JSON functions: JSON_EXTRACT\n"
            "XSS:\n"
            "  - Event handlers: onmouseover, onfocus, onerror\n"
            "  - JavaScript URIs: javascript:alert(1)\n"
            "  - SVG tags: <svg/onload=alert(1)>\n"
            "  - Template injection: {{constructor.constructor('alert(1)')()}}\n"
            "  - Mutation XSS (mXSS)\n"
            "TECHNIQUES:\n"
            "  - HTTP parameter pollution\n"
            "  - Request smuggling\n"
            "  - Chunked transfer encoding\n"
            "  - Content-Type manipulation\n"
            "  - Multipart form-data boundary\n"
            "  - IPv6 addresses\n"
            "  - IP rotation\n"
            "TOOLS:\n"
            "  wafw00f (detect WAF), sqlmap --tamper, wafninja"
        ),
        "tools": ["wafw00f", "sqlmap"],
    },
    {
        "id": "det-004", "name": "IDS/IPS Evasion",
        "category": "ids", "severity": "high",
        "desc": "IDS/IPS evasion techniques.",
        "detection": (
            "IDS/IPS EVASION:\n"
            "FRAGMENTATION:\n"
            "  nmap -f target  # Fragment packets\n"
            "  nmap --mtu 8 target  # Custom MTU\n"
            "  # IP fragmentation: split payload across packets\n"
            "  # TCP segmentation: small TCP segments\n"
            "TIMING:\n"
            "  nmap -T0 target  # Paranoid (5 min between probes)\n"
            "  nmap -T1 target  # Sneaky (15s between probes)\n"
            "  # Slow scan avoids threshold-based detection\n"
            "  # Randomize scan order\n"
            "PAYLOAD OBFUSCATION:\n"
            "  - XOR encoding\n"
            "  - Base64 encoding\n"
            "  - Custom encryption\n"
            "  - Polymorphic shellcode\n"
            "  - Staged payloads (small initial, fetch rest)\n"
            "PROTOCOL ABUSE:\n"
            "  - TTL manipulation\n"
            "  - Decoy scans: nmap -D RND:10 target\n"
            "  - Source port: nmap --source-port 53 target\n"
            "  - Idle scan: nmap -sI zombie target\n"
            "  - IPv6 scanning (often unmonitored)\n"
            "ENCRYPTED CHANNELS:\n"
            "  - HTTPS for C2\n"
            "  - DNS over HTTPS (DoH)\n"
            "  - Domain fronting\n"
            "  - Encrypted DNS tunneling\n"
            "  - Tor/VPN/proxy chains"
        ),
        "tools": ["nmap", "scapy"],
    },
    {
        "id": "det-005", "name": "Monitoring Gaps",
        "category": "gaps", "severity": "medium",
        "desc": "Common logging and monitoring gaps.",
        "detection": (
            "MONITORING GAPS:\n"
            "COMMON BLIND SPOTS:\n"
            "  - East-west traffic (internal lateral movement)\n"
            "  - Encrypted internal traffic\n"
            "  - Cloud-to-cloud communication\n"
            "  - Container-to-container traffic\n"
            "  - USB/physical access\n"
            "  - Outbound DNS (tunneling)\n"
            "  - Certificate-based auth events\n"
            "LOGGING FAILURES:\n"
            "  - Insufficient log retention\n"
            "  - Log volume overwhelm (alert fatigue)\n"
            "  - Missing correlation across sources\n"
            "  - No baseline for normal behavior\n"
            "  - Logs not centralized\n"
            "  - Clock sync issues (NTP)\n"
            "DETECTION GAPS:\n"
            "  - Living-off-the-land (LOL) binaries\n"
            "  - Fileless attacks (PowerShell, WMI)\n"
            "  - Supply chain (trusted process abuse)\n"
            "  - Insider threats\n"
            "  - Slow-and-low attacks\n"
            "  - Environment-aware malware (sandbox detection)\n"
            "COVERAGE ASSESSMENT:\n"
            "  - Map to MITRE ATT&CK coverage\n"
            "  - Identify unmonitored techniques\n"
            "  - Red team to validate detections\n"
            "  - Purple team exercises\n"
            "  - Atomic Red Team tests\n"
            "TOOLS:\n"
            "  MITRE ATT&CK Navigator, DeTT&CT, Atomic Red Team"
        ),
        "tools": ["atomic-red-team"],
    },
]


class DetectionEngineeringKB:
    """Detection engineering knowledge base.

    Provides detection/evasion patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, DetectionPattern] = {}
        self._log = logger.bind(component="detection_engineering_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load detection patterns."""
        for data in DETECTION_PATTERNS:
            pattern = DetectionPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[DetectionPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_detection_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build detection engineering prompt."""
        lines = ["## Detection & Evasion Techniques\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_category": cat_counts,
        }
