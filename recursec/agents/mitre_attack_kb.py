"""MITRE ATT&CK mapping knowledge base.

Deep knowledge about MITRE ATT&CK:
1. Tactics overview and mapping
2. Technique-to-tool mapping
3. Detection strategies per technique
4. Sub-technique details
5. ATT&CK-based assessment planning
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MITREPattern:
    """A MITRE ATT&CK pattern."""
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


MITRE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "mitre-001", "name": "ATT&CK Tactics Overview",
        "category": "tactics", "severity": "high",
        "desc": "MITRE ATT&CK tactics mapping.",
        "detection": (
            "MITRE ATT&CK TACTICS:\n"
            "TA0001 INITIAL ACCESS:\n"
            "  - Phishing (T1566)\n"
            "  - Exploit Public-Facing App (T1190)\n"
            "  - External Remote Services (T1133)\n"
            "  - Supply Chain Compromise (T1195)\n"
            "  - Valid Accounts (T1078)\n"
            "TA0002 EXECUTION:\n"
            "  - Command/Scripting Interpreter (T1059)\n"
            "  - Exploitation for Client Execution (T1203)\n"
            "  - User Execution (T1204)\n"
            "  - Scheduled Task/Job (T1053)\n"
            "TA0003 PERSISTENCE:\n"
            "  - Boot/Logon Autostart (T1547)\n"
            "  - Create Account (T1136)\n"
            "  - Scheduled Task/Job (T1053)\n"
            "  - Server Software Component (T1505)\n"
            "TA0004 PRIVILEGE ESCALATION:\n"
            "  - Exploitation for Privilege Esc (T1068)\n"
            "  - Process Injection (T1055)\n"
            "  - Valid Accounts (T1078)\n"
            "  - Access Token Manipulation (T1134)\n"
            "TA0005 DEFENSE EVASION:\n"
            "  - Obfuscated Files (T1027)\n"
            "  - Process Injection (T1055)\n"
            "  - Masquerading (T1036)\n"
            "  - Indicator Removal (T1070)\n"
            "TA0006 CREDENTIAL ACCESS:\n"
            "  - OS Credential Dumping (T1003)\n"
            "  - Brute Force (T1110)\n"
            "  - Credentials in Files (T1552)\n"
            "TA0007 DISCOVERY:\n"
            "  - Account Discovery (T1087)\n"
            "  - Network Service Discovery (T1046)\n"
            "  - Permission Groups Discovery (T1069)\n"
            "TA0008 LATERAL MOVEMENT:\n"
            "  - Remote Services (T1021)\n"
            "  - Lateral Tool Transfer (T1570)\n"
            "TA0009 COLLECTION:\n"
            "  - Data from Local System (T1005)\n"
            "  - Email Collection (T1114)\n"
            "TA0010 EXFILTRATION:\n"
            "  - Exfiltration Over C2 (T1041)\n"
            "  - Exfiltration Over Web Service (T1567)\n"
            "TA0011 C2:\n"
            "  - Application Layer Protocol (T1071)\n"
            "  - Encrypted Channel (T1573)\n"
            "TA0040 IMPACT:\n"
            "  - Data Encrypted for Impact (T1486)\n"
            "  - Service Stop (T1489)"
        ),
        "tools": [],
    },
    {
        "id": "mitre-002", "name": "Technique-to-Tool Mapping",
        "category": "tool_mapping", "severity": "high",
        "desc": "Tool mapping per technique.",
        "detection": (
            "TECHNIQUE → TOOL MAPPING:\n"
            "INITIAL ACCESS:\n"
            "  T1190 (Exploit Public App):\n"
            "    → nuclei, sqlmap, nikto, burpsuite\n"
            "  T1566 (Phishing):\n"
            "    → gophish, evilginx2, SET\n"
            "  T1133 (Remote Services):\n"
            "    → hydra, crackmapexec, nmap\n"
            "EXECUTION:\n"
            "  T1059 (Command Interpreter):\n"
            "    → metasploit, cobalt_strike\n"
            "  T1053 (Scheduled Task):\n"
            "    → schtasks, crontab, at\n"
            "PERSISTENCE:\n"
            "  T1547 (Autostart):\n"
            "    → SharPersist, PowerSploit\n"
            "  T1505 (Web Shell):\n"
            "    → weevely, p0wny-shell\n"
            "PRIVILEGE ESCALATION:\n"
            "  T1068 (Exploitation):\n"
            "    → kernel exploits, CVE-specific\n"
            "  T1055 (Process Injection):\n"
            "    → DonutLoader, ScareCrow\n"
            "CREDENTIAL ACCESS:\n"
            "  T1003 (Credential Dumping):\n"
            "    → mimikatz, pypykatz, secretsdump\n"
            "  T1110 (Brute Force):\n"
            "    → hydra, hashcat, john\n"
            "LATERAL MOVEMENT:\n"
            "  T1021 (Remote Services):\n"
            "    → psexec, evil-winrm, SSH\n"
            "  T1021.002 (SMB):\n"
            "    → crackmapexec, smbclient\n"
            "DISCOVERY:\n"
            "  T1046 (Network Scan):\n"
            "    → nmap, masscan, rustscan\n"
            "  T1087 (Account Discovery):\n"
            "    → bloodhound, ldapsearch, net\n"
            "EXFILTRATION:\n"
            "  T1567 (Web Service):\n"
            "    → custom scripts, curl\n"
            "  T1048 (Alt Protocol):\n"
            "    → dnscat2, iodine"
        ),
        "tools": [],
    },
    {
        "id": "mitre-003", "name": "Detection Strategies",
        "category": "detection", "severity": "high",
        "desc": "Detection per ATT&CK technique.",
        "detection": (
            "DETECTION STRATEGIES:\n"
            "T1003 CREDENTIAL DUMPING:\n"
            "  - Monitor lsass.exe access\n"
            "  - Sysmon Event ID 10 (process access)\n"
            "  - SACL on LSASS\n"
            "  - Credential Guard\n"
            "T1055 PROCESS INJECTION:\n"
            "  - Sysmon Event ID 8 (CreateRemoteThread)\n"
            "  - Monitor NtWriteVirtualMemory\n"
            "  - ETW for injection APIs\n"
            "  - Process hollowing: memory-only executable\n"
            "T1059 COMMAND INTERPRETER:\n"
            "  - Script Block Logging (PowerShell)\n"
            "  - Module Logging\n"
            "  - Transcription\n"
            "  - Command-line auditing\n"
            "T1021 REMOTE SERVICES:\n"
            "  - Event ID 4624 (Type 3, 10)\n"
            "  - Named pipe creation\n"
            "  - Service creation events\n"
            "  - Unusual SMB connections\n"
            "T1070 INDICATOR REMOVAL:\n"
            "  - Event log clearing (Event ID 1102)\n"
            "  - Timestomping detection\n"
            "  - USN journal gaps\n"
            "  - MFT anomalies\n"
            "T1566 PHISHING:\n"
            "  - Email gateway scanning\n"
            "  - Macro execution alerts\n"
            "  - URL sandboxing\n"
            "  - User awareness training\n"
            "T1190 EXPLOIT PUBLIC APP:\n"
            "  - WAF alerts\n"
            "  - Web server logs analysis\n"
            "  - Unexpected POST requests\n"
            "  - SQL error pages\n"
            "SIEM QUERIES:\n"
            "  - Correlate events across sources\n"
            "  - Baseline normal behavior\n"
            "  - Alert on deviations\n"
            "TOOLS:\n"
            "  Sysmon, SIEM (Splunk, ELK), Sigma rules"
        ),
        "tools": [],
    },
    {
        "id": "mitre-004", "name": "Sub-Technique Details",
        "category": "subtechniques", "severity": "high",
        "desc": "Critical sub-techniques detail.",
        "detection": (
            "KEY SUB-TECHNIQUES:\n"
            "T1003.001 LSASS Memory:\n"
            "  - mimikatz sekurlsa::logonpasswords\n"
            "  - procdump, comsvcs.dll\n"
            "  - Direct LSASS memory read\n"
            "T1003.003 NTDS:\n"
            "  - ntdsutil, DCSync\n"
            "  - Volume Shadow Copy\n"
            "  - All domain hashes\n"
            "T1021.001 RDP:\n"
            "  - xfreerdp, rdesktop\n"
            "  - Restricted Admin mode\n"
            "  - SharpRDP\n"
            "T1021.002 SMB/Windows Admin Shares:\n"
            "  - psexec, smbexec\n"
            "  - Admin$ share access\n"
            "  - File copy + service creation\n"
            "T1021.006 WinRM:\n"
            "  - evil-winrm\n"
            "  - PowerShell remoting\n"
            "  - Port 5985/5986\n"
            "T1053.005 Scheduled Task:\n"
            "  - schtasks.exe\n"
            "  - at.exe (legacy)\n"
            "  - WMI event subscription\n"
            "T1055.001 DLL Injection:\n"
            "  - LoadLibrary\n"
            "  - Manual mapping\n"
            "  - Reflective DLL\n"
            "T1059.001 PowerShell:\n"
            "  - Encoded commands (-enc)\n"
            "  - Download cradle\n"
            "  - AMSI bypass required\n"
            "T1059.003 Windows Command Shell:\n"
            "  - cmd.exe\n"
            "  - Living off the Land\n"
            "T1078.002 Domain Accounts:\n"
            "  - Credential theft\n"
            "  - Kerberoasting\n"
            "  - Pass-the-Hash/Ticket"
        ),
        "tools": [],
    },
    {
        "id": "mitre-005", "name": "ATT&CK Assessment Planning",
        "category": "planning", "severity": "medium",
        "desc": "ATT&CK-based assessment planning.",
        "detection": (
            "ATT&CK-BASED PLANNING:\n"
            "THREAT MODELING:\n"
            "  1. Identify likely threat groups\n"
            "  2. Map their known TTPs\n"
            "  3. Prioritize techniques to test\n"
            "  4. Build test plan per technique\n"
            "PURPLE TEAM:\n"
            "  - Red: execute technique\n"
            "  - Blue: detect and respond\n"
            "  - Gap analysis on coverage\n"
            "  - Improve detection rules\n"
            "COVERAGE MATRIX:\n"
            "  - Map existing controls to techniques\n"
            "  - Identify detection gaps\n"
            "  - Prioritize by threat likelihood\n"
            "  - Score: detected/alerted/prevented\n"
            "EMULATION PLANS:\n"
            "  - APT29 (Cozy Bear)\n"
            "  - APT3 (Gothic Panda)\n"
            "  - FIN6/FIN7 (financial)\n"
            "  - Sandworm (destructive)\n"
            "  - MITRE ATT&CK evaluations\n"
            "ATOMIC RED TEAM:\n"
            "  # Test individual techniques\n"
            "  Invoke-AtomicTest T1003.001\n"
            "  # Maps 1:1 to ATT&CK techniques\n"
            "  # Quick, repeatable tests\n"
            "  # Pre-defined cleanup\n"
            "REPORTING:\n"
            "  - Map findings to ATT&CK techniques\n"
            "  - Heatmap coverage visualization\n"
            "  - Navigator layer export\n"
            "  - STIX/TAXII for sharing\n"
            "TOOLS:\n"
            "  ATT&CK Navigator, Atomic Red Team,\n"
            "  CALDERA, Infection Monkey"
        ),
        "tools": [],
    },
]


class MITREAttackKB:
    """MITRE ATT&CK knowledge base.

    Provides ATT&CK patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, MITREPattern] = {}
        self._log = logger.bind(component="mitre_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load MITRE patterns."""
        for data in MITRE_PATTERNS:
            pattern = MITREPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[MITREPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_mitre_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build MITRE ATT&CK prompt."""
        lines = ["## MITRE ATT&CK\n"]
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
