"""Digital forensics knowledge base.

Deep knowledge about forensic analysis:
1. Memory forensics
2. Disk forensics
3. Network forensics
4. Log analysis
5. Incident response procedures
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ForensicsPattern:
    """A digital forensics pattern."""
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


FORENSICS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "for-001", "name": "Memory Forensics",
        "category": "memory", "severity": "high",
        "desc": "Analyzing volatile memory for evidence.",
        "detection": (
            "MEMORY FORENSICS:\n"
            "ACQUISITION:\n"
            "  # Linux\n"
            "  dd if=/proc/kcore of=memory.raw  # Kernel memory\n"
            "  lime (LiME): insmod lime.ko 'path=mem.lime format=lime'\n"
            "  # Windows\n"
            "  winpmem_mini.exe mem.raw  # WinPmem\n"
            "  FTK Imager (GUI tool)\n"
            "  Magnet RAM Capture\n"
            "VOLATILITY 3 ANALYSIS:\n"
            "  # List processes\n"
            "  vol -f memory.raw windows.pslist\n"
            "  vol -f memory.raw windows.pstree\n"
            "  # Hidden processes\n"
            "  vol -f memory.raw windows.psscan\n"
            "  # Network connections\n"
            "  vol -f memory.raw windows.netscan\n"
            "  # DLL list\n"
            "  vol -f memory.raw windows.dlllist --pid <pid>\n"
            "  # Command history\n"
            "  vol -f memory.raw windows.cmdline\n"
            "  # Registry hives\n"
            "  vol -f memory.raw windows.registry.hivelist\n"
            "  # Dump process memory\n"
            "  vol -f memory.raw windows.memmap --pid <pid> --dump\n"
            "INDICATORS:\n"
            "  - Suspicious processes (unusual names, paths)\n"
            "  - Injected code (hollowed processes)\n"
            "  - Hidden/unlinked processes\n"
            "  - Network connections to C2\n"
            "  - Malware strings in memory"
        ),
        "tools": ["volatility3", "lime", "winpmem"],
    },
    {
        "id": "for-002", "name": "Disk Forensics",
        "category": "disk", "severity": "high",
        "desc": "Analyzing disk images for evidence.",
        "detection": (
            "DISK FORENSICS:\n"
            "ACQUISITION:\n"
            "  # Create forensic image\n"
            "  dd if=/dev/sda of=disk.raw bs=64K status=progress\n"
            "  dcfldd if=/dev/sda of=disk.raw hash=sha256\n"
            "  ewfacquire /dev/sda  # E01 format (compressed)\n"
            "  # Verify integrity\n"
            "  sha256sum disk.raw\n"
            "ANALYSIS WITH AUTOPSY/TSK:\n"
            "  # Timeline\n"
            "  fls -r -m / disk.raw | mactime -b - > timeline.csv\n"
            "  # Deleted files\n"
            "  fls -rd disk.raw  # List deleted files\n"
            "  icat disk.raw <inode>  # Recover deleted file\n"
            "  # File system analysis\n"
            "  mmls disk.raw  # Partition layout\n"
            "  fsstat -o <offset> disk.raw  # FS details\n"
            "FILE CARVING:\n"
            "  # Recover files from unallocated space\n"
            "  foremost -i disk.raw -o output/\n"
            "  photorec disk.raw  # PhotoRec (more file types)\n"
            "  scalpel -c scalpel.conf -o output/ disk.raw\n"
            "ARTIFACTS:\n"
            "  - Browser history/cache\n"
            "  - Windows Event Logs\n"
            "  - Prefetch files (program execution)\n"
            "  - USN Journal (file changes)\n"
            "  - $MFT (Master File Table)\n"
            "  - Shellbags (folder access)"
        ),
        "tools": ["sleuthkit", "autopsy", "foremost"],
    },
    {
        "id": "for-003", "name": "Network Forensics",
        "category": "network", "severity": "high",
        "desc": "Analyzing network traffic for evidence.",
        "detection": (
            "NETWORK FORENSICS:\n"
            "CAPTURE:\n"
            "  # tcpdump\n"
            "  tcpdump -i any -w capture.pcap -c 100000\n"
            "  tcpdump -i eth0 host <suspect_ip> -w suspect.pcap\n"
            "  # Wireshark (GUI)\n"
            "  tshark -i eth0 -w capture.pcap  # CLI version\n"
            "ANALYSIS:\n"
            "  # Extract files from PCAP\n"
            "  NetworkMiner  # Automatic extraction\n"
            "  tshark -r capture.pcap --export-objects http,/tmp/files/\n"
            "  # DNS analysis\n"
            "  tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name\n"
            "  # HTTP analysis\n"
            "  tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri\n"
            "  # Credential extraction\n"
            "  PCredz -f capture.pcap  # Extract credentials\n"
            "  # TLS decryption (if key available)\n"
            "  editcap --inject-secrets tls,keys.log capture.pcap decrypted.pcap\n"
            "ZEEK (formerly Bro):\n"
            "  zeek -r capture.pcap  # Generate logs\n"
            "  # Produces: conn.log, dns.log, http.log, etc.\n"
            "  # Excellent for large-scale traffic analysis\n"
            "INDICATORS:\n"
            "  - DNS tunneling (long subdomain labels)\n"
            "  - Beaconing patterns (regular intervals)\n"
            "  - Data exfiltration (large outbound transfers)\n"
            "  - C2 communication patterns"
        ),
        "tools": ["wireshark", "tshark", "zeek"],
    },
    {
        "id": "for-004", "name": "Log Analysis and SIEM",
        "category": "logs", "severity": "medium",
        "desc": "Analyzing system and security logs.",
        "detection": (
            "LOG ANALYSIS:\n"
            "WINDOWS EVENT LOGS:\n"
            "  # Key Event IDs:\n"
            "  4624: Successful logon\n"
            "  4625: Failed logon\n"
            "  4648: Logon with explicit credentials\n"
            "  4672: Special privileges assigned\n"
            "  4688: Process created\n"
            "  4697: Service installed\n"
            "  4698: Scheduled task created\n"
            "  4720: User account created\n"
            "  7045: Service installed (System log)\n"
            "  # Tools:\n"
            "  evtx_dump.py <evtx_file>  # Parse EVTX\n"
            "  hayabusa -d <evtx_dir> -o results.csv  # Sigma-based detection\n"
            "LINUX LOGS:\n"
            "  /var/log/auth.log: Authentication events\n"
            "  /var/log/syslog: System events\n"
            "  /var/log/apache2/: Web server logs\n"
            "  /var/log/audit/: SELinux/auditd events\n"
            "  # Last logins\n"
            "  last -f /var/log/wtmp\n"
            "  lastb -f /var/log/btmp  # Failed logins\n"
            "SIGMA RULES:\n"
            "  # Universal detection rules\n"
            "  sigmac -t splunk -c sysmon rules/windows/*.yml\n"
            "  # Convert to SIEM-specific queries\n"
            "  # Covers: lateral movement, persistence, exfiltration"
        ),
        "tools": ["hayabusa", "sigma", "evtx_dump"],
    },
    {
        "id": "for-005", "name": "Incident Response Procedures",
        "category": "ir", "severity": "critical",
        "desc": "Structured incident response methodology.",
        "detection": (
            "INCIDENT RESPONSE:\n"
            "NIST SP 800-61 PHASES:\n"
            "  1. PREPARATION:\n"
            "    - IR plan and procedures\n"
            "    - Contact lists (internal + external)\n"
            "    - Forensic toolkit ready\n"
            "    - Baseline configurations\n"
            "  2. DETECTION & ANALYSIS:\n"
            "    - Alert triage and validation\n"
            "    - Scope assessment (affected systems)\n"
            "    - Evidence preservation (image before action)\n"
            "    - Timeline construction\n"
            "    - IOC extraction and sharing\n"
            "  3. CONTAINMENT:\n"
            "    - Short-term: Isolate affected systems\n"
            "    - Block malicious IPs/domains at firewall\n"
            "    - Disable compromised accounts\n"
            "    - Long-term: Patch vulnerabilities\n"
            "  4. ERADICATION:\n"
            "    - Remove malware/backdoors\n"
            "    - Rebuild compromised systems\n"
            "    - Reset all potentially compromised credentials\n"
            "    - Verify eradication across all systems\n"
            "  5. RECOVERY:\n"
            "    - Restore from clean backups\n"
            "    - Monitor for reinfection\n"
            "    - Gradual service restoration\n"
            "  6. LESSONS LEARNED:\n"
            "    - Post-incident review\n"
            "    - Update procedures and detection"
        ),
        "tools": ["velociraptor", "grr", "thehive"],
    },
]


class ForensicsKB:
    """Digital forensics knowledge base.

    Provides forensic analysis patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ForensicsPattern] = {}
        self._log = logger.bind(component="forensics_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load forensics patterns."""
        for data in FORENSICS_PATTERNS:
            pattern = ForensicsPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[ForensicsPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_forensics_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build forensics prompt."""
        lines = ["## Digital Forensics Patterns\n"]
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
