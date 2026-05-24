"""Digital forensics knowledge base.

Deep knowledge about digital forensics:
1. Disk forensics
2. Memory forensics
3. Network forensics
4. Log analysis
5. Malware forensics
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
    severity: str = "medium"
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
        "id": "for-001", "name": "Disk Forensics",
        "category": "disk", "severity": "medium",
        "desc": "Disk forensics techniques.",
        "detection": (
            "DISK FORENSICS:\n"
            "ACQUISITION:\n"
            "  # Create forensic image\n"
            "  dd if=/dev/sda of=image.raw bs=4M\n"
            "  dc3dd if=/dev/sda of=image.raw hash=sha256\n"
            "  # Verify integrity\n"
            "  sha256sum image.raw\n"
            "  # EWF format\n"
            "  ewfacquire /dev/sda\n"
            "ANALYSIS:\n"
            "  - Autopsy (GUI, timeline)\n"
            "  - Sleuth Kit (CLI)\n"
            "    # fls -r image.raw (file listing)\n"
            "    # icat image.raw INODE (file extract)\n"
            "    # tsk_recover image.raw output/ (carve)\n"
            "  - File system analysis\n"
            "    # NTFS: $MFT, $LogFile, $UsnJrnl\n"
            "    # ext4: journal, inode tables\n"
            "    # APFS: snapshots, clones\n"
            "FILE CARVING:\n"
            "  # Recover deleted files\n"
            "  foremost -i image.raw -o output/\n"
            "  photorec image.raw\n"
            "  scalpel -c scalpel.conf -o output/ image.raw\n"
            "ARTIFACTS:\n"
            "  - Windows: Registry, Prefetch, Amcache\n"
            "  - macOS: plist, FSEvents, Spotlight\n"
            "  - Linux: /var/log, .bash_history, systemd journal\n"
            "  - Browser: history, cache, cookies\n"
            "TOOLS:\n"
            "  Autopsy, Sleuth Kit, FTK, EnCase"
        ),
        "tools": [],
    },
    {
        "id": "for-002", "name": "Memory Forensics",
        "category": "memory", "severity": "high",
        "desc": "Memory forensics techniques.",
        "detection": (
            "MEMORY FORENSICS:\n"
            "ACQUISITION:\n"
            "  - LiME (Linux Memory Extractor)\n"
            "    # insmod lime.ko path=/tmp/mem.lime format=lime\n"
            "  - WinPmem (Windows)\n"
            "  - DumpIt (Windows GUI)\n"
            "  - VMware: .vmem file\n"
            "  - VirtualBox: VBoxManage debugvm dump\n"
            "VOLATILITY 3:\n"
            "  # Process listing\n"
            "  vol -f mem.raw windows.pslist\n"
            "  vol -f mem.raw windows.pstree\n"
            "  # Network connections\n"
            "  vol -f mem.raw windows.netscan\n"
            "  # DLL listing\n"
            "  vol -f mem.raw windows.dlllist\n"
            "  # Command history\n"
            "  vol -f mem.raw windows.cmdline\n"
            "  # Registry\n"
            "  vol -f mem.raw windows.registry.hivelist\n"
            "  # Malware detection\n"
            "  vol -f mem.raw windows.malfind\n"
            "LINUX:\n"
            "  vol -f mem.raw linux.pslist\n"
            "  vol -f mem.raw linux.bash\n"
            "  vol -f mem.raw linux.check_syscall\n"
            "  vol -f mem.raw linux.lsof\n"
            "INDICATORS:\n"
            "  - Injected code (malfind)\n"
            "  - Hidden processes\n"
            "  - Rootkit artifacts\n"
            "  - Encryption keys\n"
            "  - Credential extraction\n"
            "TOOLS:\n"
            "  Volatility 3, Rekall, LiME, WinPmem"
        ),
        "tools": [],
    },
    {
        "id": "for-003", "name": "Network Forensics",
        "category": "network", "severity": "medium",
        "desc": "Network forensics techniques.",
        "detection": (
            "NETWORK FORENSICS:\n"
            "CAPTURE:\n"
            "  # Full packet capture\n"
            "  tcpdump -i eth0 -w capture.pcap\n"
            "  # Specific traffic\n"
            "  tcpdump -i eth0 host 10.0.0.1 -w host.pcap\n"
            "  # Tshark (command-line Wireshark)\n"
            "  tshark -i eth0 -w capture.pcap\n"
            "ANALYSIS:\n"
            "  - Wireshark (GUI analysis)\n"
            "    # Follow TCP/HTTP streams\n"
            "    # Protocol hierarchy\n"
            "    # IO graphs\n"
            "    # Export objects (HTTP, SMB)\n"
            "  - NetworkMiner (artifact extraction)\n"
            "  - Zeek (protocol analysis)\n"
            "    # Connection logs (conn.log)\n"
            "    # HTTP logs (http.log)\n"
            "    # DNS logs (dns.log)\n"
            "    # SSL/TLS logs (ssl.log)\n"
            "  - Arkime (Moloch) — full PCAP search\n"
            "INDICATORS:\n"
            "  - C2 traffic patterns\n"
            "  - Data exfiltration (large outbound)\n"
            "  - DNS tunneling\n"
            "  - Beaconing behavior\n"
            "  - Lateral movement\n"
            "  - Protocol anomalies\n"
            "FLOW ANALYSIS:\n"
            "  - NetFlow/sFlow/IPFIX\n"
            "  - Communication patterns\n"
            "  - Geographic analysis\n"
            "  - Time-based analysis\n"
            "TOOLS:\n"
            "  Wireshark, Zeek, Arkime, NetworkMiner"
        ),
        "tools": [],
    },
    {
        "id": "for-004", "name": "Log Analysis",
        "category": "logs", "severity": "medium",
        "desc": "Log analysis for forensics.",
        "detection": (
            "LOG ANALYSIS:\n"
            "WINDOWS:\n"
            "  - Event logs (evtx)\n"
            "    # Security: 4624 (logon), 4625 (failed)\n"
            "    # Security: 4688 (process creation)\n"
            "    # Security: 4720 (account creation)\n"
            "    # System: 7045 (service install)\n"
            "    # PowerShell: 4104 (script block)\n"
            "    # Sysmon: 1 (process), 3 (network)\n"
            "  - Tools:\n"
            "    # EvtxECmd (parse evtx)\n"
            "    # Chainsaw (sigma + evtx)\n"
            "    # Hayabusa (fast evtx analysis)\n"
            "    # LogParser\n"
            "LINUX:\n"
            "  - /var/log/auth.log (authentication)\n"
            "  - /var/log/syslog (system events)\n"
            "  - /var/log/secure (RedHat auth)\n"
            "  - journalctl (systemd journal)\n"
            "  - /var/log/apache2/ (web server)\n"
            "  - ~/.bash_history (user commands)\n"
            "  - /var/log/audit/audit.log (auditd)\n"
            "SIEM:\n"
            "  - Splunk queries (SPL)\n"
            "  - Elastic/ELK (KQL/Lucene)\n"
            "  - Sigma rules (universal)\n"
            "TIMELINE:\n"
            "  - Plaso (log2timeline)\n"
            "    # Create super-timeline\n"
            "    # Correlate multiple sources\n"
            "  - Timeline Explorer (GUI)\n"
            "TOOLS:\n"
            "  Chainsaw, Hayabusa, Plaso, Splunk"
        ),
        "tools": [],
    },
    {
        "id": "for-005", "name": "Malware Forensics",
        "category": "malware", "severity": "high",
        "desc": "Malware analysis and forensics.",
        "detection": (
            "MALWARE FORENSICS:\n"
            "TRIAGE:\n"
            "  - File type identification\n"
            "    # file malware.exe\n"
            "    # DIE (Detect It Easy)\n"
            "  - Hash lookup (VirusTotal)\n"
            "  - String extraction\n"
            "    # strings -a malware.exe\n"
            "    # FLOSS (obfuscated strings)\n"
            "  - PE analysis\n"
            "    # pestudio, CFF Explorer\n"
            "    # Import table analysis\n"
            "STATIC:\n"
            "  - Disassembly (IDA Pro, Ghidra)\n"
            "  - Decompilation\n"
            "  - Control flow analysis\n"
            "  - Cross-references\n"
            "  - String decryption\n"
            "  - Config extraction\n"
            "DYNAMIC:\n"
            "  - Sandbox execution\n"
            "    # Cuckoo, ANY.RUN, Joe Sandbox\n"
            "  - Process monitoring (ProcMon)\n"
            "  - Network monitoring (Wireshark)\n"
            "  - Registry monitoring (RegShot)\n"
            "  - API monitoring (API Monitor)\n"
            "  - Debugger (x64dbg, OllyDbg)\n"
            "ANTI-ANALYSIS:\n"
            "  - Packing (UPX, Themida, VMProtect)\n"
            "  - Anti-debug (IsDebuggerPresent)\n"
            "  - Anti-VM (CPUID, registry checks)\n"
            "  - Anti-sandbox (timing, mouse)\n"
            "  - String obfuscation\n"
            "  - Code virtualization\n"
            "TOOLS:\n"
            "  Ghidra, IDA Pro, Cuckoo, FLOSS, x64dbg"
        ),
        "tools": [],
    },
]


class ForensicsDeepKB:
    """Digital forensics knowledge base.

    Provides forensics patterns injected
    into agent prompts.
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
                severity=data.get("severity", "medium"),
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
        lines = ["## Digital Forensics\n"]
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
