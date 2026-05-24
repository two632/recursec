"""Digital forensics knowledge base.

Deep knowledge about digital forensics:
1. Memory forensics
2. Disk forensics
3. Network forensics
4. Malware analysis
5. Anti-forensics detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ForensicsPattern:
    """A forensics pattern."""
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
        "desc": "Memory acquisition and analysis.",
        "detection": (
            "MEMORY FORENSICS:\n"
            "ACQUISITION:\n"
            "  Linux:\n"
            "    # LiME (Linux Memory Extractor)\n"
            "    insmod lime.ko 'path=/tmp/mem.lime format=lime'\n"
            "    # /proc/kcore\n"
            "    # AVML (Acquire Volatile Memory for Linux)\n"
            "  Windows:\n"
            "    # WinPmem\n"
            "    # DumpIt\n"
            "    # FTK Imager\n"
            "    # Magnet RAM Capture\n"
            "  macOS:\n"
            "    # osxpmem\n"
            "    # MacQuisition\n"
            "ANALYSIS (Volatility 3):\n"
            "  Process:\n"
            "    # vol -f mem.raw windows.pslist\n"
            "    # vol -f mem.raw windows.pstree\n"
            "    # vol -f mem.raw windows.cmdline\n"
            "    # vol -f mem.raw windows.dlllist\n"
            "    # vol -f mem.raw linux.pslist\n"
            "  Network:\n"
            "    # vol -f mem.raw windows.netscan\n"
            "    # vol -f mem.raw windows.netstat\n"
            "  Registry:\n"
            "    # vol -f mem.raw windows.registry.hivelist\n"
            "    # vol -f mem.raw windows.registry.printkey\n"
            "  Malware:\n"
            "    # vol -f mem.raw windows.malfind\n"
            "    # vol -f mem.raw windows.hollowprocesses\n"
            "    # vol -f mem.raw yarascan\n"
            "TOOLS:\n"
            "  Volatility3, Rekall, LiME, WinPmem"
        ),
        "tools": [],
    },
    {
        "id": "for-002", "name": "Disk Forensics",
        "category": "disk", "severity": "high",
        "desc": "Disk image acquisition and analysis.",
        "detection": (
            "DISK FORENSICS:\n"
            "ACQUISITION:\n"
            "  # dd if=/dev/sda of=disk.img bs=4M\n"
            "  # dc3dd if=/dev/sda of=disk.img hash=md5\n"
            "  # ewfacquire /dev/sda (E01 format)\n"
            "  # FTK Imager (GUI)\n"
            "FILESYSTEM:\n"
            "  # Autopsy (GUI)\n"
            "  # The Sleuth Kit (CLI)\n"
            "    fls -r -m / disk.img (file listing)\n"
            "    icat disk.img INODE (extract file)\n"
            "    tsk_recover disk.img output/ (recover)\n"
            "  # ext4: debugfs, extundelete\n"
            "  # NTFS: ntfsundelete, ntfs-3g\n"
            "ARTIFACTS:\n"
            "  Windows:\n"
            "    - MFT ($MFT)\n"
            "    - Registry hives\n"
            "    - Event logs (evtx)\n"
            "    - Prefetch files\n"
            "    - Jump lists\n"
            "    - ShellBags\n"
            "    - USB device history\n"
            "    - Browser history\n"
            "  Linux:\n"
            "    - /var/log/ (auth, syslog, messages)\n"
            "    - /etc/passwd, /etc/shadow\n"
            "    - ~/.bash_history\n"
            "    - /tmp\n"
            "    - Cron jobs\n"
            "    - SSH keys and known_hosts\n"
            "TOOLS:\n"
            "  Autopsy, TSK, Plaso, KAPE, X-Ways"
        ),
        "tools": [],
    },
    {
        "id": "for-003", "name": "Network Forensics",
        "category": "network", "severity": "medium",
        "desc": "Network traffic analysis.",
        "detection": (
            "NETWORK FORENSICS:\n"
            "CAPTURE:\n"
            "  # tcpdump -i eth0 -w capture.pcap\n"
            "  # dumpcap -i eth0 -w capture.pcap\n"
            "  # Network TAP (full duplex)\n"
            "  # SPAN port (switch mirror)\n"
            "ANALYSIS:\n"
            "  Wireshark/tshark:\n"
            "    # tshark -r cap.pcap -Y 'http'\n"
            "    # tshark -r cap.pcap -Y 'dns'\n"
            "    # tshark -r cap.pcap -qz conv,tcp\n"
            "    # Protocol hierarchy statistics\n"
            "  NetworkMiner:\n"
            "    # File extraction\n"
            "    # Credential capture\n"
            "    # Host profiling\n"
            "  Zeek (Bro):\n"
            "    # Connection logs (conn.log)\n"
            "    # DNS queries (dns.log)\n"
            "    # HTTP transactions (http.log)\n"
            "    # SSL/TLS (ssl.log)\n"
            "    # File hashes (files.log)\n"
            "INDICATORS:\n"
            "  - C2 beaconing patterns\n"
            "    # Regular interval connections\n"
            "    # Jitter analysis\n"
            "  - DNS tunneling\n"
            "    # Long subdomain names\n"
            "    # High query volume\n"
            "  - Data exfiltration\n"
            "    # Large outbound transfers\n"
            "    # Unusual protocols\n"
            "TOOLS:\n"
            "  Wireshark, Zeek, NetworkMiner, Moloch/Arkime"
        ),
        "tools": [],
    },
    {
        "id": "for-004", "name": "Malware Analysis",
        "category": "malware", "severity": "critical",
        "desc": "Static and dynamic malware analysis.",
        "detection": (
            "MALWARE ANALYSIS:\n"
            "STATIC:\n"
            "  - File identification\n"
            "    # file malware.exe\n"
            "    # sha256sum malware.exe\n"
            "    # ssdeep malware.exe (fuzzy hash)\n"
            "  - String extraction\n"
            "    # strings -a malware.exe\n"
            "    # FLOSS (FireEye Labs Obfuscated\n"
            "    #   String Solver)\n"
            "  - PE analysis\n"
            "    # pestudio, pefile (Python)\n"
            "    # Import table, sections\n"
            "    # Entropy analysis\n"
            "  - Disassembly\n"
            "    # Ghidra, IDA Pro, Radare2\n"
            "    # Control flow analysis\n"
            "    # Function identification\n"
            "DYNAMIC:\n"
            "  - Sandbox execution\n"
            "    # Cuckoo Sandbox\n"
            "    # ANY.RUN\n"
            "    # Joe Sandbox\n"
            "  - API monitoring\n"
            "    # Process Monitor (Windows)\n"
            "    # strace/ltrace (Linux)\n"
            "  - Network monitoring\n"
            "    # FakeNet-NG\n"
            "    # INetSim\n"
            "  - Registry/file monitoring\n"
            "YARA RULES:\n"
            "  - Pattern matching\n"
            "    # rule malware_detect {\n"
            "    #   strings: $s1 = 'malicious'\n"
            "    #   condition: $s1\n"
            "    # }\n"
            "TOOLS:\n"
            "  Ghidra, Cuckoo, YARA, Radare2, FLOSS"
        ),
        "tools": [],
    },
    {
        "id": "for-005", "name": "Anti-Forensics Detection",
        "category": "anti_forensics", "severity": "high",
        "desc": "Detecting anti-forensics techniques.",
        "detection": (
            "ANTI-FORENSICS DETECTION:\n"
            "DATA DESTRUCTION:\n"
            "  - Secure deletion detection\n"
            "    # Check for shred, srm, wipe usage\n"
            "    # MFT entry analysis\n"
            "    # Journal analysis\n"
            "  - Timestamp manipulation\n"
            "    # Timestomp detection\n"
            "    # $SI vs $FN timestamps\n"
            "    # Timeline anomalies\n"
            "  - Log tampering\n"
            "    # Missing log entries\n"
            "    # Log gaps\n"
            "    # Event log clearing events\n"
            "HIDING:\n"
            "  - Alternate Data Streams (NTFS)\n"
            "    # dir /r\n"
            "    # streams.exe (Sysinternals)\n"
            "  - Steganography\n"
            "    # StegDetect, zsteg\n"
            "    # Entropy analysis\n"
            "  - Slack space hiding\n"
            "    # Data in file slack\n"
            "    # Inter-partition gaps\n"
            "  - Rootkits\n"
            "    # chkrootkit, rkhunter\n"
            "    # Cross-view detection\n"
            "OBFUSCATION:\n"
            "  - Encryption detection\n"
            "    # High entropy files\n"
            "    # Known encryption headers\n"
            "  - Packing detection\n"
            "    # UPX, Themida\n"
            "    # Entropy per section\n"
            "  - Process injection\n"
            "    # Hollow process detection\n"
            "    # DLL injection artifacts\n"
            "TOOLS:\n"
            "  Autopsy, Plaso, KAPE, timestomp-detect"
        ),
        "tools": [],
    },
]


class ForensicsKB:
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
