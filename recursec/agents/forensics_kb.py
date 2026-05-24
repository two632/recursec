"""Digital forensics knowledge base.

Deep knowledge about digital forensics:
1. Disk forensics
2. Memory forensics
3. Network forensics
4. Log analysis and timeline
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
        "id": "for-001", "name": "Disk Forensics",
        "category": "disk", "severity": "high",
        "desc": "Disk and filesystem forensics.",
        "detection": (
            "DISK FORENSICS:\n"
            "ACQUISITION:\n"
            "  # Create forensic image\n"
            "  dd if=/dev/sda of=disk.raw bs=4M conv=noerror,sync\n"
            "  dc3dd if=/dev/sda of=disk.raw log=acquisition.log\n"
            "  ewfacquire /dev/sda  # E01 format (compressed)\n"
            "  # Verify with hash\n"
            "  sha256sum disk.raw\n"
            "  # Write blocker: use hardware or software\n"
            "ANALYSIS:\n"
            "  # Autopsy (GUI)\n"
            "  autopsy  # Sleuth Kit GUI\n"
            "  # The Sleuth Kit (CLI)\n"
            "  mmls disk.raw           # Partition table\n"
            "  fls -o 2048 disk.raw    # File listing\n"
            "  icat -o 2048 disk.raw 65  # Extract file by inode\n"
            "FILE CARVING:\n"
            "  # Recover deleted files\n"
            "  scalpel disk.raw -o output/\n"
            "  photorec disk.raw\n"
            "  foremost -i disk.raw -o output/\n"
            "FILESYSTEM:\n"
            "  - NTFS: $MFT, $LogFile, $UsnJrnl\n"
            "  - EXT4: journal, inodes, superblock\n"
            "  - APFS: snapshots, encryption\n"
            "  - FAT: directory entries, clusters\n"
            "ARTIFACTS:\n"
            "  - Browser history/cache/cookies\n"
            "  - Registry hives (Windows)\n"
            "  - Prefetch files (execution history)\n"
            "  - LNK files (recent files)\n"
            "  - Jump Lists, Shellbags\n"
            "  - Recycle Bin ($I/$R files)\n"
            "TOOLS:\n"
            "  Autopsy/TSK, FTK, EnCase, AXIOM, scalpel"
        ),
        "tools": ["autopsy", "scalpel"],
    },
    {
        "id": "for-002", "name": "Memory Forensics",
        "category": "memory", "severity": "high",
        "desc": "Memory forensics techniques.",
        "detection": (
            "MEMORY FORENSICS:\n"
            "ACQUISITION:\n"
            "  # Linux\n"
            "  dd if=/dev/mem of=memdump.raw\n"
            "  avml -o memdump.raw  # Azure VM mem acquisition\n"
            "  lime  # Linux Memory Extractor (kernel module)\n"
            "  # Windows\n"
            "  winpmem_mini_x64.exe memdump.raw\n"
            "  DumpIt.exe  # One-click dump\n"
            "  # Crash dumps, hibernation files\n"
            "ANALYSIS (Volatility 3):\n"
            "  vol -f memdump.raw windows.info\n"
            "  vol -f memdump.raw windows.pslist    # Process list\n"
            "  vol -f memdump.raw windows.pstree    # Process tree\n"
            "  vol -f memdump.raw windows.netscan   # Network connections\n"
            "  vol -f memdump.raw windows.malfind   # Injected code\n"
            "  vol -f memdump.raw windows.dlllist   # Loaded DLLs\n"
            "  vol -f memdump.raw windows.handles   # Open handles\n"
            "  vol -f memdump.raw windows.cmdline   # Command lines\n"
            "  vol -f memdump.raw windows.registry.hivelist\n"
            "KEY ARTIFACTS:\n"
            "  - Process hollowing (malfind)\n"
            "  - DLL injection (dlllist + handles)\n"
            "  - Hidden processes (psxview)\n"
            "  - Network connections (netscan)\n"
            "  - Registry keys in memory\n"
            "  - Encryption keys (aeskeyfind)\n"
            "  - Passwords in memory\n"
            "TOOLS:\n"
            "  Volatility3, Rekall, MemProcFS, WinDbg"
        ),
        "tools": ["volatility"],
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
            "  dumpcap -i eth0 -w capture.pcap\n"
            "  # Netflow/IPFIX (metadata only)\n"
            "  # DNS logs (passive DNS)\n"
            "ANALYSIS:\n"
            "  # Wireshark (GUI)\n"
            "  wireshark capture.pcap\n"
            "  # tshark (CLI)\n"
            "  tshark -r capture.pcap -Y 'http.request'\n"
            "  tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name\n"
            "  # NetworkMiner\n"
            "  # Zeek (Bro) — protocol analysis\n"
            "  zeek -r capture.pcap\n"
            "  # Generates: conn.log, dns.log, http.log, etc.\n"
            "INVESTIGATION:\n"
            "  - C2 communication patterns\n"
            "  - Data exfiltration (large outbound transfers)\n"
            "  - DNS tunneling (long subdomain queries)\n"
            "  - Beaconing (regular interval connections)\n"
            "  - Lateral movement (SMB, RDP, WinRM)\n"
            "  - Encrypted C2 (JA3/JA4 TLS fingerprints)\n"
            "FLOW:\n"
            "  - Connection timing analysis\n"
            "  - Unusual port usage\n"
            "  - Geographic anomalies\n"
            "  - Volume anomalies\n"
            "TOOLS:\n"
            "  Wireshark, tcpdump, Zeek, NetworkMiner, RITA"
        ),
        "tools": ["wireshark", "zeek"],
    },
    {
        "id": "for-004", "name": "Log Analysis and Timeline",
        "category": "logs", "severity": "medium",
        "desc": "Log analysis and timeline reconstruction.",
        "detection": (
            "LOG ANALYSIS AND TIMELINE:\n"
            "WINDOWS LOGS:\n"
            "  - Security.evtx (logon, policy changes)\n"
            "  - System.evtx (services, drivers)\n"
            "  - Application.evtx\n"
            "  - PowerShell/Operational.evtx\n"
            "  - Sysmon (if installed — process creation, network)\n"
            "  KEY EVENT IDs:\n"
            "    4624: Successful logon\n"
            "    4625: Failed logon\n"
            "    4688: Process creation\n"
            "    4720: User account created\n"
            "    4732: Member added to group\n"
            "    7045: Service installed\n"
            "    1102: Audit log cleared\n"
            "LINUX LOGS:\n"
            "  - /var/log/auth.log (authentication)\n"
            "  - /var/log/syslog or /var/log/messages\n"
            "  - /var/log/kern.log (kernel)\n"
            "  - /var/log/apache2/ or /var/log/nginx/\n"
            "  - journalctl (systemd)\n"
            "  - .bash_history, .zsh_history\n"
            "TIMELINE:\n"
            "  # Plaso/log2timeline\n"
            "  log2timeline.py timeline.plaso disk.raw\n"
            "  psort.py -o l2tcsv timeline.plaso -w timeline.csv\n"
            "  # Timeline Explorer (view in Excel)\n"
            "  # Timesketch (web UI)\n"
            "TOOLS:\n"
            "  Plaso/log2timeline, Timesketch, Chainsaw, hayabusa"
        ),
        "tools": ["plaso", "chainsaw"],
    },
    {
        "id": "for-005", "name": "Anti-Forensics Detection",
        "category": "anti_forensics", "severity": "high",
        "desc": "Detecting anti-forensics techniques.",
        "detection": (
            "ANTI-FORENSICS DETECTION:\n"
            "TECHNIQUES:\n"
            "  TIMESTOMPING:\n"
            "    - Modified file timestamps\n"
            "    - Detect: compare $MFT vs $STDINFO timestamps\n"
            "    - $MFT $FN timestamps cannot be easily modified\n"
            "    - Mismatched created/modified dates\n"
            "  LOG CLEARING:\n"
            "    - Event ID 1102 (Security log cleared)\n"
            "    - Event ID 104 (System log cleared)\n"
            "    - Gap analysis in log timeline\n"
            "    - wevtutil cl Security\n"
            "  DATA DESTRUCTION:\n"
            "    - Secure deletion tools (BleachBit, SDelete)\n"
            "    - Full disk encryption (post-incident)\n"
            "    - File wiping (shred, wipe)\n"
            "    - Overwritten slack space\n"
            "  HIDING:\n"
            "    - Alternate Data Streams (NTFS ADS)\n"
            "    - Hidden partitions\n"
            "    - Steganography (data in images)\n"
            "    - Encrypted containers (VeraCrypt)\n"
            "    - Slack space hiding\n"
            "  LIVING OFF THE LAND:\n"
            "    - Using built-in tools (PowerShell, WMI)\n"
            "    - Fileless malware (memory only)\n"
            "    - DLL sideloading\n"
            "    - No new files on disk\n"
            "DETECTION:\n"
            "  - $MFT timeline analysis\n"
            "  - USN Journal analysis\n"
            "  - Memory forensics (fileless detection)\n"
            "  - Entropy analysis (encrypted data)\n"
            "  - YARA rules for known tools\n"
            "TOOLS:\n"
            "  Timestomp Detector, ADS Scanner, stegdetect"
        ),
        "tools": [],
    },
]


class ForensicsKB:
    """Digital forensics knowledge base.

    Provides forensics patterns injected into agent prompts.
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
