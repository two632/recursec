"""Digital forensics knowledge base.

Deep knowledge about digital forensics techniques:
1. Disk and file system forensics
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
        "id": "for-001", "name": "Disk and File System",
        "category": "disk", "severity": "high",
        "desc": "Disk and file system forensics techniques.",
        "detection": (
            "DISK AND FILE SYSTEM FORENSICS:\n"
            "ACQUISITION:\n"
            "  dd if=/dev/sda of=disk.img bs=4M  # Raw image\n"
            "  dc3dd if=/dev/sda of=disk.img hash=sha256 log=log.txt  # Forensic dd\n"
            "  ewfacquire /dev/sda  # E01 format (compressed)\n"
            "  # Always hash before and after\n"
            "  sha256sum /dev/sda\n"
            "  sha256sum disk.img\n"
            "FILE SYSTEM ANALYSIS:\n"
            "  # Autopsy (GUI) — Sleuth Kit frontend\n"
            "  autopsy  # Web-based forensic analysis\n"
            "  # Sleuth Kit (CLI)\n"
            "  fls -r disk.img  # List files (including deleted)\n"
            "  icat disk.img <inode>  # Extract file by inode\n"
            "  tsk_recover -a disk.img output/  # Recover deleted files\n"
            "FILE CARVING:\n"
            "  foremost -i disk.img -o output/  # Carve files by header\n"
            "  scalpel -c scalpel.conf -o output/ disk.img\n"
            "  photorec disk.img  # Data recovery\n"
            "  # Recovers files based on magic bytes\n"
            "TIMELINE:\n"
            "  fls -m / -r disk.img > bodyfile.txt\n"
            "  mactime -b bodyfile.txt -d > timeline.csv\n"
            "  # MACB times: Modified, Accessed, Changed, Born\n"
            "  # MFT analysis (NTFS)\n"
            "  # Journal analysis (ext4)\n"
            "ARTIFACTS:\n"
            "  - $MFT, $LogFile, $UsnJrnl (NTFS)\n"
            "  - Prefetch files (C:\\Windows\\Prefetch\\)\n"
            "  - ShimCache/AmCache\n"
            "  - LNK files (recent files)\n"
            "  - Jump lists (Windows taskbar)\n"
            "  - Recycle Bin ($I/$R files)"
        ),
        "tools": ["autopsy", "sleuthkit", "foremost"],
    },
    {
        "id": "for-002", "name": "Memory Forensics",
        "category": "memory", "severity": "critical",
        "desc": "Memory acquisition and analysis techniques.",
        "detection": (
            "MEMORY FORENSICS:\n"
            "ACQUISITION:\n"
            "  # Linux\n"
            "  dd if=/proc/kcore of=memory.dump  # Kernel memory\n"
            "  LiME (Linux Memory Extractor)  # Kernel module\n"
            "  insmod lime.ko 'path=memory.lime format=lime'\n"
            "  # Windows\n"
            "  winpmem_mini.exe memory.raw\n"
            "  # DumpIt.exe (single click)\n"
            "  # FTK Imager (Forensic Toolkit)\n"
            "VOLATILITY 3:\n"
            "  # Process listing\n"
            "  vol -f memory.raw windows.pslist\n"
            "  vol -f memory.raw windows.pstree\n"
            "  vol -f memory.raw windows.cmdline\n"
            "  # Network connections\n"
            "  vol -f memory.raw windows.netscan\n"
            "  # DLL listing\n"
            "  vol -f memory.raw windows.dlllist\n"
            "  # File scanning\n"
            "  vol -f memory.raw windows.filescan\n"
            "  vol -f memory.raw windows.dumpfiles --pid <pid>\n"
            "  # Registry\n"
            "  vol -f memory.raw windows.registry.hivelist\n"
            "  vol -f memory.raw windows.registry.printkey\n"
            "  # Malware detection\n"
            "  vol -f memory.raw windows.malfind  # Injected code\n"
            "  vol -f memory.raw windows.hollowprocesses\n"
            "  # Strings extraction\n"
            "  strings -e l memory.raw | grep -i password\n"
            "LINUX ANALYSIS:\n"
            "  vol -f memory.raw linux.pslist\n"
            "  vol -f memory.raw linux.bash\n"
            "  vol -f memory.raw linux.lsof"
        ),
        "tools": ["volatility3", "lime"],
    },
    {
        "id": "for-003", "name": "Network Forensics",
        "category": "network", "severity": "high",
        "desc": "Network traffic forensics techniques.",
        "detection": (
            "NETWORK FORENSICS:\n"
            "PACKET CAPTURE:\n"
            "  tcpdump -i any -w capture.pcap\n"
            "  tcpdump -i eth0 -w capture.pcap port 80\n"
            "  tshark -i any -w capture.pcap\n"
            "ANALYSIS:\n"
            "  # Wireshark (GUI)\n"
            "  wireshark capture.pcap\n"
            "  # Tshark (CLI)\n"
            "  tshark -r capture.pcap -Y 'http.request'\n"
            "  tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name\n"
            "  tshark -r capture.pcap -Y 'tcp.flags.syn==1' -T fields -e ip.dst\n"
            "DNS ANALYSIS:\n"
            "  tshark -r capture.pcap -Y 'dns.qry.type==1' -T fields -e dns.qry.name\n"
            "  # DNS tunneling: Long subdomains, high query rate, TXT records\n"
            "  # Entropy analysis of DNS queries\n"
            "HTTP ANALYSIS:\n"
            "  tshark -r capture.pcap -Y 'http' -T fields -e http.request.uri\n"
            "  # Extract files: File → Export Objects → HTTP\n"
            "  # Check for: POST data, cookies, credentials\n"
            "TLS ANALYSIS:\n"
            "  # JA3/JA3S fingerprinting\n"
            "  tshark -r capture.pcap -Y 'tls.handshake.type==1' -T fields -e ja3.hash\n"
            "  # With SSLKEYLOGFILE: Decrypt TLS traffic\n"
            "FLOW ANALYSIS:\n"
            "  # NetFlow/sFlow/IPFIX\n"
            "  nfdump -r nfcapd.2024* -s srcip/flows\n"
            "  # Zeek (Bro) for conn.log, dns.log, http.log\n"
            "  zeek -r capture.pcap\n"
            "  # RITA (Real Intelligence Threat Analytics)\n"
            "  rita import capture.pcap dataset\n"
            "  rita show-beacons dataset"
        ),
        "tools": ["wireshark", "tshark", "zeek"],
    },
    {
        "id": "for-004", "name": "Log Analysis",
        "category": "logs", "severity": "medium",
        "desc": "Log analysis and timeline reconstruction.",
        "detection": (
            "LOG ANALYSIS:\n"
            "WINDOWS LOGS:\n"
            "  # Event Viewer / wevtutil\n"
            "  wevtutil qe Security /f:text /c:100\n"
            "  # Key Event IDs:\n"
            "  4624  # Successful logon\n"
            "  4625  # Failed logon\n"
            "  4648  # Logon using explicit credentials\n"
            "  4672  # Special privileges assigned\n"
            "  4688  # New process created\n"
            "  4697  # Service installed\n"
            "  4698  # Scheduled task created\n"
            "  7045  # Service installed (System)\n"
            "  1102  # Audit log cleared\n"
            "  # Sysmon events:\n"
            "  1  # Process creation\n"
            "  3  # Network connection\n"
            "  7  # Image loaded (DLL)\n"
            "  8  # CreateRemoteThread\n"
            "  11  # File created\n"
            "LINUX LOGS:\n"
            "  /var/log/auth.log  # Authentication\n"
            "  /var/log/syslog  # System\n"
            "  /var/log/secure  # RHEL auth\n"
            "  /var/log/apache2/access.log  # Web\n"
            "  /var/log/audit/audit.log  # Auditd\n"
            "  journalctl -u sshd  # Systemd\n"
            "  last -f /var/log/wtmp  # Login history\n"
            "TIMELINE:\n"
            "  # Plaso (log2timeline)\n"
            "  log2timeline.py timeline.plaso disk.img\n"
            "  psort.py -o l2tcsv timeline.plaso\n"
            "  # Combine: disk + memory + logs + network"
        ),
        "tools": ["plaso", "evtx"],
    },
    {
        "id": "for-005", "name": "Anti-Forensics Detection",
        "category": "anti_forensics", "severity": "critical",
        "desc": "Detecting anti-forensics techniques.",
        "detection": (
            "ANTI-FORENSICS DETECTION:\n"
            "TIMESTAMP MANIPULATION:\n"
            "  - $STANDARD_INFORMATION vs $FILE_NAME (NTFS)\n"
            "  - Timestomping detection (Volatility, MFT analysis)\n"
            "  - Journal/UsnJrnl analysis\n"
            "  - Filesystem vs application timestamps\n"
            "DATA DESTRUCTION:\n"
            "  - Secure delete (sdelete, shred, srm)\n"
            "  - Disk wiping (DBAN, nwipe)\n"
            "  - File slack space analysis\n"
            "  - Unallocated space analysis\n"
            "  - Detect: gaps in file numbering, journal gaps\n"
            "LOG TAMPERING:\n"
            "  - Event log clearing (Event ID 1102)\n"
            "  - Selective log deletion\n"
            "  - Log rotation manipulation\n"
            "  - Detect: gaps in event sequence numbers\n"
            "  - Detect: EventRecordID jumps\n"
            "ENCRYPTION:\n"
            "  - Full disk encryption (BitLocker, LUKS)\n"
            "  - Container encryption (VeraCrypt)\n"
            "  - Detect: entropy analysis\n"
            "  - Detect: known header patterns\n"
            "STEGANOGRAPHY:\n"
            "  - Data hidden in images, audio, video\n"
            "  - Detect: stegdetect, zsteg, binwalk\n"
            "  - Statistical analysis of LSB\n"
            "MEMORY EVASION:\n"
            "  - Fileless malware\n"
            "  - Process injection cleanup\n"
            "  - AMSI bypass\n"
            "  - ETW patching"
        ),
        "tools": ["volatility3", "autopsy"],
    },
]


class ForensicsKB:
    """Digital forensics knowledge base.

    Provides digital forensics patterns
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
        lines = ["## Digital Forensics Techniques\n"]
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
