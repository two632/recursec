"""Digital forensics knowledge base — memory, disk, network, mobile forensics."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class ForensicsType(str, Enum):
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    MOBILE = "mobile"
    MALWARE = "malware"

@dataclass
class ForensicsPattern:
    name: str = ""
    forensics_type: ForensicsType = ForensicsType.MEMORY
    description: str = ""
    methodology: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.forensics_type.value, "severity": self.severity}

FORENSICS_PATTERNS: list[ForensicsPattern] = [
    ForensicsPattern(name="Memory Forensics", forensics_type=ForensicsType.MEMORY, description="Volatile memory analysis: process listing, DLL injection detection, rootkit discovery, credential extraction, network connections, command history.", methodology=["Acquire memory dump (winpmem, LiME, DumpIt)", "Identify OS profile/symbol table", "List processes and detect anomalies (hidden, injected)", "Scan for malware signatures and injected code", "Extract network connections and DNS cache", "Recover credentials from LSASS, registry hives", "Analyze kernel modules for rootkits", "Timeline analysis of memory artifacts"], artifacts=["Process list (including hidden)", "DLL list and injected code regions", "Network connections (TCP, UDP, raw)", "Open file handles", "Registry hives in memory", "Cached credentials (NTLM hashes)", "Command history (cmd, PowerShell)"], tools=["volatility3", "rekall", "winpmem", "lime"], commands=["vol3 -f memory.dmp windows.pslist", "vol3 -f memory.dmp windows.malfind", "vol3 -f memory.dmp windows.netscan", "vol3 -f memory.dmp windows.hashdump"], severity="high"),
    ForensicsPattern(name="Disk Forensics", forensics_type=ForensicsType.DISK, description="Disk image analysis: file recovery, timeline generation, artifact extraction, deleted file recovery, registry analysis, browser forensics.", methodology=["Create forensic image (dd, FTK Imager, ewfacquire)", "Verify image hash integrity", "Mount image read-only", "Extract filesystem timeline (MFT, journal)", "Recover deleted files and slack space", "Analyze registry hives for user activity", "Extract browser history, downloads, cache", "Analyze prefetch files for execution history", "Check for encryption (BitLocker, LUKS)"], artifacts=["$MFT (Master File Table) entries", "NTFS journal ($UsnJrnl, $LogFile)", "Prefetch files (C:\\Windows\\Prefetch)", "Registry hives (SYSTEM, SAM, SOFTWARE, NTUSER)", "Browser databases (Chrome History, Firefox places.sqlite)", "Recent documents and LNK files", "Recycle Bin ($I and $R files)", "Volume Shadow Copies"], tools=["autopsy", "sleuthkit", "ftk-imager", "plaso"], commands=["fls -r -m / image.dd", "icat image.dd inode_number > recovered_file", "log2timeline.py plaso.dump image.dd", "psort.py -o l2tcsv plaso.dump"], severity="high"),
    ForensicsPattern(name="Network Forensics", forensics_type=ForensicsType.NETWORK, description="Network traffic analysis: packet capture analysis, flow analysis, protocol reconstruction, C2 detection, data exfiltration detection.", methodology=["Capture network traffic (tcpdump, Wireshark)", "Analyze flow data (NetFlow, sFlow)", "Reconstruct sessions and extract files", "Identify C2 beaconing patterns", "Detect data exfiltration (DNS, HTTPS, ICMP)", "Analyze SSL/TLS certificates and JA3 hashes", "Correlate with threat intelligence feeds", "Timeline network events with system events"], artifacts=["PCAP files", "NetFlow records", "DNS query logs", "HTTP request/response pairs", "TLS certificates and JA3/JA3S hashes", "Extracted files from streams", "Beaconing patterns (interval, jitter)"], tools=["wireshark", "zeek", "suricata", "networkminer"], commands=["tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri", "zeek -r capture.pcap", "suricata -r capture.pcap -l /tmp/suricata/"], severity="high"),
    ForensicsPattern(name="Mobile Forensics", forensics_type=ForensicsType.MOBILE, description="Mobile device forensics: iOS/Android data extraction, app analysis, communication recovery, location tracking, cloud data.", methodology=["Preserve device state (airplane mode, Faraday bag)", "Identify device model and OS version", "Logical acquisition (backup-based extraction)", "Physical acquisition (chip-off, JTAG, ISP)", "Parse application databases (SQLite)", "Recover deleted messages and media", "Extract location data (GPS, WiFi, cell tower)", "Analyze cloud accounts (iCloud, Google)"], artifacts=["SMS/MMS messages and iMessage", "WhatsApp/Telegram/Signal databases", "Call history and contacts", "GPS coordinates and location history", "Photos with EXIF metadata", "Application data and preferences", "Browser history and bookmarks", "Keychain/credential stores"], tools=["mvt", "andriller", "aleapp", "ileapp"], commands=["mvt-android check-adb", "mvt-ios check-backup --output /tmp/mvt/ backup/", "aleapp -t csv -i android_extraction/ -o /tmp/aleapp/"], severity="high"),
    ForensicsPattern(name="Malware Analysis", forensics_type=ForensicsType.MALWARE, description="Malware analysis: static analysis, dynamic analysis, behavioral analysis, network traffic analysis, code reverse engineering.", methodology=["Triage: file type, hashes, VirusTotal check", "Static analysis: strings, imports, PE headers, signatures", "Behavioral analysis: sandbox execution (AnyRun, Cuckoo)", "Dynamic analysis: debug and trace execution", "Network analysis: capture C2 traffic in sandbox", "Code analysis: decompile and reverse engineer", "Unpack/deobfuscate if packed/encrypted", "Write YARA rules for detection"], artifacts=["File hashes (MD5, SHA256)", "Imported functions and libraries", "Embedded strings and URLs", "Network indicators (C2 IPs, domains)", "Dropped files and registry changes", "Mutex names and named pipes", "PE compilation timestamp", "Code signing certificate"], tools=["ghidra", "ida-free", "radare2", "cuckoo", "yara"], commands=["strings malware.exe | head -100", "rabin2 -I malware.exe", "radare2 -A malware.exe -c 'afl'", "yara rules.yar /path/to/scan/"], severity="high"),
]

def build_forensics_prompt(focus_type: ForensicsType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Digital Forensics Knowledge\n"]
    patterns = FORENSICS_PATTERNS if not focus_type else [p for p in FORENSICS_PATTERNS if p.forensics_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nMethodology:")
        for m in p.methodology[:4]:
            lines.append(f"  - {m}")
        lines.append("")
    return "\n".join(lines)
