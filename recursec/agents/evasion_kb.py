"""Evasion techniques knowledge base — AV/EDR/WAF/IDS bypass."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class EvasionTarget(str, Enum):
    AV_EDR = "av_edr"
    WAF = "waf"
    IDS_IPS = "ids_ips"
    SANDBOX = "sandbox"
    LOGGING = "logging"

@dataclass
class EvasionPattern:
    name: str = ""
    target: EvasionTarget = EvasionTarget.AV_EDR
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "target": self.target.value, "severity": self.severity}

EVASION_PATTERNS: list[EvasionPattern] = [
    EvasionPattern(name="AV/EDR Evasion", target=EvasionTarget.AV_EDR, description="Bypass antivirus and endpoint detection: AMSI bypass, ETW patching, unhooking ntdll, direct syscalls, process injection, sleep obfuscation, in-memory execution.", techniques=["AMSI bypass: patch AmsiScanBuffer to return clean result", "ETW patching: disable Event Tracing for Windows logging", "Unhooking: map fresh ntdll.dll from disk to remove EDR hooks", "Direct syscalls: use syscall stubs instead of Win32 API", "Process hollowing: inject code into suspended legitimate process", "Thread stack spoofing: fake call stack to appear legitimate", "Sleep obfuscation: encrypt payload during sleep to evade scanning", "Shellcode loading: VirtualAlloc + copy + CreateThread pattern", "PE loading: reflective DLL injection from memory", "Module stomping: overwrite legitimate module in memory"], detection=["Monitor for AMSI/ETW patching attempts", "Detect ntdll remapping via file access patterns", "Track unusual memory allocation patterns (RWX)", "Monitor for process hollowing indicators", "Kernel callbacks for process/thread creation"], tools=["scarecrow", "donut", "sharpblock", "syscallwhispers"], commands=["ScareCrow -I payload.bin -Loader binary -domain microsoft.com", "donut -f assembly.exe -o loader.bin"], severity="high"),
    EvasionPattern(name="WAF Bypass", target=EvasionTarget.WAF, description="Bypass web application firewalls: encoding tricks, HTTP parameter pollution, chunked transfer, Unicode normalization, comment injection, case variation, HTTP smuggling.", techniques=["URL encoding: double/triple encode payloads", "Unicode normalization: use equivalent Unicode chars", "HTTP parameter pollution: duplicate params to confuse parser", "Chunked transfer encoding: split payload across chunks", "Comment injection: SQL comments (/**/), HTML comments", "Case variation: SeLeCt, ScRiPt", "HTTP smuggling: CL/TE or TE/CL desync", "JSON/XML content type confusion", "Multipart form data boundary manipulation", "Null byte injection: terminate string processing", "Path normalization: /./path/../path confusion", "IP-based bypass: X-Forwarded-For, X-Real-IP spoofing"], detection=["Deploy WAF in learning mode first", "Test with known bypass techniques", "Monitor for encoding anomalies", "Validate both decoded and raw input", "Test HTTP smuggling vectors"], tools=["wafw00f", "wafwoof", "bypass-firewalls-by-dns-history"], commands=["wafw00f https://target.com", "sqlmap -u 'target' --tamper=charencode,between,randomcase"], severity="high"),
    EvasionPattern(name="IDS/IPS Evasion", target=EvasionTarget.IDS_IPS, description="Bypass intrusion detection: packet fragmentation, TTL manipulation, protocol-level evasion, encrypted channels, polymorphic traffic.", techniques=["IP fragmentation: split payload across fragments", "TTL manipulation: different TTL values cause reassembly confusion", "TCP segmentation: split across multiple segments", "Overlapping fragments: ambiguous reassembly", "Encrypted C2: TLS/SSL for command and control", "Domain fronting: hide C2 behind legitimate CDN", "DNS tunneling: encode data in DNS queries", "Protocol tunneling: HTTP over DNS, TCP over ICMP", "Timing-based evasion: slow scan below threshold", "Decoy scanning: generate noise to hide real scan"], detection=["Test IDS with known evasion frameworks", "Verify fragment reassembly handling", "Check for encrypted traffic inspection", "Monitor for DNS tunneling patterns", "Validate slow-scan detection"], tools=["fragroute", "nmap", "scapy"], commands=["nmap -f --mtu 16 -T2 --data-length 24 target", "fragroute -f fragroute.conf target"], severity="high"),
    EvasionPattern(name="Sandbox Evasion", target=EvasionTarget.SANDBOX, description="Detect and evade analysis sandboxes: environment checks, timing attacks, user interaction requirements, hardware fingerprinting, anti-debug.", techniques=["Registry checks: look for VM-related registry keys", "Process checks: look for analysis tools (procmon, wireshark)", "Hardware fingerprinting: check CPU count, RAM, disk size", "Timing attacks: RDTSC-based VM detection, sleep acceleration", "User interaction: require mouse movement/clicks before execution", "Network checks: verify internet connectivity and DNS resolution", "File system checks: look for sandbox artifacts", "Anti-debug: IsDebuggerPresent, NtQueryInformationProcess", "Delayed execution: sleep for extended period before payload", "Geofencing: check IP geolocation before executing"], detection=["Test malware in multiple sandbox environments", "Check for sandbox detection code patterns", "Monitor for environment fingerprinting APIs", "Verify sandbox has realistic environment"], tools=["al-khaser", "pafish", "sboxie-detect"], commands=["python3 -c 'import os; print(os.cpu_count()); # sandbox usually has 1-2 CPUs'"], severity="medium"),
    EvasionPattern(name="Log Evasion", target=EvasionTarget.LOGGING, description="Evade logging and monitoring: event log clearing, Sysmon bypass, audit policy manipulation, timestomping, log injection.", techniques=["Event log clearing: wevtutil cl Security", "Sysmon config bypass: identify blind spots in config", "Audit policy disabling: auditpol /set to disable auditing", "Timestomping: modify file timestamps to blend in", "Log injection: inject fake entries to confuse analysts", "ETW provider disabling: blind specific telemetry sources", "Process ghosting: delete file before image is mapped", "Phantom DLL loading: load from non-standard paths"], detection=["Monitor for log clearing events (Event ID 1102)", "Detect audit policy changes", "Track ETW provider modifications", "Alert on timestamp modifications", "Forward logs to immutable SIEM"], tools=["invoke-phant0m", "timestomp", "eventcleaner"], commands=["wevtutil cl Security", "auditpol /set /subcategory:'Process Creation' /success:disable"], severity="high"),
]

def build_evasion_prompt(focus_target: EvasionTarget | None = None, max_patterns: int = 5) -> str:
    lines = ["## Evasion Techniques Knowledge\n"]
    patterns = EVASION_PATTERNS if not focus_target else [p for p in EVASION_PATTERNS if p.target == focus_target]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
