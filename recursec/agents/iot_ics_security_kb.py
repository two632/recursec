"""IoT/ICS/SCADA security knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class ICSAttackType(str, Enum):
    PROTOCOL = "protocol"
    FIRMWARE = "firmware"
    NETWORK = "network"
    HMI = "hmi"
    SUPPLY_CHAIN = "supply_chain"

@dataclass
class ICSPattern:
    name: str = ""
    attack_type: ICSAttackType = ICSAttackType.PROTOCOL
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

ICS_PATTERNS: list[ICSPattern] = [
    ICSPattern(name="Industrial Protocol Attacks", attack_type=ICSAttackType.PROTOCOL, description="Attack industrial protocols: Modbus (no auth), DNP3, OPC-UA, EtherNet/IP, BACnet, S7comm (Siemens). Most ICS protocols lack authentication and encryption.", techniques=["Modbus: read/write coils and registers (no authentication)", "DNP3: inject control commands, man-in-the-middle", "OPC-UA: certificate manipulation, auth bypass", "S7comm: read/write PLC memory, stop/start PLC", "BACnet: discover and control building automation", "EtherNet/IP: CIP command injection", "MQTT: subscribe to all topics, inject messages", "CoAP: discover and manipulate IoT endpoints"], indicators=["Unusual Modbus function codes (FC5 write, FC6 write)", "DNP3 unsolicited responses", "S7comm read/write operations from unexpected IPs", "MQTT wildcard subscriptions from new clients"], tools=["modbus-cli", "s7comm-plus", "scapy", "plcscan"], commands=["nmap -sV -p 502,102,20000,47808,44818 target", "modbus read 192.168.1.1 0 10", "plcscan -i eth0 192.168.1.0/24"], severity="critical"),
    ICSPattern(name="Firmware Analysis", attack_type=ICSAttackType.FIRMWARE, description="Extract and analyze IoT/ICS firmware: filesystem extraction, hardcoded credentials, backdoor detection, vulnerable libraries, debug interfaces.", techniques=["Firmware extraction via UART/JTAG/SPI flash", "Binwalk extraction of filesystem (SquashFS, JFFS2)", "Hardcoded credential discovery in firmware images", "Binary analysis of proprietary protocols", "Vulnerable library detection (OpenSSL, BusyBox)", "Debug interface discovery (telnet, SSH backdoors)", "Firmware update mechanism analysis", "Bootloader exploitation"], indicators=["Default credentials in shadow/passwd files", "Outdated libraries with known CVEs", "Debug interfaces listening on non-standard ports", "Unencrypted firmware update channels"], tools=["binwalk", "firmware-analysis-toolkit", "firmwalker", "ghidra"], commands=["binwalk -e firmware.bin", "firmwalker extracted_fs/", "strings firmware.bin | grep -i 'password\\|secret\\|key'"], severity="critical"),
    ICSPattern(name="ICS Network Segmentation", attack_type=ICSAttackType.NETWORK, description="Assess ICS network segmentation: IT/OT boundary, Purdue model compliance, DMZ configuration, remote access, wireless security.", techniques=["Map IT/OT network boundary and crossing points", "Verify Purdue model level segregation", "Test DMZ between enterprise and control networks", "Assess remote access mechanisms (VPN, RDP to OT)", "Discover unauthorized wireless access points", "Test network monitoring coverage in OT zone", "Verify OPC-UA server certificate validation", "Check for flat networks bridging IT and OT"], indicators=["Direct connectivity between IT and OT networks", "Missing firewall between Purdue levels", "Remote desktop directly to HMI/SCADA", "Unauthorized WiFi in control system zone"], tools=["nmap", "wireshark", "tcpdump", "zeek"], commands=["nmap -sn -PS 192.168.0.0/16", "tcpdump -i eth0 'port 502 or port 102 or port 20000'"], severity="critical"),
    ICSPattern(name="HMI/SCADA Application", attack_type=ICSAttackType.HMI, description="Attack HMI/SCADA applications: web-based HMI vulnerabilities, default credentials, unpatched SCADA software, historian database access.", techniques=["Web-based HMI: standard web vulns (XSS, SQLi, auth bypass)", "Default credentials on SCADA systems", "Unpatched vulnerabilities in SCADA software (Siemens, Schneider)", "Historian database direct access (OSIsoft PI, Wonderware)", "ActiveX/COM vulnerabilities in legacy HMI clients", "Configuration file extraction with process data", "Alarm system manipulation", "Setpoint modification via HMI access"], indicators=["Default vendor credentials still active", "Unpatched SCADA software versions", "Web HMI accessible from IT network", "Historian database accessible without authentication"], tools=["nuclei", "nikto", "burpsuite", "cisa-advisories"], commands=["nuclei -u http://scada-hmi/ -t http/cves/ -severity critical,high", "nmap -sV -p 80,443,8080,1433,5432 scada-server"], severity="critical"),
    ICSPattern(name="IoT Supply Chain", attack_type=ICSAttackType.SUPPLY_CHAIN, description="IoT supply chain risks: compromised firmware updates, malicious SDK/libraries, counterfeit hardware, weak update mechanisms, third-party component vulnerabilities.", techniques=["Firmware update MITM: intercept and modify OTA updates", "Malicious SDK injection: backdoor in vendor development kit", "Component vulnerability analysis (SBOM-based)", "Counterfeit hardware detection (visual/electrical)", "Cloud backend compromise affecting all devices", "Certificate pinning bypass for update interception", "Side-channel attacks on hardware security modules"], indicators=["Unsigned firmware updates", "HTTP (not HTTPS) update channels", "Missing SBOM documentation", "Third-party components with known CVEs", "Shared certificates across device fleet"], tools=["binwalk", "firmwalker", "syft", "grype"], commands=["syft scan firmware_extracted/ -o json", "grype sbom:firmware_sbom.json"], severity="critical"),
]

def build_iot_ics_prompt(focus_type: ICSAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## IoT/ICS/SCADA Security Knowledge\n"]
    patterns = ICS_PATTERNS if not focus_type else [p for p in ICS_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
