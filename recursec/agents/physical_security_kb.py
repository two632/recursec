"""Physical security knowledge base.

Attack patterns for physical security assessments:
1. Physical Access Control Bypass — locks, badges, tailgating
2. Social Engineering (Physical) — pretexting, impersonation
3. Wireless Signal Interception — RF, NFC, badge cloning
4. Surveillance & Counter-Surveillance — cameras, sensors, TSCM
5. Data Center / Server Room Attacks — environmental, physical access
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PhysicalAttackType(str, Enum):
    ACCESS_CONTROL = "access_control"
    SOCIAL_ENGINEERING = "social_engineering"
    SIGNAL_INTERCEPTION = "signal_interception"
    SURVEILLANCE = "surveillance"
    DATA_CENTER = "data_center"


@dataclass
class PhysicalPattern:
    """A physical security attack pattern."""
    name: str = ""
    attack_type: PhysicalAttackType = PhysicalAttackType.ACCESS_CONTROL
    description: str = ""
    detection_strategies: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.attack_type.value,
            "severity": self.severity,
            "detection_count": len(self.detection_strategies),
        }


PHYSICAL_PATTERNS: list[PhysicalPattern] = [
    PhysicalPattern(
        name="Physical Access Control Bypass",
        attack_type=PhysicalAttackType.ACCESS_CONTROL,
        description=(
            "Techniques to bypass physical access controls including "
            "electronic locks, badge readers, biometrics, and mantraps."
        ),
        detection_strategies=[
            "Test badge reader for default credentials (Wiegand protocol)",
            "Check for relay attacks on proximity cards (HID, MIFARE)",
            "Test magnetic lock bypass via REX sensor manipulation",
            "Analyze door gap for latch slip or under-door tools",
            "Test elevator access controls and floor restrictions",
            "Check for badge cloning vulnerability (125kHz vs 13.56MHz)",
            "Assess mantrap/interlock defeat scenarios",
            "Test emergency exit (REX) button accessibility from outside",
        ],
        indicators=[
            "125kHz proximity cards (easily clonable) in use",
            "Badge readers without tamper detection",
            "REX sensors that can be triggered externally",
            "Door gaps allowing latch manipulation",
            "No video surveillance on entry points",
            "Tailgating succeeds without challenge",
        ],
        tools=["proxmark3", "flipper-zero", "hid-iclass-clone",
               "chameleon-mini", "ESPKey"],
        commands=[
            "proxmark3> lf search",
            "proxmark3> hf search",
            "proxmark3> lf em 410x clone --id <card_id>",
            "proxmark3> hf mf autopwn",
            "proxmark3> hf iclass dump",
        ],
        mitre_ids=["T1200"],
        severity="high",
    ),
    PhysicalPattern(
        name="Social Engineering (Physical)",
        attack_type=PhysicalAttackType.SOCIAL_ENGINEERING,
        description=(
            "Physical social engineering techniques: pretexting as "
            "delivery/IT/maintenance, tailgating, dumpster diving, "
            "shoulder surfing, and badge impersonation."
        ),
        detection_strategies=[
            "Test reception desk verification of unscheduled visitors",
            "Attempt tailgating during peak entry/exit times",
            "Test if delivery personnel are escorted to secure areas",
            "Check dumpster/recycling for sensitive documents",
            "Assess badge challenge culture (do employees challenge strangers)",
            "Test pretext scenarios (IT support, fire inspector, vendor)",
            "Check if visitor badges are distinguishable from employee badges",
            "Test after-hours access with social engineering pretexts",
        ],
        indicators=[
            "No visitor log or sign-in process",
            "Visitor badges not visually distinct from employee badges",
            "No escort policy for visitors in secure areas",
            "Sensitive documents in unsecured dumpsters",
            "Employees hold doors without verifying badge",
            "Reception desk unattended during business hours",
        ],
        tools=["badge-printer", "lanyard-set", "clipboard", "high-vis-vest"],
        commands=[
            "# Physical tools, not CLI commands",
            "# Prepare pretext documentation and props",
            "# Create realistic-looking visitor badges",
            "# Photograph facility entry/exit patterns",
            "# Map employee badge-in/badge-out schedules",
        ],
        mitre_ids=["T1566", "T1200"],
        severity="high",
    ),
    PhysicalPattern(
        name="Wireless Signal Interception",
        attack_type=PhysicalAttackType.SIGNAL_INTERCEPTION,
        description=(
            "Intercepting and replaying wireless signals: RFID/NFC "
            "badge cloning, key fob replay, wireless keyboard sniffing, "
            "and Bluetooth device exploitation."
        ),
        detection_strategies=[
            "Scan for 125kHz RFID emissions from badge readers (clonable)",
            "Test NFC (13.56MHz) cards for MIFARE Classic vulnerabilities",
            "Check for wireless keyboards/mice (2.4GHz) vulnerable to sniffing",
            "Analyze Bluetooth devices for pairing vulnerabilities",
            "Test vehicle key fob relay attack feasibility",
            "Scan for ZigBee/Z-Wave IoT devices with default keys",
            "Check for unencrypted wireless security camera feeds",
            "Test garage door opener / gate remote replay attacks",
        ],
        indicators=[
            "MIFARE Classic cards in use (known broken crypto)",
            "Wireless keyboards transmitting keystrokes unencrypted",
            "Bluetooth devices in discoverable mode",
            "Security cameras using unencrypted wireless",
            "Key fobs without rolling code protection",
            "IoT devices with default ZigBee network keys",
        ],
        tools=["proxmark3", "flipper-zero", "hackrf", "ubertooth",
               "mousejack", "crazyradio-pa", "rtl-sdr"],
        commands=[
            "proxmark3> lf search",
            "proxmark3> hf mf chk *1 ? t",
            "ubertooth-scan -U0",
            "rtl_433 -f 433.92M",
            "hackrf_transfer -r capture.raw -f 315000000 -s 2000000",
            "nrf24-scanner.py -c 1-80",
        ],
        mitre_ids=["T1040", "T1200"],
        severity="high",
    ),
    PhysicalPattern(
        name="Surveillance & Counter-Surveillance",
        attack_type=PhysicalAttackType.SURVEILLANCE,
        description=(
            "Physical surveillance techniques and detection of "
            "surveillance countermeasures: camera mapping, sensor "
            "analysis, TSCM sweeps, and covert observation."
        ),
        detection_strategies=[
            "Map all visible and hidden camera positions",
            "Identify camera blind spots and coverage gaps",
            "Check for motion sensors and their detection patterns",
            "Test alarm system bypass (cellular, landline, IP)",
            "Analyze guard patrol schedules and routes",
            "Check for hidden listening devices (TSCM sweep)",
            "Test if security cameras have default credentials",
            "Identify physical security monitoring gaps (shift changes)",
        ],
        indicators=[
            "Camera dead zones in hallways or stairwells",
            "Motion sensors with limited coverage angles",
            "Guard patrols following predictable schedules",
            "Alarm panels accessible without authentication",
            "DVR/NVR with default credentials (admin/admin)",
            "No 24/7 monitoring of security feeds",
        ],
        tools=["rtl-sdr", "spectrum-analyzer", "wifi-analyzer",
               "thermal-camera", "signal-detector"],
        commands=[
            "nmap -p 80,443,554,8080 --script rtsp-url-brute <target>",
            "rtl_power -f 100M:1G:100k -i 10 -g 50 scan.csv",
            "airodump-ng wlan0mon --band abg",
            "iw dev wlan0 scan | grep -i 'camera\\|dvr\\|nvr'",
            "shodan search 'has_screenshot:true org:<target>'",
        ],
        mitre_ids=["T1040", "T1120"],
        severity="medium",
    ),
    PhysicalPattern(
        name="Data Center / Server Room Attacks",
        attack_type=PhysicalAttackType.DATA_CENTER,
        description=(
            "Attacks targeting physical data center infrastructure: "
            "server access, network tap installation, environmental "
            "controls manipulation, and media theft."
        ),
        detection_strategies=[
            "Test server rack physical locks and key management",
            "Check for exposed network ports in common areas",
            "Test if console/KVM ports require authentication",
            "Verify USB port disablement on servers",
            "Check for network tap detection capabilities",
            "Assess environmental control access (HVAC, fire suppression)",
            "Test removable media controls (USB, CD, tape drives)",
            "Verify secure disposal of decommissioned hardware",
        ],
        indicators=[
            "Server racks unlocked or using common keys",
            "Network jacks active in public/shared spaces",
            "KVM/IPMI consoles with default credentials",
            "USB ports enabled on production servers",
            "No network tap detection (802.1X, port security)",
            "HVAC controls accessible without authentication",
        ],
        tools=["lan-turtle", "packet-squirrel", "bash-bunny",
               "usb-rubber-ducky", "throwing-star-lan-tap"],
        commands=[
            "nmap --script ipmi-brute <target>",
            "ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN chassis status",
            "arp-scan --localnet",
            "tcpdump -i eth0 -c 1000 -w capture.pcap",
            "lsusb -v | grep -i 'device\\|serial'",
        ],
        mitre_ids=["T1200", "T1052"],
        severity="high",
    ),
]


def build_physical_security_prompt(
    focus_type: PhysicalAttackType | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with physical security knowledge."""
    lines = ["## Physical Security Knowledge\n"]

    patterns = PHYSICAL_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]

    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nDetection:")
        for strategy in pattern.detection_strategies[:4]:
            lines.append(f"  - {strategy}")
        lines.append("\nIndicators:")
        for indicator in pattern.indicators[:3]:
            lines.append(f"  - {indicator}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("")

    return "\n".join(lines)
