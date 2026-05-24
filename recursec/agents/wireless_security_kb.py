"""Wireless security knowledge base.

Deep knowledge about wireless security:
1. WiFi security (WPA/WPA2/WPA3)
2. Bluetooth security
3. RFID/NFC attacks
4. Wireless IDS/monitoring
5. Rogue access point detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WirelessPattern:
    """A wireless security pattern."""
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


WIRELESS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "wl-001", "name": "WiFi Security Assessment",
        "category": "wifi", "severity": "high",
        "desc": "WiFi security testing.",
        "detection": (
            "WIFI SECURITY:\n"
            "RECONNAISSANCE:\n"
            "  # Monitor mode\n"
            "  airmon-ng start wlan0\n"
            "  # Scan for networks\n"
            "  airodump-ng wlan0mon\n"
            "  # Target specific network\n"
            "  airodump-ng -c CHAN --bssid BSSID -w capture wlan0mon\n"
            "WPA/WPA2:\n"
            "  # Capture handshake\n"
            "  aireplay-ng -0 5 -a BSSID wlan0mon  # Deauth\n"
            "  # Wait for handshake in airodump\n"
            "  # Crack with wordlist\n"
            "  aircrack-ng -w wordlist.txt capture.cap\n"
            "  # Hashcat (GPU)\n"
            "  hcxpcapngtool capture.cap -o hash.hc22000\n"
            "  hashcat -m 22000 hash.hc22000 wordlist.txt\n"
            "WPA3:\n"
            "  - SAE (Simultaneous Authentication of Equals)\n"
            "  - Dragonfly handshake\n"
            "  - Dragonblood vulnerabilities\n"
            "  - Side-channel attacks on SAE\n"
            "WPS:\n"
            "  # WPS PIN attack\n"
            "  reaver -i wlan0mon -b BSSID -vv\n"
            "  wash -i wlan0mon  # Find WPS-enabled APs\n"
            "ENTERPRISE (WPA-EAP):\n"
            "  - Evil twin + RADIUS (hostapd-mana)\n"
            "  - EAP downgrade attacks\n"
            "  - Certificate impersonation\n"
            "  - PEAP/MS-CHAPv2 hash capture\n"
            "TOOLS:\n"
            "  aircrack-ng suite, hashcat, hostapd-mana, wifite"
        ),
        "tools": ["aircrack-ng", "hashcat"],
    },
    {
        "id": "wl-002", "name": "Bluetooth Security",
        "category": "bluetooth", "severity": "medium",
        "desc": "Bluetooth security testing.",
        "detection": (
            "BLUETOOTH SECURITY:\n"
            "SCANNING:\n"
            "  # Classic Bluetooth\n"
            "  hcitool scan          # Device discovery\n"
            "  hcitool inq           # Inquiry scan\n"
            "  sdptool browse ADDR   # Service discovery\n"
            "  # BLE (Bluetooth Low Energy)\n"
            "  hcitool lescan\n"
            "  gatttool -b ADDR -I   # Interactive GATT\n"
            "  bettercap -eval 'ble.recon on'\n"
            "ATTACKS:\n"
            "  BLUEJACKING:\n"
            "    - Send unsolicited messages\n"
            "    - OPP (Object Push) abuse\n"
            "  BLUESNARFING:\n"
            "    - Unauthorized data access\n"
            "    - Contact, calendar, email theft\n"
            "  BLUEBORNE:\n"
            "    - Remote code execution via BT\n"
            "    - No pairing required\n"
            "    - CVE-2017-0781 through 0785\n"
            "  KNOB ATTACK:\n"
            "    - Key Negotiation of Bluetooth\n"
            "    - Force 1-byte encryption key\n"
            "  BLE ATTACKS:\n"
            "    - GATT service enumeration\n"
            "    - Characteristic read/write abuse\n"
            "    - Replay attacks\n"
            "    - Eavesdropping (Ubertooth)\n"
            "TOOLS:\n"
            "  hcitool, gatttool, bettercap, Ubertooth"
        ),
        "tools": ["bettercap"],
    },
    {
        "id": "wl-003", "name": "RFID and NFC Attacks",
        "category": "rfid", "severity": "high",
        "desc": "RFID and NFC security testing.",
        "detection": (
            "RFID/NFC ATTACKS:\n"
            "RFID:\n"
            "  LOW FREQUENCY (125kHz):\n"
            "    - Proxmark3: read/clone/emulate\n"
            "    - HID/EM4100 card cloning\n"
            "    - Brute force card IDs\n"
            "  HIGH FREQUENCY (13.56MHz):\n"
            "    - MIFARE Classic (Crypto1 broken)\n"
            "    - MIFARE Classic attacks:\n"
            "      - Darkside attack\n"
            "      - Nested authentication\n"
            "      - Hardnested attack\n"
            "    - MIFARE DESFire\n"
            "    - iCLASS (HID)\n"
            "NFC:\n"
            "  - NFC relay attacks\n"
            "  - NFC data interception\n"
            "  - Tag cloning\n"
            "  - NDEF manipulation\n"
            "  - Payment terminal attacks\n"
            "  - Contactless card skimming\n"
            "TOOLS:\n"
            "  PROXMARK3:\n"
            "    # LF operations\n"
            "    lf search            # Auto-detect\n"
            "    lf hid clone -r ID   # Clone HID\n"
            "    lf em 410x clone -i ID\n"
            "    # HF operations\n"
            "    hf search            # Auto-detect\n"
            "    hf mf autopwn        # MIFARE Classic\n"
            "    hf mf dump           # Dump card\n"
            "  Flipper Zero, ChameleonMini, ACR122U"
        ),
        "tools": ["proxmark3"],
    },
    {
        "id": "wl-004", "name": "Wireless IDS/Monitoring",
        "category": "wids", "severity": "medium",
        "desc": "Wireless intrusion detection.",
        "detection": (
            "WIRELESS IDS/MONITORING:\n"
            "DETECTION:\n"
            "  - Rogue AP detection\n"
            "  - Deauthentication attacks\n"
            "  - Evil twin detection\n"
            "  - Client misbehavior\n"
            "  - Channel interference\n"
            "  - Unusual traffic patterns\n"
            "KISMET:\n"
            "  # Wireless sniffer/IDS\n"
            "  kismet -c wlan0mon\n"
            "  # Detects:\n"
            "  #   - Hidden SSIDs\n"
            "  #   - Probe requests\n"
            "  #   - Deauth floods\n"
            "  #   - WPS activity\n"
            "  #   - Client tracking\n"
            "WIDS RULES:\n"
            "  - BSSID spoofing\n"
            "  - MAC address randomization detection\n"
            "  - Excessive probe requests\n"
            "  - Power level anomalies\n"
            "  - Frame injection detection\n"
            "MONITORING:\n"
            "  - 2.4GHz and 5GHz bands\n"
            "  - Channel hopping\n"
            "  - Spectrum analysis\n"
            "  - Client association tracking\n"
            "  - Handshake capture alerts\n"
            "TOOLS:\n"
            "  Kismet, airmon-ng, Wireshark (wireless), waidps"
        ),
        "tools": ["kismet"],
    },
    {
        "id": "wl-005", "name": "Rogue Access Point",
        "category": "rogue_ap", "severity": "critical",
        "desc": "Rogue access point and evil twin.",
        "detection": (
            "ROGUE ACCESS POINT:\n"
            "EVIL TWIN:\n"
            "  # Create fake AP\n"
            "  # hostapd configuration\n"
            "  interface=wlan0\n"
            "  ssid=TargetNetwork\n"
            "  channel=6\n"
            "  hw_mode=g\n"
            "  # With captive portal\n"
            "  # DNS redirect + phishing page\n"
            "HOSTAPD-MANA:\n"
            "  # Enhanced evil twin\n"
            "  # WPA-EAP credential capture\n"
            "  # Karma attack (respond to all probes)\n"
            "  # MANA: loud mode, karma\n"
            "  # Captures EAP credentials\n"
            "EAPHAMMER:\n"
            "  # Automated evil twin\n"
            "  eaphammer --bssid BSSID --essid SSID --channel 6\n"
            "  # Supports: EAP-PEAP, EAP-TTLS\n"
            "  # Auto-captures credentials\n"
            "DETECTION:\n"
            "  - BSSID comparison\n"
            "  - Signal strength analysis\n"
            "  - Certificate validation\n"
            "  - MAC address verification\n"
            "  - DNS response analysis\n"
            "  - RADIUS server verification\n"
            "MITM:\n"
            "  - SSL stripping\n"
            "  - DNS spoofing\n"
            "  - ARP spoofing\n"
            "  - Traffic inspection\n"
            "  - Credential capture\n"
            "TOOLS:\n"
            "  hostapd-mana, eaphammer, bettercap, wifiphisher"
        ),
        "tools": ["eaphammer", "bettercap"],
    },
]


class WirelessSecurityKB:
    """Wireless security knowledge base.

    Provides wireless security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WirelessPattern] = {}
        self._log = logger.bind(component="wireless_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load wireless patterns."""
        for data in WIRELESS_PATTERNS:
            pattern = WirelessPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[WirelessPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_wireless_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build wireless security prompt."""
        lines = ["## Wireless Security\n"]
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
