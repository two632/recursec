"""Wireless security deep-dive knowledge base.

Deep knowledge about wireless security:
1. WiFi attacks (WPA2/WPA3)
2. Bluetooth attacks
3. RFID/NFC attacks
4. Zigbee/Z-Wave attacks
5. Cellular/5G security
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
        "id": "wl-001", "name": "WiFi Attacks",
        "category": "wifi", "severity": "high",
        "desc": "WiFi attack techniques.",
        "detection": (
            "WIFI ATTACKS:\n"
            "RECONNAISSANCE:\n"
            "  # Monitor mode\n"
            "  airmon-ng start wlan0\n"
            "  # Scan networks\n"
            "  airodump-ng wlan0mon\n"
            "  # Target specific AP\n"
            "  airodump-ng -c CHANNEL --bssid BSSID wlan0mon\n"
            "WPA2 PSK:\n"
            "  # Deauth to capture handshake\n"
            "  aireplay-ng -0 5 -a BSSID wlan0mon\n"
            "  # PMKID attack (no client needed)\n"
            "  hcxdumptool -i wlan0mon --enable_status=1\n"
            "  # Crack with hashcat\n"
            "  hashcat -m 22000 capture.hc22000 wordlist.txt\n"
            "WPA2 ENTERPRISE:\n"
            "  - Evil twin AP\n"
            "  - RADIUS credential capture\n"
            "  - Certificate impersonation\n"
            "  # hostapd-mana + freeradius\n"
            "  # eaphammer\n"
            "WPA3:\n"
            "  - Dragonblood attacks\n"
            "  - Downgrade to WPA2\n"
            "  - Side-channel (timing)\n"
            "  - Transition mode abuse\n"
            "EVIL TWIN:\n"
            "  # Create rogue AP\n"
            "  # Captive portal for credentials\n"
            "  # HTTPS stripping\n"
            "  # WiFi Pineapple (automated)\n"
            "TOOLS:\n"
            "  aircrack-ng, hcxtools, eaphammer, WiFi Pineapple"
        ),
        "tools": ["aircrack-ng"],
    },
    {
        "id": "wl-002", "name": "Bluetooth Attacks",
        "category": "bluetooth", "severity": "medium",
        "desc": "Bluetooth attack techniques.",
        "detection": (
            "BLUETOOTH ATTACKS:\n"
            "SCANNING:\n"
            "  # Classic Bluetooth scan\n"
            "  hcitool scan\n"
            "  # BLE scan\n"
            "  hcitool lescan\n"
            "  # Detailed info\n"
            "  hcitool info BD_ADDR\n"
            "  # Service discovery\n"
            "  sdptool browse BD_ADDR\n"
            "CLASSIC BT:\n"
            "  - Bluejacking (unsolicited messages)\n"
            "  - Bluesnarfing (data theft)\n"
            "  - BlueBorne (CVE-2017-0781)\n"
            "  - KNOB attack (key negotiation)\n"
            "  - BIAS (impersonation)\n"
            "BLE (Low Energy):\n"
            "  - GATT service enumeration\n"
            "  - Characteristic read/write\n"
            "  - Eavesdropping (unencrypted)\n"
            "  - Relay attacks\n"
            "  - Firmware extraction\n"
            "  # bettercap BLE module\n"
            "  # GATTacker (MITM)\n"
            "  # BtleJuice (MITM framework)\n"
            "TOOLS:\n"
            "  hcitool, bettercap, GATTacker, BtleJuice"
        ),
        "tools": [],
    },
    {
        "id": "wl-003", "name": "RFID/NFC Attacks",
        "category": "rfid", "severity": "high",
        "desc": "RFID and NFC attack techniques.",
        "detection": (
            "RFID/NFC ATTACKS:\n"
            "LOW FREQUENCY (125kHz):\n"
            "  - EM4100, HID ProxCard cloning\n"
            "  # Proxmark3\n"
            "  lf search          # detect card\n"
            "  lf em 410x read    # read EM4100\n"
            "  lf hid read        # read HID\n"
            "  lf hid clone       # clone to blank card\n"
            "  - Long-range readers (up to 1m)\n"
            "  - Brute force facility codes\n"
            "HIGH FREQUENCY (13.56MHz):\n"
            "  - MIFARE Classic (Crypto1 broken)\n"
            "  # mfoc (nested attack)\n"
            "  # mfcuk (darkside attack)\n"
            "  - MIFARE DESFire (more secure)\n"
            "  - NFC (ISO 14443, 15693)\n"
            "  # Proxmark3, ChameleonMini\n"
            "NFC:\n"
            "  - Tag cloning\n"
            "  - Relay attacks (NFCGate)\n"
            "  - NDEF message manipulation\n"
            "  - Payment card relay\n"
            "  - Android HCE exploitation\n"
            "PHYSICAL:\n"
            "  - Walk-by reading\n"
            "  - Long-range skimming\n"
            "  - Faraday cage evasion\n"
            "  - Implant-based (NFC ring, implant)\n"
            "TOOLS:\n"
            "  Proxmark3, Flipper Zero, ChameleonMini"
        ),
        "tools": [],
    },
    {
        "id": "wl-004", "name": "IoT Wireless (Zigbee/Z-Wave)",
        "category": "iot_wireless", "severity": "medium",
        "desc": "IoT wireless protocol attacks.",
        "detection": (
            "IOT WIRELESS:\n"
            "ZIGBEE:\n"
            "  - Network discovery\n"
            "  - Key extraction (network/link key)\n"
            "  - Replay attacks\n"
            "  - Device impersonation\n"
            "  - Trust center exploitation\n"
            "  # KillerBee framework\n"
            "  # zbstumbler (discovery)\n"
            "  # zbdump (capture)\n"
            "  # zbdsniff (key extraction)\n"
            "  # ApiMote (hardware)\n"
            "Z-WAVE:\n"
            "  - Network key extraction\n"
            "  - Replay attacks\n"
            "  - S0 security downgrade\n"
            "  - S2 key exchange attack\n"
            "  # Z-Wave SDK\n"
            "  # Scapy-radio\n"
            "  # EZ-Wave\n"
            "LORA/LORAWAN:\n"
            "  - ABP session key extraction\n"
            "  - Replay attacks\n"
            "  - Bit-flipping attacks\n"
            "  - Gateway impersonation\n"
            "THREAD/MATTER:\n"
            "  - Commissioning interception\n"
            "  - Network key extraction\n"
            "  - Device impersonation\n"
            "TOOLS:\n"
            "  KillerBee, HackRF, RTL-SDR, ApiMote"
        ),
        "tools": [],
    },
    {
        "id": "wl-005", "name": "Cellular/5G Security",
        "category": "cellular", "severity": "high",
        "desc": "Cellular and 5G security.",
        "detection": (
            "CELLULAR / 5G SECURITY:\n"
            "2G/3G:\n"
            "  - IMSI catcher (Stingray)\n"
            "  - A5/1 encryption broken\n"
            "  - Downgrade attack (force 2G)\n"
            "  - SMS interception\n"
            "  - Location tracking\n"
            "4G/LTE:\n"
            "  - aLTEr attack (DNS redirect)\n"
            "  - ReVoLTE (call eavesdrop)\n"
            "  - IMSI catcher (with relay)\n"
            "  - Diameter protocol attacks\n"
            "  - VoLTE exploitation\n"
            "5G:\n"
            "  - 5G AKA protocol weaknesses\n"
            "  - SUPI/SUCI tracking\n"
            "  - Network slice isolation\n"
            "  - MEC (Multi-access Edge) security\n"
            "  - RAN (Radio Access Network) attacks\n"
            "  - Core network (SBA) attacks\n"
            "SS7/DIAMETER:\n"
            "  - Location tracking\n"
            "  - Call/SMS interception\n"
            "  - Fraud (toll bypass)\n"
            "  - DoS attacks\n"
            "  # SigPloit (SS7/Diameter/GTP)\n"
            "SIM:\n"
            "  - SIM swapping\n"
            "  - SIM cloning\n"
            "  - eSIM vulnerabilities\n"
            "  - SIMJacker\n"
            "TOOLS:\n"
            "  srsRAN, OpenBTS, SigPloit, IMSI-catcher"
        ),
        "tools": [],
    },
]


class WirelessDeepKB:
    """Wireless security deep-dive KB.

    Provides wireless security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WirelessPattern] = {}
        self._log = logger.bind(component="wireless_deep_kb")
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
