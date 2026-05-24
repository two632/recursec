"""Wireless security knowledge base.

Deep knowledge about wireless security:
1. WiFi security assessment
2. Bluetooth and BLE attacks
3. RFID/NFC security
4. Satellite and radio security
5. Cellular network security
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
        "desc": "WiFi protocol attacks.",
        "detection": (
            "WIFI SECURITY:\n"
            "RECONNAISSANCE:\n"
            "  # airmon-ng start wlan0\n"
            "  # airodump-ng wlan0mon\n"
            "  # Capture networks, clients, signal\n"
            "  # Hidden SSID discovery\n"
            "WPA2-PSK:\n"
            "  - 4-way handshake capture\n"
            "    # airodump-ng -c CH --bssid BSSID wlan0mon\n"
            "    # aireplay-ng -0 5 -a BSSID wlan0mon (deauth)\n"
            "  - PMKID capture (clientless)\n"
            "    # hcxdumptool -i wlan0mon --enable_status=1\n"
            "  - Cracking\n"
            "    # hashcat -m 22000 capture.hc22000 wordlist\n"
            "    # aircrack-ng capture.cap -w wordlist\n"
            "WPA2-ENTERPRISE:\n"
            "  - Evil twin AP\n"
            "    # hostapd-mana\n"
            "    # eaphammer\n"
            "  - RADIUS credential capture\n"
            "  - Certificate validation bypass\n"
            "WPA3:\n"
            "  - Dragonblood attacks\n"
            "  - Downgrade attacks\n"
            "  - Side-channel attacks\n"
            "WPS:\n"
            "  - PIN brute force\n"
            "    # reaver -i wlan0mon -b BSSID\n"
            "    # bully -b BSSID -c CH wlan0mon\n"
            "  - Pixie Dust attack\n"
            "TOOLS:\n"
            "  aircrack-ng suite, hashcat, hostapd-mana"
        ),
        "tools": [],
    },
    {
        "id": "wl-002", "name": "Bluetooth/BLE Attacks",
        "category": "bluetooth", "severity": "medium",
        "desc": "Bluetooth and BLE security.",
        "detection": (
            "BLUETOOTH/BLE ATTACKS:\n"
            "CLASSIC BLUETOOTH:\n"
            "  Discovery:\n"
            "    # hcitool scan\n"
            "    # hcitool inq\n"
            "    # sdptool browse TARGET\n"
            "  Attacks:\n"
            "    - BlueBorne (CVE-2017-0785)\n"
            "    - KNOB attack (key negotiation)\n"
            "    - PIN cracking\n"
            "    - Bluetooth impersonation\n"
            "BLE (Bluetooth Low Energy):\n"
            "  Scanning:\n"
            "    # hcitool lescan\n"
            "    # bettercap ble.recon on\n"
            "  GATT Enumeration:\n"
            "    # gatttool -b TARGET -I\n"
            "    # primary (list services)\n"
            "    # characteristics (list chars)\n"
            "    # char-read-hnd HANDLE\n"
            "  Attacks:\n"
            "    - Sniffing (Ubertooth)\n"
            "    - MITM (btlejack)\n"
            "    - Relay attacks (BLE Relay)\n"
            "    - Characteristic write\n"
            "    - Jamming\n"
            "TOOLS:\n"
            "  Ubertooth, btlejack, bettercap, GATTacker"
        ),
        "tools": [],
    },
    {
        "id": "wl-003", "name": "RFID/NFC Security",
        "category": "rfid_nfc", "severity": "high",
        "desc": "RFID and NFC security.",
        "detection": (
            "RFID/NFC SECURITY:\n"
            "LOW FREQUENCY (125kHz):\n"
            "  - HID/EM4100 card cloning\n"
            "    # Proxmark3: lf search\n"
            "    # Proxmark3: lf em 410x clone\n"
            "  - T55xx tag emulation\n"
            "  - Brute force card IDs\n"
            "HIGH FREQUENCY (13.56MHz):\n"
            "  MIFARE Classic:\n"
            "    # Proxmark3: hf mf autopwn\n"
            "    # Known key attacks\n"
            "    # Nested attack\n"
            "    # Darkside attack\n"
            "    # Hardnested attack\n"
            "  MIFARE DESFire:\n"
            "    # Key diversification\n"
            "    # Side-channel attacks\n"
            "  iCLASS:\n"
            "    # Default key exploitation\n"
            "    # Cloning with Proxmark3\n"
            "NFC:\n"
            "  - Relay attacks\n"
            "    # NFCGate\n"
            "    # Phone-to-phone relay\n"
            "  - Eavesdropping\n"
            "  - Emulation\n"
            "    # Flipper Zero\n"
            "    # ChameleonMini\n"
            "  - Payment card skimming\n"
            "TOOLS:\n"
            "  Proxmark3, Flipper Zero, ChameleonMini, libnfc"
        ),
        "tools": [],
    },
    {
        "id": "wl-004", "name": "SDR and Radio Security",
        "category": "sdr", "severity": "medium",
        "desc": "Software-defined radio security.",
        "detection": (
            "SDR & RADIO SECURITY:\n"
            "EQUIPMENT:\n"
            "  - HackRF One (1MHz-6GHz, TX/RX)\n"
            "  - RTL-SDR (25MHz-1.7GHz, RX only)\n"
            "  - YARD Stick One (sub-1GHz)\n"
            "  - Flipper Zero (sub-1GHz)\n"
            "  - BladeRF (300MHz-3.8GHz)\n"
            "ATTACKS:\n"
            "  Car Key Fobs:\n"
            "    - Rolling code attacks\n"
            "    - RollJam attack\n"
            "    - Signal capture and replay\n"
            "  Garage Doors:\n"
            "    - Fixed code replay\n"
            "    - Brute force\n"
            "  Pagers:\n"
            "    - POCSAG decoding\n"
            "    - FLEX decoding\n"
            "  ADS-B:\n"
            "    - Aircraft tracking\n"
            "    - Message injection\n"
            "    # dump1090\n"
            "  TPMS:\n"
            "    - Tire pressure sensor sniffing\n"
            "    - Vehicle tracking\n"
            "ANALYSIS:\n"
            "  # GNU Radio\n"
            "  # Universal Radio Hacker (URH)\n"
            "  # inspectrum (signal analysis)\n"
            "TOOLS:\n"
            "  HackRF, RTL-SDR, GNU Radio, URH, Flipper Zero"
        ),
        "tools": [],
    },
    {
        "id": "wl-005", "name": "Cellular Network Security",
        "category": "cellular", "severity": "high",
        "desc": "Cellular network security.",
        "detection": (
            "CELLULAR SECURITY:\n"
            "2G (GSM):\n"
            "  - IMSI catching\n"
            "    # OpenBTS, osmocom-bb\n"
            "    # Fake base station\n"
            "  - A5/1 decryption\n"
            "    # Known weaknesses\n"
            "    # Rainbow tables\n"
            "  - SMS interception\n"
            "  - Call interception\n"
            "3G/4G:\n"
            "  - IMSI catcher (Stingray-like)\n"
            "    # srsRAN\n"
            "    # OpenLTE\n"
            "  - Diameter protocol attacks\n"
            "  - GTP tunneling attacks\n"
            "  - SS7 exploitation\n"
            "    # Track location\n"
            "    # Intercept calls/SMS\n"
            "    # Redirect calls\n"
            "5G:\n"
            "  - SUPI exposure\n"
            "  - Downgrade to 4G/3G\n"
            "  - RAN protocol attacks\n"
            "  - Network slicing escape\n"
            "  - API exposure (NEF)\n"
            "SIM:\n"
            "  - SIM cloning\n"
            "  - SIM swapping (social eng)\n"
            "  - eSIM vulnerabilities\n"
            "  - SIMjacker\n"
            "TOOLS:\n"
            "  srsRAN, osmocom, OpenBTS, SigPloit"
        ),
        "tools": [],
    },
]


class WirelessKB:
    """Wireless security knowledge base.

    Provides wireless patterns injected
    into agent prompts.
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
