"""Wireless and RF security knowledge base.

Deep knowledge about wireless/RF security:
1. WiFi security (WPA2/WPA3 attacks)
2. Bluetooth/BLE attacks
3. RFID/NFC exploitation
4. Software-Defined Radio (SDR)
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
        "id": "wl-001", "name": "WiFi Security",
        "category": "wifi", "severity": "high",
        "desc": "WiFi security assessment techniques.",
        "detection": (
            "WIFI SECURITY:\n"
            "WPA2 ATTACKS:\n"
            "  # Capture handshake\n"
            "  airmon-ng start wlan0\n"
            "  airodump-ng wlan0mon\n"
            "  airodump-ng -c <CH> --bssid <BSSID> -w capture wlan0mon\n"
            "  # Deauth to force reconnect\n"
            "  aireplay-ng -0 5 -a <BSSID> wlan0mon\n"
            "  # Crack with wordlist\n"
            "  aircrack-ng -w rockyou.txt capture-01.cap\n"
            "  # Hashcat (GPU)\n"
            "  hcxpcapngtool capture-01.cap -o hash.22000\n"
            "  hashcat -m 22000 hash.22000 wordlist.txt\n"
            "WPA3 ATTACKS:\n"
            "  # Dragonblood (SAE vulnerabilities)\n"
            "  # Timing side-channel on SAE\n"
            "  # Downgrade to WPA2\n"
            "  # Implementation-specific bugs\n"
            "WPA ENTERPRISE:\n"
            "  # Evil Twin (hostapd-wpe)\n"
            "  # RADIUS credential capture\n"
            "  # Certificate impersonation\n"
            "  # EAP downgrade attacks\n"
            "ROGUE AP:\n"
            "  # WiFi Pineapple\n"
            "  # hostapd evil twin\n"
            "  # Karma attack (respond to all probes)\n"
            "  # Captive portal phishing\n"
            "TOOLS:\n"
            "  aircrack-ng, hostapd-wpe, hcxtools, WiFi Pineapple"
        ),
        "tools": ["aircrack-ng", "hcxtools"],
    },
    {
        "id": "wl-002", "name": "Bluetooth/BLE Attacks",
        "category": "bluetooth", "severity": "high",
        "desc": "Bluetooth and BLE attack techniques.",
        "detection": (
            "BLUETOOTH/BLE ATTACKS:\n"
            "CLASSIC BLUETOOTH:\n"
            "  # Device scanning\n"
            "  hcitool scan\n"
            "  hcitool inq\n"
            "  # Service discovery\n"
            "  sdptool browse <BDADDR>\n"
            "  # PIN brute force (legacy pairing)\n"
            "  # MITM (KNOB attack — key negotiation)\n"
            "  # BlueBorne (RCE via Bluetooth stack)\n"
            "BLE (Low Energy):\n"
            "  # Scanning\n"
            "  hcitool lescan\n"
            "  # GATT enumeration\n"
            "  gatttool -b <ADDR> --characteristics\n"
            "  # Sniffing with Ubertooth\n"
            "  ubertooth-btle -f -t <ADDR>\n"
            "  # Read/write characteristics\n"
            "  gatttool -b <ADDR> --char-write-req -a <handle> -n <value>\n"
            "  # BLE relay attacks\n"
            "  # GATTacker (MITM)\n"
            "ATTACKS:\n"
            "  - BlueSmack (L2CAP DoS)\n"
            "  - BlueBugging (AT command injection)\n"
            "  - BIAS (impersonation)\n"
            "  - SweynTooth (BLE stack vulns)\n"
            "  - BLURtooth (CTKD bypass)\n"
            "TOOLS:\n"
            "  Ubertooth, GATTacker, BtleJuice, BLESuite"
        ),
        "tools": ["ubertooth"],
    },
    {
        "id": "wl-003", "name": "RFID/NFC Exploitation",
        "category": "rfid", "severity": "high",
        "desc": "RFID and NFC exploitation techniques.",
        "detection": (
            "RFID/NFC EXPLOITATION:\n"
            "RFID (125kHz):\n"
            "  # Low frequency — badge cloning\n"
            "  # Proxmark3 read/write/emulate\n"
            "  proxmark3> lf search\n"
            "  proxmark3> lf em 410x read\n"
            "  proxmark3> lf em 410x clone --id <ID>\n"
            "  # HID Prox II cloning\n"
            "  proxmark3> lf hid read\n"
            "  proxmark3> lf hid clone --r <RAW>\n"
            "  # Long-range readers (2-3 feet)\n"
            "  # Brute force facility codes\n"
            "RFID (13.56MHz):\n"
            "  # MIFARE Classic (cracked)\n"
            "  proxmark3> hf mf chk --1k\n"
            "  proxmark3> hf mf dump\n"
            "  # MIFARE DESFire (more secure)\n"
            "  # iClass cloning\n"
            "NFC:\n"
            "  # NFC relay attack\n"
            "  # NFCGate (Android relay)\n"
            "  # Apple Pay / Google Pay relay\n"
            "  # NDEF message injection\n"
            "  # Tag emulation\n"
            "FLIPPER ZERO:\n"
            "  - Sub-GHz transceiver\n"
            "  - 125kHz RFID\n"
            "  - NFC (13.56MHz)\n"
            "  - Infrared\n"
            "  - GPIO/iButton\n"
            "TOOLS:\n"
            "  Proxmark3, Flipper Zero, libnfc, NFCGate"
        ),
        "tools": ["proxmark3", "flipper-zero"],
    },
    {
        "id": "wl-004", "name": "Software-Defined Radio",
        "category": "sdr", "severity": "medium",
        "desc": "SDR-based RF analysis and attacks.",
        "detection": (
            "SOFTWARE-DEFINED RADIO:\n"
            "HARDWARE:\n"
            "  - RTL-SDR (cheap, receive-only, 24-1766MHz)\n"
            "  - HackRF One (TX+RX, 1MHz-6GHz)\n"
            "  - YARD Stick One (sub-GHz TX+RX)\n"
            "  - BladeRF (MIMO, wide bandwidth)\n"
            "  - LimeSDR (versatile, MIMO)\n"
            "ANALYSIS:\n"
            "  # Spectrum analysis\n"
            "  gqrx  # GUI SDR receiver\n"
            "  # Signal capture and replay\n"
            "  gnuradio  # Signal processing\n"
            "  # Protocol decoding\n"
            "  inspectrum  # Visualize and decode\n"
            "  # Frequency hopping analysis\n"
            "ATTACKS:\n"
            "  - Replay attack (garage doors, key fobs)\n"
            "  - Jamming (illegal but technically possible)\n"
            "  - GPS spoofing\n"
            "  - ADS-B spoofing (aircraft)\n"
            "  - Pager interception\n"
            "  - Two-way radio interception\n"
            "  - Car key relay/capture\n"
            "PROTOCOLS:\n"
            "  - ISM band (433MHz, 868MHz, 915MHz)\n"
            "  - LoRa/LoRaWAN\n"
            "  - Zigbee (2.4GHz)\n"
            "  - Z-Wave (908MHz)\n"
            "  - DECT (1.88-1.9GHz)\n"
            "TOOLS:\n"
            "  GNU Radio, gqrx, Universal Radio Hacker (URH)"
        ),
        "tools": ["gnuradio", "gqrx"],
    },
    {
        "id": "wl-005", "name": "Cellular Security",
        "category": "cellular", "severity": "critical",
        "desc": "Cellular network security techniques.",
        "detection": (
            "CELLULAR SECURITY:\n"
            "2G (GSM):\n"
            "  - A5/1 encryption (broken)\n"
            "  - IMSI catcher (Stingray)\n"
            "  - SMS interception\n"
            "  - Call interception\n"
            "  - Fake BTS (OpenBTS)\n"
            "3G/4G:\n"
            "  - LTE downgrade to 2G\n"
            "  - IMSI catching still works\n"
            "  - Diameter protocol attacks\n"
            "  - VoLTE vulnerabilities\n"
            "  - srsLTE (open-source LTE)\n"
            "5G:\n"
            "  - SUPI/SUCI privacy improvements\n"
            "  - Still vulnerable to downgrade\n"
            "  - Network slicing attacks\n"
            "  - MEC (Multi-access Edge) attacks\n"
            "SS7:\n"
            "  - Location tracking\n"
            "  - SMS interception\n"
            "  - Call redirection\n"
            "  - Subscriber data retrieval\n"
            "  - Most mobile networks vulnerable\n"
            "SIM ATTACKS:\n"
            "  - SIM swap (social engineering carrier)\n"
            "  - SIMjacker (S@T Browser exploit)\n"
            "  - SIM cloning (COMP128 weakness)\n"
            "  - eSIM attacks\n"
            "TOOLS:\n"
            "  srsRAN, OpenBTS, osmocom, SigPloit"
        ),
        "tools": ["srsran", "osmocom"],
    },
]


class WirelessSecurityKB:
    """Wireless security knowledge base.

    Provides wireless/RF security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WirelessPattern] = {}
        self._log = logger.bind(component="wireless_security_kb")
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
        lines = ["## Wireless & RF Security\n"]
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
