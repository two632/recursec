"""Wireless security knowledge base.

Deep knowledge about wireless attack vectors:
1. WiFi attacks (WPA2/WPA3, Evil Twin, PMKID)
2. Bluetooth exploitation
3. Zigbee/Z-Wave attacks
4. Cellular network attacks
5. RFID/NFC security
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
    protocol: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "protocol": self.protocol[:10],
        }


WIRELESS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "wifi-001", "name": "WPA2 PMKID Attack",
        "protocol": "wifi", "severity": "high",
        "desc": "Capturing PMKID for offline WPA2 cracking.",
        "detection": (
            "WPA2 PMKID ATTACK:\n"
            "CAPTURE:\n"
            "  # Put interface in monitor mode\n"
            "  airmon-ng start wlan0\n"
            "  # Capture PMKID (no client needed)\n"
            "  hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1\n"
            "  # Extract hash for hashcat\n"
            "  hcxpcapngtool -o hash.22000 capture.pcapng\n"
            "CRACKING:\n"
            "  hashcat -m 22000 hash.22000 <wordlist>\n"
            "  hashcat -m 22000 hash.22000 -a 3 ?d?d?d?d?d?d?d?d  # 8-digit\n"
            "ADVANTAGES:\n"
            "  - No client deauthentication needed\n"
            "  - Single frame capture sufficient\n"
            "  - Works against most WPA2 networks\n"
            "DETECTION:\n"
            "  - Monitor for unusual association attempts\n"
            "  - IDS alerts for PMKID capture attempts"
        ),
        "tools": ["hcxdumptool", "hcxpcapngtool", "hashcat"],
    },
    {
        "id": "wifi-002", "name": "Evil Twin / Rogue AP",
        "protocol": "wifi", "severity": "critical",
        "desc": "Creating fake access point for MITM attacks.",
        "detection": (
            "EVIL TWIN ATTACK:\n"
            "SETUP:\n"
            "  # Create fake AP matching target SSID\n"
            "  hostapd evil_twin.conf\n"
            "  # Start DHCP server\n"
            "  dnsmasq -C dnsmasq.conf\n"
            "  # Enable NAT/routing\n"
            "  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
            "CAPTIVE PORTAL:\n"
            "  - Serve fake login page matching target portal\n"
            "  - Capture credentials when user authenticates\n"
            "  - Tools: wifiphisher, fluxion, airgeddon\n"
            "KARMA ATTACK:\n"
            "  - Respond to ALL probe requests\n"
            "  - Devices auto-connect to 'known' networks\n"
            "  - Tool: hostapd-mana\n"
            "TRAFFIC INTERCEPTION:\n"
            "  - All client traffic passes through attacker\n"
            "  - SSL stripping: sslstrip\n"
            "  - DNS spoofing: modify dnsmasq for specific domains\n"
            "  - Credential capture: ettercap, bettercap"
        ),
        "tools": ["hostapd", "wifiphisher", "bettercap"],
    },
    {
        "id": "wifi-003", "name": "WPA3 Dragonblood Attacks",
        "protocol": "wifi", "severity": "high",
        "desc": "Attacking WPA3's Dragonfly handshake.",
        "detection": (
            "WPA3 DRAGONBLOOD:\n"
            "ATTACKS:\n"
            "  Side-channel (CVE-2019-9494):\n"
            "    - Timing and cache-based side channels\n"
            "    - Leak information about password during SAE handshake\n"
            "    - Requires physical proximity\n"
            "  Downgrade (CVE-2019-9496):\n"
            "    - Force WPA3-capable device to use WPA2\n"
            "    - Then apply traditional WPA2 attacks\n"
            "    - Transition mode exploitation\n"
            "  Group Downgrade:\n"
            "    - Force use of weaker elliptic curve group\n"
            "    - Reduces brute-force complexity\n"
            "  DoS:\n"
            "    - SAE handshake is computationally expensive\n"
            "    - Flood with commit messages → CPU exhaustion\n"
            "TESTING:\n"
            "  - Check if WPA3 transition mode is enabled\n"
            "  - Test downgrade to WPA2 with deauth + probe\n"
            "  - Use dragonslayer/dragonforce tools\n"
            "  - Monitor for WPA3-SAE timing variations"
        ),
        "tools": ["dragonslayer", "dragonforce", "aircrack-ng"],
    },
    {
        "id": "ble-001", "name": "Bluetooth Low Energy Exploitation",
        "protocol": "ble", "severity": "high",
        "desc": "BLE protocol security weaknesses.",
        "detection": (
            "BLE EXPLOITATION:\n"
            "SCANNING:\n"
            "  hcitool lescan  # Discover BLE devices\n"
            "  bettercap -eval 'ble.recon on'  # Active scanning\n"
            "  btlejack -d <device_addr>  # Sniff connections\n"
            "GATT ENUMERATION:\n"
            "  gatttool -b <device_addr> -I  # Interactive\n"
            "  > primary  # List services\n"
            "  > characteristics  # List characteristics\n"
            "  > char-read-hnd <handle>  # Read data\n"
            "ATTACKS:\n"
            "  Just Works Pairing:\n"
            "    - No MITM protection\n"
            "    - Intercept and spoof pairing\n"
            "  Static Passkey:\n"
            "    - Common: 000000, 123456\n"
            "    - Brute force 6-digit passkey (1M combinations)\n"
            "  KNOB Attack (CVE-2019-9506):\n"
            "    - Force low entropy in encryption key\n"
            "    - Reduce key to 1 byte → brute force\n"
            "  BLURtooth (CVE-2020-15802):\n"
            "    - Cross-transport key derivation\n"
            "    - Classic Bluetooth key → BLE key"
        ),
        "tools": ["bettercap", "gatttool", "btlejack"],
    },
    {
        "id": "rfid-001", "name": "RFID/NFC Cloning",
        "protocol": "rfid", "severity": "medium",
        "desc": "Cloning and spoofing RFID/NFC credentials.",
        "detection": (
            "RFID/NFC ATTACKS:\n"
            "LOW FREQUENCY (125kHz):\n"
            "  - HID/EM4100 cards: Easily clonable\n"
            "  - Proxmark3: lf hid read, lf hid clone\n"
            "  - No authentication, pure replay\n"
            "HIGH FREQUENCY (13.56MHz):\n"
            "  MIFARE Classic:\n"
            "    - Known crypto weakness (CRYPTO1)\n"
            "    - Attack: mfoc (nested attack), mfcuk (hardnested)\n"
            "    - Proxmark3: hf mf autopwn\n"
            "    - Full card clone possible\n"
            "  MIFARE DESFire:\n"
            "    - Stronger crypto (AES/3DES)\n"
            "    - Attack: Side-channel on some implementations\n"
            "  NFC:\n"
            "    - NFCProxy: relay NFC communications\n"
            "    - Relay attack: Extend range using two devices\n"
            "TOOLS:\n"
            "  - Proxmark3: Most versatile RFID tool\n"
            "  - Flipper Zero: Portable, multi-protocol\n"
            "  - ChameleonMini: Card emulation\n"
            "  - ACR122U: USB NFC reader/writer\n"
            "TESTING:\n"
            "  1. Identify card technology and frequency\n"
            "  2. Attempt read/dump of card data\n"
            "  3. Test for weak authentication\n"
            "  4. Attempt clone to blank card"
        ),
        "tools": ["proxmark3", "mfoc", "nfc-tools"],
    },
]


class WirelessSecurityKB:
    """Wireless security knowledge base.

    Provides wireless attack patterns injected
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
                protocol=data.get("protocol", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_protocol(self, protocol: str) -> list[WirelessPattern]:
        """Get patterns by protocol."""
        return [
            p for p in self._patterns.values()
            if p.protocol.lower() == protocol.lower()
        ]

    def build_wireless_prompt(
        self,
        protocols: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build wireless security prompt."""
        lines = ["## Wireless Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if protocols and pattern.protocol.lower() not in [p.lower() for p in protocols]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.protocol.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        proto_counts: dict[str, int] = {}
        for p in self._patterns.values():
            proto_counts[p.protocol] = proto_counts.get(p.protocol, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_protocol": proto_counts,
        }
