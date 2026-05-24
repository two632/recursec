"""Wireless security knowledge base — WiFi, Bluetooth, RFID, SDR."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class WirelessType(str, Enum):
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    RFID_NFC = "rfid_nfc"
    SDR = "sdr"
    CELLULAR = "cellular"

@dataclass
class WirelessPattern:
    name: str = ""
    wireless_type: WirelessType = WirelessType.WIFI
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.wireless_type.value, "severity": self.severity}

WIRELESS_PATTERNS: list[WirelessPattern] = [
    WirelessPattern(name="WiFi Attacks", wireless_type=WirelessType.WIFI, description="WiFi security assessment: WPA2/WPA3 cracking, evil twin, PMKID capture, deauthentication, rogue AP, enterprise WPA attacks, WiFi direct exploitation.", techniques=["WPA2 handshake capture + offline cracking (hashcat)", "PMKID capture (no client needed, first frame of RSN IE)", "Evil twin AP: clone SSID to capture credentials", "Deauthentication: force client reconnection for handshake", "WPA Enterprise: EAP downgrade, credential harvesting", "KRACK: key reinstallation attack on WPA2", "FragAttacks: frame aggregation/fragmentation vulnerabilities", "Dragonblood: WPA3 SAE downgrade and side-channel", "Rogue AP with captive portal for credential phishing", "WiFi Direct: exploit autonomous group owner negotiation"], indicators=["Unexpected deauthentication frames", "Duplicate SSIDs with different BSSIDs", "Unusual EAP types in enterprise WiFi", "WPA3 transition mode allowing WPA2 fallback"], tools=["aircrack-ng", "hashcat", "hostapd-mana", "eaphammer", "wifite2"], commands=["airmon-ng start wlan0", "airodump-ng wlan0mon", "aireplay-ng -0 5 -a BSSID wlan0mon", "hashcat -m 22000 capture.hc22000 wordlist.txt"], severity="high"),
    WirelessPattern(name="Bluetooth Attacks", wireless_type=WirelessType.BLUETOOTH, description="Bluetooth security: BLE sniffing, pairing exploitation, KNOB attack, BlueBorne, Bluetooth impersonation, GATT service enumeration.", techniques=["BLE advertisement sniffing and tracking", "BLE GATT service/characteristic enumeration", "KNOB (Key Negotiation of Bluetooth): force weak encryption", "BlueBorne: remote code execution via Bluetooth stack", "Bluetooth impersonation (BIAS): spoof paired device", "BLE relay attack: extend range of proximity-based auth", "Passkey brute force for legacy pairing", "BLE write characteristic exploitation (locks, IoT)"], indicators=["Unexpected Bluetooth pairing requests", "BLE devices with default/no security", "Bluetooth services running on non-standard ports", "Legacy Bluetooth pairing (no Secure Connections)"], tools=["btlejack", "ubertooth", "bettercap", "gattacker"], commands=["hcitool scan", "hcitool lescan", "gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x0003", "bettercap -eval 'ble.recon on'"], severity="high"),
    WirelessPattern(name="RFID/NFC Attacks", wireless_type=WirelessType.RFID_NFC, description="RFID/NFC security: card cloning, replay attacks, relay attacks, brute force sector keys, UID manipulation, NFC payment exploitation.", techniques=["MIFARE Classic: nested/hardnested attack for sector keys", "Card cloning: read and write to blank cards", "Relay attack: extend NFC range for contactless payments", "UID manipulation: change card UID for access control bypass", "Brute force default sector keys (FFFFFFFFFFFF, A0A1A2A3A4A5)", "EMV contactless: relay transaction data", "HID iClass: key diversification attacks", "Long-range RFID reading with high-gain antenna"], indicators=["Duplicate card UIDs in access logs", "NFC transactions from unusual distances", "Failed authentication attempts on RFID readers", "New card UIDs not in provisioned list"], tools=["proxmark3", "mfoc", "mfcuk", "nfc-tools", "flipper-zero"], commands=["proxmark3 -c 'hf mf autopwn'", "proxmark3 -c 'hf 14a reader'", "mfoc -O dump.mfd"], severity="high"),
    WirelessPattern(name="Software Defined Radio", wireless_type=WirelessType.SDR, description="SDR-based attacks: signal capture, replay, jamming, protocol analysis, keyfob cloning, garage door replay, pager interception, ADS-B spoofing.", techniques=["Signal capture and replay (garage doors, keyfobs)", "Protocol reverse engineering from RF captures", "Rolling code analysis and prediction", "GPS spoofing via SDR", "ADS-B aircraft position spoofing", "Pager message interception (POCSAG, FLEX)", "Two-way radio interception and transmission", "ISM band device exploitation (433/868/915 MHz)"], indicators=["Unexpected RF transmissions near target", "GPS position anomalies", "Rolling code gaps suggesting replay attempts", "Unusual signal strength patterns"], tools=["gnuradio", "hackrf", "rtl-sdr", "universal-radio-hacker"], commands=["rtl_433 -f 433920000 -s 250000", "hackrf_transfer -r capture.raw -f 433920000 -s 2000000", "urh # launch Universal Radio Hacker GUI"], severity="medium"),
    WirelessPattern(name="Cellular Security", wireless_type=WirelessType.CELLULAR, description="Cellular network attacks: IMSI catching, SS7 exploitation, 4G/5G protocol attacks, SIM cloning, baseband exploitation.", techniques=["IMSI catcher: fake base station to capture phone identifiers", "SS7 attacks: intercept SMS, track location, redirect calls", "4G/LTE: aLTEr attack (DNS redirection via data layer)", "5G: downgrade attacks forcing fallback to 4G", "SIM swapping: social engineering carrier for number transfer", "Baseband exploitation: target cellular modem firmware", "VoLTE: eavesdrop on unencrypted voice calls", "RCS: exploit Rich Communication Services vulnerabilities"], indicators=["Unexpected cell tower changes", "SMS delivery to wrong device", "Unusual baseband firmware updates", "Signal strength anomalies near facility"], tools=["srsran", "open5gs", "osmocom", "simtrace"], commands=["srsue --rf.device_name=uhd # run UE simulation", "tshark -i any -f 'port 36412' # capture S1AP"], severity="critical"),
]

def build_wireless_prompt(focus_type: WirelessType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Wireless Security Knowledge\n"]
    patterns = WIRELESS_PATTERNS if not focus_type else [p for p in WIRELESS_PATTERNS if p.wireless_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
