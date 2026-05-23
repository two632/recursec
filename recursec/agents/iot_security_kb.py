"""IoT security knowledge base.

Deep knowledge about Internet of Things security:
1. Smart home device security
2. Industrial IoT (IIoT) / SCADA
3. Automotive security
4. Medical device security
5. IoT communication protocols
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class IoTVulnPattern:
    """An IoT vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    domain: str = ""           # smart_home, industrial, automotive, medical
    severity: str = "high"
    protocols: list[str] = field(default_factory=list)
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "domain": self.domain[:12],
        }


IOT_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "iot-001", "name": "Smart Home Device Security",
        "domain": "smart_home", "severity": "high",
        "protocols": ["MQTT", "CoAP", "Zigbee", "Z-Wave", "BLE", "WiFi"],
        "desc": "Security testing of smart home devices and hubs.",
        "testing": (
            "SMART HOME DEVICE SECURITY:\n"
            "1. NETWORK RECONNAISSANCE:\n"
            "   - Discover IoT devices on network:\n"
            "     nmap -sn 192.168.1.0/24 --script broadcast-dhcp-discover\n"
            "   - Identify IoT-specific ports:\n"
            "     * 1883/8883 — MQTT (unencrypted/TLS)\n"
            "     * 5683/5684 — CoAP (unencrypted/DTLS)\n"
            "     * 8080/8443 — Web admin interfaces\n"
            "     * 5353 — mDNS (device discovery)\n"
            "     * 1900 — SSDP/UPnP\n"
            "2. MQTT TESTING:\n"
            "   - Connect without auth:\n"
            "     mosquitto_sub -h {target} -t '#' -v\n"
            "   - Subscribe to all topics (# wildcard)\n"
            "   - Check for sensitive data in messages\n"
            "   - Publish malicious commands:\n"
            "     mosquitto_pub -h {target} -t 'home/lock/command' -m 'unlock'\n"
            "   - Test ACL bypass: Subscribe to $SYS/# for broker info\n"
            "3. UPnP/SSDP:\n"
            "   - Discover: msearch or miranda\n"
            "   - SOAP action injection\n"
            "   - Port mapping abuse (AddPortMapping)\n"
            "4. WEB INTERFACE:\n"
            "   - Default credentials (admin/admin, admin/1234)\n"
            "   - Command injection in device name/SSID fields\n"
            "   - Firmware update mechanism (unsigned updates?)\n"
            "   - CSRF on device configuration\n"
            "5. CLOUD API:\n"
            "   - Capture cloud API traffic (proxy)\n"
            "   - IDOR on device serial numbers\n"
            "   - Weak authentication tokens\n"
            "   - Replay attacks on commands"
        ),
        "tools": ["nmap", "mosquitto", "miranda", "Burp Suite"],
    },
    {
        "id": "iot-002", "name": "Industrial IoT / SCADA Security",
        "domain": "industrial", "severity": "critical",
        "protocols": ["Modbus", "DNP3", "OPC-UA", "BACnet", "S7comm", "EtherNet/IP"],
        "desc": "Security testing of ICS/SCADA systems.",
        "testing": (
            "INDUSTRIAL IoT / SCADA SECURITY:\n"
            "1. PROTOCOL IDENTIFICATION:\n"
            "   - Scan for ICS protocols:\n"
            "     nmap -sV -p 502,102,4840,47808,20000,44818 {target}\n"
            "     * Port 502 — Modbus TCP\n"
            "     * Port 102 — Siemens S7comm\n"
            "     * Port 4840 — OPC-UA\n"
            "     * Port 47808 — BACnet\n"
            "     * Port 20000 — DNP3\n"
            "     * Port 44818 — EtherNet/IP\n"
            "2. MODBUS TESTING:\n"
            "   - Read coils/registers (no authentication by design):\n"
            "     modbus-cli read {target} 0 10 (read registers 0-10)\n"
            "   - Write registers (CAUTION — can affect physical systems):\n"
            "     modbus-cli write {target} 0 1 (write register 0 = 1)\n"
            "   - Function code scanning: Test all 127 function codes\n"
            "   - Replay attacks: Capture and replay Modbus packets\n"
            "3. S7COMM (Siemens PLC):\n"
            "   - Identify PLC: nmap --script s7-info {target}\n"
            "   - Read PLC info (model, firmware, serial)\n"
            "   - CPU start/stop: Can halt industrial processes\n"
            "4. OPC-UA:\n"
            "   - Enumerate endpoints: opcua-client\n"
            "   - Check for anonymous access\n"
            "   - Certificate validation issues\n"
            "   - Browse node tree for sensitive data\n"
            "5. NETWORK SEGMENTATION:\n"
            "   - Test IT/OT network boundary\n"
            "   - Check for flat network (no DMZ between IT and OT)\n"
            "   - Historian server as pivot point\n"
            "   - VPN/remote access to OT network\n"
            "WARNING: ICS testing requires authorization and safety protocols.\n"
            "Never write values without explicit authorization."
        ),
        "tools": ["nmap", "modbus-cli", "opcua-client", "Wireshark"],
    },
    {
        "id": "iot-003", "name": "Automotive Security",
        "domain": "automotive", "severity": "critical",
        "protocols": ["CAN bus", "OBD-II", "UDS", "Bluetooth", "WiFi", "Cellular"],
        "desc": "Security testing of connected vehicles.",
        "testing": (
            "AUTOMOTIVE SECURITY:\n"
            "1. CAN BUS ANALYSIS:\n"
            "   - Connect to OBD-II port with CAN adapter:\n"
            "     candump can0 (listen to all CAN traffic)\n"
            "     cansend can0 7DF#0201000000000000 (OBD query)\n"
            "   - Identify message IDs by action correlation:\n"
            "     * Turn steering → watch for changing CAN IDs\n"
            "     * Press brake → correlate with messages\n"
            "   - CAN bus fuzzing:\n"
            "     cangen can0 -I 000 -L 8 -D r (random data)\n"
            "2. INFOTAINMENT SYSTEM:\n"
            "   - Bluetooth pairing attacks (KNOB, BLURtooth)\n"
            "   - WiFi hotspot misconfiguration\n"
            "   - USB port: Malicious firmware update via USB\n"
            "   - App store: Sideloading malicious apps\n"
            "   - Browser exploits in infotainment\n"
            "3. TELEMATICS/TCU:\n"
            "   - Cellular interface: SIM card extraction, SMS commands\n"
            "   - OTA update mechanism: MITM firmware updates\n"
            "   - V2X communication: Message injection\n"
            "   - GPS spoofing: GPS-SDR-SIM\n"
            "4. KEY FOB:\n"
            "   - Relay attack: HackRF/RTL-SDR + amplifier\n"
            "   - Rolling code analysis: Rolljam attack\n"
            "   - Signal jamming + capture\n"
            "   - Key fob cloning\n"
            "5. REMOTE API:\n"
            "   - Mobile app traffic analysis\n"
            "   - Vehicle control API (start/stop/unlock)\n"
            "   - IDOR on VIN/vehicle ID\n"
            "   - Telematics data exposure"
        ),
        "tools": ["can-utils", "SavvyCAN", "HackRF", "GPS-SDR-SIM"],
    },
    {
        "id": "iot-004", "name": "Medical Device Security",
        "domain": "medical", "severity": "critical",
        "protocols": ["HL7", "DICOM", "FHIR", "MQTT", "BLE"],
        "desc": "Security testing of medical IoT devices.",
        "testing": (
            "MEDICAL DEVICE SECURITY:\n"
            "1. NETWORK DISCOVERY:\n"
            "   - Identify medical devices:\n"
            "     nmap -sV -p 104,2575,8042,11112 {target}\n"
            "     * Port 104 — DICOM (medical imaging)\n"
            "     * Port 2575 — HL7 (health data)\n"
            "     * Port 8042 — Orthanc (DICOM web)\n"
            "     * Port 11112 — DICOM TLS\n"
            "2. DICOM TESTING:\n"
            "   - DICOM C-ECHO (connectivity test):\n"
            "     echoscu {target} 104\n"
            "   - DICOM C-FIND (query patient data):\n"
            "     findscu -P -k PatientName='*' {target} 104\n"
            "   - DICOM C-STORE (upload images):\n"
            "     Check if anonymous upload is allowed\n"
            "   - PHI exposure: Patient name, DOB, SSN in DICOM headers\n"
            "3. HL7 TESTING:\n"
            "   - HL7 message injection:\n"
            "     Send malformed ADT (Admit/Discharge/Transfer) messages\n"
            "   - Authentication bypass: Many HL7 interfaces have no auth\n"
            "   - Data extraction: Query for patient records\n"
            "4. INFUSION PUMPS / MONITORS:\n"
            "   - Default credentials on web interface\n"
            "   - Firmware update mechanism\n"
            "   - Drug library manipulation\n"
            "   - Alarm suppression attacks\n"
            "5. COMPLIANCE:\n"
            "   - HIPAA: PHI protection requirements\n"
            "   - FDA premarket cybersecurity guidance\n"
            "   - IEC 62443 (industrial security for medical)\n"
            "WARNING: Medical device testing requires explicit authorization.\n"
            "Never test on production medical systems."
        ),
        "tools": ["nmap", "DCMTK", "Orthanc", "Wireshark"],
    },
    {
        "id": "iot-005", "name": "IoT Communication Protocol Attacks",
        "domain": "protocols", "severity": "high",
        "protocols": ["MQTT", "CoAP", "AMQP", "ZigBee", "LoRaWAN", "NB-IoT"],
        "desc": "Attacks on IoT-specific communication protocols.",
        "testing": (
            "IoT COMMUNICATION PROTOCOL ATTACKS:\n"
            "1. MQTT ATTACKS:\n"
            "   - Anonymous access: Connect without credentials\n"
            "   - Topic enumeration: # and $SYS/# subscriptions\n"
            "   - Message tampering: Intercept and modify MQTT messages\n"
            "   - Will message abuse: Set malicious Last Will and Testament\n"
            "   - Retained message poisoning: Publish retained messages on topics\n"
            "   - QoS downgrade: Force QoS 0 to lose delivery guarantees\n"
            "2. CoAP ATTACKS:\n"
            "   - Resource discovery: GET /.well-known/core\n"
            "   - Observe notification abuse: Subscribe to resource changes\n"
            "   - Amplification: CoAP has no built-in congestion control\n"
            "   - Block-wise transfer manipulation\n"
            "   - DTLS downgrade attacks\n"
            "3. ZIGBEE:\n"
            "   - Sniff traffic: KillerBee + ApiMote/RZUSBStick\n"
            "   - Key extraction: Trust Center key during join\n"
            "   - Replay attacks: Replay captured frames\n"
            "   - Insecure rejoin: Force device rejoin with known key\n"
            "   - Network key transport interception\n"
            "4. LoRaWAN:\n"
            "   - Gateway spoofing\n"
            "   - Replay attacks on join requests\n"
            "   - ABP (Activation by Personalization) key reuse\n"
            "   - Downlink injection\n"
            "5. BLE (Bluetooth Low Energy):\n"
            "   - GATT service enumeration: gatttool -b {mac} --primary\n"
            "   - Characteristic read/write without pairing\n"
            "   - Passive eavesdropping: Ubertooth/nRF sniffer\n"
            "   - MITM: BtleJuice proxy\n"
            "   - KNOB attack: Key negotiation downgrade"
        ),
        "tools": ["mosquitto", "coap-client", "KillerBee", "Ubertooth", "gatttool"],
    },
]


class IoTSecurityKB:
    """IoT security knowledge base.

    Provides deep IoT security testing methodology
    injected into agent prompts for IoT assessments.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IoTVulnPattern] = {}
        self._log = logger.bind(component="iot_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load IoT vulnerability patterns."""
        for data in IOT_VULN_PATTERNS:
            pattern = IoTVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                domain=data.get("domain", ""),
                severity=data.get("severity", "high"),
                protocols=data.get("protocols", []),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_domain(
        self,
        domain: str,
    ) -> list[IoTVulnPattern]:
        """Get patterns for a specific IoT domain."""
        return [
            p for p in self._patterns.values()
            if p.domain == domain
        ]

    def get_patterns_for_protocol(
        self,
        protocol: str,
    ) -> list[IoTVulnPattern]:
        """Get patterns involving a specific protocol."""
        return [
            p for p in self._patterns.values()
            if protocol.upper() in [pr.upper() for pr in p.protocols]
        ]

    def build_iot_prompt(
        self,
        domain: str = "",
        protocol: str = "",
        max_patterns: int = 3,
    ) -> str:
        """Build IoT testing prompt."""
        if domain:
            relevant = self.get_patterns_for_domain(domain)
        elif protocol:
            relevant = self.get_patterns_for_protocol(protocol)
        else:
            relevant = list(self._patterns.values())

        lines = ["## IoT Security Testing\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.protocols:
                lines.append(f"Protocols: {', '.join(pattern.protocols)}")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        domain_counts: dict[str, int] = defaultdict(int)
        protocol_set: set[str] = set()
        for p in self._patterns.values():
            domain_counts[p.domain] += 1
            protocol_set.update(p.protocols)
        return {
            "patterns": len(self._patterns),
            "protocols": len(protocol_set),
            "by_domain": dict(domain_counts),
        }
