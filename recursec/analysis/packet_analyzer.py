"""Packet and traffic analysis engine — parses pcap data, detects anomalies.

Capabilities:
- Parse tcpdump/tshark output
- Protocol distribution analysis
- Cleartext credential detection
- DNS query analysis
- HTTP request/response analysis
- Anomaly detection (port scans, brute force, data exfiltration)
- Connection graph building
- Suspicious pattern matching
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ConnectionInfo:
    """A network connection tuple."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class TrafficAnomaly:
    """A detected traffic anomaly."""
    anomaly_type: str
    severity: str
    description: str
    source_ip: str = ""
    target_ip: str = ""
    evidence: str = ""
    confidence: float = 0.0


@dataclass
class AnalysisResult:
    """Results of traffic analysis."""
    total_packets: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    connections: list[ConnectionInfo] = field(default_factory=list)
    anomalies: list[TrafficAnomaly] = field(default_factory=list)
    cleartext_creds: list[dict[str, str]] = field(default_factory=list)
    dns_queries: list[dict[str, str]] = field(default_factory=list)
    http_requests: list[dict[str, str]] = field(default_factory=list)
    top_talkers: list[dict[str, Any]] = field(default_factory=list)
    suspicious_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "protocols": self.protocols,
            "connections": len(self.connections),
            "anomalies": [{"type": a.anomaly_type, "severity": a.severity, "description": a.description} for a in self.anomalies],
            "cleartext_creds": len(self.cleartext_creds),
            "dns_queries": len(self.dns_queries),
            "http_requests": len(self.http_requests),
            "top_talkers": self.top_talkers[:10],
        }


# Known cleartext protocol ports
CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 143, 161, 389, 445, 514, 1433, 3306, 5432, 6379, 8080, 8888, 11211}

# Suspicious port ranges (commonly used by malware/backdoors)
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321, 1337}

# Credential patterns
CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(?:user(?:name)?|login|email)[=:\s]+([^\s&]+)"),
    re.compile(r"(?i)(?:pass(?:word)?|pwd|secret)[=:\s]+([^\s&]+)"),
    re.compile(r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)"),
    re.compile(r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._-]+)"),
    re.compile(r"(?i)(?:api[_-]?key|token|secret)[=:\s]+([^\s&]+)"),
    re.compile(r"(?i)Cookie:\s*(.+)"),
]

# DNS suspicious patterns
DNS_SUSPICIOUS_PATTERNS = [
    re.compile(r"\.onion$"),
    re.compile(r"\.i2p$"),
    re.compile(r"(?:tunnel|vpn|proxy|tor|hide|anon)", re.IGNORECASE),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.in-addr\.arpa"),
]


class PacketAnalyzer:
    """Analyzes network traffic for security insights."""

    def __init__(self) -> None:
        self._connections: dict[str, ConnectionInfo] = {}
        self._ip_packet_count: dict[str, int] = defaultdict(int)
        self._ip_byte_count: dict[str, int] = defaultdict(int)
        self._port_scan_tracker: dict[str, set[int]] = defaultdict(set)
        self._brute_force_tracker: dict[str, int] = defaultdict(int)

    def analyze_tcpdump(self, output: str) -> AnalysisResult:
        """Analyze tcpdump text output."""
        result = AnalysisResult()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            result.total_packets += 1

            # Parse tcpdump line format: timestamp IP src > dst: protocol
            self._parse_tcpdump_line(line, result)

        # Post-analysis
        self._detect_anomalies(result)
        self._build_top_talkers(result)

        return result

    def analyze_tshark_json(self, json_data: list[dict[str, Any]]) -> AnalysisResult:
        """Analyze tshark JSON output."""
        result = AnalysisResult()

        for packet in json_data:
            result.total_packets += 1
            layers = packet.get("_source", {}).get("layers", {})

            # Extract protocol info
            ip_layer = layers.get("ip", {})
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            dns_layer = layers.get("dns", {})
            http_layer = layers.get("http", {})

            proto = "unknown"
            if tcp:
                proto = "tcp"
            elif udp:
                proto = "udp"
            result.protocols[proto] = result.protocols.get(proto, 0) + 1

            src_ip = ip_layer.get("ip.src", "")
            dst_ip = ip_layer.get("ip.dst", "")

            if src_ip:
                self._ip_packet_count[src_ip] += 1
            if dst_ip:
                self._ip_packet_count[dst_ip] += 1

            # DNS analysis
            if dns_layer:
                qname = dns_layer.get("dns.qry.name", "")
                qtype = dns_layer.get("dns.qry.type", "")
                if qname:
                    result.dns_queries.append({"query": qname, "type": qtype, "src": src_ip})

            # HTTP analysis
            if http_layer:
                method = http_layer.get("http.request.method", "")
                uri = http_layer.get("http.request.uri", "")
                host = http_layer.get("http.host", "")
                if method:
                    result.http_requests.append({
                        "method": method, "uri": uri, "host": host, "src": src_ip,
                    })

                # Check for cleartext credentials
                full_text = str(http_layer)
                for pattern in CREDENTIAL_PATTERNS:
                    match = pattern.search(full_text)
                    if match:
                        result.cleartext_creds.append({
                            "type": "http",
                            "value": match.group(1)[:50],
                            "source": src_ip,
                            "destination": dst_ip,
                        })

        self._detect_anomalies(result)
        self._build_top_talkers(result)
        return result

    def _parse_tcpdump_line(self, line: str, result: AnalysisResult) -> None:
        """Parse a single tcpdump output line."""
        # Match common tcpdump format
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)", line)
        if ip_match:
            src_ip, src_port, dst_ip, dst_port = ip_match.groups()
            src_port = int(src_port)
            dst_port = int(dst_port)

            # Track connection
            key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if key not in self._connections:
                self._connections[key] = ConnectionInfo(
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    protocol="tcp",
                )
            self._connections[key].packets += 1

            # Track IPs
            self._ip_packet_count[src_ip] += 1
            self._ip_packet_count[dst_ip] += 1

            # Port scan detection
            self._port_scan_tracker[src_ip].add(dst_port)

            # Brute force detection (many connections to same service)
            auth_ports = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432}
            if dst_port in auth_ports:
                self._brute_force_tracker[f"{src_ip}->{dst_ip}:{dst_port}"] += 1

            result.connections = list(self._connections.values())

        # Protocol detection
        if "Flags [S]" in line or "SYN" in line:
            result.protocols["tcp_syn"] = result.protocols.get("tcp_syn", 0) + 1
        elif "UDP" in line or "udp" in line:
            result.protocols["udp"] = result.protocols.get("udp", 0) + 1
        elif "ICMP" in line or "icmp" in line:
            result.protocols["icmp"] = result.protocols.get("icmp", 0) + 1
        elif "ARP" in line or "arp" in line:
            result.protocols["arp"] = result.protocols.get("arp", 0) + 1
        else:
            result.protocols["tcp"] = result.protocols.get("tcp", 0) + 1

        # Check for cleartext credentials
        for pattern in CREDENTIAL_PATTERNS:
            match = pattern.search(line)
            if match:
                result.cleartext_creds.append({
                    "type": "cleartext",
                    "value": match.group(1)[:50],
                    "raw_line": line[:200],
                })

    def _detect_anomalies(self, result: AnalysisResult) -> None:
        """Detect traffic anomalies."""
        # Port scan detection
        for ip, ports in self._port_scan_tracker.items():
            if len(ports) > 50:
                result.anomalies.append(TrafficAnomaly(
                    anomaly_type="port_scan",
                    severity="high",
                    description=f"Port scan detected from {ip}: {len(ports)} unique ports contacted",
                    source_ip=ip,
                    confidence=min(1.0, len(ports) / 100.0),
                ))

        # Brute force detection
        for key, count in self._brute_force_tracker.items():
            if count > 20:
                parts = key.split("->")
                src = parts[0] if parts else ""
                dst = parts[1] if len(parts) > 1 else ""
                result.anomalies.append(TrafficAnomaly(
                    anomaly_type="brute_force",
                    severity="high",
                    description=f"Possible brute force from {src} to {dst}: {count} connection attempts",
                    source_ip=src,
                    target_ip=dst,
                    confidence=min(1.0, count / 50.0),
                ))

        # DNS tunneling detection
        for query in result.dns_queries:
            qname = query.get("query", "")
            if len(qname) > 100:
                result.anomalies.append(TrafficAnomaly(
                    anomaly_type="dns_tunneling",
                    severity="medium",
                    description=f"Suspiciously long DNS query: {qname[:60]}...",
                    source_ip=query.get("src", ""),
                    confidence=0.7,
                ))

            for pattern in DNS_SUSPICIOUS_PATTERNS:
                if pattern.search(qname):
                    result.anomalies.append(TrafficAnomaly(
                        anomaly_type="suspicious_dns",
                        severity="medium",
                        description=f"Suspicious DNS query: {qname}",
                        source_ip=query.get("src", ""),
                        confidence=0.6,
                    ))

        # Data exfiltration detection
        for ip, byte_count in self._ip_byte_count.items():
            if byte_count > 100_000_000:  # 100MB
                result.anomalies.append(TrafficAnomaly(
                    anomaly_type="data_exfiltration",
                    severity="critical",
                    description=f"Large data transfer from {ip}: {byte_count / 1_000_000:.1f}MB",
                    source_ip=ip,
                    confidence=0.5,
                ))

    def _build_top_talkers(self, result: AnalysisResult) -> None:
        """Build top talkers list."""
        sorted_ips = sorted(self._ip_packet_count.items(), key=lambda x: x[1], reverse=True)
        result.top_talkers = [
            {"ip": ip, "packets": count}
            for ip, count in sorted_ips[:20]
        ]
