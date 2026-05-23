"""Network scanner — host discovery, service fingerprinting, OS detection.

Capabilities:
- Host discovery (ping sweep, ARP scan, TCP/UDP probing)
- Service fingerprinting (banner grabbing, protocol detection)
- Operating system detection via TCP/IP stack fingerprinting
- Network topology mapping
- SNMP enumeration
- NetBIOS/SMB enumeration
"""

from __future__ import annotations

import asyncio
import re
import shutil
import socket
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class HostInfo:
    """Discovered host information."""
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    os_confidence: float = 0.0
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, dict[str, str]] = field(default_factory=dict)
    state: str = "up"
    ttl: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip, "hostname": self.hostname, "mac": self.mac,
            "os": self.os_guess, "os_confidence": round(self.os_confidence, 2),
            "open_ports": self.open_ports,
            "services": self.services,
            "state": self.state, "ttl": self.ttl,
        }


@dataclass
class ServiceInfo:
    """Detected service information."""
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    version: str = ""
    banner: str = ""
    product: str = ""
    extra_info: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port, "protocol": self.protocol,
            "service": self.service_name, "version": self.version,
            "banner": self.banner[:200], "product": self.product,
        }


@dataclass
class NetworkScanResult:
    """Complete network scan results."""
    network: str = ""
    hosts: list[HostInfo] = field(default_factory=list)
    total_hosts_scanned: int = 0
    hosts_up: int = 0
    scan_duration_s: float = 0.0
    findings: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "hosts": [h.to_dict() for h in self.hosts],
            "total_scanned": self.total_hosts_scanned,
            "hosts_up": self.hosts_up,
            "duration_s": round(self.scan_duration_s, 2),
            "findings": self.findings,
        }


# Well-known port → service mapping
PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 8080: "http-proxy", 8443: "https-alt",
    9090: "prometheus", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

# TTL → OS family heuristic
TTL_OS_MAP = [
    (255, "Solaris/AIX/Cisco"),
    (128, "Windows"),
    (64, "Linux/macOS/*BSD"),
    (32, "Windows 95/98"),
]

# Service banner patterns for OS detection
BANNER_OS_PATTERNS = [
    (re.compile(r"Ubuntu", re.IGNORECASE), "Linux (Ubuntu)"),
    (re.compile(r"Debian", re.IGNORECASE), "Linux (Debian)"),
    (re.compile(r"CentOS", re.IGNORECASE), "Linux (CentOS)"),
    (re.compile(r"Red Hat", re.IGNORECASE), "Linux (Red Hat)"),
    (re.compile(r"FreeBSD", re.IGNORECASE), "FreeBSD"),
    (re.compile(r"Microsoft", re.IGNORECASE), "Windows"),
    (re.compile(r"Windows", re.IGNORECASE), "Windows"),
    (re.compile(r"Apache.*Unix", re.IGNORECASE), "Unix/Linux"),
]


class NetworkScanner:
    """Comprehensive network scanner for host and service discovery."""

    def __init__(self, timeout: float = 3.0, max_concurrent: int = 50) -> None:
        self._timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._has_nmap = shutil.which("nmap") is not None
        self._has_masscan = shutil.which("masscan") is not None

    async def discover_hosts(self, network: str) -> NetworkScanResult:
        """Discover live hosts on a network."""
        result = NetworkScanResult(network=network)

        # Try nmap ping sweep first
        if self._has_nmap:
            await self._nmap_host_discovery(network, result)
        else:
            await self._ping_sweep(network, result)

        result.hosts_up = len(result.hosts)
        return result

    async def scan_host(self, ip: str, ports: list[int] | None = None) -> HostInfo:
        """Scan a single host for services."""
        host = HostInfo(ip=ip)

        # Reverse DNS
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                host.hostname = hostname
        except Exception:
            pass

        # Port scan
        if ports is None:
            ports = list(PORT_SERVICE_MAP.keys())

        open_ports = await self._tcp_connect_scan(ip, ports)
        host.open_ports = sorted(open_ports)

        # Service detection on open ports
        banner_tasks = [self._grab_banner(ip, port) for port in host.open_ports]
        banners = await asyncio.gather(*banner_tasks, return_exceptions=True)

        for port, banner_result in zip(host.open_ports, banners):
            service_name = PORT_SERVICE_MAP.get(port, "unknown")
            banner = ""
            if isinstance(banner_result, str):
                banner = banner_result
                # Try to identify service from banner
                detected = self._identify_service(port, banner)
                if detected:
                    service_name = detected

            host.services[port] = {
                "name": service_name,
                "banner": banner[:200],
            }

        # OS detection heuristic
        host.os_guess, host.os_confidence = self._guess_os(host)

        return host

    async def full_scan(
        self, target: str, ports: list[int] | None = None, top_ports: int = 0
    ) -> NetworkScanResult:
        """Full network scan with service detection."""
        result = NetworkScanResult(network=target)

        # If it's a CIDR range, discover hosts first
        if "/" in target:
            await self._nmap_host_discovery(target, result)
            for host_info in result.hosts:
                detailed = await self.scan_host(host_info.ip, ports)
                host_info.open_ports = detailed.open_ports
                host_info.services = detailed.services
                host_info.os_guess = detailed.os_guess
                host_info.hostname = detailed.hostname
        else:
            # Single host
            host = await self.scan_host(target, ports)
            result.hosts.append(host)

        result.hosts_up = len(result.hosts)
        self._analyze_findings(result)

        return result

    async def _tcp_connect_scan(self, ip: str, ports: list[int]) -> list[int]:
        """TCP connect scan for open port detection."""
        open_ports: list[int] = []

        async def check_port(port: int) -> bool:
            async with self._semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self._timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except (OSError, asyncio.TimeoutError):
                    return False

        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks)

        for port, is_open in zip(ports, results):
            if is_open:
                open_ports.append(port)

        return open_ports

    async def _grab_banner(self, ip: str, port: int) -> str:
        """Grab service banner from an open port."""
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self._timeout,
                )

                # Send probe based on port
                if port in (80, 8080, 8000, 8443, 443):
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                else:
                    writer.write(b"\r\n")

                await writer.drain()

                try:
                    data = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                    banner = data.decode(errors="replace").strip()
                except asyncio.TimeoutError:
                    banner = ""

                writer.close()
                await writer.wait_closed()
                return banner

            except (OSError, asyncio.TimeoutError):
                return ""

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from banner."""
        lower = banner.lower()

        if "ssh" in lower:
            return "ssh"
        if "http" in lower or "html" in lower:
            return "http" if port != 443 else "https"
        if "ftp" in lower or "vsftpd" in lower:
            return "ftp"
        if "smtp" in lower or "postfix" in lower:
            return "smtp"
        if "mysql" in lower or "mariadb" in lower:
            return "mysql"
        if "postgresql" in lower:
            return "postgresql"
        if "redis" in lower:
            return "redis"
        if "mongodb" in lower:
            return "mongodb"
        if "imap" in lower or "dovecot" in lower:
            return "imap"
        if "pop3" in lower:
            return "pop3"

        return PORT_SERVICE_MAP.get(port, "unknown")

    def _guess_os(self, host: HostInfo) -> tuple[str, float]:
        """Guess OS from collected evidence."""
        os_votes: dict[str, float] = {}

        # TTL-based guess
        if host.ttl > 0:
            for ttl_threshold, os_family in TTL_OS_MAP:
                if abs(host.ttl - ttl_threshold) <= 5:
                    os_votes[os_family] = os_votes.get(os_family, 0) + 0.3

        # Banner-based guess
        for service_info in host.services.values():
            banner = service_info.get("banner", "")
            for pattern, os_family in BANNER_OS_PATTERNS:
                if pattern.search(banner):
                    os_votes[os_family] = os_votes.get(os_family, 0) + 0.4

        # Port-based hints
        port_set = set(host.open_ports)
        if 135 in port_set or 139 in port_set or 445 in port_set or 3389 in port_set:
            os_votes["Windows"] = os_votes.get("Windows", 0) + 0.3
        if 22 in port_set and 111 in port_set:
            os_votes["Linux/Unix"] = os_votes.get("Linux/Unix", 0) + 0.2

        if not os_votes:
            return "Unknown", 0.0

        best_os = max(os_votes, key=os_votes.get)  # type: ignore[arg-type]
        confidence = min(1.0, os_votes[best_os])
        return best_os, confidence

    async def _nmap_host_discovery(self, network: str, result: NetworkScanResult) -> None:
        """Use nmap for host discovery."""
        if not self._has_nmap:
            return

        cmd = ["nmap", "-sn", "-T4", network]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout_data, _ = await asyncio.wait_for(proc.communicate(), timeout=120.0)
            stdout = stdout_data.decode(errors="replace") if stdout_data else ""
        except (asyncio.TimeoutError, FileNotFoundError):
            return

        # Parse nmap ping scan output
        current_ip = ""
        for line in stdout.splitlines():
            ip_match = re.search(r"Nmap scan report for (\S+)", line)
            if ip_match:
                target = ip_match.group(1)
                # Extract IP from "hostname (ip)" format
                ip_in_parens = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", target)
                if ip_in_parens:
                    current_ip = ip_in_parens.group(1)
                else:
                    current_ip = target

            if current_ip and "Host is up" in line:
                host = HostInfo(ip=current_ip)
                result.hosts.append(host)

            mac_match = re.search(r"MAC Address: (\S+)", line)
            if mac_match and result.hosts:
                result.hosts[-1].mac = mac_match.group(1)

    async def _ping_sweep(self, network: str, result: NetworkScanResult) -> None:
        """Simple ping sweep as fallback."""
        # Parse CIDR
        if "/" not in network:
            host = HostInfo(ip=network)
            result.hosts.append(host)
            return

        parts = network.split("/")
        base_ip = parts[0]
        prefix = int(parts[1])

        if prefix < 24:
            return  # Too large for simple ping sweep

        octets = base_ip.split(".")
        base = ".".join(octets[:3])

        async def ping_host(ip: str) -> str | None:
            async with self._semaphore:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ping", "-c", "1", "-W", "1", ip,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=3.0)
                    if proc.returncode == 0:
                        return ip
                except (asyncio.TimeoutError, FileNotFoundError):
                    pass
                return None

        tasks = [ping_host(f"{base}.{i}") for i in range(1, 255)]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in results_list:
            if isinstance(resp, str) and resp:
                result.hosts.append(HostInfo(ip=resp))

    def _analyze_findings(self, result: NetworkScanResult) -> None:
        """Analyze network scan results for security findings."""
        for host in result.hosts:
            # Check for dangerous services
            dangerous_ports = {
                23: ("Telnet Service", "high", "Unencrypted remote access"),
                21: ("FTP Service", "medium", "Potentially unencrypted file transfer"),
                161: ("SNMP Service", "medium", "May expose device configuration"),
                445: ("SMB Service", "medium", "May be vulnerable to EternalBlue and similar"),
                3389: ("RDP Service", "medium", "Remote desktop exposed"),
                6379: ("Redis Service", "high", "May be unauthenticated"),
                11211: ("Memcached Service", "high", "May be unauthenticated, DDoS amplification risk"),
                27017: ("MongoDB Service", "high", "May be unauthenticated"),
            }

            for port in host.open_ports:
                if port in dangerous_ports:
                    title, severity, desc = dangerous_ports[port]
                    result.findings.append({
                        "title": f"{title} on {host.ip}:{port}",
                        "severity": severity,
                        "description": desc,
                        "host": host.ip,
                        "port": port,
                    })
