"""Async TCP/UDP port scanner with service detection, OS fingerprinting, and banner grabbing.

Pure-Python implementation — no external dependencies beyond stdlib + asyncio.
Supports SYN-like connect scanning, UDP probing, rate limiting, and CIDR expansion.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

import structlog

logger = structlog.get_logger()


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class ServiceProbe:
    """A probe sent to identify a service."""
    name: str
    protocol: Protocol
    probe_data: bytes
    ports: list[int]
    match_patterns: list[tuple[str, str]]  # (service_name, regex_pattern)


@dataclass
class PortResult:
    """Result of scanning a single port."""
    host: str
    port: int
    protocol: Protocol
    state: PortState
    service: str = ""
    version: str = ""
    banner: str = ""
    ssl_info: dict[str, Any] = field(default_factory=dict)
    response_time_ms: float = 0.0
    ttl: int = 0
    raw_banner: bytes = b""


@dataclass
class HostResult:
    """Result of scanning a single host."""
    ip: str
    hostname: str = ""
    is_up: bool = False
    os_guess: str = ""
    ttl: int = 0
    ports: list[PortResult] = field(default_factory=list)
    scan_time_s: float = 0.0
    mac_address: str = ""

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def open_port_numbers(self) -> list[int]:
        return [p.port for p in self.open_ports]


@dataclass
class ScanConfig:
    """Configuration for a scan."""
    ports: list[int] = field(default_factory=lambda: list(range(1, 1025)))
    protocol: Protocol = Protocol.TCP
    timeout_s: float = 2.0
    max_concurrent: int = 500
    rate_limit: int = 0  # packets per second, 0 = unlimited
    retries: int = 1
    banner_grab: bool = True
    service_detection: bool = True
    os_detection: bool = True
    randomize_ports: bool = True
    randomize_hosts: bool = True
    source_port: int = 0  # 0 = random
    udp_payload: bool = True


# Well-known port to service mapping
WELL_KNOWN_PORTS: dict[int, str] = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 43: "whois", 53: "dns", 67: "dhcp", 68: "dhcp",
    69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    194: "irc", 201: "at-rtmp", 209: "qmtp", 220: "imap3",
    389: "ldap", 443: "https", 445: "microsoft-ds", 464: "kpasswd",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer",
    520: "rip", 521: "ripng", 530: "courier", 531: "conference",
    532: "netnews", 540: "uucp", 543: "klogin", 544: "kshell",
    546: "dhcpv6-client", 547: "dhcpv6-server", 548: "afp",
    554: "rtsp", 556: "remotefs", 563: "nntps", 587: "submission",
    591: "filemaker", 593: "http-rpc-epmap", 631: "ipp",
    636: "ldaps", 639: "msdp", 646: "ldp", 691: "resvc",
    860: "iscsi", 873: "rsync", 902: "vmware-auth", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs-or-iis",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-m",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-ssl", 3000: "grafana", 3306: "mysql",
    3389: "ms-wbt-server", 3690: "svn", 4000: "remoteanything",
    4443: "pharos", 4444: "krb524", 4567: "tram",
    4711: "trinity", 4993: "unknown", 5000: "upnp",
    5001: "commplex-link", 5003: "filemaker", 5004: "avt-profile",
    5006: "wsm-server", 5007: "wsm-server-ssl", 5050: "mmcc",
    5060: "sip", 5061: "sip-tls", 5222: "xmpp-client",
    5269: "xmpp-server", 5353: "mdns", 5432: "postgresql",
    5555: "freeciv", 5601: "esmagent", 5631: "pcanywheredata",
    5666: "nrpe", 5672: "amqp", 5683: "coap", 5900: "vnc",
    5938: "teamviewer", 5984: "couchdb", 6000: "x11",
    6379: "redis", 6443: "kubernetes-api", 6660: "irc-alt",
    6661: "irc-alt", 6662: "irc-alt", 6663: "irc-alt",
    6664: "irc-alt", 6665: "irc-alt", 6666: "irc-alt",
    6667: "irc", 6668: "irc-alt", 6669: "irc-alt",
    6697: "irc-ssl", 7000: "afs3-fileserver", 7001: "afs3-callback",
    7002: "afs3-prserver", 7070: "realserver", 7443: "oracleas-https",
    8000: "http-alt", 8008: "http-alt", 8009: "ajp13",
    8080: "http-proxy", 8081: "blackice-icecap", 8443: "https-alt",
    8888: "sun-answerbook", 9000: "cslistener", 9001: "tor-orport",
    9042: "cassandra", 9090: "zeus-admin", 9091: "xmltec-xmlmail",
    9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 9999: "abyss", 10000: "snet-sensor-mgmt",
    10250: "kubelet", 10443: "unknown", 11211: "memcached",
    11311: "unknown", 15672: "rabbitmq-mgmt", 16379: "unknown",
    25565: "minecraft", 27017: "mongodb", 27018: "mongodb",
    27019: "mongodb", 28015: "rethinkdb", 28017: "mongodb-http",
    29418: "gerrit", 32400: "plex", 33060: "mysqlx",
    37777: "unknown", 44818: "ethernetip", 47808: "bacnet",
    49152: "unknown", 50000: "ibm-db2", 50070: "hadoop-namenode",
    61616: "activemq",
}

# Common port groups
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 464, 465, 500,
    514, 515, 520, 543, 544, 548, 554, 587, 631, 636, 873, 990, 993, 995,
    1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2181, 2222, 2375, 3000,
    3306, 3389, 3690, 4443, 4444, 5000, 5060, 5222, 5432, 5555, 5601, 5672,
    5683, 5900, 5984, 6000, 6379, 6443, 6667, 6697, 7000, 7001, 7443, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9000, 9042, 9090, 9100, 9200, 9418,
    9999, 10000, 10250, 11211, 27017,
]

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]


# ── Banner Signatures ──────────────────────────────────────

BANNER_SIGNATURES: list[tuple[str, str, str]] = [
    # (signature_bytes_prefix, service, version_hint)
    ("SSH-2.0-OpenSSH", "ssh", "OpenSSH"),
    ("SSH-2.0-dropbear", "ssh", "Dropbear"),
    ("SSH-1.", "ssh", "SSHv1"),
    ("220 ", "ftp", "FTP"),
    ("220-", "ftp", "FTP"),
    ("* OK", "imap", "IMAP"),
    ("+OK", "pop3", "POP3"),
    ("HTTP/1.", "http", "HTTP"),
    ("HTTP/2", "http", "HTTP/2"),
    ("<!DOCTYPE", "http", "HTTP"),
    ("<html", "http", "HTTP"),
    ("220 ", "smtp", "SMTP"),
    ("EHLO", "smtp", "SMTP"),
    ("mysql_native_password", "mysql", "MySQL"),
    ("MariaDB", "mysql", "MariaDB"),
    ("PostgreSQL", "postgresql", "PostgreSQL"),
    ("Redis", "redis", "Redis"),
    ("Memcached", "memcached", "Memcached"),
    ("MongoDB", "mongodb", "MongoDB"),
    ("\\x00\\x00\\x00", "mysql", "MySQL"),
    ("RFB 00", "vnc", "VNC"),
    ("\\x03\\x00\\x00", "rdp", "RDP"),
    ("\\x00\\x0e\\x00", "rdp", "RDP"),
]


# ── UDP Probes ─────────────────────────────────────────────

UDP_PROBES: dict[int, bytes] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    67: b"\x01\x01\x06\x00" + b"\x00" * 236 + b"\x63\x82\x53\x63\x35\x01\x01\xff",
    69: b"\x00\x01test\x00netascii\x00",
    111: b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3",
    137: b"\xaa\xaa\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    500: b"\x00" * 16 + b"\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x68\x01\x00\x00\x34\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x28\x01\x01\x00\x01\x00\x00\x00\x20\x01\x01\x00\x00\x80\x01\x00\x07\x80\x0e\x00\x80\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02",
    520: b"\x01\x01\x00\x00" + b"\x00" * 16,
    523: b"DB2GETADDR\x00SQL09010",
    1194: b"\x38\x01\x00\x00\x00\x00\x00\x00\x00",
    1434: b"\x02",
    1604: b"\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
    3478: b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12,
    5060: b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK\r\nMax-Forwards: 70\r\nTo: <sip:nm@nm>\r\nFrom: <sip:nm@nm>;tag=root\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
    5683: b"\x40\x01\x00\x01\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65",
    11211: b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n",
}


# ── OS Fingerprint TTL-based ───────────────────────────────

def guess_os_from_ttl(ttl: int) -> str:
    """Guess the operating system from the TTL value."""
    if ttl <= 0:
        return "unknown"
    if ttl <= 32:
        return "Windows 95/98"
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Solaris/AIX/Cisco"
    return "unknown"


def expand_targets(target: str) -> list[str]:
    """Expand a target specification into individual IPs.

    Supports:
    - Single IP: 192.168.1.1
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.1-192.168.1.254
    - Hostname: example.com
    """
    ips: list[str] = []

    # CIDR notation
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            return ips
        except ValueError:
            pass

    # Range notation
    if "-" in target and not target.startswith("["):
        parts = target.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                # Handle both 192.168.1.1-254 and 192.168.1.1-192.168.1.254
                end_str = parts[1].strip()
                if "." in end_str:
                    end = ipaddress.ip_address(end_str)
                else:
                    # Short form: 192.168.1.1-254
                    base = ".".join(str(start).split(".")[:-1])
                    end = ipaddress.ip_address(f"{base}.{end_str}")

                current = int(start)
                end_int = int(end)
                while current <= end_int:
                    ips.append(str(ipaddress.ip_address(current)))
                    current += 1
                return ips
            except ValueError:
                pass

    # Try as single IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    # Try as hostname
    try:
        addr_info = socket.getaddrinfo(target, None, socket.AF_INET)
        resolved = list({info[4][0] for info in addr_info})
        return resolved
    except socket.gaierror:
        pass

    return [target]


def parse_port_spec(spec: str) -> list[int]:
    """Parse a port specification string.

    Supports:
    - Single port: 80
    - Range: 1-1024
    - List: 80,443,8080
    - Mixed: 22,80,443,1000-2000,8080-8090
    - Named: top20, top100, all
    """
    if spec == "top20":
        return TOP_20_PORTS[:]
    if spec == "top100":
        return TOP_100_PORTS[:]
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = max(1, int(start_s))
            end = min(65535, int(end_s))
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


class AsyncPortScanner:
    """High-performance async port scanner.

    Features:
    - Async TCP connect scanning with configurable concurrency
    - UDP scanning with protocol-specific probes
    - Banner grabbing and service detection
    - OS fingerprinting via TTL analysis
    - SSL/TLS certificate extraction
    - Rate limiting to avoid detection
    - CIDR/range target expansion
    """

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self._semaphore: asyncio.Semaphore | None = None
        self._rate_limiter: _RateLimiter | None = None
        self._scan_start: float = 0.0
        self._ports_scanned = 0
        self._ports_open = 0
        self._hosts_up = 0
        self._hosts_total = 0

    async def scan_host(self, host: str) -> HostResult:
        """Scan a single host for open ports."""
        result = HostResult(ip=host)
        start = time.monotonic()

        # Resolve hostname
        try:
            hostname = socket.getfqdn(host)
            if hostname != host:
                result.hostname = hostname
        except Exception:
            pass

        # Host discovery (ICMP-like via TCP)
        is_up = await self._host_discovery(host)
        result.is_up = is_up
        if not is_up:
            result.scan_time_s = time.monotonic() - start
            return result

        self._hosts_up += 1

        # Prepare ports
        ports = self.config.ports[:]
        if self.config.randomize_ports:
            random.shuffle(ports)

        # Initialize concurrency controls
        sem = asyncio.Semaphore(self.config.max_concurrent)
        if self.config.rate_limit > 0:
            rate_limiter = _RateLimiter(self.config.rate_limit)
        else:
            rate_limiter = None

        # Scan all ports concurrently
        tasks = []
        for port in ports:
            if self.config.protocol == Protocol.TCP:
                tasks.append(self._scan_tcp_port(host, port, sem, rate_limiter))
            else:
                tasks.append(self._scan_udp_port(host, port, sem, rate_limiter))

        port_results = await asyncio.gather(*tasks, return_exceptions=True)

        for pr in port_results:
            if isinstance(pr, PortResult):
                if pr.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                    result.ports.append(pr)
                    self._ports_open += 1
                self._ports_scanned += 1
            elif isinstance(pr, Exception):
                logger.debug("scan_error", host=host, error=str(pr))

        # OS detection from TTL
        if self.config.os_detection and result.ports:
            ttl_values = [p.ttl for p in result.ports if p.ttl > 0]
            if ttl_values:
                avg_ttl = sum(ttl_values) // len(ttl_values)
                result.ttl = avg_ttl
                result.os_guess = guess_os_from_ttl(avg_ttl)

        # Sort ports
        result.ports.sort(key=lambda p: p.port)
        result.scan_time_s = time.monotonic() - start
        return result

    async def scan_network(self, target: str) -> list[HostResult]:
        """Scan a network (CIDR, range, or single host)."""
        self._scan_start = time.monotonic()
        self._ports_scanned = 0
        self._ports_open = 0
        self._hosts_up = 0

        hosts = expand_targets(target)
        self._hosts_total = len(hosts)

        if self.config.randomize_hosts:
            random.shuffle(hosts)

        logger.info("scan_starting", target=target, hosts=len(hosts), ports=len(self.config.ports))

        # Scan hosts with bounded concurrency
        host_sem = asyncio.Semaphore(min(50, len(hosts)))
        tasks = [self._scan_host_with_sem(host, host_sem) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = [r for r in results if isinstance(r, HostResult)]
        elapsed = time.monotonic() - self._scan_start

        logger.info(
            "scan_complete",
            hosts_total=self._hosts_total,
            hosts_up=self._hosts_up,
            ports_scanned=self._ports_scanned,
            ports_open=self._ports_open,
            elapsed_s=round(elapsed, 2),
        )

        return valid_results

    async def scan_stream(self, target: str) -> AsyncIterator[HostResult]:
        """Stream scan results as they come in."""
        hosts = expand_targets(target)
        if self.config.randomize_hosts:
            random.shuffle(hosts)

        host_sem = asyncio.Semaphore(min(50, len(hosts)))
        for host in hosts:
            result = await self._scan_host_with_sem(host, host_sem)
            if isinstance(result, HostResult):
                yield result

    async def _scan_host_with_sem(self, host: str, sem: asyncio.Semaphore) -> HostResult:
        async with sem:
            return await self.scan_host(host)

    async def _host_discovery(self, host: str) -> bool:
        """Check if host is up via TCP connect to common ports."""
        discovery_ports = [80, 443, 22, 445, 21, 8080, 25, 3389]
        for port in discovery_ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=1.0,
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                continue
        return True  # Assume up if we can't determine

    async def _scan_tcp_port(
        self,
        host: str,
        port: int,
        sem: asyncio.Semaphore,
        rate_limiter: _RateLimiter | None,
    ) -> PortResult:
        """Scan a single TCP port."""
        async with sem:
            if rate_limiter:
                await rate_limiter.acquire()

            result = PortResult(
                host=host,
                port=port,
                protocol=Protocol.TCP,
                state=PortState.CLOSED,
            )

            for attempt in range(self.config.retries + 1):
                try:
                    start = time.monotonic()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.config.timeout_s,
                    )
                    elapsed = (time.monotonic() - start) * 1000
                    result.state = PortState.OPEN
                    result.response_time_ms = elapsed
                    result.service = WELL_KNOWN_PORTS.get(port, "")

                    # Get TTL from socket
                    try:
                        sock = writer.transport.get_extra_info("socket")
                        if sock:
                            result.ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    except Exception:
                        pass

                    # Banner grab
                    if self.config.banner_grab:
                        banner = await self._grab_banner(reader, writer, port)
                        if banner:
                            result.raw_banner = banner
                            result.banner = banner.decode("utf-8", errors="replace").strip()

                            # Service detection from banner
                            if self.config.service_detection:
                                svc, ver = self._detect_service(banner)
                                if svc:
                                    result.service = svc
                                if ver:
                                    result.version = ver

                    # SSL info for TLS ports
                    if port in (443, 465, 636, 853, 990, 993, 995, 8443):
                        try:
                            ssl_info = await self._get_ssl_info(host, port)
                            result.ssl_info = ssl_info
                        except Exception:
                            pass

                    writer.close()
                    await writer.wait_closed()
                    break

                except asyncio.TimeoutError:
                    result.state = PortState.FILTERED
                except ConnectionRefusedError:
                    result.state = PortState.CLOSED
                    break  # Definitive answer
                except OSError:
                    result.state = PortState.FILTERED

            return result

    async def _scan_udp_port(
        self,
        host: str,
        port: int,
        sem: asyncio.Semaphore,
        rate_limiter: _RateLimiter | None,
    ) -> PortResult:
        """Scan a single UDP port."""
        async with sem:
            if rate_limiter:
                await rate_limiter.acquire()

            result = PortResult(
                host=host,
                port=port,
                protocol=Protocol.UDP,
                state=PortState.OPEN_FILTERED,
            )

            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.config.timeout_s)

                # Send probe
                probe = UDP_PROBES.get(port, b"\x00" * 8) if self.config.udp_payload else b"\x00"
                await loop.sock_sendto(sock, probe, (host, port))

                try:
                    data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 4096),
                        timeout=self.config.timeout_s,
                    )
                    if data:
                        result.state = PortState.OPEN
                        result.raw_banner = data
                        result.banner = data.decode("utf-8", errors="replace").strip()[:200]
                        result.service = WELL_KNOWN_PORTS.get(port, "")
                except asyncio.TimeoutError:
                    result.state = PortState.OPEN_FILTERED
                finally:
                    sock.close()

            except Exception:
                result.state = PortState.CLOSED

            return result

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
    ) -> bytes:
        """Grab the service banner from an open port."""
        try:
            # Some services send a banner immediately
            banner = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            if banner:
                return banner
        except asyncio.TimeoutError:
            pass

        # Try sending a probe
        probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            21: b"QUIT\r\n",
            25: b"EHLO scanner\r\n",
            110: b"QUIT\r\n",
            143: b"a001 CAPABILITY\r\n",
        }
        probe = probes.get(port, b"\r\n")
        try:
            writer.write(probe)
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            return banner
        except Exception:
            return b""

    def _detect_service(self, banner: bytes) -> tuple[str, str]:
        """Detect service from banner bytes."""
        banner_str = banner.decode("utf-8", errors="replace")
        for sig, service, version_hint in BANNER_SIGNATURES:
            if sig in banner_str:
                # Try to extract version
                version = ""
                if "OpenSSH" in banner_str:
                    parts = banner_str.split("OpenSSH_")
                    if len(parts) > 1:
                        version = "OpenSSH " + parts[1].split()[0].strip()
                elif "Apache" in banner_str:
                    parts = banner_str.split("Apache/")
                    if len(parts) > 1:
                        version = "Apache " + parts[1].split()[0].strip()
                elif "nginx" in banner_str:
                    parts = banner_str.split("nginx/")
                    if len(parts) > 1:
                        version = "nginx " + parts[1].split()[0].strip()
                elif "Server:" in banner_str:
                    for line in banner_str.split("\n"):
                        if line.startswith("Server:"):
                            version = line.split(":", 1)[1].strip()
                            break
                return service, version or version_hint
        return "", ""

    async def _get_ssl_info(self, host: str, port: int) -> dict[str, Any]:
        """Extract SSL/TLS certificate information."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            ssl_obj = writer.transport.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert(binary_form=False) if ssl_obj else None

            info: dict[str, Any] = {
                "protocol": ssl_obj.version() if ssl_obj else "",
                "cipher": ssl_obj.cipher() if ssl_obj else None,
            }
            if cert:
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["not_before"] = cert.get("notBefore", "")
                info["not_after"] = cert.get("notAfter", "")
                info["serial_number"] = cert.get("serialNumber", "")
                info["san"] = [
                    entry[1]
                    for entry in cert.get("subjectAltName", [])
                ]

            writer.close()
            await writer.wait_closed()
            return info

        except Exception as e:
            return {"error": str(e)}

    def get_stats(self) -> dict[str, Any]:
        """Get scan statistics."""
        elapsed = time.monotonic() - self._scan_start if self._scan_start else 0
        return {
            "hosts_total": self._hosts_total,
            "hosts_up": self._hosts_up,
            "ports_scanned": self._ports_scanned,
            "ports_open": self._ports_open,
            "elapsed_s": round(elapsed, 2),
            "ports_per_second": round(self._ports_scanned / max(elapsed, 0.001), 1),
        }


class _RateLimiter:
    """Token bucket rate limiter for scan throttling."""

    def __init__(self, rate: int):
        self._rate = rate
        self._tokens = float(rate)
        self._max_tokens = float(rate)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._max_tokens, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# ── Convenience functions ──────────────────────────────────

async def quick_scan(target: str, ports: str = "top100") -> list[HostResult]:
    """Quick scan with sensible defaults."""
    config = ScanConfig(
        ports=parse_port_spec(ports),
        timeout_s=1.5,
        max_concurrent=500,
        banner_grab=True,
        service_detection=True,
    )
    scanner = AsyncPortScanner(config)
    return await scanner.scan_network(target)


async def stealth_scan(target: str, ports: str = "top20") -> list[HostResult]:
    """Slow, stealthy scan to avoid detection."""
    config = ScanConfig(
        ports=parse_port_spec(ports),
        timeout_s=5.0,
        max_concurrent=10,
        rate_limit=5,
        randomize_ports=True,
        randomize_hosts=True,
        banner_grab=False,
    )
    scanner = AsyncPortScanner(config)
    return await scanner.scan_network(target)


async def full_scan(target: str) -> list[HostResult]:
    """Full scan of all 65535 ports."""
    config = ScanConfig(
        ports=list(range(1, 65536)),
        timeout_s=2.0,
        max_concurrent=1000,
        banner_grab=True,
        service_detection=True,
        os_detection=True,
    )
    scanner = AsyncPortScanner(config)
    return await scanner.scan_network(target)
