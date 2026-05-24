"""DDoS and availability attacks knowledge base.

Deep knowledge about availability attacks:
1. Network layer DDoS
2. Application layer DDoS
3. Protocol exploitation DDoS
4. DDoS mitigation strategies
5. Resilience testing methodology
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class DDoSPattern:
    """A DDoS/availability pattern."""
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


DDOS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ddos-001", "name": "Network Layer DDoS",
        "category": "network_ddos", "severity": "high",
        "desc": "Network layer DDoS attacks.",
        "detection": (
            "NETWORK LAYER DDoS:\n"
            "VOLUMETRIC:\n"
            "  - UDP flood\n"
            "  - ICMP flood\n"
            "  - DNS amplification\n"
            "  - NTP amplification\n"
            "  - SSDP amplification\n"
            "  - Memcached amplification\n"
            "  - CLDAP amplification\n"
            "  AMPLIFICATION FACTORS:\n"
            "    DNS: 28-54x\n"
            "    NTP: 556x\n"
            "    Memcached: 51,000x\n"
            "    SSDP: 30x\n"
            "    CLDAP: 70x\n"
            "SYN FLOOD:\n"
            "  - TCP SYN without ACK\n"
            "  - Exhaust connection tables\n"
            "  - Spoofed source IPs\n"
            "  - SYN+ACK reflection\n"
            "FRAGMENTATION:\n"
            "  - IP fragmentation overlap\n"
            "  - Teardrop attack\n"
            "  - Fragment reassembly DoS\n"
            "TESTING (authorized):\n"
            "  # hping3 SYN flood test\n"
            "  hping3 -S --flood -V -p 80 TARGET\n"
            "  # Low-rate (safe) volumetric test\n"
            "  # Always coordinate with hosting\n"
            "DETECTION:\n"
            "  - Unexpected traffic spikes\n"
            "  - Source IP diversity analysis\n"
            "  - Protocol distribution anomaly\n"
            "  - NetFlow/IPFIX analysis\n"
            "TOOLS:\n"
            "  hping3, scapy (testing only)"
        ),
        "tools": ["hping3"],
    },
    {
        "id": "ddos-002", "name": "Application Layer DDoS",
        "category": "app_ddos", "severity": "high",
        "desc": "Application layer DDoS attacks.",
        "detection": (
            "APPLICATION LAYER DDoS:\n"
            "HTTP FLOOD:\n"
            "  - GET/POST request flood\n"
            "  - Randomized URLs and headers\n"
            "  - Bypasses rate limiting\n"
            "  - Mimics legitimate traffic\n"
            "SLOWLORIS:\n"
            "  - Incomplete HTTP requests\n"
            "  - Keep connections open\n"
            "  - Exhaust connection pool\n"
            "  - Very low bandwidth needed\n"
            "SLOW POST:\n"
            "  - Send body slowly\n"
            "  - Content-Length: large value\n"
            "  - Trickle data byte-by-byte\n"
            "RUDY (R-U-Dead-Yet):\n"
            "  - Target form submissions\n"
            "  - Long POST body, slow send\n"
            "REGEX DoS (ReDoS):\n"
            "  - Craft input to cause backtracking\n"
            "  - Exponential regex processing\n"
            "  - Common in input validation\n"
            "API ABUSE:\n"
            "  - Expensive query parameters\n"
            "  - GraphQL complexity attacks\n"
            "  - Search/filter abuse\n"
            "  - Pagination exploitation\n"
            "TESTING:\n"
            "  # slowhttptest (Slowloris + Slow POST)\n"
            "  slowhttptest -c 1000 -H -u http://TARGET\n"
            "TOOLS:\n"
            "  slowhttptest, GoldenEye (testing only)"
        ),
        "tools": ["slowhttptest"],
    },
    {
        "id": "ddos-003", "name": "Protocol Exploitation DDoS",
        "category": "protocol_ddos", "severity": "high",
        "desc": "Protocol exploitation attacks.",
        "detection": (
            "PROTOCOL EXPLOITATION:\n"
            "TLS EXHAUSTION:\n"
            "  - Renegotiation attack\n"
            "  - Asymmetric cost: client cheap, server expensive\n"
            "  - THC-SSL-DOS principle\n"
            "  - Connection flood with TLS handshakes\n"
            "DNS WATER TORTURE:\n"
            "  - Random subdomain queries\n"
            "  - Bypass DNS caches\n"
            "  - Exhaust authoritative DNS\n"
            "  - Hard to distinguish from legitimate\n"
            "DHCP STARVATION:\n"
            "  - Exhaust IP address pool\n"
            "  - Prevent new device connectivity\n"
            "  - yersinia DHCP attacks\n"
            "NTP MONLIST:\n"
            "  - ntpdc -c monlist TARGET\n"
            "  - 600 entries response to 1 query\n"
            "BGP ROUTE LEAK:\n"
            "  - Cause route blackholing\n"
            "  - Traffic redirection\n"
            "  - Routing instability\n"
            "WEBSOCKET:\n"
            "  - Connection flood\n"
            "  - Message flood\n"
            "  - Slow close\n"
            "  - Frame fragmentation\n"
            "DETECTION:\n"
            "  - Protocol behavior analysis\n"
            "  - Connection state monitoring\n"
            "  - Resource utilization tracking\n"
            "TOOLS:\n"
            "  yersinia, hping3, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "ddos-004", "name": "DDoS Mitigation Strategies",
        "category": "mitigation", "severity": "medium",
        "desc": "DDoS mitigation and defense.",
        "detection": (
            "DDoS MITIGATION:\n"
            "NETWORK LEVEL:\n"
            "  - BGP blackholing (RTBH)\n"
            "  - Scrubbing centers\n"
            "  - BGP Flowspec filtering\n"
            "  - Source IP validation (BCP38)\n"
            "  - ACL rate limiting\n"
            "  - GeoIP blocking\n"
            "CDN/PROXY:\n"
            "  - Cloudflare\n"
            "  - AWS Shield (Standard/Advanced)\n"
            "  - Azure DDoS Protection\n"
            "  - GCP Cloud Armor\n"
            "  - Akamai Kona Site Defender\n"
            "APPLICATION:\n"
            "  - Rate limiting (per IP, per session)\n"
            "  - CAPTCHA challenges\n"
            "  - JavaScript challenges\n"
            "  - Connection limits\n"
            "  - Request throttling\n"
            "  - WAF rules\n"
            "ARCHITECTURE:\n"
            "  - Auto-scaling\n"
            "  - Geographic distribution\n"
            "  - Circuit breakers\n"
            "  - Graceful degradation\n"
            "  - Static content caching\n"
            "  - Connection pooling\n"
            "ASSESSMENT:\n"
            "  - Test mitigation effectiveness\n"
            "  - Verify failover works\n"
            "  - Load test with realistic traffic\n"
            "  - Review DDoS response playbook\n"
            "TOOLS:\n"
            "  Cloud WAFs, load testing tools"
        ),
        "tools": [],
    },
    {
        "id": "ddos-005", "name": "Resilience Testing",
        "category": "resilience", "severity": "medium",
        "desc": "Resilience and availability testing.",
        "detection": (
            "RESILIENCE TESTING:\n"
            "STRESS TESTING:\n"
            "  # wrk (HTTP benchmarking)\n"
            "  wrk -t12 -c400 -d30s http://TARGET\n"
            "  # ab (Apache Bench)\n"
            "  ab -n 10000 -c 100 http://TARGET/\n"
            "  # vegeta (HTTP load testing)\n"
            "  echo 'GET http://TARGET' | vegeta attack -rate=100/s\n"
            "  # k6 (modern load testing)\n"
            "  k6 run script.js\n"
            "  # locust (Python-based)\n"
            "  locust -f locustfile.py --host=http://TARGET\n"
            "CHAOS ENGINEERING:\n"
            "  - Kill random instances\n"
            "  - Inject network latency\n"
            "  - Fill disk space\n"
            "  - Exhaust CPU/memory\n"
            "  - Block network partitions\n"
            "  TOOLS:\n"
            "    Chaos Monkey, Litmus, ChaosBlade\n"
            "FAILOVER TESTING:\n"
            "  - Database failover\n"
            "  - Load balancer failover\n"
            "  - Region failover\n"
            "  - CDN origin failover\n"
            "  - DNS failover\n"
            "CAPACITY PLANNING:\n"
            "  - Baseline performance metrics\n"
            "  - Identify bottlenecks\n"
            "  - Auto-scale thresholds\n"
            "  - Cost vs resilience tradeoffs\n"
            "TOOLS:\n"
            "  wrk, vegeta, k6, locust, Chaos Monkey"
        ),
        "tools": ["wrk", "k6"],
    },
]


class DDoSAvailabilityKB:
    """DDoS and availability knowledge base.

    Provides DDoS attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, DDoSPattern] = {}
        self._log = logger.bind(component="ddos_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load DDoS patterns."""
        for data in DDOS_PATTERNS:
            pattern = DDoSPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[DDoSPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_ddos_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build DDoS/availability prompt."""
        lines = ["## DDoS & Availability Attacks\n"]
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
