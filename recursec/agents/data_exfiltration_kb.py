"""Data exfiltration knowledge base.

Deep knowledge about data exfiltration:
1. Network-based exfiltration
2. Physical/media exfiltration
3. Cloud-based exfiltration
4. Covert channel techniques
5. Exfiltration detection and prevention
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ExfilPattern:
    """A data exfiltration pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


EXFIL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "exf-001", "name": "Network-Based Exfiltration",
        "category": "network", "severity": "critical",
        "desc": "Network-based data exfiltration.",
        "detection": (
            "NETWORK-BASED EXFILTRATION:\n"
            "DNS:\n"
            "  - DNS tunneling (iodine, dnscat2)\n"
            "  - Subdomain encoding (base64 in labels)\n"
            "  - TXT record data\n"
            "  - High-volume DNS queries\n"
            "  # Detection: unusual query volume, long\n"
            "  # subdomain labels, entropy analysis\n"
            "HTTP/HTTPS:\n"
            "  - POST data to external server\n"
            "  - Steganography in images\n"
            "  - WebSocket data streams\n"
            "  - Domain fronting\n"
            "  - CDN abuse for data transfer\n"
            "  # Detection: unusual upload volumes,\n"
            "  # connections to new domains\n"
            "ICMP:\n"
            "  - ICMP tunnel (ptunnel, icmpsh)\n"
            "  - Data in ICMP payload\n"
            "  # Detection: unusual ICMP sizes, frequency\n"
            "EMAIL:\n"
            "  - Attachments to personal email\n"
            "  - Encoded data in body\n"
            "  - BCC to external addresses\n"
            "  # Detection: DLP email scanning\n"
            "ENCRYPTED:\n"
            "  - Custom encrypted channels\n"
            "  - Tor/VPN tunnels\n"
            "  - SSH/SCP to external hosts\n"
            "  - Encrypted cloud sync\n"
            "  # Detection: traffic analysis, JA3/JA4\n"
            "TOOLS:\n"
            "  dnscat2, iodine, ptunnel, custom scripts"
        ),
        "tools": ["dnscat2"],
    },
    {
        "id": "exf-002", "name": "Physical/Media Exfiltration",
        "category": "physical", "severity": "high",
        "desc": "Physical media exfiltration.",
        "detection": (
            "PHYSICAL EXFILTRATION:\n"
            "USB:\n"
            "  - USB mass storage devices\n"
            "  - USB Rubber Ducky (automated copy)\n"
            "  - Modified USB cables (data exfil)\n"
            "  - Encrypted USB drives\n"
            "  # Detection: USB device logging,\n"
            "  # endpoint DLP, USB whitelist\n"
            "PRINT:\n"
            "  - Print sensitive documents\n"
            "  - Print to PDF, then transfer\n"
            "  - Screenshot → print\n"
            "  # Detection: print job monitoring\n"
            "CAMERA:\n"
            "  - Photograph screens\n"
            "  - Photograph documents\n"
            "  - Smartwatch/glasses\n"
            "  # Detection: physical security cameras\n"
            "PORTABLE DEVICES:\n"
            "  - External hard drives\n"
            "  - SD cards\n"
            "  - Bluetooth file transfer\n"
            "  - NFC data transfer\n"
            "  - Wi-Fi Direct\n"
            "  # Detection: device control policies\n"
            "PAPER:\n"
            "  - Copy documents\n"
            "  - Write down credentials\n"
            "  - Memorize sensitive data\n"
            "TOOLS:\n"
            "  USB Rubber Ducky, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "exf-003", "name": "Cloud-Based Exfiltration",
        "category": "cloud", "severity": "high",
        "desc": "Cloud-based data exfiltration.",
        "detection": (
            "CLOUD-BASED EXFILTRATION:\n"
            "CLOUD STORAGE:\n"
            "  - Dropbox, Google Drive, OneDrive\n"
            "  - S3 bucket upload (own account)\n"
            "  - Azure Blob storage\n"
            "  - Mega.nz (encrypted by default)\n"
            "  # Detection: CASB monitoring,\n"
            "  # unusual cloud service access\n"
            "CODE REPOS:\n"
            "  - GitHub private repo push\n"
            "  - GitLab CI artifacts\n"
            "  - Bitbucket uploads\n"
            "  # Detection: git operation monitoring\n"
            "COLLABORATION:\n"
            "  - Slack file uploads\n"
            "  - Teams message attachments\n"
            "  - Discord webhooks\n"
            "  - Telegram bot API\n"
            "  # Detection: API monitoring, DLP\n"
            "SERVERLESS:\n"
            "  - Lambda/Cloud Function as relay\n"
            "  - API Gateway as proxy\n"
            "  - Cloudflare Workers\n"
            "  # Detection: unusual function invocations\n"
            "CI/CD:\n"
            "  - Build artifact exfiltration\n"
            "  - Pipeline output capture\n"
            "  - Environment variable logging\n"
            "  # Detection: artifact access audit\n"
            "TOOLS:\n"
            "  Custom scripts, cloud CLIs"
        ),
        "tools": [],
    },
    {
        "id": "exf-004", "name": "Covert Channels",
        "category": "covert", "severity": "critical",
        "desc": "Covert channel techniques.",
        "detection": (
            "COVERT CHANNELS:\n"
            "STEGANOGRAPHY:\n"
            "  - Image steganography (LSB)\n"
            "  - Audio steganography\n"
            "  - Video steganography\n"
            "  - Document steganography\n"
            "  - Network steganography\n"
            "  TOOLS:\n"
            "    steghide, stegsolve, OpenStego\n"
            "TIMING CHANNELS:\n"
            "  - Packet timing encoding\n"
            "  - Request interval modulation\n"
            "  - TCP ISN covert channel\n"
            "  - HTTP response timing\n"
            "PROTOCOL ABUSE:\n"
            "  - TCP sequence numbers\n"
            "  - IP identification field\n"
            "  - IPv6 flow label\n"
            "  - HTTP headers (custom)\n"
            "  - TLS session data\n"
            "  - MQTT/CoAP payloads\n"
            "DEAD DROPS:\n"
            "  - Cloud storage sharing\n"
            "  - Pastebin/pastebins\n"
            "  - Image hosting sites\n"
            "  - Social media posts\n"
            "  - Blockchain transactions\n"
            "DETECTION:\n"
            "  - Statistical analysis\n"
            "  - Entropy measurement\n"
            "  - Protocol anomaly detection\n"
            "  - Traffic pattern analysis\n"
            "  - ML-based detection\n"
            "TOOLS:\n"
            "  steghide, custom scripts, scapy"
        ),
        "tools": ["scapy"],
    },
    {
        "id": "exf-005", "name": "Exfiltration Detection/Prevention",
        "category": "detection", "severity": "high",
        "desc": "Detecting and preventing exfiltration.",
        "detection": (
            "EXFILTRATION DETECTION & PREVENTION:\n"
            "DLP (Data Loss Prevention):\n"
            "  - Network DLP (egress inspection)\n"
            "  - Endpoint DLP (file operations)\n"
            "  - Cloud DLP (CASB integration)\n"
            "  - Email DLP (attachment scanning)\n"
            "  - Content inspection (regex, ML)\n"
            "  - Fingerprinting (sensitive data)\n"
            "NETWORK MONITORING:\n"
            "  - Unusual outbound volume\n"
            "  - Off-hours data transfer\n"
            "  - Connections to new destinations\n"
            "  - DNS query anomalies\n"
            "  - Protocol anomalies\n"
            "  - Encrypted traffic analysis\n"
            "ENDPOINT:\n"
            "  - USB device control\n"
            "  - Application whitelisting\n"
            "  - Clipboard monitoring\n"
            "  - Screen capture detection\n"
            "  - File access auditing\n"
            "CLOUD:\n"
            "  - CASB (Cloud Access Security Broker)\n"
            "  - API activity monitoring\n"
            "  - Cloud storage policies\n"
            "  - Shadow IT detection\n"
            "BEST PRACTICES:\n"
            "  - Data classification\n"
            "  - Least privilege access\n"
            "  - Network segmentation\n"
            "  - Egress filtering\n"
            "  - Watermarking/tracking\n"
            "TOOLS:\n"
            "  Wireshark, Zeek, SIEM, DLP platforms"
        ),
        "tools": ["zeek"],
    },
]


class DataExfiltrationKB:
    """Data exfiltration knowledge base.

    Provides data exfiltration patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ExfilPattern] = {}
        self._log = logger.bind(component="exfil_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load exfiltration patterns."""
        for data in EXFIL_PATTERNS:
            pattern = ExfilPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[ExfilPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_exfiltration_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build data exfiltration prompt."""
        lines = ["## Data Exfiltration\n"]
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
