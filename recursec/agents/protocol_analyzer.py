"""Protocol analyzer — reasons about network and application protocol weaknesses.

Knowledge for agent LLM prompts about:
1. TLS/SSL protocol vulnerabilities
2. HTTP/2 and HTTP/3 specific attacks
3. WebSocket security
4. DNS protocol abuse
5. Authentication protocol weaknesses
6. API protocol issues (REST, GraphQL, gRPC)
7. Email protocol exploitation (SMTP, IMAP)
8. Protocol downgrade attacks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ProtocolCategory(str, Enum):
    TLS = "tls"
    HTTP = "http"
    HTTP2 = "http2"
    HTTP3 = "http3"
    WEBSOCKET = "websocket"
    DNS = "dns"
    AUTH = "auth"
    API = "api"
    EMAIL = "email"
    SSH = "ssh"
    CUSTOM = "custom"


@dataclass
class ProtocolVulnPattern:
    """A protocol vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    protocol: ProtocolCategory = ProtocolCategory.HTTP
    description: str = ""
    detection_prompt: str = ""
    exploit_prompt: str = ""
    severity: str = "medium"
    cves: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "protocol": self.protocol.value,
            "severity": self.severity,
        }


# ── Protocol Vulnerability Patterns ───────────────────────────

PROTOCOL_PATTERNS: list[dict[str, Any]] = [
    # TLS
    {
        "id": "proto-001", "name": "TLS Version Downgrade",
        "protocol": "tls", "severity": "high",
        "desc": "Server accepts outdated TLS versions (1.0, 1.1) or SSL (3.0).",
        "detect": (
            "Test TLS version support: check if the server accepts TLS 1.0, TLS 1.1, or SSL 3.0. "
            "These versions have known vulnerabilities (BEAST, POODLE, LUCKY13). "
            "Use testssl.sh or nmap --script ssl-enum-ciphers. "
            "Modern servers should only support TLS 1.2 and 1.3."
        ),
        "exploit": (
            "A MITM attacker can force TLS version downgrade by modifying the ClientHello. "
            "If the server accepts TLS 1.0, BEAST attack can decrypt CBC-mode traffic. "
            "If SSL 3.0 is accepted, POODLE attack can decrypt padded blocks."
        ),
        "tools": ["testssl.sh", "nmap", "sslyze"],
        "cves": ["CVE-2014-3566", "CVE-2011-3389"],
    },
    {
        "id": "proto-002", "name": "Weak Cipher Suites",
        "protocol": "tls", "severity": "medium",
        "desc": "Server supports weak cipher suites (RC4, DES, NULL, EXPORT).",
        "detect": (
            "Enumerate supported cipher suites. Flag: RC4 (biased), DES/3DES (small block), "
            "NULL ciphers (no encryption), EXPORT ciphers (40-bit), MD5 HMAC, "
            "anonymous DH (no authentication). "
            "Modern best practice: only AEAD ciphers (AES-GCM, ChaCha20-Poly1305)."
        ),
        "exploit": (
            "RC4: statistical biases allow plaintext recovery after ~2^30 bytes. "
            "NULL ciphers: traffic sent in cleartext. "
            "EXPORT: 40-bit keys brute-forceable in seconds."
        ),
        "tools": ["testssl.sh", "nmap"],
    },
    {
        "id": "proto-003", "name": "Certificate Validation Bypass",
        "protocol": "tls", "severity": "critical",
        "desc": "Application doesn't properly validate TLS certificates.",
        "detect": (
            "Test certificate validation: (1) Self-signed cert, (2) Expired cert, "
            "(3) Wrong hostname, (4) Revoked cert, (5) Untrusted CA. "
            "If the application accepts any of these, MITM is possible. "
            "Check mobile apps especially — many disable cert validation for debugging."
        ),
        "exploit": (
            "Without proper cert validation, MITM attacker can present any certificate "
            "and intercept all encrypted traffic. Full credential theft, session hijacking."
        ),
        "tools": ["mitmproxy", "Burp Suite"],
    },

    # HTTP/2
    {
        "id": "proto-004", "name": "HTTP/2 Request Smuggling",
        "protocol": "http2", "severity": "critical",
        "desc": "Discrepancies between HTTP/2 frontend and HTTP/1.1 backend allow request smuggling.",
        "detect": (
            "HTTP/2 SMUGGLING: If the frontend uses HTTP/2 but proxies to HTTP/1.1 backend, "
            "discrepancies in header handling enable smuggling. Test: "
            "(1) Send request with both Content-Length and Transfer-Encoding (H2.CL or H2.TE), "
            "(2) Use HTTP/2 pseudo-headers that get misinterpreted by backend, "
            "(3) Test for CRLF injection in HTTP/2 header values. "
            "HTTP/2 binary framing means the frontend doesn't parse Content-Length, "
            "but the backend does — creating desync."
        ),
        "exploit": (
            "Smuggle requests to: hijack other users' requests, bypass WAF/auth checks, "
            "poison cache, perform SSRF. More dangerous than HTTP/1.1 smuggling because "
            "binary framing makes it harder for WAFs to detect."
        ),
        "tools": ["Burp Suite", "h2csmuggler", "smuggler"],
        "cves": ["CVE-2023-25690"],
    },
    {
        "id": "proto-005", "name": "HTTP/2 HPACK Bomb",
        "protocol": "http2", "severity": "medium",
        "desc": "HTTP/2 header compression (HPACK) can be abused for DoS via compression bombs.",
        "detect": (
            "Send HTTP/2 requests with headers that decompress to enormous sizes. "
            "HPACK dynamic table manipulation can cause memory exhaustion on the server. "
            "Check if server has limits on: header table size, header list size, "
            "max concurrent streams, max header frame size."
        ),
        "exploit": "Server memory exhaustion leading to denial of service.",
        "tools": ["h2load", "nghttp2"],
    },

    # WebSocket
    {
        "id": "proto-006", "name": "WebSocket Cross-Site Hijacking",
        "protocol": "websocket", "severity": "high",
        "desc": "WebSocket handshake doesn't verify Origin header, allowing CSWSH attacks.",
        "detect": (
            "WEBSOCKET HIJACKING: Check if the WebSocket server validates the Origin header "
            "during the upgrade handshake. If not, a malicious page can establish a WebSocket "
            "connection to the target using the victim's cookies (similar to CSRF). "
            "Test: connect to the WebSocket from a different origin and check if authentication "
            "is based solely on cookies."
        ),
        "exploit": (
            "From a malicious webpage, establish WebSocket to target. "
            "Victim's cookies are sent automatically. Read/write all WebSocket messages. "
            "Full data theft and action execution via the WebSocket channel."
        ),
        "tools": ["Burp Suite", "OWASP ZAP"],
    },

    # DNS
    {
        "id": "proto-007", "name": "DNS Rebinding",
        "protocol": "dns", "severity": "high",
        "desc": "Attacker controls DNS to bypass same-origin policy and access internal services.",
        "detect": (
            "DNS REBINDING: If the application makes DNS lookups for user-provided hostnames, "
            "test for DNS rebinding. Attack flow: "
            "(1) Victim visits attacker.com which resolves to attacker's IP, "
            "(2) After TTL expires, attacker's DNS returns internal IP (127.0.0.1, 169.254.169.254), "
            "(3) Browser considers it same-origin, JavaScript can now read internal responses. "
            "Check if the application: pins DNS results, validates resolved IP ranges, "
            "or uses Host header validation."
        ),
        "exploit": (
            "Access internal services, cloud metadata, admin panels that are only "
            "accessible from localhost. Bypass SSRF protections that only check at DNS time."
        ),
        "tools": ["singularity", "rbndr"],
    },

    # Authentication protocols
    {
        "id": "proto-008", "name": "OAuth 2.0 Misimplementation",
        "protocol": "auth", "severity": "high",
        "desc": "Common OAuth implementation flaws: open redirect, state missing, token leakage.",
        "detect": (
            "Test OAuth 2.0 for: "
            "(1) OPEN REDIRECT in redirect_uri: change to attacker.com to steal auth code. "
            "(2) Missing STATE parameter: CSRF on OAuth flow, attacker links their account. "
            "(3) Token in URL fragment: leaked via Referer header or browser history. "
            "(4) Implicit flow token reuse: stolen access_token from one client used on another. "
            "(5) PKCE bypass: if public client doesn't use PKCE, auth codes interceptable."
        ),
        "exploit": (
            "Account takeover via open redirect + auth code theft. "
            "Session fixation via missing state parameter. "
            "Token theft via Referer leakage."
        ),
        "tools": ["Burp Suite", "OWASP ZAP"],
    },
    {
        "id": "proto-009", "name": "JWT Implementation Flaws",
        "protocol": "auth", "severity": "critical",
        "desc": "JWT vulnerabilities: alg:none, key confusion, weak secrets, expired tokens.",
        "detect": (
            "Test JWT for: "
            "(1) ALG:NONE — set algorithm to 'none' and remove signature. If accepted, full bypass. "
            "(2) RS256→HS256 CONFUSION — sign with the PUBLIC key using HS256. If the server uses "
            "the public key to verify HS256, the signature is valid (key confusion attack). "
            "(3) WEAK SECRET — brute-force HS256 secret with hashcat/jwt_tool. "
            "(4) EXPIRED TOKENS — send expired JWT and check if server rejects it. "
            "(5) KID INJECTION — kid header may allow SQL injection or path traversal. "
            "(6) JKU/X5U HEADER — point to attacker-controlled key server."
        ),
        "exploit": (
            "Forge arbitrary JWTs to impersonate any user, escalate privileges, "
            "or bypass authentication entirely."
        ),
        "tools": ["jwt_tool", "hashcat", "Burp Suite"],
    },

    # GraphQL
    {
        "id": "proto-010", "name": "GraphQL Security Issues",
        "protocol": "api", "severity": "high",
        "desc": "GraphQL-specific vulnerabilities: introspection, batching, deep queries.",
        "detect": (
            "Test GraphQL endpoint for: "
            "(1) INTROSPECTION ENABLED — query __schema to dump entire API schema. "
            "Reveals all types, fields, mutations, and subscriptions. "
            "(2) BATCHING ATTACK — send array of queries in single request to bypass rate limiting. "
            "(3) DEEP QUERY DOS — craft deeply nested query that causes exponential resolution time. "
            "(4) FIELD SUGGESTION — error messages may suggest valid field names (info disclosure). "
            "(5) IDOR VIA QUERY — nodes query with arbitrary IDs to access other users' data. "
            "(6) MUTATION AUTHORIZATION — check if mutations have proper auth, not just queries."
        ),
        "exploit": (
            "Full API schema disclosure via introspection. "
            "Rate limit bypass via batching. "
            "DoS via deep/circular queries."
        ),
        "tools": ["graphql-cop", "InQL", "Altair", "Burp Suite"],
    },

    # gRPC
    {
        "id": "proto-011", "name": "gRPC Reflection and Abuse",
        "protocol": "api", "severity": "medium",
        "desc": "gRPC server reflection enabled, allowing service discovery and message crafting.",
        "detect": (
            "Test gRPC service for: "
            "(1) SERVER REFLECTION — if enabled, use grpcurl to list all services and methods. "
            "This reveals the entire API surface. "
            "(2) NO TLS — gRPC over plaintext allows traffic interception. "
            "(3) NO AUTH — methods accessible without authentication tokens. "
            "(4) LARGE MESSAGE — send oversized protobuf messages to test for DoS. "
            "grpcurl -plaintext target:port list"
        ),
        "exploit": (
            "Full API discovery via reflection. "
            "Craft arbitrary protobuf messages to invoke any method."
        ),
        "tools": ["grpcurl", "grpc_tools"],
    },

    # SSH
    {
        "id": "proto-012", "name": "SSH Key and Config Weaknesses",
        "protocol": "ssh", "severity": "high",
        "desc": "Weak SSH keys, outdated algorithms, agent forwarding abuse.",
        "detect": (
            "Test SSH for: "
            "(1) WEAK KEY — RSA < 2048 bits, DSA (always 1024), ECDSA with weak curves. "
            "(2) PASSWORD AUTH — password-based auth enables brute-force attacks. "
            "(3) AGENT FORWARDING — if enabled, compromised server can use your SSH keys. "
            "(4) OUTDATED ALGORITHMS — diffie-hellman-group1-sha1, ssh-dss, arcfour. "
            "(5) ROOT LOGIN — PermitRootLogin yes allows direct root access. "
            "ssh-audit is the best tool for comprehensive SSH security testing."
        ),
        "exploit": (
            "Brute-force passwords, abuse agent forwarding for lateral movement, "
            "downgrade to weak algorithms for interception."
        ),
        "tools": ["ssh-audit", "hydra"],
    },
]


class ProtocolAnalyzer:
    """Provides protocol vulnerability knowledge for agent reasoning.

    This knowledge gets injected into agent prompts so the LLMs
    reason about protocol-level attack surfaces.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ProtocolVulnPattern] = {}
        self._log = logger.bind(component="protocol_analyzer")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load protocol vulnerability patterns."""
        for data in PROTOCOL_PATTERNS:
            pattern = ProtocolVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                protocol=ProtocolCategory(data["protocol"]),
                description=data.get("desc", ""),
                detection_prompt=data.get("detect", ""),
                exploit_prompt=data.get("exploit", ""),
                severity=data.get("severity", "medium"),
                cves=data.get("cves", []),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_protocol(
        self,
        protocol: str,
    ) -> list[ProtocolVulnPattern]:
        """Get vulnerability patterns for a specific protocol."""
        try:
            proto = ProtocolCategory(protocol)
        except ValueError:
            return []

        return [
            p for p in self._patterns.values()
            if p.protocol == proto
        ]

    def get_detection_prompts(
        self,
        protocols: list[str] | None = None,
    ) -> list[str]:
        """Get detection prompts for specified protocols."""
        prompts = []

        for pattern in self._patterns.values():
            if protocols:
                if pattern.protocol.value not in protocols:
                    continue

            if pattern.detection_prompt:
                prompts.append(pattern.detection_prompt)

        return prompts

    def get_relevant_patterns(
        self,
        technologies: list[str],
    ) -> list[ProtocolVulnPattern]:
        """Get patterns relevant to detected technologies."""
        relevant = []
        tech_lower = [t.lower() for t in technologies]

        protocol_keywords = {
            "tls": ["ssl", "tls", "https", "certificate"],
            "http2": ["http2", "h2", "h2c"],
            "http3": ["http3", "quic"],
            "websocket": ["websocket", "ws", "wss", "socket.io"],
            "dns": ["dns", "bind", "named"],
            "auth": ["oauth", "jwt", "saml", "oidc", "auth"],
            "api": ["graphql", "grpc", "rest", "api"],
            "email": ["smtp", "imap", "pop3", "mail"],
            "ssh": ["ssh", "openssh", "sshd"],
        }

        matched_protocols: set[str] = set()
        for proto, keywords in protocol_keywords.items():
            for tech in tech_lower:
                if any(kw in tech for kw in keywords):
                    matched_protocols.add(proto)

        for pattern in self._patterns.values():
            if pattern.protocol.value in matched_protocols:
                relevant.append(pattern)

        return relevant

    def build_protocol_prompt(
        self,
        technologies: list[str],
        max_patterns: int = 5,
    ) -> str:
        """Build a prompt with protocol vulnerability knowledge."""
        relevant = self.get_relevant_patterns(technologies)
        if not relevant:
            return ""

        lines = ["## Protocol-Specific Vulnerability Checks\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity}]")
            lines.append(pattern.detection_prompt)
            if pattern.tools:
                lines.append(f"Tools: {', '.join(pattern.tools)}")
            lines.append("")

        return "\n".join(lines)

    def get_pattern(self, pattern_id: str) -> ProtocolVulnPattern | None:
        return self._patterns.get(pattern_id)

    def get_stats(self) -> dict[str, Any]:
        proto_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            proto_counts[p.protocol.value] += 1
        return {
            "patterns": len(self._patterns),
            "by_protocol": dict(proto_counts),
            "total_cves": sum(
                len(p.cves) for p in self._patterns.values()
            ),
        }
