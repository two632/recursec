"""Cryptography security knowledge base.

Deep knowledge about cryptographic vulnerabilities:
1. Weak TLS/SSL configuration
2. Padding oracle attacks
3. Hash collision exploitation
4. Key management flaws
5. Cryptographic implementation errors
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CryptoPattern:
    """A cryptographic vulnerability pattern."""
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


CRYPTO_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "crypto-001", "name": "Weak TLS Configuration",
        "category": "tls", "severity": "high",
        "desc": "Detecting weak TLS/SSL configurations.",
        "detection": (
            "WEAK TLS CONFIGURATION:\n"
            "SCANNING:\n"
            "  # testssl.sh — comprehensive TLS tester\n"
            "  testssl.sh <host>:<port>\n"
            "  testssl.sh --severity HIGH <host>\n"
            "  # sslscan\n"
            "  sslscan <host>:<port>\n"
            "  # nmap NSE\n"
            "  nmap --script ssl-enum-ciphers -p 443 <host>\n"
            "VULNERABILITIES TO CHECK:\n"
            "  SSL/TLS VERSION:\n"
            "    - SSLv2, SSLv3: CRITICAL (DROWN, POODLE)\n"
            "    - TLS 1.0: HIGH (BEAST)\n"
            "    - TLS 1.1: MEDIUM (deprecated)\n"
            "    - TLS 1.2: OK (with good ciphers)\n"
            "    - TLS 1.3: BEST\n"
            "  CIPHER SUITES:\n"
            "    - NULL ciphers: No encryption\n"
            "    - EXPORT ciphers: Weak (FREAK, Logjam)\n"
            "    - RC4: Broken\n"
            "    - DES/3DES: Weak (Sweet32)\n"
            "    - CBC mode: Vulnerable (BEAST, Lucky13)\n"
            "  KNOWN ATTACKS:\n"
            "    - Heartbleed (CVE-2014-0160): Memory leak\n"
            "    - ROBOT: RSA padding oracle\n"
            "    - CRIME/BREACH: Compression oracle\n"
            "    - Raccoon: DH timing attack\n"
            "  CERTIFICATE ISSUES:\n"
            "    - Self-signed certificates\n"
            "    - Expired certificates\n"
            "    - Wrong hostname\n"
            "    - Weak signature (SHA-1, MD5)"
        ),
        "tools": ["testssl", "sslscan", "nmap"],
    },
    {
        "id": "crypto-002", "name": "Padding Oracle Attacks",
        "category": "padding_oracle", "severity": "critical",
        "desc": "Exploiting CBC padding oracles.",
        "detection": (
            "PADDING ORACLE ATTACKS:\n"
            "DETECTION:\n"
            "  - Send valid encrypted data → observe response\n"
            "  - Modify last byte of ciphertext block\n"
            "  - Different error for padding vs application error = ORACLE\n"
            "  - Timing differences can also reveal oracle\n"
            "EXPLOITATION:\n"
            "  # PadBuster — automated padding oracle\n"
            "  padbuster <url> <encrypted_sample> <block_size>\n"
            "  padbuster <url> <sample> 8 -encoding 0 -plaintext '<desired>'\n"
            "  # Decrypt any ciphertext byte-by-byte\n"
            "  # Forge new valid ciphertext without key\n"
            "COMMON TARGETS:\n"
            "  - ASP.NET ViewState (ScriptResource.axd)\n"
            "  - Session cookies with CBC encryption\n"
            "  - Encrypted tokens in URL parameters\n"
            "  - Java serialized objects with CBC\n"
            "  - XML Encryption (CBC mode)\n"
            "INDICATORS:\n"
            "  - 500 vs 200 status codes on modified ciphertext\n"
            "  - 'Padding is invalid' error messages\n"
            "  - Different response length for padding vs data errors\n"
            "  - Timing difference > 10ms between error types"
        ),
        "tools": ["padbuster", "burp"],
    },
    {
        "id": "crypto-003", "name": "JWT Vulnerabilities",
        "category": "jwt", "severity": "critical",
        "desc": "Exploiting JSON Web Token implementation flaws.",
        "detection": (
            "JWT VULNERABILITIES:\n"
            "ALGORITHM CONFUSION:\n"
            "  # Change 'alg' from RS256 to HS256\n"
            "  # Use public key as HMAC secret\n"
            "  # If server verifies HS256 with RSA public key → forge tokens\n"
            "NONE ALGORITHM:\n"
            "  # Change 'alg' to 'none' or 'None'\n"
            "  # Remove signature\n"
            "  # If server accepts → full bypass\n"
            "  python3 -c \"import jwt; print(jwt.encode({'admin': True}, '', algorithm='none'))\"\n"
            "KEY CONFUSION (jwk/jku/kid):\n"
            "  # Embed attacker's public key in JWK header\n"
            "  # Point JKU to attacker-controlled URL\n"
            "  # KID injection (SQL injection, path traversal)\n"
            "  # kid: ../../dev/null → HMAC with empty string\n"
            "WEAK SECRETS:\n"
            "  # Brute force HMAC secret\n"
            "  hashcat -m 16500 <jwt> <wordlist>\n"
            "  john --format=HMAC-SHA256 jwt.txt\n"
            "  # Common weak secrets: 'secret', 'password', company name\n"
            "TOOLS:\n"
            "  jwt_tool <jwt> -T  # Tamper mode\n"
            "  jwt_tool <jwt> -C -d wordlist.txt  # Crack secret\n"
            "  jwt_tool <jwt> -X a  # Algorithm confusion"
        ),
        "tools": ["jwt_tool", "hashcat", "john"],
    },
    {
        "id": "crypto-004", "name": "Insecure Random Number Generation",
        "category": "rng", "severity": "high",
        "desc": "Exploiting weak random number generators.",
        "detection": (
            "INSECURE RNG:\n"
            "DETECTION:\n"
            "  - Collect multiple tokens/session IDs\n"
            "  - Check for patterns (sequential, time-based)\n"
            "  - Statistical tests for randomness\n"
            "COMMON WEAKNESSES:\n"
            "  - Math.random() in JavaScript (not cryptographic)\n"
            "  - Python random module (Mersenne Twister, predictable)\n"
            "  - time() as seed → predictable if time known\n"
            "  - Process ID as seed → limited entropy\n"
            "  - Insufficient entropy sources\n"
            "EXPLOITATION:\n"
            "  SESSION PREDICTION:\n"
            "    - Collect ~1000 session tokens\n"
            "    - Analyze for Mersenne Twister state recovery\n"
            "    - With 624 consecutive 32-bit outputs → predict all future\n"
            "    - Tools: randcrack (Python Mersenne Twister cracker)\n"
            "  CSRF TOKEN PREDICTION:\n"
            "    - If based on time: predict from server time header\n"
            "    - If sequential: predict from observed pattern\n"
            "  PASSWORD RESET TOKENS:\n"
            "    - Generate reset for attacker account\n"
            "    - Generate reset for victim account\n"
            "    - If tokens are sequential → derive victim's token"
        ),
        "tools": ["burp", "custom-scripts"],
    },
    {
        "id": "crypto-005", "name": "Hash Function Exploitation",
        "category": "hash", "severity": "high",
        "desc": "Exploiting weak hash functions and hash-related vulnerabilities.",
        "detection": (
            "HASH EXPLOITATION:\n"
            "PASSWORD CRACKING:\n"
            "  # Identify hash type\n"
            "  hashid <hash>\n"
            "  # hashcat modes\n"
            "  hashcat -m 0 <hashes> <wordlist>   # MD5\n"
            "  hashcat -m 100 <hashes> <wordlist>  # SHA-1\n"
            "  hashcat -m 1400 <hashes> <wordlist> # SHA-256\n"
            "  hashcat -m 3200 <hashes> <wordlist> # bcrypt\n"
            "  hashcat -m 1800 <hashes> <wordlist> # SHA-512crypt\n"
            "  # Rules for mutation\n"
            "  hashcat -m 0 <hashes> <wordlist> -r rules/best64.rule\n"
            "HASH LENGTH EXTENSION:\n"
            "  - MD5, SHA-1, SHA-256 are vulnerable\n"
            "  - If MAC = H(secret || message): can extend\n"
            "  - Tool: hash_extender\n"
            "  - hash_extender --data <known> --secret <len> --append <new>\n"
            "TYPE JUGGLING (PHP):\n"
            "  - md5('240610708') starts with '0e'\n"
            "  - PHP loose comparison: '0e...' == '0e...' → true\n"
            "  - '0' == 'string starting with 0e and digits only'\n"
            "COLLISION ATTACKS:\n"
            "  - MD5: Practical collision in seconds\n"
            "  - SHA-1: SHAttered (first public collision 2017)\n"
            "  - Can create two PDFs with same hash"
        ),
        "tools": ["hashcat", "john", "hashid"],
    },
]


class CryptographyKB:
    """Cryptography security knowledge base.

    Provides cryptographic vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CryptoPattern] = {}
        self._log = logger.bind(component="cryptography_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load crypto patterns."""
        for data in CRYPTO_PATTERNS:
            pattern = CryptoPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[CryptoPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_crypto_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build cryptography prompt."""
        lines = ["## Cryptographic Vulnerability Patterns\n"]
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
