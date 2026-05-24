"""Cryptographic attacks knowledge base.

Deep knowledge about cryptographic attacks:
1. TLS/SSL attacks
2. Hash attacks
3. Symmetric cipher attacks
4. PKI/certificate attacks
5. Cryptographic implementation flaws
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CryptoPattern:
    """A cryptographic attack pattern."""
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
        "id": "cry-001", "name": "TLS/SSL Attacks",
        "category": "tls", "severity": "high",
        "desc": "TLS/SSL protocol attacks.",
        "detection": (
            "TLS/SSL ATTACKS:\n"
            "PROTOCOL:\n"
            "  - SSLv2 (DROWN attack)\n"
            "  - SSLv3 (POODLE attack)\n"
            "  - TLS 1.0 (BEAST attack)\n"
            "  - TLS 1.1 (deprecated)\n"
            "  - TLS 1.2 (weak ciphers possible)\n"
            "  - TLS 1.3 (current best)\n"
            "CIPHER SUITES:\n"
            "  - RC4 (biased output)\n"
            "  - 3DES (Sweet32)\n"
            "  - CBC mode (Lucky13, padding oracles)\n"
            "  - Export ciphers (FREAK, Logjam)\n"
            "  - NULL ciphers\n"
            "ATTACKS:\n"
            "  HEARTBLEED (CVE-2014-0160):\n"
            "    - OpenSSL memory disclosure\n"
            "    - Leak private keys, session data\n"
            "  ROBOT:\n"
            "    - RSA PKCS#1 v1.5 padding oracle\n"
            "    - Decrypt pre-master secret\n"
            "  RENEGOTIATION:\n"
            "    - Client-initiated renegotiation DoS\n"
            "    - Triple handshake attack\n"
            "  TICKETBLEED:\n"
            "    - F5 BIG-IP session ticket leak\n"
            "TESTING:\n"
            "  # testssl.sh\n"
            "  ./testssl.sh target.com\n"
            "  # sslyze\n"
            "  sslyze --regular target.com\n"
            "  # nmap\n"
            "  nmap --script ssl-enum-ciphers -p 443 target\n"
            "TOOLS:\n"
            "  testssl.sh, sslyze, nmap, sslscan"
        ),
        "tools": ["testssl.sh", "sslyze"],
    },
    {
        "id": "cry-002", "name": "Hash Attacks",
        "category": "hash", "severity": "high",
        "desc": "Cryptographic hash attacks.",
        "detection": (
            "HASH ATTACKS:\n"
            "CRACKING:\n"
            "  HASHCAT:\n"
            "    # MD5\n"
            "    hashcat -m 0 hashes.txt wordlist.txt\n"
            "    # SHA-256\n"
            "    hashcat -m 1400 hashes.txt wordlist.txt\n"
            "    # NTLM\n"
            "    hashcat -m 1000 hashes.txt wordlist.txt\n"
            "    # bcrypt\n"
            "    hashcat -m 3200 hashes.txt wordlist.txt\n"
            "    # Rule-based\n"
            "    hashcat -m 0 hashes.txt wordlist.txt -r rules/best64.rule\n"
            "    # Mask attack\n"
            "    hashcat -m 0 hashes.txt -a 3 ?u?l?l?l?d?d?d?d\n"
            "  JOHN THE RIPPER:\n"
            "    john --wordlist=wordlist.txt hashes.txt\n"
            "    john --rules hashes.txt\n"
            "WEAK ALGORITHMS:\n"
            "  - MD5: collision attacks (chosen-prefix)\n"
            "  - SHA-1: SHAttered attack\n"
            "  - CRC32: not cryptographic\n"
            "  - MD4: completely broken\n"
            "PASSWORD STORAGE:\n"
            "  BAD: MD5, SHA-1, SHA-256 (unsalted)\n"
            "  OK: SHA-256 + salt\n"
            "  GOOD: bcrypt, scrypt, Argon2\n"
            "  BEST: Argon2id\n"
            "RAINBOW TABLES:\n"
            "  - Pre-computed hash lookups\n"
            "  - Defeated by salting\n"
            "  - Online services: CrackStation, hashes.org\n"
            "TOOLS:\n"
            "  Hashcat, John the Ripper, CrackStation"
        ),
        "tools": ["hashcat", "john"],
    },
    {
        "id": "cry-003", "name": "Symmetric Cipher Attacks",
        "category": "symmetric", "severity": "high",
        "desc": "Symmetric cipher attack patterns.",
        "detection": (
            "SYMMETRIC CIPHER ATTACKS:\n"
            "ECB MODE:\n"
            "  - Block-level pattern visible\n"
            "  - ECB penguin problem\n"
            "  - Block swapping/reordering\n"
            "  - Detect: repeated ciphertext blocks\n"
            "CBC MODE:\n"
            "  - Padding oracle (Vaudenay)\n"
            "  - Byte-at-a-time decryption\n"
            "  - CBC bit-flipping\n"
            "  - IV manipulation\n"
            "  - BEAST (browser exploit)\n"
            "  - Lucky13 (timing attack)\n"
            "CTR/GCM:\n"
            "  - Nonce reuse → keystream recovery\n"
            "  - GCM nonce reuse → authentication bypass\n"
            "  - Forbidden attack (nonce reuse in GCM)\n"
            "KEY MANAGEMENT:\n"
            "  - Hardcoded keys\n"
            "  - Key in source code/config\n"
            "  - Weak key derivation\n"
            "  - Same key for encrypt and MAC\n"
            "  - Predictable IV/nonce\n"
            "IMPLEMENTATION:\n"
            "  - Timing side-channels\n"
            "  - Power analysis\n"
            "  - Cache-timing attacks\n"
            "  - Fault injection\n"
            "TOOLS:\n"
            "  PadBuster, custom scripts, CrypTool"
        ),
        "tools": ["padbuster"],
    },
    {
        "id": "cry-004", "name": "PKI/Certificate Attacks",
        "category": "pki", "severity": "high",
        "desc": "PKI and certificate attacks.",
        "detection": (
            "PKI/CERTIFICATE ATTACKS:\n"
            "CERTIFICATE ISSUES:\n"
            "  - Self-signed certificates\n"
            "  - Expired certificates\n"
            "  - Wildcard certificate misuse\n"
            "  - Weak signature (SHA-1, MD5)\n"
            "  - Weak RSA key (< 2048 bits)\n"
            "  - Missing certificate transparency\n"
            "VALIDATION BYPASS:\n"
            "  - Hostname verification skip\n"
            "  - Certificate pinning bypass\n"
            "  - Trust store manipulation\n"
            "  - Intermediate CA abuse\n"
            "  - Null byte in CN/SAN\n"
            "ATTACKS:\n"
            "  - MITM with rogue CA\n"
            "  - BGP hijacking + CA challenge\n"
            "  - Certificate transparency log monitoring\n"
            "  - Domain fronting\n"
            "  - Key compromise (Heartbleed)\n"
            "CT MONITORING:\n"
            "  # Monitor certificate issuance\n"
            "  # crt.sh\n"
            "  curl 'https://crt.sh/?q=%.target.com&output=json'\n"
            "  # certspotter\n"
            "  # Facebook CT monitor\n"
            "ACME/LE:\n"
            "  - DNS-01 challenge hijacking\n"
            "  - HTTP-01 challenge race\n"
            "  - Domain validation bypass\n"
            "TOOLS:\n"
            "  testssl.sh, crt.sh, OpenSSL"
        ),
        "tools": ["testssl.sh"],
    },
    {
        "id": "cry-005", "name": "Crypto Implementation Flaws",
        "category": "implementation", "severity": "critical",
        "desc": "Cryptographic implementation vulnerabilities.",
        "detection": (
            "CRYPTO IMPLEMENTATION FLAWS:\n"
            "RANDOM NUMBER:\n"
            "  - Predictable PRNG seed\n"
            "  - Using Math.random() for security\n"
            "  - Weak entropy sources\n"
            "  - Time-based seeds\n"
            "  - PID/thread-based seeds\n"
            "  FIX: Use /dev/urandom, os.urandom(),\n"
            "       crypto.getRandomValues()\n"
            "CUSTOM CRYPTO:\n"
            "  - Rolling your own encryption\n"
            "  - XOR-only encryption\n"
            "  - Substitution ciphers\n"
            "  - Transposition-only ciphers\n"
            "  - Home-grown MAC\n"
            "  RULE: Never roll your own crypto\n"
            "ORACLE ATTACKS:\n"
            "  - Padding oracle (AES-CBC)\n"
            "  - Bleichenbacher (RSA PKCS#1)\n"
            "  - Error-based oracles\n"
            "  - Timing-based oracles\n"
            "  - Compression oracles (CRIME/BREACH)\n"
            "AUTHENTICATION:\n"
            "  - MAC-then-encrypt (bad order)\n"
            "  - No authentication (encrypt-only)\n"
            "  - Length extension (MD5, SHA-1, SHA-256)\n"
            "  FIX: Use AEAD (AES-GCM, ChaCha20-Poly1305)\n"
            "CODE PATTERNS TO FIND:\n"
            "  # Python\n"
            "  import random  # NOT for security\n"
            "  DES.new()  # Deprecated\n"
            "  AES.new(key, AES.MODE_ECB)  # Bad mode\n"
            "  # Java\n"
            "  new Random()  # NOT SecureRandom\n"
            "  Cipher.getInstance(\"AES\")  # Defaults to ECB\n"
            "TOOLS:\n"
            "  Semgrep crypto rules, custom analysis"
        ),
        "tools": ["semgrep"],
    },
]


class CryptoAttacksKB:
    """Cryptographic attacks knowledge base.

    Provides crypto attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CryptoPattern] = {}
        self._log = logger.bind(component="crypto_kb")
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
        """Build crypto attacks prompt."""
        lines = ["## Cryptographic Attacks\n"]
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
