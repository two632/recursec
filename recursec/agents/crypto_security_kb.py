"""Cryptography security knowledge base.

Deep knowledge about cryptographic vulnerabilities:
1. TLS/SSL misconfigurations
2. Weak cryptographic implementations
3. Certificate validation flaws
4. Key management issues
5. Cryptographic protocol attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CryptoPattern:
    """A cryptographic security pattern."""
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
        "id": "crypto-001", "name": "TLS/SSL Misconfigurations",
        "category": "tls", "severity": "high",
        "desc": "TLS/SSL configuration and implementation issues.",
        "detection": (
            "TLS/SSL MISCONFIGURATIONS:\n"
            "TESTING:\n"
            "  # testssl.sh — comprehensive TLS testing\n"
            "  testssl.sh --full https://target.com\n"
            "  # sslyze\n"
            "  sslyze --regular target.com\n"
            "  # nmap SSL scripts\n"
            "  nmap --script ssl-enum-ciphers -p 443 target.com\n"
            "COMMON ISSUES:\n"
            "  PROTOCOL:\n"
            "    - SSLv2/SSLv3 enabled (POODLE: CVE-2014-3566)\n"
            "    - TLS 1.0/1.1 enabled (deprecated)\n"
            "    - Missing TLS 1.3 support\n"
            "  CIPHER SUITES:\n"
            "    - NULL ciphers (no encryption)\n"
            "    - EXPORT ciphers (weak, 40-56 bit)\n"
            "    - RC4 (biased output: CVE-2013-2566)\n"
            "    - DES/3DES (SWEET32: CVE-2016-2183)\n"
            "    - CBC mode ciphers (BEAST, Lucky13)\n"
            "    - No forward secrecy (ECDHE/DHE)\n"
            "  KEY EXCHANGE:\n"
            "    - Weak DH parameters (Logjam: < 2048 bit)\n"
            "    - Static RSA key exchange (no PFS)\n"
            "ATTACKS:\n"
            "  - BEAST (CVE-2011-3389): CBC with TLS 1.0\n"
            "  - CRIME/BREACH: TLS compression + secrets\n"
            "  - Heartbleed (CVE-2014-0160): OpenSSL memory leak\n"
            "  - ROBOT: RSA padding oracle\n"
            "  - DROWN (CVE-2016-0800): SSLv2 cross-protocol"
        ),
        "tools": ["testssl", "sslyze", "nmap"],
    },
    {
        "id": "crypto-002", "name": "Weak Crypto Implementations",
        "category": "implementation", "severity": "critical",
        "desc": "Weak cryptographic algorithm and implementation issues.",
        "detection": (
            "WEAK CRYPTO IMPLEMENTATIONS:\n"
            "HASHING:\n"
            "  - MD5: Collision attacks, rainbow tables\n"
            "  - SHA1: Collision demonstrated (SHAttered)\n"
            "  - No salt in password hashing\n"
            "  - Fast hashes for passwords (SHA256 vs bcrypt)\n"
            "  BEST PRACTICE:\n"
            "    - Passwords: bcrypt, scrypt, Argon2id\n"
            "    - Integrity: SHA-256, SHA-3\n"
            "    - HMAC for authentication\n"
            "ENCRYPTION:\n"
            "  - ECB mode (pattern preservation)\n"
            "  - CBC without HMAC (padding oracle)\n"
            "  - Reused IV/nonce (breaks AES-CTR, AES-GCM)\n"
            "  - Hardcoded encryption keys\n"
            "  - Custom/homebrew crypto\n"
            "  BEST PRACTICE:\n"
            "    - AES-256-GCM (authenticated encryption)\n"
            "    - ChaCha20-Poly1305 (alternative AEAD)\n"
            "    - Unique nonce per encryption\n"
            "RANDOMNESS:\n"
            "  - Predictable PRNG (Math.random, rand())\n"
            "  - Weak seed (time-based)\n"
            "  - Insufficient entropy\n"
            "  BEST PRACTICE:\n"
            "    - /dev/urandom, crypto.randomBytes()\n"
            "    - secrets module (Python), SecureRandom (Java)\n"
            "DETECTION:\n"
            "  semgrep --config p/secrets .\n"
            "  # Look for: md5, sha1, des, ecb, rand()"
        ),
        "tools": ["semgrep"],
    },
    {
        "id": "crypto-003", "name": "Certificate Validation",
        "category": "certificates", "severity": "high",
        "desc": "Certificate validation and trust issues.",
        "detection": (
            "CERTIFICATE VALIDATION:\n"
            "COMMON FLAWS:\n"
            "  - Missing certificate validation (verify=False)\n"
            "  - Missing hostname verification\n"
            "  - Accepting self-signed certificates\n"
            "  - Expired certificates\n"
            "  - Revoked certificates (CRL/OCSP not checked)\n"
            "  - Wildcard certificate misuse\n"
            "CERTIFICATE PINNING:\n"
            "  - Missing certificate pinning in mobile apps\n"
            "  - Pinning bypass techniques\n"
            "  - HPKP (deprecated but may still be in use)\n"
            "TESTING:\n"
            "  # Check certificate details\n"
            "  openssl s_client -connect target.com:443 -servername target.com\n"
            "  openssl s_client -connect target.com:443 | openssl x509 -noout -text\n"
            "  # Check certificate chain\n"
            "  openssl s_client -showcerts -connect target.com:443\n"
            "  # Check expiration\n"
            "  openssl s_client -connect target.com:443 | openssl x509 -noout -dates\n"
            "  # Check OCSP stapling\n"
            "  openssl s_client -status -connect target.com:443\n"
            "  # Certificate Transparency\n"
            "  curl 'https://crt.sh/?q=target.com&output=json'"
        ),
        "tools": ["openssl", "testssl"],
    },
    {
        "id": "crypto-004", "name": "Key Management Issues",
        "category": "keys", "severity": "critical",
        "desc": "Cryptographic key management vulnerabilities.",
        "detection": (
            "KEY MANAGEMENT ISSUES:\n"
            "HARDCODED KEYS:\n"
            "  - API keys in source code\n"
            "  - Encryption keys in config files\n"
            "  - Private keys committed to git\n"
            "  - Default keys/passwords\n"
            "  # Detection\n"
            "  trufflehog git file://./\n"
            "  gitleaks detect\n"
            "  semgrep --config p/secrets\n"
            "KEY STORAGE:\n"
            "  - Keys in plaintext files\n"
            "  - Keys in environment variables (visible to processes)\n"
            "  - Keys in database without encryption\n"
            "  - Keys in Docker images/layers\n"
            "  BEST PRACTICE:\n"
            "    - Hardware Security Module (HSM)\n"
            "    - Key Management Service (AWS KMS, Azure Key Vault)\n"
            "    - HashiCorp Vault\n"
            "    - Encrypted at rest, loaded at runtime\n"
            "KEY ROTATION:\n"
            "  - No rotation policy\n"
            "  - Single key for all environments\n"
            "  - No key versioning\n"
            "  - Revoked keys still accepted\n"
            "ASYMMETRIC:\n"
            "  - RSA key < 2048 bits\n"
            "  - ECDSA with weak curve (P-192)\n"
            "  - Private key without passphrase\n"
            "  - Shared private keys across services"
        ),
        "tools": ["trufflehog", "gitleaks", "semgrep"],
    },
    {
        "id": "crypto-005", "name": "JWT Security Issues",
        "category": "jwt", "severity": "critical",
        "desc": "JSON Web Token security vulnerabilities.",
        "detection": (
            "JWT SECURITY ISSUES:\n"
            "ALGORITHM CONFUSION:\n"
            "  - Change alg: RS256 → HS256\n"
            "  - Sign with public key as HMAC secret\n"
            "  - Set alg: none (no verification)\n"
            "  jwt_tool <token> -X a  # Algorithm confusion\n"
            "  jwt_tool <token> -X n  # None algorithm\n"
            "WEAK SECRETS:\n"
            "  - Brute force HMAC secret\n"
            "  jwt_tool <token> -C -d wordlist.txt\n"
            "  hashcat -m 16500 jwt.txt wordlist.txt\n"
            "  - Common secrets: secret, password, key123\n"
            "CLAIM MANIPULATION:\n"
            "  - Change sub (subject) to another user\n"
            "  - Change role/admin claim\n"
            "  - Extend exp (expiration)\n"
            "  - Remove nbf (not before)\n"
            "JWK INJECTION:\n"
            "  - Inject JWK in header\n"
            "  - Self-signed key accepted\n"
            "  jwt_tool <token> -X i  # JWK injection\n"
            "KID INJECTION:\n"
            "  - kid path traversal: ../../dev/null\n"
            "  - kid SQL injection\n"
            "  - kid command injection\n"
            "  jwt_tool <token> -X k -pk /dev/null\n"
            "TOOLS:\n"
            "  jwt_tool  # JWT testing toolkit\n"
            "  jwt.io  # Online decoder\n"
            "  jwt_cracker  # Brute force secrets"
        ),
        "tools": ["jwt_tool", "hashcat"],
    },
]


class CryptoSecurityKB:
    """Cryptography security knowledge base.

    Provides cryptographic vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CryptoPattern] = {}
        self._log = logger.bind(component="crypto_security_kb")
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
        """Build cryptography security prompt."""
        lines = ["## Cryptography Security Patterns\n"]
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
