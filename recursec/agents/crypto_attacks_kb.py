"""Cryptography attacks knowledge base.

Deep knowledge about cryptographic attacks:
1. Symmetric cipher attacks
2. Asymmetric/PKI attacks
3. Hash function attacks
4. Protocol-level attacks
5. Implementation vulnerabilities
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CryptoPattern:
    """A cryptography attack pattern."""
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
        "id": "cry-001", "name": "Symmetric Cipher Attacks",
        "category": "symmetric", "severity": "high",
        "desc": "Symmetric cipher attack techniques.",
        "detection": (
            "SYMMETRIC CIPHER ATTACKS:\n"
            "ECB MODE:\n"
            "  - Block pattern leakage\n"
            "  - Cut-and-paste attacks\n"
            "  - Deterministic encryption\n"
            "  # Detect: identical blocks in ciphertext\n"
            "CBC MODE:\n"
            "  - Padding oracle attacks\n"
            "    # Vaudenay attack\n"
            "    # POODLE (SSLv3)\n"
            "    # Lucky 13\n"
            "  - Bit-flipping attacks\n"
            "    # Modify ciphertext → predictable plaintext\n"
            "  - IV reuse vulnerabilities\n"
            "  - CBC-R (CBC decryption as encryption)\n"
            "CTR MODE:\n"
            "  - Nonce reuse → keystream reuse\n"
            "  - Two-time pad attack\n"
            "  - Malleable ciphertext\n"
            "GCM MODE:\n"
            "  - Nonce reuse → key recovery\n"
            "  - Forbidden attack\n"
            "  - Tag truncation\n"
            "KEY MANAGEMENT:\n"
            "  - Hardcoded keys in source\n"
            "  - Weak key derivation (no PBKDF2/Argon2)\n"
            "  - Key in memory (cold boot)\n"
            "  - Key reuse across contexts\n"
            "TOOLS:\n"
            "  PadBuster, python-paddingoracle, CyberChef"
        ),
        "tools": [],
    },
    {
        "id": "cry-002", "name": "Asymmetric/PKI Attacks",
        "category": "asymmetric", "severity": "critical",
        "desc": "Asymmetric cryptography and PKI attacks.",
        "detection": (
            "ASYMMETRIC / PKI ATTACKS:\n"
            "RSA:\n"
            "  - Small public exponent (e=3)\n"
            "    # Coppersmith's attack\n"
            "    # Cube root attack\n"
            "  - Factorization\n"
            "    # Fermat's method (close primes)\n"
            "    # Pollard's rho\n"
            "    # GNFS (large keys)\n"
            "  - Common modulus attack\n"
            "  - Wiener's attack (small d)\n"
            "  - Bleichenbacher (PKCS#1 v1.5)\n"
            "  - ROCA (Infineon key generation)\n"
            "  - Padding oracle (OAEP implementation)\n"
            "ELLIPTIC CURVE:\n"
            "  - Invalid curve attack\n"
            "  - Twist attack\n"
            "  - Small subgroup attack\n"
            "  - Nonce reuse in ECDSA (Sony PS3)\n"
            "  - Lattice attacks on biased nonces\n"
            "PKI:\n"
            "  - Certificate validation bypass\n"
            "  - Null byte in CN/SAN\n"
            "  - Weak CA signing\n"
            "  - CT log monitoring gaps\n"
            "  - OCSP stapling issues\n"
            "  - Certificate pinning bypass\n"
            "TOOLS:\n"
            "  RsaCtfTool, SageMath, openssl, certtool"
        ),
        "tools": [],
    },
    {
        "id": "cry-003", "name": "Hash Function Attacks",
        "category": "hash", "severity": "high",
        "desc": "Hash function attack techniques.",
        "detection": (
            "HASH FUNCTION ATTACKS:\n"
            "WEAK HASHES:\n"
            "  - MD5 (collision in seconds)\n"
            "  - SHA-1 (SHAttered, practical collision)\n"
            "  - CRC32 (trivial collision)\n"
            "ATTACKS:\n"
            "  - Length extension attack\n"
            "    # MD5, SHA-1, SHA-256 (Merkle-Damgard)\n"
            "    # NOT: SHA-3, HMAC, truncated hashes\n"
            "    # Tool: hash_extender, hashpump\n"
            "  - Birthday attack\n"
            "    # 2^(n/2) operations for n-bit hash\n"
            "  - Preimage attack (find input for hash)\n"
            "  - Second preimage (find collision)\n"
            "PASSWORD HASHING:\n"
            "  - Unsalted hashes (rainbow table)\n"
            "  - Fast hashes (MD5, SHA-1 for passwords)\n"
            "  - Short salt\n"
            "  - Salt reuse\n"
            "  PROPER:\n"
            "    - bcrypt (Blowfish-based)\n"
            "    - scrypt (memory-hard)\n"
            "    - Argon2 (OWASP recommended)\n"
            "CRACKING:\n"
            "  # hashcat -m 0 hashes.txt wordlist.txt (MD5)\n"
            "  # hashcat -m 1000 hashes.txt wordlist.txt (NTLM)\n"
            "  # john --wordlist=rockyou.txt hashes.txt\n"
            "  - Rule-based mutations\n"
            "  - Mask attacks\n"
            "  - Combinator attacks\n"
            "TOOLS:\n"
            "  hashcat, john, hash_extender, hashpump"
        ),
        "tools": ["hashcat"],
    },
    {
        "id": "cry-004", "name": "Protocol-Level Attacks",
        "category": "protocol", "severity": "critical",
        "desc": "Cryptographic protocol attacks.",
        "detection": (
            "PROTOCOL-LEVEL ATTACKS:\n"
            "TLS:\n"
            "  - Downgrade attacks\n"
            "    # POODLE (force SSLv3)\n"
            "    # DROWN (SSLv2 on RSA)\n"
            "    # FREAK (export ciphers)\n"
            "    # Logjam (512-bit DH)\n"
            "  - BEAST (CBC in TLS 1.0)\n"
            "  - CRIME/BREACH (compression oracle)\n"
            "  - Heartbleed (OpenSSL buffer overread)\n"
            "  - ROBOT (Bleichenbacher on TLS)\n"
            "  - Raccoon (DH key exchange)\n"
            "  # testssl.sh TARGET\n"
            "  # sslyze --regular TARGET\n"
            "JWT:\n"
            "  - Algorithm confusion (RS256→HS256)\n"
            "  - None algorithm bypass\n"
            "  - Weak signing key\n"
            "  - JKU/JWK header injection\n"
            "  - Kid header path traversal\n"
            "  # jwt_tool.py -t URL -M at\n"
            "SSH:\n"
            "  - Terrapin attack (prefix truncation)\n"
            "  - Weak key exchange\n"
            "  - Host key verification\n"
            "WPA:\n"
            "  - KRACK (key reinstallation)\n"
            "  - Dragonblood (WPA3-SAE)\n"
            "TOOLS:\n"
            "  testssl.sh, sslyze, jwt_tool, ssh-audit"
        ),
        "tools": [],
    },
    {
        "id": "cry-005", "name": "Implementation Vulnerabilities",
        "category": "implementation", "severity": "high",
        "desc": "Cryptographic implementation flaws.",
        "detection": (
            "IMPLEMENTATION VULNERABILITIES:\n"
            "SIDE CHANNELS:\n"
            "  - Timing attacks\n"
            "    # String comparison timing\n"
            "    # RSA decryption timing\n"
            "    # Cache timing (Flush+Reload)\n"
            "  - Power analysis\n"
            "    # Simple (SPA)\n"
            "    # Differential (DPA)\n"
            "  - Electromagnetic emanation\n"
            "  - Acoustic (RSA key extraction)\n"
            "  - Spectre/Meltdown (CPU)\n"
            "RANDOM NUMBER:\n"
            "  - Predictable PRNG\n"
            "    # Math.random() (not crypto)\n"
            "    # time-based seeds\n"
            "    # /dev/urandom vs /dev/random\n"
            "  - Insufficient entropy\n"
            "  - PRNG state recovery\n"
            "  - Dual_EC_DRBG (NSA backdoor)\n"
            "COMMON MISTAKES:\n"
            "  - Rolling your own crypto\n"
            "  - ECB mode for structured data\n"
            "  - Nonce/IV reuse\n"
            "  - MAC-then-encrypt (vs encrypt-then-MAC)\n"
            "  - Comparing MACs without constant-time\n"
            "  - Using encryption for authentication\n"
            "  - Ignoring return values\n"
            "  - Key in source code\n"
            "  - Base64 as 'encryption'\n"
            "  - XOR with short key\n"
            "TOOLS:\n"
            "  CyberChef, SageMath, dieharder, ent"
        ),
        "tools": [],
    },
]


class CryptoAttacksKB:
    """Cryptography attacks knowledge base.

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
        lines = ["## Cryptography Attacks\n"]
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
