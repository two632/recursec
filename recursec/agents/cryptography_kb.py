"""Cryptography security knowledge base.

Deep knowledge about cryptographic security:
1. Symmetric encryption weaknesses
2. Asymmetric/PKI vulnerabilities
3. Hash function attacks
4. TLS/SSL security
5. Cryptographic implementation flaws
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CryptoPattern:
    """A cryptography security pattern."""
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
        "id": "crypto-001", "name": "Symmetric Crypto Weaknesses",
        "category": "symmetric", "severity": "high",
        "desc": "Symmetric encryption vulnerabilities.",
        "detection": (
            "SYMMETRIC ENCRYPTION WEAKNESSES:\n"
            "WEAK ALGORITHMS:\n"
            "  - DES (56-bit, brute-forceable)\n"
            "  - 3DES (meet-in-the-middle, Sweet32)\n"
            "  - RC4 (biased output, broken)\n"
            "  - Blowfish (64-bit block, Sweet32)\n"
            "MODE ISSUES:\n"
            "  ECB (Electronic Codebook):\n"
            "    - Same plaintext → same ciphertext\n"
            "    - Pattern leakage (ECB penguin)\n"
            "    - NEVER use for multi-block data\n"
            "  CBC (Cipher Block Chaining):\n"
            "    - Padding oracle (POODLE, Lucky13)\n"
            "    - Bit-flipping attacks\n"
            "    - IV reuse → known-plaintext\n"
            "  CTR (Counter):\n"
            "    - Nonce reuse → XOR plaintext recovery\n"
            "    - No authentication (need AEAD)\n"
            "  GCM:\n"
            "    - Nonce reuse → key recovery\n"
            "    - Short tags → forgery\n"
            "    - AES-GCM-SIV for nonce misuse resistance\n"
            "KEY MANAGEMENT:\n"
            "  - Hardcoded keys in source\n"
            "  - Key stored alongside ciphertext\n"
            "  - No key rotation\n"
            "  - Insufficient key derivation (no KDF)\n"
            "  - PBKDF2, Argon2, scrypt for passwords\n"
            "TOOLS:\n"
            "  CryptoLyzer, testssl.sh, openssl"
        ),
        "tools": ["testssl", "openssl"],
    },
    {
        "id": "crypto-002", "name": "Asymmetric/PKI Vulnerabilities",
        "category": "asymmetric", "severity": "critical",
        "desc": "Asymmetric cryptography and PKI vulnerabilities.",
        "detection": (
            "ASYMMETRIC/PKI VULNERABILITIES:\n"
            "RSA:\n"
            "  - Small key (< 2048 bits, factorable)\n"
            "  - Low public exponent with no padding\n"
            "  - Bleichenbacher attack (PKCS#1 v1.5)\n"
            "  - ROCA (Return of Coppersmith's Attack)\n"
            "  - Common factor attacks (shared p or q)\n"
            "  - Wiener's attack (small private exponent)\n"
            "  - Use RSA-OAEP, not PKCS#1 v1.5\n"
            "ELLIPTIC CURVE:\n"
            "  - Invalid curve attacks\n"
            "  - Weak curves (NIST P-192)\n"
            "  - Nonce reuse in ECDSA → key recovery\n"
            "  - Minerva timing attack\n"
            "  - Use Ed25519 or P-256\n"
            "PKI:\n"
            "  - Self-signed certificates in prod\n"
            "  - Expired certificates\n"
            "  - Weak signature (SHA-1, MD5)\n"
            "  - Missing revocation checks (CRL, OCSP)\n"
            "  - Certificate pinning bypass\n"
            "  - Wildcard cert abuse\n"
            "  - Subdomain takeover → cert issuance\n"
            "KEY EXCHANGE:\n"
            "  - Static DH (no forward secrecy)\n"
            "  - Weak DH groups (Logjam)\n"
            "  - Use ECDHE with X25519\n"
            "TOOLS:\n"
            "  RsaCtfTool, openssl, certipy"
        ),
        "tools": ["rsactftool", "openssl"],
    },
    {
        "id": "crypto-003", "name": "Hash Function Attacks",
        "category": "hashing", "severity": "high",
        "desc": "Hash function vulnerabilities and attacks.",
        "detection": (
            "HASH FUNCTION ATTACKS:\n"
            "BROKEN HASHES:\n"
            "  - MD5: Collision in seconds\n"
            "  - SHA-1: SHAttered (collision found 2017)\n"
            "  - CRC32: Not cryptographic\n"
            "LENGTH EXTENSION:\n"
            "  - MD5, SHA-1, SHA-256 vulnerable\n"
            "  - Append data without knowing secret\n"
            "  - H(secret||message) is vulnerable\n"
            "  - Fix: Use HMAC instead\n"
            "  - hashpump tool\n"
            "PASSWORD HASHING:\n"
            "  WEAK:\n"
            "    - Plain MD5/SHA-1 (GPU crackable)\n"
            "    - Unsalted hashes (rainbow tables)\n"
            "    - Short salt (< 16 bytes)\n"
            "  STRONG:\n"
            "    - Argon2id (memory-hard, recommended)\n"
            "    - bcrypt (CPU-hard, 72-byte limit)\n"
            "    - scrypt (memory-hard)\n"
            "    - PBKDF2 (NIST approved, high iterations)\n"
            "CRACKING:\n"
            "  hashcat -m 0 hashes.txt wordlist.txt  # MD5\n"
            "  hashcat -m 1000 hashes.txt wordlist.txt  # NTLM\n"
            "  hashcat -m 1800 hashes.txt wordlist.txt  # SHA-512crypt\n"
            "  hashcat -m 3200 hashes.txt wordlist.txt  # bcrypt\n"
            "  # Rules: hashcat -r best64.rule\n"
            "  # Masks: hashcat -a 3 ?u?l?l?l?d?d?d?d\n"
            "TOOLS:\n"
            "  hashcat, john, hashpump, hash-identifier"
        ),
        "tools": ["hashcat", "john"],
    },
    {
        "id": "crypto-004", "name": "TLS/SSL Security",
        "category": "tls", "severity": "critical",
        "desc": "TLS/SSL security assessment.",
        "detection": (
            "TLS/SSL SECURITY:\n"
            "PROTOCOL:\n"
            "  - SSLv2: Completely broken (DROWN)\n"
            "  - SSLv3: Broken (POODLE)\n"
            "  - TLS 1.0: Deprecated (BEAST)\n"
            "  - TLS 1.1: Deprecated\n"
            "  - TLS 1.2: OK with right ciphers\n"
            "  - TLS 1.3: Recommended (no weak ciphers)\n"
            "ATTACKS:\n"
            "  - BEAST (TLS 1.0 CBC)\n"
            "  - CRIME/BREACH (compression leak)\n"
            "  - POODLE (SSLv3 padding oracle)\n"
            "  - Heartbleed (OpenSSL buffer over-read)\n"
            "  - ROBOT (Bleichenbacher on RSA)\n"
            "  - SWEET32 (64-bit block ciphers)\n"
            "  - Logjam (weak DH export)\n"
            "  - FREAK (RSA export downgrade)\n"
            "  - DROWN (SSLv2 cross-protocol)\n"
            "  - Raccoon (DH key exchange timing)\n"
            "TESTING:\n"
            "  testssl.sh https://target.com\n"
            "  sslyze target.com:443\n"
            "  nmap --script ssl-enum-ciphers -p 443 target\n"
            "  # Check: certificate, ciphers, protocol, vulns\n"
            "BEST PRACTICE:\n"
            "  - TLS 1.2+ only\n"
            "  - ECDHE key exchange (forward secrecy)\n"
            "  - AES-256-GCM or ChaCha20-Poly1305\n"
            "  - HSTS with preload\n"
            "  - Certificate Transparency\n"
            "TOOLS:\n"
            "  testssl.sh, sslyze, sslscan, nmap"
        ),
        "tools": ["testssl", "sslyze", "sslscan"],
    },
    {
        "id": "crypto-005", "name": "Crypto Implementation Flaws",
        "category": "implementation", "severity": "critical",
        "desc": "Common cryptographic implementation flaws.",
        "detection": (
            "CRYPTO IMPLEMENTATION FLAWS:\n"
            "RANDOMNESS:\n"
            "  - Predictable PRNG (Math.random, rand())\n"
            "  - Insufficient entropy source\n"
            "  - Timestamp-seeded generators\n"
            "  - Use: /dev/urandom, os.urandom, CSPRNG\n"
            "TIMING ATTACKS:\n"
            "  - String comparison timing (memcmp)\n"
            "  - Use constant-time comparison\n"
            "  - hmac.compare_digest() in Python\n"
            "  - crypto.timingSafeEqual() in Node.js\n"
            "PADDING:\n"
            "  - PKCS#7 padding oracle\n"
            "  - Invalid padding error vs decryption error\n"
            "  - Use AEAD (GCM, ChaCha20-Poly1305)\n"
            "COMMON MISTAKES:\n"
            "  - Rolling your own crypto\n"
            "  - ECB mode for multi-block\n"
            "  - Static IV/nonce\n"
            "  - Key in source code\n"
            "  - Encrypt without MAC (use AEAD)\n"
            "  - Using encryption for authentication\n"
            "  - Base64 ≠ encryption\n"
            "  - Obfuscation ≠ encryption\n"
            "POST-QUANTUM:\n"
            "  - RSA/ECDSA vulnerable to quantum\n"
            "  - NIST PQC: CRYSTALS-Kyber (KEM)\n"
            "  - CRYSTALS-Dilithium (signatures)\n"
            "  - Harvest-now-decrypt-later threat\n"
            "  - Hybrid schemes (classical + PQC)\n"
            "TOOLS:\n"
            "  CryptoLyzer, cfssl, OpenSSL"
        ),
        "tools": ["openssl"],
    },
]


class CryptographyKB:
    """Cryptography security knowledge base.

    Provides crypto security patterns
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
        """Build cryptography security prompt."""
        lines = ["## Cryptography Security\n"]
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
