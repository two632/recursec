"""Cryptography security knowledge base — crypto attacks and misconfigurations."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class CryptoAttackType(str, Enum):
    WEAK_CIPHER = "weak_cipher"
    KEY_MANAGEMENT = "key_management"
    PROTOCOL = "protocol"
    IMPLEMENTATION = "implementation"
    HASH = "hash"

@dataclass
class CryptoPattern:
    name: str = ""
    attack_type: CryptoAttackType = CryptoAttackType.WEAK_CIPHER
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

CRYPTO_PATTERNS: list[CryptoPattern] = [
    CryptoPattern(name="Weak Cipher Suites", attack_type=CryptoAttackType.WEAK_CIPHER, description="Detect and exploit weak cryptographic algorithms: DES, 3DES, RC4, MD5, SHA1, ECB mode, small key sizes, export-grade ciphers.", techniques=["Identify servers accepting weak TLS cipher suites", "Force cipher downgrade via ClientHello manipulation", "Exploit ECB mode: detect repeated ciphertext blocks", "Break DES/3DES via meet-in-the-middle or brute force", "RC4 bias attacks: statistical recovery of plaintext", "SWEET32: birthday attack on 64-bit block ciphers", "Padding oracle attacks on CBC mode (POODLE, Lucky13)"], detection=["Scan TLS configuration for weak ciphers", "Check for MD5/SHA1 in certificate signatures", "Identify ECB mode usage in application code", "Detect small RSA keys (<2048 bits)"], tools=["testssl.sh", "sslscan", "sslyze", "nmap"], commands=["testssl.sh --vulnerable https://target.com", "sslscan target.com", "nmap --script ssl-enum-ciphers -p 443 target.com"], severity="high"),
    CryptoPattern(name="Key Management Flaws", attack_type=CryptoAttackType.KEY_MANAGEMENT, description="Identify insecure key management: hardcoded keys, weak key generation, improper key storage, key reuse across environments.", techniques=["Search code for hardcoded cryptographic keys", "Detect weak random number generators for key generation", "Identify key reuse across dev/staging/production", "Find keys stored in plaintext (config files, env vars)", "Detect missing key rotation policies", "Check for shared symmetric keys across users"], detection=["Static analysis for hardcoded keys and secrets", "Review key generation code for CSPRNG usage", "Check key storage mechanisms (HSM, vault, file)", "Verify key rotation schedules"], tools=["gitleaks", "truffleHog", "semgrep", "detect-secrets"], commands=["gitleaks detect --source . --verbose", "trufflehog filesystem --directory . --json"], severity="critical"),
    CryptoPattern(name="TLS/SSL Protocol Attacks", attack_type=CryptoAttackType.PROTOCOL, description="Protocol-level attacks: BEAST, CRIME, BREACH, Heartbleed, DROWN, ROBOT, Raccoon, certificate pinning bypass.", techniques=["BEAST: CBC IV prediction in TLS 1.0", "CRIME/BREACH: compression side-channel (response size)", "Heartbleed: OpenSSL memory leak (CVE-2014-0160)", "DROWN: SSLv2 cross-protocol attack on RSA", "ROBOT: Bleichenbacher oracle on RSA PKCS#1 v1.5", "Raccoon: timing side-channel in DH key exchange", "Certificate pinning bypass in mobile apps (Frida/objection)", "Renegotiation attack: inject plaintext prefix"], detection=["Test for all known TLS vulnerabilities", "Check OpenSSL version for Heartbleed", "Verify SSLv2/SSLv3 is disabled", "Test for TLS renegotiation support"], tools=["testssl.sh", "sslyze", "tlsx", "heartbleed-scanner"], commands=["testssl.sh --each-cipher --vulnerable https://target", "sslyze --regular target:443"], severity="critical"),
    CryptoPattern(name="Crypto Implementation Bugs", attack_type=CryptoAttackType.IMPLEMENTATION, description="Implementation-level crypto bugs: padding oracle, timing attacks, nonce reuse, IV reuse, improper MAC verification.", techniques=["Padding oracle: decrypt CBC ciphertext byte-by-byte", "Timing attack: measure response time to leak secret bytes", "Nonce reuse in AES-GCM: recover authentication key", "IV reuse in CTR mode: XOR of plaintexts recoverable", "MAC-then-encrypt vs encrypt-then-MAC vulnerabilities", "Length extension attacks on MD5/SHA1/SHA256", "Random number generator seeding issues"], detection=["Fuzz crypto endpoints for padding oracle responses", "Measure timing differences in authentication code", "Review code for nonce/IV generation", "Check MAC verification (constant-time comparison)"], tools=["padbuster", "padding-oracle-attacker", "hashpump"], commands=["padbuster https://target/decrypt CIPHERTEXT 16 -encoding 0"], severity="critical"),
    CryptoPattern(name="Hash Function Attacks", attack_type=CryptoAttackType.HASH, description="Attack weak hash functions: collision attacks, length extension, rainbow tables, password hash cracking.", techniques=["MD5 collision: generate two inputs with same hash", "SHA1 collision: SHAttered attack (Google 2017)", "Length extension: extend hash without knowing secret", "Rainbow tables: precomputed hash→plaintext lookup", "Password cracking: dictionary, rules, masks, combinator", "Hash identification: determine algorithm from format", "Salt detection: check if passwords are salted", "Bcrypt/scrypt/argon2: verify proper work factor"], detection=["Identify hash algorithms used in application", "Check password storage (bcrypt/scrypt/argon2 vs MD5/SHA)", "Test for unsalted hashes", "Verify HMAC usage instead of plain hash"], tools=["hashcat", "john", "hashid", "haiti"], commands=["hashid 'HASH_VALUE'", "hashcat -m 0 hashes.txt wordlist.txt", "john --wordlist=rockyou.txt hashes.txt"], severity="high"),
]

def build_crypto_security_prompt(focus_type: CryptoAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Cryptography Security Knowledge\n"]
    patterns = CRYPTO_PATTERNS if not focus_type else [p for p in CRYPTO_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
