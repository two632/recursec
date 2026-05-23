"""Cryptography vulnerability knowledge base.

Deep knowledge about cryptographic weaknesses:
1. TLS/SSL misconfigurations
2. Weak cipher suites
3. Key management issues
4. Hash collision attacks
5. Cryptographic implementation flaws
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
            "category": self.category[:15],
        }


CRYPTO_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "crypto-001", "name": "TLS/SSL Misconfiguration",
        "category": "tls", "severity": "high",
        "desc": "Weak TLS configurations exposing data.",
        "detection": (
            "TLS/SSL MISCONFIGURATION:\n"
            "TESTING:\n"
            "  testssl.sh <host>:443  # Comprehensive TLS testing\n"
            "  sslyze --regular <host>:443\n"
            "  nmap --script ssl-enum-ciphers -p 443 <host>\n"
            "CRITICAL FINDINGS:\n"
            "  Protocol versions:\n"
            "    - SSLv2, SSLv3: DROWN, POODLE attacks\n"
            "    - TLS 1.0: BEAST attack\n"
            "    - TLS 1.1: Deprecated, must be disabled\n"
            "    - Only TLS 1.2+ should be enabled\n"
            "  Weak ciphers:\n"
            "    - RC4: Biased output (CVE-2013-2566)\n"
            "    - DES/3DES: Sweet32 attack (CVE-2016-2183)\n"
            "    - NULL ciphers: No encryption\n"
            "    - Export ciphers: Downgrade to weak keys (FREAK, Logjam)\n"
            "  Certificate issues:\n"
            "    - Self-signed certificates\n"
            "    - Expired certificates\n"
            "    - Weak key size (RSA < 2048, ECC < 256)\n"
            "    - SHA-1 signature\n"
            "    - Hostname mismatch\n"
            "  Known attacks:\n"
            "    - Heartbleed (CVE-2014-0160): Memory leak in OpenSSL\n"
            "    - ROBOT: Return Of Bleichenbacher\n"
            "    - CRIME/BREACH: Compression side channels\n"
            "    - Renegotiation attack (CVE-2009-3555)"
        ),
        "tools": ["testssl", "sslyze", "nmap"],
    },
    {
        "id": "crypto-002", "name": "JWT Security Issues",
        "category": "jwt", "severity": "critical",
        "desc": "JSON Web Token implementation flaws.",
        "detection": (
            "JWT SECURITY:\n"
            "COMMON ATTACKS:\n"
            "  Algorithm Confusion:\n"
            "    - Change alg from RS256 to HS256\n"
            "    - Sign with public key as HMAC secret\n"
            "    - jwt_tool <token> -X a  # Algorithm confusion\n"
            "  None Algorithm:\n"
            "    - Set alg to 'none' or 'None' or 'NONE'\n"
            "    - Remove signature\n"
            "    - jwt_tool <token> -X n  # None algorithm\n"
            "  Weak Secret:\n"
            "    - Brute force HMAC secret\n"
            "    - hashcat -m 16500 <token> <wordlist>\n"
            "    - jwt_tool <token> -C -d <wordlist>\n"
            "  Kid Injection:\n"
            "    - kid parameter: SQL injection, path traversal\n"
            "    - kid: '../../dev/null' → empty key\n"
            "    - kid: 'key' UNION SELECT 'attacker_key'\n"
            "  JWK/JKU Injection:\n"
            "    - Set jku to attacker server\n"
            "    - Embed JWK in header pointing to attacker key\n"
            "TESTING:\n"
            "  1. Decode token: jwt.io or jwt_tool\n"
            "  2. Check algorithm (RS256 vs HS256)\n"
            "  3. Test none algorithm\n"
            "  4. Test key brute force (HS256)\n"
            "  5. Test claim manipulation (exp, iat, iss, aud)\n"
            "  6. Test kid parameter injection"
        ),
        "tools": ["jwt_tool", "hashcat", "burp"],
    },
    {
        "id": "crypto-003", "name": "Password Storage Weaknesses",
        "category": "hashing", "severity": "critical",
        "desc": "Insecure password hashing and storage.",
        "detection": (
            "PASSWORD STORAGE:\n"
            "INSECURE METHODS:\n"
            "  - Plaintext storage: Direct database access reveals passwords\n"
            "  - MD5: Rainbow tables widely available\n"
            "    hashcat -m 0 <hashes> <wordlist>\n"
            "  - SHA-1/SHA-256 (unsalted): Precomputed tables\n"
            "    hashcat -m 100/1400 <hashes> <wordlist>\n"
            "  - Single iteration: Fast to brute force\n"
            "SECURE METHODS (what should be used):\n"
            "  - bcrypt: $2b$12$ prefix, intentionally slow\n"
            "  - scrypt: Memory-hard, resists GPU attacks\n"
            "  - Argon2id: Winner of PHC, recommended\n"
            "  - PBKDF2: With sufficient iterations (100K+)\n"
            "DETECTION:\n"
            "  - Check database for hash format:\n"
            "    $2b$ = bcrypt, $argon2id$ = argon2\n"
            "    $6$ = SHA-512 crypt, $5$ = SHA-256 crypt\n"
            "    32 hex chars = MD5, 40 hex chars = SHA-1\n"
            "  - Check for password reuse across services\n"
            "  - Check for default passwords in code/config\n"
            "CRACKING:\n"
            "  hashcat -m <mode> <hashes> <wordlist>\n"
            "  john --wordlist=<wordlist> <hashes>\n"
            "  Rules: hashcat -r best64.rule, john --rules=jumbo"
        ),
        "tools": ["hashcat", "john", "hash-identifier"],
    },
    {
        "id": "crypto-004", "name": "Random Number Generation Flaws",
        "category": "rng", "severity": "high",
        "desc": "Weak or predictable random number generation.",
        "detection": (
            "RANDOM NUMBER GENERATION:\n"
            "COMMON WEAKNESSES:\n"
            "  - Math.random() (JavaScript): Not cryptographically secure\n"
            "  - random.random() (Python): Mersenne Twister, predictable\n"
            "  - java.util.Random: Linear congruential, predictable\n"
            "  - time()-based seeds: Predictable if timing is known\n"
            "IMPACT:\n"
            "  - Session tokens: Predictable → session hijacking\n"
            "  - CSRF tokens: Predictable → CSRF bypass\n"
            "  - Password reset tokens: Predictable → account takeover\n"
            "  - Encryption keys: Weak → decryption\n"
            "  - Nonces: Reuse → cryptographic breaks\n"
            "TESTING:\n"
            "  1. Collect multiple tokens/random values\n"
            "  2. Statistical analysis: Look for patterns\n"
            "  3. Entropy estimation: min-entropy tests\n"
            "  4. Sequential prediction: Try to predict next value\n"
            "  5. Time correlation: Check if values correlate with time\n"
            "SECURE ALTERNATIVES:\n"
            "  - crypto.randomBytes() (Node.js)\n"
            "  - secrets.token_hex() (Python)\n"
            "  - java.security.SecureRandom (Java)\n"
            "  - /dev/urandom (Linux)"
        ),
        "tools": ["burp-sequencer", "ent"],
    },
    {
        "id": "crypto-005", "name": "Encryption Mode and Padding Attacks",
        "category": "encryption", "severity": "high",
        "desc": "Attacks on encryption modes and padding.",
        "detection": (
            "ENCRYPTION MODE ATTACKS:\n"
            "ECB MODE:\n"
            "  - Electronic Codebook: Same plaintext → same ciphertext\n"
            "  - Detection: Encrypt identical blocks, check for repetition\n"
            "  - Block manipulation: Reorder/repeat encrypted blocks\n"
            "  - Impact: Pattern leakage, block substitution\n"
            "CBC PADDING ORACLE:\n"
            "  - Exploit: Modify ciphertext, check for padding errors\n"
            "  - Error differentiation: Different errors for bad padding vs bad data\n"
            "  - Tools: PadBuster, padding-oracle-attacker\n"
            "  - padbuster <url> <encrypted_sample> <block_size>\n"
            "  - Full plaintext recovery without key\n"
            "CTR/GCM NONCE REUSE:\n"
            "  - Same nonce + same key → XOR of plaintexts leaked\n"
            "  - In GCM: Authentication key recovery\n"
            "  - Detection: Collect multiple ciphertexts, check nonce reuse\n"
            "TESTING:\n"
            "  1. Identify encryption in cookies, tokens, parameters\n"
            "  2. Determine block size (common: 16 bytes = AES)\n"
            "  3. Check for ECB by encrypting repeated data\n"
            "  4. Test padding oracle by modifying last block\n"
            "  5. Check for nonce reuse in encrypted communications"
        ),
        "tools": ["padbuster", "burp"],
    },
]


class CryptographyKB:
    """Cryptography vulnerability knowledge base.

    Provides crypto attack patterns injected
    into agent prompts.
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
