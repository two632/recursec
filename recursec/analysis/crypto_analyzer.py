"""Cryptographic analysis engine — TLS inspection, cipher evaluation, cert analysis.

Capabilities:
- TLS/SSL certificate analysis
- Cipher suite evaluation and scoring
- Protocol version detection
- Certificate chain validation
- Key strength assessment
- Weak crypto detection (MD5, SHA1, DES, RC4, etc.)
- Certificate transparency checking
- HSTS/HPKP detection
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CertInfo:
    """Parsed certificate information."""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int = 0
    key_algorithm: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    san_names: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    chain_depth: int = 0

    def get_issues(self) -> list[dict[str, str]]:
        """Return list of certificate issues."""
        issues = []
        if self.is_expired:
            issues.append({"severity": "critical", "issue": "Certificate is expired"})
        if self.is_self_signed:
            issues.append({"severity": "high", "issue": "Self-signed certificate"})
        if self.days_remaining > 0 and self.days_remaining < 30:
            issues.append({"severity": "medium", "issue": f"Certificate expires in {self.days_remaining} days"})
        if self.key_size < 2048 and "RSA" in self.key_algorithm:
            issues.append({"severity": "high", "issue": f"Weak RSA key: {self.key_size} bits"})
        if self.key_size < 256 and "EC" in self.key_algorithm:
            issues.append({"severity": "high", "issue": f"Weak EC key: {self.key_size} bits"})
        if "MD5" in self.signature_algorithm or "md5" in self.signature_algorithm:
            issues.append({"severity": "critical", "issue": "Certificate signed with MD5"})
        if "SHA1" in self.signature_algorithm or "sha1" in self.signature_algorithm:
            issues.append({"severity": "high", "issue": "Certificate signed with SHA-1"})
        return issues


@dataclass
class CipherInfo:
    """Information about a cipher suite."""
    name: str = ""
    protocol: str = ""
    bits: int = 0
    is_weak: bool = False
    is_deprecated: bool = False
    forward_secrecy: bool = False
    aead: bool = False
    score: str = "unknown"  # A, B, C, D, F

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "protocol": self.protocol, "bits": self.bits,
            "weak": self.is_weak, "deprecated": self.is_deprecated,
            "forward_secrecy": self.forward_secrecy, "aead": self.aead,
            "score": self.score,
        }


@dataclass
class TLSAnalysisResult:
    """Results of TLS/SSL analysis."""
    host: str = ""
    port: int = 443
    protocols_supported: list[str] = field(default_factory=list)
    certificate: CertInfo = field(default_factory=CertInfo)
    ciphers: list[CipherInfo] = field(default_factory=list)
    issues: list[dict[str, str]] = field(default_factory=list)
    overall_grade: str = "unknown"
    hsts: bool = False
    hsts_max_age: int = 0
    supports_tls13: bool = False
    supports_tls12: bool = False
    supports_tls11: bool = False
    supports_tls10: bool = False
    supports_ssl3: bool = False
    supports_ssl2: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "port": self.port,
            "protocols": self.protocols_supported,
            "certificate": {
                "subject": self.certificate.subject,
                "issuer": self.certificate.issuer,
                "not_after": self.certificate.not_after,
                "key_algorithm": self.certificate.key_algorithm,
                "key_size": self.certificate.key_size,
                "self_signed": self.certificate.is_self_signed,
                "expired": self.certificate.is_expired,
                "issues": self.certificate.get_issues(),
            },
            "ciphers": [c.to_dict() for c in self.ciphers],
            "issues": self.issues,
            "grade": self.overall_grade,
            "hsts": self.hsts,
            "tls13": self.supports_tls13,
        }


# Weak cipher patterns
WEAK_CIPHERS = {
    "NULL", "EXPORT", "DES", "RC2", "RC4", "MD5",
    "anon", "ADH", "AECDH", "3DES", "IDEA",
}

# Deprecated protocols
DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

# AEAD cipher suites
AEAD_PATTERNS = {"GCM", "CHACHA20", "CCM", "POLY1305"}


class CryptoAnalyzer:
    """Analyzes TLS configurations and cryptographic security."""

    def parse_openssl_output(self, output: str, host: str = "", port: int = 443) -> TLSAnalysisResult:
        """Parse openssl s_client output."""
        result = TLSAnalysisResult(host=host, port=port)

        # Parse certificate
        cert = CertInfo()

        # Subject
        match = re.search(r"subject\s*=\s*(.*?)$", output, re.MULTILINE)
        if match:
            cert.subject = match.group(1).strip()

        # Issuer
        match = re.search(r"issuer\s*=\s*(.*?)$", output, re.MULTILINE)
        if match:
            cert.issuer = match.group(1).strip()

        # Self-signed check
        if cert.subject and cert.issuer and cert.subject == cert.issuer:
            cert.is_self_signed = True

        # Not before / not after
        match = re.search(r"Not Before\s*:\s*(.*?)$", output, re.MULTILINE)
        if match:
            cert.not_before = match.group(1).strip()
        match = re.search(r"Not After\s*:\s*(.*?)$", output, re.MULTILINE)
        if match:
            cert.not_after = match.group(1).strip()

        # Key info
        match = re.search(r"Server public key is (\d+) bit", output)
        if match:
            cert.key_size = int(match.group(1))

        match = re.search(r"Signature Algorithm:\s*(\S+)", output)
        if match:
            cert.signature_algorithm = match.group(1)

        # SANs
        san_match = re.search(r"Subject Alternative Name.*?DNS:(.*?)(?:\n|$)", output, re.DOTALL)
        if san_match:
            cert.san_names = [s.strip() for s in san_match.group(1).split(",") if "DNS:" not in s or True]

        # Check for wildcard
        if any("*" in name for name in cert.san_names) or "*" in cert.subject:
            cert.is_wildcard = True

        result.certificate = cert

        # Parse protocol version
        match = re.search(r"Protocol\s*:\s*(.*?)$", output, re.MULTILINE)
        if match:
            proto = match.group(1).strip()
            result.protocols_supported.append(proto)

        # Parse cipher
        match = re.search(r"Cipher\s*:\s*(.*?)$", output, re.MULTILINE)
        if match:
            cipher_name = match.group(1).strip()
            cipher = self._analyze_cipher(cipher_name)
            result.ciphers.append(cipher)

        # Certificate issues
        result.issues.extend(cert.get_issues())

        # Grade the configuration
        result.overall_grade = self._grade_configuration(result)

        return result

    def parse_nmap_ssl_output(self, output: str) -> TLSAnalysisResult:
        """Parse nmap ssl-enum-ciphers output."""
        result = TLSAnalysisResult()

        # Parse protocols and ciphers
        current_protocol = ""
        for line in output.splitlines():
            line = line.strip()

            proto_match = re.match(r"(TLSv\d+\.\d+|SSLv\d+):", line)
            if proto_match:
                current_protocol = proto_match.group(1)
                result.protocols_supported.append(current_protocol)

                if current_protocol == "TLSv1.3":
                    result.supports_tls13 = True
                elif current_protocol == "TLSv1.2":
                    result.supports_tls12 = True
                elif current_protocol == "TLSv1.1":
                    result.supports_tls11 = True
                elif current_protocol == "TLSv1.0":
                    result.supports_tls10 = True
                elif current_protocol == "SSLv3":
                    result.supports_ssl3 = True
                elif current_protocol == "SSLv2":
                    result.supports_ssl2 = True

            cipher_match = re.match(r"(TLS_|SSL_)(\S+)\s+.*?(\d+)\s*bits?", line)
            if cipher_match:
                cipher = self._analyze_cipher(line, current_protocol)
                result.ciphers.append(cipher)

        # Protocol issues
        if result.supports_ssl2:
            result.issues.append({"severity": "critical", "issue": "SSLv2 supported (insecure)"})
        if result.supports_ssl3:
            result.issues.append({"severity": "critical", "issue": "SSLv3 supported (POODLE vulnerable)"})
        if result.supports_tls10:
            result.issues.append({"severity": "high", "issue": "TLSv1.0 supported (deprecated)"})
        if result.supports_tls11:
            result.issues.append({"severity": "medium", "issue": "TLSv1.1 supported (deprecated)"})
        if not result.supports_tls13:
            result.issues.append({"severity": "low", "issue": "TLSv1.3 not supported"})

        # Weak cipher issues
        weak_ciphers = [c for c in result.ciphers if c.is_weak]
        if weak_ciphers:
            result.issues.append({
                "severity": "high",
                "issue": f"{len(weak_ciphers)} weak cipher(s) supported",
            })

        result.overall_grade = self._grade_configuration(result)
        return result

    def parse_testssl_output(self, output: str) -> TLSAnalysisResult:
        """Parse testssl.sh output."""
        result = TLSAnalysisResult()

        for line in output.splitlines():
            # Extract key findings
            if "VULNERABLE" in line.upper():
                result.issues.append({"severity": "critical", "issue": line.strip()})
            elif "NOT ok" in line.lower():
                result.issues.append({"severity": "high", "issue": line.strip()})
            elif "WARN" in line.upper():
                result.issues.append({"severity": "medium", "issue": line.strip()})

            # Protocol detection
            if "SSLv2" in line and "offered" in line.lower():
                result.supports_ssl2 = True
            if "SSLv3" in line and "offered" in line.lower():
                result.supports_ssl3 = True
            if "TLS 1" in line and "offered" in line.lower():
                if "1.3" in line:
                    result.supports_tls13 = True
                elif "1.2" in line:
                    result.supports_tls12 = True

            # HSTS
            if "HSTS" in line and "offered" in line.lower():
                result.hsts = True

        result.overall_grade = self._grade_configuration(result)
        return result

    def _analyze_cipher(self, cipher_text: str, protocol: str = "") -> CipherInfo:
        """Analyze a cipher suite for security properties."""
        cipher = CipherInfo(name=cipher_text.strip(), protocol=protocol)

        upper = cipher_text.upper()

        # Check for weak ciphers
        for weak in WEAK_CIPHERS:
            if weak in upper:
                cipher.is_weak = True
                break

        # Check for forward secrecy
        if "ECDHE" in upper or "DHE" in upper or "ECDH" in upper:
            cipher.forward_secrecy = True

        # Check for AEAD
        for aead in AEAD_PATTERNS:
            if aead in upper:
                cipher.aead = True
                break

        # Extract bits
        bits_match = re.search(r"(\d+)\s*bits?", cipher_text)
        if bits_match:
            cipher.bits = int(bits_match.group(1))

        # Check deprecated protocol
        if protocol in DEPRECATED_PROTOCOLS:
            cipher.is_deprecated = True

        # Score
        if cipher.is_weak:
            cipher.score = "F"
        elif cipher.is_deprecated:
            cipher.score = "C"
        elif cipher.aead and cipher.forward_secrecy and cipher.bits >= 128:
            cipher.score = "A"
        elif cipher.forward_secrecy:
            cipher.score = "B"
        else:
            cipher.score = "C"

        return cipher

    def _grade_configuration(self, result: TLSAnalysisResult) -> str:
        """Calculate overall grade for TLS configuration."""
        # Start from A+
        grade_score = 100

        # Protocol penalties
        if result.supports_ssl2:
            grade_score -= 50
        if result.supports_ssl3:
            grade_score -= 40
        if result.supports_tls10:
            grade_score -= 15
        if result.supports_tls11:
            grade_score -= 10

        # Certificate penalties
        cert = result.certificate
        if cert.is_expired:
            grade_score -= 50
        if cert.is_self_signed:
            grade_score -= 30
        if cert.key_size > 0 and cert.key_size < 2048:
            grade_score -= 25

        # Cipher penalties
        weak_count = sum(1 for c in result.ciphers if c.is_weak)
        grade_score -= weak_count * 10

        # Bonuses
        if result.supports_tls13:
            grade_score += 5
        if result.hsts:
            grade_score += 5
        if all(c.forward_secrecy for c in result.ciphers if not c.is_weak):
            grade_score += 5

        grade_score = max(0, min(100, grade_score))

        if grade_score >= 90:
            return "A"
        elif grade_score >= 80:
            return "B"
        elif grade_score >= 65:
            return "C"
        elif grade_score >= 50:
            return "D"
        else:
            return "F"
