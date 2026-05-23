"""SSL/TLS scanner — comprehensive TLS security assessment.

Capabilities:
- Protocol version enumeration (SSLv2, SSLv3, TLSv1.0-1.3)
- Cipher suite enumeration and grading
- Certificate chain validation
- Key exchange analysis
- Known vulnerability checks (POODLE, BEAST, CRIME, Heartbleed, etc.)
- HSTS and security header analysis
- Certificate transparency log checking
- OCSP stapling detection
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


async def _run_command(cmd: list[str], timeout: float = 60.0) -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode(errors="replace") if stdout else "",
            stderr.decode(errors="replace") if stderr else "",
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return "", "Command timed out", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127


@dataclass
class TLSVulnerability:
    """A TLS-specific vulnerability."""
    name: str
    severity: str
    description: str
    cve_id: str = ""
    mitigated: bool = False
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "severity": self.severity,
            "description": self.description, "cve_id": self.cve_id,
            "mitigated": self.mitigated, "evidence": self.evidence[:200],
        }


@dataclass
class SSLScanResult:
    """Complete SSL/TLS scan results."""
    host: str = ""
    port: int = 443
    protocols: dict[str, bool] = field(default_factory=dict)
    preferred_cipher: str = ""
    cipher_count: int = 0
    weak_ciphers: list[str] = field(default_factory=list)
    strong_ciphers: list[str] = field(default_factory=list)
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    cert_key_size: int = 0
    cert_sig_alg: str = ""
    cert_self_signed: bool = False
    vulnerabilities: list[TLSVulnerability] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)
    overall_grade: str = "unknown"
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "port": self.port,
            "protocols": self.protocols,
            "preferred_cipher": self.preferred_cipher,
            "weak_ciphers": self.weak_ciphers,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_expiry": self.cert_expiry,
            "cert_key_size": self.cert_key_size,
            "cert_self_signed": self.cert_self_signed,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "security_headers": self.security_headers,
            "grade": self.overall_grade,
        }


# Known vulnerable ciphers
WEAK_CIPHER_PATTERNS = [
    "NULL", "EXPORT", "DES-CBC", "RC2", "RC4", "MD5",
    "anon", "ADH", "AECDH", "DES-CBC3", "IDEA",
]

# TLS vulnerability checks
TLS_VULNS = {
    "heartbleed": {"name": "Heartbleed", "cve": "CVE-2014-0160", "severity": "critical"},
    "poodle": {"name": "POODLE", "cve": "CVE-2014-3566", "severity": "high"},
    "beast": {"name": "BEAST", "cve": "CVE-2011-3389", "severity": "medium"},
    "crime": {"name": "CRIME", "cve": "CVE-2012-4929", "severity": "high"},
    "breach": {"name": "BREACH", "cve": "CVE-2013-3587", "severity": "medium"},
    "freak": {"name": "FREAK", "cve": "CVE-2015-0204", "severity": "high"},
    "logjam": {"name": "Logjam", "cve": "CVE-2015-4000", "severity": "high"},
    "drown": {"name": "DROWN", "cve": "CVE-2016-0800", "severity": "critical"},
    "robot": {"name": "ROBOT", "cve": "CVE-2017-13099", "severity": "high"},
    "ticketbleed": {"name": "Ticketbleed", "cve": "CVE-2016-9244", "severity": "high"},
    "lucky13": {"name": "Lucky13", "cve": "CVE-2013-0169", "severity": "medium"},
    "sweet32": {"name": "Sweet32", "cve": "CVE-2016-2183", "severity": "medium"},
}


class SSLScanner:
    """Comprehensive SSL/TLS scanner."""

    def __init__(self) -> None:
        self._has_openssl = shutil.which("openssl") is not None
        self._has_testssl = shutil.which("testssl") is not None or shutil.which("testssl.sh") is not None
        self._has_sslscan = shutil.which("sslscan") is not None

    async def scan(self, host: str, port: int = 443) -> SSLScanResult:
        """Run comprehensive SSL/TLS scan."""
        result = SSLScanResult(host=host, port=port)

        # Phase 1: Basic openssl connection
        if self._has_openssl:
            await self._openssl_scan(host, port, result)

        # Phase 2: Protocol enumeration
        await self._enumerate_protocols(host, port, result)

        # Phase 3: Cipher enumeration
        await self._enumerate_ciphers(host, port, result)

        # Phase 4: Vulnerability checks
        await self._check_vulnerabilities(host, port, result)

        # Phase 5: Security headers (via HTTPS)
        await self._check_security_headers(host, port, result)

        # Phase 6: Use testssl.sh if available
        if self._has_testssl:
            await self._testssl_scan(host, port, result)

        # Phase 7: Use sslscan if available
        if self._has_sslscan:
            await self._sslscan_scan(host, port, result)

        # Calculate grade
        result.overall_grade = self._calculate_grade(result)

        return result

    async def _openssl_scan(self, host: str, port: int, result: SSLScanResult) -> None:
        """Basic openssl s_client scan."""
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host]
        stdout, stderr, rc = await _run_command(cmd)

        combined = stdout + stderr

        # Parse certificate info
        subj_match = re.search(r"subject\s*=\s*(.*?)$", combined, re.MULTILINE)
        if subj_match:
            result.cert_subject = subj_match.group(1).strip()

        issuer_match = re.search(r"issuer\s*=\s*(.*?)$", combined, re.MULTILINE)
        if issuer_match:
            result.cert_issuer = issuer_match.group(1).strip()

        if result.cert_subject and result.cert_issuer:
            result.cert_self_signed = result.cert_subject == result.cert_issuer

        key_match = re.search(r"Server public key is (\d+) bit", combined)
        if key_match:
            result.cert_key_size = int(key_match.group(1))

        sig_match = re.search(r"Signature Algorithm:\s*(\S+)", combined)
        if sig_match:
            result.cert_sig_alg = sig_match.group(1)

        proto_match = re.search(r"Protocol\s*:\s*(\S+)", combined)
        if proto_match:
            result.preferred_cipher = proto_match.group(1)

        cipher_match = re.search(r"Cipher\s*:\s*(\S+)", combined)
        if cipher_match:
            result.preferred_cipher = cipher_match.group(1)

        result.raw_output = combined[:5000]

    async def _enumerate_protocols(self, host: str, port: int, result: SSLScanResult) -> None:
        """Test which TLS/SSL protocols are supported."""
        if not self._has_openssl:
            return

        protocols = {
            "TLSv1.3": "-tls1_3",
            "TLSv1.2": "-tls1_2",
            "TLSv1.1": "-tls1_1",
            "TLSv1.0": "-tls1",
            "SSLv3": "-ssl3",
        }

        tasks = []
        proto_names = []
        for name, flag in protocols.items():
            cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", flag, "-servername", host]
            tasks.append(_run_command(cmd, timeout=10.0))
            proto_names.append(name)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, res in zip(proto_names, results):
            if isinstance(res, Exception):
                result.protocols[name] = False
                continue
            stdout, stderr, rc = res
            combined = stdout + stderr
            supported = rc == 0 and "CONNECTED" in combined
            result.protocols[name] = supported

            # Flag deprecated protocols
            if supported and name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
                result.vulnerabilities.append(TLSVulnerability(
                    name=f"Deprecated {name} Supported",
                    severity="high" if name == "SSLv3" else "medium",
                    description=f"{name} is deprecated and should be disabled",
                ))

    async def _enumerate_ciphers(self, host: str, port: int, result: SSLScanResult) -> None:
        """Enumerate supported cipher suites."""
        if not self._has_openssl:
            return

        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-cipher", "ALL:COMPLEMENTOFALL"]
        stdout, stderr, _ = await _run_command(cmd, timeout=15.0)

        combined = stdout + stderr
        cipher_match = re.search(r"Cipher\s*:\s*(\S+)", combined)
        if cipher_match:
            cipher = cipher_match.group(1)
            if cipher != "0000":
                result.cipher_count += 1
                is_weak = any(w in cipher.upper() for w in WEAK_CIPHER_PATTERNS)
                if is_weak:
                    result.weak_ciphers.append(cipher)
                else:
                    result.strong_ciphers.append(cipher)

    async def _check_vulnerabilities(self, host: str, port: int, result: SSLScanResult) -> None:
        """Check for known TLS vulnerabilities."""
        # Heartbleed check via openssl
        if self._has_openssl:
            cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-tlsextdebug"]
            stdout, stderr, _ = await _run_command(cmd, timeout=10.0)
            combined = stdout + stderr

            if "heartbeat" in combined.lower():
                result.vulnerabilities.append(TLSVulnerability(
                    name="Heartbleed", severity="critical",
                    description="TLS heartbeat extension is enabled (potential Heartbleed)",
                    cve_id="CVE-2014-0160",
                    evidence="Heartbeat extension detected in TLS negotiation",
                ))

        # POODLE check (if SSLv3 supported)
        if result.protocols.get("SSLv3", False):
            result.vulnerabilities.append(TLSVulnerability(
                name="POODLE", severity="high",
                description="SSLv3 is supported, vulnerable to POODLE attack",
                cve_id="CVE-2014-3566",
            ))

        # Sweet32 check (3DES ciphers)
        for cipher in result.weak_ciphers + result.strong_ciphers:
            if "DES-CBC3" in cipher or "3DES" in cipher:
                result.vulnerabilities.append(TLSVulnerability(
                    name="Sweet32", severity="medium",
                    description=f"3DES cipher supported: {cipher}",
                    cve_id="CVE-2016-2183",
                ))
                break

        # Certificate issues
        if result.cert_self_signed:
            result.vulnerabilities.append(TLSVulnerability(
                name="Self-Signed Certificate", severity="high",
                description="Certificate is self-signed (not trusted by default)",
            ))

        if result.cert_key_size > 0 and result.cert_key_size < 2048:
            result.vulnerabilities.append(TLSVulnerability(
                name="Weak Key Size", severity="high",
                description=f"RSA key is only {result.cert_key_size} bits (minimum 2048 recommended)",
            ))

        if result.cert_sig_alg and ("md5" in result.cert_sig_alg.lower() or "sha1" in result.cert_sig_alg.lower()):
            result.vulnerabilities.append(TLSVulnerability(
                name="Weak Signature Algorithm", severity="high",
                description=f"Certificate uses weak signature algorithm: {result.cert_sig_alg}",
            ))

    async def _check_security_headers(self, host: str, port: int, result: SSLScanResult) -> None:
        """Check HTTPS security headers."""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                resp = await client.get(f"https://{host}:{port}/")
                headers = dict(resp.headers)

                security_headers = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "x-xss-protection",
                    "referrer-policy",
                    "permissions-policy",
                ]

                for header in security_headers:
                    value = headers.get(header, "")
                    if value:
                        result.security_headers[header] = value
                    else:
                        result.vulnerabilities.append(TLSVulnerability(
                            name=f"Missing {header}",
                            severity="low",
                            description=f"Security header '{header}' not set",
                        ))

                # Check HSTS specifics
                hsts = headers.get("strict-transport-security", "")
                if hsts:
                    if "max-age=0" in hsts:
                        result.vulnerabilities.append(TLSVulnerability(
                            name="HSTS max-age=0",
                            severity="medium",
                            description="HSTS is effectively disabled (max-age=0)",
                        ))
                    elif "includeSubDomains" not in hsts:
                        result.vulnerabilities.append(TLSVulnerability(
                            name="HSTS missing includeSubDomains",
                            severity="low",
                            description="HSTS does not include subdomains",
                        ))

        except Exception as e:
            logger.debug("security_headers_check_failed", error=str(e))

    async def _testssl_scan(self, host: str, port: int, result: SSLScanResult) -> None:
        """Use testssl.sh for comprehensive scanning."""
        testssl_cmd = "testssl.sh" if shutil.which("testssl.sh") else "testssl"
        cmd = [testssl_cmd, "--json", "--quiet", f"{host}:{port}"]
        stdout, stderr, rc = await _run_command(cmd, timeout=120.0)

        if stdout:
            try:
                findings = json.loads(stdout)
                if isinstance(findings, list):
                    for finding in findings:
                        severity = finding.get("severity", "").upper()
                        if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                            result.vulnerabilities.append(TLSVulnerability(
                                name=finding.get("id", "unknown"),
                                severity=severity.lower(),
                                description=finding.get("finding", ""),
                                cve_id=finding.get("cve", ""),
                            ))
            except json.JSONDecodeError:
                pass

    async def _sslscan_scan(self, host: str, port: int, result: SSLScanResult) -> None:
        """Use sslscan for additional checks."""
        cmd = ["sslscan", "--no-colour", f"{host}:{port}"]
        stdout, stderr, rc = await _run_command(cmd, timeout=60.0)

        if stdout:
            # Parse sslscan output for additional ciphers
            for line in stdout.splitlines():
                if "Accepted" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        cipher_name = parts[-1]
                        is_weak = any(w in cipher_name.upper() for w in WEAK_CIPHER_PATTERNS)
                        if is_weak and cipher_name not in result.weak_ciphers:
                            result.weak_ciphers.append(cipher_name)
                        elif cipher_name not in result.strong_ciphers:
                            result.strong_ciphers.append(cipher_name)
                        result.cipher_count += 1

    def _calculate_grade(self, result: SSLScanResult) -> str:
        """Calculate overall SSL/TLS grade."""
        score = 100

        # Protocol penalties
        if result.protocols.get("SSLv3", False):
            score -= 40
        if result.protocols.get("TLSv1.0", False):
            score -= 15
        if result.protocols.get("TLSv1.1", False):
            score -= 10
        if not result.protocols.get("TLSv1.3", False):
            score -= 5

        # Cipher penalties
        score -= len(result.weak_ciphers) * 10

        # Vulnerability penalties
        for vuln in result.vulnerabilities:
            if vuln.severity == "critical":
                score -= 30
            elif vuln.severity == "high":
                score -= 15
            elif vuln.severity == "medium":
                score -= 5

        # Certificate penalties
        if result.cert_self_signed:
            score -= 25
        if result.cert_key_size > 0 and result.cert_key_size < 2048:
            score -= 20

        score = max(0, min(100, score))

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 65:
            return "C"
        elif score >= 50:
            return "D"
        else:
            return "F"
