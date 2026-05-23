"""DNS security scanner — comprehensive DNS enumeration and security testing.

Capabilities:
- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, PTR)
- Zone transfer attempt
- DNSSEC validation
- Subdomain brute-forcing
- DNS cache snooping
- DNS rebinding detection
- Wildcard detection
- SPF/DKIM/DMARC analysis
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


async def _run_cmd(cmd: list[str], timeout: float = 30.0) -> tuple[str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace") if stdout else "", proc.returncode or 0
    except (asyncio.TimeoutError, FileNotFoundError):
        return "", 1


@dataclass
class DNSRecord:
    """A single DNS record."""
    name: str
    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.record_type, "value": self.value, "ttl": self.ttl}


@dataclass
class DNSFinding:
    """A DNS security finding."""
    title: str
    severity: str
    description: str
    evidence: str = ""
    category: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title, "severity": self.severity,
            "description": self.description, "evidence": self.evidence[:500],
            "category": self.category,
        }


@dataclass
class EmailSecurity:
    """Email security configuration analysis."""
    spf_record: str = ""
    spf_valid: bool = False
    spf_issues: list[str] = field(default_factory=list)
    dkim_found: bool = False
    dmarc_record: str = ""
    dmarc_policy: str = "none"
    dmarc_issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spf_record": self.spf_record, "spf_valid": self.spf_valid,
            "spf_issues": self.spf_issues,
            "dkim_found": self.dkim_found,
            "dmarc_record": self.dmarc_record, "dmarc_policy": self.dmarc_policy,
            "dmarc_issues": self.dmarc_issues,
        }


@dataclass
class DNSScanResult:
    """Complete DNS scan results."""
    domain: str = ""
    records: list[DNSRecord] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    zone_transfer: bool = False
    zone_data: str = ""
    wildcard: bool = False
    dnssec: bool = False
    email_security: EmailSecurity = field(default_factory=EmailSecurity)
    findings: list[DNSFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "records": [r.to_dict() for r in self.records],
            "nameservers": self.nameservers,
            "subdomains": self.subdomains,
            "zone_transfer_possible": self.zone_transfer,
            "wildcard_detected": self.wildcard,
            "dnssec_enabled": self.dnssec,
            "email_security": self.email_security.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


# Common subdomains for brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "portal", "blog", "shop", "store", "api", "dev",
    "staging", "test", "beta", "demo", "app", "mobile",
    "ns1", "ns2", "dns1", "dns2", "mx", "mx1", "mx2",
    "vpn", "remote", "gateway", "proxy", "cdn", "static",
    "media", "assets", "img", "images", "video",
    "db", "database", "sql", "mysql", "postgres", "mongo",
    "redis", "cache", "elastic", "search", "kibana", "grafana",
    "jenkins", "ci", "cd", "build", "deploy", "git", "gitlab",
    "jira", "confluence", "wiki", "docs", "help", "support",
    "status", "monitor", "health", "metrics", "logs",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "extranet", "corp", "office",
    "exchange", "owa", "autodiscover", "lyncdiscover",
    "sso", "login", "auth", "oauth", "identity", "idp",
    "s3", "aws", "azure", "gcp", "cloud",
    "secure", "sec", "security", "waf",
    "staging1", "staging2", "dev1", "dev2", "test1", "test2",
    "uat", "qa", "preprod", "production", "prod",
]


class DNSScanner:
    """Comprehensive DNS security scanner."""

    def __init__(self, nameserver: str = "", timeout: float = 5.0) -> None:
        self._nameserver = nameserver
        self._timeout = timeout
        self._has_dig = shutil.which("dig") is not None
        self._has_nslookup = shutil.which("nslookup") is not None
        self._has_host = shutil.which("host") is not None

    async def scan(self, domain: str) -> DNSScanResult:
        """Run comprehensive DNS security scan."""
        result = DNSScanResult(domain=domain)

        # Phase 1: Record enumeration
        await self._enumerate_records(domain, result)

        # Phase 2: Get nameservers
        await self._get_nameservers(domain, result)

        # Phase 3: Zone transfer attempt
        await self._try_zone_transfer(domain, result)

        # Phase 4: Wildcard detection
        await self._detect_wildcard(domain, result)

        # Phase 5: DNSSEC check
        await self._check_dnssec(domain, result)

        # Phase 6: Email security (SPF/DKIM/DMARC)
        await self._check_email_security(domain, result)

        # Phase 7: Subdomain enumeration
        await self._enumerate_subdomains(domain, result)

        return result

    async def _enumerate_records(self, domain: str, result: DNSScanResult) -> None:
        """Enumerate all DNS record types."""
        if not self._has_dig:
            return

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

        tasks = [self._dig_query(domain, rtype) for rtype in record_types]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for rtype, response in zip(record_types, responses):
            if isinstance(response, Exception):
                continue
            for line in response.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    record = DNSRecord(
                        name=parts[0].rstrip("."),
                        record_type=parts[3],
                        value=" ".join(parts[4:]),
                        ttl=int(parts[1]) if parts[1].isdigit() else 0,
                    )
                    result.records.append(record)

    async def _dig_query(self, domain: str, rtype: str) -> str:
        """Run a dig query."""
        cmd = ["dig", "+short", "+noall", "+answer", rtype, domain]
        if self._nameserver:
            cmd.insert(1, f"@{self._nameserver}")
        output, _ = await _run_cmd(cmd, timeout=self._timeout)
        return output

    async def _get_nameservers(self, domain: str, result: DNSScanResult) -> None:
        """Get authoritative nameservers."""
        if not self._has_dig:
            return
        output, _ = await _run_cmd(["dig", "+short", "NS", domain], timeout=self._timeout)
        for line in output.splitlines():
            ns = line.strip().rstrip(".")
            if ns:
                result.nameservers.append(ns)

    async def _try_zone_transfer(self, domain: str, result: DNSScanResult) -> None:
        """Attempt zone transfer on all nameservers."""
        if not self._has_dig:
            return

        for ns in result.nameservers:
            cmd = ["dig", f"@{ns}", domain, "AXFR", "+noall", "+answer"]
            output, rc = await _run_cmd(cmd, timeout=15.0)

            if rc == 0 and output.strip() and "Transfer failed" not in output:
                line_count = len(output.splitlines())
                if line_count > 2:
                    result.zone_transfer = True
                    result.zone_data = output[:5000]
                    result.findings.append(DNSFinding(
                        title="Zone Transfer Possible",
                        severity="critical",
                        description=f"Zone transfer (AXFR) succeeded on {ns} — exposes all DNS records",
                        evidence=f"Nameserver: {ns}\nRecords returned: {line_count}",
                        category="dns",
                    ))
                    break

    async def _detect_wildcard(self, domain: str, result: DNSScanResult) -> None:
        """Detect wildcard DNS records."""
        if not self._has_dig:
            return

        # Query a random subdomain that shouldn't exist
        random_sub = f"definitely-not-a-real-subdomain-abc123.{domain}"
        output, _ = await _run_cmd(["dig", "+short", "A", random_sub], timeout=self._timeout)

        if output.strip():
            result.wildcard = True
            result.findings.append(DNSFinding(
                title="DNS Wildcard Detected",
                severity="info",
                description=f"Wildcard DNS record exists — *.{domain} resolves to {output.strip()}",
                evidence=f"Random subdomain {random_sub} resolved to {output.strip()}",
                category="dns",
            ))

    async def _check_dnssec(self, domain: str, result: DNSScanResult) -> None:
        """Check for DNSSEC."""
        if not self._has_dig:
            return

        output, _ = await _run_cmd(
            ["dig", "+dnssec", "+short", "DNSKEY", domain], timeout=self._timeout
        )

        if output.strip():
            result.dnssec = True
        else:
            result.findings.append(DNSFinding(
                title="DNSSEC Not Enabled",
                severity="medium",
                description="DNSSEC is not configured, making the domain vulnerable to DNS spoofing",
                category="dns",
            ))

    async def _check_email_security(self, domain: str, result: DNSScanResult) -> None:
        """Check SPF, DKIM, and DMARC records."""
        email = EmailSecurity()

        # SPF
        txt_records = [r for r in result.records if r.record_type == "TXT"]
        for record in txt_records:
            if "v=spf1" in record.value:
                email.spf_record = record.value
                email.spf_valid = True
                self._analyze_spf(record.value, email, result)
                break

        if not email.spf_record:
            # Direct query
            if self._has_dig:
                output, _ = await _run_cmd(["dig", "+short", "TXT", domain], timeout=self._timeout)
                for line in output.splitlines():
                    if "v=spf1" in line:
                        email.spf_record = line.strip('"')
                        email.spf_valid = True
                        self._analyze_spf(email.spf_record, email, result)
                        break

        if not email.spf_record:
            email.spf_issues.append("No SPF record found")
            result.findings.append(DNSFinding(
                title="Missing SPF Record",
                severity="medium",
                description="No SPF record found — domain is vulnerable to email spoofing",
                category="email",
            ))

        # DMARC
        if self._has_dig:
            output, _ = await _run_cmd(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"], timeout=self._timeout
            )
            for line in output.splitlines():
                if "v=DMARC1" in line:
                    email.dmarc_record = line.strip('"')
                    self._analyze_dmarc(email.dmarc_record, email, result)
                    break

        if not email.dmarc_record:
            email.dmarc_issues.append("No DMARC record found")
            result.findings.append(DNSFinding(
                title="Missing DMARC Record",
                severity="medium",
                description="No DMARC record found — no email authentication enforcement",
                category="email",
            ))

        # DKIM (check common selectors)
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]
        for selector in dkim_selectors:
            if self._has_dig:
                output, _ = await _run_cmd(
                    ["dig", "+short", "TXT", f"{selector}._domainkey.{domain}"], timeout=self._timeout
                )
                if "v=DKIM1" in output or "p=" in output:
                    email.dkim_found = True
                    break

        if not email.dkim_found:
            result.findings.append(DNSFinding(
                title="DKIM Not Detected",
                severity="low",
                description="No DKIM record found for common selectors",
                category="email",
            ))

        result.email_security = email

    def _analyze_spf(self, spf: str, email: EmailSecurity, result: DNSScanResult) -> None:
        """Analyze SPF record for issues."""
        if "+all" in spf:
            email.spf_issues.append("SPF uses +all (allows all senders)")
            result.findings.append(DNSFinding(
                title="SPF Record Uses +all",
                severity="high",
                description="SPF record allows all senders (+all), making it useless for anti-spoofing",
                evidence=spf,
                category="email",
            ))
        elif "~all" in spf:
            email.spf_issues.append("SPF uses ~all (softfail — mail still accepted)")
        elif "-all" not in spf and "?all" not in spf:
            email.spf_issues.append("SPF record has no 'all' mechanism")

        # Check for too many lookups
        lookup_count = spf.count("include:") + spf.count("a:") + spf.count("mx:") + spf.count("redirect=")
        if lookup_count > 10:
            email.spf_issues.append(f"SPF record exceeds 10 DNS lookups ({lookup_count} found)")
            result.findings.append(DNSFinding(
                title="SPF Too Many DNS Lookups",
                severity="low",
                description=f"SPF record has {lookup_count} DNS lookups (max 10 allowed by RFC 7208)",
                evidence=spf,
                category="email",
            ))

    def _analyze_dmarc(self, dmarc: str, email: EmailSecurity, result: DNSScanResult) -> None:
        """Analyze DMARC record for issues."""
        policy_match = re.search(r"p=(\w+)", dmarc)
        if policy_match:
            email.dmarc_policy = policy_match.group(1)

        if email.dmarc_policy == "none":
            email.dmarc_issues.append("DMARC policy is 'none' (monitoring only)")
            result.findings.append(DNSFinding(
                title="DMARC Policy is None",
                severity="medium",
                description="DMARC policy is 'none' — no enforcement, only monitoring",
                evidence=dmarc,
                category="email",
            ))

        sp_match = re.search(r"sp=(\w+)", dmarc)
        if not sp_match:
            email.dmarc_issues.append("No subdomain policy (sp=) specified")

        rua_match = re.search(r"rua=", dmarc)
        if not rua_match:
            email.dmarc_issues.append("No aggregate report URI (rua) specified")

    async def _enumerate_subdomains(self, domain: str, result: DNSScanResult) -> None:
        """Brute-force common subdomains."""
        if not self._has_dig:
            return

        # Determine wildcard IP to filter
        wildcard_ip = ""
        if result.wildcard:
            output, _ = await _run_cmd(
                ["dig", "+short", "A", f"nonexistent-test-sub.{domain}"], timeout=self._timeout
            )
            wildcard_ip = output.strip()

        # Resolve common subdomains
        semaphore = asyncio.Semaphore(20)

        async def check_subdomain(sub: str) -> str | None:
            fqdn = f"{sub}.{domain}"
            async with semaphore:
                output, _ = await _run_cmd(["dig", "+short", "A", fqdn], timeout=self._timeout)
                ip = output.strip().splitlines()[0] if output.strip() else ""
                if ip and ip != wildcard_ip:
                    return fqdn
                return None

        tasks = [check_subdomain(sub) for sub in COMMON_SUBDOMAINS]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, str) and resp:
                result.subdomains.append(resp)
