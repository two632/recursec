"""Mobile security knowledge base.

Deep knowledge about mobile security:
1. Android security assessment
2. iOS security assessment
3. Mobile API security
4. Mobile malware analysis
5. Mobile app reverse engineering
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MobilePattern:
    """A mobile security pattern."""
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


MOBILE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "mob-001", "name": "Android Security Assessment",
        "category": "android", "severity": "high",
        "desc": "Android application security assessment.",
        "detection": (
            "ANDROID SECURITY:\n"
            "STATIC ANALYSIS:\n"
            "  # Decompile APK\n"
            "  apktool d app.apk\n"
            "  # Extract classes\n"
            "  d2j-dex2jar app.apk\n"
            "  # View in JD-GUI / JADX\n"
            "  jadx -d output app.apk\n"
            "  CHECK:\n"
            "    - AndroidManifest.xml permissions\n"
            "    - Exported components (activities, services)\n"
            "    - Content providers (SQL injection)\n"
            "    - Broadcast receivers\n"
            "    - Hardcoded secrets/API keys\n"
            "    - Insecure SharedPreferences\n"
            "    - WebView JavaScript bridge\n"
            "    - Certificate pinning implementation\n"
            "    - Root detection bypass\n"
            "DYNAMIC ANALYSIS:\n"
            "  - Frida (runtime instrumentation)\n"
            "    # frida -U -f com.app --no-pause -l script.js\n"
            "    # SSL pinning bypass\n"
            "    # Root detection bypass\n"
            "  - objection (runtime exploration)\n"
            "    # objection --gadget com.app explore\n"
            "  - Drozer (IPC testing)\n"
            "    # run app.package.attacksurface com.app\n"
            "    # run scanner.provider.injection\n"
            "  - Proxy (Burp/mitmproxy)\n"
            "    # Certificate installation\n"
            "    # API traffic interception\n"
            "STORAGE:\n"
            "  - SQLite databases (unencrypted)\n"
            "  - SharedPreferences (world-readable)\n"
            "  - Internal/external storage files\n"
            "  - Keystore usage\n"
            "TOOLS:\n"
            "  JADX, Frida, objection, Drozer, MobSF"
        ),
        "tools": [],
    },
    {
        "id": "mob-002", "name": "iOS Security Assessment",
        "category": "ios", "severity": "high",
        "desc": "iOS application security assessment.",
        "detection": (
            "IOS SECURITY:\n"
            "STATIC ANALYSIS:\n"
            "  # Extract IPA\n"
            "  unzip app.ipa -d extracted\n"
            "  # Check binary\n"
            "  otool -L binary  # linked libraries\n"
            "  otool -l binary  # load commands\n"
            "  # Class dump\n"
            "  class-dump binary > headers.h\n"
            "  CHECK:\n"
            "    - Info.plist (permissions, URL schemes)\n"
            "    - ATS (App Transport Security) config\n"
            "    - Entitlements\n"
            "    - Hardcoded secrets\n"
            "    - Binary protections (PIE, ARC, SSP)\n"
            "    - Keychain usage\n"
            "    - Data Protection classes\n"
            "DYNAMIC ANALYSIS:\n"
            "  - Frida (runtime instrumentation)\n"
            "    # frida -U -f com.app --no-pause\n"
            "    # SSL pinning bypass\n"
            "    # Jailbreak detection bypass\n"
            "  - objection\n"
            "    # objection --gadget com.app explore\n"
            "    # ios keychain dump\n"
            "    # ios plist cat\n"
            "  - Cycript (runtime manipulation)\n"
            "  - Proxy (Burp/Charles)\n"
            "STORAGE:\n"
            "  - Keychain (most secure)\n"
            "  - NSUserDefaults / plist files\n"
            "  - Core Data / SQLite\n"
            "  - Cache/cookies/logs\n"
            "  - Binary cookies\n"
            "TOOLS:\n"
            "  Frida, objection, class-dump, MobSF"
        ),
        "tools": [],
    },
    {
        "id": "mob-003", "name": "Mobile API Security",
        "category": "api", "severity": "high",
        "desc": "Mobile API security testing.",
        "detection": (
            "MOBILE API SECURITY:\n"
            "TRAFFIC INTERCEPTION:\n"
            "  - Proxy setup (Burp/mitmproxy)\n"
            "  - Certificate pinning bypass\n"
            "    # Frida script for SSL bypass\n"
            "    # objection: ios sslpinning disable\n"
            "    # android: --no-verify\n"
            "  - VPN-based interception\n"
            "  - MITM on WiFi\n"
            "API TESTING:\n"
            "  - Authentication flaws\n"
            "    # Token manipulation\n"
            "    # Session fixation\n"
            "    # OAuth flow bypass\n"
            "    # JWT vulnerabilities\n"
            "  - Authorization flaws\n"
            "    # IDOR (Insecure Direct Object Ref)\n"
            "    # Horizontal/vertical privilege\n"
            "    # Role-based access bypass\n"
            "  - Input validation\n"
            "    # API parameter fuzzing\n"
            "    # Injection (SQL, NoSQL, Command)\n"
            "    # Mass assignment\n"
            "  - Rate limiting\n"
            "    # Brute force testing\n"
            "    # Account enumeration\n"
            "  - Data exposure\n"
            "    # Excessive data in responses\n"
            "    # PII exposure\n"
            "    # Debug endpoints\n"
            "OWASP MOBILE:\n"
            "  M1: Improper Platform Usage\n"
            "  M2: Insecure Data Storage\n"
            "  M3: Insecure Communication\n"
            "  M4: Insecure Authentication\n"
            "  M5: Insufficient Cryptography\n"
            "TOOLS:\n"
            "  Burp Suite, Frida, Postman, mitmproxy"
        ),
        "tools": [],
    },
    {
        "id": "mob-004", "name": "Mobile Malware Analysis",
        "category": "malware", "severity": "critical",
        "desc": "Mobile malware analysis techniques.",
        "detection": (
            "MOBILE MALWARE ANALYSIS:\n"
            "TRIAGE:\n"
            "  - File type identification\n"
            "  - Hash lookup (VirusTotal)\n"
            "  - Permission analysis\n"
            "  - String analysis\n"
            "  - Network indicator extraction\n"
            "ANDROID MALWARE:\n"
            "  - Dropper/loader patterns\n"
            "  - Obfuscation techniques\n"
            "    # String encryption\n"
            "    # Reflection-based calls\n"
            "    # Native code loading\n"
            "    # Packing (Qihoo 360, Bangcle)\n"
            "  - C2 communication\n"
            "  - Data exfiltration\n"
            "  - Privilege escalation exploits\n"
            "  - Banking trojan behavior\n"
            "  - Ransomware behavior\n"
            "IOS MALWARE:\n"
            "  - Enterprise certificate abuse\n"
            "  - MDM profile exploitation\n"
            "  - Jailbreak-dependent malware\n"
            "  - XcodeGhost-style supply chain\n"
            "  - WebClip/configuration profile\n"
            "SANDBOXING:\n"
            "  - Android: Cuckoo Droid\n"
            "  - iOS: Corellium (cloud)\n"
            "  - Network monitoring (tcpdump)\n"
            "  - Behavioral analysis\n"
            "TOOLS:\n"
            "  MobSF, APKiD, Cuckoo, VirusTotal"
        ),
        "tools": [],
    },
    {
        "id": "mob-005", "name": "Mobile Reverse Engineering",
        "category": "reverse", "severity": "medium",
        "desc": "Mobile app reverse engineering.",
        "detection": (
            "MOBILE REVERSE ENGINEERING:\n"
            "ANDROID:\n"
            "  - Smali/Baksmali\n"
            "    # Modify smali code\n"
            "    # Rebuild APK: apktool b\n"
            "    # Re-sign: jarsigner/apksigner\n"
            "  - JADX (decompiler)\n"
            "    # Java-like output\n"
            "    # Search functionality\n"
            "  - Ghidra (native code)\n"
            "    # ARM/ARM64 analysis\n"
            "    # JNI function identification\n"
            "  - Frida (runtime)\n"
            "    # Hook any Java method\n"
            "    # Hook native functions\n"
            "    # Trace method calls\n"
            "IOS:\n"
            "  - Hopper/IDA Pro (disassembly)\n"
            "  - class-dump (Objective-C headers)\n"
            "  - Ghidra (free alternative)\n"
            "  - Swift metadata extraction\n"
            "  - dumpDecrypted (decrypt App Store)\n"
            "TECHNIQUES:\n"
            "  - Protocol buffer parsing\n"
            "  - Custom encryption identification\n"
            "  - License check bypass\n"
            "  - Anti-tamper bypass\n"
            "  - Obfuscation removal\n"
            "  - Dynamic library injection\n"
            "  - Method swizzling (iOS)\n"
            "  - Xposed framework (Android)\n"
            "TOOLS:\n"
            "  JADX, Ghidra, Frida, Hopper, radare2"
        ),
        "tools": [],
    },
]


class MobileSecurityKB:
    """Mobile security knowledge base.

    Provides mobile security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, MobilePattern] = {}
        self._log = logger.bind(component="mobile_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load mobile patterns."""
        for data in MOBILE_PATTERNS:
            pattern = MobilePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[MobilePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_mobile_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build mobile security prompt."""
        lines = ["## Mobile Security\n"]
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
