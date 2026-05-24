"""Mobile security knowledge base.

Deep knowledge about mobile security:
1. Android security assessment
2. iOS security assessment
3. Mobile API security
4. Mobile app reverse engineering
5. Mobile malware detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MobileSecurityPattern:
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
        "desc": "Android app security testing.",
        "detection": (
            "ANDROID SECURITY:\n"
            "STATIC ANALYSIS:\n"
            "  - APK decompilation\n"
            "    # apktool d app.apk\n"
            "    # jadx app.apk\n"
            "  - Manifest analysis\n"
            "    # Exported components\n"
            "    # Permission analysis\n"
            "    # debuggable=true\n"
            "    # allowBackup=true\n"
            "  - Hardcoded secrets\n"
            "    # API keys in strings.xml\n"
            "    # Private keys in assets\n"
            "    # Firebase URLs\n"
            "  - Insecure storage\n"
            "    # SharedPreferences (plaintext)\n"
            "    # SQLite databases\n"
            "    # Internal/external storage\n"
            "DYNAMIC ANALYSIS:\n"
            "  - Frida hooking\n"
            "    # frida -U -f com.app.target -l script.js\n"
            "    # Hook SSL pinning bypass\n"
            "    # Hook root detection bypass\n"
            "    # Hook crypto functions\n"
            "  - Network traffic\n"
            "    # Proxy via Burp\n"
            "    # Certificate pinning bypass\n"
            "  - Intent sniffing\n"
            "  - Content provider leaks\n"
            "TOOLS:\n"
            "  MobSF, apktool, jadx, Frida, drozer, objection"
        ),
        "tools": [],
    },
    {
        "id": "mob-002", "name": "iOS Security Assessment",
        "category": "ios", "severity": "high",
        "desc": "iOS app security testing.",
        "detection": (
            "iOS SECURITY:\n"
            "STATIC ANALYSIS:\n"
            "  - IPA extraction\n"
            "    # ipatool/frida-ios-dump\n"
            "  - Binary analysis\n"
            "    # class-dump / dsdump\n"
            "    # otool -l binary (PIE, ARC)\n"
            "    # strings binary | grep -i key\n"
            "  - Plist analysis\n"
            "    # Info.plist\n"
            "    # App Transport Security\n"
            "    # URL schemes\n"
            "  - Entitlements check\n"
            "    # codesign -d --entitlements :- app\n"
            "DYNAMIC ANALYSIS:\n"
            "  - Frida hooking\n"
            "    # SSL pinning bypass\n"
            "    # Jailbreak detection bypass\n"
            "    # Keychain access\n"
            "  - Objection runtime\n"
            "    # objection -g com.app explore\n"
            "    # ios keychain dump\n"
            "    # ios cookies get\n"
            "  - Traffic interception\n"
            "    # Install Burp CA profile\n"
            "    # Or use Frida SSL bypass\n"
            "DATA STORAGE:\n"
            "  - Keychain analysis\n"
            "  - NSUserDefaults\n"
            "  - Core Data / SQLite\n"
            "  - Cache/snapshot images\n"
            "TOOLS:\n"
            "  MobSF, Frida, objection, class-dump, ipatool"
        ),
        "tools": [],
    },
    {
        "id": "mob-003", "name": "Mobile API Security",
        "category": "mobile_api", "severity": "high",
        "desc": "Mobile backend API security.",
        "detection": (
            "MOBILE API SECURITY:\n"
            "AUTHENTICATION:\n"
            "  - Token storage (Keychain/Keystore)\n"
            "  - Token leakage (logs, clipboard)\n"
            "  - OAuth implementation flaws\n"
            "  - Biometric bypass\n"
            "  - Certificate pinning effectiveness\n"
            "ENDPOINTS:\n"
            "  - Hidden API endpoints\n"
            "    # Reverse engineer app → find APIs\n"
            "    # mitmproxy to capture all traffic\n"
            "  - Undocumented parameters\n"
            "  - Debug endpoints left in production\n"
            "  - GraphQL introspection\n"
            "DATA EXPOSURE:\n"
            "  - Excessive data in responses\n"
            "  - PII in API responses\n"
            "  - Verbose error messages\n"
            "  - Server-side stack traces\n"
            "AUTHORIZATION:\n"
            "  - IDOR via mobile API\n"
            "  - Horizontal privilege escalation\n"
            "  - Rate limiting (or lack thereof)\n"
            "  - Business logic flaws\n"
            "TOOLS:\n"
            "  Burp, mitmproxy, Frida, Postman"
        ),
        "tools": [],
    },
    {
        "id": "mob-004", "name": "Mobile App Reverse Engineering",
        "category": "reverse_eng", "severity": "medium",
        "desc": "Mobile app reverse engineering.",
        "detection": (
            "MOBILE REVERSE ENGINEERING:\n"
            "ANDROID:\n"
            "  - DEX → Java decompilation\n"
            "    # jadx (best for reading)\n"
            "    # apktool (for modifying/repackaging)\n"
            "  - Native library analysis\n"
            "    # Ghidra / IDA for .so files\n"
            "    # frida-trace for dynamic\n"
            "  - Obfuscation detection\n"
            "    # ProGuard / R8 mapping\n"
            "    # DexGuard detection\n"
            "  - Anti-tampering bypass\n"
            "    # Signature verification\n"
            "    # Integrity checks\n"
            "iOS:\n"
            "  - Decryption (if FairPlay DRM)\n"
            "    # frida-ios-dump\n"
            "    # CrackerXI (jailbroken)\n"
            "  - Objective-C class dump\n"
            "    # class-dump / dsdump\n"
            "  - Swift binary analysis\n"
            "    # Ghidra with Swift demangling\n"
            "  - Anti-debug detection\n"
            "    # ptrace, sysctl checks\n"
            "COMMON:\n"
            "  - Protocol reverse engineering\n"
            "  - Custom crypto analysis\n"
            "  - License validation bypass\n"
            "  - Root/jailbreak detection bypass\n"
            "TOOLS:\n"
            "  jadx, Ghidra, Frida, radare2, Hopper"
        ),
        "tools": [],
    },
    {
        "id": "mob-005", "name": "Mobile Malware Detection",
        "category": "malware", "severity": "critical",
        "desc": "Mobile malware analysis.",
        "detection": (
            "MOBILE MALWARE DETECTION:\n"
            "ANDROID:\n"
            "  - Permission analysis\n"
            "    # Excessive permissions\n"
            "    # Runtime permission abuse\n"
            "    # Accessibility service abuse\n"
            "  - Behavioral indicators\n"
            "    # Background services\n"
            "    # Battery drain patterns\n"
            "    # Network traffic anomalies\n"
            "  - Code indicators\n"
            "    # Reflection/dynamic loading\n"
            "    # Native code execution\n"
            "    # Encrypted payloads\n"
            "    # C2 communication patterns\n"
            "  - Overlay attacks\n"
            "    # SYSTEM_ALERT_WINDOW\n"
            "    # Fake login screens\n"
            "iOS:\n"
            "  - Enterprise cert abuse\n"
            "  - MDM profile analysis\n"
            "  - Private API usage\n"
            "  - Background activities\n"
            "ANALYSIS:\n"
            "  - Static: MobSF, VirusTotal\n"
            "  - Dynamic: sandbox execution\n"
            "  - Network: traffic capture/analysis\n"
            "  - Memory: Frida runtime inspection\n"
            "TOOLS:\n"
            "  MobSF, VirusTotal, APKiD, YARA"
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
        self._patterns: dict[str, MobileSecurityPattern] = {}
        self._log = logger.bind(component="mobile_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load mobile patterns."""
        for data in MOBILE_PATTERNS:
            pattern = MobileSecurityPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[MobileSecurityPattern]:
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
