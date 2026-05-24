"""Mobile security knowledge base.

Deep knowledge about mobile security:
1. Android security testing
2. iOS security testing
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
        "id": "mob-001", "name": "Android Security Testing",
        "category": "android", "severity": "high",
        "desc": "Android application security testing.",
        "detection": (
            "ANDROID SECURITY:\n"
            "STATIC ANALYSIS:\n"
            "  # Decompile APK\n"
            "  apktool d app.apk -o output/\n"
            "  jadx app.apk -d decompiled/\n"
            "  # Check AndroidManifest.xml\n"
            "  #   - Exported components\n"
            "  #   - Permissions\n"
            "  #   - Debuggable flag\n"
            "  #   - Backup allowed\n"
            "  #   - Network security config\n"
            "  # Hardcoded secrets\n"
            "  grep -r 'api_key\\|secret\\|password' decompiled/\n"
            "  # Certificate pinning implementation\n"
            "DYNAMIC ANALYSIS:\n"
            "  # Frida (instrumentation)\n"
            "  frida -U -f com.target.app -l script.js\n"
            "  # SSL pinning bypass\n"
            "  objection -g com.target.app explore\n"
            "  # android sslpinning disable\n"
            "  # Proxy traffic\n"
            "  # Burp + Proxy cert install\n"
            "  # ADB\n"
            "  adb shell  # Device shell\n"
            "  adb logcat  # View logs\n"
            "STORAGE:\n"
            "  - SharedPreferences (unencrypted)\n"
            "  - SQLite databases\n"
            "  - Internal/external storage\n"
            "  - Keystore usage\n"
            "IPC:\n"
            "  - Intent sniffing/injection\n"
            "  - Content provider leaks\n"
            "  - Broadcast receiver abuse\n"
            "TOOLS:\n"
            "  MobSF, Frida, Objection, Jadx, APKTool, Drozer"
        ),
        "tools": ["mobsf", "frida", "jadx"],
    },
    {
        "id": "mob-002", "name": "iOS Security Testing",
        "category": "ios", "severity": "high",
        "desc": "iOS application security testing.",
        "detection": (
            "iOS SECURITY:\n"
            "STATIC ANALYSIS:\n"
            "  # Extract IPA\n"
            "  unzip app.ipa -d output/\n"
            "  # Class dump\n"
            "  class-dump AppBinary > headers.h\n"
            "  # Check Info.plist\n"
            "  #   - App Transport Security\n"
            "  #   - URL schemes\n"
            "  #   - Exported types\n"
            "  # Binary analysis\n"
            "  otool -L AppBinary    # Linked frameworks\n"
            "  strings AppBinary     # Hardcoded strings\n"
            "  # Check for PIE, ARC, stack canaries\n"
            "DYNAMIC ANALYSIS:\n"
            "  # Frida\n"
            "  frida -U -f com.target.app -l script.js\n"
            "  # Objection\n"
            "  objection -g com.target.app explore\n"
            "  # ios sslpinning disable\n"
            "  # Needle / Grapefruit\n"
            "STORAGE:\n"
            "  - Keychain (secure storage)\n"
            "  - NSUserDefaults (plist)\n"
            "  - Core Data (SQLite)\n"
            "  - Binary cookies\n"
            "  - Pasteboard\n"
            "  - Snapshot caching\n"
            "IPC:\n"
            "  - URL schemes\n"
            "  - Universal Links\n"
            "  - App Extensions\n"
            "  - UIPasteboard\n"
            "JAILBREAK DETECTION:\n"
            "  - Bypass techniques (Frida/Liberty)\n"
            "TOOLS:\n"
            "  MobSF, Frida, Objection, class-dump, otool"
        ),
        "tools": ["mobsf", "frida"],
    },
    {
        "id": "mob-003", "name": "Mobile API Security",
        "category": "api", "severity": "high",
        "desc": "Mobile API security testing.",
        "detection": (
            "MOBILE API SECURITY:\n"
            "INTERCEPTION:\n"
            "  # Setup proxy (Burp/mitmproxy)\n"
            "  # Install CA certificate on device\n"
            "  # Bypass certificate pinning\n"
            "  # Android: Frida / objection\n"
            "  # iOS: SSL Kill Switch 2\n"
            "COMMON ISSUES:\n"
            "  - Insecure authentication\n"
            "  - Hardcoded API keys\n"
            "  - Missing rate limiting\n"
            "  - Broken object level authorization (BOLA)\n"
            "  - Excessive data exposure\n"
            "  - Mass assignment\n"
            "  - Security misconfiguration\n"
            "  - Injection (SQL, NoSQL, command)\n"
            "  - Improper asset management\n"
            "TOKEN ANALYSIS:\n"
            "  - JWT validation (none algorithm)\n"
            "  - JWT secret brute force\n"
            "  - OAuth flow manipulation\n"
            "  - Token storage on device\n"
            "  - Refresh token handling\n"
            "  - Session fixation\n"
            "TESTING:\n"
            "  # mitmproxy scripting\n"
            "  mitmdump -s modify_request.py\n"
            "  # API fuzzing\n"
            "  # Rate limit testing\n"
            "  # Authorization testing\n"
            "TOOLS:\n"
            "  Burp Suite, mitmproxy, Postman, Insomnia"
        ),
        "tools": ["burp", "mitmproxy"],
    },
    {
        "id": "mob-004", "name": "Mobile Malware Analysis",
        "category": "malware", "severity": "high",
        "desc": "Mobile malware analysis techniques.",
        "detection": (
            "MOBILE MALWARE ANALYSIS:\n"
            "ANDROID:\n"
            "  INDICATORS:\n"
            "    - Excessive permissions\n"
            "    - Device admin requests\n"
            "    - Accessibility service abuse\n"
            "    - SMS/call interception\n"
            "    - Overlay attacks\n"
            "    - Keylogging\n"
            "    - Screen recording\n"
            "  FAMILIES:\n"
            "    - Banking trojans (Anubis, Cerberus)\n"
            "    - Spyware (Pegasus, Predator)\n"
            "    - Ransomware (DoubleLocker)\n"
            "    - Adware\n"
            "    - Crypto miners\n"
            "  ANALYSIS:\n"
            "    # MobSF automated scan\n"
            "    # Strace/ltrace\n"
            "    # Network traffic analysis\n"
            "    # Behavior monitoring\n"
            "iOS:\n"
            "  - Profile-based malware\n"
            "  - MDM abuse\n"
            "  - Sideloaded apps\n"
            "  - WebClip exploits\n"
            "  - Zero-click exploits (NSO Group)\n"
            "TOOLS:\n"
            "  MobSF, VirusTotal, Koodous, Pithus"
        ),
        "tools": ["mobsf"],
    },
    {
        "id": "mob-005", "name": "Mobile App Reverse Engineering",
        "category": "reverse", "severity": "medium",
        "desc": "Mobile application reverse engineering.",
        "detection": (
            "MOBILE REVERSE ENGINEERING:\n"
            "ANDROID:\n"
            "  # Dex → Java\n"
            "  jadx app.apk -d src/\n"
            "  # Smali\n"
            "  apktool d app.apk\n"
            "  # Modify smali → rebuild\n"
            "  apktool b output/ -o modified.apk\n"
            "  # Sign\n"
            "  jarsigner -verbose -keystore key.jks modified.apk alias\n"
            "  # Native libraries (.so)\n"
            "  # Ghidra / IDA for ARM analysis\n"
            "  # JNI function analysis\n"
            "iOS:\n"
            "  # Decrypt IPA (frida-ios-dump)\n"
            "  frida-ios-dump com.target.app\n"
            "  # Class dump\n"
            "  class-dump binary > headers.h\n"
            "  # Hopper / IDA / Ghidra\n"
            "  # Swift demangling\n"
            "  # Objective-C runtime analysis\n"
            "OBFUSCATION:\n"
            "  - ProGuard/R8 (Android)\n"
            "  - DexGuard (commercial)\n"
            "  - String encryption\n"
            "  - Control flow obfuscation\n"
            "  - Native code obfuscation (OLLVM)\n"
            "  - Anti-tamper checks\n"
            "  - Root/jailbreak detection\n"
            "PATCHING:\n"
            "  - Smali modification\n"
            "  - Frida runtime patching\n"
            "  - Binary patching (Ghidra)\n"
            "  - Method swizzling (iOS)\n"
            "TOOLS:\n"
            "  Jadx, Ghidra, IDA, Hopper, Frida, APKTool"
        ),
        "tools": ["jadx", "ghidra", "frida"],
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
