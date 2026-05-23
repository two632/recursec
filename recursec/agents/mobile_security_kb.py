"""Mobile security knowledge base.

Deep knowledge about mobile security:
1. Android security testing
2. iOS security testing
3. Mobile API security
4. Mobile app reverse engineering
5. Mobile network attacks
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
            "ANDROID SECURITY TESTING:\n"
            "STATIC ANALYSIS:\n"
            "  # APK decompilation\n"
            "  apktool d app.apk  # Decode resources + smali\n"
            "  jadx -d output/ app.apk  # Java source\n"
            "  unzip app.apk -d extracted/  # Raw extraction\n"
            "  # Check AndroidManifest.xml:\n"
            "  - exported=true components\n"
            "  - android:debuggable=true\n"
            "  - android:allowBackup=true\n"
            "  - Custom permissions\n"
            "  - Intent filters (deeplinks)\n"
            "  # Check for:\n"
            "  - Hardcoded secrets (API keys, tokens)\n"
            "  - Insecure SharedPreferences\n"
            "  - WebView vulnerabilities (JS interface)\n"
            "  - SQL injection in ContentProviders\n"
            "  - Path traversal in FileProviders\n"
            "  - Root detection bypass\n"
            "DYNAMIC ANALYSIS:\n"
            "  # Frida (runtime instrumentation)\n"
            "  frida -U -l script.js com.target.app\n"
            "  # SSL pinning bypass\n"
            "  frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida\n"
            "  # Objection (Frida wrapper)\n"
            "  objection --gadget com.target.app explore\n"
            "  > android sslpinning disable\n"
            "  > android root disable\n"
            "NETWORK:\n"
            "  # Proxy through Burp\n"
            "  # Install Burp CA certificate as system cert\n"
            "  # Check: cert pinning, cleartext traffic\n"
            "TOOLS:\n"
            "  MobSF (automated), drozer, frida, objection, apktool, jadx"
        ),
        "tools": ["mobsf", "frida", "jadx"],
    },
    {
        "id": "mob-002", "name": "iOS Security Testing",
        "category": "ios", "severity": "high",
        "desc": "iOS application security testing.",
        "detection": (
            "iOS SECURITY TESTING:\n"
            "STATIC ANALYSIS:\n"
            "  # IPA extraction (jailbroken)\n"
            "  frida-ios-dump -b com.target.app\n"
            "  # Class-dump headers\n"
            "  class-dump -H app.decrypted\n"
            "  # Check Info.plist:\n"
            "  - App Transport Security settings\n"
            "  - URL schemes\n"
            "  - Custom permissions\n"
            "  # Binary analysis:\n"
            "  otool -l app  # Load commands\n"
            "  # Check PIE, Stack Canaries, ARC\n"
            "  # Search for hardcoded strings\n"
            "  strings app | grep -i 'key\\|secret\\|password'\n"
            "DATA STORAGE:\n"
            "  # Keychain: keychain-dumper\n"
            "  # NSUserDefaults (plist files)\n"
            "  # Core Data (SQLite)\n"
            "  # Check: /var/mobile/Containers/Data/Application/<UUID>/\n"
            "DYNAMIC ANALYSIS:\n"
            "  # Frida\n"
            "  frida -U -l script.js com.target.app\n"
            "  # Objection\n"
            "  objection --gadget com.target.app explore\n"
            "  > ios sslpinning disable\n"
            "  > ios jailbreak disable\n"
            "  # Cycript (runtime manipulation)\n"
            "  cycript -p <pid>\n"
            "RUNTIME:\n"
            "  - Method swizzling\n"
            "  - Jailbreak detection bypass\n"
            "  - Biometric bypass\n"
            "TOOLS:\n"
            "  MobSF, Frida, objection, Hopper, class-dump"
        ),
        "tools": ["mobsf", "frida", "objection"],
    },
    {
        "id": "mob-003", "name": "Mobile API Security",
        "category": "api", "severity": "high",
        "desc": "Mobile API security testing.",
        "detection": (
            "MOBILE API SECURITY:\n"
            "INTERCEPT:\n"
            "  # Set proxy on device/emulator\n"
            "  # Burp Suite / mitmproxy\n"
            "  # Bypass SSL pinning first\n"
            "  # For certificate transparency: patch binary\n"
            "COMMON VULNS:\n"
            "  - Broken authentication (weak tokens)\n"
            "  - IDOR via user_id/object_id\n"
            "  - Excessive data exposure (full user object)\n"
            "  - Missing rate limiting\n"
            "  - Broken function-level auth\n"
            "  - Mass assignment\n"
            "  - GraphQL over-fetching\n"
            "API KEY EXTRACTION:\n"
            "  # Decompile → search strings\n"
            "  # Network intercept → capture API calls\n"
            "  # Firebase misconfig: /.json\n"
            "  # Check API key restrictions\n"
            "TOKEN ATTACKS:\n"
            "  - JWT manipulation\n"
            "  - Token prediction\n"
            "  - Refresh token abuse\n"
            "  - OAuth misconfiguration\n"
            "  - Deep link token interception\n"
            "TESTING:\n"
            "  1. Map all API endpoints\n"
            "  2. Test auth on every endpoint\n"
            "  3. Test IDOR on every object reference\n"
            "  4. Test input validation\n"
            "  5. Test rate limiting\n"
            "  6. Check for debug endpoints"
        ),
        "tools": ["burpsuite", "mitmproxy"],
    },
    {
        "id": "mob-004", "name": "Mobile Reverse Engineering",
        "category": "reversing", "severity": "medium",
        "desc": "Mobile app reverse engineering techniques.",
        "detection": (
            "MOBILE REVERSE ENGINEERING:\n"
            "ANDROID:\n"
            "  # APK → Smali → Java\n"
            "  apktool d app.apk  # Resources + Smali\n"
            "  jadx app.apk  # Decompile to Java\n"
            "  dex2jar app.apk  # DEX → JAR\n"
            "  # Native libs (JNI)\n"
            "  # .so files in lib/ directory\n"
            "  # IDA Pro / Ghidra for native analysis\n"
            "  # Check for obfuscation (ProGuard, R8)\n"
            "iOS:\n"
            "  # Decryption required for AppStore apps\n"
            "  # frida-ios-dump or CrackerXI\n"
            "  # Hopper / IDA Pro for disassembly\n"
            "  # class-dump for Objective-C headers\n"
            "  # Swift demangling: swift-demangle\n"
            "PATCHING:\n"
            "  # Android: Smali modification → rebuild\n"
            "  apktool d app.apk\n"
            "  # Modify smali code\n"
            "  apktool b app/ -o patched.apk\n"
            "  jarsigner -keystore key.jks patched.apk alias\n"
            "  # iOS: Binary patching with Hopper\n"
            "RUNTIME:\n"
            "  # Frida scripting (both platforms)\n"
            "  # Hook functions, modify parameters\n"
            "  # Bypass checks (root, jailbreak, debugger)\n"
            "  # Dump encryption keys at runtime\n"
            "  # Trace function calls\n"
            "OBFUSCATION:\n"
            "  - Name obfuscation (ProGuard/R8/SwiftShield)\n"
            "  - Control flow obfuscation\n"
            "  - String encryption\n"
            "  - Native code protection"
        ),
        "tools": ["jadx", "frida", "ghidra"],
    },
    {
        "id": "mob-005", "name": "Mobile Network Attacks",
        "category": "network", "severity": "critical",
        "desc": "Mobile-specific network attacks.",
        "detection": (
            "MOBILE NETWORK ATTACKS:\n"
            "ROGUE AP:\n"
            "  # Evil twin attack\n"
            "  # Captive portal phishing\n"
            "  # WiFi-Pumpkin / hostapd\n"
            "  # Intercept all traffic\n"
            "SSL/TLS:\n"
            "  # Downgrade attacks\n"
            "  # Self-signed cert acceptance\n"
            "  # Missing cert pinning\n"
            "  # Expired cert handling\n"
            "  # SSLStrip (HTTPS → HTTP)\n"
            "BLUETOOTH:\n"
            "  # BlueSmack (L2CAP flood)\n"
            "  # BlueBorne (CVE-2017-0781)\n"
            "  # BLE sniffing (Ubertooth)\n"
            "  # BLE GATT service enumeration\n"
            "  # KNOB attack\n"
            "NFC:\n"
            "  # Tag cloning\n"
            "  # Relay attacks\n"
            "  # NDEF message manipulation\n"
            "  # EMV contactless attacks\n"
            "SMS/SS7:\n"
            "  # SMS interception (SS7 vuln)\n"
            "  # SIM swapping\n"
            "  # IMSI catchers (Stingray)\n"
            "  # Silent SMS\n"
            "  # Binary SMS exploitation\n"
            "TOOLS:\n"
            "  hostapd, bettercap, ubertooth, nfc-tools"
        ),
        "tools": ["bettercap", "hostapd"],
    },
]


class MobileSecurityKB:
    """Mobile security knowledge base.

    Provides mobile security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, MobilePattern] = {}
        self._log = logger.bind(component="mobile_security_kb")
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
        lines = ["## Mobile Security Patterns\n"]
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
