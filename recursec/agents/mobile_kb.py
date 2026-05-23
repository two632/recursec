"""Mobile security knowledge base.

Deep knowledge about mobile application vulnerabilities:
1. Android security patterns
2. iOS security patterns
3. Mobile API security
4. Certificate pinning bypass
5. Data storage vulnerabilities
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MobileVulnPattern:
    """A mobile vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    platform: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "platform": self.platform[:10],
        }


MOBILE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "mob-001", "name": "Android Insecure Data Storage",
        "platform": "android", "severity": "high",
        "desc": "Sensitive data stored insecurely on Android devices.",
        "detection": (
            "ANDROID INSECURE DATA STORAGE:\n"
            "SHARED PREFERENCES:\n"
            "  - Check /data/data/<package>/shared_prefs/*.xml\n"
            "  - Look for: passwords, tokens, API keys, PII\n"
            "  - Detection: grep -r 'getSharedPreferences\\|MODE_WORLD_READABLE'\n"
            "  - Safe: EncryptedSharedPreferences (AndroidX Security)\n"
            "SQLITE DATABASES:\n"
            "  - Check /data/data/<package>/databases/*.db\n"
            "  - Use sqlite3 to inspect tables for sensitive data\n"
            "  - Detection: Look for unencrypted credential/token tables\n"
            "  - Safe: SQLCipher for encrypted databases\n"
            "INTERNAL STORAGE:\n"
            "  - Files in /data/data/<package>/files/\n"
            "  - Check for hardcoded secrets, credentials in config files\n"
            "  - Check logs in /data/data/<package>/cache/\n"
            "EXTERNAL STORAGE:\n"
            "  - /sdcard/ is world-readable\n"
            "  - Never store sensitive data on external storage\n"
            "  - Detection: grep -r 'getExternalStorage\\|WRITE_EXTERNAL'\n"
            "BACKUP:\n"
            "  - android:allowBackup=true in AndroidManifest.xml\n"
            "  - adb backup -apk -shared <package>\n"
            "  - Extract and inspect backup for secrets\n"
            "CLIPBOARD:\n"
            "  - ClipboardManager can expose copied sensitive data\n"
            "  - Other apps can read clipboard contents"
        ),
        "tools": ["frida", "objection", "adb"],
    },
    {
        "id": "mob-002", "name": "Certificate Pinning Bypass",
        "platform": "both", "severity": "high",
        "desc": "Bypassing SSL/TLS certificate pinning.",
        "detection": (
            "CERTIFICATE PINNING BYPASS:\n"
            "WHY BYPASS:\n"
            "  - Intercept HTTPS traffic for analysis\n"
            "  - Test API endpoints for vulnerabilities\n"
            "  - Analyze authentication flows\n"
            "ANDROID METHODS:\n"
            "  1. Frida script: ssl-pinning-bypass.js\n"
            "     frida -U -f <package> -l ssl_bypass.js\n"
            "  2. Objection: objection -g <package> explore\n"
            "     android sslpinning disable\n"
            "  3. Network Security Config manipulation\n"
            "     Modify res/xml/network_security_config.xml\n"
            "  4. Xposed + SSLUnpinning module\n"
            "iOS METHODS:\n"
            "  1. Frida: ios-ssl-bypass.js\n"
            "  2. Objection: ios sslpinning disable\n"
            "  3. SSL Kill Switch 2 (Cydia tweak)\n"
            "  4. Keychain access for certificates\n"
            "DETECTION INDICATORS:\n"
            "  - OkHttp CertificatePinner class\n"
            "  - TrustManager implementations\n"
            "  - NSURLSession delegate methods\n"
            "  - AFNetworking security policy"
        ),
        "tools": ["frida", "objection", "mitmproxy"],
    },
    {
        "id": "mob-003", "name": "Android Component Exposure",
        "platform": "android", "severity": "high",
        "desc": "Exposed Android components (activities, services, receivers, providers).",
        "detection": (
            "ANDROID COMPONENT EXPOSURE:\n"
            "EXPORTED ACTIVITIES:\n"
            "  - android:exported=true in AndroidManifest.xml\n"
            "  - Can be launched by any app: adb shell am start -n <package>/<activity>\n"
            "  - Check for sensitive activities without auth checks\n"
            "  - Deep link interception: <intent-filter> with custom scheme\n"
            "CONTENT PROVIDERS:\n"
            "  - SQL injection in content:// URIs\n"
            "  - Path traversal: content://authority/../../../etc/passwd\n"
            "  - adb shell content query --uri content://<authority>\n"
            "  - Detection: drozer run app.provider.finduri <package>\n"
            "BROADCAST RECEIVERS:\n"
            "  - Sensitive broadcasts without permission protection\n"
            "  - Sniffable broadcasts: sendBroadcast() without permission\n"
            "  - Detection: drozer run app.broadcast.info <package>\n"
            "SERVICES:\n"
            "  - Exposed bound services\n"
            "  - Intent-based command injection\n"
            "  - Detection: drozer run app.service.info <package>\n"
            "TESTING:\n"
            "  - drozer run app.package.attacksurface <package>\n"
            "  - jadx for static analysis of manifest\n"
            "  - apktool d <apk> for resource extraction"
        ),
        "tools": ["drozer", "adb", "jadx", "apktool"],
    },
    {
        "id": "mob-004", "name": "iOS Keychain and Data Protection",
        "platform": "ios", "severity": "high",
        "desc": "iOS keychain security and data protection issues.",
        "detection": (
            "iOS KEYCHAIN AND DATA PROTECTION:\n"
            "KEYCHAIN ANALYSIS:\n"
            "  - Dump keychain: keychain-dumper (jailbroken)\n"
            "  - Frida: ObjC.classes.SecItemCopyMatching\n"
            "  - Check kSecAttrAccessible values:\n"
            "    - kSecAttrAccessibleAlways: BAD (available even when locked)\n"
            "    - kSecAttrAccessibleAfterFirstUnlock: OK\n"
            "    - kSecAttrAccessibleWhenUnlocked: GOOD\n"
            "DATA PROTECTION CLASSES:\n"
            "  - NSFileProtectionComplete: Best (unavailable when locked)\n"
            "  - NSFileProtectionCompleteUnlessOpen: Good\n"
            "  - NSFileProtectionCompleteUntilFirstUserAuthentication: Default\n"
            "  - NSFileProtectionNone: BAD (always accessible)\n"
            "BINARY ANALYSIS:\n"
            "  - Check PIE (Position Independent Executable): otool -hv\n"
            "  - Check stack canary: otool -Iv | grep __stack_chk\n"
            "  - Check ARC: otool -Iv | grep _objc_release\n"
            "  - Check ASLR: otool -hv <binary>\n"
            "PLIST FILES:\n"
            "  - Check Info.plist for sensitive URLs, keys\n"
            "  - NSAppTransportSecurity exceptions\n"
            "  - URL scheme handlers (CFBundleURLTypes)"
        ),
        "tools": ["frida", "objection", "otool"],
    },
    {
        "id": "mob-005", "name": "Mobile API Security",
        "platform": "both", "severity": "critical",
        "desc": "Common mobile API security issues.",
        "detection": (
            "MOBILE API SECURITY:\n"
            "AUTHENTICATION ISSUES:\n"
            "  - Hardcoded API keys in app binary/resources\n"
            "  - Token stored insecurely (SharedPrefs/UserDefaults)\n"
            "  - No token expiration or refresh mechanism\n"
            "  - Weak or predictable session tokens\n"
            "AUTHORIZATION ISSUES:\n"
            "  - BOLA (Broken Object Level Authorization): Change IDs in requests\n"
            "  - Horizontal privilege escalation via user ID manipulation\n"
            "  - Missing function-level access control\n"
            "  - Admin endpoints accessible with user tokens\n"
            "DATA EXPOSURE:\n"
            "  - API returns more data than needed (verbose responses)\n"
            "  - PII in API responses without need\n"
            "  - Sensitive data in URL parameters (logged by proxies)\n"
            "TESTING APPROACH:\n"
            "  1. Intercept traffic (Burp/mitmproxy + cert pinning bypass)\n"
            "  2. Map all API endpoints from traffic\n"
            "  3. Test each endpoint for BOLA/BFLA\n"
            "  4. Check rate limiting on auth endpoints\n"
            "  5. Test parameter tampering\n"
            "  6. Check for GraphQL introspection if applicable"
        ),
        "tools": ["burp", "mitmproxy", "frida"],
    },
]


class MobileKB:
    """Mobile security knowledge base.

    Provides mobile-specific vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, MobileVulnPattern] = {}
        self._log = logger.bind(component="mobile_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load mobile patterns."""
        for data in MOBILE_PATTERNS:
            pattern = MobileVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                platform=data.get("platform", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_platform(self, platform: str) -> list[MobileVulnPattern]:
        """Get patterns by platform."""
        return [
            p for p in self._patterns.values()
            if p.platform.lower() == platform.lower() or p.platform == "both"
        ]

    def build_mobile_prompt(
        self,
        platform: str = "",
        max_patterns: int = 4,
    ) -> str:
        """Build mobile security prompt."""
        lines = ["## Mobile Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if platform and pattern.platform not in (platform, "both"):
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.platform.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        plat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            plat_counts[p.platform] = plat_counts.get(p.platform, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_platform": plat_counts,
        }
