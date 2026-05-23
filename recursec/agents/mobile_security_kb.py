"""Mobile security knowledge base.

Deep knowledge about mobile application attacks:
1. Android reverse engineering
2. iOS security testing
3. Mobile API testing
4. Certificate pinning bypass
5. Mobile data storage vulnerabilities
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
        "id": "mob-001", "name": "Android APK Reverse Engineering",
        "platform": "android", "severity": "high",
        "desc": "Decompiling and analyzing Android applications.",
        "detection": (
            "ANDROID REVERSE ENGINEERING:\n"
            "DECOMPILATION:\n"
            "  # Decompile APK to Java source\n"
            "  jadx -d output/ <app>.apk\n"
            "  # Extract resources and manifest\n"
            "  apktool d <app>.apk -o output/\n"
            "  # Convert DEX to JAR\n"
            "  d2j-dex2jar <app>.apk\n"
            "ANALYSIS TARGETS:\n"
            "  AndroidManifest.xml:\n"
            "    - Exported components (activities, services, receivers)\n"
            "    - Permissions (dangerous permissions)\n"
            "    - Backup allowed (android:allowBackup=true)\n"
            "    - Debuggable (android:debuggable=true)\n"
            "    - Network security config\n"
            "  Source Code:\n"
            "    - Hardcoded secrets (API keys, passwords, tokens)\n"
            "    - Firebase URLs (*.firebaseio.com)\n"
            "    - AWS credentials\n"
            "    - Certificate pinning implementation\n"
            "    - Crypto usage (weak algorithms, hardcoded keys)\n"
            "  Shared Preferences:\n"
            "    - /data/data/<package>/shared_prefs/\n"
            "    - Plaintext credentials/tokens\n"
            "  SQLite Databases:\n"
            "    - /data/data/<package>/databases/\n"
            "    - Unencrypted sensitive data"
        ),
        "tools": ["jadx", "apktool", "mobsf"],
    },
    {
        "id": "mob-002", "name": "Certificate Pinning Bypass",
        "platform": "both", "severity": "medium",
        "desc": "Bypassing SSL/TLS certificate pinning in mobile apps.",
        "detection": (
            "CERTIFICATE PINNING BYPASS:\n"
            "ANDROID:\n"
            "  Frida-based:\n"
            "    # Universal SSL pinning bypass\n"
            "    frida -U -l bypass-ssl.js -f <package>\n"
            "    # Objection (automated)\n"
            "    objection -g <package> explore\n"
            "    > android sslpinning disable\n"
            "  Network Security Config:\n"
            "    - Modify res/xml/network_security_config.xml\n"
            "    - Add user CA trust anchors\n"
            "    - Repackage APK\n"
            "  Specific Libraries:\n"
            "    - OkHttp: Hook CertificatePinner.check()\n"
            "    - Retrofit: Modify OkHttpClient\n"
            "    - TrustManager: Hook checkServerTrusted()\n"
            "iOS:\n"
            "  Frida-based:\n"
            "    frida -U -l ios-bypass.js <app>\n"
            "    objection -g <bundle_id> explore\n"
            "    > ios sslpinning disable\n"
            "  SSL Kill Switch (Cydia):\n"
            "    - Hooks all SSL validation functions\n"
            "    - Works on most apps without customization\n"
            "PROXY SETUP:\n"
            "  - Install Burp CA certificate on device\n"
            "  - Configure device proxy to Burp\n"
            "  - Android: Install in user CA store (API 24+: needs config)\n"
            "  - iOS: Settings → General → Profile → Install"
        ),
        "tools": ["frida", "objection", "burp"],
    },
    {
        "id": "mob-003", "name": "Insecure Data Storage",
        "platform": "both", "severity": "high",
        "desc": "Sensitive data stored insecurely on mobile devices.",
        "detection": (
            "INSECURE DATA STORAGE:\n"
            "ANDROID:\n"
            "  Locations to check:\n"
            "    /data/data/<package>/shared_prefs/  # SharedPreferences\n"
            "    /data/data/<package>/databases/  # SQLite databases\n"
            "    /data/data/<package>/files/  # Internal files\n"
            "    /data/data/<package>/cache/  # Cache files\n"
            "    /sdcard/  # External storage (world-readable)\n"
            "  Tools:\n"
            "    adb shell su -c 'cat /data/data/<pkg>/shared_prefs/*.xml'\n"
            "    sqlite3 /data/data/<pkg>/databases/*.db '.dump'\n"
            "  What to look for:\n"
            "    - Passwords, tokens, session IDs in plaintext\n"
            "    - PII (personal data) unencrypted\n"
            "    - API keys and secrets\n"
            "    - Financial data\n"
            "iOS:\n"
            "  Locations:\n"
            "    Documents/  # App documents\n"
            "    Library/Preferences/*.plist  # NSUserDefaults\n"
            "    Library/Caches/  # Cache data\n"
            "    tmp/  # Temporary files\n"
            "    Keychain  # iOS keychain (should use for secrets)\n"
            "  Tools:\n"
            "    iExplorer, iFunBox for filesystem browsing\n"
            "    Keychain-dumper for keychain extraction\n"
            "    plutil -p for plist reading"
        ),
        "tools": ["adb", "mobsf", "frida"],
    },
    {
        "id": "mob-004", "name": "Intent/Deeplink Hijacking",
        "platform": "android", "severity": "high",
        "desc": "Exploiting Android intents and deep links.",
        "detection": (
            "INTENT/DEEPLINK HIJACKING:\n"
            "EXPORTED COMPONENTS:\n"
            "  Find exported activities:\n"
            "    grep -r 'android:exported=\"true\"' AndroidManifest.xml\n"
            "    drozer: run app.activity.info -a <package>\n"
            "  Launch exported activities:\n"
            "    adb shell am start -n <package>/<activity>\n"
            "    adb shell am start -n <package>/<activity> -e key value\n"
            "  Send to exported receivers:\n"
            "    adb shell am broadcast -a <action> -e key value\n"
            "DEEP LINK TESTING:\n"
            "  Find deep links:\n"
            "    grep -r 'android:scheme' AndroidManifest.xml\n"
            "    grep -r 'android:host' AndroidManifest.xml\n"
            "  Test deep links:\n"
            "    adb shell am start -a android.intent.action.VIEW \\\n"
            "      -d 'scheme://host/path?param=value'\n"
            "  Vulnerabilities:\n"
            "    - Unvalidated deep link parameters → XSS in WebView\n"
            "    - Deep link to privileged activity\n"
            "    - OAuth redirect hijacking via deep link\n"
            "    - File:// scheme in WebView (local file read)\n"
            "CONTENT PROVIDERS:\n"
            "  drozer: run scanner.provider.injection -a <package>\n"
            "  SQL injection in content provider queries\n"
            "  Path traversal in file providers"
        ),
        "tools": ["drozer", "adb", "jadx"],
    },
    {
        "id": "mob-005", "name": "Runtime Manipulation",
        "platform": "both", "severity": "high",
        "desc": "Dynamic instrumentation and runtime manipulation.",
        "detection": (
            "RUNTIME MANIPULATION:\n"
            "FRIDA (Dynamic Instrumentation):\n"
            "  Setup:\n"
            "    # Push frida-server to device\n"
            "    adb push frida-server /data/local/tmp/\n"
            "    adb shell chmod 755 /data/local/tmp/frida-server\n"
            "    adb shell /data/local/tmp/frida-server &\n"
            "  Common Hooks:\n"
            "    - Bypass root detection:\n"
            "      Hook isRooted(), checkSu(), checkBusyBox()\n"
            "    - Bypass integrity checks:\n"
            "      Hook signature verification methods\n"
            "    - Modify return values:\n"
            "      Hook authentication methods → return true\n"
            "    - Intercept crypto operations:\n"
            "      Hook encrypt/decrypt to capture keys/plaintext\n"
            "    - Trace method calls:\n"
            "      Log arguments and return values\n"
            "OBJECTION:\n"
            "  objection -g <package> explore\n"
            "  > android hooking list activities\n"
            "  > android hooking list classes\n"
            "  > android hooking watch class <class>\n"
            "  > android hooking set return_value <method> true\n"
            "MAGISK (Rooted Devices):\n"
            "  - Hide root from apps (MagiskHide/DenyList)\n"
            "  - Systemless modifications"
        ),
        "tools": ["frida", "objection", "magisk"],
    },
]


class MobileSecurityKB:
    """Mobile security knowledge base.

    Provides mobile attack patterns injected
    into agent prompts.
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
                platform=data.get("platform", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_platform(self, platform: str) -> list[MobilePattern]:
        """Get patterns by platform."""
        return [
            p for p in self._patterns.values()
            if p.platform.lower() == platform.lower()
            or p.platform.lower() == "both"
        ]

    def build_mobile_prompt(
        self,
        platforms: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build mobile security prompt."""
        lines = ["## Mobile Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if platforms and pattern.platform.lower() not in [p.lower() for p in platforms] and pattern.platform.lower() != "both":
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
