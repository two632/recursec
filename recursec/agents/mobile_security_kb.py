"""Mobile security knowledge base.

Deep knowledge about mobile app security:
1. Android application testing
2. iOS application testing
3. Mobile API interception
4. Mobile malware analysis
5. Mobile device management bypass
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
    platform: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "platform": self.platform[:8],
        }


MOBILE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "mob-001", "name": "Android Application Analysis",
        "category": "static", "platform": "android", "severity": "high",
        "desc": "Static and dynamic analysis of Android applications.",
        "detection": (
            "ANDROID APP ANALYSIS:\n"
            "STATIC ANALYSIS:\n"
            "  # Decompile APK\n"
            "  apktool d app.apk -o output/  # Resources + smali\n"
            "  jadx app.apk -d output/  # Java source code\n"
            "  # Automated scanning\n"
            "  mobsf  # Mobile Security Framework (web UI)\n"
            "  # Manual checks:\n"
            "  - AndroidManifest.xml:\n"
            "    android:debuggable=\"true\"  # Debug enabled\n"
            "    android:allowBackup=\"true\"  # Data backup\n"
            "    android:exported=\"true\"  # Exposed components\n"
            "    android:usesCleartextTraffic=\"true\"  # HTTP allowed\n"
            "  - Hardcoded secrets in source/resources\n"
            "  - Weak crypto: ECB mode, MD5/SHA1 for passwords\n"
            "  - WebView: setJavaScriptEnabled + addJavascriptInterface\n"
            "  - SQL injection in ContentProviders\n"
            "DYNAMIC ANALYSIS:\n"
            "  # Frida (runtime instrumentation)\n"
            "  frida -U -f com.target.app -l hook.js\n"
            "  # Common hooks:\n"
            "  - SSL pinning bypass\n"
            "  - Root detection bypass\n"
            "  - Encryption key extraction\n"
            "  - Function return value modification\n"
            "  # Drozer (component testing)\n"
            "  drozer console connect\n"
            "  run app.package.info -a com.target\n"
            "  run app.activity.info -a com.target"
        ),
        "tools": ["apktool", "jadx", "frida", "mobsf"],
    },
    {
        "id": "mob-002", "name": "iOS Application Analysis",
        "category": "static", "platform": "ios", "severity": "high",
        "desc": "Static and dynamic analysis of iOS applications.",
        "detection": (
            "IOS APP ANALYSIS:\n"
            "STATIC ANALYSIS:\n"
            "  # Decrypt IPA (if from App Store)\n"
            "  # On jailbroken device:\n"
            "  flexdecrypt /var/containers/Bundle/Application/<uuid>/app\n"
            "  # Or: frida-ios-dump\n"
            "  dump.py com.target.app\n"
            "  # Analyze binary\n"
            "  class-dump app_binary  # Objective-C headers\n"
            "  otool -L app_binary  # Linked libraries\n"
            "  strings app_binary | grep -i 'api\\|key\\|secret\\|password'\n"
            "  # Hopper/IDA for disassembly\n"
            "PLIST AND DATA:\n"
            "  - Info.plist: App Transport Security settings\n"
            "  - NSAppTransportSecurity → NSAllowsArbitraryLoads\n"
            "  - Keychain items (keychain-dumper)\n"
            "  - NSUserDefaults for sensitive data\n"
            "  - SQLite databases in app sandbox\n"
            "  - Core Data stores\n"
            "DYNAMIC ANALYSIS:\n"
            "  # Frida on iOS\n"
            "  frida -U com.target.app -l bypass_ssl.js\n"
            "  # objection (Frida-based)\n"
            "  objection -g com.target.app explore\n"
            "  ios sslpinning disable\n"
            "  ios keychain dump\n"
            "  ios nsuserdefaults get\n"
            "  ios hooking search classes target"
        ),
        "tools": ["frida", "objection", "class-dump"],
    },
    {
        "id": "mob-003", "name": "Mobile Traffic Interception",
        "category": "network", "platform": "both", "severity": "high",
        "desc": "Intercepting and analyzing mobile app network traffic.",
        "detection": (
            "MOBILE TRAFFIC INTERCEPTION:\n"
            "PROXY SETUP:\n"
            "  # Burp Suite proxy\n"
            "  - Set proxy on device: <attacker_ip>:8080\n"
            "  - Install Burp CA certificate on device\n"
            "  # mitmproxy\n"
            "  mitmproxy --mode regular --listen-port 8080\n"
            "  # For HTTPS:\n"
            "  - Install mitmproxy CA on device\n"
            "SSL PINNING BYPASS:\n"
            "  # Frida universal bypass\n"
            "  frida -U -f com.target -l ssl_bypass.js --no-pause\n"
            "  # objection\n"
            "  objection -g com.target explore\n"
            "  android sslpinning disable\n"
            "  ios sslpinning disable\n"
            "  # Android: Override network_security_config.xml\n"
            "  # Magisk module: TrustUserCerts\n"
            "CERTIFICATE TRANSPARENCY:\n"
            "  - Check for cert pinning in code\n"
            "  - TrustManager implementation\n"
            "  - OkHttp CertificatePinner\n"
            "  - NSURLSessionDelegate (iOS)\n"
            "WHAT TO LOOK FOR:\n"
            "  - API keys in headers\n"
            "  - Authentication tokens\n"
            "  - Sensitive data in plaintext\n"
            "  - Hidden API endpoints\n"
            "  - Debug/admin endpoints\n"
            "  - GraphQL introspection enabled"
        ),
        "tools": ["burp", "mitmproxy", "frida"],
    },
    {
        "id": "mob-004", "name": "Android Root and Integrity Bypass",
        "category": "bypass", "platform": "android", "severity": "medium",
        "desc": "Bypassing root detection and integrity checks.",
        "detection": (
            "ROOT AND INTEGRITY BYPASS:\n"
            "ROOT DETECTION METHODS:\n"
            "  - Check for su binary: /system/xbin/su, /system/bin/su\n"
            "  - Check for Magisk/SuperSU files\n"
            "  - SafetyNet/Play Integrity API\n"
            "  - Check build tags: test-keys\n"
            "  - Check for busybox\n"
            "  - Mounting check (/system read-write)\n"
            "BYPASS TECHNIQUES:\n"
            "  # Magisk (root with hiding)\n"
            "  - MagiskHide / Zygisk DenyList\n"
            "  - Shamiko module (advanced hiding)\n"
            "  # Frida hooks\n"
            "  - Hook File.exists() → return false for su paths\n"
            "  - Hook System.getProperty() → return release-keys\n"
            "  - Hook PackageManager → hide root apps\n"
            "  # LSPosed + custom modules\n"
            "INTEGRITY CHECKS:\n"
            "  - APK signature verification\n"
            "  - Checksum of native libraries\n"
            "  - Certificate pinning\n"
            "  - Emulator detection\n"
            "  - Debugging detection (android.os.Debug)\n"
            "  - Hooking framework detection (Frida, Xposed)\n"
            "BYPASS TOOLS:\n"
            "  - apk-mitm: Automated cert bypass\n"
            "  - Objection: Runtime manipulation\n"
            "  - Medusa: Extensible framework"
        ),
        "tools": ["frida", "magisk", "objection"],
    },
    {
        "id": "mob-005", "name": "Mobile Data Storage Security",
        "category": "storage", "platform": "both", "severity": "high",
        "desc": "Analyzing insecure data storage on mobile devices.",
        "detection": (
            "MOBILE DATA STORAGE:\n"
            "ANDROID:\n"
            "  # Shared Preferences (plaintext XML)\n"
            "  /data/data/<package>/shared_prefs/*.xml\n"
            "  # SQLite databases\n"
            "  /data/data/<package>/databases/*.db\n"
            "  sqlite3 *.db '.tables'  # List tables\n"
            "  sqlite3 *.db 'SELECT * FROM credentials;'\n"
            "  # Internal storage files\n"
            "  /data/data/<package>/files/\n"
            "  # External storage (world-readable!)\n"
            "  /sdcard/Android/data/<package>/\n"
            "  # Backup extraction\n"
            "  adb backup -f backup.ab <package>\n"
            "  abe unpack backup.ab backup.tar\n"
            "IOS:\n"
            "  # Keychain (should be encrypted)\n"
            "  keychain-dumper  # On jailbroken device\n"
            "  # NSUserDefaults\n"
            "  /var/mobile/Containers/Data/Application/<uuid>/Library/Preferences/\n"
            "  # SQLite databases\n"
            "  /var/mobile/Containers/Data/Application/<uuid>/Documents/\n"
            "  # Core Data\n"
            "  # Cookies (Cookies.binarycookies)\n"
            "  # Cache (URLCache)\n"
            "  # Pasteboard data\n"
            "COMMON ISSUES:\n"
            "  - Credentials in SharedPreferences/NSUserDefaults\n"
            "  - Unencrypted SQLite databases\n"
            "  - API keys in app binary\n"
            "  - Session tokens in logs\n"
            "  - Screenshots in app switcher"
        ),
        "tools": ["adb", "frida", "keychain-dumper"],
    },
]


class MobileSecurityKB:
    """Mobile security knowledge base.

    Provides mobile app security patterns
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
            if platforms and pattern.platform.lower() not in [p.lower() for p in platforms]:
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
