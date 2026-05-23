"""Mobile security knowledge base.

Deep knowledge about mobile application security:
1. Android application security
2. iOS application security
3. Mobile API security
4. Mobile binary analysis
5. Mobile network traffic analysis
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class MobileVulnPattern:
    """A mobile security vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    platform: str = ""         # android, ios, both
    category: str = ""
    severity: str = "high"
    owasp_mobile: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "platform": self.platform[:8],
            "owasp": self.owasp_mobile[:6],
        }


MOBILE_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "mob-001", "name": "Android Application Analysis",
        "platform": "android", "category": "app_analysis",
        "severity": "high", "owasp_mobile": "M1-M10",
        "desc": "Comprehensive Android application security testing.",
        "testing": (
            "ANDROID APPLICATION ANALYSIS:\n"
            "1. STATIC ANALYSIS:\n"
            "   - Decompile APK:\n"
            "     apktool d app.apk -o output_dir\n"
            "     jadx app.apk -d jadx_output\n"
            "   - Review AndroidManifest.xml:\n"
            "     * Exported components (activities, services, receivers, providers)\n"
            "     * Permissions (dangerous permissions, custom permissions)\n"
            "     * Debug flag (android:debuggable='true')\n"
            "     * Backup flag (android:allowBackup='true')\n"
            "     * Network security config (cleartext allowed?)\n"
            "   - Hardcoded secrets:\n"
            "     grep -r 'api_key\\|secret\\|password\\|token' jadx_output/\n"
            "     grep -r 'firebase\\|aws\\|azure\\|google' jadx_output/\n"
            "   - Certificate pinning:\n"
            "     Check for OkHttp CertificatePinner, TrustManager overrides\n"
            "   - Root detection bypass:\n"
            "     Check for SafetyNet, RootBeer, Magisk detection\n"
            "2. DYNAMIC ANALYSIS:\n"
            "   - Frida hooking:\n"
            "     frida -U -l script.js com.target.app\n"
            "     Hook crypto operations, bypass SSL pinning, bypass root detection\n"
            "   - Objection:\n"
            "     objection -g com.target.app explore\n"
            "     android sslpinning disable\n"
            "     android root disable\n"
            "   - Drozer:\n"
            "     run app.package.info -a com.target.app\n"
            "     run app.package.attacksurface com.target.app\n"
            "     run app.activity.start --component com.target.app com.target.app.ExportedActivity\n"
            "3. DATA STORAGE:\n"
            "   - SharedPreferences: /data/data/com.app/shared_prefs/\n"
            "   - SQLite databases: /data/data/com.app/databases/\n"
            "   - Internal/external storage files\n"
            "   - KeyStore usage (proper or improper)\n"
            "4. IPC ATTACKS:\n"
            "   - Intent injection via exported activities\n"
            "   - Content provider SQL injection\n"
            "   - Broadcast receiver abuse\n"
            "   - PendingIntent hijacking"
        ),
        "tools": ["apktool", "jadx", "Frida", "objection", "drozer", "MobSF"],
    },
    {
        "id": "mob-002", "name": "iOS Application Analysis",
        "platform": "ios", "category": "app_analysis",
        "severity": "high", "owasp_mobile": "M1-M10",
        "desc": "Comprehensive iOS application security testing.",
        "testing": (
            "iOS APPLICATION ANALYSIS:\n"
            "1. STATIC ANALYSIS:\n"
            "   - Decrypt IPA:\n"
            "     frida-ios-dump or clutch (jailbroken device)\n"
            "   - Binary analysis:\n"
            "     class-dump -H app_binary -o headers/\n"
            "     otool -l app_binary (check PIE, ARC, stack canary)\n"
            "   - Check for:\n"
            "     * App Transport Security (ATS) exceptions in Info.plist\n"
            "     * NSAllowsArbitraryLoads = YES (insecure)\n"
            "     * URL schemes registered (potential deeplink abuse)\n"
            "     * Keychain access groups\n"
            "   - Hardcoded secrets:\n"
            "     strings app_binary | grep -i 'api\\|key\\|secret\\|token'\n"
            "2. DYNAMIC ANALYSIS:\n"
            "   - Frida on iOS:\n"
            "     frida -U -l script.js com.target.app\n"
            "     Hook Objective-C methods with ObjC.classes\n"
            "   - SSL pinning bypass:\n"
            "     objection -g com.target.app explore\n"
            "     ios sslpinning disable\n"
            "   - Jailbreak detection bypass:\n"
            "     ios jailbreak disable (objection)\n"
            "3. DATA STORAGE:\n"
            "   - NSUserDefaults (plist files in Library/Preferences/)\n"
            "   - Keychain items: keychain-dumper\n"
            "   - Core Data / SQLite databases\n"
            "   - Cache.db, cookies\n"
            "   - Pasteboard (clipboard data leakage)\n"
            "4. NETWORK:\n"
            "   - Proxy traffic: Configure Burp proxy on device\n"
            "   - Check certificate validation\n"
            "   - WebSocket, gRPC, protobuf analysis\n"
            "5. BINARY PROTECTIONS:\n"
            "   - PIE (Position Independent Executable)\n"
            "   - ARC (Automatic Reference Counting)\n"
            "   - Stack canaries\n"
            "   - Encrypted binary (FairPlay DRM)"
        ),
        "tools": ["Frida", "objection", "class-dump", "otool", "MobSF"],
    },
    {
        "id": "mob-003", "name": "Mobile API Security",
        "platform": "both", "category": "api",
        "severity": "critical", "owasp_mobile": "M3,M9",
        "desc": "Security testing of mobile application APIs.",
        "testing": (
            "MOBILE API SECURITY:\n"
            "1. TRAFFIC INTERCEPTION:\n"
            "   - Configure proxy (Burp/mitmproxy) on device\n"
            "   - Install CA certificate on device\n"
            "   - Bypass SSL pinning:\n"
            "     * Frida: Universal SSL pinning bypass script\n"
            "     * Objection: sslpinning disable\n"
            "     * Magisk + TrustMeAlready (Android)\n"
            "2. API ENDPOINT ANALYSIS:\n"
            "   - Map all API endpoints from traffic\n"
            "   - Check authentication on each endpoint\n"
            "   - Test IDOR: Change user IDs in requests\n"
            "   - Test rate limiting on sensitive endpoints\n"
            "3. AUTHENTICATION:\n"
            "   - Token analysis (JWT, OAuth):\n"
            "     * Decode JWT: jwt.io\n"
            "     * Check alg:none, weak signing key\n"
            "     * Token expiry and refresh flow\n"
            "   - Biometric bypass:\n"
            "     * Hook BiometricPrompt/LAContext via Frida\n"
            "     * Check if server validates biometric or just client-side\n"
            "4. DATA IN TRANSIT:\n"
            "   - Cleartext HTTP communication\n"
            "   - Sensitive data in URL parameters\n"
            "   - API keys in headers/body\n"
            "   - PII in responses without need-to-know\n"
            "5. PUSH NOTIFICATIONS:\n"
            "   - Check for sensitive data in push payloads\n"
            "   - Push token enumeration\n"
            "   - Firebase Cloud Messaging misconfiguration"
        ),
        "tools": ["Burp Suite", "mitmproxy", "Frida", "objection"],
    },
    {
        "id": "mob-004", "name": "Mobile Binary Protection",
        "platform": "both", "category": "binary",
        "severity": "medium", "owasp_mobile": "M8,M9",
        "desc": "Binary protection and reverse engineering resistance.",
        "testing": (
            "MOBILE BINARY PROTECTION:\n"
            "1. ANDROID:\n"
            "   - Check ProGuard/R8 obfuscation:\n"
            "     * Decompile with jadx, check if class/method names readable\n"
            "     * Obfuscated = a.a.a(), clear = com.app.LoginManager.login()\n"
            "   - Native libraries:\n"
            "     * Extract .so files from lib/ directory\n"
            "     * Analyze with Ghidra/IDA: strings, function names\n"
            "     * Check for JNI bridge (sensitive logic in native?)\n"
            "   - Tampering detection:\n"
            "     * Signature verification at runtime\n"
            "     * Debugger detection (android.os.Debug.isDebuggerConnected)\n"
            "     * Emulator detection\n"
            "     * Frida detection (check /tmp/frida-*, port scanning)\n"
            "2. iOS:\n"
            "   - Binary protections:\n"
            "     * otool -hv binary (PIE flag)\n"
            "     * otool -Iv binary | grep _stack_chk (stack canary)\n"
            "     * Check FairPlay encryption: otool -l binary | grep crypt\n"
            "   - Analyze with Hopper/IDA/Ghidra\n"
            "   - Swift vs Objective-C: Different decompilation approaches\n"
            "3. COMMON CHECKS:\n"
            "   - Debug logging in production\n"
            "   - Sensitive data in crash reports\n"
            "   - Analytics/telemetry data exposure\n"
            "   - Third-party SDK analysis (privacy implications)"
        ),
        "tools": ["jadx", "Ghidra", "IDA", "Hopper", "otool"],
    },
]


class MobileSecurityKB:
    """Mobile application security knowledge base.

    Provides deep mobile security testing methodology
    injected into agent prompts for mobile app assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, MobileVulnPattern] = {}
        self._log = logger.bind(component="mobile_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load mobile vulnerability patterns."""
        for data in MOBILE_VULN_PATTERNS:
            pattern = MobileVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                platform=data.get("platform", "both"),
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                owasp_mobile=data.get("owasp_mobile", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_platform(
        self,
        platform: str,
    ) -> list[MobileVulnPattern]:
        """Get patterns for a specific platform."""
        return [
            p for p in self._patterns.values()
            if p.platform in (platform, "both")
        ]

    def get_testing_prompts(
        self,
        platform: str = "",
        max_patterns: int = 3,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if platform and pattern.platform not in (platform, "both"):
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def build_mobile_prompt(
        self,
        platform: str = "",
        max_patterns: int = 3,
    ) -> str:
        """Build mobile testing prompt."""
        relevant = self.get_patterns_for_platform(platform) if platform else list(self._patterns.values())

        lines = ["## Mobile Application Security Testing\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.owasp_mobile:
                lines.append(f"OWASP Mobile: {pattern.owasp_mobile}")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        plat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            plat_counts[p.platform] += 1
        return {
            "patterns": len(self._patterns),
            "by_platform": dict(plat_counts),
        }
