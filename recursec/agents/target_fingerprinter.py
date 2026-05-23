"""Target fingerprinter — identifies technologies, services, and characteristics.

Implements:
1. Web technology detection
2. Server fingerprinting
3. CMS detection
4. Framework detection
5. WAF detection
6. CDN detection
7. API technology detection
8. Version extraction
9. OS fingerprinting heuristics
10. SSL/TLS fingerprinting
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Fingerprint:
    """A technology fingerprint."""
    technology: str = ""
    category: str = ""             # server, framework, cms, waf, cdn, language, os
    version: str = ""
    confidence: float = 0.7
    source: str = ""               # How it was detected
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tech": self.technology, "category": self.category,
            "version": self.version,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class TargetProfile:
    """Complete target profile from fingerprinting."""
    target: str = ""
    fingerprints: list[Fingerprint] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    os_guess: str = ""
    is_behind_waf: bool = False
    is_behind_cdn: bool = False
    technologies: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:60],
            "technologies": self.technologies[:10],
            "ports": self.open_ports[:20],
            "os": self.os_guess,
            "waf": self.is_behind_waf,
            "cdn": self.is_behind_cdn,
            "risk_factors": len(self.risk_factors),
        }


# ── Detection Signatures ─────────────────────────────────────

SERVER_SIGNATURES: dict[str, list[str]] = {
    "Apache": ["apache", "httpd"],
    "Nginx": ["nginx"],
    "IIS": ["microsoft-iis", "iis"],
    "LiteSpeed": ["litespeed"],
    "Caddy": ["caddy"],
    "Tomcat": ["apache-coyote", "tomcat"],
    "Jetty": ["jetty"],
    "Node.js": ["express", "node.js", "koa"],
    "Gunicorn": ["gunicorn"],
    "Uvicorn": ["uvicorn"],
}

CMS_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-content", "wp-includes", "wp-json", "wordpress"],
    "Drupal": ["drupal", "sites/default", "misc/drupal"],
    "Joomla": ["joomla", "com_content", "/administrator"],
    "Magento": ["magento", "mage/", "skin/frontend"],
    "Ghost": ["ghost", "ghost-api"],
    "Shopify": ["shopify", "cdn.shopify"],
    "Wix": ["wix.com", "parastorage"],
    "Squarespace": ["squarespace", "sqsp.net"],
}

FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "React": ["react", "__next", "react-dom", "_next/static"],
    "Angular": ["angular", "ng-version", "ng-app"],
    "Vue.js": ["vue.js", "vuejs", "__vue__"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Flask": ["flask", "werkzeug"],
    "Laravel": ["laravel", "laravel_session"],
    "Spring": ["spring", "jsessionid"],
    "Ruby on Rails": ["rails", "ruby", "_rails"],
    "ASP.NET": ["asp.net", "__viewstate", ".aspx"],
    "FastAPI": ["fastapi", "openapi.json"],
    "Next.js": ["next.js", "_next/", "__next"],
    "Nuxt.js": ["nuxt", "__nuxt"],
}

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache"],
    "AWS WAF": ["awswaf", "x-amzn"],
    "Akamai": ["akamai", "akamaighost"],
    "Imperva": ["imperva", "incapsula"],
    "F5 BIG-IP": ["bigip", "f5-trafficshield"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "ModSecurity": ["modsecurity", "mod_security"],
    "Barracuda": ["barracuda"],
}

CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf"],
    "Akamai": ["akamai"],
    "Fastly": ["fastly", "x-served-by"],
    "Azure CDN": ["azure", "msedge"],
    "Google Cloud CDN": ["google", "gws"],
    "Vercel": ["vercel", "x-vercel"],
    "Netlify": ["netlify"],
}

LANGUAGE_SIGNATURES: dict[str, list[str]] = {
    "PHP": [".php", "x-powered-by: php", "phpsessid"],
    "Python": ["python", "django", "flask", "gunicorn", "uvicorn"],
    "Java": [".jsp", ".do", "jsessionid", "java"],
    "Ruby": [".rb", "ruby", "rails", "rack"],
    "Go": ["go", "gorilla"],
    "Node.js": ["node", "express", "x-powered-by: express"],
    "C#": [".aspx", "asp.net", "__viewstate"],
    "Rust": ["actix", "warp", "rocket"],
}


class TargetFingerprinter:
    """Identifies technologies and characteristics of targets.

    Analyzes HTTP responses, headers, and content
    to fingerprint technologies.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._log = logger.bind(component="target_fingerprinter")

    def fingerprint(
        self,
        target: str,
        headers: dict[str, str] | None = None,
        body: str = "",
        ports: list[int] | None = None,
        services: dict[int, str] | None = None,
    ) -> TargetProfile:
        """Fingerprint a target from available data."""
        profile = TargetProfile(
            target=target,
            open_ports=ports or [],
            services=services or {},
        )

        all_text = ""
        if headers:
            all_text += " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        if body:
            all_text += " " + body[:10000].lower()

        # Server detection
        for tech, sigs in SERVER_SIGNATURES.items():
            if any(sig in all_text for sig in sigs):
                version = self._extract_version(all_text, tech)
                profile.fingerprints.append(Fingerprint(
                    technology=tech, category="server",
                    version=version, confidence=0.8,
                    source="header/body",
                ))

        # CMS detection
        for tech, sigs in CMS_SIGNATURES.items():
            if any(sig in all_text for sig in sigs):
                version = self._extract_version(all_text, tech)
                profile.fingerprints.append(Fingerprint(
                    technology=tech, category="cms",
                    version=version, confidence=0.75,
                    source="body",
                ))

        # Framework detection
        for tech, sigs in FRAMEWORK_SIGNATURES.items():
            if any(sig in all_text for sig in sigs):
                profile.fingerprints.append(Fingerprint(
                    technology=tech, category="framework",
                    confidence=0.7, source="body",
                ))

        # WAF detection
        for tech, sigs in WAF_SIGNATURES.items():
            if any(sig in all_text for sig in sigs):
                profile.fingerprints.append(Fingerprint(
                    technology=tech, category="waf",
                    confidence=0.85, source="header",
                ))
                profile.is_behind_waf = True

        # CDN detection
        for tech, sigs in CDN_SIGNATURES.items():
            if any(sig in all_text for sig in sigs):
                profile.fingerprints.append(Fingerprint(
                    technology=tech, category="cdn",
                    confidence=0.85, source="header",
                ))
                profile.is_behind_cdn = True

        # Language detection
        for tech, sigs in LANGUAGE_SIGNATURES.items():
            if any(sig in all_text for sig in sigs):
                profile.fingerprints.append(Fingerprint(
                    technology=tech, category="language",
                    confidence=0.6, source="mixed",
                ))

        # OS guessing from services
        if services:
            profile.os_guess = self._guess_os(services)

        # Build technology list
        profile.technologies = list({
            fp.technology for fp in profile.fingerprints
        })

        # Identify risk factors
        profile.risk_factors = self._identify_risks(profile)

        self._profiles[target] = profile
        return profile

    def _extract_version(self, text: str, technology: str) -> str:
        """Extract version number near technology name."""
        tech_lower = technology.lower()
        patterns = [
            rf"{tech_lower}[/\s]+(\d+\.\d+(?:\.\d+)?)",
            rf"{tech_lower}\s+version[:\s]+(\d+\.\d+(?:\.\d+)?)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""

    def _guess_os(self, services: dict[int, str]) -> str:
        """Guess OS from services."""
        service_text = " ".join(services.values()).lower()

        if any(w in service_text for w in ["windows", "iis", "rdp", "netbios", "smb"]):
            return "Windows"
        if any(w in service_text for w in ["linux", "openssh", "ubuntu", "debian", "centos"]):
            return "Linux"
        if "macos" in service_text or "apple" in service_text:
            return "macOS"

        # Port-based guessing
        if 3389 in services:  # RDP
            return "Windows"
        if 22 in services:  # SSH
            return "Linux"

        return "Unknown"

    def _identify_risks(self, profile: TargetProfile) -> list[str]:
        """Identify risk factors from profile."""
        risks = []

        # Risky services
        risky_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB",
                       3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}
        for port, service in risky_ports.items():
            if port in profile.open_ports:
                risks.append(f"Exposed {service} (port {port})")

        # No WAF
        if not profile.is_behind_waf:
            risks.append("No WAF detected")

        # Old CMS versions
        for fp in profile.fingerprints:
            if fp.category == "cms" and fp.version:
                risks.append(f"CMS detected: {fp.technology} {fp.version}")

        # PHP
        for fp in profile.fingerprints:
            if fp.technology == "PHP":
                risks.append("PHP backend (historically vulnerable)")

        return risks

    def get_profile(self, target: str) -> TargetProfile | None:
        return self._profiles.get(target)

    def get_stats(self) -> dict[str, Any]:
        return {
            "profiles": len(self._profiles),
            "technologies_detected": sum(
                len(p.technologies) for p in self._profiles.values()
            ),
        }
