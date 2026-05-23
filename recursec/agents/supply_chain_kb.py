"""Supply chain security knowledge base.

Deep knowledge about supply chain attacks:
1. Dependency confusion and typosquatting
2. CI/CD pipeline attacks
3. Package manager exploitation
4. Build system compromise
5. Third-party code review
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SupplyChainPattern:
    """A supply chain security pattern."""
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


SUPPLY_CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sc-001", "name": "Dependency Confusion",
        "category": "deps", "severity": "critical",
        "desc": "Dependency confusion and typosquatting attacks.",
        "detection": (
            "DEPENDENCY CONFUSION:\n"
            "ATTACK VECTOR:\n"
            "  - Internal package name claimed on public registry\n"
            "  - Higher version number on public registry wins\n"
            "  - Affects: npm, pip, gems, NuGet, Maven\n"
            "  - Attacker publishes malicious package with same name\n"
            "TYPOSQUATTING:\n"
            "  - Register misspelled package names\n"
            "  - lodash → lodahs, lodashs, lodash-utils\n"
            "  - requests → requets, request, python-requests\n"
            "  - Install scripts execute on install\n"
            "DETECTION:\n"
            "  # Check for internal packages on public registries\n"
            "  # npm: npm info <package-name>\n"
            "  # pip: pip index versions <package-name>\n"
            "  # Look for packages installed from unexpected registries\n"
            "  pip list --format=json | jq '.[].name'\n"
            "  npm list --all --json | jq '.dependencies'\n"
            "PREVENTION:\n"
            "  - Scope packages: @company/package\n"
            "  - Pin exact versions with lockfiles\n"
            "  - Use private registry with upstream proxying\n"
            "  - Configure .npmrc, pip.conf, settings.xml\n"
            "TOOLS:\n"
            "  confused  # Dependency confusion scanner\n"
            "  snyk  # Vulnerability database\n"
            "  socket.dev  # Package quality analysis"
        ),
        "tools": ["confused", "snyk"],
    },
    {
        "id": "sc-002", "name": "CI/CD Pipeline Attacks",
        "category": "cicd", "severity": "critical",
        "desc": "CI/CD pipeline exploitation techniques.",
        "detection": (
            "CI/CD PIPELINE ATTACKS:\n"
            "GITHUB ACTIONS:\n"
            "  - Poisoned pipeline execution (PPE)\n"
            "  - workflow_run with pull_request_target\n"
            "  - Secrets in environment variables\n"
            "  - Self-hosted runner compromise\n"
            "  - GITHUB_TOKEN scope abuse\n"
            "  # Check workflow permissions\n"
            "  # Look for: permissions: write-all\n"
            "  # Check for: pull_request_target triggers\n"
            "JENKINS:\n"
            "  - Unauthenticated access (no auth configured)\n"
            "  - Script console: /script\n"
            "  - Credential extraction from /credentials/\n"
            "  - Pipeline-as-code injection\n"
            "  - Plugin vulnerabilities\n"
            "GITLAB CI:\n"
            "  - CI/CD variables exposed in logs\n"
            "  - Protected branch bypass\n"
            "  - Shared runners: Cross-project attacks\n"
            "GENERAL:\n"
            "  - Build artifact poisoning\n"
            "  - Cache poisoning between builds\n"
            "  - Secrets in build logs\n"
            "  - Container image supply chain\n"
            "TOOLS:\n"
            "  poutine  # CI/CD security scanner\n"
            "  legitify  # GitHub/GitLab security posture"
        ),
        "tools": ["poutine", "legitify"],
    },
    {
        "id": "sc-003", "name": "Package Manager Exploitation",
        "category": "packages", "severity": "high",
        "desc": "Package manager security issues.",
        "detection": (
            "PACKAGE MANAGER EXPLOITATION:\n"
            "NPM:\n"
            "  # Install scripts (preinstall, postinstall)\n"
            "  # .npmrc credential leakage\n"
            "  # Unpublished scope claiming\n"
            "  npm audit  # Known vulnerabilities\n"
            "  npm audit --json | jq '.vulnerabilities'\n"
            "PYPI:\n"
            "  # setup.py arbitrary code execution on install\n"
            "  # Wheel vs sdist security differences\n"
            "  pip-audit  # Python dependency audit\n"
            "  safety check  # Check for known vulns\n"
            "RUBYGEMS:\n"
            "  # gem install runs extconf.rb\n"
            "  bundle-audit check\n"
            "MAVEN/GRADLE:\n"
            "  # Build plugin code execution\n"
            "  # Repository impersonation\n"
            "  mvn dependency:tree  # Analyze dependencies\n"
            "CONTAINER IMAGES:\n"
            "  # Base image vulnerabilities\n"
            "  trivy image <image>  # Scan container\n"
            "  grype <image>  # Alternative scanner\n"
            "  # Layer analysis\n"
            "  dive <image>  # Explore layers\n"
            "SBOMs:\n"
            "  # Generate Software Bill of Materials\n"
            "  syft <image> -o cyclonedx-json\n"
            "  # Analyze SBOM for vulnerabilities\n"
            "  grype sbom:sbom.json"
        ),
        "tools": ["trivy", "grype", "pip-audit"],
    },
    {
        "id": "sc-004", "name": "Build System Compromise",
        "category": "build", "severity": "critical",
        "desc": "Build system and artifact integrity attacks.",
        "detection": (
            "BUILD SYSTEM COMPROMISE:\n"
            "REPRODUCIBLE BUILDS:\n"
            "  - Verify build output matches source\n"
            "  - Compare hashes across build environments\n"
            "  - Detect injected code during build\n"
            "SIGNING AND VERIFICATION:\n"
            "  # GPG signing\n"
            "  gpg --verify package.tar.gz.sig package.tar.gz\n"
            "  # Sigstore/cosign (container signing)\n"
            "  cosign verify --key cosign.pub <image>\n"
            "  # npm package provenance\n"
            "  npm audit signatures\n"
            "SUPPLY CHAIN LEVELS (SLSA):\n"
            "  - L0: No guarantees\n"
            "  - L1: Build process documented\n"
            "  - L2: Hosted build, signed provenance\n"
            "  - L3: Hardened build, non-falsifiable provenance\n"
            "  - L4: Two-party review, hermetic builds\n"
            "ARTIFACT INTEGRITY:\n"
            "  - Check package checksums\n"
            "  - Verify download sources\n"
            "  - Use lockfiles (package-lock.json, Pipfile.lock)\n"
            "  - Pin dependencies by hash\n"
            "  # pip install --require-hashes -r requirements.txt\n"
            "ATTACKS:\n"
            "  - SolarWinds-style build injection\n"
            "  - Codecov bash uploader compromise\n"
            "  - Event-Stream npm incident\n"
            "  - ua-parser-js npm hijack"
        ),
        "tools": ["cosign", "slsa-verifier"],
    },
    {
        "id": "sc-005", "name": "Third-Party Code Review",
        "category": "review", "severity": "high",
        "desc": "Reviewing third-party code for security.",
        "detection": (
            "THIRD-PARTY CODE REVIEW:\n"
            "AUTOMATED ANALYSIS:\n"
            "  # Static analysis of dependencies\n"
            "  semgrep --config p/supply-chain .\n"
            "  # Check for suspicious patterns\n"
            "  - eval(), exec(), Function() calls\n"
            "  - Network requests in install scripts\n"
            "  - File system access outside package dir\n"
            "  - Obfuscated code (base64, hex encoding)\n"
            "  - Environment variable exfiltration\n"
            "MANUAL CHECKS:\n"
            "  - Review recent version changes\n"
            "  - Check maintainer changes (npm owner ls)\n"
            "  - Verify GitHub repo matches published package\n"
            "  - Compare package size across versions\n"
            "  - Read install/post-install scripts\n"
            "RED FLAGS:\n"
            "  - New maintainer on popular package\n"
            "  - Sudden version bump with minimal changes\n"
            "  - Install scripts making network requests\n"
            "  - Obfuscated or minified source in package\n"
            "  - Reading environment variables or SSH keys\n"
            "  - Spawning child processes\n"
            "MONITORING:\n"
            "  socket.dev  # Real-time package analysis\n"
            "  deps.dev  # Google dependency insights\n"
            "  snyk.io  # Continuous monitoring"
        ),
        "tools": ["semgrep", "socket"],
    },
]


class SupplyChainKB:
    """Supply chain security knowledge base.

    Provides supply chain attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SupplyChainPattern] = {}
        self._log = logger.bind(component="supply_chain_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load supply chain patterns."""
        for data in SUPPLY_CHAIN_PATTERNS:
            pattern = SupplyChainPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[SupplyChainPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_supply_chain_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build supply chain security prompt."""
        lines = ["## Supply Chain Security Patterns\n"]
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
