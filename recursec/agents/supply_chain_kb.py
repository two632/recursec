"""Supply chain attack knowledge base.

Deep knowledge about supply chain attacks:
1. Dependency confusion and typosquatting
2. CI/CD pipeline attacks
3. Package manager exploitation
4. Build system compromise
5. Third-party risk assessment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SupplyChainPattern:
    """A supply chain pattern."""
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


SUPPLYCHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sc-001", "name": "Dependency Confusion",
        "category": "dependency", "severity": "critical",
        "desc": "Dependency confusion and typosquatting.",
        "detection": (
            "DEPENDENCY CONFUSION:\n"
            "ATTACK:\n"
            "  - Private package name discovery\n"
            "    # package.json, requirements.txt\n"
            "    # Internal documentation\n"
            "    # Error messages\n"
            "    # JavaScript source maps\n"
            "  - Register public package with same name\n"
            "  - Higher version number = priority\n"
            "  - Preinstall/postinstall scripts\n"
            "TYPOSQUATTING:\n"
            "  - Common misspellings\n"
            "  - Hyphen/underscore swaps\n"
            "  - Scope confusion (@org/pkg)\n"
            "  - Similar-looking characters\n"
            "  # Examples:\n"
            "  # lodash → lodahs, loadash\n"
            "  # requests → requets, request\n"
            "DETECTION:\n"
            "  - Socket.dev (supply chain firewall)\n"
            "  - npm audit, pip audit\n"
            "  - Lockfile review\n"
            "  - Private registry configuration\n"
            "  - .npmrc scoped registries\n"
            "  - pip --index-url (pin registry)\n"
            "PREVENTION:\n"
            "  - Private registry (Nexus, Artifactory)\n"
            "  - Scoped packages (@company/)\n"
            "  - Lockfile pinning\n"
            "  - Integrity checks (SRI)\n"
            "TOOLS:\n"
            "  confused (tool), Socket.dev, Snyk"
        ),
        "tools": [],
    },
    {
        "id": "sc-002", "name": "CI/CD Pipeline Attacks",
        "category": "cicd", "severity": "critical",
        "desc": "CI/CD pipeline exploitation.",
        "detection": (
            "CI/CD PIPELINE ATTACKS:\n"
            "SECRETS:\n"
            "  - Exposed CI/CD secrets\n"
            "  - Environment variable leaks\n"
            "  - Build log secrets\n"
            "  - Secret in artifact\n"
            "  - GitHub Actions secrets\n"
            "  - Jenkins credential store\n"
            "CODE INJECTION:\n"
            "  - PR-triggered pipelines\n"
            "  - Workflow injection via branch name\n"
            "  - Commit message injection\n"
            "  - PR title/body injection\n"
            "  - GitHub Actions expression injection\n"
            "    ${{ github.event.pull_request.title }}\n"
            "  - Poisoned pipeline execution (PPE)\n"
            "CONFIGURATION:\n"
            "  - Self-hosted runner compromise\n"
            "  - Shared runner data leakage\n"
            "  - Insufficient branch protection\n"
            "  - Missing approval requirements\n"
            "  - Over-privileged service accounts\n"
            "ARTIFACTS:\n"
            "  - Build artifact tampering\n"
            "  - Docker image tag mutability\n"
            "  - Unsigned releases\n"
            "  - Missing SBOM\n"
            "  - Reproducible builds failure\n"
            "TOOLS:\n"
            "  CICD-Goat, Gitleaks, TruffleHog"
        ),
        "tools": ["gitleaks"],
    },
    {
        "id": "sc-003", "name": "Package Manager Exploitation",
        "category": "packages", "severity": "high",
        "desc": "Package manager exploitation.",
        "detection": (
            "PACKAGE MANAGER EXPLOITATION:\n"
            "NPM:\n"
            "  - Install scripts (preinstall/postinstall)\n"
            "  - Scope confusion\n"
            "  - npm cache poisoning\n"
            "  - package-lock.json manipulation\n"
            "  - Lifecycle script execution\n"
            "  # npm audit\n"
            "  # npm pack --dry-run (inspect contents)\n"
            "PYPI:\n"
            "  - setup.py code execution\n"
            "  - Wheel vs sdist security\n"
            "  - requirements.txt pinning\n"
            "  - Namespace confusion\n"
            "  # pip audit\n"
            "  # safety check\n"
            "MAVEN/GRADLE:\n"
            "  - Repository confusion\n"
            "  - Plugin injection\n"
            "  - Build file manipulation\n"
            "  - Dependency mediation abuse\n"
            "RUBYGEMS:\n"
            "  - Gem install scripts\n"
            "  - Extension compilation\n"
            "  - Gemfile.lock manipulation\n"
            "CARGO:\n"
            "  - build.rs execution\n"
            "  - Proc macro code execution\n"
            "  - Feature flag abuse\n"
            "GO:\n"
            "  - Module proxy cache\n"
            "  - Replace directives\n"
            "  - Vanity import paths\n"
            "GENERAL:\n"
            "  - Maintainer account takeover\n"
            "  - Star/download manipulation\n"
            "  - Malicious updates (supply chain)\n"
            "TOOLS:\n"
            "  npm audit, pip audit, Snyk, Dependabot"
        ),
        "tools": [],
    },
    {
        "id": "sc-004", "name": "Build System Compromise",
        "category": "build", "severity": "critical",
        "desc": "Build system compromise.",
        "detection": (
            "BUILD SYSTEM COMPROMISE:\n"
            "COMPILER:\n"
            "  - Compiler backdoor (Ken Thompson)\n"
            "  - Compiler flag manipulation\n"
            "  - Optimization-based vulnerabilities\n"
            "  - Undefined behavior exploitation\n"
            "BUILD TOOLS:\n"
            "  - Makefile injection\n"
            "  - CMake script execution\n"
            "  - Gradle plugin backdoor\n"
            "  - webpack/rollup plugin compromise\n"
            "  - Babel transform injection\n"
            "CONTAINER:\n"
            "  - Base image compromise\n"
            "  - Multi-stage build leakage\n"
            "  - BuildKit cache poisoning\n"
            "  - Registry confusion\n"
            "INFRASTRUCTURE:\n"
            "  - Build server compromise\n"
            "  - Shared build caches\n"
            "  - Build farm lateral movement\n"
            "  - Artifact repository tampering\n"
            "SIGNING:\n"
            "  - Code signing key theft\n"
            "  - Sigstore/cosign bypass\n"
            "  - Certificate authority compromise\n"
            "  - Timestamp manipulation\n"
            "SLSA FRAMEWORK:\n"
            "  Level 1: Documentation\n"
            "  Level 2: Hosted build + signed provenance\n"
            "  Level 3: Hardened build platform\n"
            "  Level 4: Two-person review + hermetic\n"
            "TOOLS:\n"
            "  SLSA verifier, cosign, in-toto"
        ),
        "tools": [],
    },
    {
        "id": "sc-005", "name": "Third-Party Risk Assessment",
        "category": "third_party", "severity": "high",
        "desc": "Third-party risk assessment.",
        "detection": (
            "THIRD-PARTY RISK:\n"
            "SCA (Software Composition Analysis):\n"
            "  - Dependency vulnerability scanning\n"
            "  # Snyk, Dependabot, Renovate\n"
            "  # OWASP Dependency-Check\n"
            "  # Trivy (container + code)\n"
            "  - License compliance\n"
            "  - End-of-life component detection\n"
            "  - Transitive dependency analysis\n"
            "SBOM:\n"
            "  - Software Bill of Materials\n"
            "  # SPDX format\n"
            "  # CycloneDX format\n"
            "  # syft (generate SBOM)\n"
            "  syft packages dir:./\n"
            "  # grype (scan SBOM for vulns)\n"
            "  grype sbom:./sbom.json\n"
            "VENDOR:\n"
            "  - Security questionnaires\n"
            "  - SOC 2 report review\n"
            "  - Pentest report review\n"
            "  - SLA and incident response\n"
            "  - Data handling practices\n"
            "  - Subprocessor review\n"
            "API DEPENDENCIES:\n"
            "  - API key exposure\n"
            "  - Rate limit assessment\n"
            "  - Data handling in transit\n"
            "  - API deprecation monitoring\n"
            "  - Fallback for API failure\n"
            "MONITORING:\n"
            "  - CVE monitoring for dependencies\n"
            "  - Automated dependency updates\n"
            "  - Breaking change detection\n"
            "  - Runtime dependency monitoring\n"
            "TOOLS:\n"
            "  Snyk, Trivy, syft, grype, Dependabot"
        ),
        "tools": ["trivy", "snyk"],
    },
]


class SupplyChainKB:
    """Supply chain attack knowledge base.

    Provides supply chain patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SupplyChainPattern] = {}
        self._log = logger.bind(component="supplychain_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load supply chain patterns."""
        for data in SUPPLYCHAIN_PATTERNS:
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

    def build_supplychain_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build supply chain prompt."""
        lines = ["## Supply Chain Security\n"]
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
