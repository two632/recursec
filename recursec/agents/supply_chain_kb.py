"""Supply chain attack knowledge base.

Deep knowledge about software supply chain attacks:
1. Dependency confusion attacks
2. Typosquatting detection
3. Malicious package patterns
4. Build pipeline poisoning
5. Source code integrity verification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SupplyChainPattern:
    """A supply chain attack pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


SUPPLY_CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sc-001", "name": "Dependency Confusion",
        "category": "dependency", "severity": "critical",
        "desc": "Internal package name hijacking via public registries.",
        "detection": (
            "DEPENDENCY CONFUSION ATTACKS:\n"
            "HOW IT WORKS:\n"
            "  1. Attacker discovers internal package names (via error messages, docs, source)\n"
            "  2. Registers same name on public registry (npm, PyPI, RubyGems)\n"
            "  3. Public version has higher version number\n"
            "  4. Build system prefers public package → executes attacker code\n"
            "DETECTION:\n"
            "  - Check for packages that exist on both public and private registries\n"
            "  - Verify package source in lock files (package-lock.json, yarn.lock, Pipfile.lock)\n"
            "  - Search for internal-looking package names on public registries\n"
            "  - Monitor for unexpected network connections during build\n"
            "PREVENTION:\n"
            "  - Use scoped packages (@company/package-name)\n"
            "  - Pin exact versions in lock files\n"
            "  - Configure registry priority (private > public)\n"
            "  - Use .npmrc/pip.conf to restrict sources\n"
            "  - Pre-register internal names on public registries\n"
            "TESTING:\n"
            "  - Extract package names from package.json/requirements.txt\n"
            "  - Check each against public registries\n"
            "  - Flag any unscoped internal packages"
        ),
        "indicators": ["unscoped_internal_packages", "mixed_registry_sources", "version_mismatch"],
        "tools": ["npm audit", "pip audit", "confused"],
    },
    {
        "id": "sc-002", "name": "Typosquatting",
        "category": "dependency", "severity": "high",
        "desc": "Malicious packages with similar names to popular ones.",
        "detection": (
            "TYPOSQUATTING DETECTION:\n"
            "COMMON PATTERNS:\n"
            "  - Character substitution: lodash → 1odash, lodassh\n"
            "  - Separator changes: vue-router → vue.router, vuerouter\n"
            "  - Scope confusion: @types/node → types-node\n"
            "  - Extra/missing characters: express → expresss, expres\n"
            "INDICATORS OF MALICIOUS PACKAGES:\n"
            "  - Very recent publish date with few downloads\n"
            "  - Install scripts (preinstall, postinstall) that execute code\n"
            "  - Network calls during installation\n"
            "  - Environment variable exfiltration\n"
            "  - Base64 encoded payloads\n"
            "DETECTION TOOLS:\n"
            "  - npm: socket.dev, snyk\n"
            "  - PyPI: pip audit, safety\n"
            "  - Calculate Levenshtein distance to popular packages\n"
            "TESTING:\n"
            "  - Review all dependencies for suspicious names\n"
            "  - Check publish history and maintainer reputation\n"
            "  - Inspect install scripts for network activity\n"
            "  - Verify package checksums match expected"
        ),
        "indicators": ["similar_name_popular_package", "recent_publish", "install_scripts"],
        "tools": ["socket.dev", "snyk", "pip audit", "safety"],
    },
    {
        "id": "sc-003", "name": "CI/CD Pipeline Poisoning",
        "category": "build", "severity": "critical",
        "desc": "Attacks targeting build/deployment pipelines.",
        "detection": (
            "CI/CD PIPELINE ATTACKS:\n"
            "ATTACK VECTORS:\n"
            "  1. Compromised build dependencies (SolarWinds-style)\n"
            "  2. Malicious PR that modifies CI config (yaml injection)\n"
            "  3. Poisoned base images in container builds\n"
            "  4. Stolen CI/CD secrets (tokens, keys)\n"
            "  5. Build cache poisoning\n"
            "  6. Runner compromise via escape\n"
            "GITHUB ACTIONS SPECIFIC:\n"
            "  - Untrusted workflow_run triggers\n"
            "  - actions/checkout with persist-credentials: true\n"
            "  - Script injection via github.event.* in run:\n"
            "  - GITHUB_TOKEN with excessive permissions\n"
            "  - Third-party actions without pinned SHA\n"
            "DETECTION:\n"
            "  - Review CI/CD configurations for injection points\n"
            "  - Audit secret access patterns\n"
            "  - Verify build artifact integrity (SLSA provenance)\n"
            "  - Check for unpinned actions/dependencies in CI\n"
            "  - Monitor for unusual build times or outputs\n"
            "TESTING:\n"
            "  - Review .github/workflows/*.yml\n"
            "  - Check Jenkinsfile, .gitlab-ci.yml, bitbucket-pipelines.yml\n"
            "  - Audit Dockerfile for untrusted base images\n"
            "  - Verify build reproducibility"
        ),
        "indicators": ["unpinned_actions", "script_injection", "excessive_token_perms"],
        "tools": ["semgrep", "trivy", "step-security/harden-runner"],
    },
    {
        "id": "sc-004", "name": "Malicious Package Patterns",
        "category": "dependency", "severity": "critical",
        "desc": "Common patterns in malicious packages.",
        "detection": (
            "MALICIOUS PACKAGE INDICATORS:\n"
            "CODE PATTERNS:\n"
            "  - eval(Buffer.from('...', 'base64').toString())\n"
            "  - Dynamic require/import with obfuscated paths\n"
            "  - Network calls in postinstall scripts\n"
            "  - process.env exfiltration\n"
            "  - Reading ~/.ssh/*, ~/.aws/*, browser profiles\n"
            "  - Cryptocurrency wallet file access\n"
            "  - DNS/HTTP exfiltration of gathered data\n"
            "METADATA RED FLAGS:\n"
            "  - Single maintainer, no GitHub repo link\n"
            "  - Package published within last 30 days\n"
            "  - Very few downloads but claimed to be popular\n"
            "  - README copied from legitimate package\n"
            "  - Excessive permissions requested\n"
            "DETECTION APPROACH:\n"
            "  1. Static analysis of install scripts\n"
            "  2. Behavioral analysis in sandbox\n"
            "  3. Network monitoring during install\n"
            "  4. Comparison with known malicious patterns\n"
            "  5. Entropy analysis for obfuscation detection"
        ),
        "indicators": ["base64_eval", "postinstall_network", "env_exfil", "credential_access"],
        "tools": ["socket.dev", "snyk", "npm audit", "trufflehog"],
    },
    {
        "id": "sc-005", "name": "Container Image Supply Chain",
        "category": "container", "severity": "high",
        "desc": "Container image supply chain attacks.",
        "detection": (
            "CONTAINER IMAGE SUPPLY CHAIN:\n"
            "ATTACK VECTORS:\n"
            "  1. Malicious base images on Docker Hub\n"
            "  2. Compromised build layers\n"
            "  3. Stale images with unpatched CVEs\n"
            "  4. Image tag mutability (tag rewriting)\n"
            "  5. Registry credential theft\n"
            "DETECTION:\n"
            "  - Scan images with trivy/grype for CVEs\n"
            "  - Verify image signatures (cosign, Notary)\n"
            "  - Check base image provenance\n"
            "  - Use digest pinning instead of tag references\n"
            "  - Review Dockerfile for ADD from external URLs\n"
            "BEST PRACTICES:\n"
            "  - Use minimal base images (distroless, alpine)\n"
            "  - Multi-stage builds to reduce attack surface\n"
            "  - Image signing and verification\n"
            "  - Regular image rebuilds with updated dependencies\n"
            "  - SBOM generation (syft, cyclonedx)\n"
            "TESTING:\n"
            "  - trivy image <image-name>\n"
            "  - grype <image-name>\n"
            "  - cosign verify <image-name>\n"
            "  - Check for secrets in image layers"
        ),
        "indicators": ["unverified_base_image", "stale_image", "mutable_tags"],
        "tools": ["trivy", "grype", "cosign", "syft"],
    },
]


class SupplyChainKB:
    """Supply chain attack knowledge base.

    Provides supply chain attack detection patterns
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
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                indicators=data.get("indicators", []),
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
        """Build supply chain attack prompt."""
        lines = ["## Supply Chain Attack Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
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
