"""Supply chain security knowledge base.

Deep knowledge about software supply chain security:
1. Dependency confusion attacks
2. Build pipeline security
3. Package manager attacks
4. Software composition analysis
5. SBOM and provenance
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
        "category": "dependency", "severity": "critical",
        "desc": "Dependency confusion and substitution attacks.",
        "detection": (
            "DEPENDENCY CONFUSION ATTACKS:\n"
            "CONCEPT:\n"
            "  - Private package name registered on public registry\n"
            "  - Build system pulls public (malicious) over private\n"
            "  - Affects: npm, PyPI, RubyGems, NuGet, Maven\n"
            "  - Alex Birsan research (2021): compromised Apple, MS, etc.\n"
            "ATTACK VECTORS:\n"
            "  npm:\n"
            "    - Register internal package name on npmjs.com\n"
            "    - Higher version number wins\n"
            "    - .npmrc scoping misconfiguration\n"
            "  PyPI:\n"
            "    - Register internal package on pypi.org\n"
            "    - pip installs from PyPI by default\n"
            "    - --extra-index-url adds PyPI as fallback\n"
            "  RubyGems:\n"
            "    - Register on rubygems.org\n"
            "    - Bundler gem source priority\n"
            "DETECTION:\n"
            "  - Audit registry for internal package names\n"
            "  - Monitor new packages matching internal names\n"
            "  - Lock file verification\n"
            "  - Scoped registries (@company/ in npm)\n"
            "PREVENTION:\n"
            "  - Namespace all internal packages\n"
            "  - Pin exact versions in lock files\n"
            "  - Use private registries (Artifactory, Nexus)\n"
            "  - Reserve names on public registries\n"
            "TOOLS:\n"
            "  confused (detection), safety, snyk"
        ),
        "tools": ["confused", "snyk"],
    },
    {
        "id": "sc-002", "name": "Build Pipeline Security",
        "category": "pipeline", "severity": "critical",
        "desc": "CI/CD pipeline security and attacks.",
        "detection": (
            "BUILD PIPELINE SECURITY:\n"
            "ATTACK SURFACES:\n"
            "  - Source code repo (commit injection)\n"
            "  - Build system (Jenkins, GitHub Actions)\n"
            "  - Artifact registry (Docker Hub, npm)\n"
            "  - Deployment pipeline\n"
            "  - Infrastructure-as-Code\n"
            "CI/CD ATTACKS:\n"
            "  - Poisoned Pipeline Execution (PPE)\n"
            "    Direct PPE: Modify CI config in PR\n"
            "    Indirect PPE: Modify called scripts\n"
            "  - Secret extraction from CI env\n"
            "  - Self-hosted runner compromise\n"
            "  - Dependency cache poisoning\n"
            "  - Build artifact tampering\n"
            "GITHUB ACTIONS:\n"
            "  - pull_request_target event abuse\n"
            "  - Workflow injection (untrusted input in run)\n"
            "  - Action pinning (use SHA not tag)\n"
            "  - GITHUB_TOKEN permission abuse\n"
            "  - Third-party action supply chain\n"
            "DETECTION:\n"
            "  - Review workflow files in PRs\n"
            "  - Audit secret access\n"
            "  - Build reproducibility checks\n"
            "  - SLSA provenance verification\n"
            "TOOLS:\n"
            "  step-security/harden-runner, zizmor, scorecard"
        ),
        "tools": ["scorecard"],
    },
    {
        "id": "sc-003", "name": "Package Manager Attacks",
        "category": "packages", "severity": "critical",
        "desc": "Package manager attack techniques.",
        "detection": (
            "PACKAGE MANAGER ATTACKS:\n"
            "TYPOSQUATTING:\n"
            "  - Register similar-name packages\n"
            "  - Examples: lodash → 1odash, faker → f4ker\n"
            "  - Automated mass registration\n"
            "  - Target popular packages\n"
            "MALICIOUS PACKAGES:\n"
            "  - Install scripts (postinstall in npm)\n"
            "  - setup.py code execution\n"
            "  - Data exfiltration (env vars, SSH keys)\n"
            "  - Cryptominer injection\n"
            "  - Reverse shell in package\n"
            "ACCOUNT TAKEOVER:\n"
            "  - Maintainer account compromise\n"
            "  - Credential reuse (breached passwords)\n"
            "  - Social engineering maintainers\n"
            "  - Abandoned package takeover\n"
            "  - event-stream incident (2018)\n"
            "STAR JACKING:\n"
            "  - Fork popular repo\n"
            "  - Transfer stars (GitHub)\n"
            "  - Create package pointing to fork\n"
            "  - Users trust star count\n"
            "DETECTION:\n"
            "  - Lock file auditing (npm audit, pip-audit)\n"
            "  - New dependency review in PRs\n"
            "  - Socket.dev (npm supply chain)\n"
            "  - Phylum (automated detection)\n"
            "TOOLS:\n"
            "  npm audit, pip-audit, Socket.dev, Phylum"
        ),
        "tools": ["npm-audit", "pip-audit"],
    },
    {
        "id": "sc-004", "name": "Software Composition",
        "category": "sca", "severity": "high",
        "desc": "Software composition analysis.",
        "detection": (
            "SOFTWARE COMPOSITION ANALYSIS:\n"
            "VULNERABILITY SCANNING:\n"
            "  # Known vulnerabilities in dependencies\n"
            "  trivy fs --scanners vuln .  # Aqua Trivy\n"
            "  grype .  # Anchore Grype\n"
            "  snyk test  # Snyk\n"
            "  npm audit  # npm built-in\n"
            "  pip-audit  # Python\n"
            "  cargo audit  # Rust\n"
            "LICENSE COMPLIANCE:\n"
            "  - Identify all dependency licenses\n"
            "  - Check compatibility (GPL, AGPL, MIT)\n"
            "  - License conflict detection\n"
            "  - FOSSA, SPDX tools\n"
            "DEPENDENCY GRAPH:\n"
            "  - Transitive dependency analysis\n"
            "  - Phantom dependencies\n"
            "  - Version conflict resolution\n"
            "  - Dependency tree visualization\n"
            "AUTOMATION:\n"
            "  - Dependabot / Renovate (auto-update)\n"
            "  - CI pipeline integration\n"
            "  - Policy-as-code (OPA)\n"
            "  - Break build on critical CVE\n"
            "  - Merge queue with security gates\n"
            "TOOLS:\n"
            "  Trivy, Grype, Snyk, OWASP Dep-Check, Dependabot"
        ),
        "tools": ["trivy", "grype", "snyk"],
    },
    {
        "id": "sc-005", "name": "SBOM and Provenance",
        "category": "sbom", "severity": "medium",
        "desc": "SBOM generation and provenance verification.",
        "detection": (
            "SBOM AND PROVENANCE:\n"
            "SBOM FORMATS:\n"
            "  - SPDX (ISO standard)\n"
            "  - CycloneDX (OWASP)\n"
            "  - SWID tags\n"
            "GENERATION:\n"
            "  # CycloneDX\n"
            "  cyclonedx-bom -o bom.json  # Python\n"
            "  npx @cyclonedx/cyclonedx-npm -o bom.json  # npm\n"
            "  # SPDX\n"
            "  syft . -o spdx-json > sbom.spdx.json  # Syft\n"
            "  # Trivy\n"
            "  trivy fs --format cyclonedx .  # Multi-format\n"
            "PROVENANCE:\n"
            "  SLSA (Supply-chain Levels for Software Artifacts)\n"
            "  - Level 1: Documentation of build process\n"
            "  - Level 2: Hosted source/build, signed provenance\n"
            "  - Level 3: Hardened builds, unforgeable provenance\n"
            "  - Level 4: Two-person reviewed, hermetic builds\n"
            "SIGSTORE:\n"
            "  - Cosign (container signing)\n"
            "  - Rekor (transparency log)\n"
            "  - Fulcio (certificate authority)\n"
            "  cosign sign --key cosign.key image:tag\n"
            "  cosign verify --key cosign.pub image:tag\n"
            "TOOLS:\n"
            "  Syft, Grype, Cosign, SLSA verifier"
        ),
        "tools": ["syft", "cosign"],
    },
]


class SupplyChainKB:
    """Supply chain security knowledge base.

    Provides supply chain attack/defense patterns
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
