"""Supply chain security knowledge base.

Deep knowledge about supply chain security:
1. Software supply chain attacks
2. Dependency security
3. Build pipeline security
4. Code signing and integrity
5. Third-party risk management
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


SC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sc-001", "name": "Software Supply Chain Attacks",
        "category": "attack", "severity": "critical",
        "desc": "Software supply chain attack vectors.",
        "detection": (
            "SOFTWARE SUPPLY CHAIN ATTACKS:\n"
            "ATTACK VECTORS:\n"
            "  DEPENDENCY CONFUSION:\n"
            "    - Internal package name registered on public registry\n"
            "    - Higher version on public registry\n"
            "    - pip, npm, maven, nuget vulnerable\n"
            "    - Detection: audit registry configs\n"
            "  TYPOSQUATTING:\n"
            "    - Package names similar to popular packages\n"
            "    - lodash vs lodash-es vs l0dash\n"
            "    - Detection: package name similarity analysis\n"
            "  MALICIOUS UPDATES:\n"
            "    - Maintainer account compromise\n"
            "    - SolarWinds (SUNBURST)\n"
            "    - event-stream incident (npm)\n"
            "    - ua-parser-js incident\n"
            "    - Detection: behavioral analysis of updates\n"
            "  BUILD SYSTEM COMPROMISE:\n"
            "    - CI/CD pipeline injection\n"
            "    - Compromised build tools\n"
            "    - Codecov breach (CI secrets)\n"
            "    - GitHub Actions supply chain\n"
            "  SOURCE CODE COMPROMISE:\n"
            "    - Repository access (SSH keys)\n"
            "    - Git commit signing bypass\n"
            "    - Pull request manipulation\n"
            "NOTABLE INCIDENTS:\n"
            "  - SolarWinds (2020): Build system backdoor\n"
            "  - Kaseya (2021): Software update abuse\n"
            "  - Log4Shell (2021): Ubiquitous dependency\n"
            "  - XZ Utils (2024): Long-term maintainer social eng\n"
            "TOOLS:\n"
            "  Snyk, Socket, Semgrep Supply Chain"
        ),
        "tools": ["snyk"],
    },
    {
        "id": "sc-002", "name": "Dependency Security",
        "category": "dependency", "severity": "high",
        "desc": "Dependency security auditing.",
        "detection": (
            "DEPENDENCY SECURITY:\n"
            "AUDITING:\n"
            "  # npm\n"
            "  npm audit\n"
            "  npm audit --production\n"
            "  # pip\n"
            "  pip-audit\n"
            "  safety check\n"
            "  # Go\n"
            "  govulncheck ./...\n"
            "  # Rust\n"
            "  cargo audit\n"
            "  # Ruby\n"
            "  bundle-audit\n"
            "  # Java\n"
            "  mvn dependency-check:check\n"
            "SCA TOOLS:\n"
            "  - Snyk (SCA + SAST)\n"
            "  - Trivy (containers + fs)\n"
            "  - Grype (SBOM-based)\n"
            "  - OWASP Dependency-Check\n"
            "  - Renovate/Dependabot (auto-update)\n"
            "SBOM:\n"
            "  # Software Bill of Materials\n"
            "  # CycloneDX format\n"
            "  cdxgen -o bom.json\n"
            "  # SPDX format\n"
            "  syft packages dir:. -o spdx-json > sbom.json\n"
            "  # Analyze SBOM\n"
            "  grype sbom:./bom.json\n"
            "CHECKS:\n"
            "  - Known vulnerabilities (CVE)\n"
            "  - License compliance\n"
            "  - Maintainer reputation\n"
            "  - Dependency depth\n"
            "  - Update frequency\n"
            "TOOLS:\n"
            "  Snyk, Trivy, Grype, pip-audit, npm-audit"
        ),
        "tools": ["snyk", "trivy", "grype"],
    },
    {
        "id": "sc-003", "name": "Build Pipeline Security",
        "category": "build", "severity": "critical",
        "desc": "CI/CD pipeline security.",
        "detection": (
            "BUILD PIPELINE SECURITY:\n"
            "CI/CD RISKS:\n"
            "  - Secret exposure in logs\n"
            "  - Insufficient access controls\n"
            "  - Unverified dependencies during build\n"
            "  - Mutable build inputs\n"
            "  - Shared runners (cross-tenant)\n"
            "  - Pull request trigger abuse\n"
            "GITHUB ACTIONS:\n"
            "  - Workflow injection (expression injection)\n"
            "  - Third-party action supply chain\n"
            "  - GITHUB_TOKEN permissions\n"
            "  - Self-hosted runner escape\n"
            "  - Artifact poisoning\n"
            "  # Pin actions to SHA\n"
            "  # uses: actions/checkout@<sha>\n"
            "GITLAB CI:\n"
            "  - Include: remote injection\n"
            "  - Protected branches bypass\n"
            "  - Variable masking gaps\n"
            "  - Shared runner isolation\n"
            "JENKINS:\n"
            "  - Script console access\n"
            "  - Pipeline sandbox escape\n"
            "  - Credential exposure\n"
            "  - Plugin vulnerabilities\n"
            "SLSA:\n"
            "  - Supply-chain Levels for Software Artifacts\n"
            "  - Level 1: Documented build\n"
            "  - Level 2: Hosted source/build\n"
            "  - Level 3: Hardened builds\n"
            "  - Level 4: Two-person review\n"
            "TOOLS:\n"
            "  SLSA verifier, Sigstore, StepSecurity"
        ),
        "tools": ["sigstore"],
    },
    {
        "id": "sc-004", "name": "Code Signing and Integrity",
        "category": "signing", "severity": "high",
        "desc": "Code signing and artifact integrity.",
        "detection": (
            "CODE SIGNING AND INTEGRITY:\n"
            "SIGSTORE:\n"
            "  - Cosign: container image signing\n"
            "  - Fulcio: certificate authority\n"
            "  - Rekor: transparency log\n"
            "  # Sign container image\n"
            "  cosign sign --key cosign.key IMAGE\n"
            "  # Verify\n"
            "  cosign verify --key cosign.pub IMAGE\n"
            "  # Keyless signing (OIDC)\n"
            "  cosign sign IMAGE  # uses Fulcio\n"
            "GPG:\n"
            "  # Sign git commits\n"
            "  git config commit.gpgsign true\n"
            "  # Verify signed commits\n"
            "  git log --show-signature\n"
            "  # Package signing\n"
            "  gpg --sign package.tar.gz\n"
            "ARTIFACT INTEGRITY:\n"
            "  - SHA-256 checksums\n"
            "  - Reproducible builds\n"
            "  - Binary transparency\n"
            "  - Provenance attestation\n"
            "ATTESTATION:\n"
            "  - in-toto: supply chain attestation\n"
            "  - SLSA provenance\n"
            "  - Notary v2 (container trust)\n"
            "  - npm provenance\n"
            "TOOLS:\n"
            "  Cosign, GPG, in-toto, Notary, Witness"
        ),
        "tools": ["cosign"],
    },
    {
        "id": "sc-005", "name": "Third-Party Risk",
        "category": "third_party", "severity": "high",
        "desc": "Third-party risk management.",
        "detection": (
            "THIRD-PARTY RISK:\n"
            "ASSESSMENT:\n"
            "  - Vendor security questionnaire\n"
            "  - SOC 2 report review\n"
            "  - Penetration test results\n"
            "  - Data processing agreements\n"
            "  - Incident response capabilities\n"
            "  - Business continuity plans\n"
            "MONITORING:\n"
            "  - Continuous security monitoring\n"
            "  - Breach notification tracking\n"
            "  - External attack surface\n"
            "  - Dark web monitoring\n"
            "  - Certificate transparency\n"
            "OPEN SOURCE RISK:\n"
            "  - Maintainer bus factor\n"
            "  - Project activity/health\n"
            "  - Security disclosure process\n"
            "  - License compatibility\n"
            "  - Known vulnerability history\n"
            "  - Dependency depth analysis\n"
            "METRICS:\n"
            "  - OpenSSF Scorecard\n"
            "  # scorecard --repo=github.com/owner/repo\n"
            "  - OSSF Criticality Score\n"
            "  - deps.dev dependency insights\n"
            "  - Security response time\n"
            "API SECURITY:\n"
            "  - API key management\n"
            "  - Rate limiting\n"
            "  - Data minimization\n"
            "  - Access scope review\n"
            "TOOLS:\n"
            "  OpenSSF Scorecard, deps.dev, Socket"
        ),
        "tools": [],
    },
]


class SupplyChainKB:
    """Supply chain security knowledge base.

    Provides supply chain security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SupplyChainPattern] = {}
        self._log = logger.bind(component="supply_chain_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load supply chain patterns."""
        for data in SC_PATTERNS:
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
