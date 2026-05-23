"""Supply chain security knowledge base.

Deep knowledge about supply chain attacks:
1. Dependency confusion
2. Typosquatting
3. Build pipeline poisoning
4. Open source library compromise
5. Container image attacks
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
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
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
        "desc": "Exploiting private vs public package name conflicts.",
        "detection": (
            "DEPENDENCY CONFUSION:\n"
            "ATTACK MECHANISM:\n"
            "  - Organization uses private packages (e.g., @company/utils)\n"
            "  - Attacker publishes public package with same name\n"
            "  - Package manager prefers higher version from public registry\n"
            "  - Attacker's malicious package gets installed\n"
            "DETECTION:\n"
            "  1. Enumerate private package names:\n"
            "     - Search package.json, requirements.txt, go.mod\n"
            "     - Look for internal namespaces without public registry\n"
            "     - Check JavaScript source maps for internal names\n"
            "  2. Check public registry for name availability:\n"
            "     - npm: npm info <package-name>\n"
            "     - PyPI: pip index versions <package>\n"
            "     - RubyGems: gem search <package>\n"
            "  3. If available → potential dependency confusion target\n"
            "TESTING:\n"
            "  - Register public package with pre/post-install hook\n"
            "  - Hook phones home with metadata (hostname, user, env)\n"
            "  - Use higher version number than internal package\n"
            "  - Monitor for installations from target organization\n"
            "MITIGATION CHECK:\n"
            "  - Verify .npmrc has registry scoping\n"
            "  - Check pip.conf for --extra-index-url vs --index-url\n"
            "  - Look for package pinning/lock files"
        ),
        "tools": ["npm", "pip", "trufflehog"],
    },
    {
        "id": "sc-002", "name": "Secrets in Repositories",
        "category": "secrets", "severity": "critical",
        "desc": "Exposed credentials in source code repositories.",
        "detection": (
            "SECRETS IN REPOSITORIES:\n"
            "SCANNING TOOLS:\n"
            "  trufflehog git <repo_url> --only-verified\n"
            "  gitleaks detect --source=<repo_path>\n"
            "  git-secrets --scan\n"
            "COMMON SECRET TYPES:\n"
            "  - AWS access keys: AKIA[0-9A-Z]{16}\n"
            "  - GitHub tokens: ghp_[0-9a-zA-Z]{36}\n"
            "  - Google API keys: AIza[0-9A-Za-z\\-_]{35}\n"
            "  - Stripe keys: sk_live_[0-9a-zA-Z]{24}\n"
            "  - Slack tokens: xox[bpors]-[0-9A-Za-z]{10,}\n"
            "  - Private keys: -----BEGIN (RSA|EC|DSA) PRIVATE KEY-----\n"
            "  - JWT secrets: Often in .env, config.json, settings.py\n"
            "  - Database URLs: postgres://, mysql://, mongodb://\n"
            "GIT HISTORY:\n"
            "  - Secrets may be in old commits even if removed\n"
            "  - git log --all -p -- '*.env'\n"
            "  - git log --diff-filter=D --summary  # Deleted files\n"
            "  - Check all branches, including stale/feature branches\n"
            "CI/CD CONFIGS:\n"
            "  - .github/workflows/*.yml\n"
            "  - .gitlab-ci.yml\n"
            "  - Jenkinsfile\n"
            "  - .circleci/config.yml\n"
            "  - Check for hardcoded secrets or insecure variable usage"
        ),
        "tools": ["trufflehog", "gitleaks", "git-secrets"],
    },
    {
        "id": "sc-003", "name": "Container Image Vulnerabilities",
        "category": "container", "severity": "high",
        "desc": "Insecure container images and registries.",
        "detection": (
            "CONTAINER IMAGE SECURITY:\n"
            "IMAGE SCANNING:\n"
            "  trivy image <image_name>  # Comprehensive scanner\n"
            "  grype <image_name>  # Fast vulnerability scanner\n"
            "  docker scout cves <image_name>  # Docker's built-in\n"
            "COMMON ISSUES:\n"
            "  - Known CVEs in base image packages\n"
            "  - Running as root (USER not set)\n"
            "  - Secrets baked into image layers\n"
            "  - Unnecessary packages installed\n"
            "  - Development tools in production image\n"
            "REGISTRY SECURITY:\n"
            "  - Anonymous access to private registry\n"
            "  - Unsigned images (no Docker Content Trust)\n"
            "  - Exposed registry API: /v2/_catalog\n"
            "  - Tag mutability allowing image replacement\n"
            "IMAGE ANALYSIS:\n"
            "  - Extract layers: docker save <image> | tar xf -\n"
            "  - Inspect each layer for secrets, configs\n"
            "  - Check COPY/ADD instructions in Dockerfile\n"
            "  - Dive tool: dive <image> (interactive exploration)\n"
            "DOCKERFILE ANALYSIS:\n"
            "  - hadolint Dockerfile  # Dockerfile linter\n"
            "  - Check for latest tag (unpinned)\n"
            "  - Check for curl|bash patterns\n"
            "  - Check for ADD vs COPY usage"
        ),
        "tools": ["trivy", "grype", "dive", "hadolint"],
    },
    {
        "id": "sc-004", "name": "CI/CD Pipeline Poisoning",
        "category": "cicd", "severity": "critical",
        "desc": "Attacking build and deployment pipelines.",
        "detection": (
            "CI/CD PIPELINE ATTACKS:\n"
            "ATTACK VECTORS:\n"
            "  Poisoned Pipeline Execution (PPE):\n"
            "    - Modify CI config in pull request\n"
            "    - Direct PPE: Edit .github/workflows directly\n"
            "    - Indirect PPE: Edit files referenced by CI config\n"
            "    - Public PPE: Fork repo, modify CI, submit PR\n"
            "  Shared Runner Exploitation:\n"
            "    - Access secrets from other projects on shared runner\n"
            "    - Persist on runner between jobs\n"
            "    - Docker socket access on runner\n"
            "  Artifact Poisoning:\n"
            "    - Replace build artifacts\n"
            "    - Modify deployment packages\n"
            "    - Cache poisoning\n"
            "DETECTION:\n"
            "  1. Review CI/CD configurations:\n"
            "     - Pull_request_target vs pull_request triggers\n"
            "     - Self-hosted runner security\n"
            "     - Secret exposure in logs\n"
            "  2. Check artifact integrity:\n"
            "     - Signed artifacts\n"
            "     - Provenance tracking (SLSA framework)\n"
            "  3. Runner security:\n"
            "     - Ephemeral vs persistent runners\n"
            "     - Container isolation\n"
            "     - Network segmentation"
        ),
        "tools": ["gitleaks", "semgrep", "trivy"],
    },
    {
        "id": "sc-005", "name": "Open Source Compromise Detection",
        "category": "oss", "severity": "high",
        "desc": "Detecting compromised open source libraries.",
        "detection": (
            "OPEN SOURCE COMPROMISE:\n"
            "INDICATORS OF COMPROMISE:\n"
            "  - New maintainer with no history\n"
            "  - Obfuscated code in install scripts\n"
            "  - Post-install hooks making network requests\n"
            "  - Encoded payloads in source code\n"
            "  - Sudden activity after long dormancy\n"
            "ANALYSIS:\n"
            "  npm:\n"
            "    - npm diff <package>@<prev> <package>@<current>\n"
            "    - Review install scripts: npm pack → tar extract → check\n"
            "    - socket.dev for supply chain analysis\n"
            "  PyPI:\n"
            "    - pip download <package> --no-binary :all:\n"
            "    - Check setup.py for system calls\n"
            "    - guarddog scan <package>\n"
            "  GitHub:\n"
            "    - Check contributor history\n"
            "    - Review recent commits for suspicious changes\n"
            "    - Look for force pushes to main/master\n"
            "DEPENDENCY ANALYSIS:\n"
            "  - SBOM generation: syft, cyclonedx-bom\n"
            "  - License analysis: licensee, fossa\n"
            "  - Transitive dependency audit: npm ls, pip show\n"
            "  - Check for known malicious packages lists"
        ),
        "tools": ["syft", "trivy", "guarddog", "socket"],
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
