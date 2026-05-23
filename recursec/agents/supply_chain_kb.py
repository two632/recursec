"""Supply chain security knowledge base.

Deep knowledge about supply chain attacks:
1. Dependency confusion / substitution
2. Typosquatting attacks
3. Compromised package detection
4. CI/CD pipeline attacks
5. Source code tampering
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
    severity: str = "high"
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
        "id": "sc-001", "name": "Dependency Confusion Attacks",
        "category": "dependency", "severity": "critical",
        "desc": "Exploiting dependency confusion in package managers.",
        "detection": (
            "DEPENDENCY CONFUSION:\n"
            "CONCEPT:\n"
            "  - Internal package names exist on private registry\n"
            "  - Attacker publishes same name on public registry\n"
            "  - Package manager prefers public (higher version)\n"
            "  - Attacker's package executes on build\n"
            "AFFECTED PACKAGE MANAGERS:\n"
            "  - npm (Node.js): .npmrc scoped registries\n"
            "  - pip (Python): --extra-index-url\n"
            "  - gem (Ruby): custom sources\n"
            "  - NuGet (.NET): package sources\n"
            "  - Maven (Java): repository config\n"
            "DETECTION:\n"
            "  # Find internal package names\n"
            "  - Parse package.json / requirements.txt / pom.xml\n"
            "  - Check if name exists on public registry\n"
            "  # npm\n"
            "  npm view <package-name>  # 404 = private only\n"
            "  # pip\n"
            "  pip index versions <package>  # Check PyPI\n"
            "PREVENTION CHECKS:\n"
            "  - Scoped packages (@org/package in npm)\n"
            "  - Pin exact versions in lockfiles\n"
            "  - Registry whitelisting\n"
            "  - Namespace reservation on public registries"
        ),
        "tools": ["npm", "pip", "semgrep"],
    },
    {
        "id": "sc-002", "name": "Typosquatting Detection",
        "category": "typosquat", "severity": "high",
        "desc": "Detecting typosquatted packages.",
        "detection": (
            "TYPOSQUATTING DETECTION:\n"
            "COMMON PATTERNS:\n"
            "  - Character swap: requsets → requests\n"
            "  - Missing character: reques → requests\n"
            "  - Extra character: requestss → requests\n"
            "  - Hyphen/underscore: python-requests vs python_requests\n"
            "  - Scope confusion: @popular/package vs popular-package\n"
            "  - Combosquatting: requests-utils (popular prefix)\n"
            "TOOLS:\n"
            "  # npm\n"
            "  npx npm-audit  # Check for known malicious packages\n"
            "  socket.dev  # Real-time supply chain analysis\n"
            "  # pip\n"
            "  pip-audit  # Check for known vulnerabilities\n"
            "  safety check  # Check installed packages\n"
            "  # General\n"
            "  snyk test  # Multi-language dependency check\n"
            "  trivy fs .  # Filesystem vulnerability scan\n"
            "ANALYSIS CHECKS:\n"
            "  - Package age (recently published = suspicious)\n"
            "  - Download count (very low = suspicious)\n"
            "  - Author reputation\n"
            "  - Install scripts (preinstall/postinstall hooks)\n"
            "  - Network calls during install\n"
            "  - Obfuscated code in package"
        ),
        "tools": ["pip-audit", "snyk", "trivy"],
    },
    {
        "id": "sc-003", "name": "CI/CD Pipeline Attacks",
        "category": "cicd", "severity": "critical",
        "desc": "Attacking CI/CD pipelines for code injection.",
        "detection": (
            "CI/CD PIPELINE ATTACKS:\n"
            "ATTACK VECTORS:\n"
            "  GITHUB ACTIONS:\n"
            "    - Poisoned PR: Modify .github/workflows/ in PR\n"
            "    - pull_request_target: Runs with repo token + PR code\n"
            "    - Workflow injection via issue/PR title\n"
            "    - Compromised third-party actions\n"
            "    - Secret exfiltration from forks\n"
            "  JENKINS:\n"
            "    - Groovy script console (if exposed)\n"
            "    - Pipeline script injection\n"
            "    - Credential theft from Jenkins\n"
            "    - Plugin vulnerabilities\n"
            "  GITLAB CI:\n"
            "    - .gitlab-ci.yml modification\n"
            "    - Variable exposure in logs\n"
            "    - Runner escape\n"
            "DETECTION:\n"
            "  # Audit workflow files\n"
            "  - Check for pull_request_target with code checkout\n"
            "  - Check for ${{ github.event.* }} in run: blocks\n"
            "  - Verify action versions are pinned to SHA\n"
            "  - Check for self-hosted runner risks\n"
            "  # Secrets\n"
            "  - gitleaks detect  # Find secrets in git history\n"
            "  - trufflehog git <repo>  # Deep secret scanning"
        ),
        "tools": ["gitleaks", "trufflehog", "semgrep"],
    },
    {
        "id": "sc-004", "name": "Container Image Supply Chain",
        "category": "container", "severity": "high",
        "desc": "Detecting compromised container images.",
        "detection": (
            "CONTAINER IMAGE SUPPLY CHAIN:\n"
            "BASE IMAGE RISKS:\n"
            "  - Unofficial base images (not from Docker Official)\n"
            "  - Outdated base images with known CVEs\n"
            "  - Images from untrusted registries\n"
            "  - Multi-stage build leaks\n"
            "ANALYSIS:\n"
            "  # Scan for vulnerabilities\n"
            "  trivy image <image>:<tag>\n"
            "  grype <image>:<tag>\n"
            "  # Check image provenance\n"
            "  cosign verify <image>  # Signature verification\n"
            "  # Inspect image layers\n"
            "  dive <image>  # Interactive layer analysis\n"
            "  docker history <image>  # Layer commands\n"
            "  # SBOM generation\n"
            "  syft <image>  # Software Bill of Materials\n"
            "  # Secret scanning in layers\n"
            "  ggshield secret scan docker <image>\n"
            "DOCKERFILE CHECKS:\n"
            "  - Using :latest tag (unpinned)\n"
            "  - Running as root\n"
            "  - COPY . . (copying secrets)\n"
            "  - Hardcoded tokens in ENV/ARG\n"
            "  - Unnecessary packages installed\n"
            "  - No health check defined"
        ),
        "tools": ["trivy", "grype", "cosign", "syft"],
    },
    {
        "id": "sc-005", "name": "Source Code Integrity",
        "category": "source", "severity": "high",
        "desc": "Verifying source code integrity and detecting tampering.",
        "detection": (
            "SOURCE CODE INTEGRITY:\n"
            "GIT HISTORY ANALYSIS:\n"
            "  # Detect force pushes\n"
            "  git reflog  # Check for rebase/reset\n"
            "  # Detect author spoofing\n"
            "  git log --format='%H %ae %ce' | sort\n"
            "  # Verify GPG signatures\n"
            "  git log --show-signature\n"
            "  git verify-commit HEAD\n"
            "  # Find suspicious commits\n"
            "  git log --diff-filter=A --name-only  # New files\n"
            "  git log --all --oneline -- '*.sh' '*.py' '*.js'\n"
            "BACKDOOR PATTERNS:\n"
            "  - Obfuscated code additions\n"
            "  - eval() / exec() in new code\n"
            "  - Network calls in build scripts\n"
            "  - Encoded payloads in test files\n"
            "  - Hidden functionality in unicode chars\n"
            "TOOLS:\n"
            "  semgrep --config 'p/security-audit' .  # Code patterns\n"
            "  bandit -r .  # Python security linting\n"
            "  gitleaks detect --source .  # Secret detection\n"
            "REVIEW CHECKLIST:\n"
            "  - Verify all contributors are authorized\n"
            "  - Check for unsigned commits\n"
            "  - Review changes to CI/CD configs\n"
            "  - Audit dependency updates carefully\n"
            "  - Monitor for unusual commit patterns"
        ),
        "tools": ["semgrep", "bandit", "gitleaks"],
    },
]


class SupplyChainKB:
    """Supply chain security knowledge base.

    Provides supply chain vulnerability patterns
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
