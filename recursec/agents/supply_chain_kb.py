"""Supply chain security knowledge base.

Deep knowledge about supply chain attacks:
1. Dependency confusion attacks
2. Typosquatting in package registries
3. CI/CD pipeline poisoning
4. Build system compromise
5. Software composition analysis
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
            "category": self.category[:12],
        }


SUPPLY_CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sc-001", "name": "Dependency Confusion",
        "category": "dependency", "severity": "critical",
        "desc": "Exploiting package manager resolution to inject malicious packages.",
        "detection": (
            "DEPENDENCY CONFUSION:\n"
            "ATTACK METHODOLOGY:\n"
            "  1. Identify internal/private package names\n"
            "     - Look at package.json, requirements.txt, go.mod\n"
            "     - Check for internal namespace packages\n"
            "     - Search error messages, docs, job postings\n"
            "  2. Register same name on public registry\n"
            "     - npm: npm publish with higher version\n"
            "     - PyPI: python setup.py upload\n"
            "     - RubyGems: gem push\n"
            "  3. Package manager resolves public > private\n"
            "     - npm prefers higher version from any source\n"
            "     - pip prefers public PyPI over private index\n"
            "DETECTION:\n"
            "  # Check for internal package names on public registries\n"
            "  npm view <internal-package-name>\n"
            "  pip index versions <internal-package-name>\n"
            "  # If package exists on public → potential confusion\n"
            "PREVENTION:\n"
            "  - Use scoped packages (@org/package)\n"
            "  - Pin exact versions\n"
            "  - Use package lock files\n"
            "  - Configure private registry priority"
        ),
        "tools": ["npm", "pip", "snyk"],
    },
    {
        "id": "sc-002", "name": "CI/CD Pipeline Poisoning",
        "category": "cicd", "severity": "critical",
        "desc": "Compromising CI/CD pipelines for code injection.",
        "detection": (
            "CI/CD PIPELINE POISONING:\n"
            "ATTACK VECTORS:\n"
            "  GITHUB ACTIONS:\n"
            "    - Workflow injection via pull_request_target\n"
            "    - Secret exfiltration from environment\n"
            "    - Self-hosted runner compromise\n"
            "    - Malicious fork PRs triggering workflows\n"
            "    - Actions from untrusted sources\n"
            "  GITLAB CI:\n"
            "    - .gitlab-ci.yml injection via MR\n"
            "    - Shared runner exploitation\n"
            "    - CI variable leakage\n"
            "  JENKINS:\n"
            "    - Groovy sandbox escape\n"
            "    - Pipeline script injection\n"
            "    - Plugin vulnerabilities\n"
            "    - Credential enumeration\n"
            "DETECTION:\n"
            "  # Audit CI configs\n"
            "  - Check for pull_request_target with checkout\n"
            "  - Check for env: GITHUB_TOKEN in workflow output\n"
            "  - Verify action versions are pinned to SHA\n"
            "  - Check runner labels (self-hosted = higher risk)\n"
            "  # Secret scanning\n"
            "  trufflehog git <repo_url>\n"
            "  gitleaks detect"
        ),
        "tools": ["trufflehog", "gitleaks", "semgrep"],
    },
    {
        "id": "sc-003", "name": "Typosquatting",
        "category": "typosquatting", "severity": "high",
        "desc": "Registering similar package names to intercept installations.",
        "detection": (
            "TYPOSQUATTING:\n"
            "TECHNIQUES:\n"
            "  - Character swap: lodash → lodahs, lodsah\n"
            "  - Missing character: express → expres, xpress\n"
            "  - Extra character: react → reactt, reactjs-core\n"
            "  - Homoglyph: crypto → ϲrypto (Cyrillic с)\n"
            "  - Namespace confusion: @types/node → types-node\n"
            "DETECTION:\n"
            "  # Generate typo variants\n"
            "  - Levenshtein distance = 1 from popular packages\n"
            "  - Check if variant exists on registry\n"
            "  - Compare package contents to original\n"
            "  - Check publish date vs download count\n"
            "  # Automated tools\n"
            "  typofinder <package-name>  # Generate and check variants\n"
            "  pip-audit  # Check for known malicious packages\n"
            "  npm audit  # Built-in vulnerability check\n"
            "INDICATORS OF MALICIOUS PACKAGE:\n"
            "  - install/postinstall scripts executing code\n"
            "  - Network calls in setup.py/setup.cfg\n"
            "  - Obfuscated code in package\n"
            "  - Very new package with suspicious name"
        ),
        "tools": ["npm", "pip", "snyk"],
    },
    {
        "id": "sc-004", "name": "Build System Compromise",
        "category": "build", "severity": "critical",
        "desc": "Attacking build systems to inject malicious code.",
        "detection": (
            "BUILD SYSTEM COMPROMISE:\n"
            "ATTACK VECTORS:\n"
            "  - Compromised build dependencies\n"
            "  - Malicious build plugins (Maven, Gradle, webpack)\n"
            "  - Build cache poisoning\n"
            "  - Compiler backdoors\n"
            "  - Container image poisoning\n"
            "CONTAINER IMAGE ATTACKS:\n"
            "  # Scan base images\n"
            "  trivy image <image>:<tag>\n"
            "  grype <image>:<tag>\n"
            "  # Check for:\n"
            "  - Unnecessary SUID binaries\n"
            "  - Embedded secrets in layers\n"
            "  - Running as root\n"
            "  - Unsigned images\n"
            "  - Images from untrusted registries\n"
            "SBOM ANALYSIS:\n"
            "  # Generate Software Bill of Materials\n"
            "  syft <target> -o spdx-json\n"
            "  # Check components against known vulns\n"
            "  grype sbom:<sbom_file>\n"
            "  # Track transitive dependencies\n"
            "  npm ls --all\n"
            "  pip freeze > requirements.txt"
        ),
        "tools": ["trivy", "grype", "syft"],
    },
    {
        "id": "sc-005", "name": "Open Source Intelligence for Supply Chain",
        "category": "osint_supply", "severity": "high",
        "desc": "Using OSINT to identify supply chain risks.",
        "detection": (
            "SUPPLY CHAIN OSINT:\n"
            "MAINTAINER ANALYSIS:\n"
            "  - Check maintainer account age and activity\n"
            "  - Look for maintainer account takeover indicators\n"
            "  - Check for recent ownership transfers\n"
            "  - Look for abandoned but popular packages\n"
            "DEPENDENCY TREE ANALYSIS:\n"
            "  # Map complete dependency tree\n"
            "  npm ls --all --json > deps.json\n"
            "  pipdeptree --json > deps.json\n"
            "  # Identify:\n"
            "  - Single-maintainer critical dependencies\n"
            "  - Dependencies with no recent updates\n"
            "  - Dependencies with known but unpatched vulns\n"
            "  - Excessive transitive dependency depth\n"
            "VULNERABILITY DATABASES:\n"
            "  - NVD (nvd.nist.gov)\n"
            "  - GitHub Advisory Database\n"
            "  - OSV (osv.dev)\n"
            "  - Snyk vulnerability DB\n"
            "  # Automated checking\n"
            "  osv-scanner --lockfile=package-lock.json\n"
            "  snyk test\n"
            "  safety check (Python)"
        ),
        "tools": ["osv-scanner", "snyk", "safety"],
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
        """Build supply chain prompt."""
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
