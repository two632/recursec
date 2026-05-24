"""DevSecOps and infrastructure security knowledge base.

Deep knowledge about DevSecOps:
1. CI/CD pipeline security
2. Infrastructure as Code security
3. Secret management
4. Container registry security
5. Supply chain security
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class DevSecOpsPattern:
    """A DevSecOps security pattern."""
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


DEVSECOPS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "dso-001", "name": "CI/CD Pipeline Security",
        "category": "cicd", "severity": "critical",
        "desc": "CI/CD pipeline attack techniques.",
        "detection": (
            "CI/CD PIPELINE SECURITY:\n"
            "POISONED PIPELINES:\n"
            "  - Direct PPE (modify CI config)\n"
            "    # PR modifies .github/workflows/\n"
            "    # PR modifies .gitlab-ci.yml\n"
            "    # PR modifies Jenkinsfile\n"
            "  - Indirect PPE (modify called scripts)\n"
            "    # Modify Makefile, build scripts\n"
            "    # Modify test scripts\n"
            "    # Modify dependency manifests\n"
            "  - Public PPE (fork + PR)\n"
            "JENKINS:\n"
            "  - Script console (/script)\n"
            "  - Credential theft\n"
            "    # credentials.xml\n"
            "    # Pipeline env vars\n"
            "  - Shared library injection\n"
            "  - Node agent exploitation\n"
            "GITHUB ACTIONS:\n"
            "  - Self-hosted runner escape\n"
            "  - Workflow injection\n"
            "    # ${{github.event.issue.title}}\n"
            "  - Secret exfiltration\n"
            "  - GITHUB_TOKEN scope abuse\n"
            "  - Action typosquatting\n"
            "GITLAB CI:\n"
            "  - Runner escape\n"
            "  - Variable exposure\n"
            "  - Include directive abuse\n"
            "TOOLS:\n"
            "  Cider, ggshield, semgrep"
        ),
        "tools": [],
    },
    {
        "id": "dso-002", "name": "Infrastructure as Code Security",
        "category": "iac", "severity": "high",
        "desc": "IaC security assessment.",
        "detection": (
            "IAC SECURITY:\n"
            "TERRAFORM:\n"
            "  - State file exposure\n"
            "    # S3 bucket without encryption\n"
            "    # State file contains secrets\n"
            "  - Provider credential leakage\n"
            "  - Module supply chain\n"
            "  - Plan manipulation\n"
            "  # Scanning:\n"
            "  tfsec /path/to/tf\n"
            "  checkov -d /path/to/tf\n"
            "  terrascan scan -d /path/to/tf\n"
            "CLOUDFORMATION:\n"
            "  - Template injection\n"
            "  - Parameter default values\n"
            "  - Stack output secrets\n"
            "  # cfn-nag_scan --input-path template.yaml\n"
            "ANSIBLE:\n"
            "  - Vault password exposure\n"
            "  - Hardcoded credentials in playbooks\n"
            "  - Privilege escalation\n"
            "  - Unencrypted vars/secrets\n"
            "KUBERNETES MANIFESTS:\n"
            "  - Privileged containers\n"
            "  - hostPath mounts\n"
            "  - No resource limits\n"
            "  - Default service account\n"
            "  # kubesec scan deployment.yaml\n"
            "  # kube-bench run\n"
            "TOOLS:\n"
            "  tfsec, checkov, terrascan, kube-bench"
        ),
        "tools": [],
    },
    {
        "id": "dso-003", "name": "Secret Management",
        "category": "secrets", "severity": "critical",
        "desc": "Secret management vulnerabilities.",
        "detection": (
            "SECRET MANAGEMENT:\n"
            "DETECTION:\n"
            "  - Git history scanning\n"
            "    # trufflehog git https://repo.git\n"
            "    # gitleaks detect --source=.\n"
            "    # ggshield secret scan repo .\n"
            "  - Live secrets in code\n"
            "    # grep -r 'AKIA' .  (AWS keys)\n"
            "    # grep -r 'sk-' .   (OpenAI keys)\n"
            "    # grep -r 'ghp_' .  (GitHub PATs)\n"
            "  - Environment variable leaks\n"
            "  - Config file secrets\n"
            "  - Docker layer secrets\n"
            "    # docker history IMAGE\n"
            "    # dive IMAGE\n"
            "ROTATION:\n"
            "  - Identify all secret locations\n"
            "  - Check rotation policies\n"
            "  - Test revocation procedures\n"
            "  - Verify secret scope (min privilege)\n"
            "VAULT SYSTEMS:\n"
            "  - HashiCorp Vault misconfig\n"
            "    # Unsealed vault\n"
            "    # Root token exposure\n"
            "    # Excessive policies\n"
            "  - AWS Secrets Manager\n"
            "  - Azure Key Vault\n"
            "  - GCP Secret Manager\n"
            "TOOLS:\n"
            "  trufflehog, gitleaks, ggshield, detect-secrets"
        ),
        "tools": [],
    },
    {
        "id": "dso-004", "name": "Container Registry Security",
        "category": "registry", "severity": "high",
        "desc": "Container registry security.",
        "detection": (
            "CONTAINER REGISTRY SECURITY:\n"
            "DOCKER HUB:\n"
            "  - Image typosquatting\n"
            "  - Unverified publishers\n"
            "  - Outdated base images\n"
            "  - Exposed registry credentials\n"
            "PRIVATE REGISTRIES:\n"
            "  - Anonymous access\n"
            "    # curl https://registry:5000/v2/_catalog\n"
            "  - API enumeration\n"
            "    # List repositories\n"
            "    # List tags\n"
            "    # Pull manifests\n"
            "  - Token/auth bypass\n"
            "  - Content trust disabled\n"
            "IMAGE ANALYSIS:\n"
            "  - Layer inspection\n"
            "    # docker save IMAGE | tar xf -\n"
            "    # Inspect each layer\n"
            "  - Secret extraction\n"
            "    # Dockerfile ARG/ENV secrets\n"
            "    # Build-time secrets in layers\n"
            "  - Vulnerability scanning\n"
            "    # trivy image IMAGE\n"
            "    # grype IMAGE\n"
            "    # snyk container test IMAGE\n"
            "  - SBOM generation\n"
            "    # syft IMAGE -o spdx-json\n"
            "SIGNING:\n"
            "  - Notary/cosign verification\n"
            "  - Sigstore transparency log\n"
            "  - Admission controllers\n"
            "TOOLS:\n"
            "  trivy, grype, cosign, dive, syft"
        ),
        "tools": [],
    },
    {
        "id": "dso-005", "name": "Supply Chain Security",
        "category": "supply_chain", "severity": "critical",
        "desc": "Software supply chain security.",
        "detection": (
            "SUPPLY CHAIN SECURITY:\n"
            "DEPENDENCY ATTACKS:\n"
            "  - Dependency confusion\n"
            "    # Internal package name on public registry\n"
            "    # Higher version wins\n"
            "  - Typosquatting\n"
            "    # lodash → 1odash\n"
            "    # requests → reqeusts\n"
            "  - Maintainer compromise\n"
            "    # event-stream incident\n"
            "    # ua-parser-js incident\n"
            "  - Malicious updates\n"
            "BUILD SYSTEM:\n"
            "  - Build script injection\n"
            "  - Compiler/toolchain compromise\n"
            "  - Reproducible builds verification\n"
            "  - Build environment hardening\n"
            "SBOM:\n"
            "  - Software Bill of Materials\n"
            "  - SPDX / CycloneDX formats\n"
            "  - Dependency tree analysis\n"
            "  - License compliance\n"
            "FRAMEWORKS:\n"
            "  - SLSA (Supply-chain Levels for SA)\n"
            "    # Level 1-4 requirements\n"
            "  - Sigstore (signing/verification)\n"
            "  - in-toto (build attestation)\n"
            "  - SSDF (Secure Software Dev)\n"
            "SCANNING:\n"
            "  # npm audit / yarn audit\n"
            "  # pip-audit\n"
            "  # cargo audit\n"
            "  # snyk test\n"
            "  # oss-review-toolkit\n"
            "TOOLS:\n"
            "  snyk, npm-audit, pip-audit, SLSA, cosign"
        ),
        "tools": [],
    },
]


class DevSecOpsKB:
    """DevSecOps security knowledge base.

    Provides DevSecOps patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, DevSecOpsPattern] = {}
        self._log = logger.bind(component="devsecops_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load DevSecOps patterns."""
        for data in DEVSECOPS_PATTERNS:
            pattern = DevSecOpsPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[DevSecOpsPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_devsecops_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build DevSecOps prompt."""
        lines = ["## DevSecOps Security\n"]
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
