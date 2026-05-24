"""Supply chain security knowledge base.

Attack patterns for software supply chain attacks:
1. Dependency Confusion — internal vs public package takeover
2. Malicious Package Injection — typosquatting, star-jacking
3. CI/CD Pipeline Compromise — poisoned workflows, secrets theft
4. Source Code Repository Attacks — commit injection, signed malware
5. Build System Compromise — compiler backdoors, reproducibility
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SupplyChainAttackType(str, Enum):
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MALICIOUS_PACKAGE = "malicious_package"
    CICD_COMPROMISE = "cicd_compromise"
    REPO_ATTACK = "repo_attack"
    BUILD_COMPROMISE = "build_compromise"


@dataclass
class SupplyChainPattern:
    """A supply chain attack pattern."""
    name: str = ""
    attack_type: SupplyChainAttackType = SupplyChainAttackType.DEPENDENCY_CONFUSION
    description: str = ""
    detection_strategies: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.attack_type.value,
            "severity": self.severity,
            "detection_count": len(self.detection_strategies),
            "indicator_count": len(self.indicators),
        }


SUPPLY_CHAIN_PATTERNS: list[SupplyChainPattern] = [
    SupplyChainPattern(
        name="Dependency Confusion",
        attack_type=SupplyChainAttackType.DEPENDENCY_CONFUSION,
        description=(
            "Attack where internal package names are registered on public "
            "registries, causing build systems to fetch malicious versions."
        ),
        detection_strategies=[
            "Audit package.json/requirements.txt for private scoped names",
            "Check if internal package names exist on public registries",
            "Verify .npmrc/.pip.conf registry configuration scoping",
            "Monitor build logs for unexpected package source URLs",
            "Implement namespace reservation on public registries",
            "Compare package checksums between internal and external versions",
            "Check for packages with install scripts (preinstall hooks)",
            "Monitor DNS resolution during builds for external registry calls",
        ],
        indicators=[
            "Package fetched from public registry instead of internal",
            "Version mismatch between internal and public package",
            "Unexpected network calls during package installation",
            "Install hook scripts executing on build servers",
            "Registry URL in lockfile differs from expected",
        ],
        tools=["pip-audit", "npm-audit", "socket.dev", "snyk", "ort"],
        commands=[
            "pip install pip-audit && pip-audit",
            "npm audit --json",
            "pip index versions <package_name>",
            "npm view <pkg> --registry https://registry.npmjs.org",
            "grep -r 'registry' .npmrc .yarnrc* pip.conf",
        ],
        mitre_ids=["T1195.001"],
        severity="critical",
    ),
    SupplyChainPattern(
        name="Malicious Package Injection",
        attack_type=SupplyChainAttackType.MALICIOUS_PACKAGE,
        description=(
            "Typosquatting, star-jacking, and maintainer account compromise "
            "to inject malicious code into legitimate-looking packages."
        ),
        detection_strategies=[
            "Fuzzy-match package names against known popular packages",
            "Check package creation date vs popularity (new+popular=suspect)",
            "Analyze install scripts for obfuscated code, eval(), exec()",
            "Compare package metadata against known legitimate packages",
            "Monitor for packages with encoded payloads in setup.py",
            "Check GitHub stars vs npm downloads discrepancy (star-jacking)",
            "Analyze dependency tree for unusual transitive dependencies",
            "Review package source for network calls, fs access, env reads",
        ],
        indicators=[
            "Package name similar to popular package (reqeusts vs requests)",
            "setup.py or postinstall script with obfuscated code",
            "Package reads environment variables or SSH keys",
            "Outbound HTTP calls in install hooks",
            "Base64-encoded strings in package source",
            "Few maintainers, recent creation, high download count",
        ],
        tools=["socket.dev", "snyk", "ort", "bandit", "semgrep"],
        commands=[
            "pip download --no-deps <package> && unzip *.whl",
            "npm pack <package> && tar xzf *.tgz",
            "bandit -r . -f json",
            "semgrep --config p/supply-chain .",
            "grep -rn 'eval\\|exec\\|subprocess' *.py",
        ],
        mitre_ids=["T1195.001", "T1195.002"],
        severity="critical",
    ),
    SupplyChainPattern(
        name="CI/CD Pipeline Compromise",
        attack_type=SupplyChainAttackType.CICD_COMPROMISE,
        description=(
            "Attacking CI/CD pipelines to inject malicious code during build, "
            "test, or deployment phases. Includes secrets exfiltration."
        ),
        detection_strategies=[
            "Audit GitHub Actions for pull_request_target with PR checkout",
            "Check for workflow_dispatch with unvalidated inputs in run:",
            "Scan for hardcoded secrets in CI config (even base64-encoded)",
            "Verify third-party actions pinned to commit SHAs not tags",
            "Monitor for self-hosted runner registration from unknown IPs",
            "Analyze Jenkinsfile/Gitlab CI for script injection via vars",
            "Check for OIDC token misuse in cloud provider auth",
            "Review artifact upload/download for data exfiltration",
        ],
        indicators=[
            "Workflow triggered by pull_request_target with head checkout",
            "Third-party actions referenced by mutable tag not SHA",
            "Secrets exposed in workflow logs or artifacts",
            "Unexpected outbound network calls from CI runners",
            "Modified CI config in PR without review",
            "Self-hosted runner with broad permissions",
        ],
        tools=["gitleaks", "trufflehog", "semgrep", "checkov", "ggshield"],
        commands=[
            "gitleaks detect --source . --report-format json",
            "trufflehog git file://. --json",
            "grep -rn 'pull_request_target' .github/workflows/",
            "grep -rn 'uses:.*@v[0-9]' .github/workflows/",
            "checkov -d . --framework github_actions",
        ],
        mitre_ids=["T1195.002", "T1199"],
        severity="critical",
    ),
    SupplyChainPattern(
        name="Source Code Repository Attacks",
        attack_type=SupplyChainAttackType.REPO_ATTACK,
        description=(
            "Attacks targeting source code repos: commit signing bypass, "
            "force-push to protected branches, GPG key compromise."
        ),
        detection_strategies=[
            "Verify commit signatures (GPG/SSH) on protected branches",
            "Check for force-push events in audit logs",
            "Monitor for branch protection rule changes",
            "Analyze commit author vs committer discrepancies",
            "Check for commits from unknown or expired GPG keys",
            "Monitor for large binary blobs in commits (malware)",
            "Verify PR approvals are from authorized CODEOWNERS",
            "Check for .gitattributes manipulation to hide diffs",
        ],
        indicators=[
            "Unsigned commits on protected branches",
            "Force-push events in repository audit log",
            "Commit author email differs from committer email",
            "Branch protection rules weakened or disabled",
            "Large binary files in source tree",
            "Commits referencing unknown GPG key IDs",
        ],
        tools=["git", "gitleaks", "gitrob", "trufflehog", "git-secrets"],
        commands=[
            "git log --show-signature -10",
            "git log --format='%H %an <%ae> %cn <%ce>' | head -50",
            "git log --diff-filter=A --name-only | head -50",
            "git fsck --full",
            "find . -name '.gitattributes' -exec cat {} +",
        ],
        mitre_ids=["T1195.002"],
        severity="high",
    ),
    SupplyChainPattern(
        name="Build System Compromise",
        attack_type=SupplyChainAttackType.BUILD_COMPROMISE,
        description=(
            "Attacks targeting the build process: compiler backdoors, "
            "non-reproducible builds, build cache poisoning, Dockerfiles."
        ),
        detection_strategies=[
            "Verify reproducible builds produce identical artifacts",
            "Compare build output checksums across clean environments",
            "Audit Dockerfiles for untrusted base images, ADD from URLs",
            "Check Makefile/build scripts for network calls during build",
            "Verify compiler/toolchain integrity via checksums",
            "Monitor for build cache poisoning across projects",
            "Analyze multi-stage Docker builds for data leakage",
            "Check for post-build artifact modification before signing",
        ],
        indicators=[
            "Build output differs between environments",
            "Dockerfile pulls from non-official base images",
            "Build scripts download binaries from external URLs",
            "Compiler version mismatch in build environment",
            "Build artifacts larger than expected",
            "Network calls during compilation phase",
        ],
        tools=["cosign", "syft", "grype", "trivy", "docker-bench-security"],
        commands=[
            "trivy image --severity CRITICAL,HIGH <image>",
            "syft <image> -o json",
            "cosign verify <image>",
            "docker history --no-trunc <image>",
            "grep -rn 'ADD\\|COPY.*http' Dockerfile*",
        ],
        mitre_ids=["T1195.002", "T1195.003"],
        severity="high",
    ),
]


def build_supply_chain_prompt(
    focus_type: SupplyChainAttackType | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with supply chain attack knowledge."""
    lines = ["## Supply Chain Security Knowledge\n"]

    patterns = SUPPLY_CHAIN_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]

    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nDetection:")
        for strategy in pattern.detection_strategies[:4]:
            lines.append(f"  - {strategy}")
        lines.append("\nIndicators:")
        for indicator in pattern.indicators[:3]:
            lines.append(f"  - {indicator}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("")

    return "\n".join(lines)


class SupplyChainKB:
    """Wrapper for supply chain security knowledge base."""

    def get_prompt(self, focus: SupplyChainAttackType | None = None) -> str:
        return build_supply_chain_prompt(focus_type=focus)

    def get_patterns(self) -> list[SupplyChainPattern]:
        return SUPPLY_CHAIN_PATTERNS
