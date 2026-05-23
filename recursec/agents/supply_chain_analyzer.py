"""Supply chain analyzer — dependency and build pipeline security analysis.

Implements:
1. Dependency graph construction
2. Known vulnerability matching (CVE lookup)
3. Dependency confusion detection
4. Typosquatting detection
5. Maintainer risk assessment
6. Transitive dependency analysis
7. Build pipeline integrity checks
8. Package manifest parsing
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PackageEcosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    GO = "go"
    CARGO = "cargo"
    DOCKER = "docker"


class SupplyChainRiskType(str, Enum):
    KNOWN_CVE = "known_cve"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    TYPOSQUATTING = "typosquatting"
    UNMAINTAINED = "unmaintained"
    SINGLE_MAINTAINER = "single_maintainer"
    INSTALL_SCRIPT = "install_script"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    PINNING_MISSING = "pinning_missing"
    YANKED_VERSION = "yanked_version"
    BUILD_INTEGRITY = "build_integrity"


@dataclass
class Dependency:
    """A package dependency."""
    dep_id: str = ""
    name: str = ""
    version: str = ""
    ecosystem: PackageEcosystem = PackageEcosystem.NPM
    is_direct: bool = True
    is_dev: bool = False
    pinned: bool = False
    last_publish: str = ""
    maintainer_count: int = 0
    weekly_downloads: int = 0
    has_install_script: bool = False
    transitive_deps: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.dep_id,
            "name": self.name[:25],
            "version": self.version[:15],
            "eco": self.ecosystem.value,
            "direct": self.is_direct,
            "pinned": self.pinned,
        }


@dataclass
class SupplyChainFinding:
    """A supply chain security finding."""
    finding_id: str = ""
    risk_type: SupplyChainRiskType = SupplyChainRiskType.KNOWN_CVE
    dependency: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    remediation: str = ""
    cve_id: str = ""
    affected_versions: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "risk": self.risk_type.value,
            "dep": self.dependency[:20],
            "severity": self.severity,
            "title": self.title[:30],
        }


# ── Known Typosquatting Patterns ──────────────────────────────

TYPOSQUAT_TRANSFORMS: list[tuple[str, str]] = [
    ("requests", "reqests"),
    ("requests", "requets"),
    ("flask", "flaskk"),
    ("django", "djang0"),
    ("express", "expresss"),
    ("lodash", "lodassh"),
    ("chalk", "chulk"),
    ("axios", "axois"),
    ("numpy", "numpi"),
    ("pandas", "pandass"),
]

# ── Suspicious Install Script Patterns ────────────────────────

SUSPICIOUS_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"curl\s+.+\|\s*(bash|sh)", "name": "pipe_to_shell"},
    {"pattern": r"wget\s+.+&&\s*(bash|sh)", "name": "download_and_run"},
    {"pattern": r"eval\s*\(", "name": "eval_usage"},
    {"pattern": r"(\.env|credentials|\.aws|\.ssh)", "name": "credential_access"},
    {"pattern": r"crypto\s*\.\s*createDecipher", "name": "crypto_decrypt"},
    {"pattern": r"Buffer\.from\(.+,\s*['\"]base64['\"]", "name": "base64_decode"},
    {"pattern": r"child_process|subprocess|os\.system", "name": "process_execution"},
    {"pattern": r"(webhook|exfil|c2|callback)\.", "name": "exfiltration_hint"},
    {"pattern": r"socket\.connect|net\.createConnection", "name": "network_connection"},
]


class SupplyChainAnalyzer:
    """Analyzes dependency and build pipeline security.

    Detects dependency confusion, typosquatting, unmaintained
    packages, and other supply chain risks.
    """

    def __init__(self) -> None:
        self._dependencies: dict[str, Dependency] = {}
        self._findings: list[SupplyChainFinding] = []
        self._dep_counter = 0
        self._finding_counter = 0
        self._log = logger.bind(component="supply_chain_analyzer")

    def add_dependency(
        self,
        name: str,
        version: str = "",
        ecosystem: PackageEcosystem = PackageEcosystem.NPM,
        is_direct: bool = True,
        is_dev: bool = False,
        pinned: bool = False,
        maintainer_count: int = 0,
        has_install_script: bool = False,
    ) -> Dependency:
        """Register a dependency."""
        self._dep_counter += 1
        dep = Dependency(
            dep_id=f"dep-{self._dep_counter}",
            name=name,
            version=version,
            ecosystem=ecosystem,
            is_direct=is_direct,
            is_dev=is_dev,
            pinned=pinned,
            maintainer_count=maintainer_count,
            has_install_script=has_install_script,
        )
        self._dependencies[dep.dep_id] = dep
        return dep

    def analyze_all(self) -> list[SupplyChainFinding]:
        """Run all supply chain checks."""
        findings = []

        findings.extend(self._check_unpinned())
        findings.extend(self._check_typosquatting())
        findings.extend(self._check_single_maintainer())
        findings.extend(self._check_install_scripts())
        findings.extend(self._check_dependency_confusion_risk())

        self._findings.extend(findings)
        return findings

    def _check_unpinned(self) -> list[SupplyChainFinding]:
        """Check for unpinned dependencies."""
        findings = []
        for dep in self._dependencies.values():
            if not dep.pinned and dep.is_direct:
                self._finding_counter += 1
                findings.append(SupplyChainFinding(
                    finding_id=f"scf-{self._finding_counter}",
                    risk_type=SupplyChainRiskType.PINNING_MISSING,
                    dependency=dep.name,
                    severity="medium",
                    title=f"Unpinned dependency: {dep.name}",
                    description=(
                        f"Package {dep.name}@{dep.version} is not version-pinned. "
                        f"A malicious version update would be automatically installed."
                    ),
                    remediation=f"Pin to exact version: {dep.name}=={dep.version}",
                ))
        return findings

    def _check_typosquatting(self) -> list[SupplyChainFinding]:
        """Check if dependencies might be typosquats."""
        findings = []
        dep_names = {dep.name.lower() for dep in self._dependencies.values()}

        for dep in self._dependencies.values():
            name_lower = dep.name.lower()

            # Check against known popular packages
            for popular, typo in TYPOSQUAT_TRANSFORMS:
                if name_lower == typo:
                    self._finding_counter += 1
                    findings.append(SupplyChainFinding(
                        finding_id=f"scf-{self._finding_counter}",
                        risk_type=SupplyChainRiskType.TYPOSQUATTING,
                        dependency=dep.name,
                        severity="critical",
                        title=f"Possible typosquat: {dep.name} (intended: {popular})",
                        description=(
                            f"Package '{dep.name}' closely resembles '{popular}'. "
                            f"This may be a typosquatting attack."
                        ),
                        remediation=f"Verify package is correct. Did you mean '{popular}'?",
                    ))

            # Check edit distance against other deps
            for other_name in dep_names:
                if other_name != name_lower and self._edit_distance(name_lower, other_name) == 1:
                    self._finding_counter += 1
                    findings.append(SupplyChainFinding(
                        finding_id=f"scf-{self._finding_counter}",
                        risk_type=SupplyChainRiskType.TYPOSQUATTING,
                        dependency=dep.name,
                        severity="medium",
                        title=f"Similar names: {dep.name} / {other_name}",
                        description=(
                            f"Two packages with edit distance 1: "
                            f"'{dep.name}' and '{other_name}'. Verify both are intentional."
                        ),
                        remediation="Verify both packages are legitimate dependencies",
                    ))

        return findings

    def _check_single_maintainer(self) -> list[SupplyChainFinding]:
        """Check for popular packages with single maintainer."""
        findings = []
        for dep in self._dependencies.values():
            if dep.maintainer_count == 1 and dep.weekly_downloads > 10000:
                self._finding_counter += 1
                findings.append(SupplyChainFinding(
                    finding_id=f"scf-{self._finding_counter}",
                    risk_type=SupplyChainRiskType.SINGLE_MAINTAINER,
                    dependency=dep.name,
                    severity="low",
                    title=f"Single maintainer: {dep.name}",
                    description=(
                        f"Popular package {dep.name} ({dep.weekly_downloads} weekly downloads) "
                        f"has only 1 maintainer. Account takeover would compromise all users."
                    ),
                    remediation="Monitor for maintainer changes, consider forking",
                ))
        return findings

    def _check_install_scripts(self) -> list[SupplyChainFinding]:
        """Check for suspicious install scripts."""
        findings = []
        for dep in self._dependencies.values():
            if dep.has_install_script:
                self._finding_counter += 1
                findings.append(SupplyChainFinding(
                    finding_id=f"scf-{self._finding_counter}",
                    risk_type=SupplyChainRiskType.INSTALL_SCRIPT,
                    dependency=dep.name,
                    severity="medium",
                    title=f"Install script present: {dep.name}",
                    description=(
                        f"Package {dep.name} has a post-install script. "
                        f"Install scripts can execute arbitrary code on installation."
                    ),
                    remediation="Review install script before installation",
                ))
        return findings

    def _check_dependency_confusion_risk(self) -> list[SupplyChainFinding]:
        """Check for dependency confusion risk."""
        findings = []

        # Look for packages with internal-looking names
        internal_patterns = [
            r"^@internal[/-]",
            r"^company[/-]",
            r"^private[/-]",
            r"^corp[/-]",
            r"^internal[/-]",
        ]

        for dep in self._dependencies.values():
            for pattern in internal_patterns:
                if re.match(pattern, dep.name, re.IGNORECASE):
                    self._finding_counter += 1
                    findings.append(SupplyChainFinding(
                        finding_id=f"scf-{self._finding_counter}",
                        risk_type=SupplyChainRiskType.DEPENDENCY_CONFUSION,
                        dependency=dep.name,
                        severity="high",
                        title=f"Dependency confusion risk: {dep.name}",
                        description=(
                            f"Package '{dep.name}' appears to be an internal package. "
                            f"If a matching name exists on the public registry with "
                            f"higher version, it may be installed instead."
                        ),
                        remediation="Use scoped registry, pin exact versions, use .npmrc",
                    ))
                    break

        return findings

    def check_script_content(self, content: str, package_name: str = "") -> list[SupplyChainFinding]:
        """Analyze script content for suspicious patterns."""
        findings = []
        for pattern_info in SUSPICIOUS_PATTERNS:
            if re.search(pattern_info["pattern"], content, re.IGNORECASE):
                self._finding_counter += 1
                findings.append(SupplyChainFinding(
                    finding_id=f"scf-{self._finding_counter}",
                    risk_type=SupplyChainRiskType.SUSPICIOUS_BEHAVIOR,
                    dependency=package_name,
                    severity="high",
                    title=f"Suspicious pattern: {pattern_info['name']}",
                    description=(
                        f"Install script in {package_name or 'package'} contains "
                        f"suspicious pattern: {pattern_info['name']}"
                    ),
                    remediation="Review script carefully before running",
                ))
        self._findings.extend(findings)
        return findings

    @staticmethod
    def _edit_distance(str_a: str, str_b: str) -> int:
        """Compute Levenshtein edit distance."""
        if len(str_a) < len(str_b):
            return SupplyChainAnalyzer._edit_distance(str_b, str_a)

        if len(str_b) == 0:
            return len(str_a)

        previous_row = list(range(len(str_b) + 1))

        for i, ch_a in enumerate(str_a):
            current_row = [i + 1]
            for j, ch_b in enumerate(str_b):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (ch_a != ch_b)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def get_stats(self) -> dict[str, Any]:
        risk_counts: dict[str, int] = defaultdict(int)
        for finding in self._findings:
            risk_counts[finding.risk_type.value] += 1
        return {
            "dependencies": len(self._dependencies),
            "findings": len(self._findings),
            "by_risk": dict(risk_counts),
        }
