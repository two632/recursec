"""Supply chain security knowledge base — dependency and build attacks.

Deep knowledge about supply chain vulnerabilities injected into agent prompts:
1. Dependency confusion / substitution attacks
2. Typosquatting detection
3. Malicious package indicators
4. Build pipeline integrity
5. Package manager security (npm, pip, cargo, go, maven)
6. Lock file manipulation
7. Post-install script attacks
8. Compromised maintainer detection
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SupplyChainPattern:
    """A supply chain attack pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    ecosystem: str = ""            # npm, pypi, crates, maven, go, general
    description: str = ""
    testing_methodology: str = ""
    indicators: list[str] = field(default_factory=list)
    mitigation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:15],
            "ecosystem": self.ecosystem[:10],
        }


SUPPLY_CHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sc-001", "name": "Dependency Confusion",
        "category": "substitution", "severity": "critical", "ecosystem": "general",
        "desc": "Internal package name registered on public registry, build system installs public malicious version.",
        "testing": (
            "DEPENDENCY CONFUSION TESTING:\n"
            "1. IDENTIFY INTERNAL PACKAGES:\n"
            "   - Scan package.json, requirements.txt, go.mod, Cargo.toml, pom.xml\n"
            "   - Look for packages that DON'T exist on public registries\n"
            "   - Check for private registry configurations (.npmrc, pip.conf, .pypirc)\n"
            "2. TEST FOR VULNERABILITY:\n"
            "   - npm: Check if .npmrc has a registry scope (@company:registry=...)\n"
            "     If no scope → vulnerable to public registry override\n"
            "   - pip: Check pip.conf for --index-url and --extra-index-url\n"
            "     --extra-index-url ADDS public PyPI alongside private → vulnerable\n"
            "   - Maven: Check settings.xml mirror configuration\n"
            "3. VERSION PRECEDENCE:\n"
            "   - Most package managers install the HIGHEST version\n"
            "   - Attacker publishes version 99.99.99 on public registry\n"
            "   - Build system installs attacker's version\n"
            "4. DETECTION:\n"
            "   - Compare installed packages against both public and private registries\n"
            "   - Check for packages with the same name but different maintainers\n"
            "   - Monitor DNS for unexpected outbound connections during build"
        ),
        "indicators": ["private registry", "internal package", ".npmrc", "pip.conf", "extra-index-url"],
        "mitigation": "Pin exact versions, use lock files, configure registry scopes, use package signing.",
    },
    {
        "id": "sc-002", "name": "Typosquatting",
        "category": "typosquat", "severity": "high", "ecosystem": "general",
        "desc": "Malicious packages with names similar to popular legitimate packages.",
        "testing": (
            "TYPOSQUATTING DETECTION:\n"
            "1. COMMON TYPOSQUAT PATTERNS:\n"
            "   - Missing character: 'reqests' instead of 'requests'\n"
            "   - Extra character: 'requestss', 'rrequests'\n"
            "   - Transposed characters: 'reqeusts'\n"
            "   - Homoglyphs: 'rеquests' (Cyrillic 'е')\n"
            "   - Separator confusion: 'python-requests' vs 'python_requests'\n"
            "   - Scope confusion: '@company/lodash' vs 'lodash'\n"
            "2. DETECTION METHODOLOGY:\n"
            "   - Compute Levenshtein distance between each dependency and top-1000 packages\n"
            "   - Flag any dependency with distance 1-2 from a popular package\n"
            "   - Check package age: very new packages mimicking old popular ones = suspicious\n"
            "   - Check download count: if much lower than the popular package it mimics\n"
            "3. AUTOMATED CHECKS:\n"
            "   - npm: npm audit, socket.dev/npm\n"
            "   - pip: pip-audit, safety check\n"
            "   - All: Snyk, Sonatype, Dependabot"
        ),
        "indicators": ["misspelled package", "new package", "low downloads", "suspicious name"],
        "mitigation": "Use lock files, audit dependencies, require security review for new deps.",
    },
    {
        "id": "sc-003", "name": "Malicious Post-Install Scripts",
        "category": "code_execution", "severity": "critical", "ecosystem": "npm",
        "desc": "npm packages execute arbitrary code during install via preinstall/postinstall scripts.",
        "testing": (
            "POST-INSTALL SCRIPT ANALYSIS:\n"
            "1. CHECK PACKAGE.JSON:\n"
            "   Look for: preinstall, install, postinstall, preuninstall, postuninstall scripts\n"
            "   Red flags:\n"
            "   - Scripts that fetch remote content: curl, wget, http.get\n"
            "   - Scripts that access environment variables\n"
            "   - Scripts that read SSH keys, .env files, .git/config\n"
            "   - Obfuscated or minified script content\n"
            "2. BEHAVIORAL ANALYSIS:\n"
            "   - Run in sandboxed environment and monitor:\n"
            "     * Network connections (outbound HTTP/DNS)\n"
            "     * File system reads (especially ~/.ssh, ~/.aws, ~/.npmrc)\n"
            "     * Environment variable access\n"
            "     * Process spawning\n"
            "3. STATIC ANALYSIS:\n"
            "   - Deobfuscate JavaScript (eval, Buffer.from, atob)\n"
            "   - Check for encoded strings hiding URLs or commands\n"
            "   - Compare against known malicious patterns\n"
            "4. SAFE INSTALL:\n"
            "   npm install --ignore-scripts (skip all scripts)\n"
            "   Then review scripts manually before: npm rebuild"
        ),
        "indicators": ["postinstall", "preinstall", "eval(", "Buffer.from", "child_process"],
        "mitigation": "Use --ignore-scripts, audit all install hooks, use socket.dev.",
    },
    {
        "id": "sc-004", "name": "Lock File Manipulation",
        "category": "integrity", "severity": "high", "ecosystem": "general",
        "desc": "Attacker modifies lock file to point to malicious package versions or registries.",
        "testing": (
            "LOCK FILE INTEGRITY TESTING:\n"
            "1. CHECK FOR INCONSISTENCIES:\n"
            "   - package-lock.json / yarn.lock / pnpm-lock.yaml\n"
            "   - requirements.txt / Pipfile.lock / poetry.lock\n"
            "   - Cargo.lock / go.sum / Gemfile.lock\n"
            "2. VERIFY:\n"
            "   a) Version matches between manifest and lock file\n"
            "   b) Registry URLs are correct (not pointing to attacker registry)\n"
            "   c) Integrity hashes match actual downloaded packages\n"
            "   d) No unexpected packages added to lock file\n"
            "3. DETECTION:\n"
            "   - Diff lock file changes in PRs (most important review)\n"
            "   - Verify 'resolved' URLs point to expected registry\n"
            "   - Check integrity/checksum fields haven't been modified\n"
            "   - npm: 'npm ci' fails if lock file doesn't match manifest\n"
            "4. ATTACK SCENARIOS:\n"
            "   - PR modifies lock file to add malicious transitive dependency\n"
            "   - Lock file updated to point to different registry\n"
            "   - Integrity hash changed to match malicious version"
        ),
        "indicators": ["lock file change", "resolved URL change", "integrity hash change"],
        "mitigation": "Require lock file review in PRs, use npm ci, verify checksums.",
    },
    {
        "id": "sc-005", "name": "Compromised Maintainer Account",
        "category": "account_takeover", "severity": "critical", "ecosystem": "general",
        "desc": "Legitimate package maintainer account compromised, used to publish malicious update.",
        "testing": (
            "COMPROMISED MAINTAINER DETECTION:\n"
            "1. BEHAVIORAL INDICATORS:\n"
            "   - Sudden activity after long dormancy\n"
            "   - Maintainer publishes from new IP/location\n"
            "   - Unusual publish time (3 AM local time)\n"
            "   - Many packages updated simultaneously\n"
            "   - Package size significantly increased/decreased\n"
            "2. CODE INDICATORS:\n"
            "   - New obfuscated code added\n"
            "   - Minified code where source was previously readable\n"
            "   - New network calls or system access\n"
            "   - Postinstall hooks added to previously hook-free package\n"
            "   - Dependencies added that didn't exist before\n"
            "3. VERIFICATION:\n"
            "   - Compare diff between last known-good version and suspect version\n"
            "   - Check maintainer's GitHub activity for signs of compromise\n"
            "   - Verify package signature if GPG signing is used\n"
            "   - Cross-reference with security advisories (NVD, GitHub advisories)\n"
            "4. NOTABLE CASES: event-stream (2018), ua-parser-js (2021), "
            "colors/faker (2022 — maintainer intentional), node-ipc (2022)"
        ),
        "indicators": ["sudden update", "new maintainer", "obfuscated code", "postinstall added"],
        "mitigation": "Pin exact versions, use lock files, delay auto-update, monitor advisories.",
    },
    {
        "id": "sc-006", "name": "Python Package Index (PyPI) Attacks",
        "category": "ecosystem_specific", "severity": "high", "ecosystem": "pypi",
        "desc": "PyPI-specific supply chain attack vectors.",
        "testing": (
            "PyPI SUPPLY CHAIN TESTING:\n"
            "1. SETUP.PY ANALYSIS:\n"
            "   - Check for code execution in setup.py (imports, subprocess calls)\n"
            "   - setup.py runs during 'pip install' even before package is installed\n"
            "   - Look for: os.system(), subprocess.run(), exec(), eval()\n"
            "   - Check for network calls during setup\n"
            "2. __INIT__.PY ANALYSIS:\n"
            "   - Code in __init__.py runs on import\n"
            "   - Check for obfuscated imports or delayed execution\n"
            "3. DEPENDENCY ANALYSIS:\n"
            "   - Check for overly broad version specifiers (>=0.0.0)\n"
            "   - Verify all dependencies exist on PyPI\n"
            "   - Check for dependencies with very few downloads\n"
            "4. TOOLS:\n"
            "   - pip-audit: Scan for known vulnerabilities\n"
            "   - safety: Check against safety DB\n"
            "   - bandit: Static analysis for security issues\n"
            "   - guarddog: Detect malicious packages\n"
            "5. BEST PRACTICES:\n"
            "   - Use pip install --require-hashes\n"
            "   - Pin exact versions in requirements.txt\n"
            "   - Use pip-compile for deterministic builds"
        ),
        "indicators": ["setup.py", "os.system in setup", "subprocess in setup", "exec in __init__"],
        "mitigation": "Pin versions, use --require-hashes, audit setup.py, use guarddog.",
    },
    {
        "id": "sc-007", "name": "Go Module Proxy Attacks",
        "category": "ecosystem_specific", "severity": "high", "ecosystem": "go",
        "desc": "Attacks targeting Go module system and proxy infrastructure.",
        "testing": (
            "GO MODULE SUPPLY CHAIN TESTING:\n"
            "1. PROXY CONFIGURATION:\n"
            "   - Check GOPROXY setting (default: proxy.golang.org)\n"
            "   - Private modules should use GONOSUMDB and GONOSUMCHECK\n"
            "   - GOPRIVATE should list all internal module paths\n"
            "2. MODULE AUTHENTICITY:\n"
            "   - go.sum contains SHA-256 hashes of module content\n"
            "   - Verify: go mod verify (checks against go.sum)\n"
            "   - sum.golang.org provides global transparency log\n"
            "3. ATTACK VECTORS:\n"
            "   - Vanity import path hijacking (custom domain → repo mapping)\n"
            "   - Module major version confusion (v2 vs v1)\n"
            "   - Retracted version usage (using a version the author retracted)\n"
            "   - Build tag manipulation (different code for different platforms)\n"
            "4. DETECTION:\n"
            "   - go mod verify (check hashes)\n"
            "   - govulncheck (scan for known vulns)\n"
            "   - Compare go.sum against known-good state"
        ),
        "indicators": ["go.mod", "go.sum", "GOPROXY", "replace directive"],
        "mitigation": "Use go.sum, set GOPRIVATE, run govulncheck, verify modules.",
    },
]


class SupplyChainKB:
    """Supply chain security knowledge base.

    Provides deep supply chain attack methodologies that get
    injected into agent prompts for dependency security assessment.
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
                ecosystem=data.get("ecosystem", "general"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                indicators=data.get("indicators", []),
                mitigation=data.get("mitigation", ""),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_ecosystem(
        self,
        ecosystem: str,
    ) -> list[SupplyChainPattern]:
        """Get patterns for a specific ecosystem."""
        eco_lower = ecosystem.lower()
        results = []
        for p in self._patterns.values():
            if p.ecosystem == eco_lower or p.ecosystem == "general":
                results.append(p)
        return results

    def get_testing_prompts(
        self,
        ecosystems: list[str] | None = None,
        max_patterns: int = 5,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if ecosystems and pattern.ecosystem not in ecosystems and pattern.ecosystem != "general":
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def detect_ecosystem(self, files: list[str]) -> list[str]:
        """Detect ecosystems from file list."""
        ecosystems = set()
        file_ecosystem = {
            "package.json": "npm",
            "package-lock.json": "npm",
            "yarn.lock": "npm",
            "requirements.txt": "pypi",
            "setup.py": "pypi",
            "pyproject.toml": "pypi",
            "Pipfile": "pypi",
            "Cargo.toml": "crates",
            "go.mod": "go",
            "go.sum": "go",
            "pom.xml": "maven",
            "build.gradle": "maven",
            "Gemfile": "rubygems",
        }

        for f in files:
            basename = f.rsplit("/", 1)[-1] if "/" in f else f
            eco = file_ecosystem.get(basename, "")
            if eco:
                ecosystems.add(eco)

        return sorted(ecosystems)

    def build_supply_chain_prompt(
        self,
        ecosystems: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build comprehensive supply chain testing prompt."""
        relevant = []

        if ecosystems:
            for eco in ecosystems:
                relevant.extend(self.get_patterns_for_ecosystem(eco))
        else:
            relevant = list(self._patterns.values())

        lines = ["## Supply Chain Security Testing\n"]
        seen = set()
        for pattern in relevant:
            if pattern.pattern_id in seen:
                continue
            seen.add(pattern.pattern_id)
            if len(seen) > max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}] ({pattern.ecosystem})")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        eco_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            eco_counts[p.ecosystem] += 1
        return {
            "patterns": len(self._patterns),
            "by_ecosystem": dict(eco_counts),
        }
